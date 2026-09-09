//
//  BEKArray.swift
//  Occulta
//
//  VaultManager.Backup.LayerStore — the crypto and slot logic layer over the shared
//  LayerStoreBackend, mirroring Manager.LayerStore's own shape and name deliberately
//  (VAULT_KEY_LAYERING.md item 13): same backend protocol, same "backend handles raw
//  I/O only" split, parallel naming so a reader who knows one recognizes the other
//  immediately. Filename kept for git history continuity; the type itself dropped
//  the "BEK" prefix along with every other symbol in this namespace.
//
//  ── Wire format ──────────────────────────────────────────────────────────────
//
//    File is always exactly slotCount × slotCiphertextSize bytes.
//    Every slot is independently AES-GCM sealed: PayloadCodec.payloadSize
//    bytes of plaintext, SlotAAD.aad(slotIndex:) as AAD.
//    All 32 slots are re-sealed with fresh nonces on every write (item 7).
//
//    No file-identification-by-key logic here yet — this array lives in its own
//    directory (VAULT_KEY_LAYERING.md §8, decided 2026-09-08), not the shared
//    pool, so there is only ever one file to find. That logic is real, deferred
//    work for whenever the shared-pool merge lands, not something to build now
//    against a scope this array isn't in.
//

import Foundation
import CryptoKit

extension VaultManager.Backup {

    /// Crypto and slot logic for the 32-slot backup-key array. No knowledge of
    /// the filesystem — that's `LayerStoreBackend`'s job, shared with Contact's
    /// own `Manager.LayerStore` since item 13's backend unification.
    final class LayerStore {

        enum Error: Swift.Error, Equatable {
            /// The file exists but isn't the expected total size — truncation,
            /// corruption, or a version this code doesn't understand. Distinct
            /// from "no file yet" (handled as first creation, not an error).
            case fileSizeMismatch
            /// A slot's ciphertext failed to authenticate under the correct key
            /// and AAD. Every slot this array has ever written — real or filler
            /// — authenticates under its own key and AAD; a failure here can
            /// only mean corruption, a partial write, or a bug. Never means
            /// "this slot was always empty" — see item 8's third finding.
            case corruptSlot(index: Int)
            /// AES-GCM sealing itself failed (SecRandomCopyBytes exhaustion or
            /// similar) — not the "wrong key" case, an operational one.
            case sealFailed
        }

        static let slotCount:          Int = SlotAAD.slotCount
        static let slotCiphertextSize: Int = PayloadCodec.payloadSize + 28   // nonce(12) + tag(16)
        static let fileSize:           Int = LayerStore.slotCount * LayerStore.slotCiphertextSize

        private let backend: any LayerStoreBackend

        init(backend: any LayerStoreBackend) {
            self.backend = backend
        }

        // MARK: - Read one slot (non-destructive)

        /// `nil` means genuinely empty (the slot opened correctly but didn't
        /// decode as a real `Payload` — filler). Throws for anything that means
        /// something is actually wrong. The array not existing yet at all is
        /// also `nil`, not an error — same "first creation" case `write()`
        /// already treats as legitimate.
        func read(slotIndex: Int, vaultKey: SymmetricKey) throws -> BackupEncryptionKey.Payload? {
            precondition(SlotAAD.validRange.contains(slotIndex), "slot index \(slotIndex) out of range")

            let fileData: Data
            do {
                fileData = try self.backend.read()
            } catch LayerStoreBackendError.notFound {
                return nil
            }
            guard fileData.count == Self.fileSize else { throw Error.fileSizeMismatch }

            var bytes = [UInt8](fileData)
            defer { for i in bytes.indices { bytes[i] = 0 } }

            let plaintext = try Self.openSlot(slotIndex, in: bytes, using: vaultKey)
            return PayloadCodec.decode(plaintext)
        }

        // MARK: - Write one slot (full-array reseal, item 7)

        /// Writes `payload` into `slotIndex`. Every other slot is re-sealed with
        /// a fresh nonce on every call, real content or filler alike — this is
        /// what makes a snapshot diff unable to show which slot actually
        /// changed (item 7). A slot that fails to open is a thrown error, never
        /// silently replaced with fresh filler (item 8's third finding) — the
        /// exact bug `Manager.LayerStore.push()`/`pop()` have (Bug 107), fixed
        /// here from the start rather than retrofitted.
        func write(_ payload: BackupEncryptionKey.Payload, slotIndex: Int, vaultKey: SymmetricKey) throws {
            precondition(SlotAAD.validRange.contains(slotIndex), "slot index \(slotIndex) out of range")

            var existing: [[UInt8]?] = Array(repeating: nil, count: Self.slotCount)
            defer {
                for i in existing.indices {
                    guard existing[i] != nil else { continue }
                    for j in existing[i]!.indices { existing[i]![j] = 0 }
                }
            }

            do {
                let fileData = try self.backend.read()
                guard fileData.count == Self.fileSize else { throw Error.fileSizeMismatch }
                let bytes = [UInt8](fileData)
                for i in 0..<Self.slotCount where i != slotIndex {
                    existing[i] = [UInt8](try Self.openSlot(i, in: bytes, using: vaultKey))
                }
            } catch LayerStoreBackendError.notFound {
                // First creation — no existing file. Every other slot gets fresh
                // filler below; nothing to preserve.
            }
            // Any other error (fileSizeMismatch, corruptSlot) propagates and
            // halts the write, rather than silently proceeding as if this were
            // a fresh file.

            var file = Data(capacity: Self.fileSize)
            for i in 0..<Self.slotCount {
                let plaintext: [UInt8]
                if i == slotIndex {
                    plaintext = [UInt8](try PayloadCodec.encode(payload))
                } else if let preserved = existing[i] {
                    plaintext = preserved
                } else {
                    plaintext = [UInt8](Data.randomBytes(PayloadCodec.payloadSize))
                }
                guard let combined = try? AES.GCM.seal(
                    Data(plaintext), using: vaultKey, authenticating: SlotAAD.aad(slotIndex: i)
                ).combined else {
                    throw Error.sealFailed
                }
                file.append(combined)
            }

            try self.backend.write(file)
        }

        // MARK: - Private

        private static func openSlot(_ index: Int, in bytes: [UInt8], using vaultKey: SymmetricKey) throws -> Data {
            let offset = index * Self.slotCiphertextSize
            let cipher = Data(bytes[offset..<(offset + Self.slotCiphertextSize)])
            guard let box = try? AES.GCM.SealedBox(combined: cipher),
                  let plaintext = try? AES.GCM.open(box, using: vaultKey, authenticating: SlotAAD.aad(slotIndex: index))
            else {
                throw Error.corruptSlot(index: index)
            }
            return plaintext
        }
    }
}

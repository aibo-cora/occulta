//
//  BEKArray.swift
//  Occulta
//
//  32-slot BEK array — the crypto and slot logic layer over BEKArrayBackend.
//  Wires together BEKPayloadCodec (wire format) and BEKSlotAAD (per-slot AAD).
//  Same split VaultManager.BEKPayloadCodec/BEKSlotAAD already established, and
//  the same backend/logic split Manager.LayerStore uses over LayerStoreBackend.
//
//  ── Wire format ──────────────────────────────────────────────────────────────
//
//    File is always exactly slotCount × slotCiphertextSize bytes.
//    Every slot is independently AES-GCM sealed: BEKPayloadCodec.payloadSize
//    bytes of plaintext, BEKSlotAAD.aad(slotIndex:) as AAD.
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

extension VaultManager {

    /// Crypto and slot logic for the 32-slot BEK array. No knowledge of the
    /// filesystem — that's `BEKArrayBackend`'s job.
    final class BEKArray {

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

        static let slotCount:          Int = BEKSlotAAD.slotCount
        static let slotCiphertextSize: Int = BEKPayloadCodec.payloadSize + 28   // nonce(12) + tag(16)
        static let fileSize:           Int = BEKArray.slotCount * BEKArray.slotCiphertextSize

        private let backend: any BEKArrayBackend

        init(backend: any BEKArrayBackend = AppGroupBEKArrayBackend()) {
            self.backend = backend
        }

        // MARK: - Read one slot (non-destructive)

        /// `nil` means genuinely empty (the slot opened correctly but didn't
        /// decode as a real `Payload` — filler). Throws for anything that means
        /// something is actually wrong.
        func read(slotIndex: Int, vaultKey: SymmetricKey) throws -> BackupEncryptionKey.Payload? {
            precondition(BEKSlotAAD.validRange.contains(slotIndex), "slot index \(slotIndex) out of range")

            let fileData = try self.backend.read()
            guard fileData.count == Self.fileSize else { throw Error.fileSizeMismatch }

            var bytes = [UInt8](fileData)
            defer { for i in bytes.indices { bytes[i] = 0 } }

            let plaintext = try Self.openSlot(slotIndex, in: bytes, using: vaultKey)
            return BEKPayloadCodec.decode(plaintext)
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
            precondition(BEKSlotAAD.validRange.contains(slotIndex), "slot index \(slotIndex) out of range")

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
            } catch BEKArrayBackendError.notFound {
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
                    plaintext = [UInt8](try BEKPayloadCodec.encode(payload))
                } else if let preserved = existing[i] {
                    plaintext = preserved
                } else {
                    plaintext = [UInt8](Data.randomBytes(BEKPayloadCodec.payloadSize))
                }
                guard let combined = try? AES.GCM.seal(
                    Data(plaintext), using: vaultKey, authenticating: BEKSlotAAD.aad(slotIndex: i)
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
                  let plaintext = try? AES.GCM.open(box, using: vaultKey, authenticating: BEKSlotAAD.aad(slotIndex: index))
            else {
                throw Error.corruptSlot(index: index)
            }
            return plaintext
        }
    }
}

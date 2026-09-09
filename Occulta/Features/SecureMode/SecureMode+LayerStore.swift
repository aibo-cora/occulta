//
//  SecureMode+LayerStore.swift
//  Occulta
//
//  32-slot fixed-size layer store. See LayerStore.md for full design.
//
//  ── Wire format ──────────────────────────────────────────────────────────────
//
//    File is always exactly slotCount × slotCiphertextSize bytes.
//    Every slot is AES-GCM sealed to exactly slotPlaintextSize bytes of plaintext.
//    All 32 slots are re-sealed with fresh nonces on every push and pop.
//
//    slot 0  │ AES-GCM(slotPlaintextSize bytes — random or LayerPayload JSON + zero-pad)
//    ...
//    slot k  │ AES-GCM(LayerPayload JSON + zero-pad)   ← real slot; index unknown to examiner
//    ...
//    slot 31 │ AES-GCM(...)
//
//    No header. No magic bytes. No version field. No slot count.
//    UUID filename with .occbak extension.
//
//  ── Encryption ───────────────────────────────────────────────────────────────
//
//    layerKey = HKDF-SHA256(IKM: seKey, info: "layer-store-key", outputLen: 32)
//    slot     = AES-GCM(layerKey, plaintext, randomNonce, LayerStore.SlotAAD.aad(slotIndex:))
//               [combined: nonce ∥ ciphertext ∥ tag]
//
//    AAD binds each slot to its own position (Bug 106 fix) — a slot opened without
//    it falls back to the pre-fix scheme (no AAD at all) so existing files keep
//    reading, and gets re-sealed under the new scheme on the very next push()/pop(),
//    which already reseal every slot unconditionally. No separate migration pass.
//
//  ── Storage ──────────────────────────────────────────────────────────────────
//
//    group.com.occulta.shared/blobs/<UUID>.occbak
//    File protection: .completeFileProtection
//    Excluded from iCloud backup: isExcludedFromBackup = true
//

import Foundation
import CryptoKit
import Security

// MARK: - Payload types

/// One sensitive contact serialised for a deniability layer.
///
/// All fields are plaintext — activation decrypts them from the DB before
/// constructing this record. Deactivation re-encrypts under the new DB key.
struct LayerContact: Codable {
    let draft:               Contact.Draft
    /// Decrypted JSON-encoded [SignedAttribute]; nil when never a trustee.
    let signedAttributes:    Data?
    /// Decoded visibleThroughDepth at activation time. Restored verbatim on
    /// deactivation (Bug 23 fix). nil in records written before this field was
    /// added — deactivation falls back to 0 (sensitive).
    let visibleThroughDepth: Int?
    /// Decoded globalTrusteeDepth at activation time. Restored verbatim on
    /// deactivation. nil in records written before this field was added —
    /// deactivation falls back to -1 (not a trustee).
    let globalTrusteeDepth: Int?

    // No originDepth field here, deliberately: a duress-origin contact (originDepth > 0)
    // is exempt from ceiling-based blob-sealing entirely (see activateSecureMode's Step 4
    // short-circuit) and so can never reach this struct at all. Every contact that can
    // possibly appear here has originDepth == 0 by construction, not by chance — restoring
    // it is a provable constant, not a captured value, so restoreContact writes the
    // sentinel directly instead of threading a field through the blob that could never
    // legitimately hold anything else.
}

/// The complete payload for one activation layer.
struct LayerPayload: Codable {
    /// A fresh random value chosen once at activation, not incrementing — see
    /// LayerStore.md "Sequence numbers" for why. Validated on pop (and on
    /// readPayload) to detect a stale blob from an older activation cycle.
    let sequenceNumber: Int
    /// Which of the 32 slots this payload occupies; validated on pop and on readPayload.
    let slotIndex:      Int
    let contacts:       [LayerContact]
}

extension Manager {

    /// Layer store for Secure Mode deniability. See LayerStore.md.
    ///
    /// Two roles:
    /// 1. **Forensic cover** — exists on every install from first launch, before
    ///    Secure Mode is configured. Timestamps track normal app activity.
    /// 2. **Cryptographic container** — sealed during activation; popped during
    ///    deactivation to restore sensitive contacts under a new DB key.
    final class LayerStore {

        // MARK: - Errors

        enum Error: Swift.Error, CustomNSError {
            case notFound
            case encryptionFailed
            case decryptionFailed
            case sequenceNumberMismatch(expected: Int, got: Int)
            case slotIndexMismatch(expected: Int, got: Int)
            /// Thrown from push() before any I/O when encoded payload exceeds slotPlaintextSize.
            case payloadTooLarge(contacts: Int, encodedBytes: Int, limit: Int)

            static var errorDomain: String { "Occulta.Manager.LayerStore.Error" }

            var errorCode: Int {
                switch self {
                case .notFound:                 return 0
                case .encryptionFailed:         return 1
                case .decryptionFailed:         return 2
                case .sequenceNumberMismatch:   return 3
                case .slotIndexMismatch:        return 4
                case .payloadTooLarge:          return 5
                }
            }

            var errorUserInfo: [String: Any] { [:] }
        }

        // MARK: - Constants

        /// Number of fixed slots. Must equal AppLayerConfig.maxVerifierCount so
        /// neither the file size nor the verifier array length leaks more than the other.
        static let slotCount:        Int = 32
        /// Fixed plaintext size per slot. 32 KB fits ~30 contacts with full ML-KEM material.
        static let slotPlaintextSize: Int = 32 * 1024
        /// Ciphertext size per slot: nonce(12) + ciphertext(slotPlaintextSize) + tag(16).
        static var slotCiphertextSize: Int { slotPlaintextSize + 28 }

        private static let hkdfInfo = Data("layer-store-key".utf8)

        // MARK: - Slot AAD (Bug 106 fix)

        /// AAD binding each slot's ciphertext to its own position in the file — closes
        /// Bug 106 (`bugs.md`): without this, a slot's ciphertext could be relocated to a
        /// different slot position and still decrypt successfully, since decryption never
        /// depended on where the bytes physically sit. Same shape as `VaultManager.BEKSlotAAD`
        /// (`Vault+Manager+Backup.swift`), own domain string — the two files' keys already
        /// differ, so reuse would be cryptographically safe, but a self-contained identity
        /// is the established convention here rather than leaning on key-independence as a
        /// property nobody has to reason about later.
        ///
        /// Does **not** close the separate, already-accepted gap this store shares with the
        /// BEK array (`VAULT_KEY_LAYERING.md` item 7): every slot is still sealed under the
        /// same `layerKey`, so a coercer holding that key can still open every depth's slot
        /// directly. That's the unavoidable cost of full-array reseal, not something this
        /// AAD is meant to fix.
        private enum SlotAAD {
            private static let domain = Data("occulta-layer-store-slot-v1".utf8)

            static func aad(slotIndex: Int) -> Data {
                precondition((0..<LayerStore.slotCount).contains(slotIndex), "slot index \(slotIndex) out of range")
                var out = Self.domain
                out.append(UInt8(slotIndex))
                return out
            }
        }

        /// Maintenance-rewrite threshold, drawn once per process from an 18–30 h window.
        ///
        /// A fixed 24 h cadence turns the store file's own modification timestamp into a
        /// usable signal: a write landing off-cadence is distinguishable from routine
        /// maintenance, which is what lets an activation be inferred from two filesystem
        /// captures (Bug 71). A threshold that varies means one observed write time implies
        /// much less about whether it was routine.
        ///
        /// **Drawn once per launch, not per call.** `maintain()` runs on every foreground, so
        /// a fresh draw each time would let the lowest draw win and collapse the window back
        /// toward its 18 h floor. Per-launch keeps the whole window in play.
        ///
        /// Not key material — cadence obfuscation only, so the system RNG is sufficient here
        /// and `SecRandomCopyBytes` (used for slot selection in this same file) would be noise.
        ///
        /// Reduces the signal; does not remove it. A write still happened, and the jitter
        /// window bounds rather than hides when. The other half of Bug 71's remedy —
        /// opportunistic writes during ordinary use — is not implemented.
        static let maxAge: TimeInterval = .random(in: 18 * 3_600 ... 30 * 3_600)

        // MARK: - Init

        private let backend: any LayerStoreBackend

        init(backend: any LayerStoreBackend = AppGroupLayerStoreBackend()) {
            self.backend = backend
        }

        // MARK: - Key derivation

        func deriveKey(from seKey: SymmetricKey) -> SymmetricKey? {
            HKDF<SHA256>.deriveKey(inputKeyMaterial: seKey, info: Self.hkdfInfo, outputByteCount: 32)
        }

        // MARK: - Push

        /// Encodes payload into slotIndex; re-seals all other slots with fresh nonces.
        /// Throws `.payloadTooLarge` before any I/O when the encoded payload exceeds
        /// `slotPlaintextSize`.
        func push(_ payload: LayerPayload, key: SymmetricKey, slotIndex: Int) throws {
            var plaintext = try JSONEncoder().encode(payload)
            guard plaintext.count <= Self.slotPlaintextSize else {
                throw Error.payloadTooLarge(
                    contacts:     payload.contacts.count,
                    encodedBytes: plaintext.count,
                    limit:        Self.slotPlaintextSize
                )
            }
            if plaintext.count < Self.slotPlaintextSize {
                plaintext.append(contentsOf: repeatElement(0, count: Self.slotPlaintextSize - plaintext.count))
            }
            defer { _ = plaintext.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) } }

            let existing = self.decryptedPlaintexts(using: key)

            var file = Data(capacity: Self.slotCount * Self.slotCiphertextSize)
            for i in 0..<Self.slotCount {
                if i == slotIndex {
                    guard let combined = try? AES.GCM.seal(
                        plaintext, using: key, authenticating: SlotAAD.aad(slotIndex: i)
                    ).combined else {
                        throw Error.encryptionFailed
                    }
                    file.append(combined)
                } else if let plain = existing[i],
                          let combined = try? AES.GCM.seal(
                            plain, using: key, authenticating: SlotAAD.aad(slotIndex: i)
                          ).combined {
                    // Re-seal existing plaintext (real payload at another depth or padding)
                    file.append(combined)
                } else {
                    file.append(try self.sealRandom(using: key, slotIndex: i))
                }
            }

            try self.backend.write(file)
        }

        // MARK: - Pop

        /// Decrypts slotIndex, validates sequenceNumber and slotIndex fields, erases
        /// that slot with random bytes, re-seals all remaining slots with fresh nonces,
        /// writes the full file, and returns the payload.
        func pop(key: SymmetricKey, slotIndex: Int, expectedSequenceNumber: Int) throws -> LayerPayload {
            let fileData = try self.backend.read()
            guard fileData.count == Self.slotCount * Self.slotCiphertextSize else {
                throw Error.decryptionFailed
            }

            let payload = try self.decodeSlot(slotIndex, from: fileData, using: key)

            guard payload.sequenceNumber == expectedSequenceNumber else {
                throw Error.sequenceNumberMismatch(expected: expectedSequenceNumber, got: payload.sequenceNumber)
            }
            guard payload.slotIndex == slotIndex else {
                throw Error.slotIndexMismatch(expected: slotIndex, got: payload.slotIndex)
            }

            var newFile = Data(capacity: Self.slotCount * Self.slotCiphertextSize)
            for i in 0..<Self.slotCount {
                if i == slotIndex {
                    newFile.append(try self.sealRandom(using: key, slotIndex: i))
                } else {
                    let offset = i * Self.slotCiphertextSize
                    let cipher = fileData[offset..<(offset + Self.slotCiphertextSize)]
                    if let plain    = Self.openSlot(cipher, using: key, slotIndex: i),
                       let combined = try? AES.GCM.seal(
                        plain, using: key, authenticating: SlotAAD.aad(slotIndex: i)
                       ).combined {
                        newFile.append(combined)
                    } else {
                        newFile.append(try self.sealRandom(using: key, slotIndex: i))
                    }
                }
            }

            try self.backend.write(newFile)
            return payload
        }

        // MARK: - Non-destructive read

        /// Decrypts slotIndex without modifying the file — the repeatable load Design B's
        /// own unlock step needs (lock/unlock can cycle many times within one activation,
        /// each needing a fresh, non-erasing read), distinct from `pop()`'s one-time,
        /// destructive deactivation read.
        ///
        /// Validates `sequenceNumber` and `slotIndex` exactly as `pop()` does — the same
        /// stale-blob check, just without the erasure. Not optional: `decodeSlot` alone
        /// only decrypts and decodes, so without this a caller would silently accept a
        /// blob left over from an older activation cycle, exactly what the sequence-number
        /// check exists to catch at deactivation.
        func readPayload(key: SymmetricKey, slotIndex: Int, expectedSequenceNumber: Int) throws -> LayerPayload {
            let fileData = try self.backend.read()
            guard fileData.count == Self.slotCount * Self.slotCiphertextSize else {
                throw Error.decryptionFailed
            }
            let payload = try self.decodeSlot(slotIndex, from: fileData, using: key)
            guard payload.sequenceNumber == expectedSequenceNumber else {
                throw Error.sequenceNumberMismatch(expected: expectedSequenceNumber, got: payload.sequenceNumber)
            }
            guard payload.slotIndex == slotIndex else {
                throw Error.slotIndexMismatch(expected: slotIndex, got: payload.slotIndex)
            }
            return payload
        }

        // MARK: - Slot assignment

        /// Returns a cryptographically random slot index not in `excluded`.
        func randomSlot(excluding excluded: Set<Int> = []) -> Int {
            var pool = Array(Set(0..<Self.slotCount).subtracting(excluded))
            pool.sort()
            var raw = [UInt8](repeating: 0, count: 4)
            _ = SecRandomCopyBytes(kSecRandomDefault, 4, &raw)
            let value = Int(raw[0]) | (Int(raw[1]) << 8) | (Int(raw[2]) << 16) | (Int(raw[3]) << 24)
            return pool[abs(value) % pool.count]
        }

        // MARK: - Maintenance

        /// Creates the store file on first launch; rewrites if older than 24 hours.
        func maintain() {
            if !self.backend.exists {
                self.writeNoOpFile()
                return
            }
            if let date = self.backend.modificationDate,
               Date().timeIntervalSince(date) >= Self.maxAge {
                self.writeNoOpFile()
            }
        }

        /// Unconditional rewrite with fresh random slots.
        /// Never call when Secure Mode is active — it would destroy the real payload.
        func rewrite() {
            self.writeNoOpFile()
        }

        /// Deletes the layer store file from the App Group container.
        func deleteFile() {
            self.backend.delete()
        }

        // MARK: - Capacity estimation

        /// Upper-bound estimate of the serialised LayerContact byte size for a profile.
        /// Computed from raw encrypted field sizes — no decryption required.
        /// Overestimates by ~28 bytes per field (AES-GCM overhead); safe for the
        /// contact classification capacity indicator.
        func estimatedSize(for profile: Contact.Profile) -> Int {
            var total = 0
            // imageData and thumbnailImageData are stripped from the blob (Bug 43b fix).
            total += profile.forwardSecrecyEncrypted?.count ?? 0
            total += profile.signedAttributes?.count        ?? 0
            total += profile.visibleThroughDepth?.count     ?? 0
            let strings: [String] = [
                profile.givenName, profile.familyName, profile.middleName,
                profile.namePrefix, profile.nameSuffix, profile.nickname,
                profile.organizationName, profile.departmentName, profile.jobTitle,
                profile.phoneticGivenName, profile.phoneticMiddleName, profile.phoneticFamilyName,
                profile.note, profile.birthday ?? ""
            ]
            total += strings.reduce(0) { $0 + $1.count }
            for key in profile.contactPublicKeys ?? [] {
                total += key.material?.count                   ?? 0
                total += key.acquiredAt?.count                 ?? 0
                total += key.expiredOn?.count                  ?? 0
                total += key.quantumKeyMaterialEncrypted?.count ?? 0
            }
            // JSON structural overhead
            total += 50 * (strings.count + 5) + 200
            return total
        }

        // MARK: - Private helpers

        private func decodeSlot(_ index: Int, from fileData: Data, using key: SymmetricKey) throws -> LayerPayload {
            let offset = index * Self.slotCiphertextSize
            let cipher = fileData[offset..<(offset + Self.slotCiphertextSize)]
            guard let plaintext = Self.openSlot(cipher, using: key, slotIndex: index)
            else { throw Error.decryptionFailed }
            let jsonEnd = plaintext.firstIndex(of: 0) ?? plaintext.endIndex
            return try JSONDecoder().decode(LayerPayload.self, from: plaintext[..<jsonEnd])
        }

        /// Attempts to decrypt all slots; returns nil for slots that fail authentication.
        private func decryptedPlaintexts(using key: SymmetricKey) -> [Data?] {
            guard let fileData = try? self.backend.read(),
                  fileData.count == Self.slotCount * Self.slotCiphertextSize
            else { return Array(repeating: nil, count: Self.slotCount) }
            return (0..<Self.slotCount).map { i in
                let offset = i * Self.slotCiphertextSize
                let cipher = fileData[offset..<(offset + Self.slotCiphertextSize)]
                return Self.openSlot(cipher, using: key, slotIndex: i)
            }
        }

        /// Opens one slot's ciphertext, trying the current (AAD-bound) scheme first and
        /// falling back to the pre-Bug-106-fix scheme (no AAD at all) on failure — the same
        /// "try current, then legacy" dispatch `BEKPayloadCodec` uses for format versions,
        /// keyed off which AAD succeeds rather than a version byte, since this file
        /// deliberately carries no version tag (see the header comment). A slot that fails
        /// both is genuinely corrupted or unreadable, not stale — the same distinction
        /// Bug 107 already draws for this store. Every slot re-sealed after this fix ships
        /// adopts the new AAD immediately, since push()/pop() already reseal all 32 slots
        /// unconditionally on every call — no separate migration pass is needed.
        private static func openSlot(_ cipher: Data, using key: SymmetricKey, slotIndex: Int) -> Data? {
            guard let box = try? AES.GCM.SealedBox(combined: cipher) else { return nil }
            if let plain = try? AES.GCM.open(box, using: key, authenticating: SlotAAD.aad(slotIndex: slotIndex)) {
                return plain
            }
            return try? AES.GCM.open(box, using: key)
        }

        private func sealRandom(using key: SymmetricKey, slotIndex: Int) throws -> Data {
            var random = Data(count: Self.slotPlaintextSize)
            let status = random.withUnsafeMutableBytes {
                SecRandomCopyBytes(kSecRandomDefault, Self.slotPlaintextSize, $0.baseAddress!)
            }
            guard status == errSecSuccess else { throw Error.encryptionFailed }
            guard let combined = try? AES.GCM.seal(
                random, using: key, authenticating: SlotAAD.aad(slotIndex: slotIndex)
            ).combined else {
                throw Error.encryptionFailed
            }
            return combined
        }

        private func writeNoOpFile() {
            guard
                let seKey    = try? Manager.Key().deriveSecureModeKey(),
                let layerKey = self.deriveKey(from: seKey)
            else { return }

            var file = Data(capacity: Self.slotCount * Self.slotCiphertextSize)
            for i in 0..<Self.slotCount {
                guard let slot = try? self.sealRandom(using: layerKey, slotIndex: i) else { return }
                file.append(slot)
            }

            try? self.backend.write(file)
        }
    }
}

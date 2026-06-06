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
//    slot     = AES-GCM(layerKey, plaintext, randomNonce)   [combined: nonce ∥ ciphertext ∥ tag]
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
}

/// The complete payload for one activation layer.
struct LayerPayload: Codable {
    /// Strictly increasing per push; validated on pop to detect stale blobs.
    let sequenceNumber: Int
    /// Which of the 32 slots this payload occupies; validated on pop.
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
        private static let maxAge: TimeInterval = 86_400  // 24 h

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
                    guard let combined = try? AES.GCM.seal(plaintext, using: key).combined else {
                        throw Error.encryptionFailed
                    }
                    file.append(combined)
                } else if let plain = existing[i],
                          let combined = try? AES.GCM.seal(plain, using: key).combined {
                    // Re-seal existing plaintext (real payload at another depth or padding)
                    file.append(combined)
                } else {
                    file.append(try self.sealRandom(using: key))
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
                    newFile.append(try self.sealRandom(using: key))
                } else {
                    let offset = i * Self.slotCiphertextSize
                    let cipher = fileData[offset..<(offset + Self.slotCiphertextSize)]
                    if let box      = try? AES.GCM.SealedBox(combined: cipher),
                       let plain    = try? AES.GCM.open(box, using: key),
                       let combined = try? AES.GCM.seal(plain, using: key).combined {
                        newFile.append(combined)
                    } else {
                        newFile.append(try self.sealRandom(using: key))
                    }
                }
            }

            try self.backend.write(newFile)
            return payload
        }

        // MARK: - Non-destructive read

        /// Decrypts slotIndex without modifying the file.
        /// Use for diagnostics and tests. Production code should use pop().
        func readPayload(key: SymmetricKey, slotIndex: Int) throws -> LayerPayload {
            let fileData = try self.backend.read()
            guard fileData.count == Self.slotCount * Self.slotCiphertextSize else {
                throw Error.decryptionFailed
            }
            return try self.decodeSlot(slotIndex, from: fileData, using: key)
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
            guard let box      = try? AES.GCM.SealedBox(combined: cipher),
                  let plaintext = try? AES.GCM.open(box, using: key)
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
                guard let box   = try? AES.GCM.SealedBox(combined: cipher),
                      let plain = try? AES.GCM.open(box, using: key)
                else { return nil }
                return plain
            }
        }

        private func sealRandom(using key: SymmetricKey) throws -> Data {
            var random = Data(count: Self.slotPlaintextSize)
            let status = random.withUnsafeMutableBytes {
                SecRandomCopyBytes(kSecRandomDefault, Self.slotPlaintextSize, $0.baseAddress!)
            }
            guard status == errSecSuccess else { throw Error.encryptionFailed }
            guard let combined = try? AES.GCM.seal(random, using: key).combined else {
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
            for _ in 0..<Self.slotCount {
                guard let slot = try? self.sealRandom(using: layerKey) else { return }
                file.append(slot)
            }

            try? self.backend.write(file)
        }
    }
}

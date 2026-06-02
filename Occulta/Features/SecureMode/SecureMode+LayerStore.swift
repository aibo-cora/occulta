//
//  SecureMode+LayerStore.swift
//  Occulta
//
//  Phase 1 layer store implementation. See LayerStore.md for full design.
//  Pending upgrade: 32-slot wire format, push/pop API, full slot regeneration.
//
//  ── Wire format (current — single payload) ───────────────────────────────────
//
//    AES-GCM combined: nonce(12) ∥ ciphertext ∥ tag(16)
//
//    Plaintext is bucket-padded to the nearest power-of-2 boundary so the
//    encrypted file size reveals only a tier, not the exact contact count.
//
//    No header, no magic bytes, no version field, no layer count.
//    UUID filename with .occbak extension — same extension as vault backups,
//    indistinguishable to a filesystem examiner.
//    (Vault backups start with the 4-byte "OCBK" magic; layer store files do not.
//    The vault restore path rejects them via BackupError.invalidFormat.)
//
//  ── Encryption ───────────────────────────────────────────────────────────────
//
//    layerKey = HKDF-SHA256(IKM: seKey, info: "layer-store-key", outputLen: 32)
//    payload  = AES-GCM(layerKey, paddedPlaintext)   [random nonce per write]
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
/// All fields are plaintext — the activation sequence decrypts them from the DB
/// key before constructing this record. The restore path re-encrypts under the
/// new DB key during deactivation.
struct LayerContact: Codable {
    /// Full contact data including ML-KEM material (via `Contact.Draft.Key.quantumKeyMaterial`).
    let draft: Contact.Draft
    /// Decrypted plaintext of `Contact.Profile.signedAttributes` — the JSON-encoded
    /// `[SignedAttribute]` shard records this contact holds as trustee.
    /// `nil` when the contact has never been a trustee.
    let signedAttributes: Data?
    /// The decoded `visibleThroughDepth` value at activation time (e.g. `0` = hidden at
    /// all duress depths). Restored verbatim on deactivation so the contact retains its
    /// sensitivity classification across activation cycles (Bug 23 fix).
    ///
    /// `nil` in records written before this field was added — deactivation falls back to `0`
    /// (sensitive) since any contact in the store had a finite depth by definition.
    let visibleThroughDepth: Int?
}

/// The complete payload for one activation layer.
struct LayerPayload: Codable {
    let contacts: [LayerContact]
}

extension Manager {

    /// Layer store for Secure Mode. See LayerStore.md for full design.
    ///
    /// Two roles:
    /// 1. **Forensic deniability** — file exists from first launch, predating any
    ///    Secure Mode configuration. Timestamps track normal app activity.
    /// 2. **Cryptographic container** — holds sensitive contact data during an active
    ///    Secure Mode session; restored and re-encrypted under a new DB key on deactivation.
    enum LayerStore {

        // MARK: - Constants

        private static let appGroup:  String        = "group.com.occulta.shared"
        private static let directory: String        = "blobs"
        /// HKDF info string for layer key derivation. Changing this invalidates all
        /// existing store files. Domain-separated from PIN verifier keys.
        private static let hkdfInfo:  Data          = Data("layer-store-key".utf8)
        /// Smallest plaintext bucket in bytes.
        static let minBucket:         Int           = 256
        /// Rewrite interval — decouples Last-Modified timestamp from meaningful events.
        private static let maxAge:    TimeInterval  = 86_400  // 24 h

        // MARK: - Errors

        enum Error: Swift.Error {
            /// No `.occbak` file found in the store directory.
            case notFound
            /// AES-GCM seal failed or the store directory is unavailable.
            case encryptionFailed
            /// AES-GCM open failed — wrong key, corrupt file, or truncated data.
            case decryptionFailed
        }

        // MARK: - Maintenance

        /// Creates the no-op store file on first launch; rewrites if older than 24 hours.
        ///
        /// Called from `OccultaApp.init()`, gated on the `secureMode` feature flag.
        /// Fails silently — retried on next launch. Side effect on a fresh install:
        /// creates the SE key, decoupling its Keychain timestamp from first configuration.
        static func maintain() {
            guard let dir = self.storeDirectory() else { return }

            if let existing = self.findFile(in: dir) {
                guard self.isStale(existing) else { return }
                try? FileManager.default.removeItem(at: existing)
            }

            self.writeNoOpFile(to: dir)
        }

        /// Unconditionally replaces the current file with a fresh no-op payload.
        ///
        /// Called after deactivation and on every `ModelContext` save (debounced 30 s).
        /// **Caller contract:** never call when Secure Mode is active — it destroys the
        /// real payload. `OccultaApp` gates on `!security.isSecureModeActive`.
        static func rewrite() {
            guard let dir = self.storeDirectory() else { return }
            if let existing = self.findFile(in: dir) {
                try? FileManager.default.removeItem(at: existing)
            }
            self.writeNoOpFile(to: dir)
        }

        // MARK: - Key derivation

        /// Derives the 256-bit layer encryption key from the SE-bound key via HKDF-SHA256.
        static func deriveKey(from seKey: SymmetricKey) -> SymmetricKey? {
            HKDF<SHA256>.deriveKey(inputKeyMaterial: seKey, info: hkdfInfo, outputByteCount: 32)
        }

        // MARK: - Bucket sizing

        /// Smallest power-of-2 bucket size ≥ `contentLength`, floor `minBucket`.
        static func bucketSize(for contentLength: Int) -> Int {
            var size = minBucket
            while size < contentLength { size *= 2 }
            return size
        }

        // MARK: - Seal / Unseal (to be replaced by push/pop in the 32-slot upgrade)

        /// Encrypts `payload` and writes it to `store`.
        static func seal(_ payload: LayerPayload, layerKey: SymmetricKey, store: any LayerStoreBackend) throws {
            var plaintext = try JSONEncoder().encode(payload)
            let padded    = self.bucketSize(for: plaintext.count)
            if plaintext.count < padded {
                plaintext.append(contentsOf: repeatElement(0, count: padded - plaintext.count))
            }
            defer {
                _ = plaintext.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
            }

            guard let combined = try? AES.GCM.seal(plaintext, using: layerKey).combined else {
                throw Error.encryptionFailed
            }

            try store.write(combined)
        }

        /// Decrypts and returns the payload from `store`.
        static func unseal(layerKey: SymmetricKey, store: any LayerStoreBackend) throws -> LayerPayload {
            let combined = try store.read()
            guard let box       = try? AES.GCM.SealedBox(combined: combined),
                  let plaintext = try? AES.GCM.open(box, using: layerKey)
            else { throw Error.decryptionFailed }

            // Strip bucket-padding zeros before decoding. All data fields in LayerPayload
            // are base64-encoded so the JSON itself never contains 0x00 bytes.
            let jsonEnd = plaintext.firstIndex(of: 0) ?? plaintext.endIndex
            return try JSONDecoder().decode(LayerPayload.self, from: plaintext[..<jsonEnd])
        }

        // MARK: - Private helpers

        private static func storeDirectory() -> URL? {
            guard let container = FileManager.default
                .containerURL(forSecurityApplicationGroupIdentifier: appGroup)
            else { return nil }
            let dir = container.appendingPathComponent(directory)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            return dir
        }

        private static func findFile(in dir: URL) -> URL? {
            let files = try? FileManager.default.contentsOfDirectory(
                at: dir, includingPropertiesForKeys: [.contentModificationDateKey]
            )
            return files?
                .filter { $0.pathExtension == "occbak" }
                .sorted {
                    let lhs = (try? $0.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate ?? .distantPast
                    let rhs = (try? $1.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate ?? .distantPast
                    return lhs > rhs
                }
                .first
        }

        private static func isStale(_ url: URL) -> Bool {
            guard
                let values   = try? url.resourceValues(forKeys: [.contentModificationDateKey]),
                let modified = values.contentModificationDate
            else { return true }
            return Date().timeIntervalSince(modified) >= maxAge
        }

        private static func writeNoOpFile(to dir: URL) {
            guard
                let seKey    = try? Manager.Key().deriveSecureModeKey(),
                let layerKey = self.deriveKey(from: seKey),
                let payload  = self.encryptedNoOpPayload(using: layerKey)
            else { return }

            let url = dir.appendingPathComponent("\(UUID().uuidString).occbak")

            do {
                try payload.write(to: url, options: .completeFileProtection)
                var mutableURL = url
                var values     = URLResourceValues()
                values.isExcludedFromBackup = true
                try mutableURL.setResourceValues(values)
            } catch {
                try? FileManager.default.removeItem(at: url)
            }
        }

        private static func encryptedNoOpPayload(using key: SymmetricKey) -> Data? {
            let size   = self.bucketSize(for: 0)
            var random = Data(count: size)
            let status = random.withUnsafeMutableBytes {
                SecRandomCopyBytes(kSecRandomDefault, size, $0.baseAddress!)
            }
            guard status == errSecSuccess else { return nil }
            return try? AES.GCM.seal(random, using: key).combined
        }
    }
}

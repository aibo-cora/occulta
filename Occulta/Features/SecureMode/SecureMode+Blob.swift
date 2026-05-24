//
//  SecureMode+Blob.swift
//  Occulta
//
//  Blob file infrastructure for Secure Mode.
//
//  Phase 1 (this file): writes a no-op payload on first launch and rewrites it
//  every 24 hours so the file exists — with mundane timestamps — long before
//  Secure Mode is ever configured. A forensic examiner cannot distinguish
//  "Secure Mode was used" from "this is a normal Occulta install" based on the
//  blob's presence or creation timestamp alone.
//
//  Step 4 builds the activation and deactivation sequences on top of the same
//  infrastructure: the wire format, bucket sizing, and key derivation defined
//  here are final and carry forward unchanged.
//
//  ── Wire format (single payload) ─────────────────────────────────────────────
//
//    AES-GCM combined: nonce(12) ∥ ciphertext ∥ tag(16)
//
//    Plaintext is first padded to the nearest power-of-2 bucket boundary so the
//    encrypted file size reveals only a tier (256, 512, 1024 … bytes), not the
//    exact number of contacts or vault entries.
//
//    No header, no magic bytes, no version field, no layer count.
//    UUID filename with .occbak extension — same extension as vault backups,
//    indistinguishable to a filesystem examiner.
//    (Vault backups start with the 4-byte "OCBK" magic; blobs do not. The vault
//    restore path rejects blobs via BackupError.invalidFormat — no interference.)
//
//  ── Encryption ───────────────────────────────────────────────────────────────
//
//    blobKey = HKDF-SHA256(IKM: seKey, info: "blob-key", outputLen: 32)
//    payload = AES-GCM(blobKey, paddedPlaintext)   [random nonce per write]
//
//    SE binding prevents all off-device attacks. Domain separation via the
//    HKDF info string ensures the blob key is independent of PIN verifier keys.
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

/// One hidden contact serialised for the blob.
///
/// All fields are in plaintext — the activation sequence decrypts contact fields
/// from the DB key before constructing this record. The restore path re-encrypts
/// them under the new DB key.
struct ContactBlobRecord: Codable {
    /// Full contact data including ML-KEM material (via `Contact.Draft.Key.quantumKeyMaterial`).
    let draft: Contact.Draft
    /// Decrypted plaintext of `Contact.Profile.signedAttributes` — the JSON-encoded
    /// `[SignedAttribute]` shard records this contact holds as trustee.
    /// `nil` when the contact has never been a trustee.
    let signedAttributes: Data?
}

/// One hidden vault entry's per-entry key serialised for the blob.
///
/// `encryptedLabel` / `encryptedContent` stay on disk locked in-place;
/// only the PEK travels in the blob so the entry can be decrypted on restore.
struct VaultPEKRecord: Codable {
    /// Matches `VaultEntry.id` — used as the UPDATE target on restore.
    let entryID: UUID
    /// Raw 32-byte per-entry key. Caller must zero the source bytes after `seal` returns.
    let pekBytes: Data
    /// Decrypted `ShardDistributionMetadata` for this entry, or `nil` if no SSS
    /// split has been configured. Carried so trustee relationships survive deactivation.
    let shardDistribution: ShardDistributionMetadata?
}

/// The complete blob payload for one activation layer.
struct BlobPayload: Codable {
    let contacts: [ContactBlobRecord]
    let vaultPEKs: [VaultPEKRecord]
}

extension Manager {

    /// Blob file management for Secure Mode.
    ///
    /// The blob serves two roles:
    ///
    /// 1. **Forensic deniability**: the file exists on every install from the first
    ///    launch onward. A forensic examiner cannot correlate its creation timestamp
    ///    with Secure Mode activation — it predates activation by design.
    ///
    /// 2. **Step 4 cryptographic container**: when Secure Mode is activated, the real
    ///    blob holds sensitive contact fields and vault PEKs that are locked out of the
    ///    main SQLite store by key rotation. Deactivation reads the blob and restores
    ///    those fields under a new key.
    ///
    /// Phase 1 implements only the deniability maintenance path. Step 4 adds
    /// `seal(contacts:vaultPEKs:)` and `unseal()` using the same crypto primitives.
    enum Blob {

        // MARK: - Constants

        private static let appGroup:  String        = "group.com.occulta.shared"
        private static let directory: String        = "blobs"
        /// HKDF info string for blob key derivation.
        /// Must match exactly across Phase 1 and Step 4 — changing this
        /// invalidates all existing blob files.
        private static let hkdfInfo:  Data          = Data("blob-key".utf8)
        /// Smallest plaintext bucket in bytes. A no-op payload lands here.
        /// Even 256 bytes produces a ciphertext (284 bytes on disk) that is
        /// plausibly sized for a real payload with a handful of contacts.
        static let minBucket:         Int           = 256
        /// Rewrite the blob after this interval so Last-Modified timestamps
        /// are not correlated with meaningful events (PIN entry, activation, etc.).
        private static let maxAge:    TimeInterval  = 86_400  // 24 h

        // MARK: - Maintenance

        /// Creates the no-op blob on first launch; rewrites it when the file is
        /// older than 24 hours.
        ///
        /// Called from `OccultaApp.init()`, gated on the `secureMode` feature flag.
        /// Fails silently — any error is non-fatal and will be retried on the next
        /// launch. On a fresh install, calling this also creates the SE key as a
        /// side effect, decoupling the Keychain key-creation timestamp from the
        /// moment Secure Mode is first configured.
        static func maintainNoOpBlob() {
            guard let dir = self.blobDirectory() else { return }

            if let existing = self.findBlob(in: dir) {
                guard self.isStale(existing) else { return }
                try? FileManager.default.removeItem(at: existing)
            }

            self.writeNoOpBlob(to: dir)
        }

        /// Unconditionally replaces the current blob with a fresh no-op payload.
        ///
        /// Unlike `maintainNoOpBlob()`, this ignores the 24-hour staleness check
        /// and always rewrites. Called by `OccultaApp` on every `ModelContext` save
        /// (debounced 30 s) so the blob's Last-Modified timestamp mirrors normal app
        /// activity rather than spiking only at meaningful events (activation, etc.).
        ///
        /// **Caller contract:** only call when Secure Mode is not active. When the
        /// blob holds a real payload, this call destroys it. `OccultaApp` gates on
        /// `security.state == .noPIN || security.state == .pinOnly`.
        static func rewriteNoOpBlob() {
            guard let dir = self.blobDirectory() else { return }
            if let existing = self.findBlob(in: dir) {
                try? FileManager.default.removeItem(at: existing)
            }
            self.writeNoOpBlob(to: dir)
        }

        // MARK: - Key derivation (shared with Step 4)

        /// Derives the 256-bit blob encryption key from the SE-bound key via HKDF-SHA256.
        ///
        /// Domain-separated from PIN verifier keys by the `"blob-key"` info string.
        /// Compromise of the blob key does not compromise PIN verification.
        ///
        /// - Parameter seKey: The `SymmetricKey` returned by `Manager.Key().deriveSecureModeKey()`.
        /// - Returns: A 32-byte `SymmetricKey` for AES-256-GCM blob encryption, or `nil`
        ///   if `seKey` is the wrong length for HKDF input (should never happen in practice).
        static func deriveBlobKey(from seKey: SymmetricKey) -> SymmetricKey? {
            HKDF<SHA256>.deriveKey(inputKeyMaterial: seKey, info: hkdfInfo, outputByteCount: 32)
        }

        // MARK: - Bucket sizing (shared with Step 4)

        /// Returns the smallest power-of-2 bucket size ≥ `contentLength`, with a floor
        /// of `minBucket`.
        ///
        /// Padded before encryption so the resulting file size reveals only a tier —
        /// "this payload is between 256 and 512 bytes" — not the exact contact or
        /// vault count.
        ///
        /// - Parameter contentLength: Byte length of the plaintext to be encrypted.
        /// - Returns: Bucket size in bytes (always a power of 2, always ≥ `minBucket`).
        static func bucketSize(for contentLength: Int) -> Int {
            var size = minBucket
            while size < contentLength { size *= 2 }
            return size
        }

        // MARK: - Seal / Unseal (Step 4)

        enum BlobError: Error {
            /// No `.occbak` file found in the blobs directory.
            case noBlobFound
            /// AES-GCM seal failed or the blob directory is unavailable.
            case encryptionFailed
            /// AES-GCM open failed — wrong key, corrupt file, or truncated data.
            case decryptionFailed
        }

        /// Encrypts `payload` and writes it as the current blob, replacing whatever
        /// file was there before (no-op or a previous real payload).
        ///
        /// The plaintext is bucket-padded before sealing so the file size reveals
        /// only a tier, not the contact or vault count.
        ///
        /// **Caller contract:** zero the `pekBytes` fields in all `VaultPEKRecord`
        /// instances after this method returns — those bytes are value-typed and
        /// cannot be zeroed from inside this method.
        ///
        /// - Parameter directory: Override the default app-group blob directory.
        ///   Pass `nil` (default) in production; pass a per-test temp URL in unit tests
        ///   to avoid cross-test blob collisions when tests run concurrently.
        static func seal(_ payload: BlobPayload, blobKey: SymmetricKey, directory: URL? = nil) throws {
            guard let dir = directory ?? self.blobDirectory() else { throw BlobError.encryptionFailed }

            // Replace existing blob (no-op or previous real payload).
            if let existing = self.findBlob(in: dir) {
                try FileManager.default.removeItem(at: existing)
            }

            // Encode → pad → seal. Zero the plaintext buffer before returning.
            var plaintext = try JSONEncoder().encode(payload)
            let padded    = self.bucketSize(for: plaintext.count)
            if plaintext.count < padded {
                plaintext.append(contentsOf: repeatElement(0, count: padded - plaintext.count))
            }
            defer {
                plaintext.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
            }

            guard let combined = try? AES.GCM.seal(plaintext, using: blobKey).combined else {
                throw BlobError.encryptionFailed
            }

            let url = dir.appendingPathComponent("\(UUID().uuidString).occbak")
            try combined.write(to: url, options: .completeFileProtection)
            var mutableURL = url
            var values     = URLResourceValues()
            values.isExcludedFromBackup = true
            try mutableURL.setResourceValues(values)
        }

        /// Decrypts the current blob and returns its payload.
        ///
        /// Throws `BlobError.noBlobFound` when no `.occbak` file exists (the blob
        /// directory is empty or was never written). Throws `BlobError.decryptionFailed`
        /// when the file exists but cannot be opened with `blobKey` — wrong key or
        /// corrupt data. Both are fatal for the deactivation sequence.
        ///
        /// - Parameter directory: Override the default app-group blob directory.
        ///   Must match the `directory` passed to `seal`. Pass `nil` (default) in production.
        static func unseal(blobKey: SymmetricKey, directory: URL? = nil) throws -> BlobPayload {
            guard let dir = directory ?? self.blobDirectory(),
                  let url = self.findBlob(in: dir)
            else { throw BlobError.noBlobFound }

            let combined = try Data(contentsOf: url)
            guard let box       = try? AES.GCM.SealedBox(combined: combined),
                  let plaintext = try? AES.GCM.open(box, using: blobKey)
            else { throw BlobError.decryptionFailed }

            // Strip bucket-padding zeros before decoding. seal() pads the plaintext to the
            // nearest power-of-2 bucket size using zero bytes; NSJSONSerialization rejects
            // any trailing bytes after valid JSON. All data fields in BlobPayload are
            // base64-encoded so the JSON itself never contains 0x00 bytes.
            let jsonEnd = plaintext.firstIndex(of: 0) ?? plaintext.endIndex
            return try JSONDecoder().decode(BlobPayload.self, from: plaintext[..<jsonEnd])
        }

        // MARK: - Private helpers

        private static func blobDirectory() -> URL? {
            guard let container = FileManager.default
                .containerURL(forSecurityApplicationGroupIdentifier: appGroup)
            else { return nil }
            let dir = container.appendingPathComponent(directory)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            return dir
        }

        /// Returns the first `.occbak` file in the blobs directory, if any.
        private static func findBlob(in dir: URL) -> URL? {
            let files = try? FileManager.default.contentsOfDirectory(
                at: dir, includingPropertiesForKeys: [.contentModificationDateKey]
            )
            return files?.first { $0.pathExtension == "occbak" }
        }

        private static func isStale(_ url: URL) -> Bool {
            guard
                let values   = try? url.resourceValues(forKeys: [.contentModificationDateKey]),
                let modified = values.contentModificationDate
            else { return true }
            return Date().timeIntervalSince(modified) >= maxAge
        }

        private static func writeNoOpBlob(to dir: URL) {
            guard
                let seKey   = try? Manager.Key().deriveSecureModeKey(),
                let blobKey = self.deriveBlobKey(from: seKey),
                let payload = self.encryptedNoOpPayload(using: blobKey)
            else { return }

            let url = dir.appendingPathComponent("\(UUID().uuidString).occbak")

            do {
                try payload.write(to: url, options: .completeFileProtection)
                var mutableURL = url
                var values     = URLResourceValues()
                values.isExcludedFromBackup = true
                try mutableURL.setResourceValues(values)
            } catch {
                // Remove partial file on any failure; next launch will retry.
                try? FileManager.default.removeItem(at: url)
            }
        }

        /// Encrypts a bucket-sized block of random bytes as the no-op payload.
        ///
        /// The plaintext is all random — indistinguishable from a real serialised
        /// payload after AES-GCM encryption. A random nonce is generated per write
        /// so each rewrite produces a completely different ciphertext.
        private static func encryptedNoOpPayload(using key: SymmetricKey) -> Data? {
            let size    = self.bucketSize(for: 0)
            var random  = Data(count: size)
            let status  = random.withUnsafeMutableBytes {
                SecRandomCopyBytes(kSecRandomDefault, size, $0.baseAddress!)
            }
            guard status == errSecSuccess else { return nil }
            return try? AES.GCM.seal(random, using: key).combined
        }
    }
}

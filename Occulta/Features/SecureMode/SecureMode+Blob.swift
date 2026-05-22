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
            guard let dir = blobDirectory() else { return }

            if let existing = findBlob(in: dir) {
                guard isStale(existing) else { return }
                try? FileManager.default.removeItem(at: existing)
            }

            writeNoOpBlob(to: dir)
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
                let blobKey = deriveBlobKey(from: seKey),
                let payload = encryptedNoOpPayload(using: blobKey)
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
            let size    = bucketSize(for: 0)
            var random  = Data(count: size)
            let status  = random.withUnsafeMutableBytes {
                SecRandomCopyBytes(kSecRandomDefault, size, $0.baseAddress!)
            }
            guard status == errSecSuccess else { return nil }
            return try? AES.GCM.seal(random, using: key).combined
        }
    }
}

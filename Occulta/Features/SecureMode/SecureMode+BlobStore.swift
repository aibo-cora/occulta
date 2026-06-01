//
//  SecureMode+BlobStore.swift
//  Occulta
//
//  BlobStore protocol and production AppGroupBlobStore implementation.
//  Manager.Blob owns all cryptography (padding, AES-GCM, HKDF key derivation).
//  BlobStore implementations handle only raw ciphertext I/O.
//

import Foundation

// MARK: - Protocol

/// Blob I/O back-end. All crypto lives in `Manager.Blob`; implementations
/// handle only reading and writing raw ciphertext bytes.
///
/// Phase 1: `AppGroupBlobStore` only. Phase 2 adds external destinations
/// (security-scoped URLs, etc.) without touching `Manager.Blob` or
/// `Manager.Security`.
protocol BlobStore {
    /// Write already-encrypted, already-padded ciphertext, replacing any
    /// existing blob at this destination.
    func write(_ data: Data) throws

    /// Return raw ciphertext. Throws `Manager.Blob.BlobError.noBlobFound`
    /// when no blob exists at this destination.
    func read() throws -> Data

    /// Delete the current blob. No-op if absent.
    func delete()

    /// True if a blob file exists at this destination (content not checked).
    var hasBlob: Bool { get }
}

// MARK: - AppGroupBlobStore

/// Production implementation — reads and writes a single `.occbak` file in
/// the Secure Mode blobs directory inside the shared app group container.
///
/// File attributes applied on every write:
///   • `.completeFileProtection` — device must be unlocked to read.
///   • `isExcludedFromBackup = true` — never included in iCloud or iTunes backups.
///
/// `Manager.Blob`'s no-op maintenance (`maintainNoOpBlob`, `rewriteNoOpBlob`)
/// always uses this same app group path directly, independent of which store
/// is active for the real payload — invariant I6.
struct AppGroupBlobStore: BlobStore {

    private static let appGroup  = "group.com.occulta.shared"
    private static let directory = "blobs"

    // MARK: - BlobStore

    func write(_ data: Data) throws {
        guard let dir = Self.blobDirectory() else {
            throw Manager.Blob.BlobError.encryptionFailed
        }
        if let existing = Self.findBlob(in: dir) {
            try FileManager.default.removeItem(at: existing)
        }
        let url = dir.appendingPathComponent("\(UUID().uuidString).occbak")
        try data.write(to: url, options: .completeFileProtection)
        var mutableURL = url
        var values     = URLResourceValues()
        values.isExcludedFromBackup = true
        try mutableURL.setResourceValues(values)
    }

    func read() throws -> Data {
        guard let dir = Self.blobDirectory(),
              let url = Self.findBlob(in: dir)
        else { throw Manager.Blob.BlobError.noBlobFound }
        return try Data(contentsOf: url)
    }

    func delete() {
        guard let dir = Self.blobDirectory(),
              let url = Self.findBlob(in: dir)
        else { return }
        try? FileManager.default.removeItem(at: url)
    }

    var hasBlob: Bool {
        guard let dir = Self.blobDirectory() else { return false }
        return Self.findBlob(in: dir) != nil
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

    /// Returns the most recently modified `.occbak` file in `dir`, or nil.
    private static func findBlob(in dir: URL) -> URL? {
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
}

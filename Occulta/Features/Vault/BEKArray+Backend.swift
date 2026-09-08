//
//  BEKArray+Backend.swift
//  Occulta
//
//  BEKArrayBackend protocol and production AppGroupBEKArrayBackend.
//  Raw ciphertext I/O only — no crypto, no slot logic. That lives in the
//  higher-level type built on top of this (not yet built), the same split
//  Manager.LayerStore already uses over LayerStoreBackend.
//

import Foundation

// MARK: - Protocol

/// Raw ciphertext I/O for the 32-slot BEK array. No crypto knowledge — AES-GCM,
/// per-slot AAD, and the full-array-reseal write pattern all live one level up.
/// Abstracted for testability, same shape as `LayerStoreBackend`.
protocol BEKArrayBackend {
    func write(_ data: Data) throws
    func read() throws -> Data
    func delete()
    var exists: Bool { get }
}

/// Errors specific to this raw I/O layer — no encryption/decryption happens here,
/// so `VaultManager.BackupError`'s cases don't fit; that type is also the wrong
/// layer to depend on from a backend this low-level.
enum BEKArrayBackendError: Error {
    /// The app-group container itself wasn't reachable.
    case directoryUnavailable
    /// No file exists yet — the array hasn't been created, or was deleted.
    case notFound
}

// MARK: - AppGroupBEKArrayBackend

/// Production backend — reads and writes a single `.occbak` file in its own
/// directory inside the shared app group container.
///
/// **Own directory, not the shared `"blobs"` pool — deliberate, interim,
/// decided 2026-09-08.** `VAULT_KEY_LAYERING.md` §8 item 8: `AppGroupLayerStoreBackend
/// .findFile()` selects by newest-modification-date among `.occbak` files, not by
/// which key opens them — item 5's "disambiguated by which key opens it" was never
/// actually implemented. Joining the shared directory today would make the contact
/// blob's own `read()` nondeterministically return whichever file was written most
/// recently. Fixing that is separate, deferred work; this directory keeps the two
/// features from colliding until it lands. Accepted cost: a second directory is a
/// milder version of the multi-directory signal item 5 exists to close.
///
/// File attributes applied on every write, matching `AppGroupLayerStoreBackend`
/// exactly:
///   • `.completeFileProtection` — device must be unlocked to read.
///   • `isExcludedFromBackup = true` — never included in iCloud or iTunes backups.
struct AppGroupBEKArrayBackend: BEKArrayBackend {

    private static let appGroup  = "group.com.occulta.shared"
    private static let directory = "cache"

    func write(_ data: Data) throws {
        guard let dir = Self.storeDirectory() else {
            throw BEKArrayBackendError.directoryUnavailable
        }
        // Capture the old file URL BEFORE writing the new one.
        // Write first, delete after — so the directory is never momentarily empty,
        // and a crash between write and delete leaves the old file intact.
        let old = Self.findFile(in: dir)
        let url = dir.appendingPathComponent("\(UUID().uuidString).occbak")
        try data.write(to: url, options: .completeFileProtection)
        var mutableURL = url
        var values     = URLResourceValues()
        values.isExcludedFromBackup = true
        try mutableURL.setResourceValues(values)
        if let old { try? FileManager.default.removeItem(at: old) }
    }

    func read() throws -> Data {
        guard let dir = Self.storeDirectory(),
              let url = Self.findFile(in: dir)
        else { throw BEKArrayBackendError.notFound }
        return try Data(contentsOf: url)
    }

    func delete() {
        guard let dir = Self.storeDirectory(),
              let url = Self.findFile(in: dir)
        else { return }
        try? FileManager.default.removeItem(at: url)
    }

    var exists: Bool {
        guard let dir = Self.storeDirectory() else { return false }
        return Self.findFile(in: dir) != nil
    }

    private static func storeDirectory() -> URL? {
        guard let container = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroup)
        else { return nil }
        let dir = container.appendingPathComponent(directory)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// Selects by newest modification date among `.occbak` files — correct here
    /// because exactly one file (this backend's own) is ever written to this
    /// directory. Not a template to copy into a shared directory without first
    /// fixing the selection logic per the doc comment above.
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
}

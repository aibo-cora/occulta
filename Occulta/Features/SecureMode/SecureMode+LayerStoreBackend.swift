//
//  SecureMode+LayerStoreBackend.swift
//  Occulta
//
//  LayerStoreBackend protocol and production AppGroupLayerStoreBackend.
//
//  Unified 2026-09-09 (VAULT_KEY_LAYERING.md item 13, Part A) to be shared between
//  Manager.LayerStore (contacts) and VaultManager.Backup.LayerStore (backup key) — the
//  two concrete backends were identical except for their directory constant, which
//  file's own crypto/logic layer error each one threw on failure, and whether
//  modificationDate was tracked. Manager.LayerStore and its contact blob were deleted
//  whole (Removal Stage 2, `plan.md`). VaultManager.Backup.LayerStore, this protocol's
//  last remaining consumer, was itself deleted 2026-09-11 when the BEK moved off the
//  32-slot array onto ordinary SwiftData rows (`VAULT_KEY_LAYERING.md`) — this protocol
//  currently has **no consumer**, kept deliberately: `RECOVERY_BUFFER_LAYERING.md`'s own
//  future per-depth restore-state container was already planned to reuse it.
//
//  Backends handle only raw ciphertext I/O — crypto lives in the consuming layer.
//

import Foundation

// MARK: - Errors

/// Raw-I/O failures, shared by every consumer of `LayerStoreBackend` — no crypto
/// knowledge here, so this is deliberately not either consumer's own `Error` type.
/// Each consumer catches and translates these at its own call sites.
enum LayerStoreBackendError: Error {
    /// The app-group container itself wasn't reachable.
    case directoryUnavailable
    /// No file exists yet at this backend's directory.
    case notFound
}

// MARK: - Protocol

/// Raw ciphertext I/O for a 32-slot layer store. No crypto knowledge — all AES-GCM
/// lives in the consuming crypto/logic layer (`VaultManager.Backup.LayerStore`, its
/// sole consumer since `Manager.LayerStore` was deleted — Removal Stage 2, `plan.md`).
/// Abstracted for testability.
protocol LayerStoreBackend {
    func write(_ data: Data) throws
    func read() throws -> Data
    func delete()
    var exists: Bool { get }
    /// Modification date of the backing store; nil when unavailable or non-persistent.
    var modificationDate: Date? { get }
}

// MARK: - AppGroupLayerStoreBackend

/// Production backend — reads and writes a single `.occbak` file in its own
/// directory inside the shared app group container. One instance per consumer,
/// each with its own `directory` — contacts use `"blobs"` (the original shared
/// pool, still awaiting the disambiguation-by-key fix `VAULT_KEY_LAYERING.md`
/// item 8 tracks), the backup key uses `"cache"` (its own, interim directory, same
/// item). Distinct directories keep the two features from colliding until that
/// fix lands; unifying the *type* doesn't require unifying the *directory* first.
///
/// File attributes applied on every write:
///   • `.completeFileProtection` — device must be unlocked to read.
///   • `isExcludedFromBackup = true` — never included in iCloud or iTunes backups.
struct AppGroupLayerStoreBackend: LayerStoreBackend {

    private static let appGroup = "group.com.occulta.shared"
    private let directory: String

    init(directory: String) {
        self.directory = directory
    }

    func write(_ data: Data) throws {
        guard let dir = self.storeDirectory() else {
            throw LayerStoreBackendError.directoryUnavailable
        }
        // Capture the old file URL BEFORE writing the new one.
        // Write first, delete after — so the directory is never momentarily empty.
        // A crash between write and delete leaves two files; findFile returns the
        // newer one (correct). A crash during write leaves the old file intact (I6).
        let old = self.findFile(in: dir)
        let url = dir.appendingPathComponent("\(UUID().uuidString).occbak")
        try data.write(to: url, options: .completeFileProtection)
        var mutableURL = url
        var values     = URLResourceValues()
        values.isExcludedFromBackup = true
        try mutableURL.setResourceValues(values)
        if let old { try? FileManager.default.removeItem(at: old) }
    }

    func read() throws -> Data {
        guard let dir = self.storeDirectory(),
              let url = self.findFile(in: dir)
        else { throw LayerStoreBackendError.notFound }
        return try Data(contentsOf: url)
    }

    func delete() {
        guard let dir = self.storeDirectory(),
              let url = self.findFile(in: dir)
        else { return }
        try? FileManager.default.removeItem(at: url)
    }

    var exists: Bool {
        guard let dir = self.storeDirectory() else { return false }
        return self.findFile(in: dir) != nil
    }

    var modificationDate: Date? {
        guard let dir = self.storeDirectory(),
              let url = self.findFile(in: dir)
        else { return nil }
        return (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
    }

    private func storeDirectory() -> URL? {
        guard let container = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: Self.appGroup)
        else { return nil }
        let dir = container.appendingPathComponent(self.directory)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// Selects by newest modification date among `.occbak` files — correct here
    /// because exactly one file (this backend's own) is ever written to this
    /// directory. Not a template to copy into a shared directory without first
    /// fixing the selection logic (`VAULT_KEY_LAYERING.md` item 8's first finding).
    private func findFile(in dir: URL) -> URL? {
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

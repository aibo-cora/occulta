//
//  SecureMode+LayerStoreBackend.swift
//  Occulta
//
//  LayerStoreBackend protocol and production AppGroupLayerStoreBackend.
//  Manager.LayerStore owns all cryptography. Backends handle only raw ciphertext I/O.
//

import Foundation

// MARK: - Protocol

/// Raw ciphertext I/O for the layer store. No crypto knowledge — all AES-GCM
/// lives in `Manager.LayerStore`. Abstracted for testability.
protocol LayerStoreBackend {
    func write(_ data: Data) throws
    func read() throws -> Data
    func delete()
    var exists: Bool { get }
}

// MARK: - AppGroupLayerStoreBackend

/// Production backend — reads and writes a single `.occbak` file in the Secure Mode
/// store directory inside the shared app group container.
///
/// File attributes applied on every write:
///   • `.completeFileProtection` — device must be unlocked to read.
///   • `isExcludedFromBackup = true` — never included in iCloud or iTunes backups.
struct AppGroupLayerStoreBackend: LayerStoreBackend {

    private static let appGroup  = "group.com.occulta.shared"
    private static let directory = "blobs"

    func write(_ data: Data) throws {
        guard let dir = Self.storeDirectory() else {
            throw Manager.LayerStore.Error.encryptionFailed
        }
        if let existing = Self.findFile(in: dir) {
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
        guard let dir = Self.storeDirectory(),
              let url = Self.findFile(in: dir)
        else { throw Manager.LayerStore.Error.notFound }
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

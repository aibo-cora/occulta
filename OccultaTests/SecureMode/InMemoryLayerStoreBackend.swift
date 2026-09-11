//
//  InMemoryLayerStoreBackend.swift
//  OccultaTests
//
//  Thread-unsafe in-memory LayerStoreBackend for unit tests.
//  Eliminates temp-directory creation/cleanup and app-group container access.
//

import Foundation
@testable import Occulta

/// In-memory backend for unit tests only. Not thread-safe.
///
/// Currently has **no consumer** — `VaultManager.Backup.LayerStore`, its last one, was
/// itself deleted when the BEK moved off the 32-slot array onto ordinary SwiftData rows
/// (`VAULT_KEY_LAYERING.md`, same change `Manager.LayerStore` — this type's original
/// consumer — was deleted in, Removal Stage 2, `plan.md`). Kept, not deleted, per explicit
/// instruction: `RECOVERY_BUFFER_LAYERING.md`'s own future per-depth restore-state
/// container was planned to reuse `LayerStoreBackend`, and this is its test double.
final class InMemoryLayerStoreBackend: LayerStoreBackend {
    private var stored: Data?

    func write(_ data: Data) throws {
        self.stored = data
    }

    func read() throws -> Data {
        guard let stored else { throw LayerStoreBackendError.notFound }
        return stored
    }

    func delete() {
        self.stored = nil
    }

    var exists: Bool { self.stored != nil }

    /// Defaults to `nil` — non-persistent, therefore never stale, which is what every
    /// existing test relies on. Settable so the maintenance-cadence tests can age the file.
    var modificationDate: Date? = nil
}

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
/// Injected via `Manager.LayerStore(backend: InMemoryLayerStoreBackend())`.
final class InMemoryLayerStoreBackend: LayerStoreBackend {
    private var stored: Data?

    func write(_ data: Data) throws {
        self.stored = data
    }

    func read() throws -> Data {
        guard let stored else { throw Manager.LayerStore.Error.notFound }
        return stored
    }

    func delete() {
        self.stored = nil
    }

    var exists: Bool { self.stored != nil }

    // Non-persistent — never stale.
    var modificationDate: Date? { nil }
}

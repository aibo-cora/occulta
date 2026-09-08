//
//  InMemoryBEKArrayBackend.swift
//  OccultaTests
//
//  Thread-unsafe in-memory BEKArrayBackend for unit tests.
//  Same shape as InMemoryLayerStoreBackend — eliminates app-group container access.
//

import Foundation
@testable import Occulta

/// In-memory backend for unit tests only. Not thread-safe.
final class InMemoryBEKArrayBackend: BEKArrayBackend {
    private var stored: Data?

    func write(_ data: Data) throws {
        self.stored = data
    }

    func read() throws -> Data {
        guard let stored else { throw BEKArrayBackendError.notFound }
        return stored
    }

    func delete() {
        self.stored = nil
    }

    var exists: Bool { self.stored != nil }
}

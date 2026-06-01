//
//  InMemoryBlobStore.swift
//  OccultaTests
//
//  Thread-unsafe in-memory BlobStore for unit tests.
//  Eliminates temp-directory creation/cleanup and app-group container access.
//

import Foundation
@testable import Occulta

/// In-memory BlobStore for use in unit tests only.
///
/// Stores a single encrypted blob as a `Data` value. Not thread-safe.
/// Injected via `Manager.Security(blobStore: InMemoryBlobStore())` in
/// `makeSecurityAndManagers()`.
final class InMemoryBlobStore: BlobStore {
    private var stored: Data?

    func write(_ data: Data) throws {
        self.stored = data
    }

    func read() throws -> Data {
        guard let stored else { throw Manager.Blob.BlobError.noBlobFound }
        return stored
    }

    func delete() {
        self.stored = nil
    }

    var hasBlob: Bool { self.stored != nil }
}

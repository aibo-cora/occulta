//
//  AttachmentWriteTests.swift
//  OccultaTests
//
//  `AttachmentManager.encrypt(_:to:)` seals each 256 KB chunk straight to disk instead of
//  assembling the whole sealed file in memory first. These pin that the bytes on disk are still
//  the `.eatt` format every reader expects, whatever the chunk alignment, and that a failed
//  write leaves nothing behind.
//

import Testing
import CryptoKit
import Foundation
@testable import Occulta

@MainActor struct AttachmentWriteTests {
    private static let chunkSize  = 262_144
    private static let headerSize = 101
    private static let tagSize    = 16

    private func scratchDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("attachment-write-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test(
        "round-trips at every chunk alignment",
        arguments: [0, 1, 262_143, 262_144, 262_145, 3 * 262_144, 3 * 262_144 + 17]
    )
    func roundTrips(size: Int) async throws {
        let dir = try self.scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let manager = AttachmentManager(contactKey: SymmetricKey(size: .bits256))
        let plain   = Data((0..<size).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) })
        let url     = dir.appendingPathComponent("file.eatt")

        try manager.encrypt(plain, to: url)

        #expect(AttachmentManager.isSealed(at: url))
        #expect(try await manager.data(at: url) == plain)
    }

    @Test("sealed length is header + plaintext + one tag per chunk")
    func sealedLength() throws {
        let dir = try self.scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let manager = AttachmentManager(contactKey: SymmetricKey(size: .bits256))
        let size    = 3 * Self.chunkSize + 17
        let url     = dir.appendingPathComponent("file.eatt")

        try manager.encrypt(Data(count: size), to: url)

        let onDisk = try #require(FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int)
        #expect(onDisk == Self.headerSize + size + 4 * Self.tagSize)
    }

    @Test("progress reaches 1 once, at the last chunk")
    func progress() async throws {
        let dir = try self.scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let manager = AttachmentManager(contactKey: SymmetricKey(size: .bits256))
        let url     = dir.appendingPathComponent("file.eatt")

        var last = 0.0
        for try await p in manager.encryptWithProgress(Data(count: 2 * Self.chunkSize + 1), to: url) { last = p }

        #expect(last == 1.0)
    }

    @Test("overwrites a file already at the destination")
    func overwrites() async throws {
        let dir = try self.scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let manager = AttachmentManager(contactKey: SymmetricKey(size: .bits256))
        let url     = dir.appendingPathComponent("file.eatt")
        let second  = Data(repeating: 0xAB, count: 10)

        try manager.encrypt(Data(count: 2 * Self.chunkSize), to: url)
        try manager.encrypt(second, to: url)

        #expect(try await manager.data(at: url) == second)
    }

    @Test("a write that cannot start throws and leaves no file")
    func failedWriteLeavesNothing() throws {
        let dir = try self.scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let manager = AttachmentManager(contactKey: SymmetricKey(size: .bits256))
        let url     = dir.appendingPathComponent("missing-subdirectory").appendingPathComponent("file.eatt")

        #expect(throws: (any Error).self) { try manager.encrypt(Data(count: 10), to: url) }
        #expect(!FileManager.default.fileExists(atPath: url.path))
    }
}

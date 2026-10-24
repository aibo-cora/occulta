//
//  NoCacheFileTests.swift
//  OccultaTests
//
//  STREAMING_SPEC §8.2: the I/O helpers that receive passes 1 and 2, the staged-file reader, the import loop
//  and the `.eatt` writers share. No Enclave.
//

import Testing
import CryptoKit
import Foundation
@testable import Occulta
@testable import OccultaFormats

@Suite("NoCacheFile")
struct NoCacheFileTests {

    private func scratch() throws -> URL { try streamedScratchDirectory() }

    // MARK: Reader

    @Test("a positioned read returns the bytes at that offset, and fewer only at the end")
    func positionedRead() throws {
        let dir = try self.scratch(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("a")
        let bytes = streamedPattern(1000)
        try bytes.write(to: url)

        let reader = try NoCacheFile.reader(url)
        #expect(reader.size == 1000)
        #expect(try reader.read(at: 100, count: 50) == bytes[100..<150])
        #expect(try reader.read(at: 990, count: 50) == bytes[990..<1000])
        #expect(try reader.read(at: 1000, count: 10).isEmpty)
        #expect(try reader.read(at: 0, count: 0).isEmpty)
    }

    @Test("forEachChunk walks a range in order, one piece at a time, the last one short")
    func chunkWalk() throws {
        let dir = try self.scratch(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("a")
        let bytes = streamedPattern(1000)
        try bytes.write(to: url)

        var pieces: [Data] = []
        try NoCacheFile.reader(url).forEachChunk(range: 10..<995, size: 400) { pieces.append($0) }

        #expect(pieces.map(\.count) == [400, 400, 185])
        #expect(pieces.reduce(Data(), +) == bytes[10..<995])
    }

    @Test("a range that runs past the end of the file is an error, not a short read")
    func truncatedRange() throws {
        let dir = try self.scratch(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("a")
        try streamedPattern(100).write(to: url)

        #expect(throws: NoCacheFile.Reader.Errors.truncated) {
            try NoCacheFile.reader(url).forEachChunk(range: 0..<200, size: 64) { _ in }
        }
    }

    @Test("an unlinked file stays readable through its handle")
    func readableAfterUnlink() throws {
        let dir = try self.scratch(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("a")
        let bytes = streamedPattern(5000)
        try bytes.write(to: url)

        let reader = try NoCacheFile.reader(url)
        try FileManager.default.removeItem(at: url)

        #expect(!FileManager.default.fileExists(atPath: url.path))
        #expect(try reader.read(at: 0, count: 5000) == bytes)
    }

    @Test("a file that does not exist throws")
    func missingFile() {
        #expect(throws: (any Error).self) { _ = try NoCacheFile.reader(URL(fileURLWithPath: "/nonexistent/\(UUID().uuidString)")) }
    }

    // MARK: Writer

    @Test("a finished writer leaves the bytes, excluded from backup")
    func finishedWriter() throws {
        let dir = try self.scratch(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("a")

        let writer = try NoCacheFile.writer(url)
        try writer.write(Data([1, 2, 3]))
        try writer.write(Data([4, 5]))
        #expect(writer.length == 5)
        try writer.finish()

        #expect(try Data(contentsOf: url) == Data([1, 2, 3, 4, 5]))
        #expect(try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true)
    }

    @Test("a header written last overwrites the space reserved for it")
    func overwrite() throws {
        let dir = try self.scratch(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("a")

        let writer = try NoCacheFile.writer(url)
        try writer.write(Data(count: 4))
        try writer.write(Data([9, 9]))
        try writer.overwrite(Data([1, 2, 3, 4]), at: 0)
        try writer.finish()

        #expect(try Data(contentsOf: url) == Data([1, 2, 3, 4, 9, 9]))
    }

    @Test("a writer dropped before it finishes removes its file")
    func droppedWriterDeletes() throws {
        let dir = try self.scratch(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("a")

        do {
            let writer = try NoCacheFile.writer(url)
            try writer.write(Data([1]))
            #expect(FileManager.default.fileExists(atPath: url.path))
        }

        #expect(!FileManager.default.fileExists(atPath: url.path))
    }

    @Test("abandon removes the file, and a writer that has been abandoned refuses more")
    func abandon() throws {
        let dir = try self.scratch(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("a")
        let writer = try NoCacheFile.writer(url)
        try writer.write(Data([1]))

        writer.abandon()

        #expect(!FileManager.default.fileExists(atPath: url.path))
        #expect(throws: NoCacheFile.Writer.Errors.closed) { try writer.write(Data([2])) }
        writer.abandon()   // twice is fine
    }

    @Test("abandoning after finish keeps the file")
    func abandonAfterFinish() throws {
        let dir = try self.scratch(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("a")
        let writer = try NoCacheFile.writer(url)
        try writer.write(Data([1]))
        try writer.finish()

        writer.abandon()

        #expect(FileManager.default.fileExists(atPath: url.path))
    }

    @Test("a writer into a directory that is not there throws, and leaves nothing")
    func badDestination() {
        let url = URL(fileURLWithPath: "/nonexistent/\(UUID().uuidString)/a")
        #expect(throws: (any Error).self) { _ = try NoCacheFile.writer(url) }
    }
}

// MARK: - The .eatt writers and reader on top of it

@Suite("Sealed attachment files on NoCacheFile")
@MainActor struct SealedAttachmentIOTests {

    private let manager = AttachmentManager(contactKey: SymmetricKey(size: .bits256))

    @Test("a streamed encryption round-trips, across several chunks and an exact multiple", arguments: [0, 1, 262_143, 262_144, 262_145, 786_432, 786_433])
    func streamingRoundTrip(size: Int) async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("a.eatt")
        let plaintext = streamedPattern(size)

        let encryptor = try self.manager.streamingEncryptor(to: url)
        var offset = 0
        while offset < plaintext.count {   // pieces that do not line up with the chunk size
            let end = min(offset + 65_537, plaintext.count)
            try encryptor.append(plaintext[offset..<end])
            offset = end
        }
        try encryptor.finalize()

        #expect(AttachmentManager.isSealed(at: url))
        #expect(try self.manager.plaintextSize(at: url) == size)
        #expect(try await self.manager.data(at: url) == plaintext)
    }

    @Test("a streamed encryption that is abandoned leaves no file")
    func abandonedEncryption() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("a.eatt")

        let encryptor = try self.manager.streamingEncryptor(to: url)
        try encryptor.append(streamedPattern(300_000))
        encryptor.abandon()

        #expect(!FileManager.default.fileExists(atPath: url.path))
    }

    @Test("a streamed encryption dropped unfinished leaves no file")
    func droppedEncryption() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("a.eatt")

        do {
            let encryptor = try self.manager.streamingEncryptor(to: url)
            try encryptor.append(streamedPattern(300_000))
        }

        #expect(!FileManager.default.fileExists(atPath: url.path))
    }

    @Test("a sealed file is excluded from backup")
    func sealedFileAttributes() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("a.eatt")
        let encryptor = try self.manager.streamingEncryptor(to: url)
        try encryptor.append(streamedPattern(10))
        try encryptor.finalize()

        #expect(try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true)
    }

    @Test("sealing a plaintext file in place goes through the reader, and a sealed file is left alone")
    func sealInPlace() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("plain.bin")
        let plaintext = streamedPattern(700_000)
        try plaintext.write(to: url)

        try self.manager.sealInPlace(at: url)
        #expect(AttachmentManager.isSealed(at: url))
        #expect(try await self.manager.data(at: url) == plaintext)

        let sealedBytes = try Data(contentsOf: url)
        try self.manager.sealInPlace(at: url)
        #expect(try Data(contentsOf: url) == sealedBytes)
    }

    @Test("the whole-file encryption writes the same format a streamed one reads")
    func wholeFileEncryption() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("a.eatt")
        let plaintext = streamedPattern(600_000)

        try self.manager.encrypt(plaintext, to: url)

        #expect(try await self.manager.data(at: url) == plaintext)
    }

    @Test("the at-rest chunk is the wire chunk: a sealed file's header says 262,144")
    func oneChunkConstant() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("a.eatt")
        try self.manager.encrypt(streamedPattern(10), to: url)

        let header = try NoCacheFile.reader(url).read(at: 0, count: 101)
        let chunkSize = header[5..<9].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        #expect(Int(chunkSize) == BodyStream.chunkSize)
    }
}

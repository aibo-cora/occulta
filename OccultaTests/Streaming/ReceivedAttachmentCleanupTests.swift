//
//  ReceivedAttachmentCleanupTests.swift
//  OccultaTests
//
//  Bugs 217, 218 and 219: what a received attachment leaves on disk, or holds in memory, when the message that carried it is
//  not shown, or is shown by a build that can't hold it.
//
//  217: an inline `.occ` writes each attachment, sealed, to `tmp/` before the message is presented. When the session ends
//  while the file is being opened the result is dropped, and when one write fails its siblings' files stay.
//  218: a streamed file begun after the receive was cancelled was created and finalised, and never deleted.
//  219: a streamed file labelled as an image was decrypted whole into memory to draw its thumbnail, whatever its size.
//

import Testing
import CryptoKit
import Foundation
import UIKit
@testable import Occulta
@testable import OccultaFormats

private struct FixedStagingKey: ComposeStagingKeyProviding {
    let key = SymmetricKey(size: .bits256)
    func deriveComposeStagingKey() throws -> SymmetricKey { self.key }
}

private func scratch() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("attachment-cleanup-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

private func contents(of directory: URL) -> [String] {
    (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
}

private func file(_ name: String, ext: String = "bin", bytes: Int = 1_000) -> OccultaFormats.File {
    OccultaFormats.File(content: Data(repeating: 7, count: bytes), format: .file(.init(name: name, extension: ext)), date: Date())
}

// MARK: - 217

@Suite("Bug 217 — sealed attachments of an inline message do not outlive a message that isn't shown")
@MainActor struct ReceivedAttachmentCleanupTests {

    struct WriteFailed: Error {}

    @Test("A basket sealed into a directory is removed with its files when the result is dropped", .ambientTestKeyManager)
    func droppedResultLeavesNothing() async throws {
        let dir = try scratch(); defer { try? FileManager.default.removeItem(at: dir) }
        let cm = try TestSupport.makeContactManager()
        let basket = Basket(files: [file("a"), file("b", ext: "txt"), inlineText("hi")], date: Date())

        let owned = try await cm.sealReceivedFiles(of: basket, owner: "never-met", stagingKeyProvider: FixedStagingKey(), in: dir)
        #expect(contents(of: dir).count == 2, "precondition: the two attachments are written")

        // What `processInboundFile` does with a result it will not show.
        owned.removeSealedFiles()

        #expect(contents(of: dir).isEmpty)
    }

    @Test("When a second file's write fails, the first file's is removed too", .ambientTestKeyManager)
    func failedWriteLeavesNothing() async throws {
        let dir = try scratch(); defer { try? FileManager.default.removeItem(at: dir) }
        let cm = try TestSupport.makeContactManager()
        let basket = Basket(files: [file("first", bytes: 10), file("second", bytes: 20)], date: Date())

        await #expect(throws: WriteFailed.self) {
            _ = try await cm.sealReceivedFiles(of: basket, owner: "never-met", stagingKeyProvider: FixedStagingKey(), in: dir) { manager, data, url in
                if data.count == 20 { throw WriteFailed() }
                try manager.encrypt(data, to: url)
            }
        }

        #expect(contents(of: dir).isEmpty, "files a failed seal wrote: \(contents(of: dir))")
    }

    private func inlineText(_ text: String) -> OccultaFormats.File {
        OccultaFormats.File(content: Data(text.utf8), format: .text, date: Date())
    }
}

// MARK: - 218

@Suite("Bug 218 — a streamed file begun after cancel() is not written")
struct StreamedReceiveCancelRaceTests {

    @Test("After abandonAll(), beginning and ending a trailing file leaves the directory empty")
    func beginAfterAbandonWritesNothing() throws {
        let dir = try scratch(); defer { try? FileManager.default.removeItem(at: dir) }
        let files = [file("a"), file("b")]
        let sink = ReceiveSink(
            manager: AttachmentManager(contactKey: SymmetricKey(size: .bits256)),
            plan: [0: dir.appendingPathComponent("a.bin"), 1: dir.appendingPathComponent("b.bin")], files: files
        )

        sink.abandonAll()
        // As `router.finish` would, for a trailing zero-length file, after the user's cancel.
        try? sink.begin(fileIndex: 1)
        try? sink.end()

        #expect(contents(of: dir).isEmpty, "left behind: \(contents(of: dir))")
    }

    @Test("Before any cancel, a file is begun and finished as before")
    func beginBeforeAbandonStillWrites() throws {
        let dir = try scratch(); defer { try? FileManager.default.removeItem(at: dir) }
        let sink = ReceiveSink(
            manager: AttachmentManager(contactKey: SymmetricKey(size: .bits256)),
            plan: [0: dir.appendingPathComponent("a.bin")], files: [file("a")]
        )

        try sink.begin(fileIndex: 0)
        try sink.write(Data(repeating: 1, count: 10))
        try sink.end()

        #expect(contents(of: dir) == ["a.bin"])
    }
}

// MARK: - 219

@Suite("Bug 219 — an image bubble does not decrypt a file the device can't hold")
@MainActor struct ReceivedImageMemoryTests {

    private func sealed(_ plaintext: Data, in dir: URL, key: SymmetricKey) throws -> URL {
        let url = dir.appendingPathComponent("\(UUID().uuidString).jpg")
        try AttachmentManager(contactKey: key).encrypt(plaintext, to: url)
        return url
    }

    private func jpeg() throws -> Data {
        let renderer = UIGraphicsImageRenderer(size: CGSize(width: 64, height: 64))
        return try #require(renderer.jpegData(withCompressionQuality: 0.8) { context in
            UIColor.red.setFill(); context.fill(CGRect(x: 0, y: 0, width: 64, height: 64))
        })
    }

    @Test("A file above the budget is refused from its header, before a byte is decrypted")
    func refusedBeforeDecrypting() async throws {
        let dir = try scratch(); defer { try? FileManager.default.removeItem(at: dir) }
        let key = SymmetricKey(size: .bits256)
        let url = try self.sealed(Data(repeating: 9, count: 2_000_000), in: dir, key: key)
        // The body is damaged: decrypting it would throw an authentication error, not the refusal.
        var handle = try FileHandle(forUpdating: url)
        try handle.seek(toOffset: 500); try handle.write(contentsOf: Data([0xFF])); try handle.close()
        handle = try FileHandle(forReadingFrom: url); try handle.close()

        let budget = MemoryGuard { MemoryGuard.headroom + 1_000_000 }

        await #expect(throws: OccultaBundle.BundleError.tooLargeForDevice) {
            _ = try await AttachmentManager(contactKey: key).displayImage(at: url, memoryGuard: budget)
        }
    }

    @Test("A file inside the budget still draws")
    func insideBudgetDraws() async throws {
        let dir = try scratch(); defer { try? FileManager.default.removeItem(at: dir) }
        let key = SymmetricKey(size: .bits256)
        let url = try self.sealed(try self.jpeg(), in: dir, key: key)

        let image = try await AttachmentManager(contactKey: key).displayImage(at: url, memoryGuard: MemoryGuard { Int.max })

        #expect(image.size.width > 0)
    }

    @Test("Images opened together decrypt one at a time")
    func imagesTakeTurns() async throws {
        let dir = try scratch(); defer { try? FileManager.default.removeItem(at: dir) }
        let key = SymmetricKey(size: .bits256)
        let manager = AttachmentManager(contactKey: key)
        let urls = try (0..<5).map { _ in try self.sealed(try self.jpeg(), in: dir, key: key) }
        let gate = ImageDecryptionGate()

        try await withThrowingTaskGroup(of: Void.self) { group in
            for url in urls {
                group.addTask { _ = try await manager.displayImage(at: url, memoryGuard: MemoryGuard { Int.max }, gate: gate) }
            }
            try await group.waitForAll()
        }

        #expect(await gate.peakInFlight == 1, "every image went through the gate, and never two at once")
    }

    @Test("The gate hands over to each waiter in turn, and a refused image gives its turn back")
    func gateTakesTurns() async throws {
        let dir = try scratch(); defer { try? FileManager.default.removeItem(at: dir) }
        let key = SymmetricKey(size: .bits256)
        let manager = AttachmentManager(contactKey: key)
        let big = try self.sealed(Data(repeating: 9, count: 2_000_000), in: dir, key: key)
        let small = try self.sealed(try self.jpeg(), in: dir, key: key)
        let gate = ImageDecryptionGate()
        let tight = MemoryGuard { MemoryGuard.headroom + 1_000_000 }

        await #expect(throws: OccultaBundle.BundleError.tooLargeForDevice) {
            _ = try await manager.displayImage(at: big, memoryGuard: tight, gate: gate)
        }
        // Had the refusal kept the turn, this would wait forever.
        let image = try await manager.displayImage(at: small, memoryGuard: tight, gate: gate)

        #expect(image.size.width > 0)
    }
}

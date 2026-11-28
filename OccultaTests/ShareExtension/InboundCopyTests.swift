//
//  InboundCopyTests.swift
//  OccultaTests
//
//  Bug 188: the share extension handed an inbound `.occ` to the app by loading it whole (`loadDataRepresentation`),
//  which a share extension's memory limit cannot take for a large bundle (Bug 183). `handoffInboundOCC` now copies
//  the provider's file with `NoCacheFile.copy` inside `loadFileRepresentation`'s handler.
//
//  `ShareViewController` can't be driven from the test host (D5), so what is pinned here is the copy step it calls and
//  the app's side of the handoff: that `InboundFile.open` opens the result. What is not covered: the extension's peak
//  memory in the real process (STREAMING_SPEC §8.4), the share sheet from Messages and Files, and the protection class a
//  file really lands in, which a Simulator doesn't enforce. Those need a device.
//

import Testing
import CryptoKit
import Foundation
@testable import Occulta
@testable import OccultaFormats

/// The process's physical footprint, in bytes.
private func footprint() -> UInt64 {
    var info  = task_vm_info_data_t()
    var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
    let status = withUnsafeMutablePointer(to: &info) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
        }
    }
    return status == KERN_SUCCESS ? UInt64(info.phys_footprint) : 0
}

/// Polls the footprint on its own thread while `work` runs, and returns the highest it saw above where it started.
private func peakGrowth(during work: () throws -> Void) rethrows -> UInt64 {
    final class Sampler: @unchecked Sendable {
        private let lock = NSLock()
        private var highest: UInt64 = 0
        private var running = true
        var isRunning: Bool { self.lock.withLock { self.running } }
        var peak: UInt64 { self.lock.withLock { self.highest } }
        func record(_ value: UInt64) { self.lock.withLock { self.highest = max(self.highest, value) } }
        func stop() { self.lock.withLock { self.running = false } }
    }

    let start = footprint()
    let sampler = Sampler()
    sampler.record(start)
    let thread = Thread {
        while sampler.isRunning {
            sampler.record(footprint())
            Thread.sleep(forTimeInterval: 0.002)
        }
    }
    thread.start()
    defer { sampler.stop() }

    try work()
    sampler.record(footprint())
    return sampler.peak > start ? sampler.peak - start : 0
}

/// A sparse file of `length` bytes with distinctive bytes at the start, across a chunk boundary, in the middle and at the end.
private func makeSparseFile(at url: URL, length: UInt64) throws -> [(offset: UInt64, bytes: Data)] {
    FileManager.default.createFile(atPath: url.path, contents: nil)
    let handle = try FileHandle(forWritingTo: url)
    defer { try? handle.close() }
    try handle.truncate(atOffset: length)

    let marks: [(offset: UInt64, bytes: Data)] = [
        (0, streamedPattern(64, seed: 1)),
        (1_048_576 - 20, streamedPattern(64, seed: 2)),
        (length / 2, streamedPattern(64, seed: 3)),
        (length - 64, streamedPattern(64, seed: 4)),
    ]
    for mark in marks {
        try handle.seek(toOffset: mark.offset)
        try handle.write(contentsOf: mark.bytes)
    }
    return marks
}

private func sha256(of url: URL) throws -> SHA256Digest {
    let reader = try NoCacheFile.reader(url)
    var hasher = SHA256()
    try reader.forEachChunk(range: 0..<reader.size, size: 1_048_576) { hasher.update(data: $0) }
    return hasher.finalize()
}

@Suite("Bug 188 — the inbound .occ is copied, not loaded", .serialized)
struct InboundCopyTests {

    private let fileManager = FileManager.default

    /// An `inbound/` directory as the extension makes it, with a destination name inside it.
    private func makeInbound() throws -> (root: URL, inbound: URL, destination: URL) {
        let root = try streamedScratchDirectory()
        let inbound = root.appendingPathComponent("inbound")
        try self.fileManager.createDirectory(at: inbound, withIntermediateDirectories: true)
        return (root, inbound, inbound.appendingPathComponent("\(UUID().uuidString).occ"))
    }

    // MARK: - Correctness

    @Test("the copy is byte for byte, at sizes either side of a chunk", arguments: [0, 1, 4095, 4096, 4097, 8192, 100_000])
    func byteForByte(length: Int) throws {
        let (root, inbound, destination) = try self.makeInbound()
        defer { try? self.fileManager.removeItem(at: root) }
        let source = root.appendingPathComponent("source.occ")
        let bytes = streamedPattern(length)
        try bytes.write(to: source)

        try NoCacheFile.copy(source, to: destination, chunkSize: 4096)

        #expect(try Data(contentsOf: destination) == bytes)
        #expect(try self.fileManager.contentsOfDirectory(atPath: inbound.path) == [destination.lastPathComponent])
        #expect(self.fileManager.fileExists(atPath: source.path), "the source is left to the system to remove")
    }

    @Test("a large source is copied exactly, and its size does not show up in memory")
    func largeSourceStaysOutOfMemory() throws {
        let (root, inbound, destination) = try self.makeInbound()
        defer { try? self.fileManager.removeItem(at: root) }
        let source = root.appendingPathComponent("source.occ")
        let length: UInt64 = 400 * 1_048_576
        let marks = try makeSparseFile(at: source, length: length)

        let growth = try peakGrowth { try NoCacheFile.copy(source, to: destination) }

        let copy = try NoCacheFile.reader(destination)
        #expect(copy.size == length)
        for mark in marks {
            #expect(try copy.read(at: mark.offset, count: mark.bytes.count) == mark.bytes, "offset \(mark.offset)")
        }
        #expect(try sha256(of: destination) == sha256(of: source))
        #expect(try self.fileManager.contentsOfDirectory(atPath: inbound.path) == [destination.lastPathComponent])

        // A 400 MB file moved through one 1 MiB chunk at a time. The bound is generous, since other suites run in
        // this process; the control below shows the meter does see a file of this size when it is loaded.
        #expect(growth < 100 * 1_048_576, "footprint grew by \(growth / 1_048_576) MB")
    }

    @Test("the control: loading the same file whole is visible to the meter")
    func controlLoadedWholeIsVisible() throws {
        let (root, _, _) = try self.makeInbound()
        defer { try? self.fileManager.removeItem(at: root) }
        let source = root.appendingPathComponent("source.occ")
        _ = try makeSparseFile(at: source, length: 400 * 1_048_576)

        var held: Data?
        let growth = try peakGrowth { held = try Data(contentsOf: source) }

        #expect(held?.count == 400 * 1_048_576)
        #expect(growth > 300 * 1_048_576, "footprint grew by only \(growth / 1_048_576) MB")
    }

    // MARK: - Protection

    @Test("the destination is created at complete protection and excluded from backup")
    func protectionIsSet() throws {
        let (root, _, destination) = try self.makeInbound()
        defer { try? self.fileManager.removeItem(at: root) }
        let source = root.appendingPathComponent("source.occ")
        try streamedPattern(5000).write(to: source)

        try NoCacheFile.copy(source, to: destination)

        // The Simulator keeps the class when it is asked for one; a device enforces it. What the class is on a device
        // is a device check (see the header), so a nil here is the Simulator not reporting, not a pass.
        let attributes = try self.fileManager.attributesOfItem(atPath: destination.path)
        if let protection = attributes[.protectionKey] as? FileProtectionType {
            #expect(protection == .complete)
        }
        #expect(try destination.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true)
    }

    @Test("the copy asks for complete protection at creation, not after, and does not clone the source")
    func protectionIsRequestedAtCreation() throws {
        // `NoCacheFile.Writer` creates the file with `.protectionKey: .complete` and `copy` has no `copyItem` or
        // `clonefile` in it; this reads both from the source, as `DataProtectionEntitlementTests` reads entitlements.
        let repoRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let text = try String(contentsOf: repoRoot.appendingPathComponent("Occulta/Services/NoCacheFile.swift"), encoding: .utf8)
        let copyBody = try #require(text.components(separatedBy: "static func copy(").dropFirst().first?.components(separatedBy: "// MARK: - Reader").first)

        #expect(text.contains("attributes: [.protectionKey: FileProtectionType.complete]"))
        #expect(copyBody.contains("Writer(url: destination)"))
        #expect(!copyBody.contains("copyItem"))
        #expect(!copyBody.contains("clonefile"))
        #expect(!copyBody.contains("copyfile"))
    }

    // MARK: - Failure leaves nothing

    @Test("a source that does not exist leaves nothing in inbound/")
    func missingSource() throws {
        let (root, inbound, destination) = try self.makeInbound()
        defer { try? self.fileManager.removeItem(at: root) }

        #expect(throws: (any Error).self) {
            try NoCacheFile.copy(root.appendingPathComponent("absent.occ"), to: destination)
        }

        #expect(try self.fileManager.contentsOfDirectory(atPath: inbound.path).isEmpty)
    }

    @Test("a destination that cannot be created throws and leaves nothing behind")
    func uncreatableDestination() throws {
        let (root, _, _) = try self.makeInbound()
        defer { try? self.fileManager.removeItem(at: root) }
        let source = root.appendingPathComponent("source.occ")
        try streamedPattern(100).write(to: source)
        let missingDirectory = root.appendingPathComponent("absent").appendingPathComponent("x.occ")

        #expect(throws: (any Error).self) { try NoCacheFile.copy(source, to: missingDirectory) }

        #expect(try self.fileManager.contentsOfDirectory(atPath: root.path).sorted() == ["inbound", "source.occ"])
    }

    @Test("a source that cannot be read, after the destination exists, removes the destination")
    func unreadableSource() throws {
        let (root, inbound, destination) = try self.makeInbound()
        defer { try? self.fileManager.removeItem(at: root) }
        // A directory opens for reading and fails at the first `pread`: the destination has been created by then.
        let source = root.appendingPathComponent("a-directory")
        try self.fileManager.createDirectory(at: source, withIntermediateDirectories: true)

        #expect(throws: (any Error).self) { try NoCacheFile.copy(source, to: destination) }

        #expect(try self.fileManager.contentsOfDirectory(atPath: inbound.path).isEmpty)
    }

    @Test("a source cut short part-way through the copy removes the partial destination")
    func sourceTruncatedMidCopy() async throws {
        let (root, inbound, destination) = try self.makeInbound()
        defer { try? self.fileManager.removeItem(at: root) }
        let source = root.appendingPathComponent("source.occ")
        _ = try makeSparseFile(at: source, length: 128 * 1_048_576)

        // Cut the source once the destination has begun to fill. If the copy wins the race, try again.
        final class Cut: @unchecked Sendable {
            private let lock = NSLock()
            private var bytes: UInt64 = 0
            var writtenAtCut: UInt64 { self.lock.withLock { self.bytes } }
            func record(_ value: UInt64) { self.lock.withLock { self.bytes = value } }
        }
        var failures = 0
        let cut = Cut()
        for _ in 0..<10 where failures == 0 {
            cut.record(0)
            let copy = Task.detached { try? NoCacheFile.copy(source, to: destination, chunkSize: 65_536) }
            let cutter = Thread {
                let deadline = Date().addingTimeInterval(10)
                while Date() < deadline {
                    let written = (try? FileManager.default.attributesOfItem(atPath: destination.path)[.size] as? UInt64) ?? 0
                    if written >= 65_536 {
                        cut.record(written)
                        try? FileHandle(forWritingTo: source).truncate(atOffset: 1_048_576)
                        return
                    }
                    Thread.sleep(forTimeInterval: 0.0002)
                }
            }
            cutter.start()
            _ = await copy.value
            if cut.writtenAtCut > 0, !self.fileManager.fileExists(atPath: destination.path) { failures += 1 }
            try? self.fileManager.removeItem(at: destination)
            if failures == 0 { _ = try makeSparseFile(at: source, length: 128 * 1_048_576) }
        }

        #expect(cut.writtenAtCut >= 65_536, "the destination held bytes when the source was cut")
        #expect(failures == 1, "the copy never failed part-way; the test did not exercise the path")
        #expect(try self.fileManager.contentsOfDirectory(atPath: inbound.path).isEmpty)
    }

    // MARK: - The app opens the result

    /// The recipient of a bundle sealed to this device's ambient key.
    @MainActor
    private func ownRecipient() throws -> GroupRecipient {
        GroupRecipient(publicKey: try Manager.Ambient.keyManager.retrieveIdentity(), quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
    }

    @MainActor
    @Test("a copied streamed bundle opens as a streamed handle, and its digest is the original's", .ambientTestKeyManager)
    func copiedStreamedBundleOpens() throws {
        let (root, _, destination) = try self.makeInbound()
        defer { try? self.fileManager.removeItem(at: root) }
        let original = root.appendingPathComponent("original.occ")
        _ = try writeStreamedBundle(
            to: original, from: TestKeyManager(), recipients: [try self.ownRecipient()],
            files: [inlineTextEntry("hello"), streamedEntry("clip", streamedPattern(300_000))]
        )

        try NoCacheFile.copy(original, to: destination)

        guard case .streamed(let reader) = try InboundFile.open(destination) else {
            Issue.record("a streamed bundle did not open as a streamed handle")
            return
        }
        let copied = try StreamedBody(reader: reader)
        guard case .streamed(let originalReader) = try InboundFile.open(original) else {
            Issue.record("the original did not open as a streamed handle")
            return
        }
        let first = try StreamedBody(reader: originalReader)
        #expect(try copied.digest() == first.digest())
        #expect(copied.bundle.group?.blind == first.bundle.group?.blind)
        #expect(try Data(contentsOf: destination) == Data(contentsOf: original))

        // The app unlinks an inbound file once the handle is open; the handle keeps reading.
        try self.fileManager.removeItem(at: destination)
        #expect(try reader.read(at: 0, count: WireHandle.headerLength).prefix(4).elementsEqual(WireHandle.magic))
    }

    @MainActor
    @Test("a copied inline bundle opens mapped and decodes to the original", .ambientTestKeyManager)
    func copiedInlineBundleOpens() throws {
        let (root, _, destination) = try self.makeInbound()
        defer { try? self.fileManager.removeItem(at: root) }
        let sender = Manager.Crypto(keyManager: TestKeyManager())
        let bundle = try sender.seal(message: Data("hello".utf8), groupID: UUID(), recipients: [try self.ownRecipient()])
        let encoded = try bundle.encoded(version: .v4)
        let original = root.appendingPathComponent("original.occ")
        try encoded.write(to: original)

        try NoCacheFile.copy(original, to: destination)

        guard case .mapped(let data) = try InboundFile.open(destination) else {
            Issue.record("an inline bundle did not open mapped")
            return
        }
        #expect(data == encoded)
        #expect(try OccultaBundle.decoded(from: data).group?.blind == bundle.group?.blind)
    }
}

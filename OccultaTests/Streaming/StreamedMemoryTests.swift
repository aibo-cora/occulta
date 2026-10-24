//
//  StreamedMemoryTests.swift
//  OccultaTests
//
//  STREAMING_SPEC §11, memory regression: a synthetic 1.5 GB bundle is sent and received in the Simulator, and the
//  phys-footprint delta, from `task_info`, stays under 64 MiB on each side. The inline layout needs several
//  copies of the body at once (Bug 183); the streamed one needs a few chunks.
//

import Testing
import CryptoKit
import Foundation
import MachO
@testable import Occulta
@testable import OccultaFormats

private func physFootprint() -> UInt64 {
    var info = task_vm_info_data_t()
    var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
    let result = withUnsafeMutablePointer(to: &info) { pointer in
        pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
        }
    }
    return result == KERN_SUCCESS ? info.phys_footprint : 0
}

/// Samples the footprint on its own thread until stopped, and keeps the highest it saw.
private final class PeakSampler: @unchecked Sendable {
    private let lock = NSLock()
    private var peak: UInt64 = 0
    private var running = true
    private let done = DispatchSemaphore(value: 0)

    init() {
        self.peak = physFootprint()
        Thread.detachNewThread { [self] in
            while true {
                self.lock.lock()
                let keepGoing = self.running
                self.peak = max(self.peak, physFootprint())
                self.lock.unlock()
                if !keepGoing { break }
                usleep(2_000)
            }
            self.done.signal()
        }
    }

    /// The highest footprint seen, after one last sample.
    func stop() -> UInt64 {
        self.lock.lock(); self.running = false; self.lock.unlock()
        self.done.wait()
        self.lock.lock(); defer { self.lock.unlock() }
        return self.peak
    }
}

@Suite("Streamed bundles — memory", .serialized)
@MainActor struct StreamedMemoryTests {

    static let attachmentSize = 1_500_000_000
    static let allowedDelta: UInt64 = 64 * 1024 * 1024

    @Test("a 1.5 GB bundle is sent and received within 64 MiB of footprint on each side", .ambientTestKeyManager)
    func fifteenHundredMegabytes() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let bobKeys = TestKeyManager()
        let manager = AttachmentManager(contactKey: SymmetricKey(size: .bits256))

        // The attachment, staged as compose stages one: sealed on disk, from a repeating block, a piece at a time.
        let staged = dir.appendingPathComponent("big.eatt")
        let encryptor = try manager.streamingEncryptor(to: staged)
        let block = streamedPattern(1 << 20, seed: 21)
        for _ in 0..<(Self.attachmentSize / block.count) { try encryptor.append(block) }
        try encryptor.append(block.prefix(Self.attachmentSize % block.count))
        try encryptor.finalize()
        #expect(try manager.plaintextSize(at: staged) == Self.attachmentSize)

        // ── Send ──────────────────────────────────────────────────────────────────────────────────
        let cm = try TestSupport.makeContactManager()
        try insertStreamedSender(identifier: "bob", publicKey: try bobKeys.retrieveIdentity(), marker: .streamedBodyCapable, in: cm)
        let bundleURL = dir.appendingPathComponent("big.occ")
        let basket = Basket(files: [
            OccultaFormats.File(content: Data("look".utf8), format: .text, date: Date(timeIntervalSinceReferenceDate: 1)),
            OccultaFormats.File(url: staged, format: .file(.init(name: "big", extension: "mov")), date: Date(timeIntervalSinceReferenceDate: 2)),
        ])

        let sendBaseline = physFootprint()
        let sendSampler = PeakSampler()
        let layout = try cm.encryptBundle(
            basket: basket, for: "bob",
            output: .file(destination: bundleURL, attachments: manager, memoryGuard: .system)
        )
        let sendDelta = sendSampler.stop().saturatingSubtract(sendBaseline)

        #expect(layout == .streamed)
        #expect(sendDelta < Self.allowedDelta, "send grew the footprint by \(sendDelta / 1_048_576) MiB")
        #expect(try bundleURL.resourceValues(forKeys: [.fileSizeKey]).fileSize! > Self.attachmentSize)

        // ── Receive, as Bob ───────────────────────────────────────────────────────────────────────
        let override = Manager.Ambient.Override(bobKeys)
        let ourKey = try Manager.Ambient.keyManager.retrieveIdentity()
        let bobCM = try Manager.Ambient.$override.withValue(override) { () throws -> ContactManager in
            let container = try TestSupport.makeContactManager()
            try insertStreamedSender(identifier: "us", publicKey: ourKey, in: container)
            return container
        }

        let receiveKey = SymmetricKey(size: .bits256)
        let destination = dir.appendingPathComponent("received", isDirectory: true)
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)

        let receiveBaseline = physFootprint()
        let receiveSampler = PeakSampler()
        let receive: StreamedReceive = try await Manager.Ambient.$override.withValue(override) {
            let (body, opened) = try await bobCM.openStreamedBundle(try NoCacheFile.reader(bundleURL))
            let receive = try StreamedReceive.prepare(
                message: opened.sealed.message, opened: opened, body: body, key: receiveKey, in: destination
            )
            receive.start()
            await receive.settle()
            return receive
        }
        for _ in 0..<500 where !receive.incoming.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        let receiveDelta = receiveSampler.stop().saturatingSubtract(receiveBaseline)

        #expect(!receive.failed && receive.incoming.isEmpty)
        #expect(receiveDelta < Self.allowedDelta, "receive grew the footprint by \(receiveDelta / 1_048_576) MiB")
        let sealed = try #require(receive.files.compactMap(\.url).first)
        #expect(AttachmentManager.isSealed(at: sealed))
        #expect(try AttachmentManager(contactKey: receiveKey).plaintextSize(at: sealed) == Self.attachmentSize)
        receive.cancel()
    }
}

private extension UInt64 {
    func saturatingSubtract(_ other: UInt64) -> UInt64 { self > other ? self - other : 0 }
}

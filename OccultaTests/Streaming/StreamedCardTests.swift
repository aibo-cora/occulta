//
//  StreamedCardTests.swift
//  OccultaTests
//
//  STREAMING_SPEC §10.3: an introduction-card conversation always uses the streamed layout, and the receive side
//  reads it through the same body consumers: the card slot opener, and the recognition that redeems a card on a
//  bundle from nobody we know. Importing a card makes a prekey batch, which needs a Secure Enclave.
//

import Testing
import CryptoKit
import Foundation
@testable import Occulta
@testable import OccultaFormats

private func enclaveAvailable() -> Bool { TestSupport.secureEnclaveAvailable() }

extension CardPhone {

    /// A message written to a file, as compose writes one.
    func sendToFile(
        to id: String, _ basket: Basket, attachments: AttachmentManager? = nil, in dir: URL
    ) throws -> (layout: BundleLayout, url: URL) {
        let url = dir.appendingPathComponent("\(UUID().uuidString).occ")
        let layout = try self.run {
            try self.cm.encryptBundle(
                basket: basket, for: id, output: .file(destination: url, attachments: attachments, memoryGuard: .system)
            )
        }
        return (layout, url)
    }

    /// The receive path for a streamed bundle, as this phone: slot, digest, header, manifest.
    func receiveStreamed(_ url: URL) async throws -> (ownerID: String, message: Basket, files: [Int: Data]) {
        try await Manager.Ambient.$override.withValue(self.override) {
            let (body, opened) = try await self.cm.openStreamedBundle(try NoCacheFile.reader(url))
            let cursor = try #require(opened.cursor)
            let (basket, lengths) = try WireHandle.decode(streamedBasket: opened.sealed.message)
            try cursor.validate(streamedLengths: lengths)

            final class Collector: StreamSink {
                var files: [Int: Data] = [:]
                var current = -1
                func begin(fileIndex: Int) throws { self.current = fileIndex; self.files[fileIndex] = Data() }
                func write(_ data: Data) throws { self.files[self.current, default: Data()].append(data) }
                func end() throws {}
            }
            let sink = Collector()
            try body.streamFiles(cursor: cursor, streamedLengths: lengths, sink: sink)
            return (opened.ownerID, basket, sink.files)
        }
    }
}

@Suite("Streamed send — introduction cards")
@MainActor struct StreamedCardTests {

    @Test("Carol's first message is streamed, and Bob redeems the card on it and opens it", .enabled(if: enclaveAvailable()))
    func carolsFirstMessage() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let pair = try CardPhonePair()
        let manager = AttachmentManager(contactKey: SymmetricKey(size: .bits256))
        let clip = streamedPattern(2 * BodyStream.chunkSize + 11, seed: 6)
        let staged = dir.appendingPathComponent("clip.eatt")
        let encryptor = try manager.streamingEncryptor(to: staged)
        try encryptor.append(clip)
        try encryptor.finalize()

        let basket = Basket(files: [
            File(content: Data("hello Bob".utf8), format: .text, date: Date(timeIntervalSinceReferenceDate: 1)),
            File(url: staged, format: .file(.init(name: "clip", extension: "mp4")), date: Date(timeIntervalSinceReferenceDate: 2)),
        ])
        let sent = try pair.carol.sendToFile(to: pair.carolSide, basket, attachments: manager, in: dir)

        #expect(sent.layout == .streamed)
        let received = try await pair.bob.receiveStreamed(sent.url)
        #expect(received.ownerID == pair.bobSide)
        #expect(received.files[1] == clip)
        #expect(String(data: try #require(received.message.files.first?.content), encoding: .utf8) == "hello Bob")
    }

    @Test("every message in the conversation is streamed, both ways, and each opens", .enabled(if: enclaveAvailable()))
    func conversation() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let pair = try CardPhonePair()
        let text = CardPhone.basket("text")

        let first  = try pair.carol.sendToFile(to: pair.carolSide, text, in: dir)
        let second = try pair.carol.sendToFile(to: pair.carolSide, text, in: dir)
        _ = try await pair.bob.receiveStreamed(second.url)    // the second first, as the bootstrap allows
        _ = try await pair.bob.receiveStreamed(first.url)
        let reply = try pair.bob.sendToFile(to: pair.bobSide, text, in: dir)
        _ = try await pair.carol.receiveStreamed(reply.url)
        let again = try pair.carol.sendToFile(to: pair.carolSide, text, in: dir)
        _ = try await pair.bob.receiveStreamed(again.url)

        #expect([first.layout, second.layout, reply.layout, again.layout].allSatisfy { $0 == .streamed })
    }

    @Test("a card bundle sent to memory is still the inline layout, for the callers that have no file", .enabled(if: enclaveAvailable()))
    func memoryIsInline() throws {
        let pair = try CardPhonePair()
        let data = try pair.carol.send(to: pair.carolSide)
        #expect(data[4] == 0x04)
    }
}

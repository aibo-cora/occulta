//
//  StreamedReceiveTests.swift
//  OccultaTests
//
//  STREAMING_SPEC §5 and the receive half of §11: a streamed bundle through the real receive path, from the
//  open file to sealed attachments in `tmp/`. Bundles are written by `writeStreamedBundle`, which does what a
//  sender will do.
//

import Testing
import CryptoKit
import Foundation
@testable import Occulta
@testable import OccultaFormats

private let C = BodyStream.chunkSize

private struct FixedKey: ComposeStagingKeyProviding {
    let key = SymmetricKey(size: .bits256)
    func deriveComposeStagingKey() throws -> SymmetricKey { self.key }
}

/// A one-time prekey held as a software key, which records what it was asked to consume.
private final class SoftwareOneTimePrekey: PrekeyPrivateKeys {
    let id = UUID().uuidString
    let privateKey: SecKey
    let publicKey: Data
    private(set) var consumed: [String] = []

    init() throws {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        let key = try #require(SecKeyCreateRandomKey(attributes as CFDictionary, &error))
        let publicKey = try #require(SecKeyCopyPublicKey(key))
        self.privateKey = key
        self.publicKey  = try #require(SecKeyCopyExternalRepresentation(publicKey, &error) as Data?)
    }

    func privateKey(forPrekeyID prekeyID: String, contactID: String) -> PrekeyPrivateKey? {
        prekeyID == self.id && !self.consumed.contains(prekeyID) ? .keychain(self.privateKey) : nil
    }
    func consume(prekeyID: String, contactID: String) { self.consumed.append(prekeyID) }
    func lastResortKey(forPrekeyID prekeyID: String, ephemeralPublicKey: Data) -> (keyID: String, key: PrekeyPrivateKey)? { nil }
}

private func thisDevice() throws -> Data { try Manager.Ambient.keyManager.retrieveIdentity() }

private func longTermRecipient() throws -> GroupRecipient {
    GroupRecipient(publicKey: try thisDevice(), quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
}

private func flip(_ url: URL, at offset: Int) throws {
    var bytes = try Data(contentsOf: url)
    bytes[offset] ^= 0x01
    try bytes.write(to: url)
}

private func exists(_ urls: [URL]) -> [Bool] { urls.map { FileManager.default.fileExists(atPath: $0.path) } }

// MARK: - The streamed body

@Suite("StreamedBody — opening a streamed file")
@MainActor struct StreamedBodyTests {

    let alice = TestKeyManager()

    private func write(_ files: [(file: OccultaFormats.File, streamed: Data?)], in dir: URL, to recipients: [GroupRecipient]? = nil) throws -> WrittenBundle {
        try writeStreamedBundle(
            to: dir.appendingPathComponent("m.occ"), from: self.alice,
            recipients: try recipients ?? [longTermRecipient()], files: files
        )
    }

    @Test("the header, the sections and the length are read from the file, and its body is not held", .ambientTestKeyManager)
    func parses() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let written = try self.write([streamedEntry("clip", streamedPattern(3 * C + 17))], in: dir)

        let body = try StreamedBody(reader: try NoCacheFile.reader(written.url))

        #expect(body.bundle.version == .streamedBodyCapable)
        #expect(body.bundle.ciphertext.isEmpty)
        #expect(body.bundle.group?.recipients.count == 1)
        #expect(body.bundle.group?.blind == written.bundle.group?.blind)
        #expect(body.layout.chunkCount >= 4)
    }

    @Test("the digest is the SHA-256 of the chunk stream, and is made once", .ambientTestKeyManager)
    func digest() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let written = try self.write([streamedEntry("clip", streamedPattern(2 * C + 5))], in: dir)
        let body = try StreamedBody(reader: try NoCacheFile.reader(written.url))

        let all = try Data(contentsOf: written.url)
        let stream = all[WireHandle.headerLength..<(WireHandle.headerLength + Int(body.layout.streamLength))]

        #expect(try body.digest() == Data(SHA256.hash(data: stream)))
        // The slot carries the same digest: it was sealed from the Sealer's, not recomputed.
        #expect(try body.digest() == BundleBody.streamed(body).digest())
    }

    @Test("the manifest opens without the files, and the cursor holds what follows it", .ambientTestKeyManager)
    func manifest() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let written = try self.write([inlineTextEntry("hello"), streamedEntry("clip", streamedPattern(2 * C))], in: dir)
        let body = try StreamedBody(reader: try NoCacheFile.reader(written.url))

        let opened = try BundleBody.streamed(body).openManifest(sessionKey: written.sessionKey)

        #expect(opened.payload.appVersion == "2.0.0")
        #expect(opened.cursor != nil)
        let (basket, lengths) = try WireHandle.decode(streamedBasket: opened.payload.message)
        #expect(basket.files.count == 2 && lengths == [nil, UInt64(2 * C)])
        try opened.cursor?.validate(streamedLengths: lengths)
    }

    @Test("pass 2 checks for cancellation at every chunk", .ambientTestKeyManager)
    func cancellationIsChecked() async throws {
        final class Null: StreamSink { func begin(fileIndex: Int) throws {}; func write(_ data: Data) throws {}; func end() throws {} }
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let written = try self.write([streamedEntry("clip", streamedPattern(6 * C))], in: dir)
        let body = try StreamedBody(reader: try NoCacheFile.reader(written.url))
        let opened = try BundleBody.streamed(body).openManifest(sessionKey: written.sessionKey)
        let cursor = try #require(opened.cursor)
        let (_, lengths) = try WireHandle.decode(streamedBasket: opened.payload.message)

        let outcome = await Task.detached {
            withUnsafeCurrentTask { $0?.cancel() }
            return Result { try body.streamFiles(cursor: cursor, streamedLengths: lengths, sink: Null()) }
        }.value

        #expect(throws: CancellationError.self) { try outcome.get() }
    }

    @Test("a file shorter than the header says is malformed", .ambientTestKeyManager)
    func truncatedFile() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let written = try self.write([streamedEntry("clip", streamedPattern(2 * C))], in: dir)
        let bytes = try Data(contentsOf: written.url)

        for cut in [10, WireHandle.headerLength - 1, WireHandle.headerLength + 100, bytes.count - 1000] {
            let short = dir.appendingPathComponent("short-\(cut).occ")
            try bytes.prefix(cut).write(to: short)
            #expect(throws: (any Error).self, "cut at \(cut)") { _ = try StreamedBody(reader: try NoCacheFile.reader(short)) }
        }
    }

    @Test("more than 8 MiB after the chunk stream is refused", .ambientTestKeyManager)
    func oversizeSections() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let written = try self.write([inlineTextEntry("hi")], in: dir)
        let handle = try FileHandle(forWritingTo: written.url)
        try handle.seekToEnd()
        try handle.write(contentsOf: Data(count: 8 * 1024 * 1024 + 1))
        try handle.close()

        #expect(throws: OccultaBundle.BundleError.malformedBundle) { _ = try StreamedBody(reader: try NoCacheFile.reader(written.url)) }
    }

    @Test("a version other than 0x0A is not a streamed body", .ambientTestKeyManager)
    func notStreamed() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let written = try self.write([inlineTextEntry("hi")], in: dir)
        try flip(written.url, at: 4)   // 0x0A -> 0x0B

        #expect(throws: OccultaBundle.BundleError.unsupportedVersion) { _ = try StreamedBody(reader: try NoCacheFile.reader(written.url)) }
    }

    @Test("a manifest_length over 16 MiB is refused before anything is decrypted past it", .ambientTestKeyManager)
    func hugeManifestLength() throws {
        // Seal a stream whose first four plaintext bytes claim a 16 MiB + 1 manifest.
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let sessionKey = SymmetricKey(size: .bits256)
        let secrecy = OccultaBundle.SecrecyContext(mode: .group, ephemeralPublicKey: Data(), prekeyID: nil)
        let blind = Data(repeating: 7, count: 32)
        let aad = try BodyStream.headerAAD(secrecy: secrecy, blind: blind)
        let plaintext = BodyStream.bigEndian32(UInt32(BodyStream.maxManifestLength + 1)) + Data(count: 100)
        let layout = try BodyStream.Layout(plaintextLength: UInt64(plaintext.count))
        var sealer = BodyStream.Sealer(sessionKey: sessionKey, header: aad, layout: layout)
        var stream = Data()
        try sealer.append(plaintext) { stream.append($0) }
        _ = try sealer.finish { stream.append($0) }

        let envelope = OccultaBundle(
            version: .streamedBodyCapable, secrecy: secrecy, ciphertext: Data(),
            fingerprintNonce: Data(count: 16), senderFingerprint: Data(count: 32),
            group: OccultaBundle.GroupEnvelope(blind: blind, blindNonce: Data(count: 16), recipients: [])
        )
        var file = try WireHandle.encodeHeader(envelope, ciphertextLength: layout.streamLength)
        file.append(stream)
        file.append(try WireHandle.encodeSections(envelope))
        let url = dir.appendingPathComponent("m.occ")
        try file.write(to: url)

        let body = try StreamedBody(reader: try NoCacheFile.reader(url))
        #expect(throws: BodyStream.StreamError.manifestLengthOutOfRange) {
            _ = try BundleBody.streamed(body).openManifest(sessionKey: sessionKey)
        }
    }
}

// MARK: - Routing

@Suite("StreamRouter")
struct StreamRouterTests {

    private final class Recorder: StreamSink {
        var events: [String] = []
        var bytes: [Int: Data] = [:]
        private var current = -1
        func begin(fileIndex: Int) throws { self.events.append("begin \(fileIndex)"); self.current = fileIndex; self.bytes[fileIndex] = Data() }
        func write(_ data: Data) throws { self.bytes[self.current, default: Data()].append(data) }
        func end() throws { self.events.append("end \(self.current)") }
    }

    private func route(_ lengths: [UInt64?], _ pieces: [Data]) throws -> Recorder {
        let sink = Recorder()
        var router = StreamRouter(lengths: lengths)
        for piece in pieces { try router.consume(piece, into: sink) }
        try router.finish(into: sink)
        return sink
    }

    @Test("bytes go to each file in order, and a file ends the moment its last byte is routed")
    func routesInOrder() throws {
        let sink = Recorder()
        var router = StreamRouter(lengths: [nil, 4, nil, 3])
        try router.consume(Data([1, 2]), into: sink)
        #expect(sink.events == ["begin 1"])
        try router.consume(Data([3, 4, 5]), into: sink)
        #expect(sink.events == ["begin 1", "end 1", "begin 3"])
        try router.consume(Data([6, 7]), into: sink)
        try router.finish(into: sink)

        #expect(sink.events == ["begin 1", "end 1", "begin 3", "end 3"])
        #expect(sink.bytes[1] == Data([1, 2, 3, 4]) && sink.bytes[3] == Data([5, 6, 7]))
    }

    @Test("however the stream is cut into pieces, the files are the same", arguments: [1, 2, 3, 5, 100])
    func pieceSizeDoesNotMatter(size: Int) throws {
        let all = streamedPattern(23)
        var pieces: [Data] = []
        var offset = 0
        while offset < all.count { pieces.append(all[offset..<min(offset + size, all.count)]); offset += size }

        let sink = try self.route([10, nil, 0, 13], pieces)

        #expect(sink.bytes[0] == all[0..<10] && sink.bytes[3] == all[10..<23])
    }

    @Test("a zero-length file begins and ends, in its place")
    func zeroLength() throws {
        let sink = try self.route([2, 0, 2], [Data([1, 2, 3, 4])])
        #expect(sink.events == ["begin 0", "end 0", "begin 1", "end 1", "begin 2", "end 2"])
        #expect(sink.bytes[1] == Data())
    }

    @Test("zero-length files at the end, and a stream of nothing but them, are finished by finish()")
    func trailingZeroLength() throws {
        #expect(try self.route([1, 0], [Data([9])]).events == ["begin 0", "end 0", "begin 1", "end 1"])
        #expect(try self.route([0, 0], []).events == ["begin 0", "end 0", "begin 1", "end 1"])
    }

    @Test("no streamed files, and no bytes, is complete")
    func nothingToRoute() throws {
        #expect(try self.route([nil, nil], []).events.isEmpty)
        #expect(try self.route([], []).events.isEmpty)
    }

    @Test("bytes left over are a mismatch, at the byte")
    func leftOver() {
        let sink = Recorder()
        var router = StreamRouter(lengths: [2])
        #expect(throws: BodyStream.StreamError.lengthMismatch) { try router.consume(Data([1, 2, 3]), into: sink) }
    }

    @Test("a stream that ends with a file short is a mismatch")
    func short() throws {
        let sink = Recorder()
        var router = StreamRouter(lengths: [3, 2])
        try router.consume(Data([1, 2, 3, 4]), into: sink)
        #expect(throws: BodyStream.StreamError.lengthMismatch) { try router.finish(into: sink) }
    }

    @Test("bytes where no file is expected are a mismatch")
    func bytesWithNoFiles() {
        let sink = Recorder()
        var router = StreamRouter(lengths: [nil])
        #expect(throws: BodyStream.StreamError.lengthMismatch) { try router.consume(Data([1]), into: sink) }
    }
}

// MARK: - The receive path

@Suite("Streamed receive — through the real path")
@MainActor struct StreamedReceiveTests {

    let alice = TestKeyManager()

    private func receiver() throws -> ContactManager {
        let cm = try TestSupport.makeContactManager()
        try insertStreamedSender(identifier: "alice", publicKey: try self.alice.retrieveIdentity(), in: cm)
        return cm
    }

    private func write(
        _ files: [(file: OccultaFormats.File, streamed: Data?)], in dir: URL, declaredLengths: [UInt64?]? = nil
    ) throws -> WrittenBundle {
        try writeStreamedBundle(
            to: dir.appendingPathComponent("m.occ"), from: self.alice, recipients: [try longTermRecipient()],
            files: files, declaredLengths: declaredLengths
        )
    }

    /// Where a receive of `written` puts its files.
    static func received(beside written: WrittenBundle) -> URL {
        written.url.deletingLastPathComponent().appendingPathComponent("received", isDirectory: true)
    }

    /// What a receive of `written` has left in its directory.
    private func leftBehind(_ written: WrittenBundle) -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: Self.received(beside: written).path)) ?? []
    }

    /// Steps 1 to 7, then pass 2 to the end.
    private func receive(
        _ written: WrittenBundle, on cm: ContactManager, key: SymmetricKey? = SymmetricKey(size: .bits256), start: Bool = true
    ) async throws -> StreamedReceive {
        let (body, opened) = try await cm.openStreamedBundle(try NoCacheFile.reader(written.url))
        // Into the bundle's own directory, so a test sees only what its own receive wrote.
        let destination = Self.received(beside: written)
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        let receive = try StreamedReceive.prepare(
            message: opened.sealed.message, opened: opened, body: body, key: key, in: destination
        )
        if start { receive.start(); await receive.settle() }
        return receive
    }

    @Test("the text shows first, the attachments follow sealed, and they are the bytes that were sent", .ambientTestKeyManager)
    func opensAndSeals() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let key = SymmetricKey(size: .bits256)
        let first  = streamedPattern(2 * C + 99, seed: 3)
        let second = streamedPattern(40, seed: 4)
        let written = try self.write(
            [inlineTextEntry("lunch at one"), streamedEntry("clip", first, ext: "mp4"), streamedEntry("note", second, ext: "txt")],
            in: dir
        )

        let receive = try await self.receive(written, on: try self.receiver(), key: key, start: false)
        defer { receive.cancel() }

        // Before pass 2: the text, and a placeholder for each file.
        #expect(receive.files.count == 3)
        #expect(receive.files.filter { $0.url != nil }.isEmpty)
        #expect(receive.incoming.count == 2)
        #expect(receive.files.contains { $0.content.flatMap { String(data: $0, encoding: .utf8) } == "lunch at one" })

        receive.start()
        await receive.settle()
        // The completion of the last file reaches the main actor on its own hop.
        for _ in 0..<200 where !receive.incoming.isEmpty { try await Task.sleep(for: .milliseconds(10)) }

        #expect(receive.incoming.isEmpty && !receive.failed)
        let urls = receive.files.compactMap(\.url)
        #expect(urls.count == 2)
        let manager = AttachmentManager(contactKey: key)
        for url in urls { #expect(AttachmentManager.isSealed(at: url)) }
        var byName: [String: Data] = [:]
        for file in receive.files {
            guard case .file(let metadata) = file.format, let url = file.url else { continue }
            byName[metadata.name ?? ""] = try await manager.data(at: url)
        }
        #expect(byName["clip"] == first && byName["note"] == second)
        #expect(urls.map { $0.pathExtension }.sorted() == ["mp4", "txt"])
    }

    @Test("no attachment is plaintext on disk, and the inbound file is the only plaintext-free copy", .ambientTestKeyManager)
    func nothingPlaintextOnDisk() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let marker = Data("STREAMED-MARKER-\(UUID().uuidString)".utf8)
        var plaintext = Data()
        while plaintext.count < 2 * C { plaintext.append(marker) }
        let written = try self.write([streamedEntry("clip", plaintext)], in: dir)

        let receive = try await self.receive(written, on: try self.receiver())
        defer { receive.cancel() }

        // The bundle on disk is ciphertext, and so is every file pass 2 wrote.
        #expect(try Data(contentsOf: written.url).range(of: marker) == nil)
        for url in receive.files.compactMap(\.url) { #expect(try Data(contentsOf: url).range(of: marker) == nil) }
    }

    @Test("a streamed file with no key to seal it under is refused, and nothing is written", .ambientTestKeyManager)
    func noKeyRefuses() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let written = try self.write([streamedEntry("clip", streamedPattern(300))], in: dir)

        await #expect(throws: ImportError.self) { _ = try await self.receive(written, on: try self.receiver(), key: nil) }
    }

    @Test("a message with no streamed file needs no key", .ambientTestKeyManager)
    func textOnlyNeedsNoKey() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let written = try self.write([inlineTextEntry("hi")], in: dir)

        let receive = try await self.receive(written, on: try self.receiver(), key: nil)

        #expect(receive.files.count == 1 && receive.incoming.isEmpty && receive.isFinished && !receive.failed)
    }

    @Test("a manifest whose lengths are not the stream's is refused before any file is written", .ambientTestKeyManager)
    func lengthsDisagree() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }

        for declared in [UInt64(299), 301] {   // short by one, and over by one
            let written = try self.write([streamedEntry("clip", streamedPattern(300))], in: dir, declaredLengths: [declared])
            await #expect(throws: BodyStream.StreamError.lengthMismatch) {
                _ = try await self.receive(written, on: try self.receiver())
            }
            #expect(self.leftBehind(written).isEmpty)
        }
    }

    @Test("a zero-length attachment finishes as an empty sealed file", .ambientTestKeyManager)
    func zeroLengthAttachment() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let key = SymmetricKey(size: .bits256)
        let written = try self.write([streamedEntry("empty", Data()), streamedEntry("after", streamedPattern(50))], in: dir)

        let receive = try await self.receive(written, on: try self.receiver(), key: key)
        defer { receive.cancel() }
        for _ in 0..<200 where !receive.incoming.isEmpty { try await Task.sleep(for: .milliseconds(10)) }

        let manager = AttachmentManager(contactKey: key)
        let sizes = try receive.files.compactMap(\.url).map { try manager.plaintextSize(at: $0) }.sorted()
        #expect(sizes == [0, 50])
    }

    // MARK: Failure and cancellation (§5.3)

    @Test("a chunk that fails in pass 2 deletes every file of the message, finished ones too, and shows one error", .ambientTestKeyManager)
    func pass2FailureDeletesEverything() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let key = SymmetricKey(size: .bits256)
        // A small file that finishes in the first chunks, then a large one the failure lands in.
        let written = try self.write(
            [inlineTextEntry("kept"), streamedEntry("small", streamedPattern(100)), streamedEntry("large", streamedPattern(6 * C))],
            in: dir
        )
        let receive = try await self.receive(written, on: try self.receiver(), key: key, start: false)
        let fileURLs = { receive.files.compactMap(\.url) }

        // Passed pass 1 and the header check; the file then changes under us, in a late chunk.
        try flip(written.url, at: WireHandle.headerLength + 5 * BodyStream.wireChunkSize + 1000)
        receive.start()
        await receive.settle()
        for _ in 0..<200 where !receive.failed { try await Task.sleep(for: .milliseconds(10)) }

        #expect(receive.failed && receive.isFinished)
        #expect(receive.incoming.isEmpty)
        #expect(receive.files.count == 1, "only the inline text is left")
        #expect(fileURLs().isEmpty)
    }

    @Test("a failure leaves no sealed file of the message in tmp/", .ambientTestKeyManager)
    func pass2FailureLeavesNothingInTmp() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let written = try self.write([streamedEntry("small", streamedPattern(100)), streamedEntry("large", streamedPattern(6 * C))], in: dir)
        let receive = try await self.receive(written, on: try self.receiver(), start: false)

        try flip(written.url, at: WireHandle.headerLength + 5 * BodyStream.wireChunkSize + 1000)
        receive.start()
        await receive.settle()
        for _ in 0..<200 where !receive.failed { try await Task.sleep(for: .milliseconds(10)) }

        #expect(self.leftBehind(written).isEmpty, "\(self.leftBehind(written))")
    }

    @Test("closing the sheet while pass 2 runs stops it and deletes what it wrote", .ambientTestKeyManager)
    func cancelDeletes() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let written = try self.write([streamedEntry("small", streamedPattern(100)), streamedEntry("large", streamedPattern(40 * C))], in: dir)
        let receive = try await self.receive(written, on: try self.receiver(), start: false)

        receive.start()
        receive.cancel()
        await receive.settle()

        #expect(receive.isFinished && !receive.failed)
        #expect(self.leftBehind(written).isEmpty, "\(self.leftBehind(written))")
    }

    @Test("cancelling before pass 2 starts writes nothing and releases the file", .ambientTestKeyManager)
    func cancelBeforeStart() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let written = try self.write([streamedEntry("clip", streamedPattern(300))], in: dir)
        let receive = try await self.receive(written, on: try self.receiver(), start: false)

        receive.cancel()
        receive.start()   // a cancelled receive stays cancelled
        await receive.settle()

        #expect(receive.isFinished && receive.files.compactMap(\.url).isEmpty)
        #expect(self.leftBehind(written).isEmpty, "\(self.leftBehind(written))")
    }

    @Test("closing the sheet after pass 2 finished deletes the sealed files", .ambientTestKeyManager)
    func cancelAfterFinishDeletes() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let written = try self.write([streamedEntry("clip", streamedPattern(2 * C))], in: dir)
        let receive = try await self.receive(written, on: try self.receiver())
        for _ in 0..<200 where !receive.incoming.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        let urls = receive.files.compactMap(\.url)
        #expect(urls.count == 1 && exists(urls) == [true])

        receive.cancel()

        #expect(exists(urls) == [false])
    }

    @Test("the same file gives the same result every time: same steps, same files", .ambientTestKeyManager)
    func deterministicOutcome() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let written = try self.write([inlineTextEntry("hi"), streamedEntry("clip", streamedPattern(C + 3))], in: dir)

        var shapes: [[String]] = []
        for _ in 0..<2 {
            let receive = try await self.receive(written, on: try self.receiver())
            for _ in 0..<200 where !receive.incoming.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
            shapes.append(receive.files.map { "\($0.url == nil ? "inline" : "sealed"):\($0.url?.pathExtension ?? "")" })
            receive.cancel()
        }
        #expect(shapes[0] == shapes[1])
    }

    // MARK: Who may open it

    @Test("a streamed bundle from nobody we know is refused, and nothing is written", .ambientTestKeyManager)
    func unknownSender() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let written = try self.write([streamedEntry("clip", streamedPattern(300))], in: dir)
        let stranger = try TestSupport.makeContactManager()

        await #expect(throws: (any Error).self) { _ = try await self.receive(written, on: stranger) }
    }

    @Test("a streamed bundle with no slot for this device is refused", .ambientTestKeyManager)
    func noSlot() async throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let other = TestKeyManager()
        let written = try writeStreamedBundle(
            to: dir.appendingPathComponent("m.occ"), from: self.alice,
            recipients: [GroupRecipient(publicKey: try other.retrieveIdentity(), quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)],
            files: [streamedEntry("clip", streamedPattern(300))]
        )

        await #expect(throws: GroupDecryptError.recipientSlotNotFound) { _ = try await self.receive(written, on: try self.receiver()) }
    }
}

// MARK: - Prekey safety, on both layouts

@Suite("Streamed receive — a prekey is used only by the genuine bundle")
@MainActor struct StreamedPrekeySafetyTests {

    let alice = TestKeyManager()
    let carol = TestKeyManager()

    enum Layout: CaseIterable { case inline, streamed }

    /// A one-recipient bundle sealed to `carol`'s one-time key, in the layout asked for.
    struct Fixture {
        let bundle: OccultaBundle
        let body: BundleBody
        /// The streamed file, nil for the inline layout.
        let url: URL?
        let sessionKey: SymmetricKey?
    }

    private func fixture(_ layout: Layout, key: SoftwareOneTimePrekey, in dir: URL) throws -> Fixture {
        let recipient = GroupRecipient(
            publicKey: try self.carol.retrieveIdentity(), quantumMaterial: nil,
            contactPrekey: Prekey(id: key.id, contactID: "carol", publicKey: key.publicKey), pendingBatch: nil
        )
        switch layout {
        case .inline:
            let sealed = try Manager.Crypto(keyManager: self.alice).seal(
                sealedPayload: OccultaBundle.SealedPayload(message: Data("Lunch at one.".utf8)), groupID: UUID(), recipients: [recipient]
            )
            return Fixture(bundle: sealed, body: .inline(sealed), url: nil, sessionKey: nil)
        case .streamed:
            let written = try writeStreamedBundle(
                to: dir.appendingPathComponent("m-\(UUID().uuidString).occ"), from: self.alice, recipients: [recipient],
                files: [inlineTextEntry("Lunch at one."), streamedEntry("clip", streamedPattern(2 * C))]
            )
            let body = try StreamedBody(reader: try NoCacheFile.reader(written.url))
            return Fixture(bundle: body.bundle, body: .streamed(body), url: written.url, sessionKey: written.sessionKey)
        }
    }

    private func open(_ fixture: Fixture, key: SoftwareOneTimePrekey) throws {
        _ = try Manager.Crypto(keyManager: self.carol).findAndOpenRecipientSlot(
            in: fixture.bundle, blind: try #require(fixture.bundle.group).blind, senderContactID: "alice",
            senderPublicKey: try self.alice.retrieveIdentity(), quantumMaterial: nil, prekeys: key, body: fixture.body
        )
    }

    @Test("the genuine bundle opens and uses the key up, in either layout", .ambientTestKeyManager, arguments: Layout.allCases)
    func genuineOpens(layout: Layout) throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let key = try SoftwareOneTimePrekey()

        try self.open(try self.fixture(layout, key: key, in: dir), key: key)

        #expect(key.consumed == [key.id])
    }

    /// Bug 165. A body that is not the one the slot was sealed with fails before the key is recorded as used.
    @Test("a body that doesn't match the slot's digest leaves the key unused, and the genuine bundle still opens",
          .ambientTestKeyManager, arguments: Layout.allCases)
    func badDigestKeepsTheKey(layout: Layout) throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let key = try SoftwareOneTimePrekey()
        let genuine = try self.fixture(layout, key: key, in: dir)

        // The same envelope over a different body: one byte of the stream, or of the ciphertext, changed.
        let forged: Fixture
        if let url = genuine.url {
            var bytes = try Data(contentsOf: url)
            bytes[WireHandle.headerLength + 300] ^= 0x01
            let copy = dir.appendingPathComponent("forged.occ")
            try bytes.write(to: copy)
            let body = try StreamedBody(reader: try NoCacheFile.reader(copy))
            forged = Fixture(bundle: body.bundle, body: .streamed(body), url: copy, sessionKey: genuine.sessionKey)
        } else {
            var ciphertext = genuine.bundle.ciphertext
            ciphertext[ciphertext.count / 2] ^= 0x01
            let bundle = OccultaBundle(
                version: genuine.bundle.version, secrecy: genuine.bundle.secrecy, ciphertext: ciphertext,
                fingerprintNonce: genuine.bundle.fingerprintNonce, senderFingerprint: genuine.bundle.senderFingerprint,
                group: genuine.bundle.group
            )
            forged = Fixture(bundle: bundle, body: .inline(bundle), url: nil, sessionKey: nil)
        }

        #expect(throws: GroupDecryptError.bodyDigestMismatch) { try self.open(forged, key: key) }
        #expect(key.consumed.isEmpty)

        try self.open(genuine, key: key)
        #expect(key.consumed == [key.id], "the genuine bundle uses it up, as any other")
    }

    /// Bug 181. A copy of the file with an altered header opens the slot all the same; only opening the body
    /// authenticates the header, and it must come before the key is used up.
    @Test("a copy with an altered outer header leaves the key unused, and the genuine bundle still opens",
          .ambientTestKeyManager, arguments: Layout.allCases)
    func alteredHeaderKeepsTheKey(layout: Layout) throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let key = try SoftwareOneTimePrekey()
        let genuine = try self.fixture(layout, key: key, in: dir)

        // The ephemeral key field: cleartext, ignored by the parser, covered by the AAD.
        let altered = OccultaBundle(
            version: genuine.bundle.version,
            secrecy: OccultaBundle.SecrecyContext(mode: .group, ephemeralPublicKey: Data([0x04] + Array(repeating: 0x01, count: 64)), prekeyID: nil),
            ciphertext: genuine.bundle.ciphertext, fingerprintNonce: genuine.bundle.fingerprintNonce,
            senderFingerprint: genuine.bundle.senderFingerprint, group: genuine.bundle.group
        )
        let tampered: Fixture
        if let url = genuine.url, case .streamed(let body) = genuine.body {
            // A copy of the file whose header carries the altered field.
            var bytes = try Data(contentsOf: url)
            bytes.replaceSubrange(0..<WireHandle.headerLength, with: try WireHandle.encodeHeader(altered, ciphertextLength: body.layout.streamLength))
            let copy = dir.appendingPathComponent("altered.occ")
            try bytes.write(to: copy)
            let alteredBody = try StreamedBody(reader: try NoCacheFile.reader(copy))
            tampered = Fixture(bundle: alteredBody.bundle, body: .streamed(alteredBody), url: copy, sessionKey: genuine.sessionKey)
        } else {
            tampered = Fixture(bundle: altered, body: .inline(altered), url: nil, sessionKey: nil)
        }
        #expect(tampered.bundle.secrecy.ephemeralPublicKey == altered.secrecy.ephemeralPublicKey)

        #expect(throws: (any Error).self) { try self.open(tampered, key: key) }
        #expect(key.consumed.isEmpty)

        try self.open(genuine, key: key)
        #expect(key.consumed == [key.id])
    }

    @Test("once the header is authenticated the key stays spent, whatever pass 2 does", .ambientTestKeyManager)
    func keyStaysSpentWhenPass2Fails() throws {
        let dir = try streamedScratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let key = try SoftwareOneTimePrekey()
        let genuine = try self.fixture(.streamed, key: key, in: dir)
        try self.open(genuine, key: key)
        #expect(key.consumed == [key.id])

        // Pass 2 then runs on a file that changed under us.
        guard case .streamed(let streamed) = genuine.body, let url = genuine.url, let sessionKey = genuine.sessionKey else { return }
        let opened = try genuine.body.openManifest(sessionKey: sessionKey)
        let cursor = try #require(opened.cursor)
        let (_, lengths) = try WireHandle.decode(streamedBasket: opened.payload.message)
        try flip(url, at: WireHandle.headerLength + BodyStream.wireChunkSize + 100)

        final class Null: StreamSink { func begin(fileIndex: Int) throws {}; func write(_ data: Data) throws {}; func end() throws {} }
        #expect(throws: BodyStream.StreamError.chunkNotAuthentic) {
            try streamed.streamFiles(cursor: cursor, streamedLengths: lengths, sink: Null())
        }
        #expect(key.consumed == [key.id], "still spent, and not spent twice")
    }
}

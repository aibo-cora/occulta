//
//  BodyStreamTests.swift
//  OccultaTests
//
//  STREAMING_SPEC §4 and §8.1, the codec half of §11. No Enclave, no keys of the app's: these run anywhere.
//

import Testing
import CryptoKit
import Foundation
@testable import OccultaFormats

// MARK: - Fixtures

private let C = BodyStream.chunkSize
private let W = BodyStream.wireChunkSize

/// Deterministic bytes, so a failure reproduces.
private func pattern(_ count: Int, seed: UInt8 = 1) -> Data {
    var state = UInt32(seed) &* 2_654_435_761 | 1
    return Data((0..<count).map { _ in
        state = state &* 1_664_525 &+ 1_013_904_223
        return UInt8(truncatingIfNeeded: state >> 24)
    })
}

private let sessionKey = SymmetricKey(data: Data(repeating: 0x42, count: 32))
private let otherSessionKey = SymmetricKey(data: Data(repeating: 0x43, count: 32))

private let secrecy = OccultaBundle.SecrecyContext(mode: .group, ephemeralPublicKey: Data(), prekeyID: nil)
private let blind = Data(repeating: 0x5B, count: 32)

private func headerAAD() throws -> Data { try BodyStream.headerAAD(secrecy: secrecy, blind: blind) }

/// Seals `plaintext` in uneven pieces, so the buffer is exercised across chunk boundaries.
private func seal(
    _ plaintext: Data, key: SymmetricKey = sessionKey, header: Data? = nil, piece: Int = 100_003
) throws -> (stream: Data, digest: Data, layout: BodyStream.Layout) {
    let header = try header ?? headerAAD()
    let layout = try BodyStream.Layout(plaintextLength: UInt64(plaintext.count))
    var sealer = BodyStream.Sealer(sessionKey: key, header: header, layout: layout)
    var stream = Data()
    var offset = 0
    while offset < plaintext.count {
        let end = min(offset + piece, plaintext.count)
        try sealer.append(plaintext[offset..<end]) { stream.append($0) }
        offset = end
    }
    let digest = try sealer.finish { stream.append($0) }
    return (stream, digest, layout)
}

/// Opens a whole stream, as a receiver reading it chunk by chunk would.
private func open(
    _ stream: Data, key: SymmetricKey = sessionKey, header: Data? = nil
) throws -> Data {
    let header = try header ?? headerAAD()
    let layout = try BodyStream.Layout(streamLength: UInt64(stream.count))
    var opener = BodyStream.Opener(sessionKey: key, header: header, layout: layout)
    var plaintext = Data()
    for index in 0..<layout.chunkCount {
        let start = stream.startIndex + Int(layout.wireOffset(ofChunk: index))
        plaintext.append(try opener.open(stream[start..<(start + layout.wireLength(ofChunk: index))], index: index))
    }
    return plaintext
}

private func chunk(_ index: Int, of stream: Data, layout: BodyStream.Layout) -> Data {
    let start = Int(layout.wireOffset(ofChunk: UInt64(index)))
    return stream[start..<(start + layout.wireLength(ofChunk: UInt64(index)))]
}

private func replacing(_ index: Int, in stream: Data, layout: BodyStream.Layout, with other: Data) -> Data {
    let start = Int(layout.wireOffset(ofChunk: UInt64(index)))
    var copy = Data(stream)
    copy.replaceSubrange(start..<(start + layout.wireLength(ofChunk: UInt64(index))), with: other)
    return copy
}

// MARK: - Layout

@Suite("BodyStream — layout")
struct BodyStreamLayoutTests {

    @Test("P and T convert both ways at every boundary", arguments: [
        5, C - 1, C, C + 1, 2 * C, 3 * C, 3 * C + 17, 10 * C + 1
    ])
    func layoutRoundTrips(p: Int) throws {
        let fromP = try BodyStream.Layout(plaintextLength: UInt64(p))
        let fromT = try BodyStream.Layout(streamLength: fromP.streamLength)

        #expect(fromP == fromT)
        #expect(fromP.chunkCount == UInt64((p + C - 1) / C))
        #expect(fromP.streamLength == UInt64(p) + 16 * fromP.chunkCount)
        #expect(fromP.lastChunkPlaintextLength >= 1 && fromP.lastChunkPlaintextLength <= C)
    }

    @Test("a P that is a multiple of C ends on a full chunk, never an empty one")
    func multipleOfChunkSizeHasNoTrailer() throws {
        let layout = try BodyStream.Layout(plaintextLength: UInt64(3 * C))
        #expect(layout.chunkCount == 3)
        #expect(layout.lastChunkPlaintextLength == C)
        #expect(layout.streamLength == UInt64(3 * W))
    }

    @Test("a stream whose last chunk would be under 17 bytes is rejected")
    func shortLastChunkIsRejected() throws {
        #expect(throws: BodyStream.StreamError.invalidLayout) { _ = try BodyStream.Layout(streamLength: UInt64(2 * W + 16)) }
        #expect(throws: BodyStream.StreamError.invalidLayout) { _ = try BodyStream.Layout(streamLength: 16) }
        #expect(throws: BodyStream.StreamError.invalidLayout) { _ = try BodyStream.Layout(streamLength: 0) }
        // 17 bytes is one byte of plaintext and a tag: valid as a last chunk, once the whole is at least 5.
        _ = try BodyStream.Layout(streamLength: UInt64(W + 17))
    }

    @Test("a plaintext under 5 bytes has no manifest and is rejected")
    func tooSmallPlaintext() {
        #expect(throws: BodyStream.StreamError.invalidLayout) { _ = try BodyStream.Layout(plaintextLength: 4) }
        #expect(throws: BodyStream.StreamError.invalidLayout) { _ = try BodyStream.Layout(streamLength: 4 + 16) }
    }

    @Test("an absurd length is rejected, not trapped on")
    func absurdLength() {
        #expect(throws: BodyStream.StreamError.invalidLayout) { _ = try BodyStream.Layout(plaintextLength: UInt64.max) }
        #expect(throws: BodyStream.StreamError.invalidLayout) { _ = try BodyStream.Layout(streamLength: UInt64.max) }
    }
}

// MARK: - Round trip

@Suite("BodyStream — round trip")
struct BodyStreamRoundTripTests {

    @Test("the plaintext comes back, and the sealed length is T", arguments: [
        5, C - 1, C, C + 1, 3 * C, 3 * C + 17
    ])
    func roundTrip(p: Int) throws {
        let plaintext = pattern(p)
        let (stream, _, layout) = try seal(plaintext)

        #expect(UInt64(stream.count) == layout.streamLength)
        #expect(try open(stream) == plaintext)
    }

    @Test("the piece sizes fed to the sealer do not change the bytes", arguments: [1, 7, 4096, C, C + 1, 5 * C])
    func pieceSizeDoesNotMatter(piece: Int) throws {
        let plaintext = pattern(2 * C + 99)
        let reference = try seal(plaintext, piece: plaintext.count).stream

        #expect(try seal(plaintext, piece: piece).stream == reference)
    }

    @Test("the digest is the SHA-256 of the sealed stream")
    func digestCoversTheStream() throws {
        let (stream, digest, _) = try seal(pattern(3 * C + 17))
        #expect(digest == Data(SHA256.hash(data: stream)))
    }

    @Test("the sealer refuses more plaintext than the layout holds, and refuses to finish short")
    func sealerBounds() throws {
        let header = try headerAAD()
        var over = BodyStream.Sealer(sessionKey: sessionKey, header: header, layout: try .init(plaintextLength: 10))
        #expect(throws: BodyStream.StreamError.tooMuchInput) { try over.append(pattern(11)) { _ in } }

        var short = BodyStream.Sealer(sessionKey: sessionKey, header: header, layout: try .init(plaintextLength: 10))
        try short.append(pattern(9)) { _ in }
        #expect(throws: BodyStream.StreamError.inputShort) { _ = try short.finish { _ in } }

        var done = BodyStream.Sealer(sessionKey: sessionKey, header: header, layout: try .init(plaintextLength: 5))
        try done.append(pattern(5)) { _ in }
        _ = try done.finish { _ in }
        #expect(throws: BodyStream.StreamError.alreadyFinished) { _ = try done.finish { _ in } }
        #expect(throws: BodyStream.StreamError.alreadyFinished) { try done.append(Data()) { _ in } }
    }

    @Test("the opener takes chunks in order only, and nothing after the final one")
    func openerOrder() throws {
        let (stream, _, layout) = try seal(pattern(3 * C + 17))
        let header = try headerAAD()
        var opener = BodyStream.Opener(sessionKey: sessionKey, header: header, layout: layout)

        #expect(throws: BodyStream.StreamError.chunkOutOfOrder) {
            _ = try opener.open(chunk(1, of: stream, layout: layout), index: 1)
        }
        #expect(throws: BodyStream.StreamError.chunkWrongSize) {
            _ = try opener.open(chunk(0, of: stream, layout: layout).dropLast(), index: 0)
        }
        for i in 0..<Int(layout.chunkCount) {
            _ = try opener.open(chunk(i, of: stream, layout: layout), index: UInt64(i))
        }
        #expect(opener.isFinished)
        #expect(throws: BodyStream.StreamError.chunkAfterFinal) {
            _ = try opener.open(chunk(3, of: stream, layout: layout), index: 4)
        }
    }
}

// MARK: - ChunkBuffer

@Suite("BodyStream — ChunkBuffer")
struct ChunkBufferTests {

    @Test("complete chunks come out in order and the rest is held back")
    func accumulates() {
        var buffer = BodyStream.ChunkBuffer(chunkSize: 4)
        var out: [Data] = []
        buffer.append(Data([1, 2, 3])) { out.append($0) }
        #expect(out.isEmpty && buffer.count == 3)
        buffer.append(Data([4, 5, 6, 7, 8, 9])) { out.append($0) }
        #expect(out == [Data([1, 2, 3, 4]), Data([5, 6, 7, 8])])
        #expect(buffer.drain() == Data([9]))
        #expect(buffer.count == 0)
    }

    @Test("an exact multiple leaves nothing held")
    func exactMultiple() {
        var buffer = BodyStream.ChunkBuffer(chunkSize: 2)
        var out = 0
        buffer.append(Data([1, 2, 3, 4])) { _ in out += 1 }
        #expect(out == 2 && buffer.drain().isEmpty)
    }

    @Test("a slice with a non-zero start index is read from its own start")
    func slice() {
        var buffer = BodyStream.ChunkBuffer(chunkSize: 2)
        var out: [Data] = []
        buffer.append(Data([9, 9, 1, 2, 3]).dropFirst(2)) { out.append($0) }
        #expect(out == [Data([1, 2])] && buffer.drain() == Data([3]))
    }
}

// MARK: - Rejections

@Suite("BodyStream — what is rejected")
struct BodyStreamRejectionTests {

    private let plaintext = pattern(3 * C + 17)   // four chunks, the last short

    @Test("a dropped final chunk")
    func droppedFinalChunk() throws {
        let (stream, _, layout) = try seal(self.plaintext)
        let cut = stream.prefix(Int(layout.wireOffset(ofChunk: 3)))   // three full chunks remain

        #expect(throws: BodyStream.StreamError.chunkNotAuthentic) { _ = try open(Data(cut)) }
    }

    @Test("an appended chunk")
    func appendedChunk() throws {
        let (stream, _, _) = try seal(self.plaintext)
        var longer = stream
        longer.append(pattern(W, seed: 9))   // a whole extra chunk

        #expect(throws: BodyStream.StreamError.chunkNotAuthentic) { _ = try open(longer) }
    }

    @Test("a swapped pair")
    func swappedPair() throws {
        let (stream, _, layout) = try seal(self.plaintext)
        let swapped = replacing(2, in: replacing(1, in: stream, layout: layout, with: chunk(2, of: stream, layout: layout)),
                                layout: layout, with: chunk(1, of: stream, layout: layout))

        #expect(throws: BodyStream.StreamError.chunkNotAuthentic) { _ = try open(swapped) }
    }

    @Test("a chunk from another bundle")
    func chunkFromAnotherBundle() throws {
        let (stream, _, layout) = try seal(self.plaintext)
        let (other, _, _) = try seal(self.plaintext, key: otherSessionKey)
        let spliced = replacing(1, in: stream, layout: layout, with: chunk(1, of: other, layout: layout))

        #expect(throws: BodyStream.StreamError.chunkNotAuthentic) { _ = try open(spliced) }
    }

    @Test("a forged final flag, either way round")
    func forgedFinalFlag() throws {
        let (stream, _, layout) = try seal(self.plaintext)
        let header = try headerAAD()
        let key = BodyStream.streamKey(sessionKey: sessionKey)

        // The real final chunk, claimed as not final.
        #expect(throws: (any Error).self) {
            _ = try BodyStream.open(chunk: chunk(3, of: stream, layout: layout), index: 3, final: false, key: key, header: header)
        }
        // A middle chunk, claimed as final.
        #expect(throws: (any Error).self) {
            _ = try BodyStream.open(chunk: chunk(2, of: stream, layout: layout), index: 2, final: true, key: key, header: header)
        }
        // And the genuine flags open.
        _ = try BodyStream.open(chunk: chunk(3, of: stream, layout: layout), index: 3, final: true, key: key, header: header)
    }

    @Test("a non-final chunk presented last")
    func nonFinalPresentedLast() throws {
        let (stream, _, layout) = try seal(self.plaintext)
        // Three full chunks, the last of them one that was sealed as not final.
        var opener = BodyStream.Opener(
            sessionKey: sessionKey, header: try headerAAD(),
            layout: try .init(streamLength: layout.wireOffset(ofChunk: 3))
        )
        _ = try opener.open(chunk(0, of: stream, layout: layout), index: 0)
        _ = try opener.open(chunk(1, of: stream, layout: layout), index: 1)

        #expect(throws: BodyStream.StreamError.chunkNotAuthentic) {
            _ = try opener.open(chunk(2, of: stream, layout: layout), index: 2)
        }
        #expect(!opener.isFinished)
    }

    @Test("a header byte flipped in the AAD, wherever it falls")
    func everyHeaderAADByte() throws {
        let (stream, _, layout) = try seal(self.plaintext)
        let header = try headerAAD()
        let first = chunk(0, of: stream, layout: layout)
        let key = BodyStream.streamKey(sessionKey: sessionKey)
        _ = try BodyStream.open(chunk: first, index: 0, final: false, key: key, header: header)

        for i in header.indices {
            var flipped = header
            flipped[i] ^= 0x01
            #expect(throws: (any Error).self, "byte \(i) of the header AAD is not authenticated") {
                _ = try BodyStream.open(chunk: first, index: 0, final: false, key: key, header: flipped)
            }
        }
    }

    @Test("a manifest_length of zero, over 16 MiB, or cut short")
    func manifestLengthBounds() throws {
        func prefix(_ m: UInt32) -> Data { BodyStream.bigEndian32(m) }
        let limit = UInt32(BodyStream.maxManifestLength)

        #expect(throws: BodyStream.StreamError.manifestLengthOutOfRange) { _ = try BodyStream.Manifest.length(prefix: prefix(0)) }
        #expect(throws: BodyStream.StreamError.manifestLengthOutOfRange) { _ = try BodyStream.Manifest.length(prefix: prefix(limit + 1)) }
        #expect(throws: BodyStream.StreamError.manifestLengthOutOfRange) { _ = try BodyStream.Manifest.length(prefix: prefix(.max)) }
        #expect(throws: BodyStream.StreamError.manifestLengthOutOfRange) { _ = try BodyStream.Manifest.length(prefix: Data([0, 0, 1])) }
        #expect(try BodyStream.Manifest.length(prefix: prefix(1)) == 1)
        #expect(try BodyStream.Manifest.length(prefix: prefix(limit)) == Int(limit))
    }

    @Test("a manifest that would pass 16 MiB cannot be framed")
    func oversizeManifestRefused() throws {
        let payload = OccultaBundle.SealedPayload(message: Data(count: BodyStream.maxManifestLength), appVersion: "2.0.0")
        #expect(throws: BodyStream.StreamError.manifestLengthOutOfRange) { _ = try BodyStream.Manifest.frame(payload: payload) }
    }

    @Test("bytes left over, or a file still short, at the end")
    func lengthsMustAddUp() throws {
        let manifestLength = 100
        let streamed: [UInt64?] = [nil, 1000, 0, 25]
        let p = UInt64(4 + manifestLength + 1025)
        let layout = try BodyStream.Layout(plaintextLength: p)

        try BodyStream.Manifest.validate(manifestLength: manifestLength, streamedLengths: streamed, against: layout)
        #expect(throws: BodyStream.StreamError.lengthMismatch) {
            try BodyStream.Manifest.validate(manifestLength: manifestLength, streamedLengths: [nil, 1000, 0, 24], against: layout)
        }
        #expect(throws: BodyStream.StreamError.lengthMismatch) {
            try BodyStream.Manifest.validate(manifestLength: manifestLength, streamedLengths: [nil, 1000, 0, 26], against: layout)
        }
        #expect(throws: BodyStream.StreamError.lengthMismatch) {
            try BodyStream.Manifest.validate(manifestLength: manifestLength, streamedLengths: [UInt64.max, 1], against: layout)
        }
    }
}

// MARK: - Key, nonce, AAD

@Suite("BodyStream — key, nonce, AAD")
struct BodyStreamDerivationTests {

    @Test("the nonce is four zero bytes and the index, big-endian")
    func nonceLayout() {
        #expect(BodyStream.nonce(index: 0).withUnsafeBytes { Data($0) } == Data(count: 12))
        #expect(BodyStream.nonce(index: 0x0102030405060708).withUnsafeBytes { Data($0) }
                == Data([0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]))
    }

    @Test("the AAD is the header, the index and the final flag")
    func aadLayout() {
        let aad = BodyStream.aad(header: Data([0xAA, 0xBB]), index: 1, final: true)
        #expect(aad == Data([0xAA, 0xBB, 0, 0, 0, 0, 0, 0, 0, 1, 1]))
        #expect(BodyStream.aad(header: Data([0xAA]), index: 0, final: false) == Data([0xAA, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
    }

    @Test("the header AAD names the streamed version, then the secrecy and the blind")
    func headerAADLayout() throws {
        let aad = try BodyStream.headerAAD(secrecy: secrecy, blind: blind)
        let expected = try OccultaBundle.computeAdditionalAuthentication(version: .streamedBodyCapable, secrecy: secrecy) + blind

        #expect(aad == expected)
        #expect(String(data: aad.prefix(19), encoding: .utf8) == "streamedBodyCapable")
    }

    @Test("the streamed tier's marker byte is 0x0A, and maps back to it")
    func markerByte() {
        #expect(OccultaBundle.Version.streamedBodyCapable.wireByte == 0x0A)
        #expect(WireHandle.byteToVersion(0x0A) == .streamedBodyCapable)
        #expect(OccultaBundle.Version.streamedBodyCapable.rawValue == "streamedBodyCapable")
    }

    @Test("the stream key is not the session key, and two session keys give two stream keys")
    func streamKeyDerivation() {
        let a = BodyStream.streamKey(sessionKey: sessionKey).withUnsafeBytes { Data($0) }
        let b = BodyStream.streamKey(sessionKey: otherSessionKey).withUnsafeBytes { Data($0) }

        #expect(a.count == 32)
        #expect(a != sessionKey.withUnsafeBytes { Data($0) })
        #expect(a != b)
    }
}

// MARK: - Manifests

/// A streamed body built and read the way the two sides will: the reference for the manifest cases.
private struct ReferenceBody {
    let stream: Data
    let layout: BodyStream.Layout
    let framed: Data
    let streamedLengths: [UInt64?]

    /// `files` pairs each basket file with the bytes it streams, or nil for an inline one.
    init(files: [(file: File, streamed: Data?)], key: SymmetricKey = sessionKey) throws {
        let basket = Basket(files: files.map(\.file), date: Date(timeIntervalSinceReferenceDate: 0))
        let lengths = files.map { $0.streamed.map { UInt64($0.count) } }
        let payload = OccultaBundle.SealedPayload(
            message: try WireHandle.encode(basket: basket, streamedLengths: lengths),
            appVersion: "2.0.0", senderProof: Data(repeating: 7, count: 32), groupID: UUID()
        )
        let framed = try BodyStream.Manifest.frame(payload: payload)
        let body = framed + files.compactMap(\.streamed).reduce(Data(), +)
        let sealed = try seal(body, key: key)

        self.stream = sealed.stream
        self.layout = sealed.layout
        self.framed = framed
        self.streamedLengths = lengths
    }

    /// What a receiver recovers: the payload, the basket, and each streamed file's bytes.
    func read(key: SymmetricKey = sessionKey) throws -> (payload: OccultaBundle.SealedPayload, basket: Basket, streamed: [Data?]) {
        let plaintext = try open(self.stream, key: key)
        let m = try BodyStream.Manifest.length(prefix: plaintext)
        let manifestEnd = BodyStream.Manifest.prefixLength + m
        let payload = try BodyStream.Manifest.decode(plaintext.subdata(in: BodyStream.Manifest.prefixLength..<manifestEnd))
        let (basket, lengths) = try WireHandle.decode(streamedBasket: payload.message)
        try BodyStream.Manifest.validate(manifestLength: m, streamedLengths: lengths, against: self.layout)

        var cursor = manifestEnd
        let streamed: [Data?] = lengths.map { length in
            guard let length else { return nil }
            defer { cursor += Int(length) }
            return plaintext.subdata(in: cursor..<(cursor + Int(length)))
        }
        return (payload, basket, streamed)
    }
}

private func fileEntry(_ name: String, _ data: Data) -> (file: File, streamed: Data?) {
    (File(format: .file(.init(name: name, extension: "bin")), date: Date(timeIntervalSinceReferenceDate: 1)), data)
}

private func textEntry(_ text: String) -> (file: File, streamed: Data?) {
    (File(content: Data(text.utf8), format: .text, date: Date(timeIntervalSinceReferenceDate: 2)), nil)
}

@Suite("BodyStream — manifests")
struct BodyStreamManifestTests {

    @Test("an empty basket")
    func emptyBasket() throws {
        let read = try ReferenceBody(files: []).read()
        #expect(read.basket.files.isEmpty && read.streamed.isEmpty)
        #expect(read.payload.appVersion == "2.0.0")
    }

    @Test("text only: nothing streams, and the text is in the manifest")
    func textOnly() throws {
        let body = try ReferenceBody(files: [textEntry("hello"), textEntry("again")])
        let read = try body.read()

        #expect(read.basket.files.compactMap(\.content).map { String(data: $0, encoding: .utf8) } == ["hello", "again"])
        #expect(read.streamed.allSatisfy { $0 == nil })
        #expect(body.layout.plaintextLength == UInt64(body.framed.count))
    }

    @Test("many small files, in the manifest's order")
    func manySmallFiles() throws {
        let entries = (0..<50).map { fileEntry("f\($0)", pattern(10, seed: UInt8($0))) }
        let read = try ReferenceBody(files: entries).read()

        #expect(read.streamed == entries.map(\.streamed))
        #expect(read.basket.files.count == 50)
    }

    @Test("a zero-length streamed file")
    func zeroLengthFile() throws {
        let entries = [fileEntry("empty", Data()), fileEntry("after", pattern(300))]
        let read = try ReferenceBody(files: entries).read()

        #expect(read.streamed == [Data(), pattern(300)])
    }

    @Test("a streamed file that ends exactly on a chunk boundary")
    func fileEndsOnBoundary() throws {
        // Find the length that makes the whole plaintext a multiple of C. The manifest's size depends on
        // the digits of the length, so settle by iterating.
        var length = 2 * C
        for _ in 0..<5 {
            let probe = try ReferenceBody(files: [fileEntry("big", Data(count: length))])
            let remainder = Int(probe.layout.plaintextLength) % C
            if remainder == 0 { break }
            length += C - remainder
        }
        let body = try ReferenceBody(files: [fileEntry("big", pattern(length))])

        #expect(body.layout.plaintextLength % UInt64(C) == 0)
        #expect(body.layout.lastChunkPlaintextLength == C)
        #expect(try body.read().streamed == [pattern(length)])
    }

    @Test("a body read under another session key does not open")
    func wrongKey() throws {
        let body = try ReferenceBody(files: [fileEntry("a", pattern(1000))])
        #expect(throws: BodyStream.StreamError.chunkNotAuthentic) { _ = try body.read(key: otherSessionKey) }
    }

    @Test("a basket that streams a file, and one that streams a text, are not accepted")
    func streamedFormatsAreChecked() throws {
        let streamedText = Basket(files: [File(format: .text)])
        let asStreamed = try WireHandle.encode(basket: streamedText, streamedLengths: [5])
        #expect(throws: OccultaBundle.BundleError.malformedBundle) { _ = try WireHandle.decode(streamedBasket: asStreamed) }

        let inlineFile = Basket(files: [File(content: Data([1, 2, 3]), format: .file(.init(name: "a", extension: "bin")))])
        let notStreamed = try WireHandle.encode(basket: inlineFile)
        #expect(throws: OccultaBundle.BundleError.malformedBundle) { _ = try WireHandle.decode(streamedBasket: notStreamed) }

    }

    @Test("a streamed basket needs one length per file")
    func lengthsMustMatchFiles() {
        let basket = Basket(files: [File(format: .text)])
        #expect(throws: OccultaBundle.BundleError.malformedBundle) { _ = try WireHandle.encode(basket: basket, streamedLengths: []) }
    }

    @Test("an inline basket encodes exactly as it did before streamedLength existed")
    func inlineBasketBytesUnchanged() throws {
        let basket = Basket(
            id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            files: [File(id: UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!, content: Data([1, 2]), format: .text, date: nil)]
        )
        let bytes = try WireHandle.encode(basket: basket)

        #expect(String(data: bytes, encoding: .utf8)?.contains("streamedLength") == false)
        #expect(try WireHandle.encode(basket: basket, streamedLengths: [nil]) == bytes)
    }
}

// MARK: - Wire parsing

@Suite("WireHandle — header, sections and reader rules")
struct WireHandleStreamedParsingTests {

    private func bundle(version: OccultaBundle.Version, group: Bool = true, ciphertext: Data = Data(count: 40)) -> OccultaBundle {
        OccultaBundle(
            version: version,
            secrecy: secrecy,
            ciphertext: ciphertext,
            fingerprintNonce: Data(repeating: 1, count: 16),
            senderFingerprint: Data(repeating: 2, count: 32),
            group: group ? OccultaBundle.GroupEnvelope(
                blind: blind, blindNonce: Data(repeating: 3, count: 16),
                recipients: [OccultaBundle.Recipient(
                    secrecyContext: .init(mode: .longTermFallback, ephemeralPublicKey: Data(), prekeyID: nil),
                    wrappedPayload: Data(repeating: 4, count: 80)
                )]
            ) : nil
        )
    }

    @Test("the inline bytes are the header, the ciphertext and the sections, joined")
    func inlineIsTheThreeParts() throws {
        let inline = bundle(version: .v4)
        let whole = try WireHandle.encode(inline)
        let header = try WireHandle.encodeHeader(inline, ciphertextLength: UInt64(inline.ciphertext.count))
        let sections = try WireHandle.encodeSections(inline)

        #expect(header.count == WireHandle.headerLength)
        #expect(whole == header + inline.ciphertext + sections)
    }

    @Test("the header half and the sections half parse on their own")
    func halvesParse() throws {
        let inline = bundle(version: .v4)
        let header = try WireHandle.parseHeader(try WireHandle.encode(inline))
        let sections = try WireHandle.parseSections(try WireHandle.encodeSections(inline))

        #expect(header.version == 0x04 && header.minReaderVersion == 0x04)
        #expect(header.ciphertextLength == 40)
        #expect(header.mode == 0x05)
        #expect(sections.groupEnvelope != nil)
    }

    @Test("a streamed bundle is written with version 0x0A, and reads back")
    func streamedBundleRoundTrips() throws {
        let streamed = bundle(version: .streamedBodyCapable, ciphertext: Data(repeating: 9, count: 70))
        let bytes = try WireHandle.encode(streamed)

        #expect(bytes[4] == 0x0A && bytes[5] == 0x0A)
        let parsed = try WireHandle.parse(bytes)
        #expect(parsed.version == 0x0A && parsed.ciphertext.count == 70)
        #expect(try OccultaBundle(wireBundle: parsed).version == .streamedBodyCapable)
        #expect(try OccultaBundle.decoded(from: bytes).group?.recipients.count == 1)
    }

    @Test("a wire version other than 0x04 and 0x0A is rejected, 0x05 to 0x09 and the rest", arguments: [0x00, 0x01, 0x03, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0B, 0x0F, 0x80, 0xFF])
    func otherVersionsRejected(version: Int) throws {
        var bytes = try WireHandle.encode(bundle(version: .v4))
        bytes[4] = UInt8(version)
        bytes[5] = UInt8(version)   // equal, so only rule 1 can reject it

        #expect(throws: OccultaBundle.BundleError.unsupportedVersion) { _ = try WireHandle.parse(bytes) }
        #expect(throws: OccultaBundle.BundleError.unsupportedVersion) { _ = try WireHandle.parseHeader(bytes) }
    }

    @Test("min_reader_version must equal version", arguments: [(0x04, 0x0A), (0x0A, 0x04), (0x0A, 0x09), (0x04, 0x05), (0x04, 0x03)])
    func minReaderMustMatch(version: Int, minReader: Int) throws {
        var bytes = try WireHandle.encode(bundle(version: .v4))
        bytes[4] = UInt8(version)
        bytes[5] = UInt8(minReader)

        #expect(throws: OccultaBundle.BundleError.unsupportedVersion) { _ = try WireHandle.parse(bytes) }
    }

    @Test("a streamed bundle without a group envelope is malformed")
    func streamedNeedsGroupEnvelope() throws {
        let bytes = try WireHandle.encode(bundle(version: .streamedBodyCapable, group: false))
        #expect(throws: OccultaBundle.BundleError.malformedBundle) { _ = try WireHandle.parse(bytes) }
    }

    @Test("an inline bundle without one still parses, as it always has")
    func inlineMayLackGroupEnvelope() throws {
        let bytes = try WireHandle.encode(bundle(version: .v4, group: false))
        #expect(try WireHandle.parse(bytes).groupEnvelope == nil)
    }

    @Test("a duplicate group section is malformed")
    func duplicateSection() throws {
        let inline = bundle(version: .v4)
        let sections = try WireHandle.encodeSections(inline)
        #expect(throws: OccultaBundle.BundleError.malformedBundle) { _ = try WireHandle.parseSections(sections + sections) }
    }

    @Test("a header shorter than 167 bytes is rejected")
    func shortHeader() throws {
        let bytes = try WireHandle.encode(bundle(version: .v4))
        #expect(throws: OccultaBundle.BundleError.unsupportedVersion) { _ = try WireHandle.parseHeader(bytes.prefix(166)) }
    }

    @Test("flipping any header byte either fails to parse, fails to open, or hits a field the bundle never authenticated")
    func everyOuterHeaderByte() throws {
        let body = pattern(C + 50)
        let streamed = bundle(version: .streamedBodyCapable)
        let aad = try BodyStream.headerAAD(secrecy: streamed.secrecy, blind: blind)
        let (stream, _, layout) = try seal(body, header: aad)
        var wire = try WireHandle.encodeHeader(streamed, ciphertextLength: layout.streamLength)
        wire.append(stream)
        wire.append(try WireHandle.encodeSections(streamed))

        // Offsets the AAD does not cover: `flags` (7, 8), the zero filler that stands in for an absent
        // prekeyID (10..<46), the fingerprint nonce (111..<127) and the sender fingerprint (127..<159).
        // Routing and padding, as in the inline layout; the sender's identity is bound by `senderProof`.
        let unauthenticated = Set([7, 8] + Array(10..<46) + Array(111..<159))

        for offset in 0..<WireHandle.headerLength {
            var flipped = wire
            flipped[offset] ^= 0x01
            let accepted: Bool
            do {
                let parsed = try WireHandle.parse(flipped)
                let rebuilt = try OccultaBundle(wireBundle: parsed)
                let flippedAAD = try BodyStream.headerAAD(secrecy: rebuilt.secrecy, blind: try #require(rebuilt.group).blind)
                _ = try open(parsed.ciphertext, header: flippedAAD)
                accepted = true
            } catch {
                accepted = false
            }
            #expect(accepted == unauthenticated.contains(offset), "header byte \(offset)")
        }
    }
}

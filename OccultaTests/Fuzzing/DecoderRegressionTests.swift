//
//  DecoderRegressionTests.swift
//  OccultaTests
//
//  The inputs `DecoderFuzzTests` found, kept as the exact bytes, so each stays fixed without the fuzzer
//  having to rediscover it. One test per bug, named for its entry in `Docs/Features/Secure Mode/bugs.md`.
//

import Testing
import Foundation
import UniformTypeIdentifiers
import ImageIO
@testable import Occulta
@testable import OccultaFormats
@testable import OccultaCore

// MARK: - Bug 186

@Suite("Bug 186 — decoders that read a Data slice by absolute index")
struct SliceIndexRegressionTests {

    /// `bytes` as a slice of a longer buffer, so `startIndex` is `padding` and `bytes[0]` is out of range.
    private func slice(_ bytes: [UInt8], padding: Int = 14) -> Data {
        let wide = Data(repeating: 0xAB, count: padding) + Data(bytes)
        let slice = wide[padding...]
        #expect(slice.startIndex == padding)
        return slice
    }

    /// The exact input the fuzzer found: seed 1, iteration 1 of the depth target, a two-byte depth at index 14.
    @Test("a two-byte depth plaintext that is a slice decodes, and decodes as the same bytes do on their own")
    func depthSlice() {
        let found = self.slice([0xFF, 0xFE])
        #expect(DepthCodec.decode(found) == -1)

        for value in [0, 1, 7, 253, -1, Int.max] {
            let encoded = DepthCodec.encode(value)
            #expect(DepthCodec.decode(self.slice([UInt8](encoded))) == DepthCodec.decode(encoded))
        }
    }

    @Test("a legacy JSON depth that is a slice decodes too")
    func legacyDepthSlice() {
        #expect(DepthCodec.decode(self.slice(Array("7".utf8))) == 7)
        #expect(DepthCodec.decode(self.slice(Array("-1".utf8))) == -1)
        #expect(DepthCodec.decode(self.slice(Array("x".utf8))) == nil)
    }

    /// The fuzzer's crash: `ChallengePayload.init(from:)`, `Data subscript getter`, on the 72 bytes as a slice.
    @Test("an identity-challenge payload that is a slice reads the same fields as the bytes on their own")
    @MainActor
    func challengePayloadSlice() throws {
        let payload = IdentityChallenge.ChallengePayload(
            nonce: Data(repeating: 1, count: 32), timestamp: IdentityChallenge.encodeTimestamp(1_700_000_000),
            challengerFingerprint: Data(repeating: 3, count: 32)
        )
        let encoded = payload.encoded()
        #expect(encoded.count == 72)

        let decoded = try IdentityChallenge.ChallengePayload(from: self.slice([UInt8](encoded)))
        #expect(decoded.nonce == payload.nonce)
        #expect(decoded.challengerFingerprint == payload.challengerFingerprint)
        #expect(try IdentityChallenge.decodeTimestamp(decoded.timestamp) == 1_700_000_000)
        #expect(decoded.encoded() == encoded)
    }

    @Test("an identity-challenge response that is a slice reads the same fields as the bytes on their own")
    @MainActor
    func responsePayloadSlice() throws {
        let response = IdentityChallenge.ResponsePayload(challengeNonce: Data(repeating: 1, count: 32), signature: Data(repeating: 9, count: 71))
        let encoded = response.encoded()

        let decoded = try IdentityChallenge.ResponsePayload(from: self.slice([UInt8](encoded)))
        #expect(decoded.challengeNonce == response.challengeNonce)
        #expect(decoded.signature == response.signature)
        #expect(decoded.encoded() == encoded)
    }

    /// The fuzzer's second crash in the same type: `Fatal error: load from misaligned raw pointer`. `load(as:)` wants an
    /// 8-aligned address, and a slice starts wherever its parent's index puts it.
    @Test("a timestamp that is a slice at any offset decodes")
    @MainActor
    func timestampSlice() throws {
        let stamp = [UInt8](IdentityChallenge.encodeTimestamp(0x0102_0304_0506_0708))
        for padding in 1...17 {
            #expect(try IdentityChallenge.decodeTimestamp(self.slice(stamp, padding: padding)) == 0x0102_0304_0506_0708, "padding \(padding)")
        }
        #expect(try IdentityChallenge.decodeTimestamp(Data(stamp)) == 0x0102_0304_0506_0708)
        #expect(throws: (any Error).self) { try IdentityChallenge.decodeTimestamp(self.slice([1, 2, 3], padding: 5)) }
    }

    @Test("the length checks still refuse a slice of the wrong size")
    @MainActor
    func wrongSizeSlice() {
        #expect(throws: (any Error).self) { try IdentityChallenge.ChallengePayload(from: self.slice([UInt8](repeating: 0, count: 71))) }
        #expect(throws: (any Error).self) { try IdentityChallenge.ChallengePayload(from: self.slice([UInt8](repeating: 0, count: 73))) }
        #expect(throws: (any Error).self) { try IdentityChallenge.ResponsePayload(from: self.slice([UInt8](repeating: 0, count: 32))) }
    }
}

// MARK: - Bug 189

/// 513 opening brackets and nothing else: the input that ends the process inside Foundation's JSON scanner
/// (`JSONScanner.scanArray()`, `EXC_BREAKPOINT`), on macOS 26 and on the iOS 26.2 Simulator runtime. A trap is not a
/// throw, so each of these only has to return for the fix to be shown: a failure here is the test host dying.
@Suite("Bug 189 — a JSON document of 513 open brackets")
struct NestingRegressionTests {

    static let brackets = Data(repeating: UInt8(ascii: "["), count: 513)

    private func be32(_ value: Int) -> Data { Data((0..<4).map { UInt8(truncatingIfNeeded: value >> (24 - 8 * $0)) }) }

    @Test("a .occ file that is exactly that is refused as any malformed file is")
    func fileOfBrackets() {
        #expect(Self.brackets.count == 513 && Self.brackets.allSatisfy { $0 == 0x5B })
        #expect(throws: (any Error).self) { try OccultaBundle.decoded(from: Self.brackets) }
    }

    @Test("a binary bundle whose unauthenticated group section is that is refused, and its sections still parse")
    func groupSectionOfBrackets() throws {
        let bundle = FuzzSeeds.groupBundle()
        let section = Data([0x01]) + self.be32(Self.brackets.count) + Self.brackets
        let bytes = try WireHandle.encodeHeader(bundle, ciphertextLength: 0) + section

        // The structure is sound; it is the JSON inside that is hostile, so the refusal is `BoundedJSON`'s.
        #expect(try WireHandle.parse(bytes).groupEnvelope == Self.brackets)
        #expect(throws: (any Error).self) { try OccultaBundle.decoded(from: bytes) }
    }

    @Test("a payload, a basket and a file entry whose JSON block is that are refused")
    func payloadAndBasket() {
        let message = Data() + Data(count: 8)
        #expect(throws: (any Error).self) { try WireHandle.decode(payload: self.be32(513) + Self.brackets + message) }
        #expect(throws: (any Error).self) { try WireHandle.decode(basket: self.be32(513) + Self.brackets + self.be32(0)) }

        let meta = Data(#"{"id":"C3C3C3C3-0000-4000-8000-000000000004"}"#.utf8)
        let oneFile = self.be32(meta.count) + meta + self.be32(1) + self.be32(513) + Self.brackets + Data(count: 8)
        #expect(throws: (any Error).self) { try WireHandle.decode(basket: oneFile) }
    }

    @Test("a legacy depth row that is that is unreadable, not fatal")
    func legacyDepth() {
        #expect(DepthCodec.decode(Self.brackets) == nil)
    }

    @Test("a nearby phone's message that is that is dropped, and the exchange stays where it was")
    @MainActor
    func exchangeMessage() async throws {
        let target = ExchangeSessionTarget()
        await target.pin()
        try target.run(Self.brackets)
        // One that is valid after it: the manager still reads messages.
        try target.run(AppFuzzTargets.exchangeSeeds()[4].bytes)
    }

    // MARK: The guard itself

    private struct Node: Codable, Equatable { var next: [Node]? }

    @Test("nesting is counted outside strings, escapes included, and an unbalanced close is not a negative depth")
    func counting() {
        func depth(_ text: String) -> Int { BoundedJSON.nesting(of: Data(text.utf8)) }
        #expect(depth("") == 0)
        #expect(depth("1") == 0)
        #expect(depth("[[{}],[]]") == 3)
        #expect(depth(#"{"a":"[[[[[["}"#) == 1)
        #expect(depth(#"{"a":"\"[[[[","b":[1]}"#) == 2)
        #expect(depth("]]]]]][") == 1)
        #expect(depth(#"["unterminated [[[["#) == 1)
        #expect(BoundedJSON.nesting(of: Self.brackets) > BoundedJSON.maxDepth)
    }

    @Test("a document at the limit decodes as it always did, one level deeper is refused")
    func limit() throws {
        // Each level of `Node` is two levels of JSON, an object and an array, and the innermost `{}` is a last one.
        func document(levels: Int) -> Data {
            Data((String(repeating: #"{"next":["#, count: levels) + "{}" + String(repeating: "]}", count: levels)).utf8)
        }
        let atLimit = document(levels: 31)
        #expect(BoundedJSON.nesting(of: atLimit) == 63)
        #expect(try BoundedJSON.decode(Node.self, from: atLimit) == (try JSONDecoder().decode(Node.self, from: atLimit)))

        let over = document(levels: 32)
        #expect(BoundedJSON.nesting(of: over) == 65)
        #expect(throws: DecodingError.self) { try BoundedJSON.decode(Node.self, from: over) }

        // The limit itself, on bare brackets: 64 is let through to the parser (which then finds it unterminated), 65 is not.
        struct Anything: Decodable { init(from decoder: Decoder) throws {} }
        let balanced = { (depth: Int) in Data((String(repeating: "[", count: depth) + String(repeating: "]", count: depth)).utf8) }
        #expect(throws: Never.self) { try BoundedJSON.decode(Anything.self, from: balanced(64)) }
        #expect(throws: DecodingError.self) { try BoundedJSON.decode(Anything.self, from: balanced(65)) }
    }

    @Test("what Occulta writes decodes through it to the same value as through JSONDecoder")
    func realDocuments() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let payload = try encoder.encode(FuzzSeeds.richPayload())
        let basket = try encoder.encode(FuzzSeeds.richBasket())
        let recipient = try encoder.encode(FuzzSeeds.richRecipientPayload())
        for bytes in [payload, basket, recipient] { #expect(BoundedJSON.nesting(of: bytes) < 16, "the deepest real document nests \(BoundedJSON.nesting(of: bytes))") }

        let viaBounded = try encoder.encode(try BoundedJSON.decode(OccultaBundle.SealedPayload.self, from: payload))
        let viaFoundation = try encoder.encode(try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: payload))
        #expect(viaBounded == viaFoundation)
        // Every recorded vector that is JSON.
        for vector in FuzzVectors.entries(ofKind: "recipientPayload", "legacyBundle") {
            #expect(BoundedJSON.nesting(of: vector.bytes) <= BoundedJSON.maxDepth, "\(vector.name)")
        }
    }
}

// MARK: - Bug 187

@Suite("Bug 187 — a shared image that declares more pixels than the app will decode", .serialized)
@MainActor
struct ImageSizeRegressionTests {

    /// A valid PNG of zeros, `width` by `height`, one bit per pixel, a few kilobytes for tens of millions of
    /// pixels: the IDAT is a fixed-Huffman deflate stream of one literal and then 258-byte copies of it, which is
    /// what makes the file small and the decoded image large. Written out here so the bytes don't depend on the
    /// system's compressor.
    static func png(width: Int, height: Int) -> Data {
        let rowBytes = (width + 7) / 8 + 1
        let raw = rowBytes * height

        var bits = [UInt8]()
        var bitCount = 0
        func put(_ value: Int, _ count: Int, msbFirst: Bool) {
            for index in 0..<count {
                let bit = msbFirst ? (value >> (count - 1 - index)) & 1 : (value >> index) & 1
                if bitCount % 8 == 0 { bits.append(0) }
                bits[bits.count - 1] |= UInt8(bit << (bitCount % 8))
                bitCount += 1
            }
        }
        put(1, 1, msbFirst: false); put(1, 2, msbFirst: false)    // final block, fixed Huffman codes
        put(0x30, 8, msbFirst: true)                              // literal 0
        for _ in 0..<((raw - 1) / 258) { put(0xC5, 8, msbFirst: true); put(0, 5, msbFirst: true) }   // length 258, distance 1
        for _ in 0..<((raw - 1) % 258) { put(0x30, 8, msbFirst: true) }                              // what is left
        put(0, 7, msbFirst: true)                                 // end of block

        let adler = UInt32(truncatingIfNeeded: ((raw % 65_521) << 16) | 1)    // the sum of zeros is 1; b is raw mod 65521
        let idat = [0x78, 0x01] + bits + be32(adler)
        let header = be32(UInt32(width)) + be32(UInt32(height)) + [1, 0, 0, 0, 0]   // 1-bit grayscale
        return Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] + chunk("IHDR", header) + chunk("IDAT", idat) + chunk("IEND", []))
    }

    private static func be32(_ value: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: value >> UInt32(24 - 8 * $0)) } }

    private static func chunk(_ type: String, _ body: [UInt8]) -> [UInt8] {
        let typed = Array(type.utf8) + body
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in typed {
            crc ^= UInt32(byte)
            for _ in 0..<8 { crc = crc & 1 != 0 ? (crc >> 1) ^ 0xEDB8_8320 : crc >> 1 }
        }
        return be32(UInt32(body.count)) + typed + be32(~crc)
    }

    private func stage(_ image: Data, uti: String = "public.png", ext: String = "png") throws -> (id: String, container: URL) {
        let container = FileManager.default.temporaryDirectory.appendingPathComponent("fuzz-share-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: container, withIntermediateDirectories: true)
        return (try FuzzShareStaging.stage(content: image, uti: uti, ext: ext, in: container), container)
    }

    @Test("the generated PNG is a real image of the size it declares, and a few kilobytes")
    func generatedPNGIsValid() throws {
        let image = Self.png(width: 64, height: 32)
        let source = try #require(CGImageSourceCreateWithData(image as CFData, nil))
        let properties = try #require(CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any])
        #expect((properties[kCGImagePropertyPixelWidth] as? Int) == 64)
        #expect((properties[kCGImagePropertyPixelHeight] as? Int) == 32)
        #expect(CGImageSourceCreateImageAtIndex(source, 0, nil) != nil, "the generated image does not decode")

        #expect(Self.png(width: 10_001, height: 10_000).count < 120_000)
    }

    @Test("an image of 400 million declared pixels is refused before it is decoded, and nothing is left on disk")
    func refusesOversize() throws {
        let image = Self.png(width: 20_000, height: 20_000)
        #expect(image.count < 500_000, "the bomb should be small: \(image.count) bytes")
        let (id, container) = try self.stage(image)
        defer { try? FileManager.default.removeItem(at: container) }

        #expect(throws: ShareSession.Errors.imageTooLarge) {
            try ShareSession.staged(id: id, in: container, keyManager: FuzzShareStaging.key)
        }
        #expect(!FileManager.default.fileExists(atPath: ShareSession.directory(for: id, in: container).path))
    }

    @Test("the limit is on the product of the two sides, and a little over it is refused")
    func limitIsOnTheProduct() throws {
        #expect(ShareSession.maxImagePixels == 100_000_000)
        // 100,001,000 pixels, in a shape neither side of which is large.
        let (id, container) = try self.stage(Self.png(width: 100_001, height: 1_000))
        defer { try? FileManager.default.removeItem(at: container) }
        #expect(throws: ShareSession.Errors.imageTooLarge) {
            try ShareSession.staged(id: id, in: container, keyManager: FuzzShareStaging.key)
        }
    }

    // MARK: A chunk that declares more than the file holds

    /// Signature, an IHDR for a 2 by 2 RGBA image, then an `iTXt` chunk header that declares 2,000,000,000 bytes, then
    /// an IDAT and an IEND which the declared chunk swallows. 79 bytes. ImageIO allocates the declared length when it
    /// reads the header: 1.9 GiB on macOS 26, and a transient 2 GB peak on the iOS 26.2 Simulator runtime.
    private static let declares2GB = Hex.decode("89504e470d0a1a0a0000000d494844520000000200000002080600000072b60d2477359400695458740000000e49444154789c63a8870206180300478207f193d719280000000049454e44ae426082")!

    /// The same image, well formed.
    private static let wellFormed = Hex.decode("89504e470d0a1a0a0000000d494844520000000200000002080600000072b60d240000000e49444154789c63a8870206180300478207f193d719280000000049454e44ae426082")!

    /// What the fuzzer found (seed 1, iteration 151 of the staged-file target): a 2 by 2 PNG with an EXIF chunk, in which
    /// an `iTXt` length was set to 1,676,476,820. The file is 574 bytes; the process grew by 1,032 MiB.
    private static let fuzzFound = Hex.decode("89504e470d0a1a0a0000000d494844520000000200000002080600000072b60d24000000017352474200aece1ce900000086655849664d4d002ad8bb686bbd3be3f800880a887b0b7b060000876900040000000100000032882500040000000100000050000000000002a00200040000000100000002a0030004000000010000000280000000000200010002000000024e00000000020005000000030000006e0000000000000033000000010000001e00000001000000342b4964f6ee04567963ed019469545874584d4c3a636f6d2e61646f62652e786d7000000000003c783a786d706d65746120786d6c6e733a783d2261646f62653a6e733a6d6574612f2220783a786d70746b3d22584d5020436f726520362e302e30223e0a2020203c7264663a52444620786d6c6e733a7264663d22687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e7323223e0a2020202020203c7264663a4465736372697074696f6e207264663a61626f75743d22220a202020202020202020202020786d6c6e733a657869663d22687474703a2f2f6e732e61646f62652e636f6d2f657869662f312e302f223e0a2020202020202020203c657869663a4750534c6174697464655265663e0a2020202020203c2f7264663a4465736372697074696f6e3e0a2020203c2f7264663a5244463e0a3c2f783a786d706d6574613e0a953a5a690000001449444154081d63fcffff7f3d031030810810000036f803806de6c04c0000000049454e44ae4260")!

    @Test("a PNG whose chunk is longer than the file is refused before ImageIO reads it, and nothing is left on disk")
    func refusesOverrunningChunk() throws {
        #expect(Self.declares2GB.count == 79)
        for image in [Self.declares2GB, Self.fuzzFound] {
            #expect(ShareSession.pngChunkOverruns(image))
            let (id, container) = try self.stage(image)
            defer { try? FileManager.default.removeItem(at: container) }

            #expect(throws: ShareSession.Errors.imageMalformed) {
                try ShareSession.staged(id: id, in: container, keyManager: FuzzShareStaging.key)
            }
            #expect(!FileManager.default.fileExists(atPath: ShareSession.directory(for: id, in: container).path))
        }
    }

    @Test("the chunk check passes a well-formed PNG, reads a slice, and ignores what is not a PNG")
    func chunkCheck() throws {
        #expect(!ShareSession.pngChunkOverruns(Self.wellFormed))
        #expect(ShareSession.pngChunkOverruns(Self.declares2GB))

        // As a slice that starts past 0.
        let wide = Data(repeating: 0xAB, count: 9) + Self.declares2GB
        #expect(ShareSession.pngChunkOverruns(wide[9...]))
        #expect(!ShareSession.pngChunkOverruns((Data(repeating: 0xAB, count: 9) + Self.wellFormed)[9...]))

        // A chunk length of 2^31 is not one the format allows, whatever the file holds.
        var tooLong = Self.wellFormed
        tooLong.replaceSubrange(33..<37, with: [0x80, 0x00, 0x00, 0x00])
        #expect(ShareSession.pngChunkOverruns(tooLong))

        #expect(!ShareSession.pngChunkOverruns(Data()))
        #expect(!ShareSession.pngChunkOverruns(Data([0x89, 0x50, 0x4E, 0x47])))
        #expect(!ShareSession.pngChunkOverruns(Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])))
        #expect(!ShareSession.pngChunkOverruns(try #require(ShareSessionTarget.image(as: .jpeg))))
        #expect(!ShareSession.pngChunkOverruns(try #require(ShareSessionTarget.image(as: .png))))
    }

    @Test("a well-formed PNG is still stripped and returned")
    func wellFormedPNGPasses() throws {
        let (id, container) = try self.stage(Self.wellFormed)
        defer { try? FileManager.default.removeItem(at: container) }
        #expect(try ShareSession.staged(id: id, in: container, keyManager: FuzzShareStaging.key).files.count == 1)
    }

    @Test("an ordinary image is still stripped and returned")
    func ordinaryImageUnchanged() throws {
        let jpeg = try #require(ShareSessionTarget.image(as: .jpeg))
        let (id, container) = try self.stage(jpeg, uti: "public.jpeg", ext: "jpg")
        defer { try? FileManager.default.removeItem(at: container) }

        let staged = try ShareSession.staged(id: id, in: container, keyManager: FuzzShareStaging.key)
        #expect(staged.files.count == 1)
        #expect(staged.files.first?.content?.isEmpty == false)
    }
}

// MARK: - Cost bounds

/// What a hostile input is allowed to cost, where the fuzzer can't say: the cost is in a shape of input it would never
/// build by chance.
@Suite("Hostile-input cost bounds")
struct CostBoundTests {

    /// A trustee can hand back as many well-formed shares as there are contacts. The subset search behind a backup
    /// restore must stop at its attempt limit however many there are, and spend no more than that on checks.
    @Test("a set of well-formed shares that open nothing costs at most the attempt limit")
    func shamirSearchIsBounded() {
        let shares: [[UInt8]] = (1...12).map { x in [UInt8(x)] + (0..<32).map { UInt8(truncatingIfNeeded: $0 &* x &+ 3) } }
        var checks = 0
        #expect(throws: ShamirSecretSharing.Error.noVerifiedSubset) {
            try ShamirSecretSharing.reconstruct(shares: shares, maxAttempts: 1_024) { _ in checks += 1; return false }
        }
        #expect(checks <= 1_024, "\(checks) checks")
        #expect(checks > 0)
    }

    @Test("a stream that declares the largest layout is refused or sized, never computed past the end")
    func layoutAtTheLimits() {
        for length in [BodyStream.maximumStreamLength, BodyStream.maximumStreamLength + 1, .max, 0, 1] as [UInt64] {
            _ = try? BodyStream.Layout(streamLength: length)
        }
        let largest = try? BodyStream.Layout(streamLength: BodyStream.maximumStreamLength)
        #expect(largest == nil || largest!.streamLength == BodyStream.maximumStreamLength)
    }
}

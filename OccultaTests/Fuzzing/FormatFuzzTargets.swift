//
//  FormatFuzzTargets.swift
//  OccultaTests
//
//  The decoders of `OccultaCore` and `OccultaFormats`, as fuzz targets. Pure: bytes in, a value, an error or
//  nil out, with no store, no key manager and no I/O, so they also build into the standalone harness.
//
//  A target that accepts an input also checks that it re-encodes consistently: encoding what was decoded and
//  decoding that again gives the same encoding. The decoders tolerate things the encoders never write (trailing
//  bytes, unknown TLV sections, a reordered JSON key), so the check is on the second generation, not on the
//  input.
//
//  Both `OccultaFormats` and `OccultaCore` are `@testable` here. The decoders aren't all public (`MLKEMKeyCheck`,
//  `BodyStream`'s internals), and the fuzzer has no reason to stay behind the API an app sees.
//

import Foundation
import CryptoKit
#if canImport(OccultaFormats)
@testable import OccultaFormats
#endif
#if canImport(OccultaCore)
@testable import OccultaCore
#endif

// MARK: - The target list

nonisolated enum FormatFuzzTargets {
    static var all: [any FuzzTarget] {
        [
            BundleEnvelopeTarget(),
            WireParseTarget(),
            SealedPayloadTarget(),
            BasketTarget(),
            DepthCodecTarget(),
            JSONTarget<OccultaBundle.RecipientPayload>(
                name: "RecipientPayload JSON", seeds: Self.recipientPayloadSeeds(),
                isConsumed: { _ = ShardPadding.tier(for: $0.shardOperations.count) }
            ),
            JSONTarget<OccultaBundle.SealedPayload>(name: "SealedPayload JSON (legacy)", seeds: Self.sealedPayloadJSONSeeds()),
            JSONTarget<Basket>(name: "Basket JSON (legacy)", seeds: Self.basketJSONSeeds()),
            JSONTarget<OccultaBundle.GroupEnvelope>(name: "GroupEnvelope JSON", seeds: Self.groupEnvelopeSeeds()),
            JSONTarget<IdentityChallengeEnvelope>(name: "IdentityChallengeEnvelope JSON", seeds: Self.challengeEnvelopeSeeds()),
            SignedAttributeTarget(),
            IntroductionCardTarget(),
            CardIntroductionTarget(),
            CardBootstrapTarget(),
            CardMeetingTarget(),
            BodyStreamLayoutTarget(),
            BodyStreamOpenerTarget(),
            BodyStreamManifestTarget(),
            ShamirTarget(),
            MLKEMKeyCheckTarget(),
        ] + Self.postQuantumTargets
    }

    private static var postQuantumTargets: [any FuzzTarget] {
        #if DEBUG
        if #available(iOS 26, macOS 26, *) { return [PostQuantumProviderTarget()] }
        #endif
        return []
    }

    // MARK: Seeds shared by the JSON targets

    private static func json<T: Encodable>(_ value: T) -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return try! encoder.encode(value)
    }

    static func recipientPayloadSeeds() -> [FuzzSeedInput] {
        FuzzVectors.entries(ofKind: "recipientPayload").map { FuzzSeedInput($0.name, $0.bytes, isText: true) }
            + [FuzzSeedInput("rich recipient payload", Self.json(FuzzSeeds.richRecipientPayload()), isText: true)]
    }

    static func sealedPayloadJSONSeeds() -> [FuzzSeedInput] {
        [FuzzSeedInput("rich sealed payload (JSON)", Self.json(FuzzSeeds.richPayload()), isText: true)]
    }

    static func basketJSONSeeds() -> [FuzzSeedInput] {
        [FuzzSeedInput("rich basket (JSON)", Self.json(FuzzSeeds.richBasket()), isText: true)]
    }

    static func groupEnvelopeSeeds() -> [FuzzSeedInput] {
        [FuzzSeedInput("group envelope (JSON)", Self.json(FuzzSeeds.groupBundle().group!), isText: true)]
    }

    static func challengeEnvelopeSeeds() -> [FuzzSeedInput] {
        [
            FuzzSeedInput("challenge", Self.json(IdentityChallengeEnvelope.challenge(payload: Data(repeating: 1, count: 72), contextNote: "Is this you?")), isText: true),
            FuzzSeedInput("response", Self.json(IdentityChallengeEnvelope.response(payload: Data(repeating: 2, count: 100))), isText: true),
        ]
    }
}

// MARK: - A JSON type decoded with `JSONDecoder`

/// Any `Codable` decoded from JSON. Accepted means it decodes and its encoding is stable.
nonisolated struct JSONTarget<T: Codable>: FuzzTarget {
    let name: String
    let corpus: [FuzzSeedInput]
    /// Touches the decoded value the way the app's next step does, so a trap there counts here.
    let isConsumed: @Sendable (T) -> Void

    init(name: String, seeds: [FuzzSeedInput], isConsumed: @escaping @Sendable (T) -> Void = { _ in }) {
        self.name = name
        self.corpus = seeds
        self.isConsumed = isConsumed
    }

    func run(_ input: Data) throws {
        let value = try BoundedJSON.decode(T.self, from: input)
        self.isConsumed(value)

        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let first = try encoder.encode(value)
        let second = try encoder.encode(try JSONDecoder().decode(T.self, from: first))
        guard first == second else { throw FuzzViolation("\(T.self): re-encoding a decoded value is not stable") }
    }
}

// MARK: - OccultaBundle.decoded(from:)

/// The first thing a `.occ` file meets: `OccultaBundle.decoded(from:)`, the binary envelope or the legacy JSON.
nonisolated struct BundleEnvelopeTarget: FuzzTarget {
    let name = "OccultaBundle.decoded"

    var corpus: [FuzzSeedInput] {
        var seeds = FuzzVectors.entries(ofKind: "envelope", "groupEnvelope").map {
            FuzzSeedInput($0.name, $0.bytes, lengthFields: FuzzLayout.envelope($0.bytes))
        }
        seeds += FuzzVectors.entries(ofKind: "legacyBundle").map { FuzzSeedInput($0.name, $0.bytes, isText: true) }
        let built = try! WireHandle.encode(FuzzSeeds.groupBundle())
        seeds.append(FuzzSeedInput("built group envelope", built, lengthFields: FuzzLayout.envelope(built)))
        let streamed = OccultaBundle(
            version: .streamedBodyCapable, secrecy: FuzzSeeds.groupBundle().secrecy, ciphertext: Data(),
            fingerprintNonce: Data(repeating: 1, count: 16), senderFingerprint: Data(repeating: 2, count: 32),
            group: FuzzSeeds.groupBundle().group
        )
        let streamedBytes = try! WireHandle.encodeHeader(streamed, ciphertextLength: 64) + Data(repeating: 3, count: 64) + WireHandle.encodeSections(streamed)
        seeds.append(FuzzSeedInput("built streamed envelope", streamedBytes, lengthFields: FuzzLayout.envelope(streamedBytes)))
        return seeds
    }

    func run(_ input: Data) throws {
        let first = try OccultaBundle.decoded(from: input)
        _ = first.securityLabel
        _ = first.isForwardSecret
        _ = first.group?.recipients.map(\.secrecyContext.mode)

        let isBinary = input.prefix(WireHandle.magic.count).elementsEqual(WireHandle.magic)
        guard isBinary else {
            // Legacy JSON: the encoding is stable.
            guard first.version != .unsupported, first.secrecy.mode != .unsupported else { return }
            let once = try first.encoded(version: .v3fs)
            let twice = try OccultaBundle.decoded(from: once).encoded(version: .v3fs)
            guard once == twice else { throw FuzzViolation("legacy JSON bundle: re-encoding is not stable") }
            return
        }

        // Binary: a decoded bundle encodes, and what it encodes decodes to the same bundle.
        let once = try WireHandle.encode(first)
        let second = try OccultaBundle.decoded(from: once)
        let twice = try WireHandle.encode(second)
        guard once == twice else { throw FuzzViolation("binary bundle: re-encoding is not stable") }
        guard first.version == second.version, first.secrecy.mode == second.secrecy.mode,
              first.secrecy.prekeyID == second.secrecy.prekeyID,
              first.secrecy.ephemeralPublicKey == second.secrecy.ephemeralPublicKey,
              first.ciphertext == second.ciphertext, first.fingerprintNonce == second.fingerprintNonce,
              first.senderFingerprint == second.senderFingerprint
        else { throw FuzzViolation("binary bundle: a field changed across a re-encode") }
    }
}

// MARK: - WireHandle.parse, parseHeader, parseSections

/// The three parsers `OccultaBundle.decoded` and `StreamedBody` are built from, called directly, since the
/// streamed layout reads the header and the sections apart from each other.
nonisolated struct WireParseTarget: FuzzTarget {
    let name = "WireHandle.parse/parseHeader/parseSections"

    var corpus: [FuzzSeedInput] {
        BundleEnvelopeTarget().corpus.filter { $0.bytes.starts(with: WireHandle.magic) }
    }

    func run(_ input: Data) throws {
        let header = try? WireHandle.parseHeader(input)
        let parsed = try? WireHandle.parse(input)
        _ = try? WireHandle.parseSections(input)

        // `parse` is `parseHeader` plus a body: the header it reports is the header alone.
        guard let parsed else { throw FuzzRejection() }
        guard let header else { throw FuzzViolation("parse accepted a file whose header parseHeader refused") }
        guard parsed.version == header.version, parsed.mode == header.mode, parsed.flags == header.flags,
              parsed.prekeyID == header.prekeyID, parsed.ephemeralKey == header.ephemeralKey,
              UInt64(parsed.ciphertext.count) == header.ciphertextLength
        else { throw FuzzViolation("parse and parseHeader disagree about the same header") }
    }
}

// MARK: - WireHandle.decode(payload:)

nonisolated struct SealedPayloadTarget: FuzzTarget {
    let name = "WireHandle.decode(payload:)"

    var corpus: [FuzzSeedInput] {
        var seeds = FuzzVectors.entries(ofKind: "payload").map {
            FuzzSeedInput($0.name, $0.bytes, lengthFields: FuzzLayout.payload($0.bytes))
        }
        let rich = try! WireHandle.encode(payload: FuzzSeeds.richPayload())
        seeds.append(FuzzSeedInput("built rich payload", rich, lengthFields: FuzzLayout.payload(rich), isText: false))
        // A streamed manifest is `u32 length ‖ this`.
        for manifest in FuzzVectors.entries(ofKind: "streamManifest") {
            let payload = Data(manifest.bytes.dropFirst(4))
            seeds.append(FuzzSeedInput(manifest.name + " (payload part)", payload, lengthFields: FuzzLayout.payload(payload)))
        }
        return seeds
    }

    func run(_ input: Data) throws {
        let payload = try WireHandle.decode(payload: input)
        _ = payload.shardOperations?.compactMap(\.attribute?.expiresAt)

        let once = try WireHandle.encode(payload: payload)
        let twice = try WireHandle.encode(payload: try WireHandle.decode(payload: once))
        guard once == twice else { throw FuzzViolation("payload: re-encoding a decoded payload is not stable") }
    }
}

// MARK: - WireHandle.decode(basket:) and decode(streamedBasket:)

nonisolated struct BasketTarget: FuzzTarget {
    let name = "WireHandle.decode(basket:)"

    var corpus: [FuzzSeedInput] {
        var seeds = FuzzVectors.entries(ofKind: "basket").map {
            FuzzSeedInput($0.name, $0.bytes, lengthFields: FuzzLayout.basket($0.bytes))
        }
        let rich = try! WireHandle.encode(basket: FuzzSeeds.richBasket())
        seeds.append(FuzzSeedInput("built rich basket", rich, lengthFields: FuzzLayout.basket(rich)))
        return seeds
    }

    func run(_ input: Data) throws {
        // Both layouts read the same bytes: the streamed one adds checks, and must never trap where the first didn't.
        let streamed = try? WireHandle.decode(streamedBasket: input)
        let basket = try WireHandle.decode(basket: input)

        let once = try WireHandle.encode(basket: basket)
        let again = try WireHandle.decode(basket: once)
        guard basket.id == again.id, basket.date == again.date, basket.owner == again.owner,
              basket.files.map(\.id) == again.files.map(\.id), basket.files.map(\.format) == again.files.map(\.format),
              basket.files.map(\.date) == again.files.map(\.date)
        else { throw FuzzViolation("basket: a field changed across a re-encode") }
        // An extension from the sender goes into a path only after this, and what it returns is plain.
        for file in basket.files {
            if case .file(let metadata) = file.format {
                let safe = File.Metadata.sanitizedFilesystemExtension(metadata.extension)
                guard safe == "bin" || (safe.count <= 10 && safe.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber) }) else {
                    throw FuzzViolation("sanitizedFilesystemExtension returned \(safe)")
                }
            }
        }
        // `content` is nil for an empty file on the way in and `Data()` on the way out, so compare as bytes.
        guard basket.files.map({ $0.content ?? Data() }) == again.files.map({ $0.content ?? Data() }) else {
            throw FuzzViolation("basket: file content changed across a re-encode")
        }

        if let (streamedBasket, lengths) = streamed {
            let encoded = try WireHandle.encode(basket: streamedBasket, streamedLengths: lengths)
            let (reread, relengths) = try WireHandle.decode(streamedBasket: encoded)
            guard relengths == lengths, reread.files.map(\.id) == streamedBasket.files.map(\.id) else {
                throw FuzzViolation("streamed basket: lengths changed across a re-encode")
            }
        }
    }
}

// MARK: - DepthCodec

/// The two-byte depth plaintext and the legacy JSON integer it replaced, which `decode` still reads.
nonisolated struct DepthCodecTarget: FuzzTarget {
    let name = "DepthCodec"

    var corpus: [FuzzSeedInput] {
        FuzzVectors.entries(ofKind: "depth").map { FuzzSeedInput($0.name, $0.bytes) }
            + ["0", "7", "-1", "253", "9223372036854775807"].map { FuzzSeedInput("legacy " + $0, Data($0.utf8), isText: true) }
            // Not depths, but what a mutation of one becomes: whitespace, an exponent, a string.
            + [" 3 ", "1e2", "\"x\""].map { FuzzSeedInput("legacy " + $0, Data($0.utf8), isText: true, isValid: false) }
    }

    func run(_ input: Data) throws {
        guard let depth = DepthCodec.decode(input) else {
            if let raw = FuzzLayout.uint(input, at: 0, width: 8) {
                guard DepthCodec.encode(Int(truncatingIfNeeded: raw)).count == 2 else { throw FuzzViolation("DepthCodec.encode is not two bytes") }
            }
            throw FuzzRejection()
        }
        // What was read is a depth the encoder can write, up to its ceiling.
        let encoded = DepthCodec.encode(depth)
        guard encoded.count == 2, let again = DepthCodec.decode(encoded) else { throw FuzzViolation("DepthCodec: \(depth) does not round-trip") }
        let expected = depth == Int.max ? Int.max : depth < 0 ? -1 : min(depth, DepthCodec.maxEncodableDepth)
        guard again == expected else { throw FuzzViolation("DepthCodec: \(depth) came back as \(again), expected \(expected)") }
    }
}

// MARK: - SignedAttribute

nonisolated struct SignedAttributeTarget: FuzzTarget {
    let name = "SignedAttribute JSON and verify"

    var corpus: [FuzzSeedInput] {
        [
            FuzzSeedInput("shard", Self.json(FuzzSeeds.signedAttribute()), isText: true),
            FuzzSeedInput("attestation with expiry", Self.json(FuzzSeeds.signedAttribute(category: .attestation, expiresAt: Date(timeIntervalSinceReferenceDate: 900_000_000))), isText: true),
        ]
    }

    private static func json(_ attribute: SignedAttribute) -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return try! encoder.encode(attribute)
    }

    func run(_ input: Data) throws {
        let attribute = try BoundedJSON.decode(SignedAttribute.self, from: input)

        // What every inbound shard operation does with it, before anything else looks at it.
        _ = attribute.verify(against: FuzzSeeds.signingPublicKey)
        _ = attribute.verify(against: Data(count: 64))

        let again = try JSONDecoder().decode(SignedAttribute.self, from: Self.json(attribute))
        guard Self.json(again) == Self.json(attribute) else { throw FuzzViolation("SignedAttribute: re-encoding is not stable") }
    }
}

// MARK: - Introduction cards

/// `IntroductionCard.recognize`: the one parser that sees a file with no magic bytes, so it sees every file.
nonisolated struct IntroductionCardTarget: FuzzTarget {
    let name = "IntroductionCard.recognize"

    var corpus: [FuzzSeedInput] {
        let genuine = FuzzSeeds.card().encoded
        let expired = FuzzSeeds.card(expiresAt: Date(timeIntervalSince1970: 1)).encoded
        return [
            FuzzSeedInput("genuine card", genuine),
            FuzzSeedInput("expired genuine card", expired),
        ] + FuzzVectors.entries(ofKind: "card").map { FuzzSeedInput($0.name + " (placeholder keys)", $0.bytes, isValid: false) }
    }

    func run(_ input: Data) throws {
        var violation: FuzzViolation?
        var accepted = false
        // The same bytes with the signature redone as well, which gets past the one check a mutation nearly always fails.
        for candidate in [input, FuzzSeeds.resigned(input)].compactMap({ $0 }) {
            do { try self.check(candidate); accepted = true } catch let error as FuzzViolation { violation = violation ?? error } catch {}
        }
        if let violation { throw violation }
        if !accepted { throw FuzzRejection() }
    }

    private func check(_ input: Data) throws {
        guard let card = IntroductionCard.recognize(input) else { throw FuzzRejection() }
        // The documented contract: whatever is recognised encodes back to the file it came from.
        guard card.encoded == Data(input) else { throw FuzzViolation("card: recognize(x).encoded != x") }
        guard card.digest.count == 32, card.agreementKey.count == 65, card.signingKey.count == 65 else {
            throw FuzzViolation("card: recognised with a key of the wrong size")
        }
        _ = card.expiresAt.timeIntervalSince1970
    }
}

nonisolated struct CardIntroductionTarget: FuzzTarget {
    let name = "CardIntroduction JSON and verify"

    var corpus: [FuzzSeedInput] {
        let digest = Data(repeating: 0x42, count: 32)
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return [FuzzSeedInput("genuine introduction", try! encoder.encode(FuzzSeeds.introduction(cardDigest: digest)), isText: true)]
    }

    func run(_ input: Data) throws {
        let introduction = try BoundedJSON.decode(CardIntroduction.self, from: input)
        _ = introduction.verify(cardDigest: Data(repeating: 0x42, count: 32))
        _ = introduction.verify(cardDigest: Data(count: 31))
    }
}

/// A bootstrap slot's two layers: `openOuter` takes `wrappedPayload` off the wire; `openInner` takes what is inside.
nonisolated struct CardBootstrapTarget: FuzzTarget {
    let name = "CardBootstrap.openOuter/openInner"

    static let outerKey = SymmetricKey(data: Data(repeating: 0x11, count: 32))
    static let innerKey = SymmetricKey(data: Data(repeating: 0x22, count: 32))
    static let blind = Data(repeating: 0x33, count: 32)

    var corpus: [FuzzSeedInput] {
        let sealed = try! CardBootstrap.seal(
            payload: Data("{}".utf8), mlkemCiphertext: Data(repeating: 0x44, count: CardBootstrap.mlkemCiphertextCount),
            outerKey: Self.outerKey, innerKey: Self.innerKey, blind: Self.blind
        )
        return [FuzzSeedInput("sealed slot", sealed)]
            + FuzzVectors.entries(ofKind: "cardBootstrapLayer").map { FuzzSeedInput($0.name, $0.bytes, isValid: false) }
    }

    func run(_ input: Data) throws {
        self.runInner(input)
        let (ciphertext, inner) = try CardBootstrap.openOuter(input, outerKey: Self.outerKey, blind: Self.blind)
        // The layer is the ML-KEM ciphertext, then the inner seal.
        guard ciphertext.count == CardBootstrap.mlkemCiphertextCount else { throw FuzzViolation("openOuter returned a ciphertext of the wrong size") }
        _ = try CardBootstrap.openInner(inner, mlkemCiphertext: ciphertext, innerKey: Self.innerKey, blind: Self.blind)
    }

    /// `openInner` is also reached with whatever the outer layer held, which only the right key opens, so the fuzz
    /// feeds it the raw input too.
    func runInner(_ input: Data) {
        _ = try? CardBootstrap.openInner(input, mlkemCiphertext: Data(input.prefix(CardBootstrap.mlkemCiphertextCount)),
                                         innerKey: Self.innerKey, blind: Self.blind)
    }
}

nonisolated struct CardMeetingTarget: FuzzTarget {
    let name = "CardMeeting.verifyProof/transcript"

    var corpus: [FuzzSeedInput] {
        let transcript = Data(repeating: 0x55, count: 32)
        let identity = FuzzSeeds.signingPublicKey
        let payload = CardMeeting.proofPayload(transcript: transcript, signerIdentityKey: identity)
        let proof = try! FuzzSeeds.signingKey.signature(for: payload).rawRepresentation
        // proof (64) ‖ transcript (32) ‖ signer identity key (65) ‖ signing key (65)
        return [FuzzSeedInput("valid proof", proof + transcript + identity + identity)]
    }

    func run(_ input: Data) throws {
        // Sliced where the parts are, and wherever a mutation put the boundaries.
        let proof = input.prefix(CardMeeting.proofByteCount)
        let rest = input.dropFirst(CardMeeting.proofByteCount)
        let transcript = rest.prefix(32)
        let keys = rest.dropFirst(32)
        _ = CardMeeting.verifyProof(Data(proof), transcript: Data(transcript), signerIdentityKey: Data(keys.prefix(65)), signingKey: Data(keys.dropFirst(65)))
        _ = CardMeeting.verifyProof(proof, transcript: transcript, signerIdentityKey: keys, signingKey: keys)

        // The transcript frames every element with a UInt16 length, so a long one is the case to try.
        let halves = (Data(input.prefix(input.count / 2)), Data(input.dropFirst(input.count / 2)))
        let transcriptHash = CardMeeting.transcript(identityKeys: halves, nonces: halves, mlkemCiphertexts: halves)
        guard transcriptHash.count == 32 else { throw FuzzViolation("transcript is not 32 bytes") }
        // Which of a pair is first doesn't matter.
        let swapped = CardMeeting.transcript(identityKeys: (halves.1, halves.0), nonces: (halves.1, halves.0), mlkemCiphertexts: (halves.1, halves.0))
        guard swapped == transcriptHash else { throw FuzzViolation("transcript depends on which side computes it") }
    }
}

// MARK: - BodyStream

/// `BodyStream.Layout`: the two lengths a streamed bundle's header gives, and everything computed from them.
nonisolated struct BodyStreamLayoutTarget: FuzzTarget {
    let name = "BodyStream.Layout"

    var corpus: [FuzzSeedInput] {
        let interesting: [UInt64] = [
            0, 1, 5, 21, 22, 4_096, UInt64(BodyStream.wireChunkSize), UInt64(BodyStream.wireChunkSize) + 1, UInt64(BodyStream.wireChunkSize) + 16,
            UInt64(BodyStream.wireChunkSize) + 17, 1 << 50, BodyStream.maximumStreamLength, BodyStream.maximumStreamLength + 1, .max,
        ]
        return interesting.map { value in
            FuzzSeedInput("length \(value)", Data((0..<8).map { UInt8(truncatingIfNeeded: value >> UInt64(56 - 8 * $0)) }), lengthFields: [FuzzLengthField(offset: 0, width: 8)])
        }
    }

    // Every seed is a number; whether the layout accepts it is the point, not a precondition.
    func run(_ input: Data) throws {
        guard let value = FuzzLayout.uint(input, at: 0, width: 8) else { return }

        if let layout = try? BodyStream.Layout(streamLength: value) {
            guard layout.streamLength == value, layout.chunkCount >= 1,
                  layout.plaintextLength + UInt64(BodyStream.tagSize) * layout.chunkCount == layout.streamLength,
                  (1...BodyStream.chunkSize).contains(layout.lastChunkPlaintextLength)
            else { throw FuzzViolation("Layout(streamLength: \(value)) is inconsistent") }
            // The sender's constructor, given what the receiver derived, gives the same layout back.
            guard let sender = try? BodyStream.Layout(plaintextLength: layout.plaintextLength), sender == layout else {
                throw FuzzViolation("Layout(streamLength: \(value)) and Layout(plaintextLength:) disagree")
            }
            // Every chunk's span lies inside the stream, with no overflow.
            let last = layout.chunkCount - 1
            for index in Set([0, last / 2, last]) {
                let end = layout.wireOffset(ofChunk: index) + UInt64(layout.wireLength(ofChunk: index))
                guard end <= layout.streamLength else { throw FuzzViolation("chunk \(index) ends past the stream") }
            }
        }
        _ = try? BodyStream.Layout(plaintextLength: value)
        _ = BodyStream.nonce(index: value)
        _ = BodyStream.aad(header: input, index: value, final: value & 1 == 0)
    }
}

/// `BodyStream.Opener`: a whole small stream, chunked the way a receiver chunks it.
nonisolated struct BodyStreamOpenerTarget: FuzzTarget {
    let name = "BodyStream.Opener"

    static let sessionKey = SymmetricKey(data: Data(repeating: 0x66, count: 32))
    static let header = Data("streamedBodyCapable{\"mode\":\"group\"}".utf8)

    var corpus: [FuzzSeedInput] {
        func stream(_ length: Int) -> Data {
            let layout = try! BodyStream.Layout(plaintextLength: UInt64(length))
            var sealer = BodyStream.Sealer(sessionKey: Self.sessionKey, header: Self.header, layout: layout)
            var out = Data()
            try! sealer.append(Data((0..<length).map { UInt8(truncatingIfNeeded: $0) })) { out.append($0) }
            _ = try! sealer.finish { out.append($0) }
            return out
        }
        return [
            FuzzSeedInput("5-byte stream", stream(5)),
            FuzzSeedInput("1 KiB stream", stream(1_024)),
            FuzzSeedInput("two-chunk stream", stream(BodyStream.chunkSize + 7)),
        ]
    }

    func run(_ input: Data) throws {
        let layout = try BodyStream.Layout(streamLength: UInt64(input.count))
        var opener = BodyStream.Opener(sessionKey: Self.sessionKey, header: Self.header, layout: layout)
        var plaintext = 0
        for index in 0..<layout.chunkCount {
            let start = input.startIndex + Int(layout.wireOffset(ofChunk: index))
            let chunk = input[start..<(start + layout.wireLength(ofChunk: index))]
            plaintext += try opener.open(chunk, index: index).count
        }
        guard opener.isFinished, UInt64(plaintext) == layout.plaintextLength else { throw FuzzViolation("a stream opened short of its layout") }
    }
}

/// `BodyStream.Manifest`: the u32 prefix, the manifest after it, and the lengths it declares.
nonisolated struct BodyStreamManifestTarget: FuzzTarget {
    let name = "BodyStream.Manifest"

    var corpus: [FuzzSeedInput] {
        FuzzVectors.entries(ofKind: "streamManifest").map { FuzzSeedInput($0.name, $0.bytes, lengthFields: FuzzLayout.manifest($0.bytes)) }
            + [FuzzSeedInput("framed rich payload", try! BodyStream.Manifest.frame(payload: FuzzSeeds.richPayload()), lengthFields: FuzzLayout.manifest(try! BodyStream.Manifest.frame(payload: FuzzSeeds.richPayload())))]
    }

    func run(_ input: Data) throws {
        let length = try BodyStream.Manifest.length(prefix: input)
        guard (1...BodyStream.maxManifestLength).contains(length) else { throw FuzzViolation("Manifest.length returned \(length)") }

        // The manifest as a receiver cuts it: the bytes after the prefix, as many as the prefix says.
        let body = input.dropFirst(BodyStream.Manifest.prefixLength)
        guard body.count >= length else { return }
        let payload = try BodyStream.Manifest.decode(Data(body.prefix(length)))

        // The lengths the manifest declares, summed and checked against a layout, with no overflow.
        if let message = try? WireHandle.decode(streamedBasket: payload.message) {
            let total = try? BodyStream.Manifest.plaintextLength(manifestLength: length, streamedLengths: message.streamedLengths)
            if let total, let layout = try? BodyStream.Layout(plaintextLength: total) {
                try BodyStream.Manifest.validate(manifestLength: length, streamedLengths: message.streamedLengths, against: layout)
            }
        }
    }
}

// MARK: - Shamir

/// Shares as a trustee hands them back: any number of them, of any length, with any x-coordinate. The input is
/// read as a list: a count, then for each share a length byte and that many bytes.
nonisolated struct ShamirTarget: FuzzTarget {
    let name = "ShamirSecretSharing.reconstruct"

    var corpus: [FuzzSeedInput] {
        let secret = Data((0..<32).map { UInt8($0) })
        let shares = try! ShamirSecretSharing.split(secret: secret, threshold: 3, shares: 5)
        func list(_ shares: [[UInt8]]) -> Data {
            Data([UInt8(shares.count)] + shares.flatMap { [UInt8($0.count)] + $0 })
        }
        return [
            FuzzSeedInput("3 of 5", list(Array(shares.prefix(3)))),
            FuzzSeedInput("5 of 5", list(shares)),
            FuzzSeedInput("2 shares", list(Array(shares.prefix(2)))),
        ]
    }

    func run(_ input: Data) throws {
        var cursor = input.startIndex
        func take(_ count: Int) -> [UInt8]? {
            guard count >= 0, cursor + count <= input.endIndex else { return nil }
            defer { cursor += count }
            return Array(input[cursor..<(cursor + count)])
        }
        guard let count = take(1)?.first else { return }
        var shares: [[UInt8]] = []
        for _ in 0..<Int(count) {
            guard let length = take(1)?.first, let share = take(Int(length)) else { break }
            shares.append(share)
        }

        // The public path, with a check that accepts nothing and then one that accepts anything: neither may trap.
        _ = try? ShamirSecretSharing.reconstruct(shares: shares, maxAttempts: 16) { _ in false }
        if let secret = try? ShamirSecretSharing.reconstruct(shares: shares, maxAttempts: 16, isCorrect: { _ in true }) {
            guard secret.count == 32 else { throw FuzzViolation("reconstruct returned a secret of \(secret.count) bytes") }
        }
        // The primitive underneath, which `split` and `reconstruct` share.
        _ = try? ShamirSecretSharing.reconstruct(shares: shares)

        // Parameters as the bytes give them. Most are invalid, and those must throw and never trap. A valid pair
        // is only run when it is small: the polynomial work grows with k times n and says nothing more.
        if let params = take(2), params.count == 2 {
            let k = Int(Int8(bitPattern: params[0])), n = Int(params[1])
            let isInvalid = k < 2 || n < k || n > 255
            guard isInvalid || n <= 12 else { return }
            if let split = try? ShamirSecretSharing.split(secret: Data(repeating: 7, count: 32), threshold: k, shares: n) {
                guard split.count == n, split.allSatisfy({ $0.count == 33 }) else { throw FuzzViolation("split(\(k), \(n)) returned a malformed set") }
                let back = try ShamirSecretSharing.reconstruct(shares: Array(split.prefix(k))) { $0 == Data(repeating: 7, count: 32) }
                guard back == Data(repeating: 7, count: 32) else { throw FuzzViolation("split(\(k), \(n)) does not reconstruct") }
            }
        }
    }
}

// MARK: - MLKEMKeyCheck

nonisolated struct MLKEMKeyCheckTarget: FuzzTarget {
    let name = "MLKEMKeyCheck and ML-KEM key parse"

    var corpus: [FuzzSeedInput] {
        [FuzzSeedInput("modulus-valid key", FuzzSeeds.mlkemKey)]
            + FuzzVectors.entries(ofKind: "card").compactMap { vector in
                vector.bytes.count == IntroductionCard.byteCount ? FuzzSeedInput(vector.name + " (key part)", vector.bytes.subdata(in: 136..<1704), isValid: false) : nil
            }
    }

    func run(_ input: Data) throws {
        let valid = MLKEMKeyCheck.isValidEncapsulationKey1024(input)
        guard !valid || input.count == 1_568 else { throw FuzzViolation("a key of \(input.count) bytes passed the modulus check") }
        if #available(iOS 26, macOS 26, *) {
            // The exchange hands a peer's key straight to CryptoKit, with or without the check.
            if let key = try? MLKEM1024.PublicKey(rawRepresentation: input) { _ = try? key.encapsulate() }
        }
        if !valid { throw FuzzRejection() }
    }
}

// MARK: - ML-KEM provider

#if DEBUG
/// What the exchange does with a nearby phone's bytes once they are past the JSON: encapsulate to its key and
/// decapsulate its ciphertext. The in-memory provider runs the same CryptoKit calls as the Enclave one.
@available(iOS 26, macOS 26, *)
nonisolated struct PostQuantumProviderTarget: FuzzTarget {
    let name = "PostQuantumProvider (a peer's key and ciphertext)"

    private final class Fixture: @unchecked Sendable {
        let provider: PostQuantumProvider
        let publicKey: Data
        let keyBlob: Data
        let ciphertext: Data
        let secret: Data

        init() {
            self.provider = PostQuantumProviderFactory.createForTesting()!
            let pair = self.provider.generatePersistentKeyPair()!
            self.publicKey = pair.publicKeyData
            self.keyBlob = pair.keyBlob
            let encapsulated = self.provider.encapsulate(peerPublicKeyData: pair.publicKeyData)!
            self.ciphertext = encapsulated.ciphertext
            self.secret = encapsulated.sharedSecret
        }
    }

    private let fixture = Fixture()

    var corpus: [FuzzSeedInput] {
        [FuzzSeedInput("public key", self.fixture.publicKey), FuzzSeedInput("ciphertext", self.fixture.ciphertext), FuzzSeedInput("key blob", self.fixture.keyBlob, isValid: false)]
    }

    func run(_ input: Data) throws {
        let fixture = self.fixture
        var accepted = false

        if let result = fixture.provider.encapsulate(peerPublicKeyData: input) {
            accepted = true
            guard result.sharedSecret.count == 32 else { throw FuzzViolation("encapsulate returned a secret of \(result.sharedSecret.count) bytes") }
        }
        if let secret = fixture.provider.decapsulate(ciphertext: input, keyBlob: fixture.keyBlob) {
            accepted = true
            guard secret.count == 32 else { throw FuzzViolation("decapsulate returned a secret of \(secret.count) bytes") }
            // The one ciphertext this key was sent decapsulates to the secret sent with it.
            if input == fixture.ciphertext, secret != fixture.secret { throw FuzzViolation("decapsulate of the genuine ciphertext gave another secret") }
        }
        // A hostile blob, as `generatePersistentKeyPair`'s would never be.
        _ = fixture.provider.decapsulate(ciphertext: fixture.ciphertext, keyBlob: input)
        _ = fixture.provider.publicKey(forKeyBlob: input)
        if !accepted { throw FuzzRejection() }
    }
}
#endif

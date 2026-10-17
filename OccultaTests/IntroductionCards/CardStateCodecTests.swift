//
//  CardStateCodecTests.swift
//  OccultaTests
//
//  The card field's at-rest format and its size (`Docs/Features/Introduction Cards/SPEC.md` §5, §13).
//  Pure: no Enclave, no SwiftData.
//

import Testing
import Foundation

@testable import Occulta
@testable import OccultaFormats

/// The payload length the codec wrote into the header.
private func payloadLength(of plaintext: Data) -> Int {
    [UInt8](plaintext)[1 ... 4].reduce(0) { ($0 << 8) | Int($1) }
}

/// Distinct random bytes everywhere: a binary plist stores a repeated value once, so repeated blobs would make a
/// state look smaller than any real one (FORWARD_SECRECY_GUIDE mistake 19).
private func distinctQuantum() -> QuantumKeyMaterial {
    QuantumKeyMaterial(
        encapsulatedSecret: randomBytes(32), decapsulatedSecret: randomBytes(32),
        ourCiphertext: randomBytes(1_568), peerCiphertext: randomBytes(1_568)
    )
}

private func issuedState() -> CardState {
    .issued(
        card: randomBytes(1_770), agreementKey: randomBytes(143), signingKey: randomBytes(143),
        mlkemKey: randomBytes(4_788), expiresAt: Date(timeIntervalSinceReferenceDate: 800_000_000.25)
    )
}

private func importedState(sent: Bool = true) -> CardState {
    .imported(
        peerCard: randomBytes(1_770), agreementKey: randomBytes(143), signingKey: randomBytes(143),
        mlkemKey: randomBytes(4_788), ss1: randomBytes(32), ct1: randomBytes(1_568),
        expiresAt: Date(timeIntervalSinceReferenceDate: 800_086_400.5), sentFirstMessage: sent
    )
}

private func conversationState(isIssuer: Bool, bootstrapOpen: Bool) -> CardState {
    .conversation(
        agreementKey: randomBytes(143), signingKey: randomBytes(143),
        peerAgreementKey: randomBytes(65), peerSigningKey: randomBytes(65),
        quantum: distinctQuantum(), bootstrapOpen: bootstrapOpen, isIssuer: isIssuer
    )
}

@Suite("Card state codec — at-rest format and size (SPEC §5)")
struct CardStateCodecTests {

    private let codec = CardStateCodec()

    private var everyState: [(name: String, state: CardState)] {
        [
            ("empty", .empty),
            ("issued", issuedState()),
            ("imported, not sent", importedState(sent: false)),
            ("imported, sent", importedState(sent: true)),
            ("conversation, Bob in bootstrap", conversationState(isIssuer: true, bootstrapOpen: true)),
            ("conversation, Bob, settled", conversationState(isIssuer: true, bootstrapOpen: false)),
            ("conversation, Carol, settled", conversationState(isIssuer: false, bootstrapOpen: false)),
        ]
    }

    // MARK: - Round trip

    @Test("Every state round-trips")
    func everyStateRoundTrips() throws {
        for (name, state) in self.everyState {
            let decoded = try self.codec.decode(try self.codec.encode(state))
            #expect(decoded == state, "\(name)")
        }
    }

    @Test("Every state encodes to exactly capacity bytes, so the length says nothing about the state")
    func everyStateIsCapacityBytes() throws {
        #expect(CardStateCodec.capacity == 12 * 1_024)
        for (name, state) in self.everyState {
            #expect(try self.codec.encode(state).count == CardStateCodec.capacity, "\(name)")
        }
    }

    @Test("The layout is version, big-endian length, payload, zeros")
    func layout() throws {
        let plaintext = try self.codec.encode(issuedState())
        let length    = payloadLength(of: plaintext)

        #expect(plaintext.first == 0x01)
        #expect(CardStateCodec.formatVersion == 0x01)
        #expect(CardStateCodec.headerSize == 5)
        #expect(length > 1_770 + 143 + 143 + 4_788, "the payload holds the blobs")
        #expect(plaintext.dropFirst(5 + length).allSatisfy { $0 == 0 }, "zeros to capacity")
        #expect(Data(plaintext[5 ..< 5 + length]).starts(with: Data("bplist00".utf8)), "a binary plist")
    }

    @Test("The empty state decodes back to empty and its padding is zeros")
    func emptyState() throws {
        let plaintext = try self.codec.encode(.empty)
        #expect(try self.codec.decode(plaintext) == .empty)
        #expect(payloadLength(of: plaintext) < 100)
        #expect(plaintext.dropFirst(5 + payloadLength(of: plaintext)).allSatisfy { $0 == 0 })
    }

    @Test("Different states encode to different bytes")
    func statesDiffer() throws {
        let encodings = try self.everyState.map { try self.codec.encode($0.state) }
        #expect(Set(encodings).count == encodings.count)
    }

    // MARK: - Malformed input

    @Test("Wrong length throws malformed")
    func wrongLengthIsMalformed() throws {
        let valid = try self.codec.encode(.empty)
        for bad in [Data(), Data(valid.dropLast()), valid + Data([0]), Data(count: 5), Data(valid.prefix(100))] {
            #expect(throws: CardStateCodec.CodecError.malformed, "\(bad.count) bytes") { try self.codec.decode(bad) }
        }
    }

    @Test("A wrong version byte throws malformed")
    func wrongVersionIsMalformed() throws {
        let valid = try self.codec.encode(issuedState())
        for version: UInt8 in [0x00, 0x02, 0x7F, 0xFF] {
            var bytes = [UInt8](valid)
            bytes[0] = version
            #expect(throws: CardStateCodec.CodecError.malformed, "version \(version)") { try self.codec.decode(Data(bytes)) }
        }
    }

    @Test("Garbage throws malformed: random, zeros, a length past capacity, a length of zero, a cut payload")
    func garbageIsMalformed() throws {
        let capacity = CardStateCodec.capacity
        let valid = [UInt8](try self.codec.encode(issuedState()))
        let length = payloadLength(of: Data(valid))

        var randomWithVersion = [UInt8](randomBytes(capacity)); randomWithVersion[0] = 0x01
        var randomPayload = [UInt8](Data(count: capacity)); randomPayload[0] = 0x01
        randomPayload.replaceSubrange(1 ... 4, with: [0, 0, 0x01, 0x00]) // 256 bytes of garbage
        randomPayload.replaceSubrange(5 ..< 261, with: [UInt8](randomBytes(256)))
        var tooLong = valid; tooLong.replaceSubrange(1 ... 4, with: [0xFF, 0xFF, 0xFF, 0xFF])
        var justPastCapacity = valid
        justPastCapacity.replaceSubrange(1 ... 4, with: withUnsafeBytes(of: UInt32(capacity - 5 + 1).bigEndian) { [UInt8]($0) })
        var zeroLength = valid; zeroLength.replaceSubrange(1 ... 4, with: [0, 0, 0, 0])
        var cut = valid; cut.replaceSubrange(1 ... 4, with: withUnsafeBytes(of: UInt32(length / 2).bigEndian) { [UInt8]($0) })

        let cases: [(String, [UInt8])] = [
            ("random with the right version", randomWithVersion),
            ("a short garbage payload", randomPayload),
            ("all zeros", [UInt8](Data(count: capacity))),
            ("a length of 0xFFFFFFFF", tooLong),
            ("a length one past capacity", justPastCapacity),
            ("a length of zero", zeroLength),
            ("a payload cut in half", cut),
        ]
        for (name, bytes) in cases {
            #expect(throws: CardStateCodec.CodecError.malformed, "\(name)") { try self.codec.decode(Data(bytes)) }
        }
    }

    @Test("A valid plist that is not a CardState throws malformed")
    func otherPlistIsMalformed() throws {
        let encoder = PropertyListEncoder(); encoder.outputFormat = .binary
        let payload = try encoder.encode(["not": "a card state"])
        var plaintext = Data([0x01])
        withUnsafeBytes(of: UInt32(payload.count).bigEndian) { plaintext.append(contentsOf: $0) }
        plaintext.append(payload)
        plaintext.append(Data(count: CardStateCodec.capacity - plaintext.count))

        #expect(throws: CardStateCodec.CodecError.malformed) { try self.codec.decode(plaintext) }
    }

    @Test("A Data slice decodes")
    func sliceDecodes() throws {
        let state  = importedState()
        let framed = Data(repeating: 0xEE, count: 7) + (try self.codec.encode(state))
        #expect(try self.codec.decode(framed.dropFirst(7)) == state)
    }

    // MARK: - Capacity

    @Test("A state too large for capacity throws overCapacity rather than being trimmed")
    func oversizedStateThrows() {
        let oversized = CardState.imported(
            peerCard: randomBytes(CardStateCodec.capacity), agreementKey: randomBytes(143), signingKey: randomBytes(143),
            mlkemKey: randomBytes(4_788), ss1: randomBytes(32), ct1: randomBytes(1_568),
            expiresAt: Date(), sentFirstMessage: false
        )
        #expect(throws: CardStateCodec.CodecError.overCapacity) { try self.codec.encode(oversized) }
    }

    @Test("The boundary is exact: the largest payload that fits encodes, one byte more does not")
    func capacityBoundaryIsExact() throws {
        // Grow a blob until the payload sits at the limit. A binary plist's data length header grows at 15, 255
        // and 65,535 bytes, so search rather than compute.
        func state(blobSize: Int) -> CardState {
            .issued(card: Data(repeating: 0xAB, count: blobSize), agreementKey: Data(), signingKey: Data(), mlkemKey: Data(), expiresAt: Date(timeIntervalSinceReferenceDate: 0))
        }
        var low = 0, high = CardStateCodec.capacity
        while low < high {
            let middle = (low + high + 1) / 2
            if (try? self.codec.encode(state(blobSize: middle))) != nil { low = middle } else { high = middle - 1 }
        }
        let fits = try self.codec.encode(state(blobSize: low))
        #expect(5 + payloadLength(of: fits) <= CardStateCodec.capacity)
        #expect(throws: CardStateCodec.CodecError.overCapacity) { try self.codec.encode(state(blobSize: low + 1)) }
        #expect(try self.codec.decode(fits) == state(blobSize: low))
    }

    // MARK: - Size (SPEC §5, §13)

    @Test("The largest realistic states fit with at least 1 KB of margin; sizes attached")
    func largestStatesFitWithMargin() throws {
        let limit  = CardStateCodec.capacity - CardStateCodec.headerSize
        let margin = 1_024

        let measured: [(name: String, state: CardState, inputs: String)] = [
            ("imported (Carol)", importedState(sent: true),
             "peerCard 1,770 + 2 x 143 blobs + ML-KEM blob 4,788 + ss1 32 + ct1 1,568 + expiry"),
            ("conversation (full material)", conversationState(isIssuer: true, bootstrapOpen: true),
             "2 x 143 blobs + peer keys 65 + 65 + QKM 32 + 32 + 1,568 + 1,568"),
            ("issued (Bob)", issuedState(),
             "card 1,770 + 2 x 143 blobs + ML-KEM blob 4,788 + expiry"),
        ]

        var report = ["capacity: \(CardStateCodec.capacity) bytes, header \(CardStateCodec.headerSize), payload limit \(limit)", ""]
        var results: [(name: String, payload: Int, margin: Int)] = []
        for item in measured {
            let plaintext = try self.codec.encode(item.state)
            let payload   = payloadLength(of: plaintext)
            results.append((item.name, payload, limit - payload))
            report.append("\(item.name): payload \(payload) bytes, margin \(limit - payload) bytes")
            report.append("    inputs: \(item.inputs)")
            #expect(plaintext.count == CardStateCodec.capacity, "\(item.name)")
        }

        // Control: repeated values would hide the cost. The same shape built from one repeated blob is smaller,
        // which is why the states above use distinct bytes.
        let repeated = Data(repeating: 0x5A, count: 4_788)
        let naive = CardState.imported(
            peerCard: Data(repeating: 0x5A, count: 1_770), agreementKey: Data(repeating: 0x5A, count: 143),
            signingKey: Data(repeating: 0x5A, count: 143), mlkemKey: repeated, ss1: Data(repeating: 0x5A, count: 32),
            ct1: Data(repeating: 0x5A, count: 1_568), expiresAt: Date(timeIntervalSinceReferenceDate: 800_086_400.5), sentFirstMessage: true
        )
        let naivePayload = payloadLength(of: try self.codec.encode(naive))
        report.append("")
        report.append("control, same imported shape from repeated bytes: payload \(naivePayload) bytes (understates the real size)")

        Attachment.record(report.joined(separator: "\n"), named: "card-field-sizes.txt")

        for result in results {
            #expect(result.margin >= margin, "\(result.name): payload \(result.payload) leaves \(result.margin) bytes, needs \(margin)")
        }
        #expect(naivePayload <= results[0].payload, "distinct bytes must cost at least what repeated bytes do")
    }
}

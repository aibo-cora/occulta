//
//  ShardsCodecTests.swift
//  OccultaTests
//
//  RECOVERY_BUFFER_LAYERING.md §6 item 9.3 — fixed-width wire format for
//  PendingShamirSecretRestore.shards. Pure byte-level codec; the one Secure
//  Enclave touch is TestKeyManager producing realistic signed slots to
//  round-trip, no gating needed for that.
//

import Testing
import Foundation
@testable import Occulta

@MainActor
@Suite("ShardsCodec — fixed-width PendingRestoreShardSlot wire format")
struct ShardsCodecTests {

    private typealias Codec = PendingShamirSecretRestore.ShardsCodec

    private func makeSlot(senderIdentifier: String = UUID().uuidString) throws -> PendingRestoreShardSlot {
        let signer = TestKeyManager()
        let id = UUID()
        let entryID = UUID()
        let value = Data([UInt8(1)]) + Data.randomBytes(32)
        let createdAt = Date(timeIntervalSince1970: 1_800_000_000)
        let payload = SignedAttribute.signingPayload(
            id: id, category: .shard, value: value, entryID: entryID, createdAt: createdAt
        )
        let signature = try signer.signData(payload)
        let attribute = SignedAttribute(
            id: id, label: "vault-shard", value: value, category: .shard,
            signature: signature, createdAt: createdAt, entryID: entryID
        )
        return PendingRestoreShardSlot(signedAttribute: attribute, senderIdentifier: senderIdentifier)
    }

    // MARK: Size invariant

    @Test("Encoded size is always payloadSize, whether 0, some, or capacity slots are real")
    func encodedSizeIsAlwaysFixed() throws {
        #expect(try Codec.encode([]).count == Codec.payloadSize)
        #expect(try Codec.encode([try self.makeSlot(), try self.makeSlot()]).count == Codec.payloadSize)

        let maxSlots = try (0..<Codec.shardCapacity).map { _ in try self.makeSlot() }
        #expect(try Codec.encode(maxSlots).count == Codec.payloadSize)
    }

    // MARK: Round trip

    @Test("Round trip with no real slots")
    func roundTripEmpty() throws {
        let decoded = try #require(Codec.decode(try Codec.encode([])))
        #expect(decoded.isEmpty)
    }

    @Test("Round trip with a mix of real slots")
    func roundTripRealSlots() throws {
        let slots = try (0..<5).map { _ in try self.makeSlot() }
        let decoded = try #require(Codec.decode(try Codec.encode(slots)))

        #expect(decoded.count == slots.count)
        for (expected, actual) in zip(slots, decoded) {
            #expect(actual.signedAttribute?.id == expected.signedAttribute?.id)
            #expect(actual.signedAttribute?.value == expected.signedAttribute?.value)
            #expect(actual.signedAttribute?.signature == expected.signedAttribute?.signature)
            #expect(actual.senderIdentifier == expected.senderIdentifier)
        }
    }

    @Test("Round trip at exactly the 255-slot capacity ceiling")
    func roundTripAtCapacity() throws {
        let slots = try (0..<Codec.shardCapacity).map { _ in try self.makeSlot() }
        let decoded = try #require(Codec.decode(try Codec.encode(slots)))
        #expect(decoded.count == Codec.shardCapacity)
    }

    @Test("A sender identifier at the 36-byte fixed-width boundary round-trips exactly")
    func roundTripSenderIdentifierAtBoundary() throws {
        let senderIdentifier = UUID().uuidString   // exactly 36 characters
        #expect(senderIdentifier.utf8.count == 36)
        let slot = try self.makeSlot(senderIdentifier: senderIdentifier)
        let decoded = try #require(Codec.decode(try Codec.encode([slot])))
        #expect(decoded.first?.senderIdentifier == senderIdentifier)
    }

    // MARK: Failure modes

    @Test("Encoding more slots than the Shamir ceiling throws, never truncates silently")
    func tooManySlotsThrows() throws {
        let slots = try (0...Codec.shardCapacity).map { _ in try self.makeSlot() }   // capacity + 1

        #expect(throws: Codec.CodecError.tooManySlots(count: Codec.shardCapacity + 1)) {
            try Codec.encode(slots)
        }
    }

    @Test("Decoding rejects the wrong length rather than partially decoding")
    func decodeRejectsWrongLength() {
        #expect(Codec.decode(Data.randomBytes(Codec.payloadSize - 1)) == nil)
        #expect(Codec.decode(Data.randomBytes(Codec.payloadSize + 1)) == nil)
        #expect(Codec.decode(Data()) == nil)
    }

    @Test("Decoding rejects an unrecognised formatVersion")
    func decodeRejectsWrongVersion() throws {
        var encoded = try Codec.encode([])
        encoded[0] = 0xFF
        encoded[1] = 0xFF
        #expect(Codec.decode(encoded) == nil)
    }

    @Test("Decoding a buffer too short to even hold a version tag returns nil, not a crash")
    func decodeRejectsBufferShorterThanVersionTag() {
        #expect(Codec.decode(Data()) == nil)
        #expect(Codec.decode(Data([0x00])) == nil)
    }

    @Test("Unused capacity slots never decode as real shards")
    func unusedSlotsDoNotLeakIntoDecodedShards() throws {
        let slot = try self.makeSlot()
        let decoded = try #require(Codec.decode(try Codec.encode([slot])))
        #expect(decoded.count == 1)
    }
}

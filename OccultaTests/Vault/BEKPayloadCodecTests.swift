//
//  BEKPayloadCodecTests.swift
//  OccultaTests
//
//  VAULT_KEY_LAYERING.md §8 item 3 — fixed-width wire format for
//  BackupEncryptionKey.Payload, replacing JSONEncoder/JSONDecoder. Pure byte-level
//  codec, no Secure Enclave involved, so none of these need gating.
//

import Testing
import Foundation
@testable import Occulta

@Suite("BEKPayloadCodec — fixed-width Payload wire format")
struct BEKPayloadCodecTests {

    private typealias Codec = VaultManager.Backup.PayloadCodec

    private func makeShard(
        contactID: UUID = UUID(),
        attributeID: UUID = UUID(),
        status: ShardStatus = .pending,
        distributedAt: Date? = nil
    ) -> ShardRecord {
        ShardRecord(
            contactIdentifier: contactID.uuidString,
            attributeID: attributeID,
            status: status,
            distributedAt: distributedAt
        )
    }

    // MARK: Size invariant

    @Test("Encoded size is always payloadSize, whether 0, some, or 255 shards")
    func encodedSizeIsAlwaysFixed() throws {
        let bekBytes = Data.randomBytes(32)

        let noDistribution = BackupEncryptionKey.Payload(
            bekBytes: bekBytes, distributionID: UUID(), shardMetadata: nil
        )
        #expect(try Codec.encode(noDistribution).count == Codec.payloadSize)

        let fewShards = BackupEncryptionKey.Payload(
            bekBytes: bekBytes, distributionID: UUID(),
            shardMetadata: ShardDistributionMetadata(threshold: 2, shards: [makeShard(), makeShard()])
        )
        #expect(try Codec.encode(fewShards).count == Codec.payloadSize)

        let maxShards = BackupEncryptionKey.Payload(
            bekBytes: bekBytes, distributionID: UUID(),
            shardMetadata: ShardDistributionMetadata(
                threshold: 100,
                shards: (0..<Codec.shardCapacity).map { _ in makeShard() }
            )
        )
        #expect(try Codec.encode(maxShards).count == Codec.payloadSize)
    }

    // MARK: Round trip

    @Test("Round trip with no distribution yet (shardMetadata nil)")
    func roundTripNoDistribution() throws {
        let original = BackupEncryptionKey.Payload(
            bekBytes: Data.randomBytes(32), distributionID: UUID(), shardMetadata: nil
        )

        let decoded = try #require(Codec.decode(try Codec.encode(original)))

        #expect(decoded.bekBytes == original.bekBytes)
        #expect(decoded.distributionID == original.distributionID)
        #expect(decoded.shardMetadata == nil)
    }

    @Test("Round trip with a real distribution — mixed statuses, some distributedAt set and unset")
    func roundTripRealDistribution() throws {
        // Whole-second precision only — the wire format truncates to UInt64 seconds.
        let distributedDate = Date(timeIntervalSince1970: 1_800_000_000)
        let shards = [
            makeShard(status: .pending, distributedAt: nil),
            makeShard(status: .confirmed, distributedAt: distributedDate),
            makeShard(status: .revokePending, distributedAt: distributedDate),
            makeShard(status: .revoked, distributedAt: distributedDate),
            makeShard(status: .lost, distributedAt: nil),
        ]
        let original = BackupEncryptionKey.Payload(
            bekBytes: Data.randomBytes(32),
            distributionID: UUID(),
            shardMetadata: ShardDistributionMetadata(threshold: 3, shards: shards)
        )

        let decoded = try #require(Codec.decode(try Codec.encode(original)))
        let decodedMeta = try #require(decoded.shardMetadata)

        #expect(decoded.bekBytes == original.bekBytes)
        #expect(decoded.distributionID == original.distributionID)
        #expect(decodedMeta.threshold == 3)
        #expect(decodedMeta.shards.count == shards.count)

        for (expected, actual) in zip(shards, decodedMeta.shards) {
            #expect(actual.contactIdentifier == expected.contactIdentifier)
            #expect(actual.attributeID == expected.attributeID)
            #expect(actual.status == expected.status)
            #expect(actual.distributedAt == expected.distributedAt)
        }
    }

    @Test("Round trip at exactly the 255-shard capacity ceiling")
    func roundTripAtCapacity() throws {
        let shards = (0..<Codec.shardCapacity).map { _ in makeShard() }
        let original = BackupEncryptionKey.Payload(
            bekBytes: Data.randomBytes(32),
            distributionID: UUID(),
            shardMetadata: ShardDistributionMetadata(threshold: 200, shards: shards)
        )

        let decoded = try #require(Codec.decode(try Codec.encode(original)))
        let decodedMeta = try #require(decoded.shardMetadata)

        #expect(decodedMeta.shards.count == Codec.shardCapacity)
    }

    // MARK: Failure modes

    @Test("Encoding more shards than the Shamir ceiling throws, never truncates silently")
    func tooManyShardsThrows() {
        let shards = (0...Codec.shardCapacity).map { _ in makeShard() }   // capacity + 1
        let payload = BackupEncryptionKey.Payload(
            bekBytes: Data.randomBytes(32),
            distributionID: UUID(),
            shardMetadata: ShardDistributionMetadata(threshold: 2, shards: shards)
        )

        #expect(throws: Codec.CodecError.tooManyShards(count: Codec.shardCapacity + 1)) {
            try Codec.encode(payload)
        }
    }

    @Test("Encoding a malformed contactIdentifier throws rather than silently corrupting the record")
    func invalidContactIdentifierThrows() {
        let badShard = ShardRecord(
            contactIdentifier: "not-a-uuid",
            attributeID: UUID(),
            status: .pending
        )
        let payload = BackupEncryptionKey.Payload(
            bekBytes: Data.randomBytes(32),
            distributionID: UUID(),
            shardMetadata: ShardDistributionMetadata(threshold: 1, shards: [badShard])
        )

        #expect(throws: Codec.CodecError.invalidContactIdentifier("not-a-uuid")) {
            try Codec.encode(payload)
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
        let payload = BackupEncryptionKey.Payload(
            bekBytes: Data.randomBytes(32), distributionID: UUID(), shardMetadata: nil
        )
        var encoded = try Codec.encode(payload)
        encoded[0] = 0xFF   // corrupt the high byte of formatVersion
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
        let payload = BackupEncryptionKey.Payload(
            bekBytes: Data.randomBytes(32),
            distributionID: UUID(),
            shardMetadata: ShardDistributionMetadata(threshold: 1, shards: [makeShard()])
        )

        let decoded = try #require(Codec.decode(try Codec.encode(payload)))
        #expect(decoded.shardMetadata?.shards.count == 1)
    }
}

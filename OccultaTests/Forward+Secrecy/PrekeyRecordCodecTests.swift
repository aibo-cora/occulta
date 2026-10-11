//
//  PrekeyRecordCodecTests.swift
//  OccultaTests
//
//  The prekey record's at-rest format (prekey continuity stage 1; Bug 161). Pure: no Enclave, no SwiftData.
//

import Testing
import Foundation
@testable import Occulta
@testable import OccultaCore
@testable import OccultaFormats

private func randomBytes(_ count: Int) -> Data {
    Data((0..<count).map { _ in .random(in: .min ... .max) })
}

private func uuidBytes(_ uuid: UUID = UUID()) -> Data {
    withUnsafeBytes(of: uuid.uuid) { Data($0) }
}

/// The payload length the codec wrote into the header.
private func payloadLength(of plaintext: Data) -> Int {
    [UInt8](plaintext)[1...4].reduce(0) { ($0 << 8) | Int($1) }
}

private func ownKey(withPublicKey: Bool) -> PrekeyRecord.OwnKey {
    PrekeyRecord.OwnKey(id: uuidBytes(), blob: randomBytes(143), publicKey: withPublicKey ? randomBytes(65) : nil)
}

/// A record at every limit the bookkeeper enforces at once (design §8, stage 1, "Size limits"): 48 own keys, the
/// 15 in the pending batch still carrying their public keys; two inbound batches at the per-batch limit, with
/// key IDs at the length limit (stage 1 holds one, stage 4 two); 8 accepted batch IDs; every date set.
///
/// Every value is distinct. A binary plist stores a repeated value once, so repeated IDs or blobs would make this
/// record look smaller than any real one; that is how an earlier version of this fixture passed at 13 KB while
/// the limits it claimed to model needed 19.
private func recordAtEveryLimit() -> PrekeyRecord {
    let now = Date()
    let ownBatch = { (count: Int, pending: Bool, retired: Bool) in
        PrekeyRecord.OwnBatch(id: randomBytes(16), createdAt: now, retiredAt: retired ? now : nil,
                              isPending: pending, keys: (0..<count).map { _ in ownKey(withPublicKey: pending) })
    }
    let inbound = { PrekeyRecord.InboundBatch(
        id: randomBytes(16),
        keys: (0..<PrekeyBookkeeper.maxInboundKeysPerBatch).map { _ in
            PrekeyRecord.InboundKey(
                id: UUID().uuidString.padding(toLength: PrekeyBookkeeper.maxInboundKeyIDBytes, withPad: "x", startingAt: 0),
                publicKey: randomBytes(65)
            )
        }
    ) }
    let record = PrekeyRecord(
        ownBatches: [ownBatch(18, false, true), ownBatch(15, false, false), ownBatch(15, true, false)],
        inboundBatches: [inbound(), inbound()],
        acceptedBatchIDs: (0..<8).map { _ in randomBytes(16) },
        latestInboundGeneratedAt: now,
        legacyKeys: .retired(since: now)
    )
    precondition(record.ownBatches.reduce(0) { $0 + $1.keys.count } == PrekeyBookkeeper.maxOwnKeys)
    return record
}

@Suite("PrekeyRecordCodec — fixed-size format")
struct PrekeyRecordCodecFormatTests {

    let codec = PrekeyRecordCodec()

    @Test("An empty record encodes to exactly the capacity and reads back")
    func emptyRecord() throws {
        let plaintext = try self.codec.encode(.empty)
        #expect(plaintext.count == PrekeyRecordCodec.capacity)
        #expect(plaintext.first == PrekeyRecordCodec.formatVersion)
        #expect(try self.codec.decode(plaintext) == .empty)
    }

    @Test("A record at every limit fits, encodes to exactly the capacity, and reads back")
    func everyLimitFits() throws {
        let record    = recordAtEveryLimit()
        let plaintext = try self.codec.encode(record)
        #expect(plaintext.count == PrekeyRecordCodec.capacity)
        #expect(try self.codec.decode(plaintext) == record)

        // The design budgets about 14 KB for this record. Keep at least 1 KB of headroom, so a field added
        // without revisiting the limits fails here rather than on a device.
        #expect(PrekeyRecordCodec.headerSize + payloadLength(of: plaintext) <= PrekeyRecordCodec.capacity - 1024)
    }

    @Test("A record's encoded length doesn't depend on what it holds")
    func lengthIsConstant() throws {
        var oneKey = PrekeyRecord.empty
        oneKey.inboundBatches = [PrekeyRecord.InboundBatch(id: nil, keys: [
            PrekeyRecord.InboundKey(id: UUID().uuidString, publicKey: randomBytes(65))
        ])]
        let lengths = try [PrekeyRecord.empty, oneKey, recordAtEveryLimit()].map { try self.codec.encode($0).count }
        #expect(Set(lengths) == [PrekeyRecordCodec.capacity])
    }

    @Test("A record too large throws instead of being trimmed")
    func overCapacityThrows() {
        var record = recordAtEveryLimit()
        record.ownBatches.append(PrekeyRecord.OwnBatch(
            id: randomBytes(16), createdAt: Date(), retiredAt: nil, isPending: false,
            keys: (0..<100).map { _ in ownKey(withPublicKey: true) }
        ))
        #expect(throws: PrekeyRecordCodec.CodecError.overCapacity) { try self.codec.encode(record) }
    }

    @Test("Neither format, a truncated record, or a bad length is rejected")
    func malformedIsRejected() throws {
        #expect(throws: PrekeyRecordCodec.CodecError.malformed) { try self.codec.decode(randomBytes(64)) }
        #expect(throws: PrekeyRecordCodec.CodecError.malformed) { try self.codec.decode(Data([3]) + Data(count: 100)) }

        let good = try self.codec.encode(.empty)
        #expect(throws: PrekeyRecordCodec.CodecError.malformed) { try self.codec.decode(good.prefix(1000)) }

        var badLength = good
        badLength.replaceSubrange(1..<5, with: [0xFF, 0xFF, 0xFF, 0xFF])
        #expect(throws: PrekeyRecordCodec.CodecError.malformed) { try self.codec.decode(badLength) }
    }
}

@Suite("PrekeyRecordCodec — reading today's format")
struct PrekeyRecordCodecLegacyTests {

    let codec = PrekeyRecordCodec()

    /// `ForwardSecrecy` encoded the way `Contact.Profile` stores it today.
    private func legacyPlaintext(
        inbound: [Prekey], latest: Date?, pending: OccultaBundle.SealedPayload.PrekeySyncBatch?
    ) throws -> Data {
        var secrecy = ForwardSecrecy()
        secrecy.encodedPrekeys = inbound.isEmpty ? nil : try inbound.map { try JSONEncoder().encode($0) }
        secrecy.latestPrekeysGeneratedAt = latest
        secrecy.pendingOutboundBatch = try pending.map { try JSONEncoder().encode($0) }
        return try JSONEncoder().encode(secrecy)
    }

    @Test("A fresh record from configureForwardSecrecy reads as empty, with legacy keys possibly in use")
    func freshLegacyIsEmpty() throws {
        var expected = PrekeyRecord.empty
        expected.legacyKeys = .inUse
        #expect(try self.codec.decode(JSONEncoder().encode(ForwardSecrecy())) == expected)
    }

    @Test("Every field of today's record carries over, and the repeated contactID is dropped")
    func legacyCarriesOver() throws {
        let contactID = "contact-\(UUID().uuidString)"
        let inbound = (0..<3).map { _ in Prekey(id: UUID().uuidString, contactID: contactID, publicKey: randomBytes(65)) }
        let latest  = Date(timeIntervalSince1970: 1_800_000_000)
        let wire    = (0..<15).map { _ in OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: randomBytes(65)) }
        let pending = OccultaBundle.SealedPayload.PrekeySyncBatch(generatedAt: Date(timeIntervalSince1970: 1_800_000_500), prekeys: wire)

        let record = try self.codec.decode(try self.legacyPlaintext(inbound: inbound, latest: latest, pending: pending))

        #expect(record.latestInboundGeneratedAt == latest)
        #expect(record.inboundBatches == [PrekeyRecord.InboundBatch(
            id: nil, keys: inbound.map { PrekeyRecord.InboundKey(id: $0.id, publicKey: $0.publicKey) }
        )])
        #expect(record.ownBatches == [PrekeyRecord.OwnBatch(
            id: nil, createdAt: pending.generatedAt, retiredAt: nil, isPending: true,
            keys: wire.map { PrekeyRecord.OwnKey(id: uuidBytes(UUID(uuidString: $0.id)!), blob: nil, publicKey: $0.publicKey) }
        )])
        #expect(record.acceptedBatchIDs.isEmpty)
        #expect(record.legacyKeys == .inUse, "legacy keys may exist and the contact hasn't switched yet")

        // And it survives a trip through the current format.
        #expect(try self.codec.decode(self.codec.encode(record)) == record)
    }

    @Test("A legacy pending batch whose key IDs aren't UUIDs is rejected, not guessed at")
    func legacyNonUUIDRejected() throws {
        let pending = OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Date(), prekeys: [OccultaBundle.WirePrekey(id: "not-a-uuid", publicKey: randomBytes(65))]
        )
        let plaintext = try self.legacyPlaintext(inbound: [], latest: nil, pending: pending)
        #expect(throws: PrekeyRecordCodec.CodecError.malformed) { try self.codec.decode(plaintext) }
    }
}

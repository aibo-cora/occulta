//
//  SignedAttributeCodecTests.swift
//  OccultaTests
//
//  RECOVERY_BUFFER_LAYERING.md §6 item 9.3 — fixed-width wire format for one
//  SignedAttribute, the per-slot unit ShardsCodec builds on. Pure byte-level
//  codec; the one Secure Enclave touch is TestKeyManager producing a realistic
//  DER signature to round-trip, no gating needed for that.
//

import Testing
import Foundation
@testable import Occulta
@testable import OccultaCore

@MainActor
@Suite("SignedAttributeCodec — fixed-width SignedAttribute wire format")
struct SignedAttributeCodecTests {

    private typealias Codec = PendingShamirSecretRestore.SignedAttributeCodec

    private func makeShardValue() -> Data {
        // 1-byte x-coordinate + 32-byte y-values — ShamirSecretSharing.split's own shape.
        Data([UInt8(1)]) + Data.randomBytes(32)
    }

    private func makeAttribute(
        id: UUID = UUID(),
        label: String = "vault-shard",
        value: Data? = nil,
        category: SignedAttribute.Category = .shard,
        createdAt: Date = Date(timeIntervalSince1970: 1_800_000_000),
        expiresAt: Date? = nil,
        entryID: UUID? = UUID()
    ) throws -> SignedAttribute {
        let signer = TestKeyManager()
        let shardValue = value ?? self.makeShardValue()
        let payload = SignedAttribute.signingPayload(
            id: id, category: category, value: shardValue,
            entryID: entryID, createdAt: createdAt, expiresAt: expiresAt
        )
        let signature = try signer.signData(payload)
        return SignedAttribute(
            id: id, label: label, value: shardValue, category: category,
            signature: signature, createdAt: createdAt, expiresAt: expiresAt, entryID: entryID
        )
    }

    // MARK: Size invariant

    @Test("Encoded size is always Codec.size")
    func encodedSizeIsAlwaysFixed() throws {
        let attribute = try self.makeAttribute()
        #expect(try Codec.encode(attribute).count == Codec.size)
    }

    // MARK: Round trip

    @Test("Round trip with an entryID and no expiry")
    func roundTripWithEntryIDNoExpiry() throws {
        let original = try self.makeAttribute(expiresAt: nil, entryID: UUID())
        let decoded = try #require(Codec.decode(try Codec.encode(original)))

        #expect(decoded.id == original.id)
        #expect(decoded.label == original.label)
        #expect(decoded.value == original.value)
        #expect(decoded.category == original.category)
        #expect(decoded.signature == original.signature)
        #expect(decoded.createdAt == original.createdAt)
        #expect(decoded.expiresAt == nil)
        #expect(decoded.entryID == original.entryID)
    }

    @Test("Round trip with no entryID and a real expiry")
    func roundTripNoEntryIDWithExpiry() throws {
        let expiresAt = Date(timeIntervalSince1970: 1_900_000_000)
        let original = try self.makeAttribute(expiresAt: expiresAt, entryID: nil)
        let decoded = try #require(Codec.decode(try Codec.encode(original)))

        #expect(decoded.entryID == nil)
        #expect(decoded.expiresAt == expiresAt)
        #expect(decoded.signature == original.signature)
    }

    @Test("Round trip preserves every SignedAttribute.Category")
    func roundTripEveryCategory() throws {
        let categories: [SignedAttribute.Category] = [
            .financial, .identity, .medical, .access, .emergency,
            .communication, .crypto, .shard, .attestation, .other,
        ]
        for category in categories {
            let original = try self.makeAttribute(category: category)
            let decoded = try #require(Codec.decode(try Codec.encode(original)))
            #expect(decoded.category == category)
        }
    }

    @Test("A label at the 256-byte fixed-width boundary round-trips exactly")
    func roundTripLabelAtBoundary() throws {
        let label = String(repeating: "a", count: 256)
        let original = try self.makeAttribute(label: label)
        let decoded = try #require(Codec.decode(try Codec.encode(original)))
        #expect(decoded.label == label)
    }

    @Test("A label longer than 256 bytes is truncated, not thrown — display-only field")
    func labelLongerThanBoundaryTruncates() throws {
        let label = String(repeating: "a", count: 300)
        let original = try self.makeAttribute(label: label)
        let decoded = try #require(Codec.decode(try Codec.encode(original)))
        #expect(decoded.label == String(repeating: "a", count: 256))
    }

    // MARK: Failure modes

    @Test("Encoding a value that isn't exactly 33 bytes throws, never truncates key material")
    func unexpectedValueSizeThrows() throws {
        let signer = TestKeyManager()
        let badValue = Data.randomBytes(16)
        let attribute = SignedAttribute(
            label: "vault-shard", value: badValue, category: .shard,
            signature: try signer.signData(Data()), entryID: UUID()
        )

        #expect(throws: Codec.CodecError.unexpectedValueSize(count: 16)) {
            try Codec.encode(attribute)
        }
    }

    @Test("Encoding a signature longer than 72 bytes throws, never truncates it")
    func signatureTooLongThrows() throws {
        let attribute = SignedAttribute(
            label: "vault-shard", value: self.makeShardValue(), category: .shard,
            signature: Data.randomBytes(73), entryID: UUID()
        )

        #expect(throws: Codec.CodecError.signatureTooLong(count: 73)) {
            try Codec.encode(attribute)
        }
    }

    @Test("Decoding rejects the wrong length rather than partially decoding")
    func decodeRejectsWrongLength() {
        #expect(Codec.decode(Data.randomBytes(Codec.size - 1)) == nil)
        #expect(Codec.decode(Data.randomBytes(Codec.size + 1)) == nil)
        #expect(Codec.decode(Data()) == nil)
    }

    @Test("Decoding rejects an unrecognised category tag")
    func decodeRejectsUnrecognisedCategoryTag() throws {
        let original = try self.makeAttribute()
        var encoded = try Codec.encode(original)
        encoded[305] = 0xFF   // category tag byte
        #expect(Codec.decode(encoded) == nil)
    }

    @Test("Decoding rejects a signature region that isn't a valid DER SEQUENCE")
    func decodeRejectsMalformedDERSignature() throws {
        let original = try self.makeAttribute()
        var encoded = try Codec.encode(original)
        encoded[306] = 0x00   // signature region's first byte — not 0x30
        #expect(Codec.decode(encoded) == nil)
    }
}

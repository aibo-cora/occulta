//
//  IdentityChallengePayloadTests.swift
//  OccultaTests
//
//  Simulator safe — pure binary serialisation, no SE, no SwiftData.
//

import Testing
import Foundation
@testable import Occulta

// MARK: - ChallengePayload

@Suite("IdentityChallenge — ChallengePayload")
struct IdentityChallengePayloadTests {

    private func makePayload(
        nonce: Data = Data(repeating: 0xAA, count: 32),
        timestamp: Data = IdentityChallenge.encodeTimestamp(1_700_000_000),
        fingerprint: Data = Data(repeating: 0xBB, count: 32)
    ) -> IdentityChallenge.ChallengePayload {
        IdentityChallenge.ChallengePayload(
            nonce: nonce,
            timestamp: timestamp,
            challengerFingerprint: fingerprint
        )
    }

    // MARK: Roundtrip

    @Test func encodeDecodeRoundtrip() throws {
        let original = makePayload()
        let decoded  = try IdentityChallenge.ChallengePayload(from: original.encoded())

        #expect(decoded.nonce                 == original.nonce)
        #expect(decoded.timestamp             == original.timestamp)
        #expect(decoded.challengerFingerprint == original.challengerFingerprint)
    }

    // MARK: Fixed layout

    @Test func totalSizeIs72Bytes() {
        #expect(makePayload().encoded().count == 72)
    }

    @Test func nonceAtOffset0() {
        let nonce   = Data(repeating: 0xAA, count: 32)
        let encoded = makePayload(nonce: nonce).encoded()
        #expect(encoded[0..<32] == nonce)
    }

    @Test func timestampAtOffset32() {
        let ts      = IdentityChallenge.encodeTimestamp(9_999_999_999)
        let encoded = makePayload(timestamp: ts).encoded()
        #expect(encoded[32..<40] == ts)
    }

    @Test func fingerprintAtOffset40() {
        let fp      = Data(repeating: 0xCC, count: 32)
        let encoded = makePayload(fingerprint: fp).encoded()
        #expect(encoded[40..<72] == fp)
    }

    // MARK: Timestamp big-endian encoding

    @Test func timestampBigEndianEncoding() {
        let value: UInt64 = 0x0102030405060708
        let encoded = IdentityChallenge.encodeTimestamp(value)
        #expect(encoded == Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]))
    }

    @Test func timestampDecodeRoundtrip() throws {
        let value: UInt64 = 1_700_000_000
        let encoded = IdentityChallenge.encodeTimestamp(value)
        let decoded = try IdentityChallenge.decodeTimestamp(encoded)
        #expect(decoded == value)
    }

    @Test func timestampZero() throws {
        let encoded = IdentityChallenge.encodeTimestamp(0)
        #expect(encoded == Data([0, 0, 0, 0, 0, 0, 0, 0]))
        let decoded = try IdentityChallenge.decodeTimestamp(encoded)
        #expect(decoded == 0)
    }

    @Test func timestampMaxValue() throws {
        let value = UInt64.max
        let encoded = IdentityChallenge.encodeTimestamp(value)
        let decoded = try IdentityChallenge.decodeTimestamp(encoded)
        #expect(decoded == value)
    }

    // MARK: Malformed data — too short

    @Test func tooShortThrows() {
        for length in 0..<72 {
            #expect(throws: (any Error).self) {
                try IdentityChallenge.ChallengePayload(from: Data(count: length))
            }
        }
    }

    // MARK: Malformed data — too long (strict)

    @Test func tooLongThrows() {
        #expect(throws: (any Error).self) {
            try IdentityChallenge.ChallengePayload(from: Data(count: 73))
        }
    }

    @Test func tooLongThrows_manyExtraBytes() {
        #expect(throws: (any Error).self) {
            try IdentityChallenge.ChallengePayload(from: Data(count: 200))
        }
    }

    // MARK: Exact-size boundary

    @Test func exactSizeSucceeds() throws {
        let data = Data(count: 72)
        let _ = try IdentityChallenge.ChallengePayload(from: data)
    }
}

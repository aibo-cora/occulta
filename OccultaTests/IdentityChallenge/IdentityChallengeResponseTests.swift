//
//  IdentityChallengeResponseTests.swift
//  OccultaTests
//
//  Simulator safe — pure binary serialisation, no SE, no SwiftData.
//

import Testing
import Foundation
@testable import Occulta

// MARK: - ResponsePayload

@Suite("IdentityChallenge — ResponsePayload")
struct IdentityChallengeResponseTests {

    private let sampleNonce:     Data = Data(repeating: 0xAA, count: 32)
    private let sampleSignature: Data = Data(repeating: 0x30, count: 71) // typical DER ECDSA length

    // MARK: Roundtrip

    @Test func encodeDecodeRoundtrip() throws {
        let original = IdentityChallenge.ResponsePayload(
            challengeNonce: sampleNonce,
            signature:      sampleSignature
        )
        let decoded = try IdentityChallenge.ResponsePayload(from: original.encoded())
        #expect(decoded.challengeNonce == original.challengeNonce)
        #expect(decoded.signature      == original.signature)
    }

    // MARK: Layout

    @Test func nonceAtOffset0() throws {
        let payload = IdentityChallenge.ResponsePayload(
            challengeNonce: sampleNonce,
            signature:      sampleSignature
        )
        let encoded = payload.encoded()
        #expect(encoded[0..<32] == sampleNonce)
    }

    @Test func signatureAtOffset32() throws {
        let payload = IdentityChallenge.ResponsePayload(
            challengeNonce: sampleNonce,
            signature:      sampleSignature
        )
        let encoded = payload.encoded()
        #expect(encoded[32...] == sampleSignature)
    }

    @Test func totalSizeIsNoncePlusSignature() {
        let payload = IdentityChallenge.ResponsePayload(
            challengeNonce: sampleNonce,
            signature:      sampleSignature
        )
        #expect(payload.encoded().count == 32 + sampleSignature.count)
    }

    // MARK: Variable-length signature survives roundtrip

    @Test func shortSignatureRoundtrip() throws {
        let sig     = Data(repeating: 0xFF, count: 1)
        let payload = IdentityChallenge.ResponsePayload(challengeNonce: sampleNonce, signature: sig)
        let decoded = try IdentityChallenge.ResponsePayload(from: payload.encoded())
        #expect(decoded.signature == sig)
    }

    @Test func longSignatureRoundtrip() throws {
        let sig     = Data(repeating: 0xDE, count: 256)
        let payload = IdentityChallenge.ResponsePayload(challengeNonce: sampleNonce, signature: sig)
        let decoded = try IdentityChallenge.ResponsePayload(from: payload.encoded())
        #expect(decoded.signature == sig)
    }

    // MARK: Malformed data — too short

    @Test func emptyDataThrows() {
        #expect(throws: (any Error).self) {
            try IdentityChallenge.ResponsePayload(from: Data())
        }
    }

    @Test func exactly32BytesThrows_noSignature() {
        // 32 bytes = nonce only, no signature byte → too short
        #expect(throws: (any Error).self) {
            try IdentityChallenge.ResponsePayload(from: Data(count: 32))
        }
    }

    @Test func lessThan33BytesThrows() {
        for length in 0..<33 {
            #expect(throws: (any Error).self) {
                try IdentityChallenge.ResponsePayload(from: Data(count: length))
            }
        }
    }

    @Test func exactly33BytesSucceeds() throws {
        // 32-byte nonce + 1-byte signature — minimum valid
        let data    = Data(count: 33)
        let decoded = try IdentityChallenge.ResponsePayload(from: data)
        #expect(decoded.challengeNonce.count == 32)
        #expect(decoded.signature.count == 1)
    }
}

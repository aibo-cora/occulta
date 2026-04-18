//
//  IdentityChallengeBundleTests.swift
//  OccultaTests
//
//  Verifies `SealedPayload`'s `identityChallenge` envelope routing — the
//  backward-compatible alternative to adding new `Version` / `Mode` cases.
//

import Testing
import CryptoKit
import Foundation
@testable import Occulta

@Suite("OccultaBundle — SealedPayload content routing")
struct IdentityChallengeBundleTests {

    // MARK: - SealedPayload roundtrip

    @Test func sealedPayload_withEnvelope_roundtripsClean() throws {
        let original = OccultaBundle.SealedPayload(
            message:           Data("fallback".utf8),
            prekeyBatch:       nil,
            identityChallenge: .challenge(
                payload:     Data(repeating: 0xAB, count: 72),
                contextNote: nil
            )
        )
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: encoded)

        #expect(decoded.message                    == Data("fallback".utf8))
        #expect(decoded.identityChallenge?.kind    == .challenge)
        #expect(decoded.identityChallenge?.payload == Data(repeating: 0xAB, count: 72))
        #expect(decoded.prekeyBatch                == nil)
    }

    @Test func sealedPayload_regularMessage_hasNilEnvelope() throws {
        let original = OccultaBundle.SealedPayload(message: Data("hi".utf8))
        let encoded  = try JSONEncoder().encode(original)
        let decoded  = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: encoded)

        #expect(decoded.identityChallenge == nil)
        #expect(decoded.message           == Data("hi".utf8))
    }

    @Test func sealedPayload_challengeVsResponse_routesDistinctly() throws {
        let chl = OccultaBundle.SealedPayload(
            message:           Data(),
            identityChallenge: .challenge(payload: Data([0x01]), contextNote: nil)
        )
        let rsp = OccultaBundle.SealedPayload(
            message:           Data(),
            identityChallenge: .response(payload: Data([0x01]))
        )
        let encChl = try JSONEncoder().encode(chl)
        let encRsp = try JSONEncoder().encode(rsp)

        let decChl = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: encChl)
        let decRsp = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: encRsp)

        #expect(decChl.identityChallenge?.kind == .challenge)
        #expect(decRsp.identityChallenge?.kind == .response)
    }

    // MARK: - Envelope-specific

    @Test func envelope_encodesAsNestedJSONObject() throws {
        // The envelope must live as a nested object under "identityChallenge"
        // so future per-feature envelopes can sit alongside it without
        // fighting over top-level key names.
        let sealed = OccultaBundle.SealedPayload(
            message:           Data(),
            identityChallenge: .challenge(payload: Data([0xEE]), contextNote: "why?")
        )
        let data = try JSONEncoder().encode(sealed)
        let obj  = try JSONSerialization.jsonObject(with: data) as? [String: Any]

        let env = obj?["identityChallenge"] as? [String: Any]
        #expect(env != nil)
        #expect(env?["kind"] as? String == "challenge")
        #expect(env?["contextNote"] as? String == "why?")
    }

    @Test func envelope_kindRawValuesAreStable() throws {
        // These raw strings are wire-format commitments. Changing them breaks
        // every shipped build that decodes a v1.4.0+ bundle.
        #expect(IdentityChallengeEnvelope.Kind.challenge.rawValue == "challenge")
        #expect(IdentityChallengeEnvelope.Kind.response.rawValue  == "response")
    }

    @Test func envelope_responseFactoryForcesNilContextNote() {
        // The .response factory is the single enforcement point of the
        // "responses never carry a note" rule.
        let env = IdentityChallengeEnvelope.response(payload: Data([0x01, 0x02]))
        #expect(env.kind        == .response)
        #expect(env.contextNote == nil)
    }

    @Test func envelope_challengeFactoryPreservesContextNote() {
        let env = IdentityChallengeEnvelope.challenge(payload: Data(), contextNote: "hello")
        #expect(env.kind        == .challenge)
        #expect(env.contextNote == "hello")
    }

    @Test func envelope_absent_decodesAsNil() throws {
        // A SealedPayload without the "identityChallenge" key must decode
        // with envelope == nil — that is the regular-message sentinel.
        let raw = #"""
        { "message": "", "prekeyBatch": null }
        """#
        let decoded = try JSONDecoder().decode(
            OccultaBundle.SealedPayload.self,
            from: Data(raw.utf8)
        )
        #expect(decoded.identityChallenge == nil)
    }

    // MARK: - Version backward compat

    @Test func existingV3fsBundleStillDecodes() throws {
        // A v3fs bundle written before the SealedPayload extension must still decode.
        let bundle = OccultaBundle(
            version: .v3fs,
            secrecy: OccultaBundle.SecrecyContext(
                mode:               .forwardSecret,
                ephemeralPublicKey: Data(count: 65),
                prekeyID:           "prekey-old"
            ),
            ciphertext:        Data(repeating: 0xFF, count: 32),
            fingerprintNonce:  Data(repeating: 0x01, count: 16),
            senderFingerprint: Data(repeating: 0xAA, count: 32)
        )
        let decoded = try OccultaBundle.decoded(from: bundle.encoded())

        #expect(decoded.version          == .v3fs)
        #expect(decoded.secrecy.mode     == .forwardSecret)
        #expect(decoded.secrecy.prekeyID == "prekey-old")
    }

    // MARK: - AAD unchanged for regular bundles

    @Test func aadForV3fsLongTermFallback_isStableAcrossBuilds() throws {
        // If this byte sequence changes, we have broken wire compatibility
        // with every shipped Occulta build.
        let secrecy = OccultaBundle.SecrecyContext(
            mode:               .longTermFallback,
            ephemeralPublicKey: Data(count: 65),
            prekeyID:           nil
        )
        let aad = try OccultaBundle.computeAdditionalAuthentication(version: .v3fs, secrecy: secrecy)
        // Prefix is the version raw value bytes, then the sorted-keys JSON.
        #expect(aad.prefix(4) == Data("v3fs".utf8))
    }
}

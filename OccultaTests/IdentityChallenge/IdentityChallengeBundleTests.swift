//
//  IdentityChallengeBundleTests.swift
//  OccultaTests
//
//  Verifies `SealedPayload`'s `contentType` / `contentData` routing — the
//  backward-compatible alternative to adding new `Version` / `Mode` cases.
//

import Testing
import CryptoKit
import Foundation
@testable import Occulta

@Suite("OccultaBundle — SealedPayload content routing")
struct IdentityChallengeBundleTests {

    // MARK: - SealedPayload roundtrip

    @Test func sealedPayload_withContentType_roundtripsClean() throws {
        let original = OccultaBundle.SealedPayload(
            message:     Data("fallback".utf8),
            prekeyBatch: nil,
            contentType: .identityChallenge,
            contentData: Data(repeating: 0xAB, count: 72)
        )
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: encoded)

        #expect(decoded.message     == Data("fallback".utf8))
        #expect(decoded.contentType == .identityChallenge)
        #expect(decoded.contentData == Data(repeating: 0xAB, count: 72))
        #expect(decoded.prekeyBatch == nil)
    }

    @Test func sealedPayload_regularMessage_hasNilContentType() throws {
        let original = OccultaBundle.SealedPayload(message: Data("hi".utf8))
        let encoded  = try JSONEncoder().encode(original)
        let decoded  = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: encoded)

        #expect(decoded.contentType == nil)
        #expect(decoded.contentData == nil)
        #expect(decoded.message     == Data("hi".utf8))
    }

    @Test func sealedPayload_challengeVsResponse_routesDistinctly() throws {
        let chl = OccultaBundle.SealedPayload(
            message: Data(), contentType: .identityChallenge, contentData: Data([0x01])
        )
        let rsp = OccultaBundle.SealedPayload(
            message: Data(), contentType: .identityChallengeResponse, contentData: Data([0x01])
        )
        let encChl = try JSONEncoder().encode(chl)
        let encRsp = try JSONEncoder().encode(rsp)

        let decChl = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: encChl)
        let decRsp = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: encRsp)

        #expect(decChl.contentType == .identityChallenge)
        #expect(decRsp.contentType == .identityChallengeResponse)
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

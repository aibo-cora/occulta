//
//  IdentityChallengeBundleTests.swift
//  OccultaTests
//
//  Verifies that adding `.identityChallenge` / `.identityChallengeResponse`
//  to OccultaBundle.Version and `.identityChallenge` to OccultaBundle.Mode
//  did not break existing wire-format invariants and that the new cases
//  satisfy the same Codable / AAD / fingerprint contracts as the existing
//  cases.
//

import Testing
import CryptoKit
import Foundation
@testable import Occulta

// MARK: - Version + mode roundtrip

@Suite("OccultaBundle — Identity Challenge versions and mode")
struct IdentityChallengeBundleTests {

    private func makeBundle(version: OccultaBundle.Version) -> OccultaBundle {
        OccultaBundle(
            version: version,
            secrecy: OccultaBundle.SecrecyContext(
                mode:               .identityChallenge,
                ephemeralPublicKey: Data(),       // empty per spec — long-term path only
                prekeyID:           nil           // no prekey consumption
            ),
            ciphertext:        Data(repeating: 0xAB, count: 64),
            fingerprintNonce:  Data(repeating: 0x01, count: 16),
            senderFingerprint: Data(repeating: 0xCD, count: 32)
        )
    }

    @Test func challengeVersionRoundtrip() throws {
        let bundle  = makeBundle(version: .identityChallenge)
        let decoded = try OccultaBundle.decoded(from: bundle.encoded())
        #expect(decoded.version == .identityChallenge)
    }

    @Test func challengeResponseVersionRoundtrip() throws {
        let bundle  = makeBundle(version: .identityChallengeResponse)
        let decoded = try OccultaBundle.decoded(from: bundle.encoded())
        #expect(decoded.version == .identityChallengeResponse)
    }

    @Test func challengeModeRoundtrip() throws {
        let bundle  = makeBundle(version: .identityChallenge)
        let decoded = try OccultaBundle.decoded(from: bundle.encoded())
        #expect(decoded.secrecy.mode == .identityChallenge)
    }

    @Test func emptyEphemeralKeyRoundtrip() throws {
        let bundle  = makeBundle(version: .identityChallenge)
        let decoded = try OccultaBundle.decoded(from: bundle.encoded())
        #expect(decoded.secrecy.ephemeralPublicKey == Data())
        #expect(decoded.secrecy.ephemeralPublicKey.isEmpty)
    }

    @Test func nilPrekeyIDRoundtrip() throws {
        let bundle  = makeBundle(version: .identityChallenge)
        let decoded = try OccultaBundle.decoded(from: bundle.encoded())
        #expect(decoded.secrecy.prekeyID == nil)
    }

    // MARK: - AAD: identity challenge versions are domain-separated

    private func secrecy() -> OccultaBundle.SecrecyContext {
        OccultaBundle.SecrecyContext(
            mode:               .identityChallenge,
            ephemeralPublicKey: Data(),
            prekeyID:           nil
        )
    }

    @Test func aadIncludesIdentityChallengeVersion() throws {
        let aad = try OccultaBundle.computeAdditionalAuthentication(
            version: .identityChallenge,
            secrecy: secrecy()
        )
        let prefix = "identityChallenge".data(using: .utf8)!
        #expect(aad.prefix(prefix.count) == prefix)
    }

    @Test func aadDifferentForChallengeVsResponse() throws {
        let s   = secrecy()
        let chl = try OccultaBundle.computeAdditionalAuthentication(version: .identityChallenge,         secrecy: s)
        let rsp = try OccultaBundle.computeAdditionalAuthentication(version: .identityChallengeResponse, secrecy: s)
        #expect(chl != rsp)
    }

    @Test func aadDifferentFromV3fs() throws {
        // .identityChallenge mode uses different fields — produces different AAD than v3fs.
        let challengeAAD = try OccultaBundle.computeAdditionalAuthentication(
            version: .identityChallenge,
            secrecy: secrecy()
        )
        let v3fsAAD = try OccultaBundle.computeAdditionalAuthentication(
            version: .v3fs,
            secrecy: OccultaBundle.SecrecyContext(
                mode:               .forwardSecret,
                ephemeralPublicKey: Data(count: 65),
                prekeyID:           "prekey-id"
            )
        )
        #expect(challengeAAD != v3fsAAD)
    }

    @Test func aadDifferentFromV1Fallback() throws {
        // Modes also matter — same version but different mode produces different AAD.
        let challengeAAD = try OccultaBundle.computeAdditionalAuthentication(
            version: .identityChallenge,
            secrecy: secrecy()
        )
        let fallbackAAD = try OccultaBundle.computeAdditionalAuthentication(
            version: .identityChallenge,
            secrecy: OccultaBundle.SecrecyContext(
                mode:               .longTermFallback,
                ephemeralPublicKey: Data(),
                prekeyID:           nil
            )
        )
        #expect(challengeAAD != fallbackAAD)
    }

    // MARK: - UI helpers

    @Test func isForwardSecretFalseForChallenge() {
        #expect(makeBundle(version: .identityChallenge).isForwardSecret == false)
    }

    @Test func isForwardSecretFalseForResponse() {
        #expect(makeBundle(version: .identityChallengeResponse).isForwardSecret == false)
    }

    @Test func isIdentityChallengeTrueForChallenge() {
        #expect(makeBundle(version: .identityChallenge).isIdentityChallenge == true)
    }

    @Test func isIdentityChallengeTrueForResponse() {
        #expect(makeBundle(version: .identityChallengeResponse).isIdentityChallenge == true)
    }

    @Test func isIdentityChallengeFalseForV3fs() {
        let bundle = OccultaBundle(
            version: .v3fs,
            secrecy: OccultaBundle.SecrecyContext(
                mode:               .forwardSecret,
                ephemeralPublicKey: Data(count: 65),
                prekeyID:           "x"
            ),
            ciphertext:        Data(),
            fingerprintNonce:  Data(count: 16),
            senderFingerprint: Data(count: 32)
        )
        #expect(bundle.isIdentityChallenge == false)
    }

    @Test func securityLabelForChallengeMode() {
        #expect(makeBundle(version: .identityChallenge).securityLabel == "Identity Challenge")
    }

    // MARK: - Backward compatibility

    @Test func existingV3fsBundleStillDecodesAfterEnumExtension() throws {
        // A v3fs bundle written before the enum extension must still decode.
        // We construct one with the old shape and confirm round-trip is unchanged.
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

    @Test func unknownVersionStringFailsToDecode() {
        // An old build encountering a newer version (e.g. "identityChallenge")
        // it does not know about must throw rather than crash.
        // Symmetric expectation: garbage version strings don't crash.
        let json = #"{"version":"v999","secrecy":{"mode":"forwardSecret","ephemeralPublicKey":""},"ciphertext":"","fingerprintNonce":"","senderFingerprint":""}"#
        #expect(throws: (any Error).self) {
            try OccultaBundle.decoded(from: Data(json.utf8))
        }
    }
}

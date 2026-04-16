//
//  IdentityChallengeBackwardCompatTests.swift
//  OccultaTests
//
//  Guards the wire format against the "add a new enum case" footgun.
//
//  Identity challenges MUST ride on existing `Version` / `Mode` values so that
//  old builds in the field can still decode the envelope. Content routing is
//  done inside the encrypted `SealedPayload` via the optional
//  `identityChallenge` sub-envelope — which old Codable decoders harmlessly
//  ignore.
//

import Testing
import Foundation
@testable import Occulta

// MARK: - Fixtures

/// A minimal SealedPayload as an OLD build would see it — no
/// `identityChallenge` key at all. Used to verify a new build decodes legacy
/// data cleanly and that an old build (this struct) decodes new data cleanly.
private struct OldSealedPayload: Codable {
    let message: Data
    let prekeyBatch: OccultaBundle.SealedPayload.PrekeySyncBatch?
}

// MARK: - Suite

@Suite("Identity Challenge — backward compatibility")
@MainActor struct IdentityChallengeBackwardCompatTests {

    // MARK: SealedPayload cross-version Codable

    @Test func oldDecoder_readsNewSealedPayload() throws {
        // New build writes a SealedPayload with a full identityChallenge envelope.
        let fresh = OccultaBundle.SealedPayload(
            message:           Data("hello old app".utf8),
            prekeyBatch:       nil,
            identityChallenge: .challenge(
                payload:     Data(repeating: 0xAB, count: 72),
                contextNote: "Was this you?"
            )
        )
        let bytes = try JSONEncoder().encode(fresh)

        // Old build has no knowledge of the identityChallenge key — must still decode.
        let old = try JSONDecoder().decode(OldSealedPayload.self, from: bytes)

        #expect(old.message == Data("hello old app".utf8))
        #expect(old.prekeyBatch == nil)
    }

    @Test func sealedPayload_contextNoteRoundtrips() throws {
        let original = OccultaBundle.SealedPayload(
            message:           Data(),
            identityChallenge: .challenge(payload: Data([0x00]), contextNote: "hi")
        )
        let bytes   = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: bytes)
        #expect(decoded.identityChallenge?.contextNote == "hi")
    }

    @Test func sealedPayload_contextNoteNilWhenAbsent() throws {
        let original = OccultaBundle.SealedPayload(
            message:           Data(),
            identityChallenge: .challenge(payload: Data([0x00]), contextNote: nil)
        )
        let bytes   = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: bytes)
        #expect(decoded.identityChallenge?.contextNote == nil)
    }

    @Test func newDecoder_readsOldSealedPayload() throws {
        // Old build writes a SealedPayload without the identityChallenge key.
        let old = OldSealedPayload(message: Data("legacy".utf8), prekeyBatch: nil)
        let bytes = try JSONEncoder().encode(old)

        let new = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: bytes)

        #expect(new.message           == Data("legacy".utf8))
        #expect(new.identityChallenge == nil)
    }

    @Test func fallbackMessages_areValidUtf8() {
        let a = IdentityChallenge.challengeFallbackMessage
        let b = IdentityChallenge.responseFallbackMessage

        let roundtripA = String(data: Data(a.utf8), encoding: .utf8)
        let roundtripB = String(data: Data(b.utf8), encoding: .utf8)

        #expect(roundtripA == a)
        #expect(roundtripB == b)
        #expect(!a.isEmpty)
        #expect(!b.isEmpty)
    }

    // MARK: Wire envelope pinning

    @Test func challengeBundle_wireVersionIsV3fs() throws {
        let (c, r) = Self.makeParties()
        let bundle = try c.mgr.createChallenge(for: r.view)

        // Inspect raw JSON: old parsers must see a familiar version string.
        let json = try JSONSerialization.jsonObject(with: bundle.encoded()) as? [String: Any]
        #expect(json?["version"] as? String == "v3fs")
    }

    @Test func challengeBundle_wireModeIsLongTermFallback() throws {
        let (c, r) = Self.makeParties()
        let bundle = try c.mgr.createChallenge(for: r.view)
        let json = try JSONSerialization.jsonObject(with: bundle.encoded()) as? [String: Any]
        let secrecy = json?["secrecy"] as? [String: Any]
        #expect(secrecy?["mode"] as? String == "longTermFallback")
    }

    @Test func responseBundle_wireVersionAndMode() throws {
        let (c, r) = Self.makeParties()
        let challenge = try c.mgr.createChallenge(for: r.view)
        let pending   = try r.mgr.decryptChallenge(bundle: challenge, contacts: [c.view])
        let response  = try r.mgr.respond(to: pending)

        let json    = try JSONSerialization.jsonObject(with: response.encoded()) as? [String: Any]
        let secrecy = json?["secrecy"] as? [String: Any]

        #expect(json?["version"]   as? String == "v3fs")
        #expect(secrecy?["mode"]   as? String == "longTermFallback")
    }

    // MARK: Unsupported version / mode

    @Test func unknownVersionString_decodesAsUnsupported() throws {
        let json = #"""
        {
            "version": "v99future",
            "secrecy": { "mode": "longTermFallback", "ephemeralPublicKey": "" },
            "ciphertext": "",
            "fingerprintNonce": "",
            "senderFingerprint": ""
        }
        """#
        let decoded = try OccultaBundle.decoded(from: Data(json.utf8))
        #expect(decoded.version == .unsupported)
    }

    @Test func unknownModeString_decodesAsUnsupported() throws {
        let json = #"""
        {
            "version": "v3fs",
            "secrecy": { "mode": "xyz-future-mode", "ephemeralPublicKey": "" },
            "ciphertext": "",
            "fingerprintNonce": "",
            "senderFingerprint": ""
        }
        """#
        let decoded = try OccultaBundle.decoded(from: Data(json.utf8))
        #expect(decoded.secrecy.mode == .unsupported)
    }

    @Test func unsupportedVersion_throwsBeforeDecryptInIdentityPath() throws {
        // Build a bundle manually in the unsupported state and hand it to the
        // identity manager. It must reject before touching crypto.
        let (c, r) = Self.makeParties()
        let challenge = try c.mgr.createChallenge(for: r.view)
        // Round-trip through JSON with a rewritten version to trigger `.unsupported`.
        var obj = try JSONSerialization.jsonObject(with: challenge.encoded()) as! [String: Any]
        obj["version"] = "v99future"
        let data    = try JSONSerialization.data(withJSONObject: obj)
        let decoded = try OccultaBundle.decoded(from: data)

        #expect(decoded.version == .unsupported)
        #expect(throws: IdentityChallenge.ManagerError.malformedBundle) {
            _ = try r.mgr.decryptChallenge(bundle: decoded, contacts: [c.view])
        }
    }

    // MARK: End-to-end — old-format bundle on new code

    @Test func oldFormatBundle_decryptsAsRegularMessage() throws {
        // A bundle produced without the identityChallenge key ends up with
        // envelope == nil after decode. The identity manager refuses it;
        // the regular message path treats `message` as text. Here we assert
        // the SealedPayload decoding behaviour directly.
        let old = OldSealedPayload(message: Data("plain text".utf8), prekeyBatch: nil)
        let bytes = try JSONEncoder().encode(old)
        let sealed = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: bytes)

        #expect(sealed.identityChallenge == nil)
        #expect(sealed.message           == Data("plain text".utf8))
    }

    // MARK: - Helper

    @MainActor
    private static func makeParties() -> (challenger: _Party, responder: _Party) {
        (.init(name: "c"), .init(name: "r"))
    }
}

// MARK: - Local harness (duplicated from protocol tests to avoid cross-file dependency)

@MainActor
private struct _Party {
    let km:    TestKeyManager
    let mgr:   IdentityChallenge.Manager
    let view:  IdentityChallenge.ContactView

    init(name: String) {
        let km = TestKeyManager()
        let crypto = Manager.Crypto(keyManager: km)
        let store = IdentityChallenge.OutstandingChallengeStore()
        self.km  = km
        self.mgr = IdentityChallenge.Manager(crypto: crypto, store: store)
        self.view = IdentityChallenge.ContactView(
            identifier: name,
            publicKey:  try! km.retrieveIdentity(),
            displayName: name
        )
    }
}

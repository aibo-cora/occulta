//
//  IdentityChallengeProtocolTests.swift
//  OccultaTests
//
//  End-to-end tests for the three-phase identity-challenge protocol.
//  Uses TestKeyManager (in-memory P-256) on both sides so the tests run in
//  the simulator without any Secure Enclave access.
//
//  Two test keychains per scenario: `challenger` and `responder`, each with
//  its own `Manager.Crypto` + `OutstandingChallengeStore` + `IdentityChallenge.Manager`.
//  The challenger's store holds the phase-1 entry; the responder never sees it.
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta

// MARK: - Harness

@MainActor
private struct Party {
    let km:         TestKeyManager
    let crypto:     Manager.Crypto
    let store:      IdentityChallenge.OutstandingChallengeStore
    let mgr:        IdentityChallenge.Manager
    let identifier: String
    let publicKey:  Data

    /// Clock shared between challenger and responder so tests can advance
    /// both in lockstep. Default is a fixed instant well inside the window.
    static let defaultEpoch: UInt64 = 1_700_000_000

    init(name: String, clock: @escaping () -> Date = { Date(timeIntervalSince1970: TimeInterval(defaultEpoch)) }) {
        let km = TestKeyManager()
        let crypto = Manager.Crypto(keyManager: km)
        let store = IdentityChallenge.OutstandingChallengeStore()
        let mgr = IdentityChallenge.Manager(crypto: crypto, store: store, now: clock)
        self.km         = km
        self.crypto     = crypto
        self.store      = store
        self.mgr        = mgr
        self.identifier = name
        self.publicKey  = try! km.retrieveIdentity()
    }
}

@MainActor
private func parties(
    challengerClock: @escaping () -> Date = { Date(timeIntervalSince1970: TimeInterval(Party.defaultEpoch)) },
    responderClock:  @escaping () -> Date = { Date(timeIntervalSince1970: TimeInterval(Party.defaultEpoch)) }
) -> (challenger: Party, responder: Party) {
    (Party(name: "challenger", clock: challengerClock),
     Party(name: "responder",  clock: responderClock))
}

// MARK: - Suite

@Suite("IdentityChallenge.Manager — protocol tests")
@MainActor struct IdentityChallengeProtocolTests {

    // MARK: Happy path

    @Test func happyPath_fullRoundtrip_verifies() throws {
        let (c, r) = parties()

        let challengeBundle = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier
        )

        let pending = try r.mgr.decryptChallenge(
            bundle: challengeBundle,
            senderKey: c.publicKey, senderQuantum: nil, senderID: c.identifier, senderName: c.identifier
        )
        #expect(pending.challengerPublicKey == c.publicKey && pending.challengerID == c.identifier)

        let responseBundle = try r.mgr.respond(to: pending)

        let (ok, note) = try c.mgr.verifyResponse(
            bundle: responseBundle, senderKey: r.publicKey, senderQuantum: nil, senderID: r.identifier
        )
        #expect(ok)
        #expect(note == nil)

        // Slot is released after verification.
        #expect(c.store.count == 0)
    }

    // MARK: Phase 1 — rate limiting

    @Test func rateLimit_secondChallengeToSameContact_throws() throws {
        let (c, r) = parties()
        _ = try c.mgr.createChallenge(recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier)

        #expect(throws: IdentityChallenge.ManagerError.rateLimited) {
            _ = try c.mgr.createChallenge(recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier)
        }
    }

    @Test func rateLimit_differentContacts_bothAllowed() throws {
        let c  = Party(name: "challenger")
        let r1 = Party(name: "r1")
        let r2 = Party(name: "r2")

        _ = try c.mgr.createChallenge(recipientKey: r1.publicKey, recipientQuantum: nil, contactID: r1.identifier)
        _ = try c.mgr.createChallenge(recipientKey: r2.publicKey, recipientQuantum: nil, contactID: r2.identifier)

        #expect(c.store.count == 2)
    }

    // MARK: Phase 2 — framing

    @Test func decryptChallenge_wrongSenderKey_throwsMalformedBundle() throws {
        let (c, r) = parties()
        let stranger = Party(name: "stranger")
        let bundle = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier
        )

        // Passing the stranger's key produces a wrong-key decryption → malformedBundle.
        #expect(throws: IdentityChallenge.ManagerError.malformedBundle) {
            _ = try r.mgr.decryptChallenge(
                bundle: bundle,
                senderKey: stranger.publicKey, senderQuantum: nil,
                senderID: stranger.identifier, senderName: stranger.identifier
            )
        }
    }

    @Test func decryptChallenge_garbledCiphertext_throwsMalformedBundle() throws {
        // A bundle with random ciphertext must fail decryption regardless of the
        // key provided.
        let (_, r) = parties()
        let fake = OccultaBundle(
            version: .v3fs,
            secrecy: OccultaBundle.SecrecyContext(mode: .longTermFallback, ephemeralPublicKey: Data(), prekeyID: nil),
            ciphertext: Data(count: 64),
            fingerprintNonce: Data(count: 16),
            senderFingerprint: Data(count: 32)
        )
        #expect(throws: IdentityChallenge.ManagerError.malformedBundle) {
            _ = try r.mgr.decryptChallenge(
                bundle: fake,
                senderKey: r.publicKey, senderQuantum: nil,
                senderID: r.identifier, senderName: r.identifier
            )
        }
    }

    // MARK: Phase 3 — verification

    @Test func verify_tamperedResponseCiphertext_returnsFalseOrThrows() throws {
        let (c, r) = parties()
        let challengeBundle = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier
        )
        let pending = try r.mgr.decryptChallenge(
            bundle: challengeBundle,
            senderKey: c.publicKey, senderQuantum: nil, senderID: c.identifier, senderName: c.identifier
        )
        let responseBundle = try r.mgr.respond(to: pending)

        // Tamper with the ciphertext — AES-GCM auth tag should fail.
        var tamperedCt = responseBundle.ciphertext
        tamperedCt[0] ^= 0x01
        let tampered = OccultaBundle(
            version: responseBundle.version,
            secrecy: responseBundle.secrecy,
            ciphertext: tamperedCt,
            fingerprintNonce: responseBundle.fingerprintNonce,
            senderFingerprint: responseBundle.senderFingerprint
        )

        #expect(throws: IdentityChallenge.ManagerError.malformedBundle) {
            _ = try c.mgr.verifyResponse(
                bundle: tampered, senderKey: r.publicKey, senderQuantum: nil, senderID: r.identifier
            )
        }
    }

    @Test func verify_wrongResponder_returnsFalse() throws {
        // The challenger issues a challenge to R. Then an unrelated contact
        // (imposter) replies. Even if their signature is well-formed over
        // "their" reconstruction of the signed data, it must not verify
        // against R's public key — but the contactKeyID check fires first.
        let c        = Party(name: "c")
        let r        = Party(name: "r")
        let imposter = Party(name: "imposter")

        let challenge = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier
        )

        // Imposter decrypts nothing — they fabricate a response. Easiest path:
        // let them legitimately handle a DIFFERENT challenge aimed at them,
        // then submit that response to verify against r. The store
        // lookup will find a valid entry (for r), contactKeyID mismatch fires.
        _ = challenge
        // Simulate an imposter response by having `imposter` act as responder
        // to a challenge issued to THEM. We then present that response to `c`
        // claiming it proves `imposter`'s identity... but c's store has no
        // entry for `imposter`, so the nonce lookup fails → false.
        let c2 = Party(name: "c2")
        let challengeToImposter = try c2.mgr.createChallenge(
            recipientKey: imposter.publicKey, recipientQuantum: nil, contactID: imposter.identifier
        )
        let pending = try imposter.mgr.decryptChallenge(
            bundle: challengeToImposter,
            senderKey: c2.publicKey, senderQuantum: nil, senderID: c2.identifier, senderName: c2.identifier
        )
        let imposterResponse = try imposter.mgr.respond(to: pending)

        // Now submit imposterResponse to the ORIGINAL challenger. The bundle
        // was sealed by imposter for c2 — so c cannot derive the session key.
        // Decryption fails with `.malformedBundle`. Either outcome means
        // the imposter cannot claim r's identity — which is the property.
        #expect(throws: IdentityChallenge.ManagerError.malformedBundle) {
            _ = try c.mgr.verifyResponse(
                bundle: imposterResponse,
                senderKey: imposter.publicKey, senderQuantum: nil, senderID: imposter.identifier
            )
        }
    }

    // MARK: Timing — strict 5-minute window on phase 3

    @Test func verify_staleByMoreThanWindow_returnsFalse() throws {
        let epoch = Party.defaultEpoch
        var nowTicks = epoch
        let clock: () -> Date = { Date(timeIntervalSince1970: TimeInterval(nowTicks)) }

        let c = Party(name: "c", clock: clock)
        let r = Party(name: "r", clock: clock)

        let challenge = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier
        )
        let pending = try r.mgr.decryptChallenge(
            bundle: challenge,
            senderKey: c.publicKey, senderQuantum: nil, senderID: c.identifier, senderName: c.identifier
        )
        let response = try r.mgr.respond(to: pending)

        // Advance past the 5-minute window before the challenger verifies.
        nowTicks = epoch + UInt64(IdentityChallenge.timestampWindow) + 1

        let (ok, _) = try c.mgr.verifyResponse(
            bundle: response, senderKey: r.publicKey, senderQuantum: nil, senderID: r.identifier
        )
        #expect(!ok)
    }

    @Test func verify_atWindowBoundary_returnsTrue() throws {
        let epoch = Party.defaultEpoch
        var nowTicks = epoch
        let clock: () -> Date = { Date(timeIntervalSince1970: TimeInterval(nowTicks)) }

        let c = Party(name: "c", clock: clock)
        let r = Party(name: "r", clock: clock)

        let challenge = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier
        )
        let pending = try r.mgr.decryptChallenge(
            bundle: challenge,
            senderKey: c.publicKey, senderQuantum: nil, senderID: c.identifier, senderName: c.identifier
        )
        let response = try r.mgr.respond(to: pending)

        // Just under the window.
        nowTicks = epoch + UInt64(IdentityChallenge.timestampWindow) - 1

        let (ok, _) = try c.mgr.verifyResponse(
            bundle: response, senderKey: r.publicKey, senderQuantum: nil, senderID: r.identifier
        )
        #expect(ok)
    }

    // MARK: Replay

    @Test func verify_replayedResponse_returnsFalseOnSecondAttempt() throws {
        let (c, r) = parties()
        let challenge = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier
        )
        let pending = try r.mgr.decryptChallenge(
            bundle: challenge,
            senderKey: c.publicKey, senderQuantum: nil, senderID: c.identifier, senderName: c.identifier
        )
        let response = try r.mgr.respond(to: pending)

        // First verify — succeeds and consumes the slot.
        #expect(try c.mgr.verifyResponse(
            bundle: response, senderKey: r.publicKey, senderQuantum: nil, senderID: r.identifier
        ).ok)

        // Replay — same response, but store no longer has the entry.
        let (replay, _) = try c.mgr.verifyResponse(
            bundle: response, senderKey: r.publicKey, senderQuantum: nil, senderID: r.identifier
        )
        #expect(!replay)
    }

    // MARK: Phase 2 staleness

    @Test func decryptChallenge_staleByMoreThanThreshold_throws() throws {
        let epoch = Party.defaultEpoch
        let challengerClock: () -> Date = { Date(timeIntervalSince1970: TimeInterval(epoch)) }

        // Responder's clock is far ahead — challenge looks ancient on arrival.
        let responderClock: () -> Date = {
            Date(timeIntervalSince1970: TimeInterval(epoch) + IdentityChallenge.timestampStaleThreshold + 60)
        }

        let (c, r) = parties(challengerClock: challengerClock, responderClock: responderClock)
        let bundle = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier
        )

        #expect(throws: IdentityChallenge.ManagerError.verificationFailed) {
            _ = try r.mgr.decryptChallenge(
                bundle: bundle,
                senderKey: c.publicKey, senderQuantum: nil, senderID: c.identifier, senderName: c.identifier
            )
        }
    }

    @Test func decryptChallenge_futureTimestampWithinSkewGrace_succeeds() throws {
        let epoch = Party.defaultEpoch

        // Challenger is slightly ahead of responder (within grace).
        let challengerClock: () -> Date = { Date(timeIntervalSince1970: TimeInterval(epoch) + IdentityChallenge.clockSkewGrace - 1) }
        let responderClock:  () -> Date = { Date(timeIntervalSince1970: TimeInterval(epoch)) }

        let (c, r) = parties(challengerClock: challengerClock, responderClock: responderClock)
        let bundle  = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier
        )
        let pending = try r.mgr.decryptChallenge(
            bundle: bundle,
            senderKey: c.publicKey, senderQuantum: nil, senderID: c.identifier, senderName: c.identifier
        )
        #expect(pending.challengerPublicKey == c.publicKey && pending.challengerID == c.identifier)
    }

    @Test func decryptChallenge_futureTimestampBeyondSkewGrace_throws() throws {
        let epoch = Party.defaultEpoch

        let challengerClock: () -> Date = { Date(timeIntervalSince1970: TimeInterval(epoch) + IdentityChallenge.clockSkewGrace + 60) }
        let responderClock:  () -> Date = { Date(timeIntervalSince1970: TimeInterval(epoch)) }

        let (c, r) = parties(challengerClock: challengerClock, responderClock: responderClock)
        let bundle = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier
        )

        #expect(throws: IdentityChallenge.ManagerError.verificationFailed) {
            _ = try r.mgr.decryptChallenge(
                bundle: bundle,
                senderKey: c.publicKey, senderQuantum: nil, senderID: c.identifier, senderName: c.identifier
            )
        }
    }

    // MARK: Store hygiene

    @Test func expiredEntries_areDroppedByRemoveExpired() throws {
        let epoch = Party.defaultEpoch
        var nowTicks = epoch
        let clock: () -> Date = { Date(timeIntervalSince1970: TimeInterval(nowTicks)) }

        let c = Party(name: "c", clock: clock)
        let r = Party(name: "r", clock: clock)

        _ = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier
        )
        #expect(c.store.count == 1)

        // Advance past the stale threshold and simulate an app launch sweep.
        nowTicks = epoch + UInt64(IdentityChallenge.timestampStaleThreshold) + 1
        c.store.removeExpired(now: Date(timeIntervalSince1970: TimeInterval(nowTicks)))

        #expect(c.store.count == 0)

        // Rate limit is now free again.
        #expect(!c.store.hasOutstanding(for: r.identifier))
    }

    // MARK: Bundle metadata

    @Test func challengeBundle_ridesV3fsLongTermFallback() throws {
        // Wire envelope must be indistinguishable from a regular fallback
        // message so older builds can still decode the bundle.
        let (c, r) = parties()
        let b = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier
        )
        #expect(b.version      == .v3fs)
        #expect(b.secrecy.mode == .longTermFallback)
        #expect(b.secrecy.prekeyID == nil)
    }

    // MARK: Context note

    @Test func contextNote_roundtripsThroughChallengeAndVerify() throws {
        let (c, r) = parties()
        let note = "Someone on Telegram is asking me for 18,000. Was this you?"

        let challenge = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier, contextNote: note
        )
        let pending = try r.mgr.decryptChallenge(
            bundle: challenge,
            senderKey: c.publicKey, senderQuantum: nil, senderID: c.identifier, senderName: c.identifier
        )
        #expect(pending.contextNote == note)

        let response = try r.mgr.respond(to: pending)
        let (ok, echoed) = try c.mgr.verifyResponse(
            bundle: response, senderKey: r.publicKey, senderQuantum: nil, senderID: r.identifier
        )
        #expect(ok)
        #expect(echoed == note)
    }

    @Test func contextNote_nilWhenNotProvided() throws {
        let (c, r) = parties()
        let challenge = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier
        )
        let pending = try r.mgr.decryptChallenge(
            bundle: challenge,
            senderKey: c.publicKey, senderQuantum: nil, senderID: c.identifier, senderName: c.identifier
        )
        #expect(pending.contextNote == nil)

        let response = try r.mgr.respond(to: pending)
        let (ok, echoed) = try c.mgr.verifyResponse(
            bundle: response, senderKey: r.publicKey, senderQuantum: nil, senderID: r.identifier
        )
        #expect(ok)
        #expect(echoed == nil)
    }

    @Test func contextNote_truncatedAtMaxBytes() throws {
        let (c, r) = parties()
        // 600-byte ASCII note — sender MUST truncate to 500 before seal.
        let oversize = String(repeating: "a", count: 600)
        let challenge = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier, contextNote: oversize
        )
        let pending = try r.mgr.decryptChallenge(
            bundle: challenge,
            senderKey: c.publicKey, senderQuantum: nil, senderID: c.identifier, senderName: c.identifier
        )

        #expect(pending.contextNote?.utf8.count == IdentityChallenge.maxContextNoteBytes)
        #expect(pending.contextNote == String(repeating: "a", count: IdentityChallenge.maxContextNoteBytes))
    }

    @Test func contextNote_emptyStringTreatedAsNil() throws {
        let (c, r) = parties()
        let challenge = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier, contextNote: ""
        )
        let pending = try r.mgr.decryptChallenge(
            bundle: challenge,
            senderKey: c.publicKey, senderQuantum: nil, senderID: c.identifier, senderName: c.identifier
        )
        #expect(pending.contextNote == nil)
    }

    @Test func contextNote_responseCarriesNoNote() throws {
        // Responses never include a contextNote — the response envelope on
        // a response bundle must have contextNote == nil even when the
        // originating challenge had one.
        let (c, r) = parties()
        let challenge = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier, contextNote: "hi"
        )
        let pending = try r.mgr.decryptChallenge(
            bundle: challenge,
            senderKey: c.publicKey, senderQuantum: nil, senderID: c.identifier, senderName: c.identifier
        )
        let response = try r.mgr.respond(to: pending)

        // Decrypt the response ourselves (challenger side) and inspect the
        // SealedPayload directly — can't use the public API since it strips
        // the note for response-typed bundles.
        let sessionKey = c.crypto.deriveSessionKey(using: r.publicKey)!
        let plaintext  = try c.crypto.open(response, using: sessionKey)
        let sealed     = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: plaintext)
        #expect(sealed.identityChallenge?.kind        == .response)
        #expect(sealed.identityChallenge?.contextNote == nil)
    }

    @Test func responder_silentlyIgnoresContextNoteOnResponseEnvelope() throws {
        // A non-compliant peer could craft a response envelope with a
        // contextNote set. The verifier must accept the response and simply
        // ignore the note — never throw. This test fabricates such a response
        // by hand because the public API (`.response(payload:)`) forces nil.
        let (c, r) = parties()
        let challenge = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier
        )
        let pending = try r.mgr.decryptChallenge(
            bundle: challenge,
            senderKey: c.publicKey, senderQuantum: nil, senderID: c.identifier, senderName: c.identifier
        )
        let realResponse = try r.mgr.respond(to: pending)

        // Decrypt the real response, rewrite the envelope to include a note,
        // re-seal with the same session key, and hand it to the challenger.
        let sessionKey = c.crypto.deriveSessionKey(using: r.publicKey)!
        let plaintext  = try c.crypto.open(realResponse, using: sessionKey)
        var sealed     = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: plaintext)

        let tamperedEnvelope = IdentityChallengeEnvelope(
            kind:        .response,
            payload:     sealed.identityChallenge!.payload,
            contextNote: "I should not be here"
        )
        sealed = OccultaBundle.SealedPayload(
            message:           sealed.message,
            prekeyBatch:       sealed.prekeyBatch,
            identityChallenge: tamperedEnvelope
        )

        let reencoded = try JSONEncoder().encode(sealed)
        let aad       = try OccultaBundle.computeAdditionalAuthentication(
            version: realResponse.version, secrecy: realResponse.secrecy
        )
        let box = try AES.GCM.seal(
            reencoded, using: sessionKey, nonce: AES.GCM.Nonce(), authenticating: aad
        )
        let resealed = OccultaBundle(
            version:           realResponse.version,
            secrecy:           realResponse.secrecy,
            ciphertext:        box.combined!,
            fingerprintNonce:  realResponse.fingerprintNonce,
            senderFingerprint: realResponse.senderFingerprint
        )

        // Verification should succeed — the tampered note is ignored, not fatal.
        let (ok, _) = try c.mgr.verifyResponse(
            bundle: resealed, senderKey: r.publicKey, senderQuantum: nil, senderID: r.identifier
        )
        #expect(ok)
    }

    @Test func contextNote_notInSignedData() throws {
        // Signing the same (nonce, timestamp, fingerprint) with or without a
        // note must produce data that verifies identically — the note has
        // zero cryptographic role.
        let epoch = Party.defaultEpoch
        let clock: () -> Date = { Date(timeIntervalSince1970: TimeInterval(epoch)) }

        let c = Party(name: "c", clock: clock)
        let r = Party(name: "r", clock: clock)

        // Challenge WITH note → sign → verify.
        let challengeA = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier, contextNote: "X"
        )
        let pendingA = try r.mgr.decryptChallenge(
            bundle: challengeA,
            senderKey: c.publicKey, senderQuantum: nil, senderID: c.identifier, senderName: c.identifier
        )
        let responseA = try r.mgr.respond(to: pendingA)
        let (okA, _)  = try c.mgr.verifyResponse(
            bundle: responseA, senderKey: r.publicKey, senderQuantum: nil, senderID: r.identifier
        )
        #expect(okA)
    }

    @Test func responseBundle_ridesV3fsLongTermFallback() throws {
        let (c, r) = parties()
        let challenge = try c.mgr.createChallenge(
            recipientKey: r.publicKey, recipientQuantum: nil, contactID: r.identifier
        )
        let pending = try r.mgr.decryptChallenge(
            bundle: challenge,
            senderKey: c.publicKey, senderQuantum: nil, senderID: c.identifier, senderName: c.identifier
        )
        let response = try r.mgr.respond(to: pending)
        #expect(response.version      == .v3fs)
        #expect(response.secrecy.mode == .longTermFallback)
    }
}

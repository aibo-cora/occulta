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
    let km:    TestKeyManager
    let crypto: Manager.Crypto
    let store: IdentityChallenge.OutstandingChallengeStore
    let mgr:   IdentityChallenge.Manager
    let view:  IdentityChallenge.ContactView

    /// Clock shared between challenger and responder so tests can advance
    /// both in lockstep. Default is a fixed instant well inside the window.
    static let defaultEpoch: UInt64 = 1_700_000_000

    init(name: String, clock: @escaping () -> Date = { Date(timeIntervalSince1970: TimeInterval(defaultEpoch)) }) {
        let km = TestKeyManager()
        let crypto = Manager.Crypto(keyManager: km)
        let store = IdentityChallenge.OutstandingChallengeStore()
        let mgr = IdentityChallenge.Manager(crypto: crypto, store: store, now: clock)
        self.km = km
        self.crypto = crypto
        self.store = store
        self.mgr = mgr
        self.view = IdentityChallenge.ContactView(
            identifier: name,
            publicKey:  try! km.retrieveIdentity(),
            displayName: name
        )
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

        let challengeBundle = try c.mgr.createChallenge(for: r.view)

        let pending = try r.mgr.decryptChallenge(bundle: challengeBundle, contacts: [c.view])
        #expect(pending.challenger == c.view)

        let responseBundle = try r.mgr.respond(to: pending)

        let ok = try c.mgr.verifyResponse(bundle: responseBundle, contacts: [r.view])
        #expect(ok)

        // Slot is released after verification.
        #expect(c.store.count == 0)
    }

    // MARK: Phase 1 — rate limiting

    @Test func rateLimit_secondChallengeToSameContact_throws() throws {
        let (c, r) = parties()
        _ = try c.mgr.createChallenge(for: r.view)

        #expect(throws: IdentityChallenge.ManagerError.rateLimited) {
            _ = try c.mgr.createChallenge(for: r.view)
        }
    }

    @Test func rateLimit_differentContacts_bothAllowed() throws {
        let c  = Party(name: "challenger")
        let r1 = Party(name: "r1")
        let r2 = Party(name: "r2")

        _ = try c.mgr.createChallenge(for: r1.view)
        _ = try c.mgr.createChallenge(for: r2.view)

        #expect(c.store.count == 2)
    }

    // MARK: Phase 2 — framing

    @Test func decryptChallenge_unknownSender_throws() throws {
        let (c, r) = parties()
        let stranger = Party(name: "stranger")
        let bundle = try c.mgr.createChallenge(for: r.view)

        // Responder's contact list does not include the challenger.
        #expect(throws: IdentityChallenge.ManagerError.unknownSender) {
            _ = try r.mgr.decryptChallenge(bundle: bundle, contacts: [stranger.view])
        }
    }

    @Test func decryptChallenge_wrongVersion_throws() throws {
        let (c, r) = parties()
        // A regular v3fs bundle must not be routed through the challenge decryptor.
        let fake = OccultaBundle(
            version: .v3fs,
            secrecy: OccultaBundle.SecrecyContext(mode: .longTermFallback, ephemeralPublicKey: Data(), prekeyID: nil),
            ciphertext: Data(count: 64),
            fingerprintNonce: Data(count: 16),
            senderFingerprint: Data(count: 32)
        )
        _ = c
        #expect(throws: IdentityChallenge.ManagerError.malformedBundle) {
            _ = try r.mgr.decryptChallenge(bundle: fake, contacts: [])
        }
    }

    // MARK: Phase 3 — verification

    @Test func verify_tamperedResponseCiphertext_returnsFalseOrThrows() throws {
        let (c, r) = parties()
        let challengeBundle = try c.mgr.createChallenge(for: r.view)
        let pending = try r.mgr.decryptChallenge(bundle: challengeBundle, contacts: [c.view])
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
            _ = try c.mgr.verifyResponse(bundle: tampered, contacts: [r.view])
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

        let challenge = try c.mgr.createChallenge(for: r.view)

        // Imposter decrypts nothing — they fabricate a response. Easiest path:
        // let them legitimately handle a DIFFERENT challenge aimed at them,
        // then submit that response to verify against r.view. The store
        // lookup will find a valid entry (for r), contactKeyID mismatch fires.
        _ = challenge
        // Simulate an imposter response by having `imposter` act as responder
        // to a challenge issued to THEM. We then present that response to `c`
        // claiming it proves `imposter`'s identity... but c's store has no
        // entry for `imposter`, so the nonce lookup fails → false.
        let c2 = Party(name: "c2")
        let challengeToImposter = try c2.mgr.createChallenge(for: imposter.view)
        let pending             = try imposter.mgr.decryptChallenge(bundle: challengeToImposter, contacts: [c2.view])
        let imposterResponse    = try imposter.mgr.respond(to: pending)

        // Now submit imposterResponse to the ORIGINAL challenger. The bundle
        // routes to `imposter` by fingerprint, but was sealed against c2's
        // identity — so c cannot derive the session key. Decryption fails
        // with `.malformedBundle`. Either outcome (throw or `false`) means
        // the imposter cannot claim r's identity — which is the property.
        #expect(throws: IdentityChallenge.ManagerError.malformedBundle) {
            _ = try c.mgr.verifyResponse(bundle: imposterResponse, contacts: [r.view, imposter.view])
        }
    }

    // MARK: Timing — strict 5-minute window on phase 3

    @Test func verify_staleByMoreThanWindow_returnsFalse() throws {
        let epoch = Party.defaultEpoch
        var nowTicks = epoch
        let clock: () -> Date = { Date(timeIntervalSince1970: TimeInterval(nowTicks)) }

        let c = Party(name: "c", clock: clock)
        let r = Party(name: "r", clock: clock)

        let challenge = try c.mgr.createChallenge(for: r.view)
        let pending   = try r.mgr.decryptChallenge(bundle: challenge, contacts: [c.view])
        let response  = try r.mgr.respond(to: pending)

        // Advance past the 5-minute window before the challenger verifies.
        nowTicks = epoch + UInt64(IdentityChallenge.timestampWindow) + 1

        let ok = try c.mgr.verifyResponse(bundle: response, contacts: [r.view])
        #expect(!ok)
    }

    @Test func verify_atWindowBoundary_returnsTrue() throws {
        let epoch = Party.defaultEpoch
        var nowTicks = epoch
        let clock: () -> Date = { Date(timeIntervalSince1970: TimeInterval(nowTicks)) }

        let c = Party(name: "c", clock: clock)
        let r = Party(name: "r", clock: clock)

        let challenge = try c.mgr.createChallenge(for: r.view)
        let pending   = try r.mgr.decryptChallenge(bundle: challenge, contacts: [c.view])
        let response  = try r.mgr.respond(to: pending)

        // Just under the window.
        nowTicks = epoch + UInt64(IdentityChallenge.timestampWindow) - 1

        let ok = try c.mgr.verifyResponse(bundle: response, contacts: [r.view])
        #expect(ok)
    }

    // MARK: Replay

    @Test func verify_replayedResponse_returnsFalseOnSecondAttempt() throws {
        let (c, r) = parties()
        let challenge = try c.mgr.createChallenge(for: r.view)
        let pending   = try r.mgr.decryptChallenge(bundle: challenge, contacts: [c.view])
        let response  = try r.mgr.respond(to: pending)

        // First verify — succeeds and consumes the slot.
        #expect(try c.mgr.verifyResponse(bundle: response, contacts: [r.view]))

        // Replay — same response, but store no longer has the entry.
        let replay = try c.mgr.verifyResponse(bundle: response, contacts: [r.view])
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
        let bundle = try c.mgr.createChallenge(for: r.view)

        #expect(throws: IdentityChallenge.ManagerError.verificationFailed) {
            _ = try r.mgr.decryptChallenge(bundle: bundle, contacts: [c.view])
        }
    }

    @Test func decryptChallenge_futureTimestampWithinSkewGrace_succeeds() throws {
        let epoch = Party.defaultEpoch

        // Challenger is slightly ahead of responder (within grace).
        let challengerClock: () -> Date = { Date(timeIntervalSince1970: TimeInterval(epoch) + IdentityChallenge.clockSkewGrace - 1) }
        let responderClock:  () -> Date = { Date(timeIntervalSince1970: TimeInterval(epoch)) }

        let (c, r) = parties(challengerClock: challengerClock, responderClock: responderClock)
        let bundle  = try c.mgr.createChallenge(for: r.view)
        let pending = try r.mgr.decryptChallenge(bundle: bundle, contacts: [c.view])
        #expect(pending.challenger == c.view)
    }

    @Test func decryptChallenge_futureTimestampBeyondSkewGrace_throws() throws {
        let epoch = Party.defaultEpoch

        let challengerClock: () -> Date = { Date(timeIntervalSince1970: TimeInterval(epoch) + IdentityChallenge.clockSkewGrace + 60) }
        let responderClock:  () -> Date = { Date(timeIntervalSince1970: TimeInterval(epoch)) }

        let (c, r) = parties(challengerClock: challengerClock, responderClock: responderClock)
        let bundle = try c.mgr.createChallenge(for: r.view)

        #expect(throws: IdentityChallenge.ManagerError.verificationFailed) {
            _ = try r.mgr.decryptChallenge(bundle: bundle, contacts: [c.view])
        }
    }

    // MARK: Store hygiene

    @Test func expiredEntries_areDroppedByRemoveExpired() throws {
        let epoch = Party.defaultEpoch
        var nowTicks = epoch
        let clock: () -> Date = { Date(timeIntervalSince1970: TimeInterval(nowTicks)) }

        let c = Party(name: "c", clock: clock)
        let r = Party(name: "r", clock: clock)

        _ = try c.mgr.createChallenge(for: r.view)
        #expect(c.store.count == 1)

        // Advance past the stale threshold and simulate an app launch sweep.
        nowTicks = epoch + UInt64(IdentityChallenge.timestampStaleThreshold) + 1
        c.store.removeExpired(now: Date(timeIntervalSince1970: TimeInterval(nowTicks)))

        #expect(c.store.count == 0)

        // Rate limit is now free again.
        #expect(!c.store.hasOutstanding(for: r.view.identifier))
    }

    // MARK: Bundle metadata

    @Test func challengeBundle_hasCorrectVersionAndMode() throws {
        let (c, r) = parties()
        let b = try c.mgr.createChallenge(for: r.view)
        #expect(b.version      == .identityChallenge)
        #expect(b.secrecy.mode == .identityChallenge)
        #expect(b.secrecy.ephemeralPublicKey.isEmpty)
        #expect(b.secrecy.prekeyID == nil)
    }

    @Test func responseBundle_hasCorrectVersionAndMode() throws {
        let (c, r) = parties()
        let challenge = try c.mgr.createChallenge(for: r.view)
        let pending   = try r.mgr.decryptChallenge(bundle: challenge, contacts: [c.view])
        let response  = try r.mgr.respond(to: pending)
        #expect(response.version      == .identityChallengeResponse)
        #expect(response.secrecy.mode == .identityChallenge)
    }
}

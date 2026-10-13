//
//  IdentityChallengeUnsolicitedResponseTests.swift
//  OccultaTests
//
//  `bugs.md` Bug 166: a response naming no challenge we're waiting for showed "Verification failed — this may not
//  be <contact>". Reopening a genuine response file after it passed was enough: its nonce was used up when it
//  passed. A result is now shown only for a response that opens and names our challenge to that contact.
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta
@testable import OccultaFormats

@Suite("Identity challenge — a response we aren't waiting for shows nothing (Bug 166)")
@MainActor struct IdentityChallengeUnsolicitedResponseTests {

    // We are this device's ambient identity; Alice is the contact we challenge.
    let alice = TestKeyManager()
    let envelope = IdentityChallengeEnvelope.response(payload: Data())

    private func aliceProfile() throws -> Contact.Profile {
        let profile = Contact.Profile(
            identifier: "alice", givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        profile.contactPublicKeys = [Contact.Profile.Key(
            material: try #require(try Manager.Crypto().encrypt(data: try self.alice.retrieveIdentity())),
            owner: Data(), date: Data(), quantumKeyMaterialEncrypted: nil
        )]
        return profile
    }

    /// We challenge Alice, and she answers on her own phone.
    private func challengeAndResponse(
        _ coordinator: IdentityChallenge.Coordinator, profile: Contact.Profile
    ) throws -> OccultaBundle {
        try coordinator.createChallenge(for: profile, contextNote: nil)
        let challengeFile = try #require(coordinator.outboundShare?.url)
        defer { try? FileManager.default.removeItem(at: challengeFile) }

        let aliceManager = IdentityChallenge.Manager(
            crypto: Manager.Crypto(keyManager: self.alice), store: IdentityChallenge.OutstandingChallengeStore()
        )
        let pending = try aliceManager.decryptChallenge(
            bundle: try OccultaBundle.decoded(from: try Data(contentsOf: challengeFile)),
            senderKey: try Manager.Ambient.keyManager.retrieveIdentity(), senderQuantum: nil,
            senderID: "us", senderName: "Us"
        )
        return try aliceManager.respond(to: pending)
    }

    @Test("Reopening a response that already passed shows no result", .ambientTestKeyManager)
    func reopenedResponseShowsNothing() throws {
        let profile = try self.aliceProfile()
        let coordinator = IdentityChallenge.Coordinator()
        let response = try self.challengeAndResponse(coordinator, profile: profile)

        coordinator.handleInboundChallenge(bundle: response, envelope: self.envelope, sender: profile)
        #expect(coordinator.verificationOutcome?.passed == true, "control: the first time, it passes")

        coordinator.verificationOutcome = nil
        coordinator.handleInboundChallenge(bundle: response, envelope: self.envelope, sender: profile)
        #expect(coordinator.verificationOutcome == nil)
    }

    /// A stray response mustn't settle the challenge either: Alice's own answer still has to count.
    @Test("A response that doesn't open shows nothing, and leaves the challenge waiting", .ambientTestKeyManager)
    func unopenableResponseShowsNothing() throws {
        let profile = try self.aliceProfile()
        let coordinator = IdentityChallenge.Coordinator()
        let response = try self.challengeAndResponse(coordinator, profile: profile)

        var ciphertext = response.ciphertext
        ciphertext[ciphertext.startIndex] ^= 0x01
        let damaged = OccultaBundle(
            version: response.version, secrecy: response.secrecy, ciphertext: ciphertext,
            fingerprintNonce: response.fingerprintNonce, senderFingerprint: response.senderFingerprint
        )
        coordinator.handleInboundChallenge(bundle: damaged, envelope: self.envelope, sender: profile)
        #expect(coordinator.verificationOutcome == nil)
        #expect(coordinator.store.hasOutstanding(for: "alice"))

        coordinator.handleInboundChallenge(bundle: response, envelope: self.envelope, sender: profile)
        #expect(coordinator.verificationOutcome?.passed == true)
    }

    /// What the sheet is for: a response to our challenge, from the contact, that doesn't verify.
    @Test("A response naming our challenge with a bad signature still shows \"Verification failed\"", .ambientTestKeyManager)
    func badSignatureStillFails() throws {
        let profile = try self.aliceProfile()
        let coordinator = IdentityChallenge.Coordinator()
        let response = try self.challengeAndResponse(coordinator, profile: profile)

        // Alice's response with its signature broken, resealed under the same long-term session key.
        let sessionKey = try #require(Manager.Crypto().deriveSessionKey(using: try self.alice.retrieveIdentity()))
        let sealed = try JSONDecoder().decode(
            OccultaBundle.SealedPayload.self, from: try Manager.Crypto().open(response, using: sessionKey)
        )
        let answer = try IdentityChallenge.ResponsePayload(from: try #require(sealed.identityChallenge).payload)
        var signature = answer.signature
        signature[signature.index(before: signature.endIndex)] ^= 0x01
        let broken = try JSONEncoder().encode(OccultaBundle.SealedPayload(
            message: sealed.message,
            identityChallenge: .response(payload: IdentityChallenge.ResponsePayload(
                challengeNonce: answer.challengeNonce, signature: signature
            ).encoded())
        ))
        let aad = try OccultaBundle.computeAdditionalAuthentication(version: response.version, secrecy: response.secrecy)
        let resealed = OccultaBundle(
            version: response.version, secrecy: response.secrecy,
            ciphertext: try #require(try AES.GCM.seal(broken, using: sessionKey, authenticating: aad).combined),
            fingerprintNonce: response.fingerprintNonce, senderFingerprint: response.senderFingerprint
        )

        coordinator.handleInboundChallenge(bundle: resealed, envelope: self.envelope, sender: profile)
        #expect(coordinator.verificationOutcome?.passed == false)
        #expect(!coordinator.store.hasOutstanding(for: "alice"), "a failed answer settles the challenge")
    }
}

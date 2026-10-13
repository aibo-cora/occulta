//
//  IdentityChallengeUnsolicitedResponseTests.swift
//  OccultaTests
//
//  `bugs.md` Bug 166: a response naming no challenge we're waiting for shows "Verification failed — this may not
//  be <contact>". Reopening a genuine response file after it passed is enough: its nonce was used up when it passed.
//

import Testing
import Foundation
@testable import Occulta
@testable import OccultaFormats

@Suite("Identity challenge — a response we aren't waiting for shows nothing (Bug 166)")
@MainActor struct IdentityChallengeUnsolicitedResponseTests {

    @Test("Reopening a response that already passed shows no result", .ambientTestKeyManager)
    func reopenedResponseShowsNothing() throws {
        // We are this device's ambient identity; Alice is the contact we challenge.
        let alice = TestKeyManager()
        let profile = Contact.Profile(
            identifier: "alice", givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        profile.contactPublicKeys = [Contact.Profile.Key(
            material: try #require(try Manager.Crypto().encrypt(data: try alice.retrieveIdentity())),
            owner: Data(), date: Data(), quantumKeyMaterialEncrypted: nil
        )]

        let coordinator = IdentityChallenge.Coordinator()
        try coordinator.createChallenge(for: profile, contextNote: nil)
        let challengeFile = try #require(coordinator.outboundShare?.url)
        defer { try? FileManager.default.removeItem(at: challengeFile) }

        // Alice answers on her own phone.
        let aliceManager = IdentityChallenge.Manager(
            crypto: Manager.Crypto(keyManager: alice), store: IdentityChallenge.OutstandingChallengeStore()
        )
        let pending = try aliceManager.decryptChallenge(
            bundle: try OccultaBundle.decoded(from: try Data(contentsOf: challengeFile)),
            senderKey: try Manager.Ambient.keyManager.retrieveIdentity(), senderQuantum: nil,
            senderID: "us", senderName: "Us"
        )
        let response = try aliceManager.respond(to: pending)
        let envelope = IdentityChallengeEnvelope.response(payload: Data())

        coordinator.handleInboundChallenge(bundle: response, envelope: envelope, sender: profile)
        #expect(coordinator.verificationOutcome?.passed == true, "control: the first time, it passes")

        coordinator.verificationOutcome = nil
        coordinator.handleInboundChallenge(bundle: response, envelope: envelope, sender: profile)
        withKnownIssue("Bug 166: the reopened response shows \"Verification failed\" for Alice") {
            #expect(coordinator.verificationOutcome == nil)
        }
    }
}

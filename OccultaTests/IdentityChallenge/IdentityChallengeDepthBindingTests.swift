//
//  IdentityChallengeDepthBindingTests.swift
//  OccultaTests
//
//  `bugs.md` Bug 180: the outstanding-challenge store and `verifiedAt` outlived `endSession`, so a response to a
//  challenge made at the real depth, opened after a duress unlock, showed "Identity verified" with the owner's
//  own question. Both are now bound to the depth that created them, in the ledger `ContactManager` keeps; at any
//  other depth a response finds no entry and shows nothing.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta
@testable import OccultaFormats

@Suite("Identity challenge — state is bound to the depth that created it (Bug 180)")
@MainActor struct IdentityChallengeDepthBindingTests {

    let alice = TestKeyManager()
    let envelope = IdentityChallengeEnvelope.response(payload: Data())

    /// A coordinator on a phone with Secure Mode on, so the depth can be moved between 0 and 1 by PIN.
    @MainActor private struct Phone {
        let coordinator: IdentityChallenge.Coordinator
        let contacts: ContactManager
        let security: Manager.Security

        /// What the ledger says about Alice at the depth that is open now.
        var waiting: Bool { self.contacts.hasOutstanding(for: "alice", now: Date()) }

        func unlock(_ pin: String) throws {
            self.security.applyVerifyState(for: try self.security.verify(pin))
        }

        /// What `RootView.endSession` clears on a lock or a depth change.
        func endSession() {
            self.coordinator.outboundShare       = nil
            self.coordinator.incomingChallenge   = nil
            self.coordinator.verificationOutcome = nil
        }
    }

    private func phone() throws -> Phone {
        let schema = Schema([
            AppLayerConfig.self, Group.self, Contact.Profile.self, Contact.Profile.PhoneNumber.self,
            Contact.Profile.EmailAddress.self, Contact.Profile.PostalAddress.self,
            Contact.Profile.URLAddress.self, Contact.Profile.Key.self, VaultEntry.self,
        ])
        let container = try ModelContainer(
            for: schema, configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
        )
        let security = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        let contacts = ContactManager(modelContainer: container, security: security)
        try security.configurePIN("111111")
        try security.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        #expect(security.currentDepth == 0)
        return Phone(
            coordinator: IdentityChallenge.Coordinator(ledger: contacts, sealer: contacts), contacts: contacts, security: contacts.security
        )
    }

    /// Alice, stored: the challenge state is a column on her row.
    private func aliceProfile(in contacts: ContactManager) throws -> Contact.Profile {
        let profile = Contact.Profile(
            identifier: "alice", givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        profile.contactPublicKeys = [Contact.Profile.Key(
            material: try Manager.Crypto().encrypt(data: try self.alice.retrieveIdentity()),
            owner: Data(), date: Data(), quantumKeyMaterialEncrypted: nil
        )]
        contacts.modelContext.insert(profile)
        try contacts.modelContext.save()
        return profile
    }

    /// We challenge Alice with a note, and she answers on her own phone.
    private func challengeAndResponse(_ coordinator: IdentityChallenge.Coordinator, profile: Contact.Profile) throws -> OccultaBundle {
        try coordinator.createChallenge(for: profile, contextNote: "real-depth question")
        let challengeFile = try #require(coordinator.outboundShare?.url)
        defer { try? FileManager.default.removeItem(at: challengeFile) }

        let aliceManager = IdentityChallenge.Manager(
            crypto: Manager.Crypto(keyManager: self.alice), ledger: IdentityChallenge.OutstandingChallengeStore()
        )
        let pending = try aliceManager.decryptChallenge(
            bundle: try OccultaBundle.decoded(from: try Data(contentsOf: challengeFile)),
            senderKey: try Manager.Ambient.keyManager.retrieveIdentity(), senderQuantum: nil,
            senderID: "us", senderName: "Us"
        )
        return try aliceManager.respond(to: pending)
    }

    @Test("A response opened at another depth shows nothing, and leaves the entry for the creating depth", .ambientTestKeyManager)
    func responseAtAnotherDepthShowsNothing() throws {
        let phone = try self.phone()
        let profile = try self.aliceProfile(in: phone.contacts)
        let response = try self.challengeAndResponse(phone.coordinator, profile: profile)

        phone.endSession()
        try phone.unlock("999999")
        #expect(phone.security.currentDepth == 1)

        phone.coordinator.handleInboundChallenge(bundle: response, envelope: self.envelope, sender: profile)
        #expect(phone.coordinator.verificationOutcome == nil)
        #expect(!phone.waiting, "no challenge is visible at another depth")

        try phone.unlock("111111")
        #expect(phone.waiting, "the creating depth still waits for its answer")
    }

    @Test("A response opened at the creating depth after a lock and a duress session still passes", .ambientTestKeyManager)
    func responseAtCreatingDepthAfterLockPasses() throws {
        let phone = try self.phone()
        let profile = try self.aliceProfile(in: phone.contacts)
        let response = try self.challengeAndResponse(phone.coordinator, profile: profile)

        phone.endSession()
        try phone.unlock("999999")
        phone.endSession()
        try phone.unlock("111111")
        #expect(phone.security.currentDepth == 0)

        phone.coordinator.handleInboundChallenge(bundle: response, envelope: self.envelope, sender: profile)
        #expect(phone.coordinator.verificationOutcome?.passed == true)
        #expect(phone.coordinator.verificationOutcome?.contextNote == "real-depth question")
    }

    @Test("\"Verified N minutes ago\" shows only at the depth that verified", .ambientTestKeyManager)
    func verifiedBadgeIsDepthBound() throws {
        let phone = try self.phone()
        let profile = try self.aliceProfile(in: phone.contacts)
        let response = try self.challengeAndResponse(phone.coordinator, profile: profile)
        phone.coordinator.handleInboundChallenge(bundle: response, envelope: self.envelope, sender: profile)
        #expect(phone.coordinator.verifiedBadge(for: "alice") != nil, "control: shown where it was verified")

        phone.endSession()
        try phone.unlock("999999")
        #expect(phone.coordinator.verifiedBadge(for: "alice") == nil)

        try phone.unlock("111111")
        #expect(phone.coordinator.verifiedBadge(for: "alice") != nil)
    }

    @Test("A challenge at one depth doesn't block a challenge to the same contact at another", .ambientTestKeyManager)
    func challengesAtTwoDepthsAreIndependent() throws {
        let phone = try self.phone()
        let profile = try self.aliceProfile(in: phone.contacts)
        try phone.coordinator.createChallenge(for: profile, contextNote: nil)
        let atDepthZero = try #require(phone.contacts.challenge(for: "alice"))

        phone.endSession()
        try phone.unlock("999999")
        #expect(!phone.waiting)
        try phone.coordinator.createChallenge(for: profile, contextNote: nil)
        #expect(phone.waiting)

        let atDepthOne = try #require(phone.contacts.challenge(for: "alice"))
        #expect(atDepthOne.nonce != atDepthZero.nonce)

        try phone.unlock("111111")
        #expect(phone.waiting)
        #expect(phone.contacts.challenge(for: "alice") == atDepthZero, "slot 0 is unchanged after the depth-1 write")
    }
}

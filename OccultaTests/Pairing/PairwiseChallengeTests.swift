//
//  PairwiseChallengeTests.swift
//  OccultaTests
//
//  Bug 196, stage 2: an identity challenge to a pair-key pairing is made and answered with the pair signing keys. A challenge's
//  inner fingerprint is made from the challenger's pair signing key and its response is signed by the responder's, so holding
//  an identity key's private half answers nothing for such a pairing; and a challenge outstanding when the pairing is made
//  again is dropped, so a stale answer shows nothing.
//
//  Software pair keys behind `SoftwareCardKeys`; no Enclave.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta
@testable import OccultaFormats

// MARK: - Fixture

/// One side of a pairing: an identity key manager, a challenge manager over its own ledger, and the pair keys.
@MainActor
private struct Side {
    let identity = TestKeyManager()
    let ledger = IdentityChallenge.OutstandingChallengeStore()
    let slot: PairingSlotKeys
    let manager: IdentityChallenge.Manager

    init(keys: PairKeys, provider: any CardKeyProviding = SoftwareCardKeys(), ledger: (any IdentityChallenge.ChallengeLedger)? = nil) {
        let identity = self.identity
        self.slot = PairingSlotKeys(keys: keys, provider: provider)
        self.manager = IdentityChallenge.Manager(
            crypto: Occulta.Manager.Crypto(keyManager: identity), ledger: ledger ?? self.ledger
        )
    }
}

private func mirroredKeys() throws -> (a: PairKeys, b: PairKeys) {
    let keys = try MirroredPairKeys()
    return (keys.a, keys.b)
}

// MARK: - Suite

@MainActor
@Suite("Bug 196 — identity challenges between pair-key pairings", .serialized)
struct PairwiseChallengeTests {

    /// A challenges B and B answers, each with the pair keys of the pairing. The envelopes are what would travel.
    private func exchange(
        challenger: Side, responder: Side, challengerPairing: PairingSlotKeys?, responderPairing: PairingSlotKeys?
    ) throws -> (challenge: IdentityChallengeEnvelope, pending: IdentityChallenge.PendingApproval, response: IdentityChallengeEnvelope) {
        let challenge = try challenger.manager.createChallenge(
            contactID: "b", contextNote: "Was this you?", pairing: challengerPairing
        ) { $0 }
        let pending = try responder.manager.decryptChallenge(
            envelope: challenge, senderKey: try challenger.identity.retrieveIdentity(), senderQuantum: nil,
            senderID: "a", senderName: "A", pairing: responderPairing
        )
        let response = try responder.manager.respond(to: pending, pairing: responderPairing) { $0 }
        return (challenge, pending, response)
    }

    @Test("A challenge made and answered with the pair signing keys verifies", .ambientTestKeyManager)
    func roundTrip() throws {
        let keys = try mirroredKeys()
        let a = Side(keys: keys.a), b = Side(keys: keys.b)
        let sent = try self.exchange(challenger: a, responder: b, challengerPairing: a.slot, responderPairing: b.slot)

        let result = try a.manager.verifyResponse(
            envelope: sent.response, senderKey: try b.identity.retrieveIdentity(), senderID: "b", pairing: a.slot
        )
        #expect(result == .passed(contextNote: "Was this you?"))
    }

    @Test("The inner fingerprint is the challenger's pair signing key's, not the identity key's", .ambientTestKeyManager)
    func fingerprintIsFromThePairSigningKey() throws {
        let keys = try mirroredKeys()
        let a = Side(keys: keys.a), b = Side(keys: keys.b)
        let sent = try self.exchange(challenger: a, responder: b, challengerPairing: a.slot, responderPairing: b.slot)

        let fingerprint = sent.pending.payload.challengerFingerprint
        #expect(fingerprint == OccultaBundle.SecrecyContext.fingerprint(for: keys.a.ourSigningKey, nonce: sent.pending.payload.nonce))
        #expect(fingerprint != OccultaBundle.SecrecyContext.fingerprint(for: try a.identity.retrieveIdentity(), nonce: sent.pending.payload.nonce))
    }

    @Test("A challenge made with the identity key is refused by a pair-key responder", .ambientTestKeyManager)
    func identityKeyChallengeIsRefused() throws {
        let keys = try mirroredKeys()
        let a = Side(keys: keys.a), b = Side(keys: keys.b)

        #expect(throws: IdentityChallenge.ManagerError.self) {
            try self.exchange(challenger: a, responder: b, challengerPairing: nil, responderPairing: b.slot)
        }
    }

    @Test("A response signed with the identity key does not verify for a pair-key challenger", .ambientTestKeyManager)
    func identityKeyResponseFails() throws {
        let keys = try mirroredKeys()
        let a = Side(keys: keys.a), b = Side(keys: keys.b)
        // B answers as a plain pairing would: the fingerprint it checks and the signature it makes are the identity key's.
        let challenge = try a.manager.createChallenge(contactID: "b", pairing: a.slot) { $0 }
        let payload = try IdentityChallenge.ChallengePayload(from: challenge.payload)
        let pending = IdentityChallenge.PendingApproval(
            challengerID: "a", challengerName: "A", challengerPublicKey: try a.identity.retrieveIdentity(), challengerQuantum: nil,
            payload: payload, contextNote: nil
        )
        let response = try b.manager.respond(to: pending) { $0 }

        let result = try a.manager.verifyResponse(
            envelope: response, senderKey: try b.identity.retrieveIdentity(), senderID: "b", pairing: a.slot
        )
        #expect(result == .failed(contextNote: nil))
    }

    @Test("A response signed with the pair key does not verify for a challenger without pair keys", .ambientTestKeyManager)
    func pairKeyResponseIsNotTheIdentityKeys() throws {
        let keys = try mirroredKeys()
        let a = Side(keys: keys.a), b = Side(keys: keys.b)
        let sent = try self.exchange(challenger: a, responder: b, challengerPairing: a.slot, responderPairing: b.slot)

        let result = try a.manager.verifyResponse(
            envelope: sent.response, senderKey: try b.identity.retrieveIdentity(), senderID: "b", pairing: nil
        )
        #expect(result == .failed(contextNote: "Was this you?"))
    }

    @Test("A responder whose pair signing key won't import produces no response, and never signs with the identity key", .ambientTestKeyManager)
    func unimportableKeyProducesNoResponse() throws {
        let keys = try mirroredKeys()
        let a = Side(keys: keys.a), b = Side(keys: keys.b, provider: BrokenCardKeys())
        let challenge = try a.manager.createChallenge(contactID: "b", pairing: a.slot) { $0 }
        let pending = try b.manager.decryptChallenge(
            envelope: challenge, senderKey: try a.identity.retrieveIdentity(), senderQuantum: nil, senderID: "a", senderName: "A",
            pairing: b.slot
        )

        #expect(throws: PairingSlotKeys.SlotKeyError.unavailable) { try b.manager.respond(to: pending, pairing: b.slot) { $0 } }
    }

    // MARK: A re-pair

    @Test("A challenge outstanding when a pair-key pairing is made again is dropped, so a stale answer shows nothing", .ambientTestKeyManager)
    func rePairDropsTheOutstandingChallenge() throws {
        let keys = try mirroredKeys(), second = try mirroredKeys()
        let schema = Schema([
            Group.self, Contact.Profile.self, Contact.Profile.PhoneNumber.self, Contact.Profile.EmailAddress.self,
            Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self, Contact.Profile.Key.self,
        ])
        let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
        let cm = ContactManager(
            modelContainer: container, security: Manager.Security(modelContainer: container, keyManager: TestKeyManager()),
            pairKeys: SoftwareCardKeys()
        )
        let b = Side(keys: keys.b)
        let a = Side(keys: keys.a, ledger: cm)

        // The contact B, held by A with pair keys.
        let profile = Contact.Profile(
            identifier: "b", givenName: "", familyName: "", middleName: "", nickname: "", organizationName: "",
            departmentName: "", jobTitle: ""
        )
        let key = Contact.Profile.Key(
            material: try Manager.Crypto().encrypt(data: try b.identity.retrieveIdentity()), owner: Data(), date: Data(),
            quantumKeyMaterialEncrypted: nil
        )
        try cm.store(.paired(routingKey: Data(repeating: 1, count: 32), keys: keys.a), in: key)
        profile.contactPublicKeys = [key]
        try cm.insertProfile(profile)

        // A challenges B; B answers; the answer has not arrived.
        let sent = try self.exchange(challenger: a, responder: b, challengerPairing: a.slot, responderPairing: b.slot)
        #expect(cm.challenge(for: "b") != nil)

        // The two meet again: a new pairing, new pair keys, the same identity key.
        let draft = try #require(Contact.Draft.Key(
            material: try b.identity.retrieveIdentity(), owner: Data(repeating: 1, count: 65), date: "2",
            routingKey: Data(repeating: 2, count: 32), pairKeys: second.a
        ))
        try cm.update(key: draft, for: "b")

        #expect(cm.challenge(for: "b") == nil, "the retired pair signing key can't verify it")
        let stale = try a.manager.verifyResponse(
            envelope: sent.response, senderKey: try b.identity.retrieveIdentity(), senderID: "b",
            pairing: PairingSlotKeys(keys: second.a, provider: SoftwareCardKeys())
        )
        #expect(stale == .notOurs)
    }

    @Test("A re-pair of a pairing without pair keys leaves an outstanding challenge alone", .ambientTestKeyManager)
    func plainRePairKeepsTheChallenge() throws {
        let schema = Schema([
            Group.self, Contact.Profile.self, Contact.Profile.PhoneNumber.self, Contact.Profile.EmailAddress.self,
            Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self, Contact.Profile.Key.self,
        ])
        let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
        let cm = ContactManager(
            modelContainer: container, security: Manager.Security(modelContainer: container, keyManager: TestKeyManager()),
            pairKeys: SoftwareCardKeys()
        )
        let peer = TestKeyManager()
        let profile = Contact.Profile(
            identifier: "b", givenName: "", familyName: "", middleName: "", nickname: "", organizationName: "",
            departmentName: "", jobTitle: ""
        )
        let key = Contact.Profile.Key(
            material: try Manager.Crypto().encrypt(data: try peer.retrieveIdentity()), owner: Data(), date: Data(),
            quantumKeyMaterialEncrypted: nil
        )
        try cm.store(.empty, in: key)
        profile.contactPublicKeys = [key]
        try cm.insertProfile(profile)
        try cm.record(IdentityChallenge.OutstandingChallenge(nonce: Data(repeating: 9, count: 32), issuedAt: UInt64(Date().timeIntervalSince1970)), for: "b", now: Date())

        let draft = try #require(Contact.Draft.Key(material: try peer.retrieveIdentity(), owner: Data(repeating: 1, count: 65), date: "2"))
        try cm.update(key: draft, for: "b")

        #expect(cm.challenge(for: "b") != nil, "its fingerprint is the identity key's, which a re-pair does not change")
    }
}

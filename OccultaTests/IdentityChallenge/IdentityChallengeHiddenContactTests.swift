//
//  IdentityChallengeHiddenContactTests.swift
//  OccultaTests
//
//  Settles whether approving an identity challenge from a contact hidden at the current duress
//  depth still signs and seals a response to them. Bug 40's guard (`passSecurityControl`) was
//  removed in `b1f9045` under the 2026-08-13 presence-oracle decision, which covers *rendering*
//  the sender's name; neither `fetchContact(by:)` nor `encryptBundle` checks visibility.
//
//  `approvePending` gates on `LAContext` (Face ID / passcode), which a test cannot satisfy, so this
//  runs what it runs after that gate: `fetchContact(by:)`, then `Manager.respond(to:)` sealing
//  through `ContactManager.encryptBundle`. The inbound half goes through the coordinator itself.
//
//  Runs under `.ambientTestKeyManager`: no Secure Enclave needed.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta
@testable import OccultaFormats

@MainActor
private struct DuressFixture {
    let contactManager: ContactManager
    let security:       Manager.Security
    let alice:          Contact.Profile
    let aliceKeys:      TestKeyManager
}

/// A device in Secure Mode, sitting at duress depth 1 (entered by the duress PIN), holding Alice
/// as a contact classified real-only: hidden at depth 1. A pending batch of ours waits for her, so
/// nothing here needs an Enclave.
@MainActor
private func makeDuressDevice() throws -> DuressFixture {
    let schema = Schema([
        AppLayerConfig.self,
        Group.self,
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    let security  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
    let contacts  = ContactManager(modelContainer: container, security: security)

    let aliceKeys = TestKeyManager()
    let profile   = Contact.Profile(
        identifier: "alice", givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.contactPublicKeys = [Contact.Profile.Key(
        material: try Manager.Crypto().encrypt(data: try aliceKeys.retrieveIdentity()), owner: Data(), date: Data(),
        quantumKeyMaterialEncrypted: nil
    )]
    profile.maxBundleVersion = try Manager.Crypto().encrypt(
        data: Data([try #require(OccultaBundle.Version.bodyDigestCapable.wireByte)])
    )
    profile.visibleThroughDepth = try DepthCodec.encode(0).encrypt()

    var record = PrekeyRecord.empty
    record.ownBatches = [PrekeyRecord.OwnBatch(
        id: Data((0..<16).map { _ in .random(in: .min ... .max) }), createdAt: Date(), retiredAt: nil, isPending: true,
        keys: [PrekeyRecord.OwnKey(id: withUnsafeBytes(of: UUID().uuid) { Data($0) }, blob: nil,
                                   publicKey: try TestKeyManager().retrieveIdentity())]
    )]
    profile.prekeyRecordEncrypted = try PrekeyRecordCodec().encode(record).encrypt()
    try contacts.insertProfile(profile)

    try security.configurePIN("123456")
    try security.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
    security.applyVerifyState(for: try security.verify("999999"))

    return DuressFixture(contactManager: contacts, security: security, alice: profile, aliceKeys: aliceKeys)
}

@Suite("Identity challenge — contact hidden at the current duress depth")
@MainActor struct IdentityChallengeHiddenContactTests {

    /// Precondition for the rest: the device really is at depth 1 and Alice really is hidden there.
    @Test("Fixture: depth 1, Alice hidden", .ambientTestKeyManager)
    func fixtureIsHiddenAtDepth1() throws {
        let fixture = try makeDuressDevice()
        #expect(fixture.security.currentDepth == 1)
        #expect(fixture.security.isRestricted)
        #expect(fixture.alice.isVisible(atDepth: 1) == false)
    }

    /// The lead: a challenge from the hidden contact reaches the approval sheet, and approving it
    /// produces a sealed response that verifies on her phone.
    @Test("A challenge from a contact hidden at depth 1 is answered with a sealed, valid response",
          .ambientTestKeyManager)
    func hiddenContactChallengeIsAnswered() throws {
        let fixture = try makeDuressDevice()
        let ourPublicKey = try Manager.Ambient.keyManager.retrieveIdentity()

        // Alice challenges us, in group format.
        let alicesManager = IdentityChallenge.Manager(
            crypto: Manager.Crypto(keyManager: fixture.aliceKeys), ledger: IdentityChallenge.OutstandingChallengeStore()
        )
        let challenge = try alicesManager.createChallenge(contactID: "us") { envelope in
            try Manager.Crypto(keyManager: fixture.aliceKeys).seal(
                sealedPayload: OccultaBundle.SealedPayload(
                    message: Data(IdentityChallenge.challengeFallbackMessage.utf8), identityChallenge: envelope, appVersion: "2.0.0"
                ),
                groupID: UUID(),
                recipients: [GroupRecipient(
                    publicKey: ourPublicKey, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil,
                    prefixesEphemeralSignature: true
                )]
            )
        }

        // Inbound, as `OccultaApp.buildOwnedBasket` runs it: no visibility check on the way in.
        let authenticated = try #require(try fixture.contactManager.openGroup(bundle: challenge, ownerID: "alice").challenge)
        let coordinator = IdentityChallenge.Coordinator(ledger: fixture.contactManager, sealer: fixture.contactManager)
        coordinator.handleAuthenticatedChallenge(authenticated, sender: fixture.alice)
        let pending = try #require(coordinator.incomingChallenge?.pending,
                                   "a challenge from a contact hidden at depth 1 should not reach the approval sheet")

        // Approval, past the biometric gate: `approvePending`'s own body.
        let challenger = try #require(try fixture.contactManager.fetchContact(by: pending.challengerID),
                                      "fetchContact(by:) must not hide a contact hidden at the current depth")
        #expect(challenger.isVisible(atDepth: fixture.security.currentDepth) == false)

        let ours = IdentityChallenge.Manager(crypto: Manager.Crypto(), ledger: IdentityChallenge.OutstandingChallengeStore())
        let answer = try OccultaBundle.decoded(from: try ours.respond(to: pending) { envelope in
            try fixture.contactManager.encryptBundle(for: pending.challengerID, identityChallenge: envelope)
        })
        #expect(answer.group != nil)

        // Alice's phone opens it and the signature passes: a valid "this is the owner" attestation
        // reached a contact the current depth hides.
        let aliceCrypto = Manager.Crypto(keyManager: fixture.aliceKeys)
        let (slot, _, _) = try aliceCrypto.findAndOpenRecipientSlot(
            in: answer, blind: try #require(answer.group).blind, senderContactID: "us",
            senderPublicKey: ourPublicKey, quantumMaterial: nil, prekeys: Manager.PrekeySecretsManager()
        )
        let sealed = try WireHandle.decode(payload: try aliceCrypto.openGroupCiphertext(answer, using: SymmetricKey(data: slot.sessionKey)))
        #expect(try alicesManager.verifyResponse(
            envelope: try #require(sealed.identityChallenge), senderKey: ourPublicKey, senderID: "us"
        ) == .passed(contextNote: nil))
    }
}

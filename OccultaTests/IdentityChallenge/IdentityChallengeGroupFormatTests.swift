//
//  IdentityChallengeGroupFormatTests.swift
//  OccultaTests
//
//  Prekey continuity stage 3 (§3.4): identity challenges and responses in group format, to contacts at
//  `.bodyDigestCapable`. `ContactManager.openGroup` authenticates them and hands them over as
//  `IdentityChallenge.Authenticated`, which the coordinator trusts without reopening the bundle with the long-term
//  key. On a forward-secret slot that needs the sender's signature in the prefixed form, whatever tier is recorded.
//
//  The long-term slot tests run anywhere. The forward-secret ones need a prekey this device holds, an Enclave blob,
//  so they're gated on a Secure Enclave, as `PrekeyReplenishmentTriggerTests` is.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta
@testable import OccultaFormats

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

@MainActor
private func makeContactManager() throws -> ContactManager {
    let schema = Schema([
        Group.self,
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    let security  = try Manager.Security(modelContainer: container, keyManager: TestKeyManager())
    return ContactManager(modelContainer: container, security: security)
}

/// Alice as a contact on this device, with `marker` as her recorded tier. With `pendingBatch`, a batch of ours waits
/// for her, so a long-term bundle from her generates no new one, which would need an Enclave.
@MainActor
@discardableResult
private func insertAlice(
    _ alice: TestKeyManager, marker: Data? = nil, pendingBatch: Bool = true, in contactManager: ContactManager
) throws -> Contact.Profile {
    let profile = Contact.Profile(
        identifier: "alice", givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.contactPublicKeys = [Contact.Profile.Key(
        material: try #require(try Manager.Crypto().encrypt(data: try alice.retrieveIdentity())), owner: Data(), date: Data(),
        quantumKeyMaterialEncrypted: nil
    )]
    profile.maxBundleVersion = marker
    if pendingBatch {
        var record = PrekeyRecord.empty
        record.ownBatches = [PrekeyRecord.OwnBatch(
            id: Data((0..<16).map { _ in .random(in: .min ... .max) }), createdAt: Date(), retiredAt: nil, isPending: true,
            keys: [PrekeyRecord.OwnKey(id: withUnsafeBytes(of: UUID().uuid) { Data($0) }, blob: nil,
                                       publicKey: try TestKeyManager().retrieveIdentity())]
        )]
        profile.prekeyRecordEncrypted = try PrekeyRecordCodec().encode(record).encrypt()
    }
    try contactManager.insertProfile(profile)
    return profile
}

/// A challenge from Alice, as her `Manager.createChallenge` builds one, now.
private func challengeFrom(_ alice: TestKeyManager) throws -> IdentityChallengeEnvelope {
    let nonce = Data((0..<IdentityChallenge.nonceLength).map { _ in UInt8.random(in: .min ... .max) })
    let payload = IdentityChallenge.ChallengePayload(
        nonce:                 nonce,
        timestamp:             IdentityChallenge.encodeTimestamp(UInt64(Date().timeIntervalSince1970)),
        challengerFingerprint: OccultaBundle.SecrecyContext.fingerprint(for: try alice.retrieveIdentity(), nonce: nonce)
    )
    return .challenge(payload: payload.encoded(), contextNote: "Was this you?")
}

/// `envelope` in a one-recipient group bundle from Alice to `recipient`: long-term with no `prekey`.
private func groupBundle(
    _ envelope: IdentityChallengeEnvelope, from alice: TestKeyManager, to recipient: Data,
    prekey: Prekey? = nil, prefixesSignature: Bool = true
) throws -> OccultaBundle {
    try Manager.Crypto(keyManager: alice).seal(
        sealedPayload: OccultaBundle.SealedPayload(
            message: Data(IdentityChallenge.challengeFallbackMessage.utf8), identityChallenge: envelope, appVersion: "2.0.0"
        ),
        groupID: UUID(),
        recipients: [GroupRecipient(
            publicKey: recipient, quantumMaterial: nil, contactPrekey: prekey, pendingBatch: nil,
            prefixesEphemeralSignature: prefixesSignature
        )]
    )
}

@Suite("Identity challenge in group format — receiving (prekey continuity stage 3)")
@MainActor struct IdentityChallengeGroupReceiveTests {

    let alice = TestKeyManager()

    @Test("A group-format challenge on a long-term slot is authenticated by openGroup and reaches approval", .ambientTestKeyManager)
    func longTermChallengeReachesApproval() throws {
        let cm = try makeContactManager()
        let profile = try insertAlice(self.alice, in: cm)
        let envelope = try challengeFrom(self.alice)
        let bundle = try groupBundle(envelope, from: self.alice, to: try Manager.Ambient.keyManager.retrieveIdentity())

        let challenge = try #require(try cm.openGroup(bundle: bundle, ownerID: "alice").challenge)
        #expect(challenge.envelope == envelope)

        let coordinator = IdentityChallenge.Coordinator()
        coordinator.handleAuthenticatedChallenge(challenge, sender: profile)
        #expect(coordinator.incomingChallenge?.pending.challengerID == "alice")
        #expect(coordinator.incomingChallenge?.pending.contextNote == "Was this you?")
        #expect(coordinator.errorMessage == nil)
    }

    /// The checks after opening still run: a challenge that isn't bound to the sender's key is refused.
    @Test("An authenticated challenge whose inner fingerprint names someone else is refused", .ambientTestKeyManager)
    func innerFingerprintStillChecked() throws {
        let cm = try makeContactManager()
        let profile = try insertAlice(self.alice, in: cm)
        let bundle = try groupBundle(
            try challengeFrom(TestKeyManager()), from: self.alice, to: try Manager.Ambient.keyManager.retrieveIdentity()
        )

        let challenge = try #require(try cm.openGroup(bundle: bundle, ownerID: "alice").challenge)
        let coordinator = IdentityChallenge.Coordinator()
        coordinator.handleAuthenticatedChallenge(challenge, sender: profile)
        #expect(coordinator.incomingChallenge == nil)
        #expect(coordinator.errorMessage != nil)
    }

    @Test("A message carries no authenticated challenge", .ambientTestKeyManager)
    func messageCarriesNone() throws {
        let cm = try makeContactManager()
        try insertAlice(self.alice, in: cm)
        let bundle = try Manager.Crypto(keyManager: self.alice).seal(
            sealedPayload: OccultaBundle.SealedPayload(message: Data("Lunch at one.".utf8)),
            groupID: UUID(),
            recipients: [GroupRecipient(
                publicKey: try Manager.Ambient.keyManager.retrieveIdentity(), quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil
            )]
        )

        #expect(try cm.openGroup(bundle: bundle, ownerID: "alice").challenge == nil)
    }

    @Test("decryptChallenge(envelope:) refuses a response envelope, and verifyResponse(envelope:) a challenge")
    func kindsAreChecked() throws {
        let manager = IdentityChallenge.Manager(
            crypto: Manager.Crypto(keyManager: TestKeyManager()), store: IdentityChallenge.OutstandingChallengeStore()
        )
        let alicePublicKey = try self.alice.retrieveIdentity()

        #expect(throws: IdentityChallenge.ManagerError.malformedBundle) {
            try manager.decryptChallenge(
                envelope: .response(payload: Data(count: 40)), senderKey: alicePublicKey, senderQuantum: nil,
                senderID: "alice", senderName: "Alice"
            )
        }
        #expect(throws: IdentityChallenge.ManagerError.malformedBundle) {
            try manager.verifyResponse(envelope: try challengeFrom(self.alice), senderKey: alicePublicKey, senderID: "alice")
        }
    }
}

// MARK: - Forward-secret slots

/// This device holding a batch of its own prekeys for Alice, as after her long-term message arrives.
@MainActor
private struct ForwardSecretFixture {
    let cm: ContactManager
    let profile: Contact.Profile
    let selfPublicKey: Data

    init(alice: TestKeyManager, marker: Data?) throws {
        self.cm = try makeContactManager()
        self.profile = try insertAlice(alice, marker: marker, pendingBatch: false, in: self.cm)
        self.selfPublicKey = try Manager.Key().retrieveIdentity()
        let prekeys = try self.cm.senderPrekeys(for: self.profile)
        try self.cm.installFreshBatch(into: prekeys)
        try self.cm.store(prekeys.record, for: self.profile)
    }

    /// One of the keys in our pending batch, as Alice holds it.
    func prekey(_ index: Int) throws -> Prekey {
        let batch = try #require(PrekeyBookkeeper().pendingBatch(
            in: try self.cm.prekeyRecord(for: self.profile), publicKeyOfBlob: Manager.PrekeySecretsManager.publicKey(ofBlob:)
        ))
        let wire = batch.prekeys[index]
        return Prekey(id: wire.id, contactID: "alice", publicKey: wire.publicKey)
    }
}

@Suite("Identity challenge in group format — forward-secret slots (prekey continuity stage 3)")
@MainActor struct IdentityChallengeGroupForwardSecretTests {

    let alice = TestKeyManager()

    @Test("A challenge on a forward-secret slot, signed in the prefixed form, is authenticated",
          .enabled(if: secureEnclaveAvailable()))
    func prefixedSignatureAccepted() throws {
        let f = try ForwardSecretFixture(alice: self.alice, marker: nil)
        let envelope = try challengeFrom(self.alice)
        let bundle = try groupBundle(envelope, from: self.alice, to: f.selfPublicKey, prekey: try f.prekey(0))

        #expect(try f.cm.openGroup(bundle: bundle, ownerID: "alice").challenge?.envelope == envelope)
    }

    /// The bare form is what a 1.10.0/1.10.1 sender signs, and no sender of a group-format challenge is one. With no
    /// tier recorded, the gate for messages lets an unsigned or bare-signed slot through; a challenge it doesn't.
    @Test("A challenge on a forward-secret slot signed in the bare form is refused, even with no tier recorded",
          .enabled(if: secureEnclaveAvailable()))
    func bareSignatureRefused() throws {
        let f = try ForwardSecretFixture(alice: self.alice, marker: nil)
        // Both read before either is used: using one delivers the batch, which drops its public keys.
        let (first, second) = (try f.prekey(0), try f.prekey(1))
        let challengeBundle = try groupBundle(
            try challengeFrom(self.alice), from: self.alice, to: f.selfPublicKey, prekey: first, prefixesSignature: false
        )

        #expect(throws: GroupDecryptError.missingSenderEphemeralSignature) {
            try f.cm.openGroup(bundle: challengeBundle, ownerID: "alice")
        }

        // Control: the same slot form around a message opens.
        let message = try Manager.Crypto(keyManager: self.alice).seal(
            sealedPayload: OccultaBundle.SealedPayload(message: Data("Lunch at one.".utf8)),
            groupID: UUID(),
            recipients: [GroupRecipient(
                publicKey: f.selfPublicKey, quantumMaterial: nil, contactPrekey: second, pendingBatch: nil,
                prefixesEphemeralSignature: false
            )]
        )
        #expect(try f.cm.openGroup(bundle: message, ownerID: "alice").sealed.message == Data("Lunch at one.".utf8))
    }

    /// `decryptSealed`'s forward-secret bundles carry no sender binding, so the one-to-one path keeps reopening a
    /// challenge with the long-term key, which a forward-secret bundle never opens with.
    @Test("A challenge in a one-to-one forward-secret bundle is refused", .enabled(if: secureEnclaveAvailable()))
    func oneToOneForwardSecretRefused() throws {
        let f = try ForwardSecretFixture(alice: self.alice, marker: nil)
        let envelope = try challengeFrom(self.alice)
        let bundle = try Manager.Crypto(keyManager: self.alice).seal(
            message: try WireHandle.encode(payload: OccultaBundle.SealedPayload(
                message: Data(IdentityChallenge.challengeFallbackMessage.utf8), identityChallenge: envelope
            )),
            contactPrekey: try f.prekey(0), recipientMaterial: f.selfPublicKey, quantumMaterial: nil, version: .v4
        )

        let (sealed, ownerID) = try f.cm.decryptSealed(bundle: bundle)
        #expect(ownerID == "alice")
        let coordinator = IdentityChallenge.Coordinator()
        coordinator.handleInboundChallenge(bundle: bundle, envelope: try #require(sealed.identityChallenge), sender: f.profile)
        #expect(coordinator.incomingChallenge == nil)
        #expect(coordinator.errorMessage != nil)
    }
}

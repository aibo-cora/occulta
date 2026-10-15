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

        let coordinator = IdentityChallenge.Coordinator(contactManager: cm)
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
        let coordinator = IdentityChallenge.Coordinator(contactManager: cm)
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
        let coordinator = IdentityChallenge.Coordinator(contactManager: f.cm)
        coordinator.handleInboundChallenge(bundle: bundle, envelope: try #require(sealed.identityChallenge), sender: f.profile)
        #expect(coordinator.incomingChallenge == nil)
        #expect(coordinator.errorMessage != nil)
    }
}

// MARK: - Sending

/// Alice's tier as recorded on our phone.
@MainActor
private func marker(_ tier: OccultaBundle.Version) throws -> Data {
    let byte = try #require(tier.wireByte)
    return try #require(try Manager.Crypto().encrypt(data: Data([byte])))
}

/// Alice's last-resort private half as a software key: she'd hold an Enclave blob, but these tests run without an
/// Enclave. Found as her receive path finds it, by the prekey ID derived from it.
private struct SoftwareLastResort: PrekeyPrivateKeys {
    let keyID = UUID().uuidString
    let privateKey: SecKey
    let publicKey: Data

    init() throws {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        let key = try #require(SecKeyCreateRandomKey(attributes as CFDictionary, &error))
        let publicKey = try #require(SecKeyCopyPublicKey(key))
        self.privateKey = key
        self.publicKey  = try #require(SecKeyCopyExternalRepresentation(publicKey, &error) as Data?)
    }

    func privateKey(forPrekeyID prekeyID: String, contactID: String) -> PrekeyPrivateKey? { nil }
    func consume(prekeyID: String, contactID: String) {}
    func lastResortKey(forPrekeyID prekeyID: String, ephemeralPublicKey: Data) -> (keyID: String, key: PrekeyPrivateKey)? {
        OccultaBundle.SecrecyContext.lastResortPrekeyID(keyID: self.keyID, ephemeralPublicKey: ephemeralPublicKey) == prekeyID
            ? (self.keyID, .keychain(self.privateKey))
            : nil
    }
}

@Suite("Identity challenge in group format — sending (prekey continuity stage 3)")
@MainActor struct IdentityChallengeGroupSendTests {

    let alice = TestKeyManager()

    /// What Alice's phone does with a group bundle from us: opens her slot and the body.
    private func openOnAlicesPhone(
        _ bundle: OccultaBundle, prekeys: PrekeyPrivateKeys = Manager.PrekeySecretsManager()
    ) throws -> (slot: OccultaBundle.RecipientPayload, used: InboundPrekeyUse, sealed: OccultaBundle.SealedPayload) {
        let crypto = Manager.Crypto(keyManager: self.alice)
        let (slot, used, _) = try crypto.findAndOpenRecipientSlot(
            in: bundle, blind: try #require(bundle.group).blind, senderContactID: "us",
            senderPublicKey: try Manager.Ambient.keyManager.retrieveIdentity(), quantumMaterial: nil, prekeys: prekeys
        )
        let sealed = try WireHandle.decode(payload: try crypto.openGroupCiphertext(bundle, using: SymmetricKey(data: slot.sessionKey)))
        return (slot, used, sealed)
    }

    @Test("A challenge to a contact at the tier goes as a message, and her group-format answer passes once",
          .ambientTestKeyManager)
    func endToEnd() throws {
        let cm = try makeContactManager()
        let profile = try insertAlice(self.alice, marker: try marker(.bodyDigestCapable), in: cm)
        let coordinator = IdentityChallenge.Coordinator(contactManager: cm)

        try coordinator.createChallenge(for: profile, contextNote: "Was this you?")
        let file = try #require(coordinator.outboundShare?.url)
        defer { try? FileManager.default.removeItem(at: file) }
        let challengeBundle = try OccultaBundle.decoded(from: try Data(contentsOf: file))
        #expect(challengeBundle.group != nil, "group format, like a message")

        // Alice's phone. She holds none of our keys, so the challenge is on the long-term slot, and our pending
        // batch rides with it, as with any message.
        let opened = try self.openOnAlicesPhone(challengeBundle)
        #expect(opened.used == .longTerm)
        #expect(opened.slot.prekeyBatch != nil)
        #expect(opened.slot.bodyDigest != nil)
        #expect(opened.sealed.shardOperations == nil && opened.sealed.custodyManifest == nil)
        let ourPublicKey = try Manager.Ambient.keyManager.retrieveIdentity()
        let alicesManager = IdentityChallenge.Manager(
            crypto: Manager.Crypto(keyManager: self.alice), store: IdentityChallenge.OutstandingChallengeStore()
        )
        let pending = try alicesManager.decryptChallenge(
            envelope: try #require(opened.sealed.identityChallenge), senderKey: ourPublicKey, senderQuantum: nil,
            senderID: "us", senderName: "Us"
        )
        #expect(pending.contextNote == "Was this you?")
        let response = try alicesManager.respond(to: pending) { envelope in
            try groupBundle(envelope, from: self.alice, to: ourPublicKey)
        }

        // Ours.
        coordinator.handleAuthenticatedChallenge(
            try #require(try cm.openGroup(bundle: response, ownerID: "alice").challenge), sender: profile
        )
        #expect(coordinator.verificationOutcome?.passed == true)
        #expect(coordinator.verificationOutcome?.contextNote == "Was this you?")

        // A long-term slot opens again; reopened, the answer names nothing waiting (Bug 166).
        coordinator.verificationOutcome = nil
        coordinator.handleAuthenticatedChallenge(
            try #require(try cm.openGroup(bundle: response, ownerID: "alice").challenge), sender: profile
        )
        #expect(coordinator.verificationOutcome == nil)
    }

    @Test("Our answer to a contact at the tier goes as a message, and passes on her phone", .ambientTestKeyManager)
    func answerGoesAsMessage() throws {
        let cm = try makeContactManager()
        try insertAlice(self.alice, marker: try marker(.bodyDigestCapable), in: cm)
        let ourPublicKey = try Manager.Ambient.keyManager.retrieveIdentity()

        // Alice challenges us, in group format.
        let alicesManager = IdentityChallenge.Manager(
            crypto: Manager.Crypto(keyManager: self.alice), store: IdentityChallenge.OutstandingChallengeStore()
        )
        let challenge = try alicesManager.createChallenge(contactID: "us") { envelope in
            try groupBundle(envelope, from: self.alice, to: ourPublicKey)
        }
        let authenticated = try #require(try cm.openGroup(bundle: challenge, ownerID: "alice").challenge)

        // We approve and answer, as `approvePending` does after Face ID.
        let ours = IdentityChallenge.Manager(crypto: Manager.Crypto(), store: IdentityChallenge.OutstandingChallengeStore())
        let pending = try ours.decryptChallenge(
            envelope: authenticated.envelope, senderKey: try self.alice.retrieveIdentity(), senderQuantum: nil,
            senderID: "alice", senderName: "Alice"
        )
        let answer = try OccultaBundle.decoded(from: try ours.respond(to: pending) { envelope in
            try cm.encryptBundle(for: "alice", identityChallenge: envelope)
        })
        #expect(answer.group != nil)

        let opened = try self.openOnAlicesPhone(answer)
        #expect(try alicesManager.verifyResponse(
            envelope: try #require(opened.sealed.identityChallenge), senderKey: ourPublicKey, senderID: "us"
        ) == .passed(contextNote: nil))
    }

    @Test("Out of one-time keys, a challenge goes to the contact's last-resort key", .ambientTestKeyManager)
    func lastResort() throws {
        let cm = try makeContactManager()
        let profile = try insertAlice(self.alice, marker: try marker(.bodyDigestCapable), pendingBatch: false, in: cm)
        let alicesLastResort = try SoftwareLastResort()
        var record = PrekeyRecord.empty
        record.inboundLastResort = PrekeyRecord.InboundKey(id: alicesLastResort.keyID, publicKey: alicesLastResort.publicKey)
        try cm.store(record, for: profile)
        let coordinator = IdentityChallenge.Coordinator(contactManager: cm)

        try coordinator.createChallenge(for: profile, contextNote: nil)
        let file = try #require(coordinator.outboundShare?.url)
        defer { try? FileManager.default.removeItem(at: file) }

        let opened = try self.openOnAlicesPhone(try OccultaBundle.decoded(from: try Data(contentsOf: file)), prekeys: alicesLastResort)
        #expect(opened.used == .lastResort(keyID: alicesLastResort.keyID))
        #expect(opened.sealed.identityChallenge?.kind == .challenge)
    }

    @Test("A challenge to a contact below the tier keeps the long-term format", .ambientTestKeyManager)
    func belowTierKeepsLongTerm() throws {
        let cm = try makeContactManager()
        let profile = try insertAlice(self.alice, marker: try marker(.prefixedSenderSignatureCapable), in: cm)
        let coordinator = IdentityChallenge.Coordinator(contactManager: cm)

        try coordinator.createChallenge(for: profile, contextNote: nil)
        let file = try #require(coordinator.outboundShare?.url)
        defer { try? FileManager.default.removeItem(at: file) }
        let bundle = try OccultaBundle.decoded(from: try Data(contentsOf: file))

        #expect(bundle.group == nil)
        #expect(bundle.secrecy.mode == .longTermFallback)
    }

    /// Our record of a contact's version can lag behind their update; their build still reads both formats.
    @Test("A long-term challenge from a contact recorded at the tier is still accepted", .ambientTestKeyManager)
    func longTermFromContactAtTier() throws {
        let cm = try makeContactManager()
        let profile = try insertAlice(self.alice, marker: try marker(.bodyDigestCapable), in: cm)
        let alicesManager = IdentityChallenge.Manager(
            crypto: Manager.Crypto(keyManager: self.alice), store: IdentityChallenge.OutstandingChallengeStore()
        )
        let bundle = try alicesManager.createChallenge(
            recipientKey: try Manager.Ambient.keyManager.retrieveIdentity(), recipientQuantum: nil, contactID: "us"
        )

        let coordinator = IdentityChallenge.Coordinator(contactManager: cm)
        coordinator.handleInboundChallenge(bundle: bundle, envelope: .challenge(payload: Data(), contextNote: nil), sender: profile)
        #expect(coordinator.incomingChallenge?.pending.challengerID == "alice")
    }

    @Test("encryptBundle sends a challenge alone, and only to a contact at the tier", .ambientTestKeyManager)
    func encryptBundleRefusals() throws {
        let cm = try makeContactManager()
        let profile = try insertAlice(self.alice, marker: try marker(.bodyDigestCapable), in: cm)
        let envelope = try challengeFrom(TestKeyManager())

        #expect(throws: ContactManager.Errors.identityChallengeNotAlone) {
            try cm.encryptBundle(for: "alice", custodyManifest: [UUID()], identityChallenge: envelope)
        }
        #expect(throws: ContactManager.Errors.identityChallengeNotAlone) {
            try cm.encryptBundle(basket: Basket(files: []), for: "alice", identityChallenge: envelope)
        }

        // Below the tier, refused before any of her keys is taken.
        profile.maxBundleVersion = try marker(.prefixedSenderSignatureCapable)
        var record = try cm.prekeyRecord(for: profile)
        record.inboundBatches = [.init(id: nil, keys: [.init(id: UUID().uuidString, publicKey: try TestKeyManager().retrieveIdentity())])]
        try cm.store(record, for: profile)
        #expect(throws: ContactManager.Errors.identityChallengeBelowTier) {
            try cm.encryptBundle(for: "alice", identityChallenge: envelope)
        }
        #expect(try cm.prekeyRecord(for: profile).inboundBatches.first?.keys.count == 1)
    }
}

// MARK: - Bug 155

@Suite("Identity challenge — a long-term one from an older contact makes no batch (Bug 155)")
@MainActor struct IdentityChallengeMakesNoBatchTests {

    /// Without the fix this generates 15 Enclave keys; with it, nothing touches the Enclave, so it runs anywhere.
    @Test("A long-term challenge and response from a contact with no batch of ours pending create none",
          .ambientTestKeyManager, arguments: [IdentityChallengeEnvelope.Kind.challenge, .response])
    func noBatch(kind: IdentityChallengeEnvelope.Kind) throws {
        let alice = TestKeyManager()
        let cm = try makeContactManager()
        let profile = try insertAlice(alice, pendingBatch: false, in: cm)
        let envelope: IdentityChallengeEnvelope = kind == .challenge
            ? try challengeFrom(alice)
            : .response(payload: Data(count: 100))
        let bundle = try Manager.Crypto(keyManager: alice).seal(
            message: try WireHandle.encode(payload: OccultaBundle.SealedPayload(
                message: Data(IdentityChallenge.challengeFallbackMessage.utf8), identityChallenge: envelope
            )),
            contactPrekey: nil, recipientMaterial: try Manager.Ambient.keyManager.retrieveIdentity(), quantumMaterial: nil,
            version: .v4
        )

        let (sealed, _) = try cm.decryptSealed(bundle: bundle)

        #expect(sealed.identityChallenge?.kind == kind)
        #expect(!PrekeyBookkeeper().hasPendingBatch(try cm.prekeyRecord(for: profile)))
    }
}

//
//  PairingRoutingTests.swift
//  OccultaTests
//
//  Bug 196, stage 5: a file of the pairing-secret form from seal to open. Its slot is found by routing tag and opens only with
//  the secret mixed into its key; its sender proof is in the slot and covers the routing tag; two records that share one
//  identity key and hold different secrets each see only their own pairing's files; an old-form file is refused by a
//  pairing that began with a secret and accepted by one that didn't.
//
//  The receiver is the ambient test key manager; the sender is a `TestKeyManager` of its own. No Enclave: the files are
//  sealed long-term, which is the case this fix is for.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta
@testable import OccultaFormats

// MARK: - Helpers

@MainActor
private func makeContactManager() throws -> ContactManager {
    let schema = Schema([
        Group.self, Contact.Profile.self, Contact.Profile.PhoneNumber.self, Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self, Contact.Profile.Key.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    let security  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
    return ContactManager(modelContainer: container, security: security)
}

private func secret(_ byte: UInt8) -> Data { Data(repeating: byte, count: 32) }

/// `publicKey` as a contact on this device holding `state` for the pairing. A pending batch of ours stands waiting for
/// them, so a long-term file from them generates no new one, which would need an Enclave.
@MainActor
@discardableResult
private func insertSender(
    identifier: String = UUID().uuidString, publicKey: Data, state: PairingSecretState, in cm: ContactManager
) throws -> Contact.Profile {
    let profile = Contact.Profile(
        identifier: identifier, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    let key = Contact.Profile.Key(
        material: try Manager.Crypto().encrypt(data: publicKey), owner: Data(), date: Data(), quantumKeyMaterialEncrypted: nil
    )
    try cm.store(state, in: key)
    profile.contactPublicKeys = [key]
    var record = PrekeyRecord.empty
    record.ownBatches = [PrekeyRecord.OwnBatch(
        id: Data((0..<16).map { _ in .random(in: .min ... .max) }), createdAt: Date(), retiredAt: nil, isPending: true,
        keys: [PrekeyRecord.OwnKey(id: withUnsafeBytes(of: UUID().uuid) { Data($0) }, blob: nil, publicKey: Data(repeating: 4, count: 65))]
    )]
    profile.prekeyRecordEncrypted = try PrekeyRecordCodec().encode(record).encrypt()
    try cm.insertProfile(profile)
    return profile
}

private func payload(_ text: String = "hello") -> OccultaBundle.SealedPayload {
    OccultaBundle.SealedPayload(message: Data(text.utf8), appVersion: "2.0.1")
}

/// A file sealed long-term from `sender` to `recipients`, each with their own pairing secret or none.
@MainActor
private func seal(
    from sender: TestKeyManager, to recipients: [(publicKey: Data, secret: Data?)]
) throws -> OccultaBundle {
    try Manager.Crypto(keyManager: sender).seal(
        sealedPayload: payload(), groupID: UUID(),
        recipients: recipients.map {
            GroupRecipient(publicKey: $0.publicKey, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil, pairingSecret: $0.secret)
        }
    )
}

// MARK: - A file of the new form

@MainActor
@Suite("Bug 196 — a pairing-secret file from seal to open", .serialized)
struct PairingRoutingTests {

    private let sender = TestKeyManager()

    @Test("It opens for the pairing that holds the secret, in .longTermNoPQ mode", .ambientTestKeyManager)
    func opensForItsPairing() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let contact = try insertSender(publicKey: try self.sender.retrieveIdentity(), state: .derived(secret: secret(1)), in: cm)

        let bundle = try seal(from: self.sender, to: [(me, secret(1))])
        let opened = try cm.openGroup(bundle: bundle)

        #expect(opened.ownerID == contact.identifier)
        #expect(bundle.group?.recipients.first?.secrecyContext.mode == .longTermNoPQ)
        #expect(opened.sealed.message == Data("hello".utf8))
    }

    @Test("The file names its sender to nobody who lacks the secret: no identity fingerprint in the header", .ambientTestKeyManager)
    func headerCarriesNoFingerprint() throws {
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()
        let bundle = try seal(from: self.sender, to: [(me, secret(1))])

        #expect(bundle.senderFingerprint.count == 32)
        #expect(bundle.senderFingerprint != OccultaBundle.SecrecyContext.fingerprint(for: senderKey, nonce: bundle.fingerprintNonce))
    }

    @Test("A file with no secret still carries the identity fingerprint, as before", .ambientTestKeyManager)
    func oldFormKeepsFingerprint() throws {
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()
        let bundle = try seal(from: self.sender, to: [(me, nil)])

        #expect(bundle.senderFingerprint == OccultaBundle.SecrecyContext.fingerprint(for: senderKey, nonce: bundle.fingerprintNonce))
    }

    @Test("The slot's routing tag is the HMAC of the file's nonce under the secret", .ambientTestKeyManager)
    func tagIsTheHMAC() throws {
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let bundle = try seal(from: self.sender, to: [(me, secret(1))])
        let tag = try #require(bundle.group?.recipients.first?.routingTag)

        #expect(tag == PairingSecret.routingTag(secret: secret(1), nonce: bundle.fingerprintNonce))
    }

    // MARK: Two pairings, one identity key

    @Test("Two records with one identity key each see only their own pairing's files", .ambientTestKeyManager)
    func twinRecordsAreSeparate() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()
        let hidden = try insertSender(publicKey: senderKey, state: .derived(secret: secret(1)), in: cm)
        let decoy  = try insertSender(publicKey: senderKey, state: .derived(secret: secret(2)), in: cm)

        let fromHidden = try seal(from: self.sender, to: [(me, secret(1))])
        let fromDecoy  = try seal(from: self.sender, to: [(me, secret(2))])

        #expect(try cm.identifyOwner(of: fromHidden) == hidden.identifier)
        #expect(try cm.identifyOwner(of: fromDecoy) == decoy.identifier)

        // The other record, asked to open it, finds no slot of its pairing.
        #expect(throws: GroupDecryptError.recipientSlotNotFound) {
            try cm.openGroup(bundle: fromHidden, ownerID: decoy.identifier)
        }
        #expect(throws: GroupDecryptError.recipientSlotNotFound) {
            try cm.openGroup(bundle: fromDecoy, ownerID: hidden.identifier)
        }
        #expect(try cm.openGroup(bundle: fromHidden, ownerID: hidden.identifier).ownerID == hidden.identifier)
    }

    @Test("The secret is in the key: a record with the wrong secret can't open the slot even when told which one", .ambientTestKeyManager)
    func wrongSecretCannotOpen() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let other = try insertSender(publicKey: try self.sender.retrieveIdentity(), state: .derived(secret: secret(9)), in: cm)

        let bundle = try seal(from: self.sender, to: [(me, secret(1))])

        #expect(throws: GroupDecryptError.recipientSlotNotFound) { try cm.openGroup(bundle: bundle, ownerID: other.identifier) }
    }

    // MARK: Old form

    @Test("A pairing that began with a secret refuses an old-form file from the same identity", .ambientTestKeyManager)
    func refusesOldForm() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let contact = try insertSender(publicKey: try self.sender.retrieveIdentity(), state: .derived(secret: secret(1)), in: cm)

        let oldForm = try seal(from: self.sender, to: [(me, nil)])

        #expect(throws: ContactManager.Errors.self) { try cm.identifyOwner(of: oldForm) }
        #expect(throws: GroupDecryptError.recipientSlotNotFound) { try cm.openGroup(bundle: oldForm, ownerID: contact.identifier) }
    }

    @Test("A pairing without a secret opens an old-form file as before", .ambientTestKeyManager)
    func acceptsOldFormWithoutSecret() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let contact = try insertSender(publicKey: try self.sender.retrieveIdentity(), state: .empty, in: cm)

        let oldForm = try seal(from: self.sender, to: [(me, nil)])

        #expect(try cm.identifyOwner(of: oldForm) == contact.identifier)
        #expect(try cm.openGroup(bundle: oldForm).ownerID == contact.identifier)
    }

    @Test("A swapped pairing keeps accepting old form while it holds the secret (the split rule)", .ambientTestKeyManager)
    func swappedPairingAcceptsOldForm() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let swapped = PairingSecretState(phase: .held(secret: secret(3), peerConfirmed: true), refusesOldForm: false)
        let contact = try insertSender(publicKey: try self.sender.retrieveIdentity(), state: swapped, in: cm)

        #expect(try cm.openGroup(bundle: try seal(from: self.sender, to: [(me, nil)])).ownerID == contact.identifier)
        #expect(try cm.openGroup(bundle: try seal(from: self.sender, to: [(me, secret(3))])).ownerID == contact.identifier)
    }

    // MARK: The sender proof

    @Test("The sender proof moved into the slot: the shared one is random filler, the slot's verifies", .ambientTestKeyManager)
    func proofIsInTheSlot() throws {
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()
        let bundle = try seal(from: self.sender, to: [(me, secret(1))])
        let tag = try #require(bundle.group?.recipients.first?.routingTag)

        // Open the slot the way the receiver would, to read its proof.
        let cm = try makeContactManager()
        try insertSender(publicKey: senderKey, state: .derived(secret: secret(1)), in: cm)
        let opened = try cm.openGroup(bundle: bundle)
        #expect(opened.sealed.senderProof?.count == 32)
        #expect(opened.sealed.senderProof != Data(HMAC<SHA256>.authenticationCode(for: senderKey, using: SymmetricKey(data: Data(count: 32)))))
        #expect(PairingSecret.isValidSlotProof(
            PairingSecret.slotProof(secret: secret(1), routingTag: tag, senderPublicKey: senderKey),
            secret: secret(1), routingTag: tag, senderPublicKey: senderKey
        ))
    }

    @Test("A slot whose proof covers another routing tag is refused", .ambientTestKeyManager)
    func proofOverAnotherTagFails() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()
        try insertSender(publicKey: senderKey, state: .derived(secret: secret(1)), in: cm)

        // A file whose slot carries a proof made over some other routing tag.
        let bundle = try sealWithProof(
            from: self.sender, to: me, secret: secret(1),
            proof: PairingSecret.slotProof(secret: secret(1), routingTag: Data(repeating: 0xEE, count: 32), senderPublicKey: senderKey)
        )

        #expect(throws: GroupDecryptError.senderProofMismatch) { try cm.openGroup(bundle: bundle) }
    }

    @Test("A slot with no proof in the new form is refused", .ambientTestKeyManager)
    func missingProofFails() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        try insertSender(publicKey: try self.sender.retrieveIdentity(), state: .derived(secret: secret(1)), in: cm)

        let bundle = try sealWithProof(from: self.sender, to: me, secret: secret(1), proof: nil)

        #expect(throws: GroupDecryptError.senderProofMismatch) { try cm.openGroup(bundle: bundle) }
    }

    // MARK: Groups

    @Test("A group file gives each member a routing tag only their own secret computes", .ambientTestKeyManager)
    func groupTagsAreSeparate() throws {
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let other = try TestKeyManager().retrieveIdentity()
        let bundle = try seal(from: self.sender, to: [(me, secret(1)), (other, secret(2))])
        let tags = try #require(bundle.group?.recipients.map(\.routingTag))

        #expect(tags[0] == PairingSecret.routingTag(secret: secret(1), nonce: bundle.fingerprintNonce))
        #expect(tags[1] == PairingSecret.routingTag(secret: secret(2), nonce: bundle.fingerprintNonce))
        #expect(tags[0] != tags[1])
        // A member holding the other secret computes the other routing tag, never ours.
        #expect(PairingSecret.routingTag(secret: secret(2), nonce: bundle.fingerprintNonce) != tags[0])
    }

    @Test("A group member opens their own slot and not another's", .ambientTestKeyManager)
    func memberOpensOwnSlot() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let other = try TestKeyManager().retrieveIdentity()
        let contact = try insertSender(publicKey: try self.sender.retrieveIdentity(), state: .derived(secret: secret(1)), in: cm)

        // Our slot is second; the first is another member's.
        let bundle = try seal(from: self.sender, to: [(other, secret(2)), (me, secret(1))])

        #expect(try cm.openGroup(bundle: bundle).ownerID == contact.identifier)
    }

    @Test("One recipient on the old form keeps the identity fingerprint for the whole file", .ambientTestKeyManager)
    func mixedGroupKeepsFingerprint() throws {
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let other = try TestKeyManager().retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()
        let bundle = try seal(from: self.sender, to: [(me, secret(1)), (other, nil)])

        #expect(bundle.senderFingerprint == OccultaBundle.SecrecyContext.fingerprint(for: senderKey, nonce: bundle.fingerprintNonce))
    }

    @Test("Every slot carries a routing tag, a swap field and a slot proof, whether or not it has a secret", .ambientTestKeyManager)
    func slotsAreUniform() throws {
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let other = try TestKeyManager().retrieveIdentity()
        let bundle = try seal(from: self.sender, to: [(me, secret(1)), (other, nil)])
        let recipients = try #require(bundle.group?.recipients)

        #expect(recipients.allSatisfy { $0.routingTag?.count == 32 })
        // A filler routing tag belongs to no secret.
        #expect(recipients[1].routingTag != PairingSecret.routingTag(secret: secret(1), nonce: bundle.fingerprintNonce))
    }

    // MARK: Identity challenges

    /// A challenge from `sender`, as `Manager.createChallenge` builds one, now.
    private func challenge(from sender: TestKeyManager) throws -> IdentityChallengeEnvelope {
        let nonce = Data((0..<IdentityChallenge.nonceLength).map { _ in UInt8.random(in: .min ... .max) })
        let payload = IdentityChallenge.ChallengePayload(
            nonce: nonce, timestamp: IdentityChallenge.encodeTimestamp(UInt64(Date().timeIntervalSince1970)),
            challengerFingerprint: OccultaBundle.SecrecyContext.fingerprint(for: try sender.retrieveIdentity(), nonce: nonce)
        )
        return .challenge(payload: payload.encoded(), contextNote: "Was this you?")
    }

    @Test("A challenge on a pairing with a secret is routed by tag, on the long-term slot, and reaches the coordinator authenticated",
          .ambientTestKeyManager)
    func challengeIsRoutedByTag() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()
        let hidden = try insertSender(publicKey: senderKey, state: .derived(secret: secret(1)), in: cm)
        let decoy  = try insertSender(publicKey: senderKey, state: .derived(secret: secret(2)), in: cm)

        let bundle = try Manager.Crypto(keyManager: self.sender).seal(
            sealedPayload: OccultaBundle.SealedPayload(
                message: Data("challenge".utf8), identityChallenge: try self.challenge(from: self.sender), appVersion: "2.0.1"
            ),
            groupID: UUID(),
            recipients: [GroupRecipient(publicKey: me, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil, pairingSecret: secret(1))]
        )

        #expect(bundle.group?.recipients.first?.secrecyContext.mode == .longTermNoPQ, "the slot a coercer can make us use")
        #expect(bundle.senderFingerprint != OccultaBundle.SecrecyContext.fingerprint(for: senderKey, nonce: bundle.fingerprintNonce))
        #expect(try cm.identifyOwner(of: bundle) == hidden.identifier)
        #expect(try cm.openGroup(bundle: bundle).challenge != nil)
        #expect(throws: GroupDecryptError.recipientSlotNotFound) { try cm.openGroup(bundle: bundle, ownerID: decoy.identifier) }
    }

    // MARK: Gating

    @Test("Only a held, confirmed secret at the tier is sent with", .ambientTestKeyManager)
    func sendingGate() throws {
        let cm = try makeContactManager()
        let key = try TestKeyManager().retrieveIdentity()
        let confirmed = try insertSender(publicKey: key, state: .derived(secret: secret(1)), in: cm)
        let unconfirmed = try insertSender(
            publicKey: key, state: PairingSecretState(phase: .held(secret: secret(2), peerConfirmed: false), refusesOldForm: false), in: cm
        )
        let none = try insertSender(publicKey: key, state: .empty, in: cm)

        #expect(cm.pairingSecretForSending(to: confirmed, tier: .pairingSecretCapable) == secret(1))
        #expect(cm.pairingSecretForSending(to: confirmed, tier: .streamedBodyCapable) == nil, "a peer below the tier gets the old form")
        #expect(cm.pairingSecretForSending(to: unconfirmed, tier: .pairingSecretCapable) == nil)
        #expect(cm.pairingSecretForSending(to: none, tier: .pairingSecretCapable) == nil)
    }
}

// MARK: - A hand-made file

/// A one-recipient file of the new form with the slot proof given, which the real seal always gets right.
@MainActor
private func sealWithProof(
    from sender: TestKeyManager, to recipientPublicKey: Data, secret: Data, proof: Data?
) throws -> OccultaBundle {
    let groupID    = UUID()
    let contentKey = SymmetricKey(size: .bits256)
    let blindNonce = try OccultaBundle.SecrecyContext.generateNonce()
    let blind      = Data(HMAC<SHA256>.authenticationCode(
        for: blindNonce, using: SymmetricKey(data: withUnsafeBytes(of: groupID.uuid) { Data($0) })
    ))
    let outerSecrecy = OccultaBundle.SecrecyContext(mode: .group, ephemeralPublicKey: Data(), prekeyID: nil)
    let outerNonce = try OccultaBundle.SecrecyContext.generateNonce()
    var aad = try OccultaBundle.computeAdditionalAuthentication(version: .v4, secrecy: outerSecrecy)
    aad.append(blind)
    let sealedBody = try WireHandle.encode(payload: OccultaBundle.SealedPayload(
        // No `appVersion`: a body claiming 2.0.0 or later without a digest is refused for that before the proof is read.
        message: Data("hello".utf8), appVersion: nil, senderProof: try PairingSecret.fillerTag(), groupID: groupID
    ))

    let (derived, context) = try Manager.Crypto(keyManager: sender).deriveOutboundKey(
        contactPrekey: nil, recipientPublicKey: recipientPublicKey, quantumMaterial: nil
    )
    let wrappingKey = PairingSecret.bind(derived, secret: secret)
    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    let slot = try encoder.encode(OccultaBundle.RecipientPayload(
        sessionKey: contentKey.withUnsafeBytes { Data($0) }, senderEphemeralSignature: Data(count: 72),
        pairingSwap: try PairingSecretSwap.filler(), slotProof: proof
    ))
    return OccultaBundle(
        version: .v4, secrecy: outerSecrecy,
        ciphertext: try #require(try AES.GCM.seal(sealedBody, using: contentKey, authenticating: aad).combined),
        fingerprintNonce: outerNonce, senderFingerprint: try PairingSecret.fillerTag(),
        group: OccultaBundle.GroupEnvelope(blind: blind, blindNonce: blindNonce, recipients: [OccultaBundle.Recipient(
            secrecyContext: context,
            wrappedPayload: try #require(try AES.GCM.seal(slot, using: wrappingKey, authenticating: blind).combined),
            routingTag: PairingSecret.routingTag(secret: secret, nonce: outerNonce)
        )])
    )
}

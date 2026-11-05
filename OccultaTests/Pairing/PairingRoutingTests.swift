//
//  PairingRoutingTests.swift
//  OccultaTests
//
//  Bug 196, stage 5: a file of the pairing form from seal to open. Its slot is found by routing tag and opens only with
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
    identifier: String = UUID().uuidString, publicKey: Data, state: PairingState, in cm: ContactManager
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

/// A file sealed long-term from `sender` to `recipients`, each with their own routing key or none.
@MainActor
private func seal(
    from sender: TestKeyManager, to recipients: [(publicKey: Data, secret: Data?)]
) throws -> OccultaBundle {
    try Manager.Crypto(keyManager: sender).seal(
        sealedPayload: payload(), groupID: UUID(),
        recipients: recipients.map {
            GroupRecipient(publicKey: $0.publicKey, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil, routingKey: $0.secret)
        }
    )
}

// MARK: - A file of the new form

@MainActor
@Suite("Bug 196 — a pairing file from seal to open", .serialized)
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

        #expect(tag == RoutingKey.routingTag(routingKey: secret(1), nonce: bundle.fingerprintNonce))
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

    // MARK: The legacy raw trial decrypt

    /// A file in the oldest form: the sender's identity ECDH key AES-GCM sealed the bytes with no bundle around them.
    private func legacyFile(to me: Data) throws -> Data {
        try #require(try Manager.Crypto(keyManager: self.sender).encrypt(message: Data("legacy".utf8), using: me))
    }

    @Test("A raw legacy file does not open on a pairing that refuses the old form", .ambientTestKeyManager)
    func legacyFileRefusedByRoutingKeyPairing() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        try insertSender(publicKey: try self.sender.retrieveIdentity(), state: .derived(secret: secret(1)), in: cm)

        #expect(throws: ContactManager.Errors.self) { try cm.decrypt(data: try self.legacyFile(to: me)) }
    }

    @Test("A raw legacy file opens on the twin record that has no routing key, not on the one that has", .ambientTestKeyManager)
    func legacyFileReachesTheTwinWithoutOne() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()
        try insertSender(publicKey: senderKey, state: .derived(secret: secret(1)), in: cm)
        let twin = try insertSender(publicKey: senderKey, state: .empty, in: cm)

        let opened = try cm.decrypt(data: try self.legacyFile(to: me))
        #expect(opened.ownerID == twin.identifier)
        #expect(opened.plaintext == Data("legacy".utf8))
    }

    @Test("A raw legacy file opens on a pairing without a routing key, as before", .ambientTestKeyManager)
    func legacyFileOpensWithoutRoutingKey() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let contact = try insertSender(publicKey: try self.sender.retrieveIdentity(), state: .empty, in: cm)

        #expect(try cm.decrypt(data: try self.legacyFile(to: me)).ownerID == contact.identifier)
    }

    // MARK: The current key

    @Test("A re-pair retires every earlier row, so exactly one is current and it is the new one", .ambientTestKeyManager)
    func rePairLeavesOneCurrentKey() throws {
        let cm = try makeContactManager()
        let identity = try self.sender.retrieveIdentity()
        let contact = try insertSender(publicKey: identity, state: .derived(secret: secret(1)), in: cm)

        let draft = try #require(Contact.Draft.Key(material: identity, owner: Data(repeating: 1, count: 65), date: "2", routingKey: secret(2)))
        try cm.update(key: draft, for: contact.identifier)

        let rows = try #require(contact.contactPublicKeys)
        #expect(rows.count == 2)
        #expect(rows.filter { $0.expiredOn == nil }.count == 1)
        #expect(cm.pairingState(for: contact) == .derived(secret: secret(2)))
        #expect(contact.currentKey?.acquiredAt == rows.first { $0.expiredOn == nil }?.acquiredAt)
        #expect(contact.displayedKey != nil)
    }

    // MARK: Depth

    @Test("A contact hidden at the current depth routes and opens exactly as a visible one does (no depth oracle)", .ambientTestKeyManager)
    func hiddenContactRoutesLikeAVisibleOne() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()

        let visible = try insertSender(publicKey: senderKey, state: .derived(secret: secret(1)), in: cm)
        let hidden  = try insertSender(publicKey: senderKey, state: .derived(secret: secret(2)), in: cm)
        hidden.visibleThroughDepth = try DepthCodec.encode(0).encrypt()
        try cm.modelContext.save()

        // At depth 1 one is shown and the other is not.
        #expect(visible.isVisible(atDepth: 1))
        #expect(hidden.isVisible(atDepth: 1) == false)

        // A file for either routes to its own record and opens, whatever the depth: a hidden contact's file is not refused
        // (`Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md`). Only what is shown differs, later.
        let forVisible = try seal(from: self.sender, to: [(me, secret(1))])
        let forHidden  = try seal(from: self.sender, to: [(me, secret(2))])

        #expect(try cm.identifyOwner(of: forVisible) == visible.identifier)
        #expect(try cm.identifyOwner(of: forHidden) == hidden.identifier)
        #expect(try cm.openGroup(bundle: forVisible).ownerID == visible.identifier)
        #expect(try cm.openGroup(bundle: forHidden).ownerID == hidden.identifier)
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
        #expect(RoutingKey.isValidSlotProof(
            RoutingKey.slotProof(routingKey: secret(1), routingTag: tag, senderPublicKey: senderKey),
            routingKey: secret(1), routingTag: tag, senderPublicKey: senderKey
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
            proof: RoutingKey.slotProof(routingKey: secret(1), routingTag: Data(repeating: 0xEE, count: 32), senderPublicKey: senderKey)
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

        #expect(tags[0] == RoutingKey.routingTag(routingKey: secret(1), nonce: bundle.fingerprintNonce))
        #expect(tags[1] == RoutingKey.routingTag(routingKey: secret(2), nonce: bundle.fingerprintNonce))
        #expect(tags[0] != tags[1])
        // A member holding the other secret computes the other routing tag, never ours.
        #expect(RoutingKey.routingTag(routingKey: secret(2), nonce: bundle.fingerprintNonce) != tags[0])
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

    @Test("Every slot carries a routing tag and a slot proof, whether or not it has a secret", .ambientTestKeyManager)
    func slotsAreUniform() throws {
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let other = try TestKeyManager().retrieveIdentity()
        let bundle = try seal(from: self.sender, to: [(me, secret(1)), (other, nil)])
        let recipients = try #require(bundle.group?.recipients)

        #expect(recipients.allSatisfy { $0.routingTag?.count == 32 })
        // A filler routing tag belongs to no secret.
        #expect(recipients[1].routingTag != RoutingKey.routingTag(routingKey: secret(1), nonce: bundle.fingerprintNonce))
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
            recipients: [GroupRecipient(publicKey: me, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil, routingKey: secret(1))]
        )

        #expect(bundle.group?.recipients.first?.secrecyContext.mode == .longTermNoPQ, "the slot a coercer can make us use")
        #expect(bundle.senderFingerprint != OccultaBundle.SecrecyContext.fingerprint(for: senderKey, nonce: bundle.fingerprintNonce))
        #expect(try cm.identifyOwner(of: bundle) == hidden.identifier)
        #expect(try cm.openGroup(bundle: bundle).challenge != nil)
        #expect(throws: GroupDecryptError.recipientSlotNotFound) { try cm.openGroup(bundle: bundle, ownerID: decoy.identifier) }
    }

    // MARK: Gating

    @Test("Only a held secret at the tier is sent with", .ambientTestKeyManager)
    func sendingGate() throws {
        let cm = try makeContactManager()
        let key = try TestKeyManager().retrieveIdentity()
        let held = try insertSender(publicKey: key, state: .derived(secret: secret(1)), in: cm)
        let none = try insertSender(publicKey: key, state: .empty, in: cm)

        #expect(cm.routingKeyForSending(to: held, tier: .pairingCapable) == secret(1))
        #expect(cm.routingKeyForSending(to: held, tier: .streamedBodyCapable) == nil, "a peer below the tier gets the old form")
        #expect(cm.routingKeyForSending(to: none, tier: .pairingCapable) == nil)
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
        message: Data("hello".utf8), appVersion: nil, senderProof: try RoutingKey.fillerTag(), groupID: groupID
    ))

    let (derived, context) = try Manager.Crypto(keyManager: sender).deriveOutboundKey(
        contactPrekey: nil, recipientPublicKey: recipientPublicKey, quantumMaterial: nil
    )
    let wrappingKey = RoutingKey.bind(derived, routingKey: secret)
    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    let slot = try encoder.encode(OccultaBundle.RecipientPayload(
        sessionKey: contentKey.withUnsafeBytes { Data($0) }, senderEphemeralSignature: Data(count: 72),
        slotProof: proof
    ))
    return OccultaBundle(
        version: .v4, secrecy: outerSecrecy,
        ciphertext: try #require(try AES.GCM.seal(sealedBody, using: contentKey, authenticating: aad).combined),
        fingerprintNonce: outerNonce, senderFingerprint: try RoutingKey.fillerTag(),
        group: OccultaBundle.GroupEnvelope(blind: blind, blindNonce: blindNonce, recipients: [OccultaBundle.Recipient(
            secrecyContext: context,
            wrappedPayload: try #require(try AES.GCM.seal(slot, using: wrappingKey, authenticating: blind).combined),
            routingTag: RoutingKey.routingTag(routingKey: secret, nonce: outerNonce)
        )])
    )
}

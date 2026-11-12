//
//  PairingRoutingTests.swift
//  OccultaTests
//
//  Bug 196, stage 5: a file of the pairing form from seal to open. Its slot is found by routing tag and opens only with
//  the routing key mixed into its key; its sender proof is in the slot and covers the routing tag; two records that share one
//  identity key and hold different pairings each see only their own pairing's files; an old-form file is refused by a
//  pair-key pairing and accepted by one that has none. `PairwiseRoutingTests` is the same from the pair keys' side.
//
//  The receiver is the ambient test key manager; the sender is a `TestKeyManager` of its own. The pair keys are software
//  keys behind `SoftwareCardKeys`, so no Enclave: the files are sealed long-term, which is the case this fix is for.
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
    return ContactManager(modelContainer: container, security: security, pairKeys: SoftwareCardKeys())
}

private func secret(_ byte: UInt8) -> Data { Data(repeating: byte, count: 32) }

/// One pairing between the sender and this device: the routing key, and each side's mirrored pair keys.
private struct Pairing {
    let routingKey: Data
    private let keys: MirroredPairKeys

    init(_ byte: UInt8) throws {
        self.routingKey = secret(byte)
        self.keys = try MirroredPairKeys()
    }

    /// What this device holds for the sender, with these pair keys and `routingKey` (the pairing's own by default).
    func state(routingKey: Data? = nil) -> PairingState { .paired(routingKey: routingKey ?? self.routingKey, keys: self.keys.b) }
    var state: PairingState { self.state() }

    /// What the sender seals a slot to this device with.
    var slot: PairingSlotKeys { PairingSlotKeys(routingKey: self.routingKey, keys: self.keys.a, provider: SoftwareCardKeys()) }
}

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

/// A file sealed long-term from `sender` to `recipients`, each with the pairing's slot keys or none (the old form).
@MainActor
private func seal(
    from sender: TestKeyManager, to recipients: [(publicKey: Data, pairing: PairingSlotKeys?)]
) throws -> OccultaBundle {
    try Manager.Crypto(keyManager: sender).seal(
        sealedPayload: payload(), groupID: UUID(),
        recipients: recipients.map {
            GroupRecipient(publicKey: $0.publicKey, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil, pairing: $0.pairing)
        }
    )
}

// MARK: - A file of the new form

@MainActor
@Suite("Bug 196 — a pairing file from seal to open", .serialized)
struct PairingRoutingTests {

    private let sender = TestKeyManager()

    @Test("The file names its sender to nobody who lacks the routing key: no identity fingerprint in the header", .ambientTestKeyManager)
    func headerCarriesNoFingerprint() throws {
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()
        let bundle = try seal(from: self.sender, to: [(me, try Pairing(1).slot)])

        #expect(bundle.senderFingerprint.count == 32)
        #expect(bundle.senderFingerprint != OccultaBundle.SecrecyContext.fingerprint(for: senderKey, nonce: bundle.fingerprintNonce))
    }

    @Test("A file with no pair keys still carries the identity fingerprint, as before", .ambientTestKeyManager)
    func oldFormKeepsFingerprint() throws {
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()
        let bundle = try seal(from: self.sender, to: [(me, nil)])

        #expect(bundle.senderFingerprint == OccultaBundle.SecrecyContext.fingerprint(for: senderKey, nonce: bundle.fingerprintNonce))
    }

    @Test("The slot's routing tag is the HMAC of the file's nonce under the routing key", .ambientTestKeyManager)
    func tagIsTheHMAC() throws {
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let bundle = try seal(from: self.sender, to: [(me, try Pairing(1).slot)])
        let tag = try #require(bundle.group?.recipients.first?.routingTag)

        #expect(tag == RoutingKey.routingTag(routingKey: secret(1), nonce: bundle.fingerprintNonce))
    }

    // MARK: Two pairings, one identity key

    @Test("Two records with one identity key each see only their own pairing's files", .ambientTestKeyManager)
    func twinRecordsAreSeparate() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()
        let one = try Pairing(1), two = try Pairing(2)
        let hidden = try insertSender(publicKey: senderKey, state: one.state, in: cm)
        let decoy  = try insertSender(publicKey: senderKey, state: two.state, in: cm)

        let fromHidden = try seal(from: self.sender, to: [(me, one.slot)])
        let fromDecoy  = try seal(from: self.sender, to: [(me, two.slot)])

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

    @Test("A record with the same pair keys and another routing key finds no slot", .ambientTestKeyManager)
    func wrongRoutingKeyCannotOpen() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let sent = try Pairing(1)
        let other = try insertSender(publicKey: try self.sender.retrieveIdentity(), state: sent.state(routingKey: secret(9)), in: cm)

        let bundle = try seal(from: self.sender, to: [(me, sent.slot)])

        #expect(throws: GroupDecryptError.recipientSlotNotFound) { try cm.openGroup(bundle: bundle, ownerID: other.identifier) }
    }

    // MARK: Old form

    @Test("A pairing without pair keys opens an old-form file as before", .ambientTestKeyManager)
    func acceptsOldFormWithoutPairKeys() throws {
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
        let key = try #require(self.sender.createSharedSecret(using: me))
        return try #require(try AES.GCM.seal(Data("legacy".utf8), using: key, nonce: AES.GCM.Nonce()).combined)
    }

    @Test("A raw legacy file does not open on a pair-key pairing", .ambientTestKeyManager)
    func legacyFileRefusedByPairKeyPairing() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        try insertSender(publicKey: try self.sender.retrieveIdentity(), state: try Pairing(1).state, in: cm)

        #expect(throws: ContactManager.Errors.self) { try cm.decrypt(data: try self.legacyFile(to: me)) }
    }

    @Test("A raw legacy file opens on the twin record that has no pair keys, not on the one that has", .ambientTestKeyManager)
    func legacyFileReachesTheTwinWithoutOne() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()
        try insertSender(publicKey: senderKey, state: try Pairing(1).state, in: cm)
        let twin = try insertSender(publicKey: senderKey, state: .empty, in: cm)

        let opened = try cm.decrypt(data: try self.legacyFile(to: me))
        #expect(opened.ownerID == twin.identifier)
        #expect(opened.plaintext == Data("legacy".utf8))
    }

    @Test("A raw legacy file opens on a pairing without pair keys, as before", .ambientTestKeyManager)
    func legacyFileOpensWithoutPairKeys() throws {
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
        let contact = try insertSender(publicKey: identity, state: try Pairing(1).state, in: cm)
        let second = try Pairing(2)

        let draft = try #require(Contact.Draft.Key(material: identity, owner: Data(repeating: 1, count: 65), date: "2", pairing: second.state))
        try cm.update(key: draft, for: contact.identifier)

        let rows = try #require(contact.contactPublicKeys)
        #expect(rows.count == 2)
        #expect(rows.filter { $0.expiredOn == nil }.count == 1)
        #expect(cm.pairingState(for: contact) == second.state)
        #expect(contact.currentKey?.acquiredAt == rows.first { $0.expiredOn == nil }?.acquiredAt)
        #expect(contact.displayedKey != nil)
    }

    // MARK: The sender proof

    @Test("The sender proof moved into the slot: the shared one is random filler, the slot's verifies", .ambientTestKeyManager)
    func proofIsInTheSlot() throws {
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()
        let pairing = try Pairing(1)
        let bundle = try seal(from: self.sender, to: [(me, pairing.slot)])
        let tag = try #require(bundle.group?.recipients.first?.routingTag)

        // Open the slot the way the receiver would, to read its proof.
        let cm = try makeContactManager()
        try insertSender(publicKey: senderKey, state: pairing.state, in: cm)
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
        let pairing = try Pairing(1)
        try insertSender(publicKey: senderKey, state: pairing.state, in: cm)

        // A file whose slot carries a proof made over some other routing tag.
        let bundle = try sealWithProof(
            from: self.sender, to: me, routingKey: pairing.routingKey, pairing: pairing.slot,
            proof: { _ in RoutingKey.slotProof(routingKey: secret(1), routingTag: Data(repeating: 0xEE, count: 32), senderPublicKey: senderKey) }
        )

        #expect(throws: GroupDecryptError.senderProofMismatch) { try cm.openGroup(bundle: bundle) }
    }

    @Test("A slot with no proof in the new form is refused", .ambientTestKeyManager)
    func missingProofFails() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let pairing = try Pairing(1)
        try insertSender(publicKey: try self.sender.retrieveIdentity(), state: pairing.state, in: cm)

        let bundle = try sealWithProof(from: self.sender, to: me, routingKey: pairing.routingKey, pairing: pairing.slot, proof: { _ in nil })

        #expect(throws: GroupDecryptError.senderProofMismatch) { try cm.openGroup(bundle: bundle) }
    }

    @Test("A slot sealed with the identity key under the right tag and routing key opens nothing of a pair-key pairing", .ambientTestKeyManager)
    func identityKeySlotUnderTheRightTagIsRefused() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()
        let pairing = try Pairing(1)
        let contact = try insertSender(publicKey: senderKey, state: pairing.state, in: cm)

        // Someone who holds the routing key and the identity key, but not the pair keys, makes a slot a plain pairing would
        // open: the identity key's ECDH, bound to the routing key, with a proof that verifies. It carries the right tag.
        let bundle = try sealWithProof(
            from: self.sender, to: me, routingKey: pairing.routingKey, pairing: nil,
            proof: { RoutingKey.slotProof(routingKey: pairing.routingKey, routingTag: $0, senderPublicKey: senderKey) }
        )

        #expect(throws: GroupDecryptError.recipientSlotNotFound) { try cm.openGroup(bundle: bundle, ownerID: contact.identifier) }
    }

    // MARK: Groups

    @Test("A group file gives each member a routing tag only their own routing key computes", .ambientTestKeyManager)
    func groupTagsAreSeparate() throws {
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let other = try TestKeyManager().retrieveIdentity()
        let bundle = try seal(from: self.sender, to: [(me, try Pairing(1).slot), (other, try Pairing(2).slot)])
        let tags = try #require(bundle.group?.recipients.map(\.routingTag))

        #expect(tags[0] == RoutingKey.routingTag(routingKey: secret(1), nonce: bundle.fingerprintNonce))
        #expect(tags[1] == RoutingKey.routingTag(routingKey: secret(2), nonce: bundle.fingerprintNonce))
        #expect(tags[0] != tags[1])
        // A member holding the other routing key computes the other routing tag, never ours.
        #expect(RoutingKey.routingTag(routingKey: secret(2), nonce: bundle.fingerprintNonce) != tags[0])
    }

    @Test("A group member opens their own slot and not another's", .ambientTestKeyManager)
    func memberOpensOwnSlot() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let other = try TestKeyManager().retrieveIdentity()
        let mine = try Pairing(1)
        let contact = try insertSender(publicKey: try self.sender.retrieveIdentity(), state: mine.state, in: cm)

        // Our slot is second; the first is another member's.
        let bundle = try seal(from: self.sender, to: [(other, try Pairing(2).slot), (me, mine.slot)])

        #expect(try cm.openGroup(bundle: bundle).ownerID == contact.identifier)
    }

    @Test("One recipient on the old form keeps the identity fingerprint for the whole file", .ambientTestKeyManager)
    func mixedGroupKeepsFingerprint() throws {
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let other = try TestKeyManager().retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()
        let bundle = try seal(from: self.sender, to: [(me, try Pairing(1).slot), (other, nil)])

        #expect(bundle.senderFingerprint == OccultaBundle.SecrecyContext.fingerprint(for: senderKey, nonce: bundle.fingerprintNonce))
    }

    @Test("Every slot carries a routing tag and a slot proof, whether or not it has pair keys", .ambientTestKeyManager)
    func slotsAreUniform() throws {
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let other = try TestKeyManager().retrieveIdentity()
        let bundle = try seal(from: self.sender, to: [(me, try Pairing(1).slot), (other, nil)])
        let recipients = try #require(bundle.group?.recipients)

        #expect(recipients.allSatisfy { $0.routingTag?.count == 32 })
        // A filler routing tag belongs to no routing key.
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

    @Test("A challenge on a pair-key pairing is routed by tag, on the long-term slot, and reaches the coordinator authenticated",
          .ambientTestKeyManager)
    func challengeIsRoutedByTag() throws {
        let cm = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()
        let one = try Pairing(1), two = try Pairing(2)
        let hidden = try insertSender(publicKey: senderKey, state: one.state, in: cm)
        let decoy  = try insertSender(publicKey: senderKey, state: two.state, in: cm)

        let bundle = try Manager.Crypto(keyManager: self.sender).seal(
            sealedPayload: OccultaBundle.SealedPayload(
                message: Data("challenge".utf8), identityChallenge: try self.challenge(from: self.sender), appVersion: "2.0.1"
            ),
            groupID: UUID(),
            recipients: [GroupRecipient(publicKey: me, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil, pairing: one.slot)]
        )

        #expect(bundle.group?.recipients.first?.secrecyContext.mode == .longTermNoPQ, "the slot a coercer can make us use")
        #expect(bundle.senderFingerprint != OccultaBundle.SecrecyContext.fingerprint(for: senderKey, nonce: bundle.fingerprintNonce))
        #expect(try cm.identifyOwner(of: bundle) == hidden.identifier)
        #expect(try cm.openGroup(bundle: bundle).challenge != nil)
        #expect(throws: GroupDecryptError.recipientSlotNotFound) { try cm.openGroup(bundle: bundle, ownerID: decoy.identifier) }
    }
}

// MARK: - A hand-made file

/// A one-recipient file of the new form with the slot proof given, which the real seal always gets right.
@MainActor
private func sealWithProof(
    from sender: TestKeyManager, to recipientPublicKey: Data, routingKey: Data, pairing: PairingSlotKeys?,
    proof: (_ routingTag: Data) -> Data?
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
        contactPrekey: nil, recipientPublicKey: recipientPublicKey, quantumMaterial: nil, pairing: pairing
    )
    let wrappingKey = RoutingKey.bind(derived, routingKey: routingKey)
    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    let routingTag = RoutingKey.routingTag(routingKey: routingKey, nonce: outerNonce)
    let slot = try encoder.encode(OccultaBundle.RecipientPayload(
        sessionKey: contentKey.withUnsafeBytes { Data($0) }, senderEphemeralSignature: Data(count: 72),
        slotProof: proof(routingTag)
    ))
    return OccultaBundle(
        version: .v4, secrecy: outerSecrecy,
        ciphertext: try #require(try AES.GCM.seal(sealedBody, using: contentKey, authenticating: aad).combined),
        fingerprintNonce: outerNonce, senderFingerprint: try RoutingKey.fillerTag(),
        group: OccultaBundle.GroupEnvelope(blind: blind, blindNonce: blindNonce, recipients: [OccultaBundle.Recipient(
            secrecyContext: context,
            wrappedPayload: try #require(try AES.GCM.seal(slot, using: wrappingKey, authenticating: blind).combined),
            routingTag: routingTag
        )])
    )
}

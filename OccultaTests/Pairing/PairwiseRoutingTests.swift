//
//  PairwiseRoutingTests.swift
//  OccultaTests
//
//  Bug 196, stage 2, send and receive: a file to a pair-key pairing from seal to open. Its long-term slot key comes from the
//  pair-key ECDH and the identity key is in none of it; it is found by routing tag and opens only with the routing key mixed
//  in; a file made the old way (the identity key, or no pair keys) opens nothing of such a pairing, and says no more about
//  it than an unknown sender would; a pairing whose Enclave blob won't import is undeliverable and never falls back to
//  the identity key.
//
//  The receiver is the ambient test key manager; the sender is a `TestKeyManager` of its own. Pair keys are software
//  CryptoKit keys behind `SoftwareCardKeys`, so none of this needs an Enclave. The forward-secret mode, which needs a real
//  prekey, is in `PairwiseConversationTests`.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta
@testable import OccultaFormats

// MARK: - Fixture

private func routingKey(_ byte: UInt8) -> Data { Data(repeating: byte, count: 32) }

/// Two phones' pair keys, mirrored (`MirroredPairKeys`), and the provider that opens them.
private struct PairKeyFixture {
    let provider = SoftwareCardKeys()
    let senderKeys: PairKeys
    let receiverKeys: PairKeys

    init() throws {
        let keys = try MirroredPairKeys()
        self.senderKeys = keys.a
        self.receiverKeys = keys.b
    }

    /// The sender's side of a slot to the receiver.
    func slot(for sender: TestKeyManager) -> PairingSlotKeys { PairingSlotKeys(keys: self.senderKeys, provider: self.provider) }
}

@MainActor
private func makeContactManager(provider: any CardKeyProviding) throws -> ContactManager {
    let schema = Schema([
        Group.self, Contact.Profile.self, Contact.Profile.PhoneNumber.self, Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self, Contact.Profile.Key.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    let security  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
    return ContactManager(modelContainer: container, security: security, pairKeys: provider)
}

private func quantum() -> (sender: QuantumKeyMaterial, receiver: QuantumKeyMaterial) {
    let s1 = Data(repeating: 0x31, count: 32), s2 = Data(repeating: 0x32, count: 32)
    let c1 = Data(repeating: 0x41, count: 16), c2 = Data(repeating: 0x42, count: 16)
    return (
        QuantumKeyMaterial(encapsulatedSecret: s1, decapsulatedSecret: s2, ourCiphertext: c1, peerCiphertext: c2),
        QuantumKeyMaterial(encapsulatedSecret: s2, decapsulatedSecret: s1, ourCiphertext: c2, peerCiphertext: c1)
    )
}

/// `publicKey` as a contact on this device holding `state` for the pairing. A pending batch of ours stands waiting for them,
/// so a long-term file from them generates no new one, which would need an Enclave.
@MainActor
@discardableResult
private func insertSender(
    identifier: String = UUID().uuidString, publicKey: Data, state: PairingState, quantum: QuantumKeyMaterial? = nil,
    tier: OccultaBundle.Version? = .pairingCapable, in cm: ContactManager
) throws -> Contact.Profile {
    let profile = Contact.Profile(
        identifier: identifier, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    let key = Contact.Profile.Key(
        material: try Manager.Crypto().encrypt(data: publicKey), owner: Data(), date: Data(),
        quantumKeyMaterialEncrypted: try quantum.flatMap { try Manager.Crypto().encrypt(data: try JSONEncoder().encode($0)) }
    )
    try cm.store(state, in: key)
    profile.contactPublicKeys = [key]
    if let byte = tier?.wireByte { profile.maxBundleVersion = try Manager.Crypto().encrypt(data: Data([byte])) }
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

private struct Recipient {
    let publicKey: Data
    let routingKey: Data?
    var pairing: PairingSlotKeys? = nil
    var quantum: QuantumKeyMaterial? = nil
}

@MainActor
private func seal(from sender: TestKeyManager, to recipients: [Recipient]) throws -> OccultaBundle {
    try Manager.Crypto(keyManager: sender).seal(
        sealedPayload: payload(), groupID: UUID(),
        recipients: recipients.map {
            GroupRecipient(
                publicKey: $0.publicKey, quantumMaterial: $0.quantum, contactPrekey: nil, pendingBatch: nil,
                routingKey: $0.routingKey, pairing: $0.pairing
            )
        }
    )
}

// MARK: - Suite

@MainActor
@Suite("Bug 196 — a pair-key file from seal to open", .serialized)
struct PairwiseRoutingTests {

    private let sender = TestKeyManager()

    // MARK: It opens

    @Test("It opens for its pairing in .longTermNoPQ, and the identity key is in neither the slot key nor the signature", .ambientTestKeyManager)
    func opensLongTermNoPQ() throws {
        let keys = try PairKeyFixture()
        let cm = try makeContactManager(provider: keys.provider)
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let contact = try insertSender(publicKey: try self.sender.retrieveIdentity(), state: .paired(routingKey: routingKey(1), keys: keys.receiverKeys), in: cm)

        let bundle = try seal(from: self.sender, to: [Recipient(publicKey: me, routingKey: routingKey(1), pairing: keys.slot(for: self.sender))])
        let opened = try cm.openGroup(bundle: bundle)

        #expect(opened.ownerID == contact.identifier)
        #expect(opened.sealed.message == Data("hello".utf8))
        #expect(bundle.group?.recipients.first?.secrecyContext.mode == .longTermNoPQ)
    }

    @Test("It opens in .longTermFallback, with the ML-KEM secrets in the slot key", .ambientTestKeyManager)
    func opensLongTermHybrid() throws {
        let keys = try PairKeyFixture()
        let cm = try makeContactManager(provider: keys.provider)
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let q = quantum()
        let contact = try insertSender(
            publicKey: try self.sender.retrieveIdentity(), state: .paired(routingKey: routingKey(1), keys: keys.receiverKeys),
            quantum: q.receiver, in: cm
        )

        let bundle = try seal(from: self.sender, to: [Recipient(publicKey: me, routingKey: routingKey(1), pairing: keys.slot(for: self.sender), quantum: q.sender)])

        #expect(bundle.group?.recipients.first?.secrecyContext.mode == .longTermFallback)
        #expect(try cm.openGroup(bundle: bundle).ownerID == contact.identifier)
    }

    // MARK: It does not open the old way

    @Test("A long-term slot made with the identity key, even with the right routing key, opens nothing of a pair-key pairing", .ambientTestKeyManager)
    func identityKeySlotIsRefused() throws {
        let keys = try PairKeyFixture()
        let cm = try makeContactManager(provider: keys.provider)
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let contact = try insertSender(publicKey: try self.sender.retrieveIdentity(), state: .paired(routingKey: routingKey(1), keys: keys.receiverKeys), in: cm)

        // The sender holds the routing key but seals as a plain pairing would: with the identity key.
        let bundle = try seal(from: self.sender, to: [Recipient(publicKey: me, routingKey: routingKey(1))])

        #expect(throws: GroupDecryptError.recipientSlotNotFound) { try cm.openGroup(bundle: bundle, ownerID: contact.identifier) }
    }

    @Test("A pair-key slot opens nothing of a pairing that holds a routing key but no pair keys", .ambientTestKeyManager)
    func pairKeySlotIsRefusedByAPlainRoutingKey() throws {
        let keys = try PairKeyFixture()
        let cm = try makeContactManager(provider: keys.provider)
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let contact = try insertSender(publicKey: try self.sender.retrieveIdentity(), state: .derived(secret: routingKey(1)), in: cm)

        let bundle = try seal(from: self.sender, to: [Recipient(publicKey: me, routingKey: routingKey(1), pairing: keys.slot(for: self.sender))])

        #expect(throws: GroupDecryptError.recipientSlotNotFound) { try cm.openGroup(bundle: bundle, ownerID: contact.identifier) }
    }

    @Test("An old-form file is refused by a pair-key pairing, whoever made it", .ambientTestKeyManager)
    func oldFormIsRefused() throws {
        let keys = try PairKeyFixture()
        let cm = try makeContactManager(provider: keys.provider)
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let contact = try insertSender(publicKey: try self.sender.retrieveIdentity(), state: .paired(routingKey: routingKey(1), keys: keys.receiverKeys), in: cm)

        let oldForm = try seal(from: self.sender, to: [Recipient(publicKey: me, routingKey: nil)])

        #expect(throws: ContactManager.Errors.self) { try cm.identifyOwner(of: oldForm) }
        #expect(throws: GroupDecryptError.recipientSlotNotFound) { try cm.openGroup(bundle: oldForm, ownerID: contact.identifier) }
    }

    @Test("Every refusal is the error an unknown slot gives, so it says no more than not being ours", .ambientTestKeyManager)
    func refusalsLookLikeNotOurs() throws {
        let keys = try PairKeyFixture()
        let cm = try makeContactManager(provider: keys.provider)
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let contact = try insertSender(publicKey: try self.sender.retrieveIdentity(), state: .paired(routingKey: routingKey(1), keys: keys.receiverKeys), in: cm)

        let wrongRoutingKey = try seal(from: self.sender, to: [Recipient(publicKey: me, routingKey: routingKey(9), pairing: keys.slot(for: self.sender))])
        let identityKey = try seal(from: self.sender, to: [Recipient(publicKey: me, routingKey: routingKey(1))])
        let oldForm = try seal(from: self.sender, to: [Recipient(publicKey: me, routingKey: nil)])
        for bundle in [wrongRoutingKey, identityKey, oldForm] {
            #expect(throws: GroupDecryptError.recipientSlotNotFound) { try cm.openGroup(bundle: bundle, ownerID: contact.identifier) }
        }
    }

    // MARK: Two records with one identity key

    @Test("Two records that share an identity key and hold different pair keys each see only their own pairing's files", .ambientTestKeyManager)
    func twinRecordsAreTold() throws {
        let one = try PairKeyFixture(), two = try PairKeyFixture()
        let cm = try makeContactManager(provider: SoftwareCardKeys())
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()
        let first = try insertSender(publicKey: senderKey, state: .paired(routingKey: routingKey(1), keys: one.receiverKeys), in: cm)
        let second = try insertSender(publicKey: senderKey, state: .paired(routingKey: routingKey(2), keys: two.receiverKeys), in: cm)
        let provider = SoftwareCardKeys()

        let toFirst = try seal(from: self.sender, to: [Recipient(publicKey: me, routingKey: routingKey(1), pairing: PairingSlotKeys(keys: one.senderKeys, provider: provider))])
        let toSecond = try seal(from: self.sender, to: [Recipient(publicKey: me, routingKey: routingKey(2), pairing: PairingSlotKeys(keys: two.senderKeys, provider: provider))])

        #expect(try cm.openGroup(bundle: toFirst).ownerID == first.identifier)
        #expect(try cm.openGroup(bundle: toSecond).ownerID == second.identifier)
        #expect(throws: GroupDecryptError.recipientSlotNotFound) { try cm.openGroup(bundle: toFirst, ownerID: second.identifier) }
    }

    @Test("A contact hidden at the current depth routes and opens exactly as a visible one does", .ambientTestKeyManager)
    func hiddenContactRoutesLikeAVisibleOne() throws {
        let keys = try PairKeyFixture()
        let cm = try makeContactManager(provider: keys.provider)
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let senderKey = try self.sender.retrieveIdentity()
        let hidden = try insertSender(publicKey: senderKey, state: .paired(routingKey: routingKey(1), keys: keys.receiverKeys), in: cm)
        hidden.visibleThroughDepth = try DepthCodec.encode(0).encrypt()
        let decoy = try insertSender(publicKey: senderKey, state: .empty, in: cm)
        // One level deeper than the contact is visible through: it really is hidden here.
        cm.security.applyVerifyState(for: .normal(depth: 1))
        #expect(!hidden.isVisible(atDepth: cm.security.currentDepth))

        let bundle = try seal(from: self.sender, to: [Recipient(publicKey: me, routingKey: routingKey(1), pairing: keys.slot(for: self.sender))])

        // Found by routing tag at every depth, hidden or not, and the decoy that holds the same identity key can't take it.
        #expect(try cm.openGroup(bundle: bundle).ownerID == hidden.identifier)
        #expect(throws: GroupDecryptError.recipientSlotNotFound) { try cm.openGroup(bundle: bundle, ownerID: decoy.identifier) }
    }

    // MARK: Sizes

    /// The slot's random fields (the signature filler of a long-term slot, a filler routing tag and proof) are base64, and
    /// Foundation writes `/` in base64 as `\/`, so two slots that hold the same fields differ by a few bytes by the slashes
    /// they happen to hold. That is true of every slot, pair-key or not. A slot that differed in what it carries would differ
    /// by tens of bytes, not by a handful, so the spread over many seals is what is pinned.
    @Test("A pair-key slot is the same size as an identity-key slot and a plain one, to within the noise random fields make", .ambientTestKeyManager)
    func slotLengthsMatch() throws {
        let keys = try PairKeyFixture()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let other = try TestKeyManager().retrieveIdentity()
        let third = try TestKeyManager().retrieveIdentity()

        for q in [nil, quantum().sender] as [QuantumKeyMaterial?] {
            var pairKey = [Int](), identityKey = [Int](), plain = [Int]()
            for _ in 0..<30 {
                let bundle = try seal(from: self.sender, to: [
                    Recipient(publicKey: me, routingKey: routingKey(1), pairing: keys.slot(for: self.sender), quantum: q),
                    Recipient(publicKey: other, routingKey: routingKey(2), quantum: q),
                    Recipient(publicKey: third, routingKey: nil, quantum: q),
                ])
                let lengths = try #require(bundle.group?.recipients).map(\.wrappedPayload.count)
                pairKey.append(lengths[0]); identityKey.append(lengths[1]); plain.append(lengths[2])
            }
            let all = pairKey + identityKey + plain
            #expect((all.max()! - all.min()!) <= 16, "slot lengths range \(all.min()!)...\(all.max()!)")
            // Neither kind is systematically larger: the same range, not shifted.
            let meanPair = Double(pairKey.reduce(0, +)) / 30, meanIdentity = Double(identityKey.reduce(0, +)) / 30
            #expect(abs(meanPair - meanIdentity) < 4, "means \(meanPair) and \(meanIdentity)")
        }
    }

    // MARK: A key that won't import

    @Test("A pair-key pairing whose blob won't import can't be opened, and is refused like any slot that isn't ours", .ambientTestKeyManager)
    func unimportableBlobOpensNothing() throws {
        let keys = try PairKeyFixture()
        let cm = try makeContactManager(provider: BrokenCardKeys())
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let contact = try insertSender(publicKey: try self.sender.retrieveIdentity(), state: .paired(routingKey: routingKey(1), keys: keys.receiverKeys), in: cm)

        let bundle = try seal(from: self.sender, to: [Recipient(publicKey: me, routingKey: routingKey(1), pairing: keys.slot(for: self.sender))])

        #expect(throws: GroupDecryptError.recipientSlotNotFound) { try cm.openGroup(bundle: bundle, ownerID: contact.identifier) }
    }

    @Test("Sealing to a pair-key pairing whose blob won't import fails, and never falls back to the identity key", .ambientTestKeyManager)
    func sealingWithAnUnimportableBlobFails() throws {
        let keys = try PairKeyFixture()
        let broken = PairingSlotKeys(keys: keys.senderKeys, provider: BrokenCardKeys())
        let me = try Manager.Ambient.keyManager.retrieveIdentity()

        #expect(throws: PairingSlotKeys.SlotKeyError.unavailable) {
            try seal(from: self.sender, to: [Recipient(publicKey: me, routingKey: routingKey(1), pairing: broken)])
        }
    }

    @Test("A pair-key slot without a routing key is refused rather than sealed", .ambientTestKeyManager)
    func pairKeysNeedARoutingKey() throws {
        let keys = try PairKeyFixture()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()

        #expect(throws: Manager.Crypto.EncryptionError.invalidRecipientMaterial) {
            try seal(from: self.sender, to: [Recipient(publicKey: me, routingKey: nil, pairing: keys.slot(for: self.sender))])
        }
    }

    // MARK: The send path

    @Test("A message to a pair-key contact whose stored tier is below the group format is refused, not sent with the identity key", .ambientTestKeyManager)
    func legacyFormIsRefused() throws {
        let keys = try PairKeyFixture()
        let cm = try makeContactManager(provider: keys.provider)
        let contact = try insertSender(
            publicKey: try self.sender.retrieveIdentity(), state: .paired(routingKey: routingKey(1), keys: keys.receiverKeys),
            tier: nil, in: cm
        )

        #expect(throws: ContactManager.Errors.noPublicKeyToEncryptWith) { try cm.encryptBundle(basket: Basket(files: []), for: contact.identifier) }
    }

    @Test("The routing key goes to a pair-key contact whatever tier is stored, and to a plain pairing only at the tier", .ambientTestKeyManager)
    func routingKeyForSendingRule() throws {
        let keys = try PairKeyFixture()
        let cm = try makeContactManager(provider: keys.provider)
        let key = try self.sender.retrieveIdentity()
        let paired = try insertSender(publicKey: key, state: .paired(routingKey: routingKey(1), keys: keys.receiverKeys), in: cm)
        let plain = try insertSender(publicKey: key, state: .derived(secret: routingKey(2)), in: cm)

        #expect(cm.routingKeyForSending(to: paired, tier: .v3fs) == routingKey(1))
        #expect(cm.routingKeyForSending(to: plain, tier: .v3fs) == nil)
        #expect(cm.routingKeyForSending(to: plain, tier: .pairingCapable) == routingKey(2))
        #expect(cm.pairingSlotKeys(for: paired) != nil && cm.pairingSlotKeys(for: plain) == nil)
    }

    @Test("A re-pair keeps the identity key, so a trustee's pieces keep their fingerprint and aren't deleted", .ambientTestKeyManager)
    func rePairKeepsTheIdentityKey() throws {
        let keys = try PairKeyFixture(), second = try PairKeyFixture()
        let cm = try makeContactManager(provider: keys.provider)
        let senderKey = try self.sender.retrieveIdentity()
        let contact = try insertSender(publicKey: senderKey, state: .paired(routingKey: routingKey(1), keys: keys.receiverKeys), in: cm)
        let before = try cm.currentPublicKey(forIdentifier: contact.identifier)

        let draft = try #require(Contact.Draft.Key(
            material: senderKey, owner: Data(repeating: 1, count: 65), date: "2", routingKey: routingKey(2), pairKeys: second.receiverKeys
        ))
        try cm.update(key: draft, for: contact.identifier)

        // Pieces a trustee holds are filed and checked by the identity key's fingerprint, which a re-pair does not change.
        #expect(try cm.currentPublicKey(forIdentifier: contact.identifier) == before)
        #expect(cm.pairingState(for: contact) == .paired(routingKey: routingKey(2), keys: second.receiverKeys))
    }

    // MARK: The slot payload

    @Test("A slot payload with a field this build doesn't know decodes, so a later release can add one")
    func unknownSlotFieldDecodes() throws {
        let json = #"{"sessionKey":"AA==","somethingAddedLater":{"nested":[1,2,3]},"slotProof":"AQ=="}"#
        let decoded = try JSONDecoder().decode(OccultaBundle.RecipientPayload.self, from: Data(json.utf8))
        #expect(decoded.sessionKey == Data([0]) && decoded.slotProof == Data([1]))
    }
}

//
//  PairingLifecycleTests.swift
//  OccultaTests
//
//  Bug 196, review findings: a pairing whose sealed state can't be read fails closed and never falls back to the identity key;
//  a re-exchange that would replace a pair-key pairing with a plainer one is refused; a re-pair that fails changes nothing;
//  and a re-pair drops an outstanding challenge only when the form of the pairing changes, and keeps what was verified.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta
@testable import OccultaFormats

@MainActor
private func makeContactManager() throws -> ContactManager {
    let schema = Schema([
        Group.self, Contact.Profile.self, Contact.Profile.PhoneNumber.self, Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self, Contact.Profile.Key.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    return ContactManager(
        modelContainer: container, security: Manager.Security(modelContainer: container, keyManager: TestKeyManager()),
        pairKeys: SoftwareCardKeys()
    )
}

/// A contact with one key row whose pairing column holds `column` as given, with a pending batch of ours so a long-term
/// file from them makes no new batch (which would need an Enclave).
@MainActor
@discardableResult
private func insert(
    _ cm: ContactManager, peer: TestKeyManager? = nil, state: PairingState? = nil, rawColumn: Data? = nil,
    tier: OccultaBundle.Version? = .pairingCapable
) throws -> Contact.Profile {
    let peer = peer ?? TestKeyManager()
    let profile = Contact.Profile(
        identifier: UUID().uuidString, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    let row = Contact.Profile.Key(
        material: try Manager.Crypto().encrypt(data: try peer.retrieveIdentity()), owner: Data(), date: Data(),
        quantumKeyMaterialEncrypted: nil
    )
    if let state { try cm.store(state, in: row) }
    if let rawColumn { row.pairingEncrypted = rawColumn }
    profile.contactPublicKeys = [row]
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

@MainActor
@Suite("Bug 196 — pairing lifecycle: unreadable, weaker, failing and challenged", .serialized)
struct PairingLifecycleTests {

    // MARK: An unreadable column

    @Test("A column that won't decode is unreadable, not empty: a send is refused and the old form is not accepted", .ambientTestKeyManager)
    func unreadableColumnFailsClosed() throws {
        let cm = try makeContactManager()
        let sender = TestKeyManager()
        let contact = try insert(cm, peer: sender, rawColumn: try Data(repeating: 0xAB, count: 4_000).encrypt())

        #expect(!cm.pairingIsReadable(for: contact))
        #expect(!cm.acceptsOldForm(from: contact))
        #expect(throws: ContactManager.Errors.pairingUnreadable) { try cm.encryptBundle(basket: Basket(files: []), for: contact.identifier) }
    }

    @Test("A group send to a contact whose pairing can't be read is refused, not sent with the identity key", .ambientTestKeyManager)
    func groupSendToUnreadablePairingIsRefused() throws {
        let cm = try makeContactManager()
        let contact = try insert(cm, rawColumn: try Data(repeating: 0xAB, count: 4_000).encrypt())
        let group = try cm.createGroup(name: "G")
        try group.addMember(contact.identifier, atDepth: 0)

        #expect(throws: ContactManager.Errors.pairingUnreadable) {
            try cm.encryptGroupBundle(basket: Basket(files: []), groupID: try #require(group.readID()))
        }
    }

    @Test("A caller that names the owner of a file gets no slot tried with the identity key for an unreadable pairing", .ambientTestKeyManager)
    func namedOwnerWithUnreadablePairingIsRefused() throws {
        let cm = try makeContactManager()
        let sender = TestKeyManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let contact = try insert(cm, peer: sender, rawColumn: try Data(repeating: 0xAB, count: 4_000).encrypt())
        let plain = try insert(cm, peer: sender, state: .empty)

        let bundle = try Manager.Crypto(keyManager: sender).seal(
            sealedPayload: OccultaBundle.SealedPayload(message: Data("hello".utf8), appVersion: "1.11.1"), groupID: UUID(),
            recipients: [GroupRecipient(publicKey: me, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)]
        )

        #expect(throws: GroupDecryptError.recipientSlotNotFound) { try cm.openGroup(bundle: bundle, ownerID: contact.identifier) }
        #expect(try cm.openGroup(bundle: bundle, ownerID: plain.identifier).ownerID == plain.identifier, "a plain pairing still opens it")
    }

    @Test("The challenge entry points ask whether the pairing is readable", .ambientTestKeyManager)
    func challengeSealerSeesAnUnreadablePairing() throws {
        let cm = try makeContactManager()
        let unreadable = try insert(cm, rawColumn: try Data(repeating: 0xAB, count: 4_000).encrypt())
        let plain = try insert(cm)

        #expect(!cm.pairingIsReadable(for: unreadable.identifier))
        #expect(cm.pairingIsReadable(for: plain.identifier))
        #expect(cm.pairingIsReadable(for: "nobody"), "no contact is not an unreadable one")
    }

    @Test("A column that won't open under the local key is unreadable too", .ambientTestKeyManager)
    func undecryptableColumnFailsClosed() throws {
        let cm = try makeContactManager()
        let contact = try insert(cm, rawColumn: Data(repeating: 0x11, count: 200))

        #expect(!cm.pairingIsReadable(for: contact) && !cm.acceptsOldForm(from: contact))
    }

    @Test("A column never filled is a plain pairing, as before: it is sent to the old way and accepts the old form", .ambientTestKeyManager)
    func nilColumnIsPlain() throws {
        let cm = try makeContactManager()
        let contact = try insert(cm)

        #expect(cm.pairingIsReadable(for: contact))
        #expect(cm.acceptsOldForm(from: contact))
        #expect(cm.readablePairingState(of: try #require(contact.currentKey)) == .empty)
    }

    @Test("A readable pair-key column still refuses the old form, and a plain one accepts it", .ambientTestKeyManager)
    func readableStatesAreAsBefore() throws {
        let cm = try makeContactManager()
        let paired = try insert(cm, state: .paired(routingKey: Data(repeating: 1, count: 32), keys: samplePairKeys()))
        let plain = try insert(cm, state: .empty)

        #expect(cm.pairingIsReadable(for: paired) && !cm.acceptsOldForm(from: paired))
        #expect(cm.pairingIsReadable(for: plain) && cm.acceptsOldForm(from: plain))
    }

    // MARK: A weaker re-exchange

    @Test("A re-exchange that gives no pair keys to a pair-key contact is refused and changes nothing", .ambientTestKeyManager)
    func weakerRePairIsRefused() throws {
        let cm = try makeContactManager()
        let peer = TestKeyManager()
        let state = PairingState.paired(routingKey: Data(repeating: 1, count: 32), keys: samplePairKeys())
        let contact = try insert(cm, peer: peer, state: state)
        let before = try #require(contact.currentKey)
        let sealedBefore = before.pairingEncrypted
        let recordBefore = contact.prekeyRecordEncrypted

        let plain = try #require(Contact.Draft.Key(material: try peer.retrieveIdentity(), owner: Data(repeating: 1, count: 65), date: "2"))
        #expect(throws: ContactManager.Errors.pairingWouldBeWeaker) { try cm.update(key: plain, for: contact.identifier) }

        #expect(contact.contactPublicKeys?.count == 1)
        #expect(contact.currentKey === before && before.expiredOn == nil)
        #expect(before.pairingEncrypted == sealedBefore && cm.pairingState(for: contact) == state)
        #expect(contact.prekeyRecordEncrypted == recordBefore)
        #expect(!cm.modelContext.hasChanges)
    }

    @Test("A re-exchange that gives pair keys to a pair-key contact is saved, and so is any exchange with a plain one", .ambientTestKeyManager)
    func equalOrBetterIsSaved() throws {
        let cm = try makeContactManager()
        let peer = TestKeyManager()
        let paired = try insert(cm, peer: peer, state: .paired(routingKey: Data(repeating: 1, count: 32), keys: samplePairKeys()))
        let plain = try insert(cm, peer: peer, state: .empty)

        let again = try #require(Contact.Draft.Key(
            material: try peer.retrieveIdentity(), owner: Data(repeating: 1, count: 65), date: "2",
            pairing: .paired(routingKey: Data(repeating: 2, count: 32), keys: samplePairKeys())
        ))
        try cm.update(key: again, for: paired.identifier)
        #expect(cm.pairingState(for: paired).keys != nil)

        let upgrade = try #require(Contact.Draft.Key(material: try peer.retrieveIdentity(), owner: Data(repeating: 1, count: 65), date: "2"))
        try cm.update(key: upgrade, for: plain.identifier)
        #expect(plain.contactPublicKeys?.count == 2)
    }

    // MARK: A failing re-pair

    @Test("A pairing state that doesn't fit its column fails before anything changes", .ambientTestKeyManager)
    func oversizedStateChangesNothing() throws {
        let cm = try makeContactManager()
        let peer = TestKeyManager()
        let contact = try insert(cm, peer: peer, state: .empty)
        try cm.modelContext.save()
        let before = try #require(contact.currentKey)
        let tier = contact.maxBundleVersion
        let record = contact.prekeyRecordEncrypted

        let draft = try #require(Contact.Draft.Key(
            material: try peer.retrieveIdentity(), owner: Data(repeating: 1, count: 65), date: "2",
            pairing: .paired(routingKey: Data(repeating: 2, count: 32), keys: samplePairKeys(blob: PairingCodec.p256BlobRoom + 1))
        ))
        #expect(throws: PairingCodec.CodecError.wrongSize) { try cm.update(key: draft, for: contact.identifier) }

        #expect(contact.contactPublicKeys?.count == 1 && before.expiredOn == nil)
        #expect(contact.maxBundleVersion == tier && contact.prekeyRecordEncrypted == record)
        #expect(!cm.modelContext.hasChanges)
    }

    // MARK: The challenge

    @Test("A re-pair over a column that can't be read drops the outstanding challenge", .ambientTestKeyManager)
    func unreadableColumnDropsTheChallenge() throws {
        let cm = try makeContactManager()
        let peer = TestKeyManager()
        let contact = try insert(cm, peer: peer, rawColumn: try Data(repeating: 0xAB, count: 4_000).encrypt())
        let id = contact.identifier
        try cm.record(
            IdentityChallenge.OutstandingChallenge(nonce: Data(repeating: 1, count: 32), issuedAt: UInt64(Date().timeIntervalSince1970)),
            for: id, now: Date()
        )
        #expect(cm.challenge(for: id) != nil)

        // The new pairing is plain: nothing about the form of the new one drops the challenge, only the old column that may have held pair keys.
        let draft = try #require(Contact.Draft.Key(material: try peer.retrieveIdentity(), owner: Data(repeating: 1, count: 65), date: "2"))
        try cm.update(key: draft, for: id)

        #expect(cm.challenge(for: id) == nil)
    }

    @Test("An upgrade from plain to pair keys drops an outstanding challenge and keeps what was verified", .ambientTestKeyManager)
    func upgradeDropsTheChallengeButKeepsVerified() throws {
        let cm = try makeContactManager()
        let peer = TestKeyManager()
        let contact = try insert(cm, peer: peer, state: .empty)
        let id = contact.identifier

        let first = IdentityChallenge.OutstandingChallenge(nonce: Data(repeating: 1, count: 32), issuedAt: UInt64(Date().timeIntervalSince1970))
        try cm.record(first, for: id, now: Date())
        cm.settle(nonce: first.nonce, for: id, passedAt: Date())
        let second = IdentityChallenge.OutstandingChallenge(nonce: Data(repeating: 2, count: 32), issuedAt: UInt64(Date().timeIntervalSince1970))
        try cm.record(second, for: id, now: Date())
        #expect(cm.challenge(for: id) != nil && cm.verifiedAt(for: id) != nil)

        let upgrade = try #require(Contact.Draft.Key(
            material: try peer.retrieveIdentity(), owner: Data(repeating: 1, count: 65), date: "2",
            pairing: .paired(routingKey: Data(repeating: 3, count: 32), keys: samplePairKeys())
        ))
        try cm.update(key: upgrade, for: id)

        #expect(cm.challenge(for: id) == nil, "its fingerprint was made for a pairing that is gone")
        #expect(cm.verifiedAt(for: id) != nil, "what was verified before is still true")
    }
}

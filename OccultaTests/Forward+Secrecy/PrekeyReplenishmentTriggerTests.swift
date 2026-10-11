//
//  PrekeyReplenishmentTriggerTests.swift
//  OccultaTests
//
//  ⚠️  Requires a Secure Enclave: the receive path generates prekeys through `PrekeySecretsManager`, and the
//  legacy test creates keychain prekeys there.
//
//  Drives the real prekey replenishment trigger in `ContactManager.decryptSealed` and
//  `ContactManager.openGroup`, end to end (`bugs.md` Bug 160). The tests in
//  `ForwardSecrecyIntegrationTests` re-implement this orchestration in their own bodies, so they
//  would keep passing with the trigger deleted; these call it.
//
//  The receiver is always this device's own identity: both methods build `Manager.Crypto()`
//  internally. The sender is a `TestKeyManager` registered as a contact. Our prekeys live in the
//  sender's record (prekey continuity stage 1), so the counts asserted here are the record's. The
//  keychain is checked too, for the one contact identifier each test owns: new prekeys must leave
//  nothing there.
//
//  Also pins Bug 159: a bundle that fails after the trigger's position must leave no pending batch
//  and no keys behind; and the stage 1 wiring: a used key is saved out of the record before the
//  bundle can still be rejected, and a legacy keychain prekey still opens.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta
@testable import OccultaCore

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

// MARK: - Fixture

@MainActor
private struct Fixture {
    let container: ModelContainer
    let cm:        ContactManager
    let senderKM:  TestKeyManager
    let senderID:  String
    let selfPub:   Data
    let pm = Manager.PrekeySecretsManager()

    /// A store with one contact, the sender, on the group-capable tier, holding no keys either way.
    init() throws {
        let schema = Schema([
            Group.self,
            Contact.Profile.self,
            Contact.Profile.PhoneNumber.self,
            Contact.Profile.EmailAddress.self,
            Contact.Profile.PostalAddress.self,
            Contact.Profile.URLAddress.self,
            Contact.Profile.Key.self,
        ])
        let container  = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
        self.container = container
        self.cm        = ContactManager(modelContainer: container, security: try Manager.Security(modelContainer: container, keyManager: TestKeyManager()))
        self.senderKM  = TestKeyManager()
        self.senderID  = "trigger.\(UUID().uuidString)"
        self.selfPub   = try Manager.Key().retrieveIdentity()

        let realCrypto   = Manager.Crypto()
        let encryptedKey = try #require(try realCrypto.encrypt(data: try self.senderKM.retrieveIdentity()))
        let profile = Contact.Profile(
            identifier: self.senderID, givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        profile.contactPublicKeys = [Contact.Profile.Key(
            material: encryptedKey, owner: Data(), date: Data(), quantumKeyMaterialEncrypted: nil
        )]
        let tier = try #require(OccultaBundle.Version.groupCapable.wireByte)
        profile.maxBundleVersion = try realCrypto.encrypt(data: Data([tier]))
        try self.cm.insertProfile(profile)
    }

    var sender: Contact.Profile {
        get throws { try #require(try self.cm.fetchContact(by: self.senderID)) }
    }

    var record: PrekeyRecord {
        get throws { try self.cm.prekeyRecord(for: try self.sender) }
    }

    /// The record as saved: read through a fresh context, so nothing unsaved on `cm`'s can show.
    var savedRecord: PrekeyRecord {
        get throws {
            let id = self.senderID
            let fresh = try ModelContext(self.container).fetch(
                FetchDescriptor<Contact.Profile>(predicate: #Predicate { $0.identifier == id })
            )
            return try self.cm.prekeyRecord(for: try #require(fresh.first))
        }
    }

    var pendingBatch: PrekeyBookkeeper.OutboundBatch? {
        get throws { PrekeyBookkeeper().pendingBatch(in: try self.record) }
    }

    /// Our prekeys for the sender whose private keys the record still holds.
    var ownPrekeyCount: Int {
        get throws { try self.record.ownBatches.reduce(0) { $0 + $1.keys.filter { $0.blob != nil }.count } }
    }

    /// Our prekeys for the sender in the keychain: legacy keys only.
    var keychainPrekeyCount: Int { self.pm.remainingCount(for: self.senderID) }

    func cleanUp() { self.pm.deleteAllKeys(for: self.senderID) }

    // MARK: Bundles from the sender

    /// A single-recipient (legacy-format) bundle from the sender, on the long-term path.
    func longTermBundle(payload: OccultaBundle.SealedPayload = .init(message: Data("hi".utf8))) throws -> OccultaBundle {
        try Manager.Crypto(keyManager: self.senderKM).seal(
            message: try WireHandle.encode(payload: payload),
            contactPrekey: nil, recipientMaterial: self.selfPub, quantumMaterial: nil, version: .v4
        )
    }

    /// A single-recipient (legacy-format) bundle from the sender, sealed to one of our prekeys.
    func forwardSecretBundle(to prekey: Prekey) throws -> OccultaBundle {
        try Manager.Crypto(keyManager: self.senderKM).seal(
            message: try WireHandle.encode(payload: .init(message: Data("hi".utf8))),
            contactPrekey: prekey, recipientMaterial: self.selfPub, quantumMaterial: nil, version: .v4
        )
    }

    /// A group-format bundle from the sender with one slot, ours: long-term when `prekey` is nil.
    func groupBundle(prekey: Prekey? = nil) throws -> OccultaBundle {
        try Manager.Crypto(keyManager: self.senderKM).seal(
            message: Data("hi".utf8), groupID: UUID(),
            recipients: [GroupRecipient(publicKey: self.selfPub, quantumMaterial: nil, contactPrekey: prekey, pendingBatch: nil)]
        )
    }

    /// `bundle` with its shared ciphertext corrupted: its slot still opens (it is keyed to `blind`,
    /// not to the shared ciphertext), and the shared ciphertext then fails authentication.
    func corrupted(_ bundle: OccultaBundle) -> OccultaBundle {
        var ciphertext = bundle.ciphertext
        ciphertext[ciphertext.index(before: ciphertext.endIndex)] ^= 0x01
        return OccultaBundle(
            version: bundle.version, secrecy: bundle.secrecy, ciphertext: ciphertext,
            fingerprintNonce: bundle.fingerprintNonce, senderFingerprint: bundle.senderFingerprint, group: bundle.group
        )
    }

    /// The first prekey of the batch we're waiting to deliver, as the sender would hold it.
    func firstPendingPrekey() throws -> Prekey {
        let batch = try #require(try self.pendingBatch)
        let wire  = try #require(batch.prekeys.first)
        return Prekey(id: wire.id, contactID: self.senderID, publicKey: wire.publicKey)
    }
}

// MARK: - decryptSealed

@Suite("Prekey replenishment trigger — decryptSealed")
@MainActor struct DecryptSealedReplenishmentTests {

    @Test("A long-term bundle with no batch pending stores a batch of fresh Enclave prekeys", .enabled(if: secureEnclaveAvailable()))
    func longTermGeneratesBatch() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        _ = try f.cm.decryptSealed(bundle: try f.longTermBundle())

        let batch = try #require(try f.pendingBatch)
        #expect(batch.prekeys.count == Manager.PrekeySecretsManager.defaultBatchSize)
        #expect(try f.ownPrekeyCount == Manager.PrekeySecretsManager.defaultBatchSize)
        #expect(f.keychainPrekeyCount == 0)
    }

    @Test("A second long-term bundle while a batch is pending generates nothing", .enabled(if: secureEnclaveAvailable()))
    func longTermWithPendingGeneratesNothing() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        _ = try f.cm.decryptSealed(bundle: try f.longTermBundle())
        let first = try #require(try f.pendingBatch)

        _ = try f.cm.decryptSealed(bundle: try f.longTermBundle())

        let after = try #require(try f.pendingBatch)
        #expect(after == first, "the pending batch must not be replaced")
        #expect(try f.ownPrekeyCount == Manager.PrekeySecretsManager.defaultBatchSize)
    }

    @Test("A forward-secret bundle sealed to one of our prekeys clears the pending batch and consumes the prekey", .enabled(if: secureEnclaveAvailable()))
    func forwardSecretClearsPending() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        _ = try f.cm.decryptSealed(bundle: try f.longTermBundle())
        let prekey = try f.firstPendingPrekey()

        _ = try f.cm.decryptSealed(bundle: try f.forwardSecretBundle(to: prekey))

        #expect(try f.pendingBatch == nil)
        #expect(try f.ownPrekeyCount == Manager.PrekeySecretsManager.defaultBatchSize - 1)
        #expect(PrekeyBookkeeper().blob(forPrekeyID: prekey.id, in: try f.savedRecord) == nil, "the prekey must be gone from the record")
    }

    /// Bug 159. The batch used to be generated before the payload was decoded, so a bundle that
    /// failed afterwards left Enclave keys behind and a pending batch in the unsaved profile.
    @Test("A long-term bundle rejected after it opens leaves no batch and no keys", .enabled(if: secureEnclaveAvailable()))
    func rejectedAfterOpenLeavesNothing() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        // A 64-byte prekey fails the bookkeeper's size check, after the bundle has opened.
        let badBatch = OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Date(), prekeys: [OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: Data(count: 64))]
        )
        let bundle = try f.longTermBundle(payload: .init(message: Data("hi".utf8), prekeyBatch: badBatch))

        #expect(throws: (any Error).self) { _ = try f.cm.decryptSealed(bundle: bundle) }

        #expect(try f.pendingBatch == nil)
        #expect(try f.ownPrekeyCount == 0)
        #expect(f.keychainPrekeyCount == 0)
    }
}

// MARK: - openGroup

@Suite("Prekey replenishment trigger — openGroup")
@MainActor struct OpenGroupReplenishmentTests {

    @Test("A long-term slot with no batch pending stores a batch of fresh Enclave prekeys", .enabled(if: secureEnclaveAvailable()))
    func longTermSlotGeneratesBatch() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        _ = try f.cm.openGroup(bundle: try f.groupBundle(), ownerID: f.senderID)

        let batch = try #require(try f.pendingBatch)
        #expect(batch.prekeys.count == Manager.PrekeySecretsManager.defaultBatchSize)
        #expect(try f.ownPrekeyCount == Manager.PrekeySecretsManager.defaultBatchSize)
        #expect(f.keychainPrekeyCount == 0)
    }

    @Test("A second long-term slot while a batch is pending generates nothing", .enabled(if: secureEnclaveAvailable()))
    func longTermSlotWithPendingGeneratesNothing() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        _ = try f.cm.openGroup(bundle: try f.groupBundle(), ownerID: f.senderID)
        let first = try #require(try f.pendingBatch)

        _ = try f.cm.openGroup(bundle: try f.groupBundle(), ownerID: f.senderID)

        let after = try #require(try f.pendingBatch)
        #expect(after == first, "the pending batch must not be replaced")
        #expect(try f.ownPrekeyCount == Manager.PrekeySecretsManager.defaultBatchSize)
    }

    @Test("A forward-secret slot sealed to one of our prekeys clears the pending batch and consumes the prekey", .enabled(if: secureEnclaveAvailable()))
    func forwardSecretSlotClearsPending() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        _ = try f.cm.openGroup(bundle: try f.groupBundle(), ownerID: f.senderID)
        let prekey = try f.firstPendingPrekey()

        _ = try f.cm.openGroup(bundle: try f.groupBundle(prekey: prekey), ownerID: f.senderID)

        #expect(try f.pendingBatch == nil)
        #expect(try f.ownPrekeyCount == Manager.PrekeySecretsManager.defaultBatchSize - 1)
        #expect(PrekeyBookkeeper().blob(forPrekeyID: prekey.id, in: try f.savedRecord) == nil, "the prekey must be gone from the record")
    }

    /// Bug 159. The batch used to be generated before the shared ciphertext was opened and the
    /// sender proof checked.
    @Test("A long-term slot whose shared ciphertext fails leaves no batch and no keys", .enabled(if: secureEnclaveAvailable()))
    func rejectedAfterSlotOpensLeavesNothing() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        let bundle = f.corrupted(try f.groupBundle())
        #expect(throws: (any Error).self) { _ = try f.cm.openGroup(bundle: bundle, ownerID: f.senderID) }

        #expect(try f.pendingBatch == nil)
        #expect(try f.ownPrekeyCount == 0)
        #expect(f.keychainPrekeyCount == 0)
    }
}

// MARK: - Full cycle

@Suite("Prekey replenishment trigger — full cycle")
@MainActor struct ReplenishmentCycleTests {

    /// Long-term in → batch generated → it rides our next message → the sender seals to one of
    /// its keys → the pending batch clears. Our side runs through the real `openGroup` and
    /// `encryptBundle`; the sender's side is played with `Manager.Crypto(keyManager:)`.
    @Test("The batch generated for a long-term message reaches the sender and its first use clears it", .enabled(if: secureEnclaveAvailable()))
    func longTermToForwardSecret() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        _ = try f.cm.openGroup(bundle: try f.groupBundle(), ownerID: f.senderID)
        let pending = try #require(try f.pendingBatch)

        // Our reply carries the pending batch, with its ID, in the sender's slot.
        let reply = try OccultaBundle.decoded(from: try f.cm.encryptBundle(basket: Basket(files: []), for: f.senderID))
        let (senderSlot, _, _) = try Manager.Crypto(keyManager: f.senderKM).findAndOpenRecipientSlot(
            in: reply, blind: try #require(reply.group).blind,
            senderContactID: "self", senderPublicKey: f.selfPub,
            quantumMaterial: nil, prekeys: f.pm
        )
        let delivered = try #require(senderSlot.prekeyBatch)
        #expect(delivered.prekeys == pending.prekeys)
        #expect(delivered.id == pending.id)

        // The sender's next message uses the first key it received.
        let wire   = try #require(delivered.prekeys.first)
        let prekey = Prekey(id: wire.id, contactID: f.senderID, publicKey: wire.publicKey)
        _ = try f.cm.openGroup(bundle: try f.groupBundle(prekey: prekey), ownerID: f.senderID)

        #expect(try f.pendingBatch == nil)
        #expect(try f.ownPrekeyCount == Manager.PrekeySecretsManager.defaultBatchSize - 1)
    }
}

// MARK: - Stage 1 wiring

@Suite("Prekey record wiring")
@MainActor struct PrekeyRecordWiringTests {

    /// §2.2: the private key has already derived the slot's key, so it must be gone from disk even
    /// when the bundle is then rejected. The store at the end is never reached on that path, so only
    /// the save at consumption can do it. Its batch counts as delivered too: only the holder of our
    /// batch could have opened the slot.
    @Test("A used prekey is saved out of the record even when the bundle is rejected", .enabled(if: secureEnclaveAvailable()))
    func consumptionSavedBeforeRejection() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        _ = try f.cm.openGroup(bundle: try f.groupBundle(), ownerID: f.senderID)
        let prekey = try f.firstPendingPrekey()

        let bundle = f.corrupted(try f.groupBundle(prekey: prekey))
        #expect(throws: (any Error).self) { _ = try f.cm.openGroup(bundle: bundle, ownerID: f.senderID) }

        let saved = try f.savedRecord
        #expect(PrekeyBookkeeper().blob(forPrekeyID: prekey.id, in: saved) == nil)
        #expect(PrekeyBookkeeper().pendingBatch(in: saved) == nil)
    }

    /// D1: a retired batch's leftover keys are kept 30 days for files sealed to them and still on their way. The
    /// contact seals two files to batch A, moves on to batch B, and only then do those files arrive: the first,
    /// within the 30 days, opens; the second, after the sweep at 31 days, doesn't.
    @Test("A file sealed to a retired key opens within the grace period, and not after it", .enabled(if: secureEnclaveAvailable()))
    func retiredKeyOpensWithinGrace() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        // Batch A is generated and delivered: the contact uses its first key.
        _ = try f.cm.openGroup(bundle: try f.groupBundle(), ownerID: f.senderID)
        let batchA = try #require(try f.pendingBatch).prekeys.map {
            Prekey(id: $0.id, contactID: f.senderID, publicKey: $0.publicKey)
        }
        _ = try f.cm.openGroup(bundle: try f.groupBundle(prekey: batchA[0]), ownerID: f.senderID)

        // Two files sealed to A's next keys, held back: still on their way.
        let late    = try f.groupBundle(prekey: batchA[1])
        let tooLate = try f.groupBundle(prekey: batchA[2])

        // The contact runs out, gets batch B, and uses it: A retires.
        _ = try f.cm.openGroup(bundle: try f.groupBundle(), ownerID: f.senderID)
        let batchB = try f.firstPendingPrekey()
        _ = try f.cm.openGroup(bundle: try f.groupBundle(prekey: batchB), ownerID: f.senderID)
        #expect(try f.record.ownBatches.first?.retiredAt != nil, "precondition: batch A is retired")

        _ = try f.cm.openGroup(bundle: late, ownerID: f.senderID)

        #expect(PrekeyBookkeeper().blob(forPrekeyID: batchA[2].id, in: try f.record) != nil)
        try f.cm.sweepPrekeys(of: try f.sender, now: Date() + 31 * 86_400)
        try f.cm.modelContext.save()
        #expect(PrekeyBookkeeper().blob(forPrekeyID: batchA[2].id, in: try f.savedRecord) == nil)
        #expect(throws: (any Error).self) { _ = try f.cm.openGroup(bundle: tooLate, ownerID: f.senderID) }
    }

    /// The sweep on receipt (D1, Bug 156) runs before the bundle is opened and is saved at once, so
    /// even a bundle that is then rejected leaves expired keys deleted: from the record, and the
    /// legacy ones from the keychain.
    @Test("A message from a contact sweeps their record first, even when it is rejected", .enabled(if: secureEnclaveAvailable()))
    func receiptSweepsBeforeRejection() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        _ = try f.pm.generateBatch(contactID: f.senderID)
        let now = Date()
        var record = PrekeyRecord.empty
        record.ownBatches = [PrekeyRecord.OwnBatch(
            id: Data(count: 16), createdAt: now - 60 * 86_400, retiredAt: now - 31 * 86_400, isPending: false,
            keys: [PrekeyRecord.OwnKey(id: Data(count: 16), blob: Data(count: 143), publicKey: nil)]
        )]
        record.legacyKeys = .retired(since: now - 31 * 86_400)
        try f.cm.store(record, for: try f.sender)
        try f.cm.modelContext.save()

        let bundle = f.corrupted(try f.groupBundle())
        #expect(throws: (any Error).self) { _ = try f.cm.openGroup(bundle: bundle, ownerID: f.senderID) }

        let saved = try f.savedRecord
        #expect(saved.ownBatches.isEmpty)
        #expect(saved.legacyKeys == PrekeyRecord.LegacyKeys.none)
        #expect(f.keychainPrekeyCount == 0, "legacy keys past their grace period must be gone from the keychain")
    }

    /// A contact still holding a batch from before stage 1 seals to a keychain key, which the record
    /// has no blob for. Their record is carried over by the launch migration, as on an upgraded device;
    /// the message must then open, and the key leave the keychain.
    @Test("A legacy keychain prekey still opens after the migration and is consumed", .enabled(if: secureEnclaveAvailable()))
    func legacyKeychainPrekeyOpens() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        let keys = try f.pm.generateBatch(contactID: f.senderID)
        let batch = OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Date(), prekeys: keys.map { OccultaBundle.WirePrekey(id: $0.id, publicKey: $0.publicKey) }
        )
        var legacy = ForwardSecrecy()
        legacy.pendingOutboundBatch = try JSONEncoder().encode(batch)
        let sender = try f.sender
        sender.encryptionScheme = EncryptionScheme.v2_hybridPQ.rawValue
        sender.retiredForwardSecrecyEncrypted = try #require(try JSONEncoder().encode(legacy).encrypt())
        try f.cm.modelContext.save()
        try DatabaseMigration.migratePrekeyRecords(modelContext: f.cm.modelContext)

        let prekey = try #require(keys.first)
        _ = try f.cm.decryptSealed(bundle: try f.forwardSecretBundle(to: prekey))

        #expect(f.pm.retrievePrivateKey(for: prekey) == nil, "the legacy key must be gone from the keychain")
        #expect(f.keychainPrekeyCount == keys.count - 1)
        let saved = try f.savedRecord
        #expect(PrekeyBookkeeper().pendingBatch(in: saved) == nil, "using it delivers the legacy batch")
        #expect(saved.legacyKeys == .inUse, "the rest of the legacy batch is still the contact's to use")
        #expect(try f.sender.prekeyRecordEncrypted != nil)
    }
}

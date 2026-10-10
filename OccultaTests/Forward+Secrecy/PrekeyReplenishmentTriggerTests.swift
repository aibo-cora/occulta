//
//  PrekeyReplenishmentTriggerTests.swift
//  OccultaTests
//
//  ⚠️  Requires a Secure Enclave: the receive path generates prekeys through `PrekeyManager`.
//
//  Drives the real prekey replenishment trigger in `ContactManager.decryptSealed` and
//  `ContactManager.openGroup`, end to end (`bugs.md` Bug 160). The tests in
//  `ForwardSecrecyIntegrationTests` re-implement this orchestration in their own bodies, so they
//  would keep passing with the trigger deleted; these call it.
//
//  The receiver is always this device's own identity: both methods build `Manager.Crypto()`
//  internally. The sender is a `TestKeyManager` registered as a contact. Each test uses its own
//  contact identifier and deletes that contact's Enclave prekeys afterwards, so suites running in
//  parallel can't change the counts asserted here.
//
//  Also pins Bug 159: a bundle that fails after the trigger's position must leave no pending batch
//  and no Enclave keys behind.
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
    let cm:        ContactManager
    let senderKM:  TestKeyManager
    let senderID:  String
    let selfPub:   Data
    let pm = Manager.PrekeyManager()

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
        let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
        self.cm       = ContactManager(modelContainer: container, security: try Manager.Security(modelContainer: container, keyManager: TestKeyManager()))
        self.senderKM = TestKeyManager()
        self.senderID = "trigger.\(UUID().uuidString)"
        self.selfPub  = try Manager.Key().retrieveIdentity()

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

    /// Our prekeys held in the Enclave for the sender.
    var enclavePrekeyCount: Int { self.pm.remainingCount(for: self.senderID) }

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

    /// The first prekey of the batch we're waiting to deliver, as the sender would hold it.
    func firstPendingPrekey() throws -> Prekey {
        let batch = try #require(try self.sender.loadPendingBatch())
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

        let batch = try #require(try f.sender.loadPendingBatch())
        #expect(batch.prekeys.count == Manager.PrekeyManager.defaultBatchSize)
        #expect(f.enclavePrekeyCount == Manager.PrekeyManager.defaultBatchSize)
    }

    @Test("A second long-term bundle while a batch is pending generates nothing", .enabled(if: secureEnclaveAvailable()))
    func longTermWithPendingGeneratesNothing() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        _ = try f.cm.decryptSealed(bundle: try f.longTermBundle())
        let first = try #require(try f.sender.loadPendingBatch())

        _ = try f.cm.decryptSealed(bundle: try f.longTermBundle())

        let after = try #require(try f.sender.loadPendingBatch())
        #expect(after.prekeys == first.prekeys, "the pending batch must not be replaced")
        #expect(f.enclavePrekeyCount == Manager.PrekeyManager.defaultBatchSize)
    }

    @Test("A forward-secret bundle sealed to one of our prekeys clears the pending batch and consumes the prekey", .enabled(if: secureEnclaveAvailable()))
    func forwardSecretClearsPending() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        _ = try f.cm.decryptSealed(bundle: try f.longTermBundle())
        let prekey = try f.firstPendingPrekey()

        _ = try f.cm.decryptSealed(bundle: try f.forwardSecretBundle(to: prekey))

        #expect(try f.sender.hasPendingBatch == false)
        #expect(f.enclavePrekeyCount == Manager.PrekeyManager.defaultBatchSize - 1)
        #expect(f.pm.retrievePrivateKey(for: prekey) == nil, "the prekey must be gone from the Enclave")
    }

    /// Bug 159. The batch used to be generated before the payload was decoded, so a bundle that
    /// failed afterwards left Enclave keys behind and a pending batch in the unsaved profile.
    @Test("A long-term bundle rejected after it opens leaves no batch and no Enclave keys", .enabled(if: secureEnclaveAvailable()))
    func rejectedAfterOpenLeavesNothing() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        // A 64-byte prekey fails `storeInboundBatch`'s size check, after the bundle has opened.
        let badBatch = OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Date(), prekeys: [OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: Data(count: 64))]
        )
        let bundle = try f.longTermBundle(payload: .init(message: Data("hi".utf8), prekeyBatch: badBatch))

        #expect(throws: (any Error).self) { _ = try f.cm.decryptSealed(bundle: bundle) }

        #expect(try f.sender.hasPendingBatch == false)
        #expect(f.enclavePrekeyCount == 0)
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

        let batch = try #require(try f.sender.loadPendingBatch())
        #expect(batch.prekeys.count == Manager.PrekeyManager.defaultBatchSize)
        #expect(f.enclavePrekeyCount == Manager.PrekeyManager.defaultBatchSize)
    }

    @Test("A second long-term slot while a batch is pending generates nothing", .enabled(if: secureEnclaveAvailable()))
    func longTermSlotWithPendingGeneratesNothing() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        _ = try f.cm.openGroup(bundle: try f.groupBundle(), ownerID: f.senderID)
        let first = try #require(try f.sender.loadPendingBatch())

        _ = try f.cm.openGroup(bundle: try f.groupBundle(), ownerID: f.senderID)

        let after = try #require(try f.sender.loadPendingBatch())
        #expect(after.prekeys == first.prekeys, "the pending batch must not be replaced")
        #expect(f.enclavePrekeyCount == Manager.PrekeyManager.defaultBatchSize)
    }

    @Test("A forward-secret slot sealed to one of our prekeys clears the pending batch and consumes the prekey", .enabled(if: secureEnclaveAvailable()))
    func forwardSecretSlotClearsPending() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        _ = try f.cm.openGroup(bundle: try f.groupBundle(), ownerID: f.senderID)
        let prekey = try f.firstPendingPrekey()

        _ = try f.cm.openGroup(bundle: try f.groupBundle(prekey: prekey), ownerID: f.senderID)

        #expect(try f.sender.hasPendingBatch == false)
        #expect(f.enclavePrekeyCount == Manager.PrekeyManager.defaultBatchSize - 1)
        #expect(f.pm.retrievePrivateKey(for: prekey) == nil, "the prekey must be gone from the Enclave")
    }

    /// Bug 159. The batch used to be generated before the shared ciphertext was opened and the
    /// sender proof checked.
    @Test("A long-term slot whose shared ciphertext fails leaves no batch and no Enclave keys", .enabled(if: secureEnclaveAvailable()))
    func rejectedAfterSlotOpensLeavesNothing() throws {
        let f = try Fixture()
        defer { f.cleanUp() }

        // The slot opens (it is keyed to `blind`, not to the shared ciphertext); the shared
        // ciphertext then fails authentication.
        let good = try f.groupBundle()
        var corrupted = good.ciphertext
        corrupted[corrupted.index(before: corrupted.endIndex)] ^= 0x01
        let bundle = OccultaBundle(
            version: good.version, secrecy: good.secrecy, ciphertext: corrupted,
            fingerprintNonce: good.fingerprintNonce, senderFingerprint: good.senderFingerprint, group: good.group
        )

        #expect(throws: (any Error).self) { _ = try f.cm.openGroup(bundle: bundle, ownerID: f.senderID) }

        #expect(try f.sender.hasPendingBatch == false)
        #expect(f.enclavePrekeyCount == 0)
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
        let pending = try #require(try f.sender.loadPendingBatch())

        // Our reply carries the pending batch in the sender's slot.
        let reply = try OccultaBundle.decoded(from: try f.cm.encryptBundle(basket: Basket(files: []), for: f.senderID))
        let (senderSlot, _, _) = try Manager.Crypto(keyManager: f.senderKM).findAndOpenRecipientSlot(
            in: reply, blind: try #require(reply.group).blind,
            senderContactID: "self", senderPublicKey: f.selfPub,
            quantumMaterial: nil, prekeyManager: f.pm
        )
        let delivered = try #require(senderSlot.prekeyBatch)
        #expect(delivered.prekeys == pending.prekeys)

        // The sender's next message uses the first key it received.
        let wire   = try #require(delivered.prekeys.first)
        let prekey = Prekey(id: wire.id, contactID: f.senderID, publicKey: wire.publicKey)
        _ = try f.cm.openGroup(bundle: try f.groupBundle(prekey: prekey), ownerID: f.senderID)

        #expect(try f.sender.hasPendingBatch == false)
        #expect(f.enclavePrekeyCount == Manager.PrekeyManager.defaultBatchSize - 1)
    }
}

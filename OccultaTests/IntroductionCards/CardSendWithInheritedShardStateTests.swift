//
//  CardSendWithInheritedShardStateTests.swift
//  OccultaTests
//
//  Bug 182 (`Docs/Features/Secure Mode/bugs.md`): a contact that was a trustee or an owner before it became a card
//  contact (revoke, then a card) leaves `CustodyShard` and `PendingShardDistribute` rows behind. Compose and the
//  share extension build shard content from those rows for every one-to-one recipient, and
//  `encryptCardBundle` refuses any shard content (SPEC §8), so every send in that conversation threw `hardBlocked`.
//
//  Each device is a `CardPhone`; the custody rows live in a `ShardCustodyManager` of their own, keyed to the
//  contact's identifier exactly as compose looks them up. Importing a card makes a prekey batch, so the suite
//  needs an Enclave.
//

import Testing
import CryptoKit
import SwiftData
import Foundation
@testable import Occulta
@testable import OccultaFormats

private let enclave = TestSupport.secureEnclaveAvailable()

@MainActor
private struct CustodyRig {
    let km = TestKeyManager()
    let owner = TestKeyManager()
    let container: ModelContainer
    let custody: ShardCustodyManager
    let vault: VaultManager

    init() throws {
        let schema = Schema([
            VaultEntry.self,
            CustodyShard.self,
            ReconstructShard.self,
            PendingShardDistribute.self,
            PendingShardStatusUpdate.self,
            PotentiallyLostShard.self,
            GlobalShardConfig.self
        ])
        let container = try ModelContainer(for: schema, configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)])
        self.container = container
        self.vault = VaultManager(modelContainer: container, keyManager: self.km)
        self.custody = ShardCustodyManager(modelContainer: container, keyManager: self.km)
    }

    /// A signed shard attribute, as an owner's device would produce one.
    func attribute() throws -> SignedAttribute {
        let id = UUID(), entryID = UUID(), createdAt = Date(), value = Data([0xAB, 0xCD])
        let payload = SignedAttribute.signingPayload(
            id: id, category: .shard, value: value, entryID: entryID, createdAt: createdAt, expiresAt: nil
        )
        return SignedAttribute(
            id: id, label: "vault-shard", value: value, category: .shard,
            signature: try self.owner.signData(payload), createdAt: createdAt, expiresAt: nil, entryID: entryID
        )
    }

    /// This device holds a shard for `ownerIdentifier`, through the real inbound path.
    func holdShard(for ownerIdentifier: String) throws {
        self.custody.handleInbound(
            shardOperations: [.init(kind: .distribute, attribute: try self.attribute())],
            custodyManifest: nil,
            senderPublicKey: try self.owner.retrieveIdentity(),
            senderIdentifier: ownerIdentifier,
            vaultManager: self.vault
        )
    }

    /// A shard queued to be sent to `contactIdentifier`, as `distributeBackup` leaves it.
    func queueShard(for contactIdentifier: String) throws {
        try self.custody.queueDistribute(attribute: try self.attribute(), for: contactIdentifier)
    }

    func count<Row: PersistentModel>(_: Row.Type) throws -> Int {
        try ModelContext(self.container).fetch(FetchDescriptor<Row>()).count
    }
}

@MainActor
@Suite("Card send with shard state inherited from before the card (Bug 182)", .serialized, .enabled(if: enclave))
struct CardSendWithInheritedShardStateTests {

    /// What `ComposeViewModel.encrypt` does for one recipient, up to and including the encrypt call.
    private func composeSend(_ device: CardPhone, to id: String, rig: CustodyRig) throws -> Data {
        try device.run {
            let contactPub = try? device.cm.currentPublicKey(forIdentifier: id)
            let isCard = try device.cm.isCardContact(identifier: id)
            let shardOps = try rig.custody.buildShardOperations(for: id, currentContactPublicKey: contactPub, isCardContact: isCard)
            let manifest = try? rig.custody.buildCustodyManifest(for: id, isCardContact: isCard)
            return try device.cm.encryptBundle(
                basket: CardPhone.basket("hello"), for: id,
                shardOperations: shardOps.isEmpty ? nil : shardOps, custodyManifest: manifest
            )
        }
    }

    @Test("Custodian side: a shard held for the contact from before the card does not block sends")
    func heldShard() throws {
        let pair = try CardPhonePair()
        try pair.converse()
        let rig = try CustodyRig()
        try rig.holdShard(for: pair.bobSide)
        #expect(try rig.count(CustodyShard.self) == 1, "precondition")

        let bundle = try self.composeSend(pair.bob, to: pair.bobSide, rig: rig)
        #expect(!bundle.isEmpty)
    }

    @Test("Owner side: a shard queued for the contact from before the card does not block sends")
    func queuedShard() throws {
        let pair = try CardPhonePair()
        try pair.converse()
        let rig = try CustodyRig()
        try rig.queueShard(for: pair.bobSide)
        #expect(try rig.count(PendingShardDistribute.self) == 1, "precondition")

        let bundle = try self.composeSend(pair.bob, to: pair.bobSide, rig: rig)
        #expect(!bundle.isEmpty)
    }

    @Test("Both sides of a conversation send, with a held shard and a queued one for the contact")
    func bothSidesSend() throws {
        let pair = try CardPhonePair()
        try pair.converse()
        for (device, side) in [(pair.bob, pair.bobSide), (pair.carol, pair.carolSide)] {
            let rig = try CustodyRig()
            try rig.holdShard(for: side)
            try rig.queueShard(for: side)
            let bundle = try self.composeSend(device, to: side, rig: rig)
            #expect(!bundle.isEmpty)
        }
    }

    @Test("The builders return nothing for a card contact and leave every row as it was")
    func rowsUntouched() throws {
        let rig = try CustodyRig()
        try rig.holdShard(for: "contact")
        try rig.queueShard(for: "contact")

        #expect(try rig.custody.buildShardOperations(for: "contact", currentContactPublicKey: nil, isCardContact: true).isEmpty)
        #expect(try rig.custody.buildCustodyManifest(for: "contact", isCardContact: true).isEmpty)
        #expect(try rig.count(CustodyShard.self) == 1)
        #expect(try rig.count(PendingShardDistribute.self) == 1)

        // Nothing was lost: once the contact is no longer a card contact, the same rows come back.
        #expect(try rig.custody.buildShardOperations(for: "contact", currentContactPublicKey: nil, isCardContact: false).count == 1)
        #expect(try rig.custody.buildCustodyManifest(for: "contact", isCardContact: false).count == 1)
    }

    @Test("A contact that is not a card contact still gets shard content and its manifest")
    func ordinaryContact() throws {
        let carol = try CardPhone(), bob = try CardPhone()
        let side = try bob.newContact("Carol")
        try bob.addOrdinary(carol, as: side)
        #expect(try bob.run { try bob.cm.isCardContact(identifier: side) } == false)

        let rig = try CustodyRig()
        try rig.holdShard(for: side)
        try rig.queueShard(for: side)
        let isCard = try bob.run { try bob.cm.isCardContact(identifier: side) }
        #expect(try rig.custody.buildShardOperations(for: side, currentContactPublicKey: nil, isCardContact: isCard).count == 1)
        #expect(try rig.custody.buildCustodyManifest(for: side, isCardContact: isCard).count == 1)
    }

    @Test("Shard content built without the card check is still refused by the card send")
    func backstop() throws {
        let pair = try CardPhonePair()
        try pair.converse()
        let rig = try CustodyRig()
        try rig.queueShard(for: pair.bobSide)
        let ops = try rig.custody.buildShardOperations(for: pair.bobSide, currentContactPublicKey: nil, isCardContact: false)
        #expect(ops.count == 1, "precondition")

        try pair.bob.run {
            #expect { try pair.bob.cm.encryptBundle(basket: CardPhone.basket("x"), for: pair.bobSide, shardOperations: ops) }
                throws: { if case ContactManager.CardError.hardBlocked = $0 { true } else { false } }
        }
    }

    @Test("isCardContact is true on both sides of a conversation and while imported, false otherwise")
    func isCardContactStates() throws {
        let pair = try CardPhonePair()
        #expect(try pair.carol.run { try pair.carol.cm.isCardContact(identifier: pair.carolSide) }, "imported")
        try pair.converse()
        #expect(try pair.bob.run { try pair.bob.cm.isCardContact(identifier: pair.bobSide) }, "conversation, Bob")
        #expect(try pair.carol.run { try pair.carol.cm.isCardContact(identifier: pair.carolSide) }, "conversation, Carol")
        #expect(try pair.bob.run { try pair.bob.cm.isCardContact(identifier: UUID().uuidString) } == false, "unknown contact")
    }
}

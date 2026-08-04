//
//  ShardCustodyPurgeTests.swift
//  OccultaTests
//
//  Tests for ShardCustodyManager.purgeCustody(for:), called from
//  ContactManager.deleteContact — see
//  Docs/Bugs/v1.10.0/Shard-Custody-Not-Cleaned-Up-On-Contact-Deletion.md.
//
//  Simulator-safe — uses TestKeyManager throughout (ShardCustodyManager takes an
//  injected KeyManagerProtocol, unlike Group/ContactManager's hardcoded Manager.Key()).
//

import Testing
import CryptoKit
import SwiftData
import Foundation
import LocalAuthentication
@testable import Occulta

// MARK: - Helpers

@MainActor
private func makeCustodyRig() throws -> (
    custody:   ShardCustodyManager,
    vault:     VaultManager,
    km:        TestKeyManager,
    container: ModelContainer
) {
    let km     = TestKeyManager()
    let schema = Schema([
        VaultEntry.self,
        CustodyShard.self,
        ReconstructShard.self,
        PendingShardDistribute.self,
        PendingShardStatusUpdate.self,
        PotentiallyLostShard.self,
        GlobalShardConfig.self
    ])
    let cfg       = ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)
    let container = try ModelContainer(for: schema, configurations: [cfg])
    let vault     = VaultManager(modelContainer: container, keyManager: km)
    let custody   = ShardCustodyManager(modelContainer: container, keyManager: km)
    return (custody, vault, km, container)
}

@MainActor
private func makeAttr(
    signer:     TestKeyManager,
    entryID:    UUID = UUID(),
    shardBytes: Data = Data([0xAB, 0xCD])
) throws -> SignedAttribute {
    let attrID    = UUID()
    let createdAt = Date()
    let payload   = SignedAttribute.signingPayload(
        id: attrID, category: .shard, value: shardBytes,
        entryID: entryID, createdAt: createdAt, expiresAt: nil
    )
    return SignedAttribute(
        id: attrID, label: "vault-shard", value: shardBytes, category: .shard,
        signature: try signer.signData(payload),
        createdAt: createdAt, expiresAt: nil, entryID: entryID
    )
}

/// Inserts a CustodyShard row owned by `ownerIdentifier`, via the real inbound path.
@MainActor
private func receiveShard(
    from ownerKM: TestKeyManager,
    ownerIdentifier: String,
    into custody: ShardCustodyManager,
    vault: VaultManager
) throws {
    let attr = try makeAttr(signer: ownerKM)
    _ = custody.handleInbound(
        shardOperations:  [.init(kind: .distribute, attribute: attr)],
        custodyManifest:  nil,
        expectedShards:   nil,
        senderPublicKey:  try ownerKM.retrieveIdentity(),
        senderIdentifier: ownerIdentifier,
        vaultManager:     vault
    )
}

/// Manually seals and inserts a PotentiallyLostShard row — no single-shot public API
/// exists for this (real rows are only created mid-manifest-reconciliation).
@MainActor
private func insertPotentiallyLostShard(
    contactIdentifier: String,
    using km: TestKeyManager,
    in container: ModelContainer
) throws {
    guard let key = try km.deriveShardCustodyKey() else { throw TestSetupError.keyUnavailable }
    let ctx     = ModelContext(container)
    let rowID   = UUID()
    let payload = PotentiallyLostShard.Payload(attributeID: UUID(), contactIdentifier: contactIdentifier, isAbsent: true)
    let bytes   = try JSONEncoder().encode(payload)
    let sealed  = try AES.GCM.seal(bytes, using: key, nonce: AES.GCM.Nonce(), authenticating: rowID.uuidString.data(using: .utf8)!)
    guard let combined = sealed.combined else { throw TestSetupError.keyUnavailable }
    ctx.insert(PotentiallyLostShard(id: rowID, encryptedPayload: combined))
    try ctx.save()
}

private enum TestSetupError: Error { case keyUnavailable }

@MainActor private func custodyShardCount(in container: ModelContainer) throws -> Int {
    try ModelContext(container).fetch(FetchDescriptor<CustodyShard>()).count
}
@MainActor private func distributeRowCount(in container: ModelContainer) throws -> Int {
    try ModelContext(container).fetch(FetchDescriptor<PendingShardDistribute>()).count
}
@MainActor private func lostShardRowCount(in container: ModelContainer) throws -> Int {
    try ModelContext(container).fetch(FetchDescriptor<PotentiallyLostShard>()).count
}

// MARK: - CustodyShard

@Suite("purgeCustody — CustodyShard")
@MainActor struct PurgeCustody_CustodyShardTests {

    @Test func removesShardsForDeletedOwner() throws {
        let (custody, vault, _, container) = try makeCustodyRig()
        let aliceKM = TestKeyManager()
        try receiveShard(from: aliceKM, ownerIdentifier: "alice", into: custody, vault: vault)
        #expect(try custodyShardCount(in: container) == 1)

        try custody.purgeCustody(for: "alice")

        #expect(try custodyShardCount(in: container) == 0)
    }

    @Test func leavesOtherOwnersShardsIntact() throws {
        let (custody, vault, _, container) = try makeCustodyRig()
        let aliceKM = TestKeyManager()
        let carolKM = TestKeyManager()
        try receiveShard(from: aliceKM, ownerIdentifier: "alice", into: custody, vault: vault)
        try receiveShard(from: carolKM, ownerIdentifier: "carol", into: custody, vault: vault)
        #expect(try custodyShardCount(in: container) == 2)

        try custody.purgeCustody(for: "alice")

        #expect(try custodyShardCount(in: container) == 1)
    }
}

// MARK: - PendingShardDistribute

@Suite("purgeCustody — PendingShardDistribute")
@MainActor struct PurgeCustody_PendingDistributeTests {

    @Test func removesQueuedDistributesForDeletedContact() throws {
        let (custody, _, km, container) = try makeCustodyRig()
        let attr = try makeAttr(signer: km)
        try custody.queueDistribute(attribute: attr, for: "alice")
        #expect(try distributeRowCount(in: container) == 1)

        try custody.purgeCustody(for: "alice")

        #expect(try distributeRowCount(in: container) == 0)
    }

    @Test func leavesOtherContactsQueuedDistributesIntact() throws {
        let (custody, _, km, container) = try makeCustodyRig()
        try custody.queueDistribute(attribute: try makeAttr(signer: km), for: "alice")
        try custody.queueDistribute(attribute: try makeAttr(signer: km), for: "carol")
        #expect(try distributeRowCount(in: container) == 2)

        try custody.purgeCustody(for: "alice")

        #expect(try distributeRowCount(in: container) == 1)
    }
}

// MARK: - PotentiallyLostShard

@Suite("purgeCustody — PotentiallyLostShard")
@MainActor struct PurgeCustody_PotentiallyLostTests {

    @Test func removesWatchRowsForDeletedContact() throws {
        let (custody, _, km, container) = try makeCustodyRig()
        try insertPotentiallyLostShard(contactIdentifier: "alice", using: km, in: container)
        #expect(try lostShardRowCount(in: container) == 1)

        try custody.purgeCustody(for: "alice")

        #expect(try lostShardRowCount(in: container) == 0)
    }
}

// MARK: - Combined pass

@Suite("purgeCustody — combined pass reuses one key derivation")
@MainActor struct PurgeCustody_CombinedTests {

    @Test func purgesAllThreeStoresInOnePass() throws {
        let (custody, vault, km, container) = try makeCustodyRig()
        let aliceKM = TestKeyManager()

        try receiveShard(from: aliceKM, ownerIdentifier: "alice", into: custody, vault: vault)
        try custody.queueDistribute(attribute: try makeAttr(signer: km), for: "alice")
        try insertPotentiallyLostShard(contactIdentifier: "alice", using: km, in: container)

        try custody.purgeCustody(for: "alice")

        #expect(try custodyShardCount(in: container) == 0)
        #expect(try distributeRowCount(in: container) == 0)
        #expect(try lostShardRowCount(in: container) == 0)
    }
}

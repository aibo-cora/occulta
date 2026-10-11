//
//  ReconstructShardMigrationTests.swift
//  OccultaTests
//
//  Stage 5 of the RECOVERY_BUFFER_LAYERING.md §9.3 restore-refactor plan —
//  migrateReconstructShardsIfNeeded() moves any leftover ReconstructShard rows (the
//  retired pre-§9.3 mechanism) into PendingShamirSecretRestore. Runs under
//  `.ambientTestKeyManager`: absorbShard seals PendingShamirSecretRestore.attributeID/
//  .deletionToken under the ambient local key, never the injected key manager — see
//  ShardCustodyTests.swift's ReconstructionBufferTests for the fuller trap explanation.
//

import Testing
import CryptoKit
import SwiftData
import Foundation
import LocalAuthentication
@testable import Occulta
@testable import OccultaFormats

@MainActor
private func makeVault() throws -> (vault: VaultManager, km: TestKeyManager, container: ModelContainer) {
    let km     = TestKeyManager()
    let schema = Schema([
        VaultEntry.self,
        CustodyShard.self,
        ReconstructShard.self,
        Vault.self,
        PendingShamirSecretRestore.self,
        PendingShardDistribute.self,
        PendingShardStatusUpdate.self,
        PotentiallyLostShard.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    let vault     = VaultManager(modelContainer: container, keyManager: km)
    vault.unlock(context: LAContext())
    return (vault, km, container)
}

/// A genuine-shaped `.shard` SignedAttribute — 33-byte value, real DER signature —
/// matching what every legacy `ReconstructShard.Payload` actually carried.
private func makeShardAttribute(signer: TestKeyManager, entryID: UUID) throws -> SignedAttribute {
    let id        = UUID()
    let value     = Data([UInt8(1)]) + Data.randomBytes(32)
    let createdAt = Date()
    let payload   = SignedAttribute.signingPayload(
        id: id, category: .shard, value: value, entryID: entryID, createdAt: createdAt
    )
    let signature = try signer.signData(payload)
    return SignedAttribute(
        id: id, label: "vault-shard", value: value, category: .shard,
        signature: signature, createdAt: createdAt, entryID: entryID
    )
}

/// v1.10.3's HKDF info string for the key that sealed `ReconstructShard` rows
/// (`deriveRecoveryBufferKey`), written out rather than read from `SaltInfo`, so these rows
/// stay shaped like the release's even if the constant changes (`bugs.md` Bug 137).
private let v1_10_3RecoveryBufferInfo = Data("Occulta-v1-recovery-buffer-2026".utf8)

/// Inserts a legacy `ReconstructShard` row directly, sealed as v1.10.3 sealed it — bypassing
/// `absorbShard` entirely, since the whole point is to fix a population that predates it.
@MainActor
private func insertLegacyRow(
    vault: VaultManager,
    km: TestKeyManager,
    entryID: UUID,
    attribute: SignedAttribute,
    senderIdentifier: String
) throws {
    guard let restoreKey = try km.deriveCustodySEKey(info: v1_10_3RecoveryBufferInfo) else {
        Issue.record("expected v1.10.3's restore key")
        return
    }
    let rowID   = UUID()
    let aad     = rowID.uuidString.data(using: .utf8)!
    let payload = ReconstructShard.Payload(
        entryID: entryID, attrID: attribute.id,
        signedAttribute: attribute, senderIdentifier: senderIdentifier
    )
    let plaintext = try JSONEncoder().encode(payload)
    let sealed    = try AES.GCM.seal(plaintext, using: restoreKey, nonce: AES.GCM.Nonce(), authenticating: aad)
    let combined  = try #require(sealed.combined)

    vault.modelContext.insert(ReconstructShard(id: rowID, encryptedPayload: combined))
    try vault.modelContext.save()
}

@MainActor
private func legacyRowCount(in container: ModelContainer) throws -> Int {
    try ModelContext(container).fetch(FetchDescriptor<ReconstructShard>()).count
}

@Suite("ReconstructShard → PendingShamirSecretRestore migration", .ambientTestKeyManager)
@MainActor
struct ReconstructShardMigrationTests {

    @Test("No legacy rows is a no-op")
    func noRowsIsANoOp() throws {
        let (vault, _, container) = try makeVault()
        try vault.migrateReconstructShardsIfNeeded()
        #expect(try legacyRowCount(in: container) == 0)
    }

    @Test("A BEK-restore population (entryID resolving to no real VaultEntry) migrates and becomes readable")
    func migratesBEKRestorePopulation() throws {
        let (vault, km, container) = try makeVault()
        let distributionID = UUID()   // never a real VaultEntry.id
        let attr = try makeShardAttribute(signer: km, entryID: distributionID)
        try insertLegacyRow(vault: vault, km: km, entryID: distributionID, attribute: attr, senderIdentifier: "trustee-0")

        try vault.migrateReconstructShardsIfNeeded()

        #expect(try legacyRowCount(in: container) == 0, "source row must be deleted after migration")
        let collected = try vault.collectedShards(forAttributeID: distributionID)
        #expect(collected.count == 1)
        #expect(collected.first?.attribute.id == attr.id)
        #expect(collected.first?.sender == TrusteeTag(identifier: "trustee-0"))
    }

    @Test("A PEK population (entryID matching a real VaultEntry) migrates and becomes readable")
    func migratesPEKPopulation() throws {
        let (vault, km, container) = try makeVault()
        let entry = try vault.addEntry(label: "seed", content: Data("payload".utf8), type: .seedPhrase)
        let attr  = try makeShardAttribute(signer: km, entryID: entry.id)
        try insertLegacyRow(vault: vault, km: km, entryID: entry.id, attribute: attr, senderIdentifier: "trustee-0")

        try vault.migrateReconstructShardsIfNeeded()

        #expect(try legacyRowCount(in: container) == 0)
        let collected = try vault.collectedShards(forAttributeID: entry.id)
        #expect(collected.count == 1)
        #expect(collected.first?.attribute.id == attr.id)
    }

    @Test("Both populations present migrate independently, neither contaminating the other")
    func migratesBothPopulationsIndependently() throws {
        let (vault, km, container) = try makeVault()

        let distributionID = UUID()
        let bekAttr = try makeShardAttribute(signer: km, entryID: distributionID)
        try insertLegacyRow(vault: vault, km: km, entryID: distributionID, attribute: bekAttr, senderIdentifier: "trustee-bek")

        let entry = try vault.addEntry(label: "seed", content: Data("payload".utf8), type: .seedPhrase)
        let pekAttr = try makeShardAttribute(signer: km, entryID: entry.id)
        try insertLegacyRow(vault: vault, km: km, entryID: entry.id, attribute: pekAttr, senderIdentifier: "trustee-pek")

        try vault.migrateReconstructShardsIfNeeded()

        #expect(try legacyRowCount(in: container) == 0)
        let bekCollected = try vault.collectedShards(forAttributeID: distributionID)
        let pekCollected = try vault.collectedShards(forAttributeID: entry.id)
        #expect(bekCollected.count == 1 && bekCollected.first?.attribute.id == bekAttr.id)
        #expect(pekCollected.count == 1 && pekCollected.first?.attribute.id == pekAttr.id)
    }

    @Test("Many single-sender legacy rows for one secret collapse into one target row's shard slots")
    func manyRowsCollapseToOneTargetRow() throws {
        let (vault, km, container) = try makeVault()
        let distributionID = UUID()

        var attrs: [SignedAttribute] = []
        for i in 0..<5 {
            let attr = try makeShardAttribute(signer: km, entryID: distributionID)
            try insertLegacyRow(vault: vault, km: km, entryID: distributionID, attribute: attr, senderIdentifier: "trustee-\(i)")
            attrs.append(attr)
        }
        #expect(try legacyRowCount(in: container) == 5, "five distinct legacy rows before migration")

        try vault.migrateReconstructShardsIfNeeded()

        #expect(try legacyRowCount(in: container) == 0, "all five source rows deleted")
        let collected = try vault.collectedShards(forAttributeID: distributionID)
        #expect(collected.count == 5, "all five shards collapsed into one target row's slots")
        let collectedIDs = Set(collected.map { $0.attribute.id })
        #expect(collectedIDs == Set(attrs.map { $0.id }))
    }

    @Test("Running migration twice is idempotent — no duplication, no error")
    func migrationIsIdempotent() throws {
        let (vault, km, container) = try makeVault()
        let distributionID = UUID()
        let attr = try makeShardAttribute(signer: km, entryID: distributionID)
        try insertLegacyRow(vault: vault, km: km, entryID: distributionID, attribute: attr, senderIdentifier: "trustee-0")

        try vault.migrateReconstructShardsIfNeeded()
        try vault.migrateReconstructShardsIfNeeded()   // second pass — nothing left to migrate

        #expect(try legacyRowCount(in: container) == 0)
        let collected = try vault.collectedShards(forAttributeID: distributionID)
        #expect(collected.count == 1, "no duplication from running migration a second time")
    }
}

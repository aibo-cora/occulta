//
//  ReconstructShardMigrationTests.swift
//  OccultaTests
//
//  Stage 5 of the RECOVERY_BUFFER_LAYERING.md §9.3 restore-refactor plan —
//  migrateReconstructShardsIfNeeded() moves any leftover ReconstructShard rows (the
//  retired pre-§9.3 mechanism) into PendingShamirSecretRestore. Needs a real Secure
//  Enclave: absorbShard seals PendingShamirSecretRestore.attributeID/.deletionToken
//  under the ambient Manager.Key() local key, never the injected key manager — see
//  ShardCustodyTests.swift's ReconstructionBufferTests for the fuller trap explanation.
//

import Testing
import CryptoKit
import SwiftData
import Foundation
import LocalAuthentication
@testable import Occulta

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

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

/// Inserts a legacy `ReconstructShard` row directly, sealed exactly as the retired
/// mechanism used to seal it — bypassing `absorbShard` entirely, since the whole point
/// is to fix a population that predates it.
@MainActor
private func insertLegacyRow(
    vault: VaultManager,
    km: TestKeyManager,
    entryID: UUID,
    attribute: SignedAttribute,
    senderIdentifier: String
) throws {
    guard let restoreKey = try km.deriveRestoreVaultKey() else {
        Issue.record("expected restore vault key")
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

@Suite("ReconstructShard → PendingShamirSecretRestore migration", .enabled(if: secureEnclaveAvailable()))
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
        #expect(collected.first?.senderIdentifier == "trustee-0")
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

    @Test("Migrated shards drive finalisation exactly like directly-absorbed ones")
    func migratedShardsFinalizeNormally() throws {
        let (vault, km, container) = try makeVault()
        let entry      = try vault.addEntry(label: "seed", content: Data("payload".utf8), type: .seedPhrase)
        let recipients = try makeProfilesForMigrationTests(count: 2)
        let attrs       = try vault.prepareShards(for: entry.id, threshold: 2, recipients: recipients)

        // Both shards arrive via the legacy mechanism.
        try insertLegacyRow(vault: vault, km: km, entryID: entry.id, attribute: attrs[0], senderIdentifier: recipients[0].identifier)
        try insertLegacyRow(vault: vault, km: km, entryID: entry.id, attribute: attrs[1], senderIdentifier: recipients[1].identifier)

        try vault.migrateReconstructShardsIfNeeded()
        try vault.tryFinalizeReconstruction(entryID: entry.id)

        #expect(try legacyRowCount(in: container) == 0)
        #expect(try vault.decryptLabel(for: entry) == "seed")
        #expect(try vault.collectedShards(forAttributeID: entry.id).isEmpty,
                "row must be orphaned after successful finalisation, same as a directly-absorbed one")
    }
}

@MainActor
private func makeProfilesForMigrationTests(count: Int) throws -> [Contact.Profile] {
    let schema = Schema([
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
    ])
    let config    = ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)
    let container = try ModelContainer(for: schema, configurations: [config])
    let ctx       = ModelContext(container)

    return (0..<count).map { i in
        let p = Contact.Profile(
            identifier: UUID().uuidString,
            givenName: "Trustee", familyName: "\(i)",
            middleName: "", nickname: "",
            organizationName: "", departmentName: "", jobTitle: ""
        )
        ctx.insert(p)
        return p
    }
}

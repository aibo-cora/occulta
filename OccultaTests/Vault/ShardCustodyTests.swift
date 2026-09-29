//
//  ShardCustodyTests.swift
//  OccultaTests
//
//  Phase 2 — ShardCustodyManager + reconstruction buffer (Vault+Manager+ReturnBuffer).
//  Simulator-safe — uses TestKeyManager throughout.
//
//  Coverage:
//  - CustodyShard sealed-blob round-trip and AAD binding.
//  - ReconstructShard sealed-blob round-trip and AAD binding.
//  - .distribute / .replace dispatch.
//  - Handed-back backup-key pieces banked in the restore buffer; per-entry pieces are not
//    (per-entry splitting retired, decisions.md "Retire per-entry splitting").
//

import Testing
import CryptoKit
import SwiftData
import Foundation
import LocalAuthentication
@testable import Occulta

// MARK: - Helpers

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

@MainActor
private func makeAlice(
    inactivityTimeout: TimeInterval = 5 * 60
) throws -> (vault: VaultManager, km: TestKeyManager, container: ModelContainer) {
    let alice  = TestKeyManager()
    let schema = Schema([
        VaultEntry.self,
        CustodyShard.self,
        Vault.self,
        PendingShamirSecretRestore.self
    ])
    let config    = ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)
    let container = try ModelContainer(for: schema, configurations: [config])
    let vault     = VaultManager(modelContainer: container, keyManager: alice, inactivityTimeout: inactivityTimeout)
    return (vault, alice, container)
}

@MainActor
private func makeBob() throws -> (custody: ShardCustodyManager, km: TestKeyManager, container: ModelContainer) {
    let bob    = TestKeyManager()
    let schema = Schema([
        VaultEntry.self,
        CustodyShard.self,
        ReconstructShard.self
    ])
    let config    = ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)
    let container = try ModelContainer(for: schema, configurations: [config])
    let custody   = ShardCustodyManager(modelContainer: container, keyManager: bob)
    return (custody, bob, container)
}

/// Build a SignedAttribute as if `signer` (Alice) had signed it — a backup-key piece
/// unless `label` says otherwise. The value has a real piece's 33 bytes (x-coordinate +
/// 32-byte share), which the restore buffer's codec requires.
@MainActor
private func makeShardAttr(
    signer: TestKeyManager,
    entryID: UUID = UUID(),
    shardBytes: Data = Data([UInt8(1)]) + Data.randomBytes(32),
    label: String = SignedAttribute.backupKeyPieceLabel
) throws -> SignedAttribute {
    let attrID    = UUID()
    let createdAt = Date()
    let payload   = SignedAttribute.signingPayload(
        id:        attrID,
        category:  .shard,
        value:     shardBytes,
        entryID:   entryID,
        createdAt: createdAt,
        expiresAt: nil
    )
    let signature = try signer.signData(payload)
    return SignedAttribute(
        id:        attrID,
        label:     label,
        value:     shardBytes,
        category:  .shard,
        signature: signature,
        createdAt: createdAt,
        expiresAt: nil,
        entryID:   entryID
    )
}

@MainActor
private func custodyShardCount(in container: ModelContainer) throws -> Int {
    let ctx = ModelContext(container)
    return try ctx.fetch(FetchDescriptor<CustodyShard>()).count
}

/// Sum of buffered shards across every given entry — the reconstruction buffer is now
/// keyed per-attributeID (`PendingShamirSecretRestore`), not one shared pool, so a test
/// that wants a total across several entries names them explicitly.
@MainActor
private func reconstructShardCount(vault: VaultManager, entryIDs: [UUID]) throws -> Int {
    try entryIDs.reduce(0) { total, id in
        total + (try vault.collectedShards(forAttributeID: id).count)
    }
}

// MARK: - Recovery buffer key derivation

@Suite("Recovery buffer key — derivation")
@MainActor struct RecoveryBufferKeyTests {

    @Test("deriveRestoreVaultKey() returns a 256-bit key")
    func returnsKey() throws {
        let km  = TestKeyManager()
        let key = try km.deriveRestoreVaultKey()
        #expect(key != nil)
        var byteCount = 0
        key?.withUnsafeBytes { byteCount = $0.count }
        #expect(byteCount == 32)
    }

    @Test("Recovery buffer key is distinct from shard custody key (HKDF domain separation)")
    func distinctFromCustodyKey() throws {
        let km = TestKeyManager()
        var restoreBytes  = Data()
        var custodyBytes = Data()
        try km.deriveRestoreVaultKey()?.withUnsafeBytes { restoreBytes  = Data($0) }
        try km.deriveShardCustodyKey()?.withUnsafeBytes   { custodyBytes = Data($0) }
        #expect(restoreBytes.count == 32 && custodyBytes.count == 32)
        #expect(restoreBytes != custodyBytes,
                "buffer key and custody key must differ — same SE source, different HKDF info")
    }

    /// Bug 137: renaming this string re-keys every banked piece on disk, and v1.10.3's
    /// `ReconstructShard` rows stop opening. Pinned to the exact bytes v1.10.3 used.
    @Test("The restore vault key's info string is still v1.10.3's")
    func infoStringIsV1_10_3s() throws {
        let legacy = Data("Occulta-v1-recovery-buffer-2026".utf8)
        #expect(SaltInfo.kRestoreVaultKeyInfo == legacy)

        let km = TestKeyManager()
        var current = Data(), v1_10_3 = Data()
        try km.deriveRestoreVaultKey()?.withUnsafeBytes { current = Data($0) }
        try km.deriveCustodySEKey(info: legacy)?.withUnsafeBytes { v1_10_3 = Data($0) }
        #expect(current.count == 32 && current == v1_10_3)
    }

    @Test("Recovery buffer key is deterministic for the same key manager")
    func deterministic() throws {
        let km = TestKeyManager()
        var b1 = Data(), b2 = Data()
        try km.deriveRestoreVaultKey()?.withUnsafeBytes { b1 = Data($0) }
        try km.deriveRestoreVaultKey()?.withUnsafeBytes { b2 = Data($0) }
        #expect(b1 == b2)
    }
}

// MARK: - .distribute path

@Suite("ShardCustodyManager — .distribute")
@MainActor struct DistributeTests {

    @Test(".distribute persists a CustodyShard sealed under the custody key")
    func storesShardOnDistribute() throws {
        let alice = TestKeyManager()
        let (custody, _, container) = try makeBob()

        let attr = try makeShardAttr(signer: alice)
        let op   = OccultaBundle.ShardOperation(kind: .distribute, attribute: attr)
        let alicePub = try alice.retrieveIdentity()

        _ = custody.handleInbound(
            shardOperations:  [op],
            custodyManifest:  nil,
            senderPublicKey:  alicePub,
            senderIdentifier: "alice",
            vaultManager:     try makeAlice().vault
        )

        #expect(try custodyShardCount(in: container) == 1)
    }

    @Test(".distribute with a wrong-key signature is rejected — no row inserted")
    func badSignatureRejected() throws {
        let alice    = TestKeyManager()   // signs the attr
        let imposter = TestKeyManager()   // pretends to be alice
        let (custody, _, container) = try makeBob()

        let attr = try makeShardAttr(signer: alice)
        let op   = OccultaBundle.ShardOperation(kind: .distribute, attribute: attr)

        // Verifying against the imposter's public key MUST fail and skip insert.
        let imposterPub = try imposter.retrieveIdentity()
        _ = custody.handleInbound(
            shardOperations:  [op],
            custodyManifest:  nil,
            senderPublicKey:  imposterPub,
            senderIdentifier: "imposter",
            vaultManager:     try makeAlice().vault
        )

        #expect(try custodyShardCount(in: container) == 0)
    }

    @Test(".distribute with replacesID deletes the prior CustodyShard")
    func replacesIDDeletesOld() throws {
        let alice = TestKeyManager()
        let (custody, _, container) = try makeBob()
        let alicePub = try alice.retrieveIdentity()
        let entryID  = UUID()

        // First distribution.
        let oldAttr = try makeShardAttr(signer: alice, entryID: entryID, shardBytes: Data([0x01, 0x02]))
        _ = custody.handleInbound(
            shardOperations:  [.init(kind: .distribute, attribute: oldAttr)],
            custodyManifest:  nil,
            senderPublicKey:  alicePub,
            senderIdentifier: "alice",
            vaultManager:     try makeAlice().vault
        )
        #expect(try custodyShardCount(in: container) == 1)

        // Re-distribution — .replace supersedes oldAttr.
        let newAttr = try makeShardAttr(signer: alice, entryID: entryID, shardBytes: Data([0x09, 0x0A]))
        _ = custody.handleInbound(
            shardOperations:  [.init(kind: .replace, attribute: newAttr, attributeID: oldAttr.id)],
            custodyManifest:  nil,
            senderPublicKey:  alicePub,
            senderIdentifier: "alice",
            vaultManager:     try makeAlice().vault
        )

        // Old row replaced by new — count is still 1, but the surviving row carries newAttr.
        #expect(try custodyShardCount(in: container) == 1)
    }

    @Test(".replace cannot delete another owner's shard by targeting their attributeID")
    func replaceCannotDeleteAnotherOwnersShard() throws {
        let alice   = TestKeyManager()
        let mallory = TestKeyManager()
        let (custody, _, container) = try makeBob()
        let alicePub   = try alice.retrieveIdentity()
        let malloryPub = try mallory.retrieveIdentity()

        // Alice distributes a real shard.
        let aliceAttr = try makeShardAttr(signer: alice, shardBytes: Data([0x01, 0x02]))
        _ = custody.handleInbound(
            shardOperations:  [.init(kind: .distribute, attribute: aliceAttr)],
            custodyManifest:  nil,
            senderPublicKey:  alicePub,
            senderIdentifier: "alice",
            vaultManager:     try makeAlice().vault
        )
        #expect(try custodyShardCount(in: container) == 1)

        // Mallory sends her own genuinely-signed .replace, but targets Alice's real
        // attributeID as oldID — simulating an attacker who learned it via manifest
        // traffic or otherwise, with no relationship to Alice's shard at all.
        let malloryAttr = try makeShardAttr(signer: mallory, shardBytes: Data([0x09, 0x0A]))
        _ = custody.handleInbound(
            shardOperations:  [.init(kind: .replace, attribute: malloryAttr, attributeID: aliceAttr.id)],
            custodyManifest:  nil,
            senderPublicKey:  malloryPub,
            senderIdentifier: "mallory",
            vaultManager:     try makeAlice().vault
        )

        // Mallory's own shard is stored, but Alice's must survive untouched — Mallory
        // has no ownership relationship to the row her oldID happened to name.
        let ctx  = ModelContext(container)
        let rows = try ctx.fetch(FetchDescriptor<CustodyShard>())
        #expect(rows.count == 2)

        let byOwner = Dictionary(uniqueKeysWithValues: custody.heldShards(from: rows).map { ($0.ownerContactIdentifier, $0.count) })
        #expect(byOwner["alice"] == 1)
        #expect(byOwner["mallory"] == 1)
    }
}

// MARK: - Re-sealing survivors on deletion (Bug 130)

/// Every surviving row's sealed bytes and decrypted signed-attribute ID, keyed by row ID.
@MainActor
private func custodySnapshot(in container: ModelContainer, using km: TestKeyManager) throws -> [UUID: (bytes: Data, attributeID: UUID)] {
    let key  = try #require(try km.deriveShardCustodyKey())
    let rows = try ModelContext(container).fetch(FetchDescriptor<CustodyShard>())
    return try Dictionary(uniqueKeysWithValues: rows.map { row in
        let box     = try AES.GCM.SealedBox(combined: row.encryptedPayload)
        let plain   = try AES.GCM.open(box, using: key, authenticating: row.id.uuidString.data(using: .utf8)!)
        let payload = try JSONDecoder().decode(CustodyShard.Payload.self, from: plain)
        return (row.id, (row.encryptedPayload, payload.signedAttribute.id))
    })
}

@MainActor
private func distribute(
    _ attr: SignedAttribute,
    kind: OccultaBundle.ShardOperation.Kind = .distribute,
    replacing oldID: UUID? = nil,
    from signer: TestKeyManager,
    as identifier: String,
    into custody: ShardCustodyManager,
    vault: VaultManager
) throws {
    _ = custody.handleInbound(
        shardOperations:  [.init(kind: kind, attribute: attr, attributeID: oldID)],
        custodyManifest:  nil,
        senderPublicKey:  try signer.retrieveIdentity(),
        senderIdentifier: identifier,
        vaultManager:     vault
    )
}

/// Bug 130: a deletion that left every surviving row byte-identical let a two-snapshot diff
/// point at exactly the row that went. Each path that deletes custody rows must re-seal every
/// survivor with a fresh nonce, same content.
@Suite("ShardCustodyManager — deletions re-seal survivors (Bug 130)")
@MainActor struct CustodyDeletionResealTests {

    /// Asserts `before`'s rows minus `deleted` are exactly `after`'s pre-existing rows, each with
    /// new bytes and the same content.
    private func expectResealed(
        before: [UUID: (bytes: Data, attributeID: UUID)],
        after:  [UUID: (bytes: Data, attributeID: UUID)],
        deleted: Set<UUID>
    ) {
        let survivors = Set(before.keys).subtracting(deleted)
        #expect(!survivors.isEmpty)
        #expect(deleted.allSatisfy { after[$0] == nil }, "deleted rows must be gone")
        for id in survivors {
            #expect(after[id]?.bytes != before[id]?.bytes, "a surviving row must be re-sealed")
            #expect(after[id]?.attributeID == before[id]?.attributeID, "re-sealing must not change content")
        }
    }

    @Test(".distribute under a new owner key re-seals every survivor")
    func distributeResealsSurvivors() throws {
        let aliceOld = TestKeyManager()
        let aliceNew = TestKeyManager()
        let carol    = TestKeyManager()
        let (custody, km, container) = try makeBob()
        let vault = try makeAlice().vault

        let oldAttr = try makeShardAttr(signer: aliceOld)
        try distribute(oldAttr, from: aliceOld, as: "alice", into: custody, vault: vault)
        try distribute(try makeShardAttr(signer: carol), from: carol, as: "carol", into: custody, vault: vault)
        let before = try custodySnapshot(in: container, using: km)

        // Alice re-keyed: her old-fingerprint shard is deleted as the new one lands.
        try distribute(try makeShardAttr(signer: aliceNew), from: aliceNew, as: "alice", into: custody, vault: vault)

        let after = try custodySnapshot(in: container, using: km)
        #expect(after.count == 2)
        self.expectResealed(before: before, after: after, deleted: [try self.rowID(of: oldAttr, in: before)])
    }

    @Test(".replace re-seals every survivor")
    func replaceResealsSurvivors() throws {
        let alice = TestKeyManager()
        let carol = TestKeyManager()
        let (custody, km, container) = try makeBob()
        let vault = try makeAlice().vault

        let oldAttr = try makeShardAttr(signer: alice)
        try distribute(oldAttr, from: alice, as: "alice", into: custody, vault: vault)
        try distribute(try makeShardAttr(signer: alice), from: alice, as: "alice", into: custody, vault: vault)
        try distribute(try makeShardAttr(signer: carol), from: carol, as: "carol", into: custody, vault: vault)
        let before = try custodySnapshot(in: container, using: km)

        try distribute(try makeShardAttr(signer: alice), kind: .replace, replacing: oldAttr.id,
                       from: alice, as: "alice", into: custody, vault: vault)

        let after = try custodySnapshot(in: container, using: km)
        #expect(after.count == 3)
        self.expectResealed(before: before, after: after, deleted: [try self.rowID(of: oldAttr, in: before)])
    }

    private func rowID(of attr: SignedAttribute, in snapshot: [UUID: (bytes: Data, attributeID: UUID)]) throws -> UUID {
        try #require(snapshot.first { $0.value.attributeID == attr.id }?.key)
    }
}

// MARK: - Handback and the restore buffer

// Needs a real Secure Enclave: PendingShamirSecretRestore.attributeID/.deletionToken are
// sealed under the ambient Manager.Key() local key (never the injected key manager) —
// the same forced split BackupEncryptionKey.depth/.deletionToken already uses, and every
// test here goes through acceptReturnedShard, which touches that field. No seam reaches
// it, so unlike this file's other suites this one cannot run on TestKeyManager alone.
@Suite("Restore buffer — handed-back pieces", .enabled(if: secureEnclaveAvailable()))
@MainActor struct ReconstructionBufferTests {

    @Test("acceptReturnedShard banks a backup-key piece in a row that decrypts under the restore vault key")
    func acceptInsertsRow() throws {
        let (vault, alice, container) = try makeAlice()
        let distributionID = UUID()
        let piece = try makeShardAttr(signer: alice, entryID: distributionID)

        try vault.acceptReturnedShard(piece, senderIdentifier: "contact-0")

        #expect(try reconstructShardCount(vault: vault, entryIDs: [distributionID]) == 1)

        // The row's attributeID decrypts (under the ambient local key) to the piece's
        // distribution ID, and its shards decode to the one banked piece.
        let localKey = try #require(try Manager.Key().createHybridLocalEncryptionKey())
        let row = try #require(ModelContext(container).fetch(FetchDescriptor<PendingShamirSecretRestore>()).first)
        let idBytes = try #require(row.attributeID?.decrypt(using: localKey))
        #expect(idBytes == withUnsafeBytes(of: distributionID.uuid) { Data($0) })
        #expect(try vault.collectedShards(forAttributeID: distributionID).first?.attribute.id == piece.id)
    }

    @Test("Wrong id in AAD invalidates GCM tag — shards no longer decrypt")
    func aadBindingHolds() throws {
        let (vault, alice, container) = try makeAlice()
        try vault.acceptReturnedShard(try makeShardAttr(signer: alice), senderIdentifier: "contact-0")

        // Must be Alice's own key manager — deriveRestoreVaultKey() is deterministic per
        // key manager (RecoveryBufferKeyTests above), so a different instance would not
        // match what absorbShard sealed the row under.
        guard let restoreKey = try alice.deriveRestoreVaultKey() else {
            Issue.record("expected restore vault key"); return
        }
        let row = try #require(ModelContext(container).fetch(FetchDescriptor<PendingShamirSecretRestore>()).first)
        let box = try AES.GCM.SealedBox(combined: try #require(row.shards))

        // Wrong AAD (a different UUID) — GCM authentication tag must reject it.
        let wrongAAD = UUID().uuidString.data(using: .utf8)!
        #expect(throws: (any Error).self) {
            _ = try AES.GCM.open(box, using: restoreKey, authenticating: wrongAAD)
        }

        // Correct AAD — must succeed.
        #expect(throws: Never.self) {
            _ = try AES.GCM.open(box, using: restoreKey, authenticating: row.aad())
        }
    }

    @Test("acceptReturnedShard ignores duplicate attrID")
    func duplicateAttrDeduplicated() throws {
        let (vault, alice, _) = try makeAlice()
        let distributionID = UUID()
        let piece = try makeShardAttr(signer: alice, entryID: distributionID)

        try vault.acceptReturnedShard(piece, senderIdentifier: "contact-0")
        try vault.acceptReturnedShard(piece, senderIdentifier: "contact-0")  // duplicate

        #expect(try reconstructShardCount(vault: vault, entryIDs: [distributionID]) == 1)
    }

    /// A trustee hands back every piece it holds under the owner's old key, per-entry
    /// ones included; `restoreBackup` would try each such group against the whole file.
    @Test("A handed-back per-entry piece is not banked")
    func perEntryPieceNotBanked() throws {
        let (vault, alice, container) = try makeAlice()
        let entryID = UUID()

        try vault.acceptReturnedShard(try makeShardAttr(signer: alice, entryID: entryID, label: "vault-shard"),
                                      senderIdentifier: "contact-0")

        #expect(try reconstructShardCount(vault: vault, entryIDs: [entryID]) == 0)
        #expect(try ModelContext(container).fetch(FetchDescriptor<PendingShamirSecretRestore>()).isEmpty)
    }
}

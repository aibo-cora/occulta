//
//  ShardManifestTests.swift
//  OccultaTests
//
//  Tests for the manifest-based shard reconciliation protocol.
//  Cases match SHARD_PROTOCOL_CASES.md 1-19. The owner's status cases (5, 6, 12, 17) went
//  with per-entry splitting; backup-key statuses are covered by BackupPieceReconcileTests.
//
//  Actors used throughout:
//    Alice = shard owner (VaultManager + TestKeyManager)
//    Bob   = trustee    (ShardCustodyManager + TestKeyManager)
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

// MARK: - Helpers shared across suites

/// Alice's in-memory test setup: vault + distribute queue in one container.
@MainActor
private func makeAlice() throws -> (
    vault:     VaultManager,
    custody:   ShardCustodyManager,
    km:        TestKeyManager,
    container: ModelContainer
) {
    let km     = TestKeyManager()
    let schema = Schema([
        VaultEntry.self,
        CustodyShard.self,
        Vault.self,
        PendingShamirSecretRestore.self,
        PendingShardDistribute.self,
        PendingShardStatusUpdate.self,
        PotentiallyLostShard.self
    ])
    let cfg       = ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)
    let container = try ModelContainer(for: schema, configurations: [cfg])
    let vault     = VaultManager(modelContainer: container, keyManager: km)
    let custody   = ShardCustodyManager(modelContainer: container, keyManager: km)
    return (vault, custody, km, container)
}

/// Bob's in-memory test setup: custody store only.
@MainActor
private func makeBob() throws -> (
    custody:   ShardCustodyManager,
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
        PotentiallyLostShard.self
    ])
    let cfg       = ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)
    let container = try ModelContainer(for: schema, configurations: [cfg])
    let custody   = ShardCustodyManager(modelContainer: container, keyManager: km)
    return (custody, km, container)
}

/// Build and sign a shard-category SignedAttribute.
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
        id: attrID, label: SignedAttribute.backupKeyPieceLabel, value: shardBytes, category: .shard,
        signature: try signer.signData(payload),
        createdAt: createdAt, expiresAt: nil, entryID: entryID
    )
}

@MainActor
private func custodyCount(in container: ModelContainer) throws -> Int {
    try ModelContext(container).fetch(FetchDescriptor<CustodyShard>()).count
}

@MainActor
private func distributeRowCount(in container: ModelContainer) throws -> Int {
    try ModelContext(container).fetch(FetchDescriptor<PendingShardDistribute>()).count
}

/// Distribute a shard from Alice to Bob, returns the SignedAttribute.
@MainActor
private func distribute(
    from aliceKM: TestKeyManager,
    to bobCustody: ShardCustodyManager,
    vaultManager: VaultManager,
    entryID: UUID = UUID()
) throws -> SignedAttribute {
    let attr     = try makeAttr(signer: aliceKM, entryID: entryID)
    let alicePub = try aliceKM.retrieveIdentity()
    _ = bobCustody.handleInbound(
        shardOperations:  [.init(kind: .distribute, attribute: attr)],
        custodyManifest:  nil,
        senderPublicKey:  alicePub,
        senderIdentifier: "alice",
        vaultManager:     vaultManager
    )
    return attr
}

// MARK: - Case 1: Normal distribution (happy path)

@Suite("Case 1 — Normal distribution")
@MainActor struct Case1_NormalDistribution {

    @Test("Bob stores shard after .distribute; custodyManifest includes its ID")
    func bobStoresAndManifests() throws {
        let (vault, _, km, _)         = try makeAlice()
        let (bobCustody, _, bobCont)  = try makeBob()
        vault.unlock(context: LAContext())

        let attr = try distribute(from: km, to: bobCustody, vaultManager: vault)
        #expect(try custodyCount(in: bobCont) == 1)

        let manifest = try bobCustody.buildCustodyManifest(for: "alice")
        #expect(manifest.contains(attr.id))
    }
}

// MARK: - Case 2: Distribution bundle lost in transit

@Suite("Case 2 — Distribution bundle lost, retry")
@MainActor struct Case2_DistributionLost {

    @Test("PendingShardDistribute row persists until manifest confirms it")
    func retryUntilConfirmed() throws {
        let (_, aliceCustody, km, aliceCont) = try makeAlice()
        let attr = try makeAttr(signer: km)

        // Alice queues a distribute row (simulating bundle lost in transit).
        try aliceCustody.queueDistribute(attribute: attr, for: "bob")
        #expect(try distributeRowCount(in: aliceCont) == 1)

        // Bob's manifest doesn't list the piece yet: delivery is still in flight.
        try aliceCustody.processInboundManifest([], from: "bob")
        #expect(try distributeRowCount(in: aliceCont) == 1, "row retained — delivery in flight")
    }
}

// MARK: - Case 3: Replacement (PEK rotated)

@Suite("Case 3 — Replacement shard supersedes old")
@MainActor struct Case3_Replacement {

    @Test(".replace stores new shard and deletes old in one operation")
    func replaceDeletesOld() throws {
        let (vault, _, km, _) = try makeAlice()
        let (bobCustody, _, bobCont) = try makeBob()
        vault.unlock(context: LAContext())

        let entryID = UUID()
        let oldAttr = try makeAttr(signer: km, entryID: entryID, shardBytes: Data([0x01]))
        let alicePub = try km.retrieveIdentity()

        _ = bobCustody.handleInbound(
            shardOperations:  [.init(kind: .distribute, attribute: oldAttr)],
            custodyManifest:  nil,
            senderPublicKey:  alicePub,
            senderIdentifier: "alice",
            vaultManager:     vault
        )
        #expect(try custodyCount(in: bobCont) == 1)

        let newAttr = try makeAttr(signer: km, entryID: entryID, shardBytes: Data([0x02]))
        _ = bobCustody.handleInbound(
            shardOperations:  [.init(kind: .replace, attribute: newAttr, attributeID: oldAttr.id)],
            custodyManifest:  nil,
            senderPublicKey:  alicePub,
            senderIdentifier: "alice",
            vaultManager:     vault
        )

        #expect(try custodyCount(in: bobCont) == 1, "one shard: new replaces old")
        let manifest = try bobCustody.buildCustodyManifest(for: "alice")
        #expect(manifest.contains(newAttr.id))
        #expect(!manifest.contains(oldAttr.id))
    }
}

// MARK: - Case 7: Owner key rotation triggers .handback

@Suite("Case 7 — Owner key rotation: handback computed live")
@MainActor struct Case7_KeyRotation {

    @Test("buildShardOperations emits .handback for mismatch-fingerprint shards")
    func mismatchFingerprintHandback() throws {
        let aliceOld = TestKeyManager() // Alice's old key
        let aliceNew = TestKeyManager() // Alice's new key (new device)
        let (vault, _, _, _)         = try makeAlice()
        let (bobCustody, _, bobCont) = try makeBob()
        vault.unlock(context: LAContext())

        let aliceOldPub = try aliceOld.retrieveIdentity()
        let aliceNewPub = try aliceNew.retrieveIdentity()

        // Bob stores a shard for Alice under her OLD fingerprint.
        _ = try distribute(from: aliceOld, to: bobCustody, vaultManager: vault)
        #expect(try custodyCount(in: bobCont) == 1)

        // Bob's contact record now has Alice's NEW public key.
        // buildShardOperations detects mismatch → includes .handback.
        let ops = try bobCustody.buildShardOperations(for: "alice", currentContactPublicKey: aliceNewPub)
        #expect(ops.contains { $0.kind == .handback }, "must handback mismatch shard")
        _ = aliceOldPub // silence warning
    }
}

// MARK: - Case 8: Fresh distribution deletes mismatch shards

@Suite("Case 8 — Fresh distribute clears mismatch shards")
@MainActor struct Case8_FreshDistribute {

    @Test(".distribute with new fingerprint deletes all mismatch shards for that contact")
    func freshDistributeClearsMismatch() throws {
        let aliceOld = TestKeyManager()
        let aliceNew = TestKeyManager()
        let (vault, _, _, _)         = try makeAlice()
        let (bobCustody, _, bobCont) = try makeBob()
        vault.unlock(context: LAContext())

        let aliceNewPub = try aliceNew.retrieveIdentity()

        // Bob holds old-fingerprint shard.
        _ = try distribute(from: aliceOld, to: bobCustody, vaultManager: vault)
        #expect(try custodyCount(in: bobCont) == 1)

        // Alice redistributes with her new key → new fingerprint.
        _ = try distribute(from: aliceNew, to: bobCustody, vaultManager: vault)

        // Mismatch shard is gone; only the new one remains.
        #expect(try custodyCount(in: bobCont) == 1)
        let manifest = try bobCustody.buildCustodyManifest(for: "alice")
        #expect(manifest.count == 1)

        // buildShardOperations no longer emits .handback (no mismatch shards left).
        let ops = try bobCustody.buildShardOperations(for: "alice", currentContactPublicKey: aliceNewPub)
        #expect(!ops.contains { $0.kind == .handback })
    }
}

// MARK: - Case 13: Vault locked when .handback arrives

// Needs a real Secure Enclave — .handback routes through acceptReturnedShard/absorbShard,
// which seals PendingShamirSecretRestore.attributeID/.deletionToken under the ambient
// Manager.Key() local key, never the injected key manager (see ShardCustodyTests.swift's
// ReconstructionBufferTests for the fuller trap explanation).
@Suite("Case 13 — Vault locked when .handback arrives", .enabled(if: secureEnclaveAvailable()))
@MainActor struct Case13_LockedHandback {

    @Test(".handback inserts a PendingShamirSecretRestore row even while vault is locked")
    func handbackBufferedWhenLocked() throws {
        let (vault, aliceCustody, km, _) = try makeAlice()
        let distributionID = UUID()
        // A genuine piece's value is 33 bytes; the restore buffer's codec requires it.
        let piece = try makeAttr(signer: km, entryID: distributionID, shardBytes: Data([UInt8(1)]) + Data.randomBytes(32))
        #expect(!vault.isUnlocked)

        // Bob sends .handback with the piece Alice's own key signed.
        _ = aliceCustody.handleInbound(
            shardOperations:  [.init(kind: .handback, attribute: piece)],
            custodyManifest:  nil,
            senderPublicKey:  try km.retrieveIdentity(),
            senderIdentifier: "bob",
            vaultManager:     vault
        )

        // Buffer row absorbed under the restore vault key (no biometric needed) — readable
        // via collectedShards without unlocking.
        let collected = try vault.collectedShards(forAttributeID: distributionID)
        #expect(collected.count == 1, "buffer row inserted while locked")
    }
}

// MARK: - Case 15: Duplicate .distribute (idempotency)

@Suite("Case 15 — Duplicate .distribute is idempotent")
@MainActor struct Case15_DuplicateDistribute {

    @Test("Second .distribute with same attrID does not create a second CustodyShard row")
    func duplicateDistributeDeduplicates() throws {
        let (vault, _, km, _)        = try makeAlice()
        let (bobCustody, _, bobCont) = try makeBob()
        vault.unlock(context: LAContext())

        let attr     = try makeAttr(signer: km)
        let alicePub = try km.retrieveIdentity()
        let op       = OccultaBundle.ShardOperation(kind: .distribute, attribute: attr)

        _ = bobCustody.handleInbound(shardOperations: [op], custodyManifest: nil, senderPublicKey: alicePub,
                                     senderIdentifier: "alice", vaultManager: vault)
        _ = bobCustody.handleInbound(shardOperations: [op], custodyManifest: nil, senderPublicKey: alicePub,
                                     senderIdentifier: "alice", vaultManager: vault)

        #expect(try custodyCount(in: bobCont) == 1, "duplicate must not insert a second row")
    }
}

// MARK: - Case 16: Tampered shard (signature verification)

@Suite("Case 16 — Tampered shard is rejected")
@MainActor struct Case16_TamperedShard {

    @Test(".distribute signed by wrong key is rejected — no row inserted")
    func wrongSignatureRejected() throws {
        let alice    = TestKeyManager()
        let imposter = TestKeyManager()
        let (vault, _, _, _)         = try makeAlice()
        let (bobCustody, _, bobCont) = try makeBob()
        vault.unlock(context: LAContext())

        let attr        = try makeAttr(signer: alice)
        let imposterPub = try imposter.retrieveIdentity()

        _ = bobCustody.handleInbound(
            shardOperations:  [.init(kind: .distribute, attribute: attr)],
            custodyManifest:  nil,
            senderPublicKey:  imposterPub,
            senderIdentifier: "imposter",
            vaultManager:     vault
        )

        #expect(try custodyCount(in: bobCont) == 0)
    }
}

// MARK: - Case 19: ShardStatus.revokePending (legacy decode)

@Suite("Case 19 — revokePending is decoded as inactive (legacy compat)")
@MainActor struct Case19_RevokePending {

    @Test("ShardStatus.revokePending decodes from JSON without error")
    func revokePendingDecodesOK() throws {
        let json = #"{"contactIdentifier":"bob","attributeID":"11111111-1111-1111-1111-111111111111","status":"revokePending"}"#
        let data   = json.data(using: .utf8)!
        let record = try JSONDecoder().decode(ShardRecord.self, from: data)
        #expect(record.status == .revokePending, "old .revokePending raw value must decode correctly")
    }
}

// MARK: - Manifest protocol invariants

@Suite("Manifest invariants")
@MainActor struct ManifestInvariants {

    @Test("Invariant 2: PendingShardDistribute row is deleted only on manifest confirmation")
    func distributeRowSurvivesSend() throws {
        let (_, aliceCustody, km, aliceCont) = try makeAlice()
        let attr = try makeAttr(signer: km)

        try aliceCustody.queueDistribute(attribute: attr, for: "bob")
        #expect(try distributeRowCount(in: aliceCont) == 1, "row exists after queuing")

        // Build outbound ops (simulates send) — row must NOT be deleted by this.
        _ = try aliceCustody.buildShardOperations(for: "bob", currentContactPublicKey: nil)
        #expect(try distributeRowCount(in: aliceCont) == 1, "row persists until manifest confirms")

        // Manifest confirms → row deleted.
        try aliceCustody.processInboundManifest([attr.id], from: "bob")
        #expect(try distributeRowCount(in: aliceCont) == 0, "row deleted after manifest confirmation")
    }

    @Test("Invariant 3: .handback included on every outbound bundle while mismatch shards exist")
    func handbackContinuesUntilMismatchCleared() throws {
        let aliceOld = TestKeyManager()
        let aliceNew = TestKeyManager()
        let (vault, _, _, _)         = try makeAlice()
        let (bobCustody, _, _)       = try makeBob()
        vault.unlock(context: LAContext())

        let aliceNewPub = try aliceNew.retrieveIdentity()

        // Bob holds mismatch shard.
        _ = try distribute(from: aliceOld, to: bobCustody, vaultManager: vault)

        let ops1 = try bobCustody.buildShardOperations(for: "alice", currentContactPublicKey: aliceNewPub)
        #expect(ops1.contains { $0.kind == .handback }, "handback on first bundle")

        let ops2 = try bobCustody.buildShardOperations(for: "alice", currentContactPublicKey: aliceNewPub)
        #expect(ops2.contains { $0.kind == .handback }, "handback on second bundle — still present")
    }

    @Test("Invariant 4: .distribute op re-included on every bundle until manifest confirms")
    func distributeRetried() throws {
        let (_, aliceCustody, km, _) = try makeAlice()
        try aliceCustody.queueDistribute(attribute: try makeAttr(signer: km), for: "bob")

        let ops1 = try aliceCustody.buildShardOperations(for: "bob", currentContactPublicKey: nil)
        #expect(ops1.contains { $0.kind == .distribute })

        let ops2 = try aliceCustody.buildShardOperations(for: "bob", currentContactPublicKey: nil)
        #expect(ops2.contains { $0.kind == .distribute }, "distribute included again — not fire-and-forget")
    }

    @Test("Invariant 5: unknown JSON fields in SealedPayload are silently ignored (old-build compat)")
    func unknownFieldsIgnored() throws {
        // A v1.10.3 sender still writes `expectedShards`, removed with implicit revoke
        // (bugs.md Bug 141); the payload must still decode, the field dropped unread.
        let original = OccultaBundle.SealedPayload(
            message: Data("hello".utf8),
            custodyManifest: [UUID()]
        )
        var json = try #require(try JSONSerialization.jsonObject(with: JSONEncoder().encode(original)) as? [String: Any])
        json["expectedShards"] = [UUID().uuidString]
        let decoded = try JSONDecoder().decode(
            OccultaBundle.SealedPayload.self, from: try JSONSerialization.data(withJSONObject: json)
        )
        #expect(decoded.custodyManifest?.count == 1)
    }
}

// MARK: - buildCustodyManifest

@Suite("Manifest building helpers")
@MainActor struct ManifestBuilding {

    @Test("buildCustodyManifest returns IDs of all shards Bob holds for Alice")
    func custodyManifestMatchesHeldShards() throws {
        let (vault, _, km, _)        = try makeAlice()
        let (bobCustody, _, _)       = try makeBob()
        vault.unlock(context: LAContext())

        let attr1 = try distribute(from: km, to: bobCustody, vaultManager: vault)
        let attr2 = try distribute(from: km, to: bobCustody, vaultManager: vault)

        let manifest = try bobCustody.buildCustodyManifest(for: "alice")
        #expect(manifest.count == 2)
        #expect(manifest.contains(attr1.id))
        #expect(manifest.contains(attr2.id))
    }

    @Test("buildCustodyManifest returns empty for contacts we hold nothing for")
    func custodyManifestEmptyForOtherContact() throws {
        let (vault, _, km, _)        = try makeAlice()
        let (bobCustody, _, _)       = try makeBob()
        vault.unlock(context: LAContext())

        _ = try distribute(from: km, to: bobCustody, vaultManager: vault)

        let carolManifest = try bobCustody.buildCustodyManifest(for: "carol")
        #expect(carolManifest.isEmpty)
    }
}

// MARK: - handleInbound routing

@Suite("handleInbound — routing coverage")
@MainActor struct HandleInboundRouting {

    @Test("handleInbound returns false when no shard fields are present")
    func returnsFalseWithNoShardData() throws {
        let (vault, _, km, _)   = try makeAlice()
        let (bobCustody, _, _) = try makeBob()
        vault.unlock(context: LAContext())

        let result = bobCustody.handleInbound(
            shardOperations:  nil,
            custodyManifest:  nil,
            senderPublicKey:  try km.retrieveIdentity(),
            senderIdentifier: "alice",
            vaultManager:     vault
        )
        #expect(!result)
    }

    @Test("handleInbound returns true when custodyManifest is present (even if empty)")
    func returnsTrueWithEmptyManifest() throws {
        let (vault, _, km, _)  = try makeAlice()
        let (bobCustody, _, _) = try makeBob()
        vault.unlock(context: LAContext())

        let result = bobCustody.handleInbound(
            shardOperations:  nil,
            custodyManifest:  [],
            senderPublicKey:  try km.retrieveIdentity(),
            senderIdentifier: "alice",
            vaultManager:     vault
        )
        #expect(result)
    }
}

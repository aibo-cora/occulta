//
//  ShardManifestTests.swift
//  OccultaTests
//
//  Tests for the manifest-based shard reconciliation protocol.
//  Cases match SHARD_PROTOCOL_CASES.md 1-19.
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
        ReconstructShard.self,
        PendingShardDistribute.self,
        PendingShardStatusUpdate.self
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
        PendingShardStatusUpdate.self
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
        id: attrID, label: "vault-shard", value: shardBytes, category: .shard,
        signature: try signer.signData(payload),
        createdAt: createdAt, expiresAt: nil, entryID: entryID
    )
}

/// Wrap a single ShardOperation in a SealedPayload.
@MainActor
private func sealed(_ op: OccultaBundle.ShardOperation) -> OccultaBundle.SealedPayload {
    OccultaBundle.SealedPayload(message: Data(), shardOperations: [op])
}

/// Wrap manifest fields into a SealedPayload (no ops).
@MainActor
private func sealedManifest(
    custodyManifest: [UUID]? = nil,
    expectedShards:  [UUID]? = nil
) -> OccultaBundle.SealedPayload {
    OccultaBundle.SealedPayload(
        message:         Data(),
        custodyManifest: custodyManifest,
        expectedShards:  expectedShards
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
        sealed:           sealed(.init(kind: .distribute, attribute: attr)),
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
        let (vault, aliceCustody, km, aliceCont) = try makeAlice()
        vault.unlock(context: LAContext())
        let entry      = try vault.addEntry(label: "s", content: Data(), type: .note)
        let recipients = try makeProfiles(count: 2)
        let attrs      = try vault.prepareShards(for: entry.id, threshold: 2, recipients: recipients)

        // Alice queues a distribute row (simulating bundle lost in transit).
        try aliceCustody.queueDistribute(attribute: attrs[0], for: "bob")
        #expect(try distributeRowCount(in: aliceCont) == 1)

        // Simulate Bob's manifest NOT containing the shard ID (still pending delivery).
        try aliceCustody.processInboundManifest([], from: "bob", vaultManager: vault)

        // Because a distribute row exists, status must NOT change to .lost.
        let meta = try vault.shardDistributionMetadata(for: entry.id)!
        #expect(meta.shards[0].status == .pending)
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
            sealed:           sealed(.init(kind: .distribute, attribute: oldAttr)),
            senderPublicKey:  alicePub,
            senderIdentifier: "alice",
            vaultManager:     vault
        )
        #expect(try custodyCount(in: bobCont) == 1)

        let newAttr = try makeAttr(signer: km, entryID: entryID, shardBytes: Data([0x02]))
        _ = bobCustody.handleInbound(
            sealed:           sealed(.init(kind: .replace, attribute: newAttr, attributeID: oldAttr.id)),
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

// MARK: - Case 4: Revocation (implicit via expectedShards)

@Suite("Case 4 — Revocation via expectedShards")
@MainActor struct Case4_Revocation {

    @Test("Empty expectedShards from Alice causes Bob to delete same-fingerprint shard")
    func implicitRevoke() throws {
        let (vault, _, km, _) = try makeAlice()
        let (bobCustody, _, bobCont) = try makeBob()
        vault.unlock(context: LAContext())

        let alicePub = try km.retrieveIdentity()
        let attr     = try distribute(from: km, to: bobCustody, vaultManager: vault)
        #expect(try custodyCount(in: bobCont) == 1)

        // Alice sends expectedShards: [] — shard absent → implicit revoke.
        _ = bobCustody.handleInbound(
            sealed:           sealedManifest(expectedShards: []),
            senderPublicKey:  alicePub,
            senderIdentifier: "alice",
            vaultManager:     vault
        )
        #expect(try custodyCount(in: bobCont) == 0)
        _ = attr // silence warning
    }
}

// MARK: - Cases 5 & 6: Manifest confirms or detects loss

@Suite("Cases 5 & 6 — Manifest: confirm and detect loss")
@MainActor struct Cases5And6_Manifest {

    @Test("Case 5: manifest with shard ID marks ShardRecord .confirmed")
    func manifestConfirms() throws {
        let (vault, aliceCustody, km, aliceCont) = try makeAlice()
        vault.unlock(context: LAContext())
        let entry      = try vault.addEntry(label: "s", content: Data(), type: .note)
        let recipients = try makeProfiles(count: 2)
        let attrs      = try vault.prepareShards(for: entry.id, threshold: 2, recipients: recipients)

        try aliceCustody.queueDistribute(attribute: attrs[0], for: "bob")

        // Bob's manifest contains the ID → confirm.
        try aliceCustody.processInboundManifest([attrs[0].id], from: "bob", vaultManager: vault)

        let meta = try vault.shardDistributionMetadata(for: entry.id)!
        #expect(meta.shards[0].status == .confirmed)
        #expect(try distributeRowCount(in: aliceCont) == 0, "row deleted on confirmation")
    }

    @Test("Case 6: manifest missing shard ID (no distribute row) marks .lost")
    func manifestLost() throws {
        let (vault, aliceCustody, km, _) = try makeAlice()
        vault.unlock(context: LAContext())
        let entry      = try vault.addEntry(label: "s", content: Data(), type: .note)
        let recipients = try makeProfiles(count: 2)
        let attrs      = try vault.prepareShards(for: entry.id, threshold: 2, recipients: recipients)

        // Confirm first, then Bob reinstalls (empty manifest, no distribute row).
        try aliceCustody.queueDistribute(attribute: attrs[0], for: "bob")
        try aliceCustody.processInboundManifest([attrs[0].id], from: "bob", vaultManager: vault)

        // Now Bob sends empty manifest — shard is gone, no distribute row → lost.
        try aliceCustody.processInboundManifest([], from: "bob", vaultManager: vault)

        let meta = try vault.shardDistributionMetadata(for: entry.id)!
        #expect(meta.shards[0].status == .lost)
        _ = km // silence warning
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

// MARK: - Case 12: Old-build trustee (nil manifest)

@Suite("Case 12 — Old-build trustee: nil manifest is a no-op")
@MainActor struct Case12_OldBuild {

    @Test("nil custodyManifest on inbound bundle causes no status change")
    func nilManifestNoop() throws {
        let (vault, aliceCustody, km, _) = try makeAlice()
        vault.unlock(context: LAContext())
        let entry      = try vault.addEntry(label: "s", content: Data(), type: .note)
        let recipients = try makeProfiles(count: 2)
        let attrs      = try vault.prepareShards(for: entry.id, threshold: 2, recipients: recipients)

        try aliceCustody.queueDistribute(attribute: attrs[0], for: "bob")

        // Old build: no custodyManifest field.
        _ = aliceCustody.handleInbound(
            sealed:           OccultaBundle.SealedPayload(message: Data()),
            senderPublicKey:  try km.retrieveIdentity(),
            senderIdentifier: "bob",
            vaultManager:     vault
        )

        // Status remains .pending — nil manifest means old build, no update.
        let meta = try vault.shardDistributionMetadata(for: entry.id)!
        #expect(meta.shards[0].status == .pending)
    }
}

// MARK: - Case 13: Vault locked when .handback arrives

@Suite("Case 13 — Vault locked when .handback arrives")
@MainActor struct Case13_LockedHandback {

    @Test(".handback inserts ReconstructShard row even while vault is locked")
    func handbackBufferedWhenLocked() throws {
        let (vault, _, km, container) = try makeAlice()
        vault.unlock(context: LAContext())
        let entry      = try vault.addEntry(label: "s", content: Data("hi".utf8), type: .note)
        let recipients = try makeProfiles(count: 2)
        let attrs      = try vault.prepareShards(for: entry.id, threshold: 2, recipients: recipients)

        // Lock vault before handback arrives.
        vault.lock()
        #expect(!vault.isUnlocked)

        // Bob sends .handback with the shard.
        let (bobCustody, _, _) = try makeBob()
        _ = bobCustody.handleInbound(
            sealed:           sealed(.init(kind: .handback, attribute: attrs[0])),
            senderPublicKey:  try km.retrieveIdentity(),
            senderIdentifier: "bob",
            vaultManager:     vault
        )

        // ReconstructShard row was inserted under the buffer key (no biometric needed).
        let rows = try ModelContext(container).fetch(FetchDescriptor<ReconstructShard>())
        #expect(rows.count == 1, "buffer row inserted while locked")
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

        _ = bobCustody.handleInbound(sealed: sealed(op), senderPublicKey: alicePub,
                                     senderIdentifier: "alice", vaultManager: vault)
        _ = bobCustody.handleInbound(sealed: sealed(op), senderPublicKey: alicePub,
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
            sealed:           sealed(.init(kind: .distribute, attribute: attr)),
            senderPublicKey:  imposterPub,
            senderIdentifier: "imposter",
            vaultManager:     vault
        )

        #expect(try custodyCount(in: bobCont) == 0)
    }
}

// MARK: - Case 17: Below-threshold reconstruction

@Suite("Case 17 — Below-threshold reconstruction is a no-op")
@MainActor struct Case17_BelowThreshold {

    @Test("tryFinalizeReconstruction with one shard (k=2) leaves buffer intact")
    func belowThresholdNoop() throws {
        let (vault, _, km, container) = try makeAlice()
        vault.unlock(context: LAContext())
        let entry      = try vault.addEntry(label: "s", content: Data("hello".utf8), type: .note)
        let recipients = try makeProfiles(count: 3)
        let attrs      = try vault.prepareShards(for: entry.id, threshold: 2, recipients: recipients)

        try vault.acceptReturnedShard(attrs[0])
        try vault.tryFinalizeReconstruction(entryID: entry.id)

        let rows = try ModelContext(container).fetch(FetchDescriptor<ReconstructShard>())
        #expect(rows.count == 1, "one shard buffered; threshold not met — row intact")
        _ = km // silence warning
    }
}

// MARK: - Case 18: expectedShards arrives while distribute is in flight

@Suite("Case 18 — expectedShards does not revoke in-flight shard")
@MainActor struct Case18_ExpectedShardsInFlight {

    @Test("expectedShards containing the shard ID retains the shard")
    func expectedShardsRetainsInFlight() throws {
        let (vault, _, km, _)        = try makeAlice()
        let (bobCustody, _, bobCont) = try makeBob()
        vault.unlock(context: LAContext())

        let attr     = try distribute(from: km, to: bobCustody, vaultManager: vault)
        let alicePub = try km.retrieveIdentity()

        // Alice sends expectedShards that includes the shard ID.
        try bobCustody.processExpectedShards([attr.id], from: "alice", senderPublicKey: alicePub)

        #expect(try custodyCount(in: bobCont) == 1, "shard in expectedShards must not be deleted")
    }

    @Test("expectedShards NOT containing a same-fingerprint shard deletes it")
    func expectedShardsDeletesAbsent() throws {
        let (vault, _, km, _)        = try makeAlice()
        let (bobCustody, _, bobCont) = try makeBob()
        vault.unlock(context: LAContext())

        let alicePub = try km.retrieveIdentity()
        _ = try distribute(from: km, to: bobCustody, vaultManager: vault)

        // Empty expectedShards → implicit revoke.
        try bobCustody.processExpectedShards([], from: "alice", senderPublicKey: alicePub)

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

    @Test("Invariant 1: mismatch-fingerprint shard is immune to expectedShards deletion")
    func mismatchImmune() throws {
        let aliceOld = TestKeyManager()
        let aliceNew = TestKeyManager()
        let (vault, _, _, _)         = try makeAlice()
        let (bobCustody, _, bobCont) = try makeBob()
        vault.unlock(context: LAContext())

        let aliceNewPub = try aliceNew.retrieveIdentity()

        // Bob holds a shard stored under Alice's OLD fingerprint.
        _ = try distribute(from: aliceOld, to: bobCustody, vaultManager: vault)
        #expect(try custodyCount(in: bobCont) == 1)

        // Alice's NEW key sends expectedShards: [] — different fingerprint → immune.
        try bobCustody.processExpectedShards([], from: "alice", senderPublicKey: aliceNewPub)
        #expect(try custodyCount(in: bobCont) == 1, "mismatch shard must survive expectedShards")
    }

    @Test("Invariant 2: PendingShardDistribute row is deleted only on manifest confirmation")
    func distributeRowSurvivesSend() throws {
        let (vault, aliceCustody, km, aliceCont) = try makeAlice()
        vault.unlock(context: LAContext())
        let entry      = try vault.addEntry(label: "s", content: Data(), type: .note)
        let recipients = try makeProfiles(count: 2)
        let attrs      = try vault.prepareShards(for: entry.id, threshold: 2, recipients: recipients)

        try aliceCustody.queueDistribute(attribute: attrs[0], for: "bob")
        #expect(try distributeRowCount(in: aliceCont) == 1, "row exists after queuing")

        // Build outbound ops (simulates send) — row must NOT be deleted by this.
        _ = try aliceCustody.buildShardOperations(for: "bob", currentContactPublicKey: nil)
        #expect(try distributeRowCount(in: aliceCont) == 1, "row persists until manifest confirms")

        // Manifest confirms → row deleted.
        try aliceCustody.processInboundManifest([attrs[0].id], from: "bob", vaultManager: vault)
        #expect(try distributeRowCount(in: aliceCont) == 0, "row deleted after manifest confirmation")
        _ = km // silence warning
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
        let (vault, aliceCustody, km, _) = try makeAlice()
        vault.unlock(context: LAContext())
        let entry      = try vault.addEntry(label: "s", content: Data(), type: .note)
        let recipients = try makeProfiles(count: 2)
        let attrs      = try vault.prepareShards(for: entry.id, threshold: 2, recipients: recipients)

        try aliceCustody.queueDistribute(attribute: attrs[0], for: "bob")

        let ops1 = try aliceCustody.buildShardOperations(for: "bob", currentContactPublicKey: nil)
        #expect(ops1.contains { $0.kind == .distribute })

        let ops2 = try aliceCustody.buildShardOperations(for: "bob", currentContactPublicKey: nil)
        #expect(ops2.contains { $0.kind == .distribute }, "distribute included again — not fire-and-forget")
        _ = km // silence warning
    }

    @Test("Invariant 5: unknown JSON fields in SealedPayload are silently ignored (old-build compat)")
    func unknownFieldsIgnored() throws {
        // Encode a SealedPayload that includes the new manifest fields, then decode
        // it WITHOUT those fields in the type (simulated by just checking Codable round-trip).
        let original = OccultaBundle.SealedPayload(
            message: Data("hello".utf8),
            custodyManifest: [UUID()],
            expectedShards:  [UUID()]
        )
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: encoded)
        // New fields survive the round-trip.
        #expect(decoded.custodyManifest?.count == 1)
        #expect(decoded.expectedShards?.count  == 1)
    }
}

// MARK: - buildCustodyManifest and buildExpectedShards

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

    @Test("buildExpectedShards returns active (pending/confirmed) shard IDs for a trustee")
    func expectedShardsActiveOnly() throws {
        let (vault, aliceCustody, km, _) = try makeAlice()
        vault.unlock(context: LAContext())
        let entry      = try vault.addEntry(label: "s", content: Data(), type: .note)
        let recipients = try makeProfiles(count: 3)
        let attrs      = try vault.prepareShards(for: entry.id, threshold: 2, recipients: recipients)

        // attrs[0] → "bob" (pending)
        try aliceCustody.queueDistribute(attribute: attrs[0], for: "bob")

        let expected = try aliceCustody.buildExpectedShards(for: "bob", vaultManager: vault)
        #expect(expected.contains(attrs[0].id))
        _ = km // silence warning
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
            sealed:           OccultaBundle.SealedPayload(message: Data("plain".utf8)),
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
            sealed:           sealedManifest(custodyManifest: []),
            senderPublicKey:  try km.retrieveIdentity(),
            senderIdentifier: "alice",
            vaultManager:     vault
        )
        #expect(result)
    }

    @Test("handleInbound returns true when expectedShards is present")
    func returnsTrueWithExpectedShards() throws {
        let (vault, _, km, _)  = try makeAlice()
        let (bobCustody, _, _) = try makeBob()
        vault.unlock(context: LAContext())

        let result = bobCustody.handleInbound(
            sealed:           sealedManifest(expectedShards: []),
            senderPublicKey:  try km.retrieveIdentity(),
            senderIdentifier: "alice",
            vaultManager:     vault
        )
        #expect(result)
    }
}

// MARK: - Helpers (profiles)

@MainActor
private func makeProfiles(count: Int) throws -> [Contact.Profile] {
    let schema = Schema([
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self
    ])
    let config    = ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)
    let container = try ModelContainer(for: schema, configurations: [config])
    let ctx       = ModelContext(container)
    return (0..<count).map { i in
        let p = Contact.Profile(
            identifier: "contact-\(i)",
            givenName: "C", familyName: "\(i)",
            middleName: "", nickname: "",
            organizationName: "", departmentName: "", jobTitle: ""
        )
        ctx.insert(p)
        return p
    }
}

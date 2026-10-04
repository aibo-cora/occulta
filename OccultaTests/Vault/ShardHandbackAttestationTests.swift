//
//  ShardHandbackAttestationTests.swift
//  OccultaTests
//
//  Bug 94 remedy 2 — originally, trustee attestation let a rotated-identity owner
//  accept a shard their new device structurally cannot verify, without falling
//  back to "accept anything whenever a restore happens to be pending" (the
//  original hole). `bugs.md` Bug 125 (2026-09-19) removed attestation itself: it
//  never verified content authenticity, only sender identity, which the bundle's
//  own transport (a 1:1 exchange, session key derivable only by the two real
//  parties) already establishes before `handleHandback` is ever called. Branch B
//  collapsed into unconditional accept on Branch A failure.
//
//  Kept this file's name despite attestation being gone — a purely cosmetic
//  rename, not done as part of that change. What still needs covering: Branch A
//  still runs and still means something when it succeeds (content authenticity);
//  a rotated-identity shard is now accepted unconditionally rather than rejected;
//  and distinct-sender enforcement — the actual fix for Bug 94's severity, since
//  reconstruction counts distinct senders, not distinct SignedAttribute.id's — is
//  untouched by any of this and still needs its own regression coverage.
//

import Testing
import CryptoKit
import SwiftData
import Foundation
import LocalAuthentication
@testable import Occulta
@testable import OccultaCore

// MARK: - Helpers

@MainActor
private func makeRig() throws -> (
    custody:   ShardCustodyManager,
    vault:     VaultManager,
    container: ModelContainer,
    ownerKey:  TestKeyManager
) {
    let km     = TestKeyManager()
    let schema = Schema([
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
        VaultEntry.self,
        CustodyShard.self,
        Vault.self,
        PendingShamirSecretRestore.self,
        PendingShardDistribute.self,
        PendingShardStatusUpdate.self,
        PotentiallyLostShard.self,
        GlobalShardConfig.self,
        AppLayerConfig.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    let custody   = ShardCustodyManager(modelContainer: container, keyManager: km)
    let vault     = VaultManager(modelContainer: container, keyManager: km)
    vault.unlock(context: LAContext())
    return (custody, vault, container, km)
}

/// Build a `.shard` SignedAttribute as if `signer` had signed it.
///
/// Default `shardBytes` is a genuine 33-byte shape (1-byte x-coordinate + 32-byte
/// value) — `ShamirSecretSharing.split`'s own output size — not an arbitrary short
/// value. `SignedAttributeCodec.encode` (via `absorbShard`) now enforces exactly
/// this size and throws `unexpectedValueSize` otherwise, matching every genuine
/// `.shard` attribute this codec will ever actually see.
private func makeShardAttr(
    signer: TestKeyManager,
    entryID: UUID,
    id: UUID = UUID(),
    shardBytes: Data = Data([UInt8(1)]) + Data.randomBytes(32)
) throws -> SignedAttribute {
    let createdAt = Date()
    let payload = SignedAttribute.signingPayload(
        id: id, category: .shard, value: shardBytes,
        entryID: entryID, createdAt: createdAt, expiresAt: nil
    )
    let signature = try signer.signData(payload)
    return SignedAttribute(
        id: id, label: SignedAttribute.backupKeyPieceLabel, value: shardBytes, category: .shard,
        signature: signature, createdAt: createdAt, expiresAt: nil, entryID: entryID
    )
}

@MainActor
private func reconstructShardCount(vault: VaultManager, entryID: UUID) throws -> Int {
    try vault.collectedShards(forAttributeID: entryID).count
}

// MARK: - Tests

@MainActor
// Runs under .ambientTestKeyManager: absorbShard (via acceptReturnedShard) seals
// PendingShamirSecretRestore.attributeID/.deletionToken under the ambient local key
// (Manager.Ambient), never the injected key manager — see ShardCustodyTests.swift's
// ReconstructionBufferTests for the fuller trap explanation.
@Suite("Bug 94 remedy 2 — shard handback acceptance", .serialized, .ambientTestKeyManager)
struct ShardHandbackAttestationTests {

    @Test("Branch A: a shard signed by the owner's own current identity is accepted")
    func branchADirectVerifyStillWorks() throws {
        let (custody, vault, _, ownerKey) = try makeRig()
        let entryID = UUID()   // a backup key's distribution ID

        let attr = try makeShardAttr(signer: ownerKey, entryID: entryID)
        let op   = OccultaBundle.ShardOperation(kind: .handback, attribute: attr)

        _ = custody.handleInbound(
            shardOperations: [op], custodyManifest: nil,
            senderPublicKey: try ownerKey.retrieveIdentity(), senderIdentifier: "trustee-a",
            vaultManager: vault
        )

        #expect(try reconstructShardCount(vault: vault, entryID: entryID) == 1,
                "a directly-verifiable shard must be accepted")
    }

    @Test("A rotated-identity shard is accepted unconditionally — Bug 125 removed the attestation fallback entirely")
    func rotatedIdentityAcceptedUnconditionally() throws {
        let (custody, vault, _, _) = try makeRig()
        let entryID = UUID()   // a backup key's distribution ID

        // Signed by the owner's OLD identity — unreachable from this device (rotated),
        // so custody's own retrieveIdentity() can never verify it. No attestation
        // accompanies this at all; there is no longer a mechanism for one to.
        let ownerOldKey = TestKeyManager()
        let trusteeKey  = TestKeyManager()
        let attr = try makeShardAttr(signer: ownerOldKey, entryID: entryID)
        let op   = OccultaBundle.ShardOperation(kind: .handback, attribute: attr)

        _ = custody.handleInbound(
            shardOperations: [op], custodyManifest: nil,
            senderPublicKey: try trusteeKey.retrieveIdentity(), senderIdentifier: "trustee-b",
            vaultManager: vault
        )

        #expect(try reconstructShardCount(vault: vault, entryID: entryID) == 1, """
            A rotated-identity shard must be accepted even with no signature verifiable at all —
            transport already authenticated the sender before this ever ran (Bug 125); there is
            no stronger check left to fall back to, so Branch A failing means accept, not reject.
            """)
    }

    @Test("A second share from the same sender replaces the first, never accumulates")
    func sameSenderReplacesNotAccumulates() throws {
        let (custody, vault, _, _) = try makeRig()
        let entryID = UUID()   // a backup key's distribution ID

        let ownerOldKey = TestKeyManager()
        let senderPub   = try TestKeyManager().retrieveIdentity()

        for _ in 0..<3 {
            let attr = try makeShardAttr(signer: ownerOldKey, entryID: entryID, id: UUID())
            let op   = OccultaBundle.ShardOperation(kind: .handback, attribute: attr)
            _ = custody.handleInbound(
                shardOperations: [op], custodyManifest: nil,
                senderPublicKey: senderPub, senderIdentifier: "same-trustee",
                vaultManager: vault
            )
        }

        #expect(try reconstructShardCount(vault: vault, entryID: entryID) == 1, """
            Three distinct shares all arrived from the same sender identifier. Storage must keep
            exactly one — a second share from a sender already represented for this entryID
            replaces the first rather than adding a second vote toward threshold.
            """)
    }

    /// **The critical case.** Without distinct-sender enforcement, one attacker holding one
    /// identity could mint threshold-many fake shares and reconstruct alone — now that
    /// nothing except sender identity gates acceptance at all, this is the one property doing
    /// real work. Confirms it's closed.
    @Test("A single sender cannot mint enough distinct shares to reach a 2-of-2 threshold alone")
    func singleSenderCannotReachThresholdAlone() throws {
        let (custody, vault, _, _) = try makeRig()
        let entryID = UUID()   // a backup key's distribution ID

        let attacker = TestKeyManager()
        let attackerPub = try attacker.retrieveIdentity()

        // Two DISTINCT fabricated shares, both "from" the same sender identity.
        for _ in 0..<2 {
            let attr = try makeShardAttr(signer: attacker, entryID: entryID, id: UUID())
            let op   = OccultaBundle.ShardOperation(kind: .handback, attribute: attr)
            _ = custody.handleInbound(
                shardOperations: [op], custodyManifest: nil,
                senderPublicKey: attackerPub, senderIdentifier: "lone-attacker",
                vaultManager: vault
            )
        }

        #expect(try reconstructShardCount(vault: vault, entryID: entryID) == 1, """
            Both fabricated shares came from the same sender identifier, so only one is ever
            stored — a lone attacker cannot single-handedly assemble a 2-of-2 threshold no
            matter how many distinct fake SignedAttribute.id's they mint. Two DISTINCT senders
            would be required, matching genuine trustee-collusion cost, not one.
            """)
    }

    // MARK: - Trustee-side building (buildShardOperations, mismatchHandbackOps)

    /// End to end on the trustee's own device: they hold a genuine `CustodyShard`
    /// distributed under the owner's old key, and the owner's current key (as the trustee
    /// has it on file) has since changed. `buildShardOperations` must still produce a
    /// `.handback` op for it — the trustee no longer needs to build anything alongside it
    /// (no attestation to construct, no retained-old-key lookup), which this confirms
    /// directly rather than assuming from the receiving-side tests above.
    @Test("A trustee still hands back a mismatch-fingerprint shard, with nothing else attached")
    func trusteeHandsBackOnFingerprintMismatch() throws {
        let trusteeKM = TestKeyManager()
        let schema = Schema([
            Contact.Profile.self,
            Contact.Profile.PhoneNumber.self,
            Contact.Profile.EmailAddress.self,
            Contact.Profile.PostalAddress.self,
            Contact.Profile.URLAddress.self,
            Contact.Profile.Key.self,
            VaultEntry.self,
            CustodyShard.self,
            PendingShardDistribute.self,
            PendingShardStatusUpdate.self,
            PotentiallyLostShard.self,
            GlobalShardConfig.self,
        ])
        let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
        let trusteeCustody = ShardCustodyManager(modelContainer: container, keyManager: trusteeKM)
        let dummyVault      = VaultManager(modelContainer: container, keyManager: trusteeKM)

        let ownerOldKey = TestKeyManager()
        let ownerOldPub = try ownerOldKey.retrieveIdentity()
        let entryID     = UUID()

        let distributedAttr = try makeShardAttr(signer: ownerOldKey, entryID: entryID)
        let distributeOp = OccultaBundle.ShardOperation(kind: .distribute, attribute: distributedAttr)
        _ = trusteeCustody.handleInbound(
            shardOperations: [distributeOp], custodyManifest: nil,
            senderPublicKey: ownerOldPub, senderIdentifier: "owner",
            vaultManager: dummyVault
        )

        // The owner's device has since rotated — the trustee sees a different current key
        // for them now, which is what triggers the mismatch-handback.
        let ownerNewPub = try TestKeyManager().retrieveIdentity()
        let ops = try trusteeCustody.buildShardOperations(for: "owner", currentContactPublicKey: ownerNewPub)
        let handback = try #require(ops.first { $0.kind == .handback })

        #expect(handback.attribute?.id == distributedAttr.id,
                "the mismatch-fingerprint shard must still be handed back")
    }
}

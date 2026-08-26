//
//  ShardHandbackAttestationTests.swift
//  OccultaTests
//
//  Bug 94 remedy 2 — trustee attestation lets a rotated-identity owner accept a
//  shard their new device structurally cannot verify, without falling back to
//  "accept anything whenever a restore happens to be pending" (the original hole).
//
//  A first-pass design of Branch B only checked that *some* known contact signed
//  *something* — it never independently verified the original attribute's
//  signature, so a single attacker could self-attest their own fabricated shard,
//  threshold-many times over, reintroducing Bug 94's exact severity through the
//  new mechanism. The fix: storage keeps at most one accepted share per
//  (entryID, senderIdentifier), so reconstruction structurally requires
//  threshold-many *distinct senders*. These tests exercise both the acceptance
//  logic (handleHandback's Branch A/B) and that specific closed vulnerability
//  directly — nothing in the existing suite touched Branch B at all before this.
//

import Testing
import CryptoKit
import SwiftData
import Foundation
import LocalAuthentication
@testable import Occulta

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
        ReconstructShard.self,
        PendingShardDistribute.self,
        PendingShardStatusUpdate.self,
        PotentiallyLostShard.self,
        GlobalShardConfig.self,
        AppLayerConfig.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    let custody   = ShardCustodyManager(modelContainer: container, keyManager: km)
    let vault     = VaultManager(modelContainer: container, keyManager: km)
    vault.unlock(context: LAContext(), currentDepth: 0)
    return (custody, vault, container, km)
}

/// A VaultEntry with an outstanding per-entry distribution (`shardDistributionEncrypted`
/// set) — the precondition Bug 94 remedy 2's per-entry gate checks for. Recipients are
/// dummy contacts; only the entryID and threshold matter to the tests below.
@MainActor
private func makeDistributedEntry(vault: VaultManager, threshold: Int = 2) throws -> UUID {
    let entry = try vault.addEntry(label: "seed", content: Data("payload".utf8), type: .seedPhrase)
    let recipients = (0..<max(threshold, 2)).map { i -> Contact.Profile in
        Contact.Profile(
            identifier: "dummy-\(i)", givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
    }
    _ = try vault.prepareShards(for: entry.id, threshold: threshold, recipients: recipients)
    return entry.id
}

/// Build a `.shard` SignedAttribute as if `signer` had signed it.
private func makeShardAttr(
    signer: TestKeyManager,
    entryID: UUID,
    id: UUID = UUID(),
    shardBytes: Data = Data([0x01, 0x02, 0x03, 0x04])
) throws -> SignedAttribute {
    let createdAt = Date()
    let payload = SignedAttribute.signingPayload(
        id: id, category: .shard, value: shardBytes,
        entryID: entryID, createdAt: createdAt, expiresAt: nil
    )
    let signature = try signer.signData(payload)
    return SignedAttribute(
        id: id, label: "vault-shard", value: shardBytes, category: .shard,
        signature: signature, createdAt: createdAt, expiresAt: nil, entryID: entryID
    )
}

/// Build a `.attestation` SignedAttribute over `attribute`, as if `attester` had
/// checked `attribute` against some retained key and vouched for it — mirrors
/// `ShardCustodyManager.attestation(for:)`'s construction exactly.
private func makeAttestation(attester: TestKeyManager, over attribute: SignedAttribute) throws -> SignedAttribute {
    let hash      = Data(SHA256.hash(data: attribute.signingPayload()))
    let attrID    = UUID()
    let createdAt = Date()
    let payload = SignedAttribute.signingPayload(
        id: attrID, category: .attestation, value: hash,
        entryID: attribute.entryID, createdAt: createdAt
    )
    let signature = try attester.signData(payload)
    return SignedAttribute(
        id: attrID, label: "shard-attestation", value: hash, category: .attestation,
        signature: signature, createdAt: createdAt, entryID: attribute.entryID
    )
}

@MainActor
private func reconstructShardCount(in container: ModelContainer) throws -> Int {
    try ModelContext(container).fetch(FetchDescriptor<ReconstructShard>()).count
}

// MARK: - Tests

@MainActor
@Suite("Bug 94 remedy 2 — trustee attestation", .serialized)
struct ShardHandbackAttestationTests {

    @Test("Branch A: a shard signed by the owner's own current identity is accepted with no attestation")
    func branchADirectVerifyStillWorks() throws {
        let (custody, vault, container, ownerKey) = try makeRig()
        let entryID = try makeDistributedEntry(vault: vault)

        let attr = try makeShardAttr(signer: ownerKey, entryID: entryID)
        let op   = OccultaBundle.ShardOperation(kind: .handback, attribute: attr)

        _ = custody.handleInbound(
            shardOperations: [op], custodyManifest: nil, expectedShards: nil,
            senderPublicKey: try ownerKey.retrieveIdentity(), senderIdentifier: "trustee-a",
            vaultManager: vault, currentDepth: 0
        )

        #expect(try reconstructShardCount(in: container) == 1,
                "a directly-verifiable shard must be accepted without any attestation")
    }

    @Test("Branch B: a rotated-identity shard is accepted when a valid attestation accompanies it")
    func branchBAttestationAccepted() throws {
        let (custody, vault, container, _) = try makeRig()
        let entryID = try makeDistributedEntry(vault: vault)

        // The shard was signed by the owner's OLD identity — unreachable from this
        // device (rotated), so custody's own retrieveIdentity() can never verify it.
        let ownerOldKey = TestKeyManager()
        let trusteeKey  = TestKeyManager()

        let attr        = try makeShardAttr(signer: ownerOldKey, entryID: entryID)
        let attestation = try makeAttestation(attester: trusteeKey, over: attr)
        let op = OccultaBundle.ShardOperation(kind: .handback, attribute: attr, attestation: attestation)

        _ = custody.handleInbound(
            shardOperations: [op], custodyManifest: nil, expectedShards: nil,
            senderPublicKey: try trusteeKey.retrieveIdentity(), senderIdentifier: "trustee-b",
            vaultManager: vault, currentDepth: 0
        )

        #expect(try reconstructShardCount(in: container) == 1,
                "a rotated-identity shard with a valid trustee attestation must be accepted")
    }

    @Test("A rotated-identity shard with no attestation at all is rejected")
    func noAttestationRejected() throws {
        let (custody, vault, container, _) = try makeRig()
        let entryID = try makeDistributedEntry(vault: vault)

        let ownerOldKey = TestKeyManager()
        let attr = try makeShardAttr(signer: ownerOldKey, entryID: entryID)
        let op   = OccultaBundle.ShardOperation(kind: .handback, attribute: attr)

        _ = custody.handleInbound(
            shardOperations: [op], custodyManifest: nil, expectedShards: nil,
            senderPublicKey: try TestKeyManager().retrieveIdentity(), senderIdentifier: "trustee-c",
            vaultManager: vault, currentDepth: 0
        )

        #expect(try reconstructShardCount(in: container) == 0,
                "no direct signature and no attestation must be rejected outright — this is the old, now-removed isRestorePending escape hatch's replacement")
    }

    @Test("An attestation that doesn't match senderPublicKey is rejected")
    func attestationWrongSenderRejected() throws {
        let (custody, vault, container, _) = try makeRig()
        let entryID = try makeDistributedEntry(vault: vault)

        let ownerOldKey = TestKeyManager()
        let trusteeKey  = TestKeyManager()
        let impostorKey = TestKeyManager()

        let attr        = try makeShardAttr(signer: ownerOldKey, entryID: entryID)
        let attestation = try makeAttestation(attester: trusteeKey, over: attr)
        let op = OccultaBundle.ShardOperation(kind: .handback, attribute: attr, attestation: attestation)

        // senderPublicKey claims to be someone other than who actually signed the attestation.
        _ = custody.handleInbound(
            shardOperations: [op], custodyManifest: nil, expectedShards: nil,
            senderPublicKey: try impostorKey.retrieveIdentity(), senderIdentifier: "trustee-d",
            vaultManager: vault, currentDepth: 0
        )

        #expect(try reconstructShardCount(in: container) == 0,
                "an attestation must verify against the actual sending key, not just exist")
    }

    @Test("An attestation over a different shard's payload is rejected — cannot be transplanted")
    func attestationHashMismatchRejected() throws {
        let (custody, vault, container, _) = try makeRig()
        let entryID = try makeDistributedEntry(vault: vault)

        let ownerOldKey = TestKeyManager()
        let trusteeKey  = TestKeyManager()

        let realAttr = try makeShardAttr(signer: ownerOldKey, entryID: entryID)
        let otherAttr = try makeShardAttr(signer: ownerOldKey, entryID: entryID, id: UUID(), shardBytes: Data([0xFF]))
        // Attestation genuinely signed by the trustee, but over a DIFFERENT attribute's hash.
        let mismatchedAttestation = try makeAttestation(attester: trusteeKey, over: otherAttr)
        let op = OccultaBundle.ShardOperation(kind: .handback, attribute: realAttr, attestation: mismatchedAttestation)

        _ = custody.handleInbound(
            shardOperations: [op], custodyManifest: nil, expectedShards: nil,
            senderPublicKey: try trusteeKey.retrieveIdentity(), senderIdentifier: "trustee-e",
            vaultManager: vault, currentDepth: 0
        )

        #expect(try reconstructShardCount(in: container) == 0,
                "an attestation must be bound to the exact attribute it accompanies")
    }

    @Test("A second share from the same sender replaces the first, never accumulates")
    func sameSenderReplacesNotAccumulates() throws {
        let (custody, vault, container, _) = try makeRig()
        let entryID = try makeDistributedEntry(vault: vault)

        let ownerOldKey = TestKeyManager()
        let trusteeKey  = TestKeyManager()
        let senderPub   = try trusteeKey.retrieveIdentity()

        for _ in 0..<3 {
            let attr        = try makeShardAttr(signer: ownerOldKey, entryID: entryID, id: UUID())
            let attestation = try makeAttestation(attester: trusteeKey, over: attr)
            let op = OccultaBundle.ShardOperation(kind: .handback, attribute: attr, attestation: attestation)
            _ = custody.handleInbound(
                shardOperations: [op], custodyManifest: nil, expectedShards: nil,
                senderPublicKey: senderPub, senderIdentifier: "same-trustee",
                vaultManager: vault, currentDepth: 0
            )
        }

        #expect(try reconstructShardCount(in: container) == 1, """
            Three distinct, individually-valid attested shares all arrived from the same \
            sender identifier. Storage must keep exactly one — a second share from a sender \
            already represented for this entryID replaces the first rather than adding a \
            second vote toward threshold.
            """)
    }

    /// **The critical case.** This is exactly the vulnerability the first-pass design had:
    /// without distinct-sender enforcement, one attacker holding one identity could mint
    /// threshold-many self-attested fake shares and reconstruct alone. Confirms it's closed.
    @Test("A single sender cannot self-attest enough distinct shares to reach a 2-of-2 threshold alone")
    func singleSenderCannotReachThresholdAlone() throws {
        let (custody, vault, container, _) = try makeRig()
        let entryID = try makeDistributedEntry(vault: vault, threshold: 2)

        let attacker = TestKeyManager() // plays both "original signer" and "attester" — the flaw's premise
        let attackerPub = try attacker.retrieveIdentity()

        // Two DISTINCT fabricated shares, both self-attested by the same identity.
        for _ in 0..<2 {
            let attr        = try makeShardAttr(signer: attacker, entryID: entryID, id: UUID())
            let attestation = try makeAttestation(attester: attacker, over: attr)
            let op = OccultaBundle.ShardOperation(kind: .handback, attribute: attr, attestation: attestation)
            _ = custody.handleInbound(
                shardOperations: [op], custodyManifest: nil, expectedShards: nil,
                senderPublicKey: attackerPub, senderIdentifier: "lone-attacker",
                vaultManager: vault, currentDepth: 0
            )
        }

        #expect(try reconstructShardCount(in: container) == 1, """
            Both fabricated shares came from the same sender identifier, so only one is ever \
            stored — a lone attacker cannot single-handedly assemble a 2-of-2 threshold no \
            matter how many distinct fake SignedAttribute.id's they mint. Two DISTINCT senders \
            would be required, matching genuine trustee-collusion cost, not one.
            """)
    }

    // MARK: - Trustee-side building (attestation(for:), via mismatchHandbackOps)

    /// End to end on the trustee's own device: they hold a genuine `CustodyShard`
    /// distributed under the owner's old key, retain that old key in their own
    /// contact history for the owner, and the owner's current key (as the trustee
    /// has it on file) has since changed. `buildShardOperations` must produce a
    /// `.handback` op carrying a real attestation — the half of remedy 2 the other
    /// tests above don't reach, since they hand-craft attestations directly rather
    /// than exercising the code that builds them.
    @Test("A trustee holding a genuine shard produces a working attestation on mismatch")
    func trusteeBuildsAttestationOnFingerprintMismatch() throws {
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
        let dummyVault     = VaultManager(modelContainer: container, keyManager: trusteeKM)

        // The owner's identity at original distribution time.
        let ownerOldKey = TestKeyManager()
        let ownerOldPub = try ownerOldKey.retrieveIdentity()
        let entryID     = UUID()

        // Owner distributes a genuine shard to this trustee.
        let distributedAttr = try makeShardAttr(signer: ownerOldKey, entryID: entryID)
        let distributeOp = OccultaBundle.ShardOperation(kind: .distribute, attribute: distributedAttr)
        _ = trusteeCustody.handleInbound(
            shardOperations: [distributeOp], custodyManifest: nil, expectedShards: nil,
            senderPublicKey: ownerOldPub, senderIdentifier: "owner",
            vaultManager: dummyVault, currentDepth: 0
        )

        // The trustee's own contact record for the owner retains that old key —
        // exactly what a genuine trustee has and an arbitrary contact never was given.
        let ownerProfile = Contact.Profile(
            identifier: "owner", givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        let encryptedOldKey = try Manager.Crypto(keyManager: trusteeKM).encrypt(data: ownerOldPub)
        let keyRecord = Contact.Profile.Key(material: encryptedOldKey, owner: Data(), date: Data())
        ownerProfile.contactPublicKeys = [keyRecord]
        let ctx = ModelContext(container)
        ctx.insert(ownerProfile)
        try ctx.save()

        // The owner's device has since rotated — the trustee sees a different
        // current key for them now, which is what triggers the mismatch-handback.
        let ownerNewPub = try TestKeyManager().retrieveIdentity()

        let ops = try trusteeCustody.buildShardOperations(for: "owner", currentContactPublicKey: ownerNewPub)
        let handback = try #require(ops.first { $0.kind == .handback })
        let attestation = try #require(handback.attestation, "a genuine trustee must produce an attestation")

        #expect(attestation.category == .attestation)
        #expect(attestation.entryID == entryID)
        #expect(attestation.verify(against: try trusteeKM.retrieveIdentity()),
                "the attestation must verify against the trustee's own current identity")
        #expect(attestation.value == Data(SHA256.hash(data: distributedAttr.signingPayload())),
                "the attestation must bind to exactly the shard it accompanies")
    }

    @Test("A contact with no matching retained key for the owner produces no attestation")
    func noMatchingRetainedKeyProducesNoAttestation() throws {
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
            shardOperations: [distributeOp], custodyManifest: nil, expectedShards: nil,
            senderPublicKey: ownerOldPub, senderIdentifier: "owner",
            vaultManager: dummyVault, currentDepth: 0
        )

        // No Contact.Profile inserted at all for "owner" — nothing to retain the old
        // key with. Mirrors the population Bug 94 is actually about: an arbitrary
        // contact who was never a real trustee has nothing to attest with either.
        let ownerNewPub = try TestKeyManager().retrieveIdentity()
        let ops = try trusteeCustody.buildShardOperations(for: "owner", currentContactPublicKey: ownerNewPub)
        let handback = try #require(ops.first { $0.kind == .handback })

        // Padding, not a vouch. Every op now ships an attestation so the field's mere
        // presence cannot partition a group send by `wrappedPayload` size — see
        // `ShardCustodyManager.attestationFiller`. The security property is unchanged and is
        // asserted directly here: a device with nothing to check against cannot produce one
        // that verifies, so filler is rejected by Branch B exactly as a nil was.
        let attestation = try #require(handback.attestation)
        #expect(!attestation.verify(against: try trusteeKM.retrieveIdentity()),
                "filler must not verify — a device with no retained key must not be able to vouch")
        #expect(attestation.value != Data(SHA256.hash(data: distributedAttr.signingPayload())),
                "filler must not carry the hash a real attestation commits to")
    }
}

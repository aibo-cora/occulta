//
//  InboundShardCustodyDuressTests.swift
//  OccultaTests
//
//  Verifies inbound shard custody storage is not depth-gated: a safe contact's
//  real `.distribute` bundle, received while `Manager.Security.currentDepth > 0`,
//  is stored successfully and stays visible both at that duress depth and back at
//  depth 0 — the ceiling behavior `Contact.Profile.visibleThroughDepth` already
//  provides for "safe" contacts, with no new field or mechanism needed. Contrasts
//  with a sensitive (ceiling = 0) contact's shard, which stores identically but is
//  correctly hidden from the duress-depth display filter. See
//  Docs/Bugs/v1.10.0/Shard-Custody-Not-Cleaned-Up-On-Contact-Deletion.md,
//  "Duress signaling for shard custody".
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
private func makeRig() throws -> (
    contacts:  ContactManager,
    custody:   ShardCustodyManager,
    security:  Manager.Security,
    vault:     VaultManager,
    container: ModelContainer
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
    let security  = try Manager.Security(modelContainer: container, keyManager: km)
    let contacts  = ContactManager(modelContainer: container, security: security)
    let custody   = ShardCustodyManager(modelContainer: container, keyManager: km)
    let vault     = VaultManager(modelContainer: container, keyManager: km)
    return (contacts, custody, security, vault, container)
}

/// Inserts a contact stamped with an explicit `visibleThroughDepth` ceiling,
/// matching production's real creation-time stamp (`Contact+Manager.swift:206-207`) —
/// `Int.max` for a safe contact, a finite depth for a sensitive one.
@discardableResult
@MainActor
private func insertContact(identifier: String, visibleThroughDepth ceiling: Int, in cm: ContactManager) throws -> Contact.Profile {
    let profile = Contact.Profile(
        identifier: identifier, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.visibleThroughDepth = try JSONEncoder().encode(ceiling).encrypt()
    try cm.insertProfile(profile)
    return profile
}

/// Build a SignedAttribute as if `signer` had signed it — mirrors `ShardCustodyTests`.
@MainActor
private func makeShardAttr(
    signer: TestKeyManager,
    entryID: UUID = UUID(),
    shardBytes: Data = Data([0x01, 0x02, 0x03, 0x04])
) throws -> SignedAttribute {
    let attrID    = UUID()
    let createdAt = Date()
    let payload   = SignedAttribute.signingPayload(
        id: attrID, category: .shard, value: shardBytes,
        entryID: entryID, createdAt: createdAt, expiresAt: nil
    )
    let signature = try signer.signData(payload)
    return SignedAttribute(
        id: attrID, label: "vault-shard", value: shardBytes, category: .shard,
        signature: signature, createdAt: createdAt, expiresAt: nil, entryID: entryID
    )
}

@MainActor
private func custodyShardCount(in container: ModelContainer) throws -> Int {
    try ModelContext(container).fetch(FetchDescriptor<CustodyShard>()).count
}

// MARK: - Tests

@MainActor
@Suite("Inbound shard custody at a duress depth", .serialized)
struct InboundShardCustodyDuressTests {

    @Test func safeContactDistribute_atDuressDepth_storesAndStaysVisibleDownToDepthZero() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }

        let (contacts, custody, security, vault, container) = try makeRig()

        // A genuinely safe contact — Int.max ceiling, exactly what production stamps
        // for a depth-0 contact (Contact+Manager.swift:206).
        let alice    = try insertContact(identifier: "alice", visibleThroughDepth: Int.max, in: contacts)
        let aliceKey = TestKeyManager()
        let alicePub = try aliceKey.retrieveIdentity()

        // Move to a duress depth — mirrors a real coercion session.
        security.applyVerifyState(for: .duress)
        #expect(security.currentDepth == 1)
        #expect(contacts.isSafeContact("alice"),
                "a ceiling of Int.max must remain displayable at a duress depth")

        // Alice sends a real, signed shard-distribute op while we're at this depth —
        // exactly what buildOwnedBasket hands to ShardCustodyManager.handleInbound
        // once passSecurityControl has already let it through (sender is safe).
        let attr = try makeShardAttr(signer: aliceKey)
        let op   = OccultaBundle.ShardOperation(kind: .distribute, attribute: attr)
        _ = custody.handleInbound(
            shardOperations:  [op],
            custodyManifest:  nil,
            expectedShards:   nil,
            senderPublicKey:  alicePub,
            senderIdentifier: "alice",
            vaultManager:     vault
        )

        #expect(try custodyShardCount(in: container) == 1,
                "a safe contact's real shard must be stored even though the device is at a duress depth — nothing in handleInbound/handleDistribute gates on depth")

        // CustodyShard carries no depth stamp of its own — Vault+Tab.swift's display
        // filter keys entirely off the owner contact's own ceiling. Confirm that
        // ceiling already produces the desired behavior: visible at the depth it
        // arrived, and still visible back at the real depth 0 — no new field needed.
        #expect(alice.isVisible(atDepth: security.currentDepth),
                "still visible at the duress depth it was received at")

        security.applyVerifyState(for: .normal(depth: 0))
        #expect(security.currentDepth == 0)
        #expect(alice.isVisible(atDepth: security.currentDepth),
                "a safe contact's shard must remain visible back at the real depth 0 too")
    }

    @Test func sensitiveContactDistribute_atDuressDepth_storesButIsHiddenFromDisplay() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }

        let (contacts, custody, security, vault, container) = try makeRig()

        // A sensitive contact — visible only at depth 0, hidden at any duress depth.
        let bob    = try insertContact(identifier: "bob", visibleThroughDepth: 0, in: contacts)
        let bobKey = TestKeyManager()
        let bobPub = try bobKey.retrieveIdentity()

        security.applyVerifyState(for: .duress)
        #expect(security.currentDepth == 1)

        // passSecurityControl would actually block this bundle before it ever reaches
        // handleInbound (C1, forensic-trace-avoidance.md) — this test isolates
        // ShardCustodyManager's own behavior to confirm storage itself is
        // depth-agnostic, and that the real protection against a leak is the
        // display-time isDisplayable filter, not a storage-time gate.
        let attr = try makeShardAttr(signer: bobKey)
        let op   = OccultaBundle.ShardOperation(kind: .distribute, attribute: attr)
        _ = custody.handleInbound(
            shardOperations:  [op],
            custodyManifest:  nil,
            expectedShards:   nil,
            senderPublicKey:  bobPub,
            senderIdentifier: "bob",
            vaultManager:     vault
        )

        #expect(try custodyShardCount(in: container) == 1,
                "storage is unconditional regardless of the owner's own sensitivity — display filtering is what protects this, not a storage gate")
        #expect(bob.isVisible(atDepth: security.currentDepth) == false,
                "a sensitive owner's shard must never render at a duress depth, even though the row exists")
    }
}

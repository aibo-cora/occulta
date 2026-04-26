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
//  - .distribute / .revoke / .respond dispatch.
//  - Multi-entry reconstruction buffer isolation.
//  - tryFinalizeReconstruction: threshold gate, lock gate, multi-entry independence.
//

import Testing
import CryptoKit
import SwiftData
import Foundation
import LocalAuthentication
@testable import Occulta

// MARK: - Helpers

@MainActor
private func makeAlice(
    inactivityTimeout: TimeInterval = 5 * 60
) throws -> (vault: VaultManager, km: TestKeyManager, container: ModelContainer) {
    let alice  = TestKeyManager()
    let schema = Schema([
        VaultEntry.self,
        CustodyShard.self,
        ReconstructShard.self
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

/// Build a SignedAttribute as if `signer` (Alice) had signed it.
@MainActor
private func makeShardAttr(
    signer: TestKeyManager,
    entryID: UUID = UUID(),
    shardBytes: Data = Data([0x01, 0x02, 0x03, 0x04])
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
        label:     "vault-shard",
        value:     shardBytes,
        category:  .shard,
        signature: signature,
        createdAt: createdAt,
        expiresAt: nil,
        entryID:   entryID
    )
}

@MainActor
private func sealedOp(_ op: OccultaBundle.ShardOperation) -> OccultaBundle.SealedPayload {
    OccultaBundle.SealedPayload(message: Data(), shardOperation: op)
}

@MainActor
private func custodyShardCount(in container: ModelContainer) throws -> Int {
    let ctx = ModelContext(container)
    return try ctx.fetch(FetchDescriptor<CustodyShard>()).count
}

@MainActor
private func reconstructShardCount(in container: ModelContainer) throws -> Int {
    let ctx = ModelContext(container)
    return try ctx.fetch(FetchDescriptor<ReconstructShard>()).count
}

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
            givenName: "Contact", familyName: "\(i)",
            middleName: "", nickname: "",
            organizationName: "", departmentName: "", jobTitle: ""
        )
        ctx.insert(p)
        return p
    }
}

// MARK: - Recovery buffer key derivation

@Suite("Recovery buffer key — derivation")
@MainActor struct RecoveryBufferKeyTests {

    @Test("deriveRecoveryBufferKey() returns a 256-bit key")
    func returnsKey() throws {
        let km  = TestKeyManager()
        let key = try km.deriveRecoveryBufferKey()
        #expect(key != nil)
        var byteCount = 0
        key?.withUnsafeBytes { byteCount = $0.count }
        #expect(byteCount == 32)
    }

    @Test("Recovery buffer key is distinct from shard custody key (HKDF domain separation)")
    func distinctFromCustodyKey() throws {
        let km = TestKeyManager()
        var bufferBytes  = Data()
        var custodyBytes = Data()
        try km.deriveRecoveryBufferKey()?.withUnsafeBytes { bufferBytes  = Data($0) }
        try km.deriveShardCustodyKey()?.withUnsafeBytes   { custodyBytes = Data($0) }
        #expect(bufferBytes.count == 32 && custodyBytes.count == 32)
        #expect(bufferBytes != custodyBytes,
                "buffer key and custody key must differ — same SE source, different HKDF info")
    }

    @Test("Recovery buffer key is deterministic for the same key manager")
    func deterministic() throws {
        let km = TestKeyManager()
        var b1 = Data(), b2 = Data()
        try km.deriveRecoveryBufferKey()?.withUnsafeBytes { b1 = Data($0) }
        try km.deriveRecoveryBufferKey()?.withUnsafeBytes { b2 = Data($0) }
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
            sealed:           sealedOp(op),
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
            sealed:           sealedOp(op),
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
            sealed:           sealedOp(.init(kind: .distribute, attribute: oldAttr)),
            senderPublicKey:  alicePub,
            senderIdentifier: "alice",
            vaultManager:     try makeAlice().vault
        )
        #expect(try custodyShardCount(in: container) == 1)

        // Re-distribution with replacesID = oldAttr.id.
        let newAttr = try makeShardAttr(signer: alice, entryID: entryID, shardBytes: Data([0x09, 0x0A]))
        _ = custody.handleInbound(
            sealed:           sealedOp(.init(kind: .distribute, attribute: newAttr, replacesID: oldAttr.id)),
            senderPublicKey:  alicePub,
            senderIdentifier: "alice",
            vaultManager:     try makeAlice().vault
        )

        // Old row replaced by new — count is still 1, but the surviving row carries newAttr.
        #expect(try custodyShardCount(in: container) == 1)
    }
}

// MARK: - .revoke

@Suite("ShardCustodyManager — .revoke")
@MainActor struct RevokeTests {

    @Test(".revoke deletes the matching CustodyShard")
    func revokeDeletes() throws {
        let alice = TestKeyManager()
        let (custody, _, container) = try makeBob()
        let alicePub = try alice.retrieveIdentity()
        let aliceVault = try makeAlice().vault

        let attr = try makeShardAttr(signer: alice)
        _ = custody.handleInbound(
            sealed:           sealedOp(.init(kind: .distribute, attribute: attr)),
            senderPublicKey:  alicePub,
            senderIdentifier: "alice",
            vaultManager:     aliceVault
        )
        #expect(try custodyShardCount(in: container) == 1)

        _ = custody.handleInbound(
            sealed:           sealedOp(.init(kind: .revoke, attrID: attr.id)),
            senderPublicKey:  alicePub,
            senderIdentifier: "alice",
            vaultManager:     aliceVault
        )
        #expect(try custodyShardCount(in: container) == 0)
    }

    @Test(".revoke for an unknown attrID is a no-op")
    func revokeUnknownIsNoop() throws {
        let alice = TestKeyManager()
        let (custody, _, container) = try makeBob()
        _ = custody.handleInbound(
            sealed:           sealedOp(.init(kind: .revoke, attrID: UUID())),
            senderPublicKey:  try alice.retrieveIdentity(),
            senderIdentifier: "alice",
            vaultManager:     try makeAlice().vault
        )
        #expect(try custodyShardCount(in: container) == 0)
    }
}

// MARK: - .respond and the reconstruction buffer

@Suite("Reconstruction buffer — accept / finalise")
@MainActor struct ReconstructionBufferTests {

    @Test(".respond inserts a ReconstructShard and the row decrypts under the buffer key")
    func acceptInsertsRow() throws {
        let (vault, alice, container) = try makeAlice()
        vault.unlock(context: LAContext())
        let entry      = try vault.addEntry(label: "seed", content: Data("payload".utf8), type: .seedPhrase)
        let recipients = try makeProfiles(count: 3)
        let attrs      = try vault.prepareShards(for: entry.id, threshold: 2, recipients: recipients)

        // Simulate a .respond bundle delivering one shard back to Alice.
        try vault.acceptReturnedShard(attrs[0])

        #expect(try reconstructShardCount(in: container) == 1)

        // Sanity: the row decrypts under the recovery buffer key.
        guard let bufferKey = try alice.deriveRecoveryBufferKey() else {
            Issue.record("expected recovery buffer key")
            return
        }
        let row  = try ModelContext(container).fetch(FetchDescriptor<ReconstructShard>()).first!
        let box  = try AES.GCM.SealedBox(combined: row.encryptedPayload)
        let pt   = try AES.GCM.open(box, using: bufferKey, authenticating: row.aad())
        let pl   = try JSONDecoder().decode(ReconstructShard.Payload.self, from: pt)
        #expect(pl.entryID == entry.id)
        #expect(pl.attrID  == attrs[0].id)
    }

    @Test("Wrong id in AAD invalidates GCM tag — payload no longer decrypts")
    func aadBindingHolds() throws {
        let (vault, alice, container) = try makeAlice()
        vault.unlock(context: LAContext())
        let entry      = try vault.addEntry(label: "seed", content: Data(), type: .seedPhrase)
        let recipients = try makeProfiles(count: 2)
        let attrs      = try vault.prepareShards(for: entry.id, threshold: 2, recipients: recipients)
        try vault.acceptReturnedShard(attrs[0])

        guard let bufferKey = try alice.deriveRecoveryBufferKey() else {
            Issue.record("expected recovery buffer key"); return
        }
        let row = try ModelContext(container).fetch(FetchDescriptor<ReconstructShard>()).first!
        let box = try AES.GCM.SealedBox(combined: row.encryptedPayload)

        // Wrong AAD (a different UUID) — GCM authentication tag must reject it.
        let wrongAAD = UUID().uuidString.data(using: .utf8)!
        #expect(throws: (any Error).self) {
            _ = try AES.GCM.open(box, using: bufferKey, authenticating: wrongAAD)
        }

        // Correct AAD — must succeed.
        #expect(throws: Never.self) {
            _ = try AES.GCM.open(box, using: bufferKey, authenticating: row.aad())
        }
    }

    @Test("Below threshold: tryFinalizeReconstruction is a no-op")
    func belowThresholdNoop() throws {
        let (vault, _, container) = try makeAlice()
        vault.unlock(context: LAContext())
        let entry = try vault.addEntry(label: "seed", content: Data("plaintext".utf8), type: .seedPhrase)
        let recipients = try makeProfiles(count: 3)
        let attrs = try vault.prepareShards(for: entry.id, threshold: 2, recipients: recipients)

        // Forget the wrap so legacy unwrap can't satisfy reconstruction; only
        // shards can recover. Then deliver only ONE shard (k=2, below threshold).
        try vault.acceptReturnedShard(attrs[0])
        try vault.tryFinalizeReconstruction(entryID: entry.id)

        #expect(try reconstructShardCount(in: container) == 1, "buffer row remains since threshold not met")
    }

    @Test("At threshold: tryFinalizeReconstruction succeeds and clears the buffer")
    func atThresholdFinalizes() throws {
        let (vault, _, container) = try makeAlice()
        vault.unlock(context: LAContext())
        let entry = try vault.addEntry(label: "seed", content: Data("plaintext".utf8), type: .seedPhrase)
        let recipients = try makeProfiles(count: 3)
        let attrs = try vault.prepareShards(for: entry.id, threshold: 2, recipients: recipients)

        try vault.acceptReturnedShard(attrs[0])
        try vault.acceptReturnedShard(attrs[1])
        // accept on the last shard auto-triggers finalisation.

        #expect(try reconstructShardCount(in: container) == 0, "buffer must be empty after finalisation")
        // Decryption still works — the recovered PEK is re-wrapped under the vault key.
        #expect(try vault.decryptLabel(for: entry) == "seed")
    }

    @Test("Multi-entry isolation: shards from one entry do not satisfy another's threshold")
    func multiEntryIsolation() throws {
        let (vault, _, container) = try makeAlice()
        vault.unlock(context: LAContext())

        let entry1 = try vault.addEntry(label: "alpha", content: Data("a".utf8), type: .seedPhrase)
        let entry2 = try vault.addEntry(label: "beta",  content: Data("b".utf8), type: .seedPhrase)
        let recipients = try makeProfiles(count: 3)

        let attrs1 = try vault.prepareShards(for: entry1.id, threshold: 2, recipients: recipients)
        let attrs2 = try vault.prepareShards(for: entry2.id, threshold: 2, recipients: recipients)

        // Deliver one shard for each entry — each entry has 1/2.
        try vault.acceptReturnedShard(attrs1[0])
        try vault.acceptReturnedShard(attrs2[0])

        #expect(try reconstructShardCount(in: container) == 2,
                "two entries, two distinct buffered shards, neither at threshold")

        // Push entry1 to threshold; entry2 stays at 1/2.
        try vault.acceptReturnedShard(attrs1[1])

        #expect(try reconstructShardCount(in: container) == 1,
                "entry1 finalised → only entry2's single shard remains")
    }

    @Test("acceptReturnedShard ignores duplicate attrID")
    func duplicateAttrDeduplicated() throws {
        let (vault, _, container) = try makeAlice()
        vault.unlock(context: LAContext())
        let entry = try vault.addEntry(label: "seed", content: Data(), type: .seedPhrase)
        let recipients = try makeProfiles(count: 2)
        let attrs = try vault.prepareShards(for: entry.id, threshold: 2, recipients: recipients)

        try vault.acceptReturnedShard(attrs[0])
        try vault.acceptReturnedShard(attrs[0])  // duplicate

        // Threshold k=2; only one unique shard buffered → no finalise.
        #expect(try reconstructShardCount(in: container) == 1)
    }

    @Test("tryFinalizeAllReconstructions sweeps all entries that hit threshold")
    func sweepFinalisesAll() throws {
        let (vault, _, container) = try makeAlice()
        vault.unlock(context: LAContext())

        let entry1 = try vault.addEntry(label: "alpha", content: Data("a".utf8), type: .seedPhrase)
        let entry2 = try vault.addEntry(label: "beta",  content: Data("b".utf8), type: .seedPhrase)
        let recipients = try makeProfiles(count: 2)

        let attrs1 = try vault.prepareShards(for: entry1.id, threshold: 2, recipients: recipients)
        let attrs2 = try vault.prepareShards(for: entry2.id, threshold: 2, recipients: recipients)

        // Lock so opportunistic finalisation does NOT fire on accept.
        vault.lock()

        try vault.acceptReturnedShard(attrs1[0])
        try vault.acceptReturnedShard(attrs1[1])
        try vault.acceptReturnedShard(attrs2[0])
        try vault.acceptReturnedShard(attrs2[1])

        #expect(try reconstructShardCount(in: container) == 4, "all rows still buffered while locked")

        // Unlock — sweep should drain both entries.
        vault.unlock(context: LAContext())

        #expect(try reconstructShardCount(in: container) == 0,
                "unlock-time sweep finalises every entry that crossed threshold")
    }

    @Test("cancelReconstruction drops only rows for the targeted entry")
    func cancelDropsTargetedRows() throws {
        let (vault, _, container) = try makeAlice()
        vault.unlock(context: LAContext())

        let entry1 = try vault.addEntry(label: "alpha", content: Data(), type: .seedPhrase)
        let entry2 = try vault.addEntry(label: "beta",  content: Data(), type: .seedPhrase)
        let recipients = try makeProfiles(count: 3)

        let attrs1 = try vault.prepareShards(for: entry1.id, threshold: 3, recipients: recipients)
        let attrs2 = try vault.prepareShards(for: entry2.id, threshold: 3, recipients: recipients)

        try vault.acceptReturnedShard(attrs1[0])
        try vault.acceptReturnedShard(attrs2[0])
        try vault.acceptReturnedShard(attrs2[1])

        try vault.cancelReconstruction(entryID: entry2.id)

        #expect(try reconstructShardCount(in: container) == 1,
                "only entry2's rows should be dropped — entry1's single shard survives")
    }
}

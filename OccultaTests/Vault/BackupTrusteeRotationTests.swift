//
//  BackupTrusteeRotationTests.swift
//  OccultaTests
//
//  Bug 124 — a trustee removed from the current distribution kept a permanently-valid
//  credential, since neither the shared secret nor the id tagging its shards ever
//  changed on an ordinary trustee-set mutation. Fixed for BEK by minting a fresh
//  `distributionID` on every `prepareShards` call (`Vault+Manager+Backup.swift`);
//  `bekBytes` stays untouched, so already-exported `.occbak` files are unaffected.
//
//  Runs under `.ambientTestKeyManager` — `Backup.persist`'s filler-row claim and its
//  `depth`/`deletionToken` fields derive the local key ambiently via `Manager.Ambient`,
//  never through the injected `TestKeyManager`, regardless of which key manager the
//  vault itself was constructed with (same trap as `BackupEncryptionKeyStorageTests`).
//

import Testing
import Foundation
import CryptoKit
import LocalAuthentication
import SwiftData
@testable import Occulta
@testable import OccultaCore

/// `exportBackup` writes `backup-export-meta.dat` under Application Support — must exist
/// before the first export, same requirement `VaultRestoreTrustTests` works around.
private let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]

@MainActor
private func makeContainer() throws -> ModelContainer {
    let schema = Schema([
        AppLayerConfig.self,
        BackupEncryptionKey.self,
        VaultEntry.self,
        // restoreBackup reads banked shards from these.
        Vault.self,
        PendingShamirSecretRestore.self,
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
    ])
    return try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
}

/// A vault with a BEK already set up at depth 0, no entries. Distribution rounds are
/// each test's own concern — nothing here picks a trustee set.
@MainActor
private func makeVaultWithBackup() throws -> VaultManager {
    let container = try makeContainer()
    try? FileManager.default.createDirectory(at: appSupport, withIntermediateDirectories: true)
    let vault = VaultManager(modelContainer: container, keyManager: TestKeyManager())
    vault.unlock(context: LAContext())
    try vault.setupBackup(currentDepth: 0)
    return vault
}

/// A vault with no BEK at all — the restore target these tests reconstruct into,
/// mirroring `VaultRestoreTrustTests`' own `makeFreshVault()`.
@MainActor
private func makeFreshVault() throws -> VaultManager {
    let container = try makeContainer()
    let vault = VaultManager(modelContainer: container, keyManager: TestKeyManager())
    vault.unlock(context: LAContext())
    return vault
}

@MainActor
private func bekBytes(of vault: VaultManager) throws -> Data {
    var bytes = Data()
    try vault.currentBackupKey(currentDepth: 0).withUnsafeBytes { bytes = Data($0) }
    return bytes
}

@Suite("Backup key distribution — trustee-set mutation (Bug 124)")
@MainActor
struct BackupTrusteeRotationTests {

    @Test("Redistributing to a different trustee set mints a new distributionID",
          .ambientTestKeyManager)
    func redistributionMintsNewDistributionID() throws {
        let vault = try makeVaultWithBackup()

        let firstRound  = try vault.prepareBackupShards(
            threshold: 2, recipients: [realFormatContactIdentifier(), realFormatContactIdentifier()], currentDepth: 0
        )
        let secondRound = try vault.prepareBackupShards(
            threshold: 2, recipients: [realFormatContactIdentifier(), realFormatContactIdentifier()], currentDepth: 0
        )

        let firstID  = firstRound.first?.entryID
        let secondID = secondRound.first?.entryID

        #expect(firstID != nil)
        #expect(secondID != nil)
        #expect(firstID != secondID, """
            Redistributing must mint a fresh distributionID — otherwise a trustee dropped \
            from the new recipient set keeps a permanently-valid credential (Bug 124).
            """)

        // Every shard within one round shares the same id — a mixed-round attempt is
        // what the second test below actually exercises.
        #expect(secondRound.allSatisfy { $0.entryID == secondID })
    }

    /// **Not a test that a mixed submission is rejected** — it is, but for a reason that
    /// doesn't distinguish this fix from its absence. Checked directly:
    /// `ShamirSecretSharing.reconstruct` uses every supplied point unconditionally, no
    /// error-correction — mixing a share from round 1 with one from round 2 poisons the
    /// interpolation and fails the GCM check regardless of whether `distributionID`
    /// changed between rounds. Grouping-by-`entryID` (`restoreBackup`, production
    /// code) is what actually prevents that mix from being attempted in the first place —
    /// covered by `redistributionMintsNewDistributionID` above, not re-tested here. This
    /// test instead checks the one thing that fix could plausibly have broken: that a
    /// clean restore, using only the current round's shares, still works.
    @Test("Redistributing still allows a clean restore using only the current round's shares",
          .ambientTestKeyManager)
    func cleanRestoreStillSucceedsAfterRedistribution() throws {
        let vault = try makeVaultWithBackup()

        // Round 1: Bob and Marla.
        _ = try vault.prepareBackupShards(
            threshold: 2, recipients: [realFormatContactIdentifier(), realFormatContactIdentifier()], currentDepth: 0
        )

        // Round 2: Marla is dropped, Carol takes her place.
        let round2 = try vault.prepareBackupShards(
            threshold: 2, recipients: [realFormatContactIdentifier(), realFormatContactIdentifier()], currentDepth: 0
        )
        try vault.setBackupShardStatuses(Dictionary(uniqueKeysWithValues: round2.map { ($0.id, .confirmed) }), currentDepth: 0)

        let backupData = try vault.exportBackup(currentDepth: 0)
        let realBEK     = try bekBytes(of: vault)

        let restoreTarget = try makeFreshVault()
        var senders = Set<String>()
        for (i, shard) in round2.enumerated() {
            let sender = realFormatContactIdentifier()
            try restoreTarget.absorbShard(shard, senderIdentifier: sender)
            senders.insert(sender)
        }
        #expect(try restoreTarget.restoreBackup(from: backupData, currentDepth: 0, visibleContactIdentifiers: senders))
        let reconstructed = try bekBytes(of: restoreTarget)
        #expect(reconstructed == realBEK)
    }
}

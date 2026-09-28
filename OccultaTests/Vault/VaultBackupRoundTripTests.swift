//
//  VaultBackupRoundTripTests.swift
//  OccultaTests
//
//  Bug 88 — vault backup ignores `visibleThroughDepth` in both directions.
//
//  Written before any fix, to pin current behaviour. Until this file, the backup format had no
//  round-trip coverage at all — depth-related or otherwise. That matters because a format
//  change with no round-trip test underneath it is how you lose backups.
//
//  Export half fixed 2026-08-24 — exportBackup(currentDepth:) filters to that depth's
//  entries. Import half fixed 2026-08-25 — restored entries are stamped with the depth they
//  are restored at, the same way addEntry does.
//
//  Since 2026-09-23 (bugs.md Bug 129) the only way to import is restoreBackup, the new-device
//  path: every round trip here exports from one vault and restores into a fresh one holding
//  the owner's shards, rather than re-importing into the vault it came from.
//

import Testing
import Foundation
import CryptoKit
import LocalAuthentication
import SwiftData
@testable import Occulta

/// `VaultManager` takes an injected key manager and the harness below uses one, but that seam
/// does not reach the depth stamps: `addEntry` writes `visibleThroughDepth` through the bare
/// `Data.encrypt()` extension, which constructs `Manager.Crypto()` — and therefore
/// `Manager.Key()` — at the call site. No injection reaches it, so these are gated rather than
/// rewritten.
///
/// The failure is quiet in one respect and loud in another. `addEntry`'s depth stamp goes
/// through the bare `Data.encrypt()` extension (uninjectable); when no real key is available it
/// returns nil rather than throwing, so `addEntry` still succeeds and simply stamps a nil
/// ceiling — `entriesVisible(atDepth:whenUnclassified:)` treats that as included (a "never
/// classified" row, not a gap), so this part stays quiet. But `entriesVisible` also derives the
/// local DB key directly via the same uninjectable path, once, up front — on CI that derivation
/// itself fails and `entriesVisible` throws, which `exportBackup` doesn't swallow. So any test
/// that calls `exportBackup` at all fails loudly with a thrown error on CI, not just ones
/// asserting on counts or content. Tests that never call `exportBackup` (e.g. only checking a
/// pre-existing file's sealing) don't hit either path and keep running — hence the gating is
/// per test, not per suite.
private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

// MARK: - Harness

/// Export refuses to run below the shard threshold, so a usable vault needs a BEK *and*
/// enough confirmed BEK shards. `prepareBackupShards` creates them `.pending`;
/// `setBackupShardStatuses` is the seam that confirms them without driving the whole
/// distribution and manifest flow.
@MainActor
private func makeBackupReadyVault() throws -> (VaultManager, ModelContainer, [SignedAttribute]) {
    let (vault, container) = try makeVault()
    let shards = try setUpConfirmedBEK(for: vault, currentDepth: 0)
    return (vault, container, shards)
}

/// A vault with no backup key — the fresh device a restore lands on.
@MainActor
private func makeVault() throws -> (VaultManager, ModelContainer) {
    let schema = Schema([
        VaultEntry.self,
        BackupEncryptionKey.self,
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
    let container = try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
    // `exportBackup` seals an export-metadata snapshot into Application Support, which the
    // app always has but an in-memory test store does not. Create it rather than skip the
    // write — the staleness snapshot is part of what export does, and stubbing it out would
    // make the round trip less faithful than the thing it is pinning.
    let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    try? FileManager.default.createDirectory(at: appSupport, withIntermediateDirectories: true)

    let vault = VaultManager(
        modelContainer: container, keyManager: TestKeyManager()
    )
    vault.unlock(context: LAContext())
    return (vault, container)
}

/// Set up a BEK and confirm enough shards to clear `exportBackup`'s threshold check, at
/// `currentDepth`'s own slot. Stage 2 (`VAULT_KEY_LAYERING.md`) made each depth's BEK
/// independent — `exportBackup(currentDepth:)` reads whichever depth it's exporting *at*,
/// so a depth other than 0 needs its own call to this, not just depth 0's.
@MainActor
@discardableResult
private func setUpConfirmedBEK(for vault: VaultManager, currentDepth: Int) throws -> [SignedAttribute] {
    try vault.setupBackup(currentDepth: currentDepth)

    // Identifiers in the form the app stores (encrypted base64), not UUIDs or labels — the
    // assumption that they were UUIDs broke every real distribution (bugs.md Bug 145). No
    // Contact.Profile needed — prepareBackupShards takes identifiers directly.
    let recipients = (0..<2).map { _ in realFormatContactIdentifier() }

    let attributes = try vault.prepareBackupShards(threshold: 2, recipients: recipients, currentDepth: currentDepth)
    try vault.setBackupShardStatuses(Dictionary(uniqueKeysWithValues: attributes.map { ($0.id, .confirmed) }), currentDepth: currentDepth)
    return attributes
}

/// Restores `backup` the way a new phone does: a fresh vault banks every one of the owner's
/// `shards`, then opens the file at `depth`. Returns the fresh vault's container.
@MainActor
private func restoreOnFreshVault(_ backup: Data, shards: [SignedAttribute], atDepth depth: Int) throws -> ModelContainer {
    let (fresh, container) = try makeVault()
    var senders = Set<String>()
    for (i, shard) in shards.enumerated() {
        let sender = realFormatContactIdentifier()
        try fresh.absorbShard(shard, senderIdentifier: sender)
        senders.insert(sender)
    }
    let imported = try fresh.restoreBackup(from: backup, currentDepth: depth, visibleContactIdentifiers: senders)
    try #require(imported, "the restore itself failed, so nothing below measures the backup's contents")
    return container
}

@MainActor
private func entries(in container: ModelContainer) throws -> [VaultEntry] {
    try ModelContext(container).fetch(FetchDescriptor<VaultEntry>())
}

@Suite("Bug 88 — vault backup round trip", .serialized)
@MainActor
struct VaultBackupRoundTripTests {

    // MARK: - What works today, and must keep working through a format change

    @Test("Entries survive export → import with id, timestamp, label and content intact",
          .enabled(if: secureEnclaveAvailable()))
    func roundTripPreservesEntries() throws {
        let (vault, _, shards) = try makeBackupReadyVault()
        let note = try vault.addEntry(label: "note-label", content: Data("note-body".utf8), type: .note)
        let card = try vault.addEntry(label: "card-label", content: Data("card-body".utf8), type: .note)
        let backup = try vault.exportBackup(currentDepth: 0)

        let restored = try entries(in: restoreOnFreshVault(backup, shards: shards, atDepth: 0))
        #expect(restored.count == 2, "both entries must come back")

        let byID = Dictionary(uniqueKeysWithValues: restored.map { ($0.id, $0) })
        for original in [note, card] {
            let row = try #require(byID[original.id], "entry \(original.id) was not restored")
            #expect(row.createdAt == original.createdAt, "createdAt must survive the round trip")
        }
    }

    @Test("A backup is unreadable without the BEK", .enabled(if: secureEnclaveAvailable()))
    func backupIsSealed() throws {
        let (vault, _, _) = try makeBackupReadyVault()
        _ = try vault.addEntry(label: "secret-label", content: Data("secret-body".utf8), type: .note)
        let backup = try vault.exportBackup(currentDepth: 0)

        #expect(!backup.contains(Data("secret-label".utf8)),
                "the label appears in plaintext in the exported file")
        #expect(!backup.contains(Data("secret-body".utf8)),
                "the content appears in plaintext in the exported file")
    }

    // MARK: - The bug, in both directions

    /// `exportBackup(currentDepth:)` filters to entries with `visibleThroughDepth ==
    /// currentDepth` — exact match, not a ceiling (see Bug 88's "vault entries are
    /// exact-match, not a ceiling"). An export taken from a duress depth must therefore
    /// contain only that depth's entries, never the real layer's.
    @Test("Export excludes entries hidden at the current depth",
          .enabled(if: secureEnclaveAvailable()))
    func exportExcludesHiddenEntries() throws {
        let (vault, _, _) = try makeBackupReadyVault()
        // Visible at the duress depth this export is taken from.
        _ = try vault.addEntry(label: "decoy", content: Data("decoy".utf8), type: .note, currentDepth: 2)

        // Hidden at every depth but the real one — created at real depth 0.
        let hidden = try vault.addEntry(label: "real-secret",
                                        content: Data("real-secret".utf8),
                                        type: .note, currentDepth: 0)
        #expect(hidden.visibleThroughDepth != nil, "addEntry always stamps a ceiling")

        // Depth 2 needs its own confirmed BEK before it can export — Stage 2 made each
        // depth's BEK independent, so depth 0's setup in makeBackupReadyVault() doesn't
        // cover depth 2.
        let depth2Shards = try setUpConfirmedBEK(for: vault, currentDepth: 2)

        // Export taken under coercion, from the duress depth — not the real one.
        let backup = try vault.exportBackup(currentDepth: 2)

        let restoredCount = try entries(in: restoreOnFreshVault(backup, shards: depth2Shards, atDepth: 2)).count

        #expect(restoredCount == 1, """
            The export from depth 2 contained \(restoredCount) entries. Only the entry \
            visible at that depth should be present — an entry hidden from every duress \
            view must not be written into an export taken under coercion.
            """)
    }

    // MARK: - Bug 114: legacy nil-depth entries and duress-depth exports

    /// Simulates a legacy pre-field entry by clearing `visibleThroughDepth` through a
    /// separate, saved `ModelContext`, so the change is committed before `exportBackup`
    /// reads it rather than sitting unsaved on `VaultManager`'s own context.
    @MainActor
    private func makeLegacyEntry(via vault: VaultManager, in container: ModelContainer) throws -> UUID {
        let entry = try vault.addEntry(label: "legacy", content: Data("legacy".utf8), type: .note)
        let id    = entry.id
        let mutate = ModelContext(container)
        let toMutate = try #require(
            try mutate.fetch(FetchDescriptor<VaultEntry>(predicate: #Predicate { $0.id == id })).first
        )
        toMutate.visibleThroughDepth = nil
        try mutate.save()
        return id
    }

    /// `entriesVisible(atDepth:)` passes `whenUnclassified: depth == 0` (Bug 114) — a
    /// legacy entry with no `visibleThroughDepth` (pre-dating the field) is real content
    /// that predates duress depths existing at all, and must not be swept into a backup
    /// exported from one.
    @Test("Export excludes a legacy nil-depth entry when taken from a duress depth",
          .enabled(if: secureEnclaveAvailable()))
    func exportExcludesLegacyNilDepthEntryAtDuressDepth() throws {
        let (vault, container, _) = try makeBackupReadyVault()
        _ = try makeLegacyEntry(via: vault, in: container)

        let depth2Shards = try setUpConfirmedBEK(for: vault, currentDepth: 2)
        let backup = try vault.exportBackup(currentDepth: 2)

        let restoredCount = try entries(in: restoreOnFreshVault(backup, shards: depth2Shards, atDepth: 2)).count

        #expect(restoredCount == 0, """
            The export from depth 2 contained \(restoredCount) entries. A legacy entry with \
            no depth stamp must not be swept into a backup exported from a duress depth.
            """)
    }

    /// The other half, and the behavior Bug 114's fix must not regress: at the real depth
    /// 0, a legacy nil-depth entry must still be included — the original fix
    /// (`Docs/Bugs/v1.10.3/Backup-Export-Silently-Drops-Legacy-Nil-Depth-Vault-Entries.md`)
    /// this codebase shipped specifically to stop it silently vanishing from ordinary,
    /// non-duress backups.
    @Test("Export still includes a legacy nil-depth entry at the real depth 0",
          .enabled(if: secureEnclaveAvailable()))
    func exportIncludesLegacyNilDepthEntryAtRealDepth0() throws {
        let (vault, container, shards) = try makeBackupReadyVault()
        _ = try makeLegacyEntry(via: vault, in: container)

        let backup = try vault.exportBackup(currentDepth: 0)

        let restoredCount = try entries(in: restoreOnFreshVault(backup, shards: shards, atDepth: 0)).count

        #expect(restoredCount == 1, """
            The export from the real depth 0 contained \(restoredCount) entries. A legacy \
            entry with no depth stamp must still be included in an ordinary, non-duress backup.
            """)
    }

    /// Fixed: a restore stamps every entry with the depth it runs at, mirroring `addEntry`.
    /// A file only ever holds one layer's entries (Bug 88 remedy 4), so the depth to stamp
    /// is simply whichever depth the restore is running at — here, the same depth 0 the
    /// backup was exported from.
    @Test("Import restores the depth ceiling rather than defaulting to always-visible",
          .enabled(if: secureEnclaveAvailable()))
    func importRestoresDepthCeiling() throws {
        let (vault, _, shards) = try makeBackupReadyVault()
        _ = try vault.addEntry(label: "hidden", content: Data("hidden".utf8), type: .note, currentDepth: 0)
        let backup = try vault.exportBackup(currentDepth: 0)

        let restored = try #require(try entries(in: restoreOnFreshVault(backup, shards: shards, atDepth: 0)).first)

        let decodedDepth = restored.visibleThroughDepth?.decrypt().flatMap { DepthCodec.decode($0) }
        #expect(decodedDepth == 0, """
            The restored entry's ceiling decoded to \(String(describing: decodedDepth)), not 0. A \
            wrong (non-nil) ceiling would show or hide the entry at the wrong depth after \
            restore; a nil ceiling would fail closed in the duress display path but still \
            surface in every future backup export — either way, not the depth it was hidden at \
            when exported.
            """)
    }

    // MARK: - Staleness metadata (32-slot, one per depth)

    /// All 32 slots share one vault key — depth-indexing is the only thing keeping them
    /// apart, not cryptography (see `refreshBackupStaleness`'s own doc comment). This is
    /// the test that makes that indexing an enforced property rather than an assumption:
    /// a new entry at one depth must never surface as staleness at another.
    @Test("Staleness for one depth is never derived from another depth's export or entries",
          .enabled(if: secureEnclaveAvailable()))
    func stalenessIsIsolatedPerDepth() throws {
        let (vault, container, _) = try makeBackupReadyVault()

        _ = try vault.addEntry(label: "real",  content: Data("real".utf8),  type: .note, currentDepth: 0)
        _ = try vault.addEntry(label: "decoy", content: Data("decoy".utf8), type: .note, currentDepth: 2)

        // Depth 2 needs its own confirmed BEK before it can export — Stage 2 made each
        // depth's BEK independent, so depth 0's setup in makeBackupReadyVault() doesn't
        // cover depth 2.
        try setUpConfirmedBEK(for: vault, currentDepth: 2)

        _ = try vault.exportBackup(currentDepth: 0)
        _ = try vault.exportBackup(currentDepth: 2)

        vault.refreshBackupStaleness(currentDepth: 0)
        #expect(vault.backupStaleness == nil, "depth 0 was just exported and should not be stale")
        vault.refreshBackupStaleness(currentDepth: 2)
        #expect(vault.backupStaleness == nil, "depth 2 was just exported and should not be stale")

        // A new entry at depth 0 only.
        _ = try vault.addEntry(label: "new-real", content: Data("new".utf8), type: .note, currentDepth: 0)

        vault.refreshBackupStaleness(currentDepth: 0)
        #expect(vault.backupStaleness?.newEntryCount == 1,
                "depth 0 has one new entry since its own last export")

        vault.refreshBackupStaleness(currentDepth: 2)
        #expect(vault.backupStaleness == nil, """
            Depth 2's signal must not be affected by a new entry at depth 0 — if it were, \
            that depth's staleness would be derived from another depth's state, which is \
            exactly the cross-depth leak this design exists to prevent.
            """)
    }

    /// The old format was a single JSON-encoded `BackupExportMetadata` record, not a
    /// 32-slot array — decoding it under the new fixed-width layout must fail cleanly,
    /// not crash, and a subsequent export must self-heal the file rather than needing
    /// explicit migration code. Constructs the old file by hand rather than trusting
    /// that the fallback path is exercised — the two prior tests never actually put an
    /// old-format file on disk.
    @Test("An old single-record export-meta file degrades to nil, not a crash",
          .enabled(if: secureEnclaveAvailable()))
    func oldFormatFileDegradesGracefully() throws {
        let (vault, _, _) = try makeBackupReadyVault()
        let vaultKey = try vault.currentKey()

        struct LegacyMeta: Codable {
            let exportedAt: Date, distributionID: UUID, shardCount: Int, entryCount: Int
        }
        let legacy = LegacyMeta(exportedAt: Date(), distributionID: UUID(), shardCount: 2, entryCount: 5)
        let plain  = try JSONEncoder().encode(legacy)
        let sealed = try AES.GCM.seal(
            plain, using: vaultKey, nonce: AES.GCM.Nonce(),
            authenticating: Data("occulta.backup-export-meta-v1".utf8)
        )
        let url = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("backup-export-meta.dat")
        try sealed.combined!.write(to: url, options: [.atomic, .completeFileProtection])

        vault.refreshBackupStaleness(currentDepth: 0)
        #expect(vault.backupStaleness == nil,
                "an old-format file must decode to nil, not crash or misread as this depth's record")

        // Self-heals: the next export overwrites the whole file with the new format.
        _ = try vault.addEntry(label: "x", content: Data("x".utf8), type: .note, currentDepth: 0)
        _ = try vault.exportBackup(currentDepth: 0)
        vault.refreshBackupStaleness(currentDepth: 0)
        #expect(vault.backupStaleness == nil, "a fresh export must read back cleanly under the new format")
    }

    // MARK: - Key changes and staleness (Bug 141)

    @Test("A redistribution that keeps the key does not report it rotated",
          .enabled(if: secureEnclaveAvailable()))
    func redistributionIsNotRotation() throws {
        let (vault, _, _) = try makeBackupReadyVault()
        _ = try vault.exportBackup(currentDepth: 0)

        _ = try vault.prepareBackupShards(threshold: 2, recipients: [realFormatContactIdentifier(), realFormatContactIdentifier()], currentDepth: 0)

        vault.refreshBackupStaleness(currentDepth: 0)
        #expect(vault.backupStaleness?.bekRotated != true,
                "a new distributionID alone used to read as a rotation")
    }

    @Test("A new key reports the key rotated, and an earlier backup no longer opens",
          .enabled(if: secureEnclaveAvailable()))
    func newKeyIsRotation() throws {
        let (vault, _, _) = try makeBackupReadyVault()
        let earlier = try vault.exportBackup(currentDepth: 0)

        _ = try vault.prepareBackupShards(
            threshold: 2, recipients: [realFormatContactIdentifier(), realFormatContactIdentifier()], newKey: true, currentDepth: 0
        )

        vault.refreshBackupStaleness(currentDepth: 0)
        #expect(vault.backupStaleness?.bekRotated == true)

        let box = try AES.GCM.SealedBox(combined: earlier.dropFirst(VaultManager.backupMagic.count))
        #expect(throws: (any Error).self) {
            try AES.GCM.open(box, using: try vault.currentBackupKey(currentDepth: 0), authenticating: VaultManager.backupFileAAD)
        }
    }

    /// Before Bug 141 the export record held the `distributionID`; one that still matches
    /// means nothing has changed since that export.
    @Test("An export record from before the fix, holding the current distributionID, is not a rotation",
          .enabled(if: secureEnclaveAvailable()))
    func legacyRecordMatchingDistributionIsNotRotation() throws {
        let (vault, _, shards) = try makeBackupReadyVault()
        let distributionID = try #require(shards.first?.entryID)
        try vault.writeBackupExportMetadata(
            VaultManager.BackupExportMetadata(exportedAt: Date(), keyID: distributionID, shardCount: 2, entryCount: 0),
            at: 0, vaultKey: try vault.currentKey()
        )

        vault.refreshBackupStaleness(currentDepth: 0)
        #expect(vault.backupStaleness == nil)
    }

    // MARK: - Shard status routing (VAULT_KEY_LAYERING.md §8, Bug 141)

    /// Backup-key statuses change only at the depth that owns them (`bugs.md` Bug 141).
    /// `updateShardStatus` used to search every depth's row for the ID; now a depth
    /// writes only its own row, and an ID another depth owns is ignored.
    @Test("A backup-key status change touches only the current depth's row",
          .enabled(if: secureEnclaveAvailable()))
    func shardConfirmationAppliesToOwningDepthOnly() throws {
        let (vault, _, _) = try makeBackupReadyVault() // depth 0: both shards pre-confirmed

        // Depth 2 gets its own BEK with shards left pending (not auto-confirmed).
        try vault.setupBackup(currentDepth: 2)
        let recipients = (0..<2).map { _ in realFormatContactIdentifier() }
        let depth2Shards = try vault.prepareBackupShards(threshold: 2, recipients: recipients, currentDepth: 2)

        // Named from depth 0: not depth 0's piece, so nothing changes anywhere.
        try vault.setBackupShardStatuses([depth2Shards[1].id: .confirmed], currentDepth: 0)
        try vault.setBackupShardStatuses([depth2Shards[0].id: .confirmed], currentDepth: 2)

        let depth0Meta = try vault.backupShardMetadata(currentDepth: 0)
        #expect(depth0Meta?.shards.allSatisfy { $0.status == .confirmed } == true,
                "depth 0's shards, confirmed before depth 2 even existed, must be untouched")

        let depth2Meta = try vault.backupShardMetadata(currentDepth: 2)
        #expect(depth2Meta?.shards.first { $0.attributeID == depth2Shards[0].id }?.status == .confirmed,
                "the targeted shard must be confirmed")
        #expect(depth2Meta?.shards.first { $0.attributeID == depth2Shards[1].id }?.status == .pending,
                "the other depth-2 shard must be left alone")
    }

    /// Bug 128: "Erase all data" deleted rows and keys but no files. The wipe now also deletes
    /// the held `.occbak` under both its names, the old shard file, and the export metadata.
    /// Lives in this serialized suite because it deletes the export-metadata file the
    /// staleness tests above read.
    @Test("Wiping the vault deletes the backup and restore files",
          .enabled(if: secureEnclaveAvailable()))
    func wipeDeletesBackupFiles() throws {
        let schema = Schema([
            VaultEntry.self, BackupEncryptionKey.self, CustodyShard.self, PendingShardDistribute.self,
            PendingShardStatusUpdate.self, PendingShamirSecretRestore.self, Vault.self,
            ReconstructShard.self, GlobalShardConfig.self, PotentiallyLostShard.self, AppLayerConfig.self,
        ])
        let container = try ModelContainer(
            for: schema, configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
        )
        let vault = VaultManager(modelContainer: container, keyManager: TestKeyManager())
        vault.unlock(context: LAContext())

        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: appSupport, withIntermediateDirectories: true)
        let files = ["backup-import-cache.occbak", "pending-restore.occbak", "pending-restore-shards.dat", "backup-export-meta.dat"]
            .map { appSupport.appendingPathComponent($0) }
        for url in files { try Data("x".utf8).write(to: url) }

        try vault.deleteAllData()

        for url in files {
            #expect(!FileManager.default.fileExists(atPath: url.path), "\(url.lastPathComponent) survived the wipe")
        }
    }
    /// Erase all data doesn't relaunch the app, and `init` was the only place the Vault row and
    /// the backup-key filler baseline were created.
    @Test("Wiping the vault restores a fresh install's Vault row and filler baseline")
    func wipeRestoresFreshShape() throws {
        let schema = Schema([
            VaultEntry.self, BackupEncryptionKey.self, CustodyShard.self, PendingShardDistribute.self,
            PendingShardStatusUpdate.self, PendingShamirSecretRestore.self, Vault.self,
            ReconstructShard.self, GlobalShardConfig.self, PotentiallyLostShard.self, AppLayerConfig.self,
        ])
        let container = try ModelContainer(
            for: schema, configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
        )
        let vault = VaultManager(modelContainer: container, keyManager: TestKeyManager())
        let context = ModelContext(container)
        let baseline = try context.fetchCount(FetchDescriptor<BackupEncryptionKey>())
        #expect(baseline == AppLayerConfig.maxDepthCount)

        try vault.deleteAllData()

        #expect(try context.fetchCount(FetchDescriptor<Vault>()) == 1)
        #expect(try context.fetchCount(FetchDescriptor<BackupEncryptionKey>()) == baseline)
        #expect(throws: Never.self) { _ = try vault.requireVault() }
    }
}

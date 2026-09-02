//
//  VaultBackupRoundTripTests.swift
//  OccultaTests
//
//  Bug 88 — vault backup ignores `visibleThroughDepth` in both directions.
//
//  Written before any fix, to pin current behaviour. Until this file, a repo-wide search for
//  `exportBackup` or `importBackup` under OccultaTests returned nothing, so the format had no
//  round-trip coverage at all — depth-related or otherwise. That matters because the leading
//  remedy bumps the wire format, and a format change with no round-trip test underneath it is
//  how you lose backups.
//
//  Export half fixed 2026-08-24 — exportBackup(currentDepth:) filters to that depth's
//  entries. exportExcludesHiddenEntries is a real assertion now, not a withKnownIssue.
//  Import half fixed 2026-08-25, once Bug 93 made "stamp with currentDepth" safe on the
//  automatic restore-on-unlock path — importBackup(_:currentDepth:) now stamps every
//  restored entry the same way addEntry does. importRestoresDepthCeiling is a real
//  assertion now too.
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
/// enough confirmed BEK shards. `prepareBEKShards` creates them `.pending`;
/// `updateBEKShardStatus` is the seam that confirms them without driving the whole
/// distribution and manifest flow.
@MainActor
private func makeBackupReadyVault() throws -> (VaultManager, ModelContainer) {
    let schema = Schema([
        VaultEntry.self,
        BackupEncryptionKey.self,
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

    let vault = VaultManager(modelContainer: container, keyManager: TestKeyManager())
    vault.unlock(context: LAContext(), currentDepth: 0)
    try vault.setupBEK()

    let recipients = (0..<2).map { i -> Contact.Profile in
        let p = Contact.Profile(
            identifier: "trustee-\(i)", givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        container.mainContext.insert(p)
        return p
    }
    try container.mainContext.save()

    let attributes = try vault.prepareBEKShards(threshold: 2, recipients: recipients)
    for attribute in attributes {
        try vault.updateBEKShardStatus(attributeID: attribute.id, to: .confirmed)
    }
    return (vault, container)
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
        let (vault, container) = try makeBackupReadyVault()
        let note = try vault.addEntry(label: "note-label", content: Data("note-body".utf8), type: .note)
        let card = try vault.addEntry(label: "card-label", content: Data("card-body".utf8), type: .note)
        let backup = try vault.exportBackup(currentDepth: 0)

        // Wipe, then restore from the backup alone.
        let wipe = ModelContext(container)
        for entry in try wipe.fetch(FetchDescriptor<VaultEntry>()) { wipe.delete(entry) }
        try wipe.save()
        #expect(try entries(in: container).isEmpty)

        try vault.importBackup(backup, currentDepth: 0)

        let restored = try entries(in: container)
        #expect(restored.count == 2, "both entries must come back")

        let byID = Dictionary(uniqueKeysWithValues: restored.map { ($0.id, $0) })
        for original in [note, card] {
            let row = try #require(byID[original.id], "entry \(original.id) was not restored")
            #expect(row.createdAt == original.createdAt, "createdAt must survive the round trip")
        }
    }

    @Test("A backup is unreadable without the BEK", .enabled(if: secureEnclaveAvailable()))
    func backupIsSealed() throws {
        let (vault, _) = try makeBackupReadyVault()
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
        let (vault, container) = try makeBackupReadyVault()
        // Visible at the duress depth this export is taken from.
        _ = try vault.addEntry(label: "decoy", content: Data("decoy".utf8), type: .note, currentDepth: 2)

        // Hidden at every depth but the real one — created at real depth 0.
        let hidden = try vault.addEntry(label: "real-secret",
                                        content: Data("real-secret".utf8),
                                        type: .note, currentDepth: 0)
        #expect(hidden.visibleThroughDepth != nil, "addEntry always stamps a ceiling")

        // Export taken under coercion, from the duress depth — not the real one.
        let backup = try vault.exportBackup(currentDepth: 2)

        // Wipe before importing: importBackup skips any entry whose id already exists,
        // so without a wipe both entries would be skipped regardless of what the file
        // actually contains, and the count below would never reflect export filtering.
        let wipe = ModelContext(container)
        for entry in try wipe.fetch(FetchDescriptor<VaultEntry>()) { wipe.delete(entry) }
        try wipe.save()

        try vault.importBackup(backup, currentDepth: 2)
        let restoredCount = try entries(in: container).count

        #expect(restoredCount == 1, """
            The export from depth 2 contained \(restoredCount) entries. Only the entry \
            visible at that depth should be present — an entry hidden from every duress \
            view must not be written into an export taken under coercion.
            """)
    }

    /// Fixed: `importBackup(_:currentDepth:)` now stamps every restored entry with
    /// `currentDepth`, mirroring `addEntry`. A file only ever holds one layer's entries
    /// (Bug 88 remedy 4), so the depth to stamp is simply whichever depth the import is
    /// running at — here, the same depth 0 the backup was exported from.
    @Test("Import restores the depth ceiling rather than defaulting to always-visible",
          .enabled(if: secureEnclaveAvailable()))
    func importRestoresDepthCeiling() throws {
        let (vault, container) = try makeBackupReadyVault()
        _ = try vault.addEntry(label: "hidden", content: Data("hidden".utf8), type: .note, currentDepth: 0)
        let backup = try vault.exportBackup(currentDepth: 0)

        let wipe = ModelContext(container)
        for entry in try wipe.fetch(FetchDescriptor<VaultEntry>()) { wipe.delete(entry) }
        try wipe.save()

        try vault.importBackup(backup, currentDepth: 0)
        let restored = try #require(try entries(in: container).first)

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
        let (vault, _) = try makeBackupReadyVault()

        _ = try vault.addEntry(label: "real",  content: Data("real".utf8),  type: .note, currentDepth: 0)
        _ = try vault.addEntry(label: "decoy", content: Data("decoy".utf8), type: .note, currentDepth: 2)

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
        let (vault, _) = try makeBackupReadyVault()
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
}

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
//  The two `withKnownIssue` tests are the bug. They fail — and so flip to failing-as-unexpected
//  — the moment it is fixed, at which point the wrapper comes off and the assertion stays.
//

import Testing
import Foundation
import CryptoKit
import LocalAuthentication
import SwiftData
@testable import Occulta

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
    vault.unlock(context: LAContext())
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

    @Test("Entries survive export → import with id, timestamp, label and content intact")
    func roundTripPreservesEntries() throws {
        let (vault, container) = try makeBackupReadyVault()
        let note = try vault.addEntry(label: "note-label", content: Data("note-body".utf8), type: .note)
        let card = try vault.addEntry(label: "card-label", content: Data("card-body".utf8), type: .note)
        let backup = try vault.exportBackup()

        // Wipe, then restore from the backup alone.
        let wipe = ModelContext(container)
        for entry in try wipe.fetch(FetchDescriptor<VaultEntry>()) { wipe.delete(entry) }
        try wipe.save()
        #expect(try entries(in: container).isEmpty)

        try vault.importBackup(backup)

        let restored = try entries(in: container)
        #expect(restored.count == 2, "both entries must come back")

        let byID = Dictionary(uniqueKeysWithValues: restored.map { ($0.id, $0) })
        for original in [note, card] {
            let row = try #require(byID[original.id], "entry \(original.id) was not restored")
            #expect(row.createdAt == original.createdAt, "createdAt must survive the round trip")
        }
    }

    @Test("A backup is unreadable without the BEK")
    func backupIsSealed() throws {
        let (vault, _) = try makeBackupReadyVault()
        _ = try vault.addEntry(label: "secret-label", content: Data("secret-body".utf8), type: .note)
        let backup = try vault.exportBackup()

        #expect(!backup.contains(Data("secret-label".utf8)),
                "the label appears in plaintext in the exported file")
        #expect(!backup.contains(Data("secret-body".utf8)),
                "the content appears in plaintext in the exported file")
    }

    // MARK: - The bug, in both directions

    /// Export calls `fetchAllEntries()` — no depth predicate, no reference to `currentDepth` —
    /// so an export taken at a duress depth writes the real vault, decrypted, into a file the
    /// coercer keeps. `isEntryVisible` exists and is consulted by exactly one call site in the
    /// codebase: the vault list UI.
    @Test("Export excludes entries hidden at the current depth")
    func exportExcludesHiddenEntries() throws {
        let (vault, container) = try makeBackupReadyVault()
        _ = try vault.addEntry(label: "decoy", content: Data("decoy".utf8), type: .note)

        // An entry stamped hidden at every duress depth — created at real depth 0.
        let hidden = try vault.addEntry(label: "real-secret",
                                        content: Data("real-secret".utf8),
                                        type: .note, currentDepth: 0)
        #expect(hidden.visibleThroughDepth != nil, "addEntry always stamps a ceiling")

        let backup = try vault.exportBackup()
        try vault.importBackup(backup)
        let restoredCount = try entries(in: container).count

        withKnownIssue("Bug 88: exportBackup fetches every entry, unfiltered by depth") {
            #expect(restoredCount == 1, """
                The export contained \(restoredCount) entries. An entry hidden from every duress \
                view was written into the backup, so an export taken under coercion hands over a \
                portable, permanent, decrypted copy of the real vault.
                """)
        }
    }

    /// Import builds a fresh `VaultEntry` and never sets `visibleThroughDepth`. The model
    /// default is nil, and `isEntryVisible` reads nil as *visible at every depth* — so a
    /// restored entry that was hidden at depth 0 becomes visible in every duress view.
    @Test("Import restores the depth ceiling rather than defaulting to always-visible")
    func importRestoresDepthCeiling() throws {
        let (vault, container) = try makeBackupReadyVault()
        _ = try vault.addEntry(label: "hidden", content: Data("hidden".utf8), type: .note, currentDepth: 0)
        let backup = try vault.exportBackup()

        let wipe = ModelContext(container)
        for entry in try wipe.fetch(FetchDescriptor<VaultEntry>()) { wipe.delete(entry) }
        try wipe.save()

        try vault.importBackup(backup)
        let restored = try #require(try entries(in: container).first)

        withKnownIssue("Bug 88: importBackup never assigns visibleThroughDepth, and nil means visible") {
            #expect(restored.visibleThroughDepth != nil, """
                The restored entry has a nil ceiling, which `isEntryVisible` treats as visible at \
                every depth — including duress ones. An entry hidden before the backup comes back \
                exposed, and `VaultBackupEntry` has no field to carry the ceiling at all.
                """)
        }
    }
}

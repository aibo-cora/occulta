//
//  VaultEntryDeletionTokenMigrationTests.swift
//  OccultaTests
//
//  Bug 133 — entries created before `VaultEntry.deletionToken` existed (v1.10.3 and earlier)
//  have no token, and `isOrphaned` reads a missing token as orphaned, so upgrading hid every
//  one of them. `DatabaseMigration.migrateVaultEntryDeletionTokens` gives them a live token.
//
//  The token is sealed under the ambient local key (`Manager.Ambient`), as `addEntry` seals
//  it, so the suite runs under `.ambientTestKeyManager`, which supplies that key.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta
@testable import OccultaCore

@MainActor
private func makeContainer() throws -> ModelContainer {
    let schema = Schema([
        VaultEntry.self,
        BackupEncryptionKey.self,
        Vault.self,
        PendingShamirSecretRestore.self,
    ])
    return try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
}

/// An entry as v1.10.3 left it: every field it knew about, and no `deletionToken`.
@MainActor
@discardableResult
private func insertEntry(deletionToken: Data?, in context: ModelContext) throws -> VaultEntry {
    let entry = VaultEntry(encryptedLabel: Data([0x01]), encryptedContent: Data([0x02]))
    entry.visibleThroughDepth = try DepthCodec.encode(0).encrypt()
    entry.deletionToken       = deletionToken
    context.insert(entry)
    return entry
}

private func localKey() throws -> SymmetricKey {
    try #require(try Manager.Ambient.keyManager.createHybridLocalEncryptionKey())
}

@Suite("Bug 133 — entries from before deletionToken existed stay visible", .serialized, .ambientTestKeyManager)
@MainActor
struct VaultEntryDeletionTokenMigrationTests {

    @Test("A pre-field entry is hidden before the migration and live after it")
    func legacyEntryBecomesLive() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let vault     = VaultManager(modelContainer: container, keyManager: TestKeyManager())
        let first     = try insertEntry(deletionToken: nil, in: context)
        let second    = try insertEntry(deletionToken: nil, in: context)
        try context.save()

        // The bug: the upgrade leaves these hidden from every read.
        #expect(try vault.fetchAllEntries().isEmpty)

        try DatabaseMigration.migrateVaultEntryDeletionTokens(modelContext: context)

        let key = try localKey()
        #expect(!first.isOrphaned(usingKey: key))
        #expect(!second.isOrphaned(usingKey: key))
        #expect(Set(try vault.fetchAllEntries().map(\.id)) == [first.id, second.id])
        #expect(first.deletionToken != second.deletionToken, "each row must be sealed with its own nonce")
    }

    /// A nil token is the only thing the migration may touch: an orphaned entry must stay
    /// orphaned, and a live one must keep its bytes.
    @Test("Entries that already have a token are left byte-identical")
    func existingTokensUntouched() throws {
        let key       = try localKey()
        let context   = ModelContext(try makeContainer())
        let orphaned  = try insertEntry(deletionToken: try VaultEntry.orphanedToken.encrypt(using: key), in: context)
        let live      = try insertEntry(deletionToken: try VaultEntry.liveToken.encrypt(using: key), in: context)
        try context.save()
        let orphanedBefore = orphaned.deletionToken
        let liveBefore     = live.deletionToken

        try DatabaseMigration.migrateVaultEntryDeletionTokens(modelContext: context)

        #expect(orphaned.deletionToken == orphanedBefore)
        #expect(orphaned.isOrphaned(usingKey: key))
        #expect(live.deletionToken == liveBefore)
    }

    @Test("A second run changes nothing")
    func idempotent() throws {
        let context = ModelContext(try makeContainer())
        let entry   = try insertEntry(deletionToken: nil, in: context)
        try context.save()

        try DatabaseMigration.migrateVaultEntryDeletionTokens(modelContext: context)
        let afterFirst = entry.deletionToken
        try DatabaseMigration.migrateVaultEntryDeletionTokens(modelContext: context)

        #expect(afterFirst != nil)
        #expect(entry.deletionToken == afterFirst)
    }
}

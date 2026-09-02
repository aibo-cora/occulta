//
//  GlobalTrusteeDepthTests.swift
//  OccultaTests
//
//  Coverage for Contact.Profile.globalTrusteeDepth: exact-match read/write, and
//  isolation from GlobalShardConfig (the real, depth-0 trustee list). Encrypted
//  round-trips require the Secure Enclave and guard on secureEnclaveAvailable(),
//  matching the pattern established in GroupModelTests.swift.
//

import Testing
import Foundation
import SwiftData
import CryptoKit
@testable import Occulta

// MARK: - Helpers

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

@MainActor
private func makeContainer() throws -> ModelContainer {
    let schema = Schema([
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
        GlobalShardConfig.self,
    ])
    return try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
}

@MainActor
private func makeContactManager() throws -> (ContactManager, ModelContainer) {
    let container = try makeContainer()
    let security  = try Manager.Security(modelContainer: container, keyManager: TestKeyManager())
    return (ContactManager(modelContainer: container, security: security), container)
}

@discardableResult
@MainActor
private func insertPlainProfile(identifier: String, globalTrusteeDepth: Data? = nil,
                                 visibleThroughDepth: Data? = nil, in cm: ContactManager) throws -> Contact.Profile {
    let profile = Contact.Profile(
        identifier: identifier, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.globalTrusteeDepth  = globalTrusteeDepth
    profile.visibleThroughDepth = visibleThroughDepth
    try cm.insertProfile(profile)
    return profile
}

// MARK: - Read: isGlobalTrustee / globalTrusteeIdentifiers

@MainActor
@Suite("ContactManager — globalTrusteeDepth reads", .serialized)
struct GlobalTrusteeDepthReadTests {

    @Test func isGlobalTrustee_exactMatchAtCurrentDepth_true() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let (cm, _) = try makeContactManager()
        let id = UUID().uuidString
        try insertPlainProfile(identifier: id, globalTrusteeDepth: try JSONEncoder().encode(0).encrypt(), in: cm)
        #expect(cm.isGlobalTrustee(id))
    }

    @Test func isGlobalTrustee_differentDepth_false() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let (cm, _) = try makeContactManager()
        let id = UUID().uuidString
        try insertPlainProfile(identifier: id, globalTrusteeDepth: try JSONEncoder().encode(2).encrypt(), in: cm)
        // currentDepth defaults to 0 — a depth-2 stamp must not read as a trustee here.
        #expect(!cm.isGlobalTrustee(id))
    }

    @Test func isGlobalTrustee_sentinelNotTrustee_false() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let (cm, _) = try makeContactManager()
        let id = UUID().uuidString
        try insertPlainProfile(identifier: id, globalTrusteeDepth: try JSONEncoder().encode(-1).encrypt(), in: cm)
        #expect(!cm.isGlobalTrustee(id))
    }

    @Test func isGlobalTrustee_nilLegacy_false() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let (cm, _) = try makeContactManager()
        let id = UUID().uuidString
        try insertPlainProfile(identifier: id, globalTrusteeDepth: nil, in: cm)
        #expect(!cm.isGlobalTrustee(id))
    }

    @Test func globalTrusteeIdentifiers_filtersToExactCurrentDepth() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let (cm, _) = try makeContactManager()
        let trusteeID    = UUID().uuidString
        let otherDepthID = UUID().uuidString
        try insertPlainProfile(identifier: trusteeID,    globalTrusteeDepth: try JSONEncoder().encode(0).encrypt(), in: cm)
        try insertPlainProfile(identifier: otherDepthID, globalTrusteeDepth: try JSONEncoder().encode(1).encrypt(), in: cm)
        #expect(cm.globalTrusteeIdentifiers() == [trusteeID])
    }

    @Test func globalTrusteeIdentifiers_excludesNonDisplayableContact() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let (cm, _) = try makeContactManager()
        let hiddenID = UUID().uuidString
        // Ceiling 0: visible only through depth 0. Move to duress depth 1 below —
        // this contact becomes non-displayable even though it's stamped a trustee.
        try insertPlainProfile(
            identifier: hiddenID,
            globalTrusteeDepth: try JSONEncoder().encode(1).encrypt(),
            visibleThroughDepth: try JSONEncoder().encode(0).encrypt(),
            in: cm
        )
        cm.security.applyVerifyState(for: .duress)
        #expect(cm.security.currentDepth == 1)
        #expect(cm.globalTrusteeIdentifiers().isEmpty,
                "a contact hidden at the current depth must never surface as a trustee suggestion, even if stamped one")
    }
}

// MARK: - Write: saveGlobalTrusteeDepth

@MainActor
@Suite("ContactManager — saveGlobalTrusteeDepth", .serialized)
struct SaveGlobalTrusteeDepthTests {

    @Test func stampsSelectedAtCurrentDepth_othersGetSentinel() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let (cm, _) = try makeContactManager()
        let selectedID   = UUID().uuidString
        let unselectedID = UUID().uuidString
        try insertPlainProfile(identifier: selectedID, in: cm)
        try insertPlainProfile(identifier: unselectedID, in: cm)

        try cm.saveGlobalTrusteeDepth(selectedIDs: [selectedID])

        #expect(cm.isGlobalTrustee(selectedID))
        #expect(!cm.isGlobalTrustee(unselectedID))
    }

    @Test func skipsNonDisplayableContact_leavesItsFieldUntouched() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let (cm, _) = try makeContactManager()
        let hiddenID = UUID().uuidString
        let profile = try insertPlainProfile(
            identifier: hiddenID,
            visibleThroughDepth: try JSONEncoder().encode(0).encrypt(),
            in: cm
        )
        cm.security.applyVerifyState(for: .duress)
        #expect(cm.security.currentDepth == 1)

        try cm.saveGlobalTrusteeDepth(selectedIDs: [hiddenID])

        #expect(profile.globalTrusteeDepth == nil,
                "a contact not displayable at the current depth must not be touched by the save")
    }

    /// GlobalShardConfig is orphaned as of item 3's consolidation (see the
    /// shard-custody bug doc) — saveGlobalTrusteeDepth never touches it, at depth 0
    /// or any duress depth. Only DatabaseMigration.migrateGlobalShardConfigToPerContact
    /// ever reads it, and only once.
    @Test func neverTouchesGlobalShardConfig_atAnyDepth() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let (cm, container) = try makeContactManager()

        // Pre-populate a GlobalShardConfig row with known content — a leftover from
        // before the item 3 consolidation migration has run.
        let ctx = ModelContext(container)
        let sentinelPayload = Data([0xDE, 0xAD, 0xBE, 0xEF])
        ctx.insert(GlobalShardConfig(encryptedPayload: sentinelPayload))
        try ctx.save()

        for depth in [0, 1] {
            if depth == 1 { cm.security.applyVerifyState(for: .duress) }
            #expect(cm.security.currentDepth == depth)

            let id = UUID().uuidString
            try insertPlainProfile(identifier: id, in: cm)
            try cm.saveGlobalTrusteeDepth(selectedIDs: [id])

            #expect(cm.isGlobalTrustee(id))
        }

        let freshCtx = ModelContext(container)
        let rows = try freshCtx.fetch(FetchDescriptor<GlobalShardConfig>())
        #expect(rows.count == 1)
        #expect(rows.first?.encryptedPayload == sentinelPayload,
                "saveGlobalTrusteeDepth must never touch GlobalShardConfig, at any depth — it is orphaned.")
    }
}

// MARK: - Backfill migration

@MainActor
@Suite("DatabaseMigration — globalTrusteeDepth backfill", .serialized)
struct GlobalTrusteeDepthBackfillTests {

    @Test func backfillsNilRowsToSentinel_leavesExistingValuesAlone() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let (cm, container) = try makeContactManager()
        let legacyID  = UUID().uuidString
        let stampedID = UUID().uuidString
        try insertPlainProfile(identifier: legacyID, globalTrusteeDepth: nil, in: cm)
        try insertPlainProfile(identifier: stampedID, globalTrusteeDepth: try JSONEncoder().encode(3).encrypt(), in: cm)

        try DatabaseMigration.migrateGlobalTrusteeDepthBackfill(modelContext: ModelContext(container))

        let freshCtx = ModelContext(container)
        let profiles = try freshCtx.fetch(FetchDescriptor<Contact.Profile>())
        let legacy  = profiles.first { $0.identifier == legacyID }
        let stamped = profiles.first { $0.identifier == stampedID }

        #expect(legacy?.globalTrusteeDepth != nil, "legacy nil row must be backfilled")
        #expect(
            legacy?.globalTrusteeDepth.flatMap { $0.decrypt() }
                .flatMap { DepthCodec.decode($0) } == -1,
            "backfilled value must be the -1 sentinel"
        )
        #expect(
            stamped?.globalTrusteeDepth.flatMap { $0.decrypt() }
                .flatMap { DepthCodec.decode($0) } == 3,
            "an already-stamped row must not be overwritten by the backfill"
        )
    }

    @Test func idempotent_secondRunIsNoOp() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let (cm, container) = try makeContactManager()
        try insertPlainProfile(identifier: UUID().uuidString, globalTrusteeDepth: nil, in: cm)

        try DatabaseMigration.migrateGlobalTrusteeDepthBackfill(modelContext: ModelContext(container))
        let afterFirst = try ModelContext(container).fetch(FetchDescriptor<Contact.Profile>())
            .map(\.globalTrusteeDepth)

        try DatabaseMigration.migrateGlobalTrusteeDepthBackfill(modelContext: ModelContext(container))
        let afterSecond = try ModelContext(container).fetch(FetchDescriptor<Contact.Profile>())
            .map(\.globalTrusteeDepth)

        #expect(afterFirst == afterSecond)
    }
}

// MARK: - Consolidation migration

@MainActor
@Suite("DatabaseMigration — GlobalShardConfig consolidation", .serialized)
struct GlobalShardConfigConsolidationMigrationTests {

    /// Manually seals a GlobalShardConfig row — mirrors ShardCustodyManager's own
    /// private sealRow/rowAAD, since the write path itself was removed as part of
    /// this consolidation (see the shard-custody bug doc, item 3).
    private func insertLegacyConfig(trusteeIDs: [String], in container: ModelContainer, using km: TestKeyManager) throws {
        guard let custodyKey = try km.deriveShardCustodyKey() else {
            Issue.record("test key manager could not derive custody key")
            return
        }
        let rowID   = UUID()
        let payload = GlobalShardConfig.Payload(trusteeIDs: trusteeIDs)
        let sealed  = try AES.GCM.seal(
            JSONEncoder().encode(payload), using: custodyKey, nonce: AES.GCM.Nonce(),
            authenticating: rowID.uuidString.data(using: .utf8)!
        )
        guard let combined = sealed.combined else { Issue.record("seal failed"); return }
        let ctx = ModelContext(container)
        ctx.insert(GlobalShardConfig(id: rowID, encryptedPayload: combined))
        try ctx.save()
    }

    @Test func migratesExistingTrusteesToDepthZero_thenDeletesRow() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let (cm, container) = try makeContactManager()
        let km      = TestKeyManager()
        let custody = ShardCustodyManager(modelContainer: container, keyManager: km)

        let trusteeID    = UUID().uuidString
        let nonTrusteeID = UUID().uuidString
        try insertPlainProfile(identifier: trusteeID, in: cm)
        try insertPlainProfile(identifier: nonTrusteeID, in: cm)
        try self.insertLegacyConfig(trusteeIDs: [trusteeID], in: container, using: km)

        try DatabaseMigration.migrateGlobalShardConfigToPerContact(
            modelContext: ModelContext(container), shardCustodyManager: custody
        )

        #expect(cm.isGlobalTrustee(trusteeID))
        #expect(!cm.isGlobalTrustee(nonTrusteeID))

        let remainingRows = try ModelContext(container).fetch(FetchDescriptor<GlobalShardConfig>())
        #expect(remainingRows.isEmpty, "GlobalShardConfig row must be deleted once its data has been migrated")
    }

    @Test func noExistingConfig_isNoOp() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let (_, container) = try makeContactManager()
        let custody = ShardCustodyManager(modelContainer: container, keyManager: TestKeyManager())

        try DatabaseMigration.migrateGlobalShardConfigToPerContact(
            modelContext: ModelContext(container), shardCustodyManager: custody
        )

        let rows = try ModelContext(container).fetch(FetchDescriptor<GlobalShardConfig>())
        #expect(rows.isEmpty)
    }

    @Test func idempotent_secondRunIsNoOp() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let (cm, container) = try makeContactManager()
        let km      = TestKeyManager()
        let custody = ShardCustodyManager(modelContainer: container, keyManager: km)

        let trusteeID = UUID().uuidString
        try insertPlainProfile(identifier: trusteeID, in: cm)
        try self.insertLegacyConfig(trusteeIDs: [trusteeID], in: container, using: km)

        try DatabaseMigration.migrateGlobalShardConfigToPerContact(
            modelContext: ModelContext(container), shardCustodyManager: custody
        )
        try DatabaseMigration.migrateGlobalShardConfigToPerContact(
            modelContext: ModelContext(container), shardCustodyManager: custody
        )

        #expect(cm.isGlobalTrustee(trusteeID))
        let rows = try ModelContext(container).fetch(FetchDescriptor<GlobalShardConfig>())
        #expect(rows.isEmpty)
    }
}

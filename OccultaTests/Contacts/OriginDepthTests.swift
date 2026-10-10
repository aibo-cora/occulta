//
//  OriginDepthTests.swift
//  OccultaTests
//
//  Coverage for Contact.Profile.originDepth: floor-semantics visibility for
//  duress-origin contacts, sensitivity classification being a deliberate no-op for
//  them, creation-time stamping, and the backfill migration. Encrypted round-trips
//  run under `.ambientTestKeyManager`, which supplies the local DB key.
//

import Testing
import Foundation
import SwiftData
import CryptoKit
@testable import Occulta
@testable import OccultaFormats

// MARK: - Helpers

@MainActor
private func makeContainer() throws -> ModelContainer {
    let schema = Schema([
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
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
private func insertPlainProfile(
    identifier: String,
    originDepth: Data? = nil,
    visibleThroughDepth: Data? = nil,
    in cm: ContactManager
) throws -> Contact.Profile {
    let profile = Contact.Profile(
        identifier: identifier, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.originDepth         = originDepth
    profile.visibleThroughDepth = visibleThroughDepth
    try cm.insertProfile(profile)
    return profile
}

// MARK: - isVisible floor semantics

@MainActor
@Suite("Contact.Profile.isVisible — originDepth floor semantics", .serialized)
struct OriginDepthFloorTests {

    @Test(.ambientTestKeyManager) func bornAtDepth1_visibleAtItsOwnDepth() throws {
        let (cm, _) = try makeContactManager()
        let profile = try insertPlainProfile(
            identifier: UUID().uuidString,
            originDepth: try JSONEncoder().encode(1).encrypt(),
            in: cm
        )
        #expect(profile.isVisible(atDepth: 1))
    }

    @Test(.ambientTestKeyManager) func bornAtDepth1_visibleAtEveryDeeperNestedLayer() throws {
        let (cm, _) = try makeContactManager()
        let profile = try insertPlainProfile(
            identifier: UUID().uuidString,
            originDepth: try JSONEncoder().encode(1).encrypt(),
            in: cm
        )
        #expect(profile.isVisible(atDepth: 2))
        #expect(profile.isVisible(atDepth: 5))
    }

    @Test(.ambientTestKeyManager) func bornAtDepth1_hiddenAtTheRealDepth() throws {
        let (cm, _) = try makeContactManager()
        let profile = try insertPlainProfile(
            identifier: UUID().uuidString,
            originDepth: try JSONEncoder().encode(1).encrypt(),
            in: cm
        )
        #expect(!profile.isVisible(atDepth: 0),
                "a duress-origin contact must never leak into the real depth-0 view")
    }

    @Test(.ambientTestKeyManager) func notDuressOrigin_ceilingLogicUnaffected() throws {
        let (cm, _) = try makeContactManager()
        // originDepth = 0 (the sentinel) — defers entirely to visibleThroughDepth's ceiling.
        let profile = try insertPlainProfile(
            identifier: UUID().uuidString,
            originDepth: try JSONEncoder().encode(0).encrypt(),
            visibleThroughDepth: try JSONEncoder().encode(1).encrypt(),
            in: cm
        )
        #expect(profile.isVisible(atDepth: 0))
        #expect(profile.isVisible(atDepth: 1))
        #expect(!profile.isVisible(atDepth: 2), "ceiling semantics must still apply normally when originDepth is 0")
    }

    @Test(.ambientTestKeyManager) func sensitivityClassification_isNoOpForDuressOriginContact() throws {
        let (cm, _) = try makeContactManager()
        // Born at depth 1, but ALSO stamped with a ceiling of 1 (as if "marked sensitive"
        // while at depth 1 — the exact scenario that motivated floor-not-exact-match).
        // The ceiling must be completely ignored: floor-only visibility, unaffected by
        // any sensitivity classification on this contact.
        let profile = try insertPlainProfile(
            identifier: UUID().uuidString,
            originDepth: try JSONEncoder().encode(1).encrypt(),
            visibleThroughDepth: try JSONEncoder().encode(1).encrypt(),
            in: cm
        )
        #expect(profile.isVisible(atDepth: 2),
                "sensitivity classification must never re-hide a duress-origin contact at a deeper nested layer")
    }

    @Test(.ambientTestKeyManager) func nilOriginDepth_treatedAsSentinelNotAsUndecryptable() throws {
        let (cm, _) = try makeContactManager()
        // Legacy row predating the field — nil, not yet backfilled.
        let profile = try insertPlainProfile(
            identifier: UUID().uuidString,
            originDepth: nil,
            visibleThroughDepth: try JSONEncoder().encode(Int.max).encrypt(),
            in: cm
        )
        #expect(profile.isVisible(atDepth: 0))
        #expect(profile.isVisible(atDepth: 3), "a legacy contact must fall back to normal ceiling behavior, not be treated as duress-origin")
    }

    /// Regression test for the fail-open decode gap: a present-but-undecryptable
    /// originDepth must exclude the contact outright, never fall through to the
    /// ceiling check — falling through would mean a duress-origin contact whose
    /// origin becomes unreadable loses its protection and can leak to depth 0 the
    /// instant its (still-valid) visibleThroughDepth ceiling includes 0, which it
    /// always does for a contact stamped at creation (ceiling >= 0 is always true).
    @Test(.ambientTestKeyManager) func undecryptableOriginDepth_excludesOutright_neverFallsThroughToCeiling() throws {
        let (cm, _) = try makeContactManager()
        // Present but garbage — decrypt() will fail. visibleThroughDepth is Int.max,
        // which would make this contact visible everywhere if the check fell through.
        let profile = try insertPlainProfile(
            identifier: UUID().uuidString,
            originDepth: Data([0xFF, 0xFE, 0x00, 0x01]),
            visibleThroughDepth: try JSONEncoder().encode(Int.max).encrypt(),
            in: cm
        )
        #expect(!profile.isVisible(atDepth: 0),
                "undecryptable originDepth must exclude the contact, not fall through to an Int.max ceiling")
        #expect(!profile.isVisible(atDepth: 5),
                "exclusion must hold at every depth, not just 0")
    }
}

// MARK: - Creation-time stamping

@MainActor
@Suite("ContactManager — originDepth creation-time stamping", .serialized)
struct OriginDepthCreationTests {

    @Test(.ambientTestKeyManager) func savedAtRealDepth_stampsZeroSentinel() throws {
        let (cm, _) = try makeContactManager()
        let draft = Contact.Draft(identifier: UUID().uuidString, givenName: "A", familyName: "B")
        try cm.save(contact: draft, currentDepth: 0)

        let saved = try cm.fetchAllContacts().first { $0.identifier.decrypt() == draft.identifier }
        #expect(saved != nil)
        let decoded = saved?.originDepth.flatMap { $0.decrypt() }.flatMap { DepthCodec.decode($0) }
        #expect(decoded == 0, "a contact created at the real depth must be stamped with the 0 sentinel")
    }

    @Test(.ambientTestKeyManager) func savedAtDuressDepth_stampsThatDepth() throws {
        let (cm, _) = try makeContactManager()
        let draft = Contact.Draft(identifier: UUID().uuidString, givenName: "A", familyName: "B")
        try cm.save(contact: draft, currentDepth: 2)

        let saved = try cm.fetchAllContacts().first { $0.identifier.decrypt() == draft.identifier }
        #expect(saved != nil)
        let decoded = saved?.originDepth.flatMap { $0.decrypt() }.flatMap { DepthCodec.decode($0) }
        #expect(decoded == 2, "a contact created while at duress depth 2 must be stamped originDepth = 2")
        #expect(saved!.isVisible(atDepth: 2))
        #expect(saved!.isVisible(atDepth: 3))
        #expect(!saved!.isVisible(atDepth: 0))
    }
}

// MARK: - Backfill migration

@MainActor
@Suite("DatabaseMigration — originDepth backfill", .serialized)
struct OriginDepthBackfillTests {

    @Test(.ambientTestKeyManager) func backfillsNilRowsToSentinel_leavesExistingValuesAlone() throws {
        let (cm, container) = try makeContactManager()
        let legacyID  = UUID().uuidString
        let stampedID = UUID().uuidString
        try insertPlainProfile(identifier: legacyID, originDepth: nil, in: cm)
        try insertPlainProfile(identifier: stampedID, originDepth: try JSONEncoder().encode(3).encrypt(), in: cm)

        try DatabaseMigration.migrateOriginDepthBackfill(modelContext: ModelContext(container))

        let freshCtx = ModelContext(container)
        let profiles = try freshCtx.fetch(FetchDescriptor<Contact.Profile>())
        let legacy  = profiles.first { $0.identifier == legacyID }
        let stamped = profiles.first { $0.identifier == stampedID }

        #expect(legacy?.originDepth != nil, "legacy nil row must be backfilled")
        #expect(
            legacy?.originDepth.flatMap { $0.decrypt() }
                .flatMap { DepthCodec.decode($0) } == 0,
            "backfilled value must be the 0 sentinel"
        )
        #expect(
            stamped?.originDepth.flatMap { $0.decrypt() }
                .flatMap { DepthCodec.decode($0) } == 3,
            "an already-stamped row must not be overwritten by the backfill"
        )
    }

    @Test(.ambientTestKeyManager) func idempotent_secondRunIsNoOp() throws {
        let (cm, container) = try makeContactManager()
        try insertPlainProfile(identifier: UUID().uuidString, originDepth: nil, in: cm)

        try DatabaseMigration.migrateOriginDepthBackfill(modelContext: ModelContext(container))
        let afterFirst = try ModelContext(container).fetch(FetchDescriptor<Contact.Profile>())
            .map(\.originDepth)

        try DatabaseMigration.migrateOriginDepthBackfill(modelContext: ModelContext(container))
        let afterSecond = try ModelContext(container).fetch(FetchDescriptor<Contact.Profile>())
            .map(\.originDepth)

        #expect(afterFirst == afterSecond)
    }
}

// MARK: - visibleContactIdentifiers

/// The set `VaultManager.restoreBackup` counts banked restore shards against: only shards from
/// these contacts count at the depth (`RECOVERY_BUFFER_LAYERING.md` §9.4).
@MainActor
@Suite("ContactManager.visibleContactIdentifiers — which restore shards count at a depth",
       .serialized, .ambientTestKeyManager)
struct VisibleContactIdentifiersTests {

    @Test func matchesVisibilityAtEachDepth() throws {
        let (cm, _) = try makeContactManager()
        try insertPlainProfile(identifier: "everywhere", in: cm)
        try insertPlainProfile(identifier: "hidden-trustee", visibleThroughDepth: DepthCodec.encode(0).encrypt(), in: cm)
        try insertPlainProfile(identifier: "coercer", originDepth: DepthCodec.encode(2).encrypt(), in: cm)

        let deleted = Contact.Profile(
            identifier: "deleted", givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        deleted.deletionToken = Data([0x01])
        try cm.insertProfile(deleted)

        #expect(cm.visibleContactIdentifiers(atDepth: 0) == ["everywhere", "hidden-trustee"],
                "a coercer's contact, created in his layer, must not count at depth 0")
        #expect(cm.visibleContactIdentifiers(atDepth: 2) == ["everywhere", "coercer"],
                "a trustee the owner hid from the duress layer must not count there")
    }
}

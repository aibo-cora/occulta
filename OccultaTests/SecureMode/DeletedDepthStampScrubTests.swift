//
//  DeletedDepthStampScrubTests.swift
//  OccultaTests
//
//  Bug 89 — a soft-deleted row's depth stamps must not keep their legacy length.
//
//  Needs no Secure Enclave, and that is the point of the design rather than a convenience:
//  the scrub never encrypts and never decrypts, so an unavailable key cannot block it.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta

@MainActor
private func makeContainer() throws -> ModelContainer {
    let schema = Schema([
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
        VaultEntry.self,
        AppLayerConfig.self,
    ])
    return try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
}

@MainActor
@discardableResult
private func insert(_ id: String, deleted: Bool, stamps: Data?,
                    in context: ModelContext) -> Contact.Profile {
    let profile = Contact.Profile(
        identifier: id, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.visibleThroughDepth = stamps
    profile.globalTrusteeDepth  = stamps
    profile.originDepth         = stamps
    if deleted { profile.deletionToken = Data([0xDE, 0xAD]) }
    context.insert(profile)
    return profile
}

/// A legacy `Int.max` sealed under the old format: 19 plaintext bytes plus AES-GCM's 28.
private let legacyIntMax = Data(repeating: 0xA1, count: 47)
/// A legacy small depth — the value that says a contact was classified as sensitive.
private let legacySmallDepth = Data(repeating: 0xB2, count: 29)

@Suite("Bug 89 — soft-deleted depth stamp scrub", .serialized)
@MainActor
struct DeletedDepthStampScrubTests {

    /// The leak. A 29-byte stamp can only come from a classification write or from creation
    /// at a duress depth, and both say Secure Mode was configured — so a stranded row that
    /// keeps its legacy length still carries that inference.
    @Test("A soft-deleted row's stamps are brought to the uniform length")
    func deletedRowStampsAreScrubbed() throws {
        let context = ModelContext(try makeContainer())
        insert("deleted", deleted: true, stamps: legacySmallDepth, in: context)
        try context.save()

        try DatabaseMigration.migrateScrubDeletedDepthStamps(modelContext: context)

        let row = try #require(try context.fetch(FetchDescriptor<Contact.Profile>()).first)
        #expect(row.visibleThroughDepth?.count == DepthCodec.sealedSize, """
            A stranded 29-byte stamp still says a contact was classified sensitive, which \
            says Secure Mode was configured — on a row whose content is already erased.
            """)
        #expect(row.globalTrusteeDepth?.count == DepthCodec.sealedSize)
        #expect(row.originDepth?.count        == DepthCodec.sealedSize)
    }

    /// The constraint that keeps this apart from Bug 87. A live row's unreadable ceiling
    /// still means *hidden* — `isVisible` fails closed on it — so overwriting one would
    /// un-hide the contact it was hiding.
    @Test("A live row is never touched, whatever its stamps look like")
    func liveRowIsUntouched() throws {
        let context = ModelContext(try makeContainer())
        insert("live", deleted: false, stamps: legacyIntMax, in: context)
        try context.save()

        try DatabaseMigration.migrateScrubDeletedDepthStamps(modelContext: context)

        let row = try #require(try context.fetch(FetchDescriptor<Contact.Profile>()).first)
        #expect(row.visibleThroughDepth == legacyIntMax, """
            A live row's stamps must be left alone even when they are the wrong length. An \
            unreadable ceiling on a live row still reads as hidden; overwriting it is Bug 87.
            """)
    }

    /// Per field, not per row. A deleted row can legitimately have one stamp already at the
    /// uniform length — the three backfills do not filter `deletionToken`, so they stamp
    /// current-key values onto deleted rows — and that one must not be needlessly rewritten.
    @Test("Only the stamps that need it are rewritten")
    func scrubIsPerFieldNotPerRow() throws {
        let context = ModelContext(try makeContainer())
        let alreadyUniform = Data(repeating: 0xC3, count: DepthCodec.sealedSize)
        let row = insert("mixed", deleted: true, stamps: legacyIntMax, in: context)
        row.globalTrusteeDepth = alreadyUniform
        try context.save()

        try DatabaseMigration.migrateScrubDeletedDepthStamps(modelContext: context)

        let fetched = try #require(try context.fetch(FetchDescriptor<Contact.Profile>()).first)
        #expect(fetched.globalTrusteeDepth == alreadyUniform,
                "a stamp already at the uniform length must not be rewritten")
        #expect(fetched.visibleThroughDepth?.count == DepthCodec.sealedSize)
        #expect(fetched.visibleThroughDepth != legacyIntMax)
    }

    /// It runs on every launch, so a second pass must change nothing — otherwise every start
    /// re-randomises the stamps of up to 50 rows for no reason.
    @Test("A second run changes nothing")
    func scrubIsIdempotent() throws {
        let context = ModelContext(try makeContainer())
        insert("deleted", deleted: true, stamps: legacySmallDepth, in: context)
        try context.save()

        try DatabaseMigration.migrateScrubDeletedDepthStamps(modelContext: context)
        let afterFirst = try #require(
            try context.fetch(FetchDescriptor<Contact.Profile>()).first
        ).visibleThroughDepth

        try DatabaseMigration.migrateScrubDeletedDepthStamps(modelContext: context)
        let afterSecond = try #require(
            try context.fetch(FetchDescriptor<Contact.Profile>()).first
        ).visibleThroughDepth

        #expect(afterFirst == afterSecond)
    }

    /// nil is its own tell (S6): every contact has carried a non-nil stamp since creation, so
    /// a nil one stands out against that baseline rather than blending into it.
    @Test("A nil stamp on a deleted row is filled, not left nil")
    func nilStampIsFilled() throws {
        let context = ModelContext(try makeContainer())
        insert("deleted", deleted: true, stamps: nil, in: context)
        try context.save()

        try DatabaseMigration.migrateScrubDeletedDepthStamps(modelContext: context)

        let row = try #require(try context.fetch(FetchDescriptor<Contact.Profile>()).first)
        #expect(row.visibleThroughDepth?.count == DepthCodec.sealedSize)
    }

    /// The property the whole bug is about, stated directly: after the pass, live and deleted
    /// rows are one length. `DepthCodecTests` asserts this for live rows only, which is why
    /// this survived Bug 85's fix.
    @Test("Live and deleted rows end at one length")
    func everyRowIsOneLength() throws {
        let context = ModelContext(try makeContainer())
        insert("live",    deleted: false, stamps: try DepthCodec.encode(Int.max).encrypt()
                                                  ?? Data(repeating: 0, count: DepthCodec.sealedSize),
               in: context)
        insert("deleted", deleted: true,  stamps: legacySmallDepth, in: context)
        insert("deleted2", deleted: true, stamps: legacyIntMax,     in: context)
        try context.save()

        try DatabaseMigration.migrateScrubDeletedDepthStamps(modelContext: context)

        let lengths = Set(
            try context.fetch(FetchDescriptor<Contact.Profile>())
                .compactMap { $0.visibleThroughDepth?.count }
        )
        #expect(lengths == [DepthCodec.sealedSize],
                "lengths \(lengths.sorted()) — a row still names its former classification")
    }
}

// MARK: - Bug 97

/// The three backfills matched purely on the field being nil, with no `deletionToken`
/// filter — so a deleted row with a nil stamp got sealed under the *current* key by
/// ordinary backfill logic, indistinguishable from a live contact's stamp being written.
/// That's the exact asymmetry Bug 88's keyless-filler remedy exists to avoid: a deleted
/// row's other fields don't decrypt under the current key, so one current-key field on
/// that row is a tell in itself. Reuses `DeletedDepthStampScrubTests`' harness — same
/// bug family, same "how deleted rows interact with depth-stamp writes" concern, just
/// the backfill side of it rather than the scrub side.
@Suite("Bug 97 — depth-field backfills exclude soft-deleted rows", .serialized)
@MainActor
struct DeletedRowBackfillExclusionTests {

    private func runAllBackfills(_ context: ModelContext) throws {
        try DatabaseMigration.migrateSafeContactVisibilityBackfill(modelContext: context)
        try DatabaseMigration.migrateGlobalTrusteeDepthBackfill(modelContext: context)
        try DatabaseMigration.migrateOriginDepthBackfill(modelContext: context)
    }

    /// The defect, and its fix.
    @Test("A soft-deleted row's nil stamps are left for the scrub, not backfilled")
    func deletedRowIsExcludedFromBackfill() throws {
        let context = ModelContext(try makeContainer())
        insert("deleted", deleted: true, stamps: nil, in: context)
        try context.save()

        try self.runAllBackfills(context)

        let row = try #require(try context.fetch(FetchDescriptor<Contact.Profile>()).first)
        #expect(row.visibleThroughDepth == nil, """
            A deleted row's nil stamp was sealed under the current key by the backfill — \
            exactly the asymmetry Bug 88's keyless-filler remedy exists to avoid. This row \
            must be left nil for migrateScrubDeletedDepthStamps to handle with keyless \
            random bytes instead.
            """)
        #expect(row.globalTrusteeDepth == nil)
        #expect(row.originDepth == nil)
    }

    /// The constraint that keeps this from over-scoping: a live row's nil stamp is
    /// exactly the case the backfill exists to fix, and must still be stamped.
    @Test("A live row's nil stamps are still backfilled normally")
    func liveRowIsStillBackfilled() throws {
        let context = ModelContext(try makeContainer())
        insert("live", deleted: false, stamps: nil, in: context)
        try context.save()

        try self.runAllBackfills(context)

        let row = try #require(try context.fetch(FetchDescriptor<Contact.Profile>()).first)
        #expect(row.visibleThroughDepth?.count == DepthCodec.sealedSize,
                "a live row's nil stamp must still be backfilled — this is the case the fix exists for")
        #expect(row.globalTrusteeDepth?.count == DepthCodec.sealedSize)
        #expect(row.originDepth?.count == DepthCodec.sealedSize)
    }

    /// The two fixes compose: a row the backfill correctly leaves nil is picked up by
    /// the scrub (Bug 89), rather than ending up in a gap neither one covers.
    @Test("A deleted row left nil by the backfill is picked up by the scrub")
    func excludedRowIsHandledByScrub() throws {
        let context = ModelContext(try makeContainer())
        insert("deleted", deleted: true, stamps: nil, in: context)
        try context.save()

        try self.runAllBackfills(context)
        try DatabaseMigration.migrateScrubDeletedDepthStamps(modelContext: context)

        let row = try #require(try context.fetch(FetchDescriptor<Contact.Profile>()).first)
        #expect(row.visibleThroughDepth?.count == DepthCodec.sealedSize,
                "the scrub must still reach a row the backfill correctly skipped")
    }
}

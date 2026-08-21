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

//
//  DeletedDepthStampScrubTests.swift
//  OccultaTests
//
//  Bug 89 — a soft-deleted row's depth stamps must not keep their legacy length, and must
//  not keep their *value* either: the true values name the layer the contact lived in.
//
//  The stranded-row half needs no Secure Enclave, which is a real property rather than a
//  convenience — with no key available every row reads as stranded and the pass degrades to
//  the key-free length normalisation below. The readable-row half is necessarily gated: it
//  exists precisely to write values that decrypt.
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

// MARK: - Bug 89 remedy — the scrub matches the row it sits on

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

@MainActor
private func makeGroupCapableContainer() throws -> ModelContainer {
    let schema = Schema([
        Group.self,
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
    ])
    return try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
}

/// Scrubbing to random bytes is only correct for a row whose *other* fields are also
/// unreadable. On a row deleted since the last rotation the names still decrypt, so three
/// stamps that did not would not read as concealment — they would read as evidence something
/// was deliberately destroyed, which is the trace this project must not leave. There the
/// scrub has to write a sealed benign value instead.
@Suite("Bug 89 — the scrub matches its row's readability", .serialized)
@MainActor
struct ScrubMatchesRowReadabilityTests {

    /// Seals `value` under the current DB key, as a live row's stamp would be.
    private func sealed(_ value: Int) throws -> Data {
        try #require(try DepthCodec.encode(value).encrypt())
    }

    /// A deleted row whose `deletionToken` decrypts — i.e. no rotation since deletion.
    private func insertReadableDeleted(
        visibleThrough: Int, trustee: Int, origin: Int, in context: ModelContext
    ) throws -> Contact.Profile {
        let profile = Contact.Profile(
            identifier: UUID().uuidString, givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        profile.visibleThroughDepth = try self.sealed(visibleThrough)
        profile.globalTrusteeDepth  = try self.sealed(trustee)
        profile.originDepth         = try self.sealed(origin)
        profile.deletionToken       = try Data([1]).encrypt()
        context.insert(profile)
        return profile
    }

    private func decoded(_ field: Data?) -> Int? {
        guard let field, let plain = field.decrypt() else { return nil }
        return DepthCodec.decode(plain)
    }

    /// The leak this remedy closes. A contact classified sensitive (`visibleThroughDepth == 0`,
    /// hidden from every duress layer) and born at depth 2 leaves both facts readable on its
    /// soft-deleted row — direct evidence that a layer at depth 2 exists and was in use.
    @Test("A readable deleted row's stamps are replaced with benign values",
          .enabled(if: secureEnclaveAvailable()))
    func readableRowGetsBenignValues() throws {
        let context = ModelContext(try makeContainer())
        try self.insertReadableDeleted(visibleThrough: 0, trustee: 2, origin: 2, in: context)
        try context.save()

        try DatabaseMigration.migrateScrubDeletedDepthStamps(modelContext: context)

        let row = try #require(try context.fetch(FetchDescriptor<Contact.Profile>()).first)
        #expect(self.decoded(row.visibleThroughDepth) == Int.max, """
            visibleThroughDepth must read as an ordinary contact visible at every duress \
            depth. A retained 0 says this contact was deliberately hidden from every cover \
            story, which is the incriminating value, not a benign one.
            """)
        #expect(self.decoded(row.globalTrusteeDepth) == -1,
                "the trustee stamp must read as 'not a trustee', never as a depth")
        #expect(self.decoded(row.originDepth) == 0, """
            originDepth must read as born in the real session. A retained 2 names a duress \
            layer that the cover story does not admit exists.
            """)
    }

    /// The stamps must stay *readable* on a readable row. Random bytes would be a tamper tell:
    /// three unreadable fields sitting on a row whose names still decrypt.
    @Test("A readable deleted row's stamps still decrypt after the scrub",
          .enabled(if: secureEnclaveAvailable()))
    func readableRowStaysReadable() throws {
        let context = ModelContext(try makeContainer())
        try self.insertReadableDeleted(visibleThrough: 0, trustee: -1, origin: 3, in: context)
        try context.save()

        try DatabaseMigration.migrateScrubDeletedDepthStamps(modelContext: context)

        let row = try #require(try context.fetch(FetchDescriptor<Contact.Profile>()).first)
        #expect(row.visibleThroughDepth?.decrypt() != nil, """
            An unreadable stamp on a row whose deletionToken still decrypts is evidence of \
            deliberate destruction — worse than the value it was hiding.
            """)
        #expect(row.visibleThroughDepth?.count == DepthCodec.sealedSize)
    }

    /// It runs on every launch. Re-sealing draws a fresh nonce, so an unconditional rewrite
    /// would churn the bytes — and the row's mtime — at every start for no gain.
    @Test("A second run over a readable row changes nothing",
          .enabled(if: secureEnclaveAvailable()))
    func readableScrubIsIdempotent() throws {
        let context = ModelContext(try makeContainer())
        try self.insertReadableDeleted(visibleThrough: 0, trustee: 2, origin: 2, in: context)
        try context.save()

        try DatabaseMigration.migrateScrubDeletedDepthStamps(modelContext: context)
        let afterFirst = try #require(
            try context.fetch(FetchDescriptor<Contact.Profile>()).first
        ).visibleThroughDepth

        try DatabaseMigration.migrateScrubDeletedDepthStamps(modelContext: context)
        let afterSecond = try #require(
            try context.fetch(FetchDescriptor<Contact.Profile>()).first
        ).visibleThroughDepth

        #expect(afterFirst == afterSecond, "a benign fixed-width stamp must not be re-sealed")
    }

    /// A legacy-format stamp can already decode to the benign value while still leaking
    /// through its length, and the fixed-width pass no longer visits deleted rows — so value
    /// alone cannot be the idempotency test.
    @Test("A readable legacy-width stamp is rewritten even when its value is already benign",
          .enabled(if: secureEnclaveAvailable()))
    func readableLegacyWidthIsStillRewritten() throws {
        let context = ModelContext(try makeContainer())
        let row = try self.insertReadableDeleted(visibleThrough: 0, trustee: -1, origin: 0, in: context)
        // Int.max in the legacy JSON format: benign in value, 19 plaintext bytes in length.
        row.visibleThroughDepth = try #require(
            try JSONEncoder().encode(Int.max).encrypt()
        )
        try context.save()

        try DatabaseMigration.migrateScrubDeletedDepthStamps(modelContext: context)

        let fetched = try #require(try context.fetch(FetchDescriptor<Contact.Profile>()).first)
        #expect(fetched.visibleThroughDepth?.count == DepthCodec.sealedSize,
                "a benign value in the legacy format still partitions rows by length (Bug 85)")
        #expect(self.decoded(fetched.visibleThroughDepth) == Int.max)
    }

    /// The other half of the rule. A stranded row's names do not decrypt, so a stamp that did
    /// would be the outlier — the mirror image of the readable case.
    @Test("A stranded row's stamps are not sealed into readability",
          .enabled(if: secureEnclaveAvailable()))
    func strandedRowIsNotMadeReadable() throws {
        let context = ModelContext(try makeContainer())
        // deletionToken that will not decrypt = the row is stranded under a superseded key.
        insert("stranded", deleted: true, stamps: legacySmallDepth, in: context)
        try context.save()

        try DatabaseMigration.migrateScrubDeletedDepthStamps(modelContext: context)

        let row = try #require(try context.fetch(FetchDescriptor<Contact.Profile>()).first)
        #expect(row.visibleThroughDepth?.count == DepthCodec.sealedSize)
        #expect(row.visibleThroughDepth?.decrypt() == nil, """
            A stamp that decrypts on a row whose every other field does not implies something \
            wrote after the erasure.
            """)
    }
}

// MARK: - The pass that fed the skip

/// `migrateDepthFieldsToFixedWidth` ran first and fetched every row, so it converted a
/// deleted row's legacy stamp to the uniform width before the scrub saw it — and the scrub's
/// old length test then skipped it permanently. Excluding deleted rows is what keeps the two
/// passes from cancelling each other out.
@Suite("Bug 89 — the fixed-width pass leaves deleted rows to the scrub", .serialized)
@MainActor
struct FixedWidthPassExcludesDeletedRowsTests {

    @Test("A deleted row's readable legacy stamp is not normalised by the fixed-width pass",
          .enabled(if: secureEnclaveAvailable()))
    func deletedRowIsSkipped() throws {
        let context = ModelContext(try makeContainer())
        let profile = Contact.Profile(
            identifier: UUID().uuidString, givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        let legacy = try #require(try JSONEncoder().encode(2).encrypt())
        profile.visibleThroughDepth = legacy
        profile.deletionToken       = try Data([1]).encrypt()
        context.insert(profile)
        try context.save()

        try DatabaseMigration.migrateDepthFieldsToFixedWidth(modelContext: context)

        let row = try #require(try context.fetch(FetchDescriptor<Contact.Profile>()).first)
        #expect(row.visibleThroughDepth == legacy, """
            Normalising a deleted row here hands the scrub a row it can no longer distinguish \
            from one already scrubbed, which is how the stamp survived at its true value.
            """)
    }

    /// The constraint: live rows are the whole point of that pass and must still convert.
    @Test("A live row's legacy stamp is still normalised",
          .enabled(if: secureEnclaveAvailable()))
    func liveRowIsStillNormalised() throws {
        let context = ModelContext(try makeContainer())
        let profile = Contact.Profile(
            identifier: UUID().uuidString, givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        profile.visibleThroughDepth = try #require(try JSONEncoder().encode(2).encrypt())
        context.insert(profile)
        try context.save()

        try DatabaseMigration.migrateDepthFieldsToFixedWidth(modelContext: context)

        let row = try #require(try context.fetch(FetchDescriptor<Contact.Profile>()).first)
        #expect(row.visibleThroughDepth?.count == DepthCodec.sealedSize)
    }
}

// MARK: - deleteContact writes the benign stamps itself

/// The migration is only ever a repair pass; this is the control that keeps the population
/// from growing. Without it every future deletion re-creates the leak.
@Suite("Bug 89 — deleteContact scrubs the stamps at deletion time", .serialized)
@MainActor
struct DeleteContactScrubsStampsTests {

    @Test("Deleting a contact replaces its depth stamps with benign values",
          .enabled(if: secureEnclaveAvailable()))
    func deleteContactScrubsDepthStamps() throws {
        let container = try makeGroupCapableContainer()
        let security  = try Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        let contacts  = ContactManager(modelContainer: container, security: security)

        let identifier = UUID().uuidString
        let profile = Contact.Profile(
            identifier: identifier, givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        profile.visibleThroughDepth = try #require(try DepthCodec.encode(0).encrypt())
        profile.originDepth         = try #require(try DepthCodec.encode(2).encrypt())
        try contacts.insertProfile(profile)

        try contacts.deleteContact(identifier: identifier)

        let verifyContext = ModelContext(container)
        let row = try #require(
            try verifyContext.fetch(
                FetchDescriptor<Contact.Profile>(predicate: #Predicate { $0.deletionToken != nil })
            ).first
        )
        let visible = try #require(row.visibleThroughDepth?.decrypt())
        let origin  = try #require(row.originDepth?.decrypt())
        #expect(DepthCodec.decode(visible) == Int.max, """
            deleteContact must overwrite the classification before the row goes cold — \
            rotation never re-keys a soft-deleted row, so whatever is here is what an \
            examiner reads for as long as the row survives.
            """)
        #expect(DepthCodec.decode(origin) == 0,
                "originDepth must not keep naming the duress layer the contact was born in")
    }
}

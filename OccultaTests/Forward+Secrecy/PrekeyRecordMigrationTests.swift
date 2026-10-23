//
//  PrekeyRecordMigrationTests.swift
//  OccultaTests
//
//  `DatabaseMigration.migratePrekeyRecords`, prekey continuity stage 1's one pass at launch
//  (`Docs/Features/Prekey Continuity/DESIGN.md`, "Migration"): afterwards every row's new field is present at one
//  size and every row's old field is nil, whatever the row started with. Runs under `.ambientTestKeyManager`,
//  which supplies the local DB key; nothing here touches the Enclave. That a migrated legacy prekey still opens a
//  message is in `PrekeyReplenishmentTriggerTests`, which needs one.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta
@testable import OccultaCore
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

/// A row as an upgraded device holds it: on the v2 scheme, with whatever it's given.
@discardableResult
@MainActor
private func insertRow(
    old: Data? = nil,
    new: Data? = nil,
    deletionToken: Data? = nil,
    scheme: EncryptionScheme = .v2_hybridPQ,
    in context: ModelContext
) -> Contact.Profile {
    let profile = Contact.Profile(
        identifier: UUID().uuidString, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.encryptionScheme = scheme.rawValue
    profile.retiredForwardSecrecyEncrypted = old
    profile.prekeyRecordEncrypted = new
    profile.deletionToken = deletionToken
    context.insert(profile)
    return profile
}

/// Today's record, sealed: the keys held from the contact and a batch of ours waiting to be delivered.
private func sealedLegacyRecord(inboundIDs: [String] = [UUID().uuidString]) throws -> Data {
    var legacy = ForwardSecrecy()
    legacy.encodedPrekeys = try inboundIDs.map {
        try JSONEncoder().encode(Prekey(id: $0, contactID: "", publicKey: Data(repeating: 0x04, count: 65)))
    }
    legacy.latestPrekeysGeneratedAt = Date(timeIntervalSince1970: 1_800_000_000)
    legacy.pendingOutboundBatch = try JSONEncoder().encode(OccultaBundle.SealedPayload.PrekeySyncBatch(
        generatedAt: Date(timeIntervalSince1970: 1_800_000_000),
        prekeys: [OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: Data(repeating: 0x04, count: 65))]
    ))
    return try #require(try JSONEncoder().encode(legacy).encrypt())
}

private func sealed(_ record: PrekeyRecord) throws -> Data {
    try #require(try PrekeyRecordCodec().encode(record).encrypt())
}

private func opened(_ field: Data?) throws -> PrekeyRecord {
    let field = try #require(field)
    return try PrekeyRecordCodec().decode(try #require(field.decrypt()))
}

/// What a record that couldn't be carried over becomes: empty, with keys of ours possibly still in the keychain.
private var startedOver: PrekeyRecord {
    var record = PrekeyRecord.empty
    record.legacyKeys = .inUse
    return record
}

// MARK: - Tests

@MainActor
@Suite("DatabaseMigration — prekey records", .serialized)
struct PrekeyRecordMigrationTests {

    @Test("A live row's record is carried over, and its old field emptied", .ambientTestKeyManager)
    func liveRowCarriedOver() throws {
        let context = ModelContext(try makeContainer())
        let old = try sealedLegacyRecord()
        let row = insertRow(old: old, in: context)

        try DatabaseMigration.migratePrekeyRecords(modelContext: context)

        let expected = try PrekeyRecordCodec().decode(try #require(old.decrypt()))
        #expect(try opened(row.prekeyRecordEncrypted) == expected)
        #expect(expected.legacyKeys == .inUse && expected.inboundBatches.count == 1 && expected.ownBatches.count == 1,
                "precondition: the fixture exercises both halves of today's record")
        #expect(row.retiredForwardSecrecyEncrypted == nil)
    }

    /// Before stage 1 a contact's batch could hold up to 30 keys with IDs of any length; today's limits are 15 keys
    /// and 36-byte IDs. Keys outside them are dropped rather than carried over, so every record meets the limits the
    /// codec's 16 KB is budgeted for. Our pending batch is kept.
    @Test("A carried-over record drops the contact's keys if they are outside today's limits", .ambientTestKeyManager)
    func oversizedInboundDropped() throws {
        let context = ModelContext(try makeContainer())
        let row = insertRow(old: try sealedLegacyRecord(inboundIDs: (0..<20).map { _ in UUID().uuidString }), in: context)

        try DatabaseMigration.migratePrekeyRecords(modelContext: context)

        let record = try opened(row.prekeyRecordEncrypted)
        #expect(record.inboundBatches.isEmpty)
        #expect(record.ownBatches.count == 1 && record.ownBatches.first?.isPending == true)
        #expect(record.legacyKeys == .inUse)
    }

    @Test("A live row with no record gets an empty one, with no legacy keys", .ambientTestKeyManager)
    func liveRowWithoutRecord() throws {
        let context = ModelContext(try makeContainer())
        let row = insertRow(in: context)

        try DatabaseMigration.migratePrekeyRecords(modelContext: context)

        #expect(try opened(row.prekeyRecordEncrypted) == .empty)
    }

    @Test("A live record that won't decrypt, decode or fit starts over, with legacy keys in use", .ambientTestKeyManager,
          arguments: ["undecryptable", "malformed", "overCapacity"])
    func unreadableLiveRecordStartsOver(_ kind: String) throws {
        let context = ModelContext(try makeContainer())
        let old: Data
        switch kind {
        case "undecryptable": old = Data.randomBytes(300)
        case "malformed":     old = try #require(try Data("{\"encodedPrekeys\": 7}".utf8).encrypt())
        default:
            // Before stage 1 nothing bounded an inbound key ID; 30 of a kilobyte each can't fit in 16 KB. Distinct,
            // because a binary plist stores a repeated string once.
            old = try sealedLegacyRecord(inboundIDs: (0..<30).map { _ in UUID().uuidString + String(repeating: "x", count: 1_000) })
        }
        let row = insertRow(old: old, in: context)

        try DatabaseMigration.migratePrekeyRecords(modelContext: context)

        #expect(try opened(row.prekeyRecordEncrypted) == startedOver)
        #expect(row.retiredForwardSecrecyEncrypted == nil)
    }

    @Test("A soft-deleted row whose token decrypts gets the sealed empty record", .ambientTestKeyManager)
    func readableDeletedRow() throws {
        let context = ModelContext(try makeContainer())
        let row = insertRow(old: try sealedLegacyRecord(), deletionToken: try Data([1]).encrypt(), in: context)

        try DatabaseMigration.migratePrekeyRecords(modelContext: context)

        #expect(try opened(row.prekeyRecordEncrypted) == .empty, "no keys are kept for a deleted contact")
        #expect(row.retiredForwardSecrecyEncrypted == nil)
    }

    @Test("A soft-deleted row whose token doesn't decrypt gets random bytes at the sealed size", .ambientTestKeyManager)
    func strandedDeletedRow() throws {
        let context = ModelContext(try makeContainer())
        let row = insertRow(old: Data.randomBytes(300), deletionToken: Data.randomBytes(33), in: context)

        try DatabaseMigration.migratePrekeyRecords(modelContext: context)

        let field = try #require(row.prekeyRecordEncrypted)
        #expect(field.count == (try sealed(.empty)).count)
        #expect(field.decrypt() == nil, "it must be as unreadable as the rest of its row")
        #expect(row.retiredForwardSecrecyEncrypted == nil)
    }

    @Test("A row with both fields keeps its new one and loses the old", .ambientTestKeyManager)
    func bothFieldsKeepsNew() throws {
        let context = ModelContext(try makeContainer())
        var record = PrekeyRecord.empty
        record.acceptedBatchIDs = [Data(count: 16)]
        let new = try sealed(record)
        let row = insertRow(old: try sealedLegacyRecord(), new: new, in: context)

        try DatabaseMigration.migratePrekeyRecords(modelContext: context)

        #expect(row.prekeyRecordEncrypted == new)
        #expect(row.retiredForwardSecrecyEncrypted == nil)
    }

    @Test("A row still on the v1 scheme is left for migrateToV2", .ambientTestKeyManager)
    func v1RowSkipped() throws {
        let context = ModelContext(try makeContainer())
        let old = Data.randomBytes(300)
        let row = insertRow(old: old, scheme: .v1_identityDerived, in: context)

        try DatabaseMigration.migratePrekeyRecords(modelContext: context)

        #expect(row.prekeyRecordEncrypted == nil)
        #expect(row.retiredForwardSecrecyEncrypted == old)
    }

    /// The whole population at once: one size, no old field, saved, and nothing rewritten by a second launch.
    @Test("After the pass every row has one size and no old field; a second pass changes nothing", .ambientTestKeyManager)
    func everyRowUniformAndIdempotent() throws {
        let container = try makeContainer()
        let context = ModelContext(container)
        insertRow(old: try sealedLegacyRecord(), in: context)
        insertRow(in: context)
        insertRow(old: Data.randomBytes(300), in: context)
        insertRow(new: try sealed(.empty), in: context)
        insertRow(old: try sealedLegacyRecord(), deletionToken: try Data([1]).encrypt(), in: context)
        insertRow(deletionToken: Data.randomBytes(33), in: context)
        try context.save()

        try DatabaseMigration.migratePrekeyRecords(modelContext: context)

        let rows = try ModelContext(container).fetch(FetchDescriptor<Contact.Profile>())
        let sizes = Set(rows.map { $0.prekeyRecordEncrypted?.count })
        #expect(sizes == [try sealed(.empty).count])
        #expect(rows.allSatisfy { $0.retiredForwardSecrecyEncrypted == nil })

        let before = rows.map(\.prekeyRecordEncrypted)
        try DatabaseMigration.migratePrekeyRecords(modelContext: context)
        let after = try ModelContext(container).fetch(FetchDescriptor<Contact.Profile>()).map(\.prekeyRecordEncrypted)
        #expect(Set(after) == Set(before), "a second launch must leave every record byte-identical")
    }
}

/// The launch pass can fail, for one when the app starts while the local DB key is unavailable. The rows it didn't
/// reach still have only the old field, and the session goes on: `prekeyRecord(for:)` must read them as their old
/// record, so the first store writes that, and the pass that runs later has nothing left to lose.
@MainActor
@Suite("DatabaseMigration — a row the launch pass didn't reach", .serialized)
struct PrekeyRecordUnmigratedRowTests {

    private func makeContactManager() throws -> ContactManager {
        let schema = Schema([
            Group.self,
            Contact.Profile.self,
            Contact.Profile.PhoneNumber.self,
            Contact.Profile.EmailAddress.self,
            Contact.Profile.PostalAddress.self,
            Contact.Profile.URLAddress.self,
            Contact.Profile.Key.self,
        ])
        let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
        return ContactManager(modelContainer: container, security: Manager.Security(modelContainer: container, keyManager: TestKeyManager()))
    }

    @Test("It reads as its old record, and a store then the pass keep what was used", .ambientTestKeyManager)
    func readAsOldRecordAndKept() throws {
        let cm = try self.makeContactManager()
        let old = try sealedLegacyRecord(inboundIDs: [UUID().uuidString, UUID().uuidString])
        let row = insertRow(old: old, in: cm.modelContext)
        let carriedOver = try PrekeyRecordCodec().decode(try #require(old.decrypt()))

        #expect(try cm.prekeyRecord(for: row) == carriedOver)

        // A send takes one of the contact's keys, and stores the record.
        var record = try cm.prekeyRecord(for: row)
        #expect(PrekeyBookkeeper().takeInboundPrekey(from: &record, contactID: row.identifier) != nil)
        try cm.store(record, for: row)

        try DatabaseMigration.migratePrekeyRecords(modelContext: cm.modelContext)

        let kept = try opened(row.prekeyRecordEncrypted)
        #expect(kept == record, "the contact's other key, our pending batch and the legacy keys are all still there")
        #expect(kept.inboundBatches.first?.keys.count == 1 && kept.ownBatches.count == 1 && kept.legacyKeys == .inUse)
        #expect(row.retiredForwardSecrecyEncrypted == nil)
    }

    @Test("A row with neither field reads as empty, with no legacy keys", .ambientTestKeyManager)
    func neitherReadsEmpty() throws {
        let cm = try self.makeContactManager()
        let row = insertRow(in: cm.modelContext)
        #expect(try cm.prekeyRecord(for: row) == .empty)
    }
}

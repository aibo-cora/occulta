//
//  PrekeyLifecycleTests.swift
//  OccultaTests
//
//  Prekey continuity stage 1: a contact's prekey record from creation to deletion, and the sweep in between
//  (`Docs/Features/Prekey Continuity/DESIGN.md`). The field is never nil and always the same size, so it says
//  nothing about a contact without a key (Bug 161); the sweep deletes what the grace period no longer protects
//  (D1, Bug 156).
//
//  These run under `.ambientTestKeyManager`: the records hold filler blobs, and nothing here touches the Enclave.
//  Deleting legacy keychain keys and the sweep on receipt are in `PrekeyReplenishmentTriggerTests`, which have one.
//

import Testing
import Foundation
import SwiftData
import Contacts
@testable import Occulta
@testable import OccultaCore

// MARK: - Helpers

@MainActor
private func makeContactManager() throws -> (ContactManager, ModelContainer) {
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
    let security  = try Manager.Security(modelContainer: container, keyManager: TestKeyManager())
    return (ContactManager(modelContainer: container, security: security), container)
}

@MainActor
private func insertProfile(
    identifier: String = UUID().uuidString, visibleThroughDepth: Int = Int.max, in cm: ContactManager
) throws -> Contact.Profile {
    let profile = Contact.Profile(
        identifier: identifier, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.visibleThroughDepth = try DepthCodec.encode(visibleThroughDepth).encrypt()
    try cm.insertProfile(profile)
    return profile
}

/// An own batch of `count` keys with filler blobs.
private func ownBatch(count: Int, createdAt: Date, retiredAt: Date?) -> PrekeyRecord.OwnBatch {
    PrekeyRecord.OwnBatch(
        id: Data(count: 16), createdAt: createdAt, retiredAt: retiredAt, isPending: false,
        keys: (0..<count).map { _ in
            PrekeyRecord.OwnKey(id: withUnsafeBytes(of: UUID().uuid) { Data($0) }, blob: Data(count: 143), publicKey: nil)
        }
    )
}

/// A record with keys in it, for comparing sizes against.
private func busyRecord() -> PrekeyRecord {
    var record = PrekeyRecord.empty
    record.ownBatches = [ownBatch(count: 15, createdAt: Date(), retiredAt: nil)]
    record.inboundBatches = [.init(id: nil, keys: [.init(id: UUID().uuidString, publicKey: Data(count: 65))])]
    return record
}

private let day: TimeInterval = 24 * 60 * 60

// MARK: - Never nil, always the same size

@MainActor
@Suite("Prekey record — present at one size from creation to deletion", .serialized)
struct PrekeyRecordPresenceTests {

    @Test("A contact saved from a draft starts with an empty record", .ambientTestKeyManager)
    func savedContactHasEmptyRecord() throws {
        let (cm, _) = try makeContactManager()
        try cm.save(contact: Contact.Draft(identifier: UUID().uuidString, givenName: "A", familyName: "B"))

        let contact = try #require(try cm.fetchAllContacts().first)
        let sealed  = try #require(contact.prekeyRecordEncrypted)
        #expect(try cm.prekeyRecord(for: contact) == .empty)

        let other = try insertProfile(in: cm)
        try cm.store(busyRecord(), for: other)
        #expect(sealed.count == other.prekeyRecordEncrypted?.count, "an empty record must be the size of a busy one")
    }

    @Test("A contact imported from the address book starts with an empty record", .ambientTestKeyManager)
    func importedContactHasEmptyRecord() throws {
        let (cm, _) = try makeContactManager()
        let imported = CNMutableContact()
        imported.givenName = "A"
        try cm.createContacts(from: [imported])

        let contact = try #require(try cm.fetchAllContacts().first)
        #expect(contact.prekeyRecordEncrypted != nil)
        #expect(try cm.prekeyRecord(for: contact) == .empty)
    }

    @Test("Deleting a contact overwrites its record with an empty one of the same size", .ambientTestKeyManager)
    func deletedContactRecordIsEmptied() throws {
        let (cm, _) = try makeContactManager()
        let contact = try insertProfile(in: cm)
        try cm.store(busyRecord(), for: contact)
        let sizeBefore = try #require(contact.prekeyRecordEncrypted).count

        try cm.deleteContact(identifier: contact.identifier)

        let sealed = try #require(contact.prekeyRecordEncrypted)
        #expect(sealed.count == sizeBefore)
        #expect(try cm.prekeyRecord(for: contact) == .empty, "a deleted contact's record holds no blobs")
    }
}

// MARK: - Sweep

@MainActor
@Suite("Prekey record — the sweep", .serialized)
struct PrekeySweepTests {

    @Test("A batch retired more than 30 days ago is deleted; one retired since is kept", .ambientTestKeyManager)
    func sweepDeletesOnlyPastGrace() throws {
        let (cm, _) = try makeContactManager()
        let contact = try insertProfile(in: cm)
        let now = Date()
        let expired = ownBatch(count: 2, createdAt: now - 60 * day, retiredAt: now - 31 * day)
        let inGrace = ownBatch(count: 2, createdAt: now - 40 * day, retiredAt: now - 29 * day)
        let current = ownBatch(count: 2, createdAt: now - 10 * day, retiredAt: nil)
        var record = PrekeyRecord.empty
        record.ownBatches = [expired, inGrace, current]
        try cm.store(record, for: contact)

        #expect(try cm.sweepPrekeys(of: contact, now: now))

        #expect(try cm.prekeyRecord(for: contact).ownBatches == [inGrace, current])
        #expect(try !cm.sweepPrekeys(of: contact, now: now), "nothing left to sweep, so the record isn't rewritten")
    }

    @Test("Legacy keys are marked gone once 30 days after they retired, and not before", .ambientTestKeyManager)
    func sweepRetiresLegacyKeysOnce() throws {
        let (cm, _) = try makeContactManager()
        let contact = try insertProfile(in: cm)
        let now = Date()
        var record = PrekeyRecord.empty
        record.legacyKeys = .retired(since: now - 29 * day)
        try cm.store(record, for: contact)

        #expect(try !cm.sweepPrekeys(of: contact, now: now))
        #expect(try cm.prekeyRecord(for: contact).legacyKeys == .retired(since: now - 29 * day))

        #expect(try cm.sweepPrekeys(of: contact, now: now + 2 * day))
        #expect(try cm.prekeyRecord(for: contact).legacyKeys == PrekeyRecord.LegacyKeys.none)
    }

    /// Once records are sealed per depth, a depth can read only the records of the contacts it shows.
    @Test("The sweep at unlock covers the contacts visible at that depth, and saves", .ambientTestKeyManager)
    func unlockSweepCoversVisibleContactsOnly() throws {
        let (cm, container) = try makeContactManager()
        let visible = try insertProfile(visibleThroughDepth: Int.max, in: cm)
        let hidden  = try insertProfile(visibleThroughDepth: 0, in: cm)
        let now = Date()
        var record = PrekeyRecord.empty
        record.ownBatches = [ownBatch(count: 2, createdAt: now - 60 * day, retiredAt: now - 31 * day)]
        try cm.store(record, for: visible)
        try cm.store(record, for: hidden)
        try cm.modelContext.save()

        try cm.sweepPrekeys(visibleAtDepth: 1, now: now)

        let fresh = try ModelContext(container).fetch(FetchDescriptor<Contact.Profile>())
        let saved = { (id: String) in try cm.prekeyRecord(for: try #require(fresh.first { $0.identifier == id })) }
        #expect(try saved(visible.identifier).ownBatches.isEmpty)
        #expect(try saved(hidden.identifier) == record)
    }
}

//
//  PostalCountryMigrationTests.swift
//  OccultaTests
//
//  Bug 216 — `migrateContact` left `PostalAddress.country` out of its field list, so a v1 contact's country stayed
//  sealed under the v1 key, a function of the identity public key. Rows already marked v2 hold such a value too, and
//  nothing retried them: `migrateCountryOrphans` reseals those.
//
//  Runs under `.ambientTestKeyManager`: v1 values are sealed with the test manager's `createLocalEncryptionKey()` and
//  no authenticated data, exactly as v1 did.
//

import Testing
import Foundation
import CryptoKit
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
    ])
    return try ModelContainer(for: schema, configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)])
}

/// An isolated `UserDefaults`, so a test of a one-time pass's marker neither sees nor leaves one in the app's.
func freshDefaults() -> UserDefaults {
    let name = "OccultaTests.\(UUID().uuidString)"
    let defaults = UserDefaults(suiteName: name)!
    defaults.removePersistentDomain(forName: name)
    return defaults
}

@Suite("Bug 216 — postal country leaves the v1 key", .serialized)
@MainActor
struct PostalCountryMigrationTests {

    private let keys: TestKeyManager

    init() throws {
        // The trait binds a `TestKeyManager` for the test; the suite builds its own only to seal v1 values with. The two
        // are separate instances, so the v1 key is read from the ambient one in each helper.
        self.keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
    }

    // MARK: - Sealing helpers

    /// As v1 sealed a string: the v1 key, no authenticated data, base64 of the combined box.
    private func sealedV1(_ text: String) throws -> String {
        let key = try #require(try self.keys.createLocalEncryptionKey())
        return try AES.GCM.seal(Data(text.utf8), using: key).combined!.base64EncodedString()
    }

    private func sealedCurrent(_ text: String) throws -> String {
        try #require(try Manager.Crypto().encrypt(data: Data(text.utf8))).base64EncodedString()
    }

    private func opensV1(_ base64: String) -> String? {
        guard let key = try? self.keys.createLocalEncryptionKey(), let data = Data(base64Encoded: base64),
              let box = try? AES.GCM.SealedBox(combined: data), let plain = try? AES.GCM.open(box, using: key) else { return nil }
        return String(data: plain, encoding: .utf8)
    }

    private func opensCurrent(_ base64: String) -> String? {
        guard let data = Data(base64Encoded: base64), let plain = try? Manager.Crypto().decrypt(data: data) else { return nil }
        return String(data: plain, encoding: .utf8)
    }

    @discardableResult
    private func insert(
        scheme: EncryptionScheme, country: String, seal: (String) throws -> String,
        deleted: Bool = false, in context: ModelContext
    ) throws -> (Contact.Profile, Contact.Profile.PostalAddress) {
        let profile = Contact.Profile(
            identifier: try seal(UUID().uuidString), givenName: try seal("Alice"), familyName: try seal("Wonderland"),
            middleName: "", nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        profile.encryptionScheme = scheme.rawValue
        if deleted { profile.deletionToken = Data([1, 2, 3]) }

        let postal = Contact.Profile.PostalAddress(label: "home", street: "", city: "", state: "", postalCode: "", country: "", isoCountryCode: "")
        postal.label = try seal("home")
        postal.street = try seal("1 Main St")
        postal.city = try seal("Chisinau")
        postal.state = try seal("")
        postal.postalCode = try seal("2001")
        postal.country = country
        postal.isoCountryCode = try seal("MD")
        postal.profile = profile
        profile.postalAddresses = [postal]

        context.insert(profile)
        context.insert(postal)
        try context.save()
        return (profile, postal)
    }

    // MARK: - migrateToV2

    /// The defect. After the launch migrations a v1 row's country opened only under the v1 key.
    @Test("A v1 contact's country is moved off the v1 key by migrateToV2", .ambientTestKeyManager)
    func postalCountryLeavesV1Key() throws {
        let context = ModelContext(try makeContainer())
        let (profile, postal) = try self.insert(scheme: .v1_identityDerived, country: try self.sealedV1("Moldova"), seal: self.sealedV1, in: context)

        try DatabaseMigration.migrateToV2(modelContext: context, legacyCrypto: LegacyCryptoManager(), newCrypto: Manager.Crypto())

        #expect(profile.encryptionScheme == EncryptionScheme.v2_hybridPQ.rawValue)
        #expect(self.opensCurrent(postal.city) == "Chisinau", "the other postal fields were already moved")
        #expect(self.opensCurrent(postal.country) == "Moldova", "country must open under the current key")
        #expect(self.opensV1(postal.country) == nil, "country must no longer open under the v1 key, which a holder of the identity public key derives")
    }

    @Test("An empty country stays empty through migrateToV2", .ambientTestKeyManager)
    func emptyCountryStaysEmpty() throws {
        let context = ModelContext(try makeContainer())
        let (_, postal) = try self.insert(scheme: .v1_identityDerived, country: "", seal: self.sealedV1, in: context)

        try DatabaseMigration.migrateToV2(modelContext: context, legacyCrypto: LegacyCryptoManager(), newCrypto: Manager.Crypto())

        #expect(postal.country == "")
    }

    // MARK: - The repair pass, for rows already marked v2

    @Test("A v2 row whose country is still under the v1 key is resealed under the current key", .ambientTestKeyManager)
    func v2RowWithV1CountryIsResealed() throws {
        let context = ModelContext(try makeContainer())
        let (_, postal) = try self.insert(scheme: .v2_hybridPQ, country: try self.sealedV1("Moldova"), seal: self.sealedCurrent, in: context)

        try DatabaseMigration.migrateCountryOrphans(modelContext: context, legacyCrypto: LegacyCryptoManager(), newCrypto: Manager.Crypto())

        let fresh = ModelContext(context.container)
        let stored = try #require(try fresh.fetch(FetchDescriptor<Contact.Profile.PostalAddress>()).first)
        #expect(self.opensCurrent(stored.country) == "Moldova")
        #expect(self.opensV1(stored.country) == nil)
        #expect(self.opensCurrent(stored.city) == "Chisinau", "no other field is touched")
        _ = postal
    }

    @Test("The pass leaves a country already under the current key byte-identical, and a second run changes nothing", .ambientTestKeyManager)
    func passIsIdempotent() throws {
        let context = ModelContext(try makeContainer())
        let sealed = try self.sealedCurrent("Moldova")
        let (_, postal) = try self.insert(scheme: .v2_hybridPQ, country: sealed, seal: self.sealedCurrent, in: context)

        try DatabaseMigration.migrateCountryOrphans(modelContext: context, legacyCrypto: LegacyCryptoManager(), newCrypto: Manager.Crypto())
        #expect(postal.country == sealed)

        let (_, second) = try self.insert(scheme: .v2_hybridPQ, country: try self.sealedV1("Romania"), seal: self.sealedCurrent, in: context)
        try DatabaseMigration.migrateCountryOrphans(modelContext: context, legacyCrypto: LegacyCryptoManager(), newCrypto: Manager.Crypto())
        let once = second.country
        try DatabaseMigration.migrateCountryOrphans(modelContext: context, legacyCrypto: LegacyCryptoManager(), newCrypto: Manager.Crypto())

        #expect(self.opensCurrent(once) == "Romania")
        #expect(second.country == once, "a resealed value is not touched again")
        #expect(postal.country == sealed)
    }

    @Test("A country that opens under no key is left as it is", .ambientTestKeyManager)
    func unreadableCountryIsLeft() throws {
        let context = ModelContext(try makeContainer())
        let noise = Data((0..<60).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
        let (_, postal) = try self.insert(scheme: .v2_hybridPQ, country: noise, seal: self.sealedCurrent, in: context)

        try DatabaseMigration.migrateCountryOrphans(modelContext: context, legacyCrypto: LegacyCryptoManager(), newCrypto: Manager.Crypto())

        #expect(postal.country == noise)
    }

    @Test("An empty country, a soft-deleted contact's country and a v1 row are not touched by the pass", .ambientTestKeyManager)
    func passSkipsWhatItShould() throws {
        let context = ModelContext(try makeContainer())
        let v1Sealed = try self.sealedV1("Moldova")

        let (_, empty) = try self.insert(scheme: .v2_hybridPQ, country: "", seal: self.sealedCurrent, in: context)
        let (_, deleted) = try self.insert(scheme: .v2_hybridPQ, country: v1Sealed, seal: self.sealedCurrent, deleted: true, in: context)
        let (_, v1Row) = try self.insert(scheme: .v1_identityDerived, country: v1Sealed, seal: self.sealedV1, in: context)

        try DatabaseMigration.migrateCountryOrphans(modelContext: context, legacyCrypto: LegacyCryptoManager(), newCrypto: Manager.Crypto())

        #expect(empty.country == "")
        #expect(deleted.country == v1Sealed, "a soft-deleted row is left, as migrateToV2 leaves it")
        #expect(v1Row.country == v1Sealed, "a v1 row belongs to migrateToV2")
    }

    // MARK: - Run until completed once

    @Test("The pass runs until it has completed once, and not at every launch after", .ambientTestKeyManager)
    func passRunsOnlyUntilCompleted() throws {
        let context = ModelContext(try makeContainer())
        let defaults = freshDefaults()
        let (_, first) = try self.insert(scheme: .v2_hybridPQ, country: try self.sealedV1("Moldova"), seal: self.sealedCurrent, in: context)

        try DatabaseMigration.migrateCountryOrphansOnce(
            modelContext: context, legacyCrypto: LegacyCryptoManager(), newCrypto: Manager.Crypto(), defaults: defaults
        )
        #expect(self.opensCurrent(first.country) == "Moldova")

        // Nothing makes a new one after a completed pass, so a second run is not made: this one is left.
        let sealed = try self.sealedV1("Romania")
        let (_, later) = try self.insert(scheme: .v2_hybridPQ, country: sealed, seal: self.sealedCurrent, in: context)
        try DatabaseMigration.migrateCountryOrphansOnce(
            modelContext: context, legacyCrypto: LegacyCryptoManager(), newCrypto: Manager.Crypto(), defaults: defaults
        )

        #expect(later.country == sealed)
    }

    @Test("A pass that could not read every country is not marked, and runs again", .ambientTestKeyManager)
    func incompletePassRunsAgain() throws {
        let context = ModelContext(try makeContainer())
        let defaults = freshDefaults()
        let noise = Data((0..<60).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
        let (_, stuck) = try self.insert(scheme: .v2_hybridPQ, country: noise, seal: self.sealedCurrent, in: context)

        try DatabaseMigration.migrateCountryOrphansOnce(
            modelContext: context, legacyCrypto: LegacyCryptoManager(), newCrypto: Manager.Crypto(), defaults: defaults
        )
        #expect(stuck.country == noise)

        // What could not be read is readable now (a rotation finished, say): the next launch must try again.
        stuck.country = try self.sealedV1("Moldova")
        try context.save()
        try DatabaseMigration.migrateCountryOrphansOnce(
            modelContext: context, legacyCrypto: LegacyCryptoManager(), newCrypto: Manager.Crypto(), defaults: defaults
        )

        #expect(self.opensCurrent(stuck.country) == "Moldova")
    }

    @Test("A pass that throws is not marked", .ambientTestKeyManager)
    func throwingPassRunsAgain() throws {
        let defaults = freshDefaults()
        struct Failure: Error {}
        var runs = 0

        #expect(throws: Failure.self) {
            try DatabaseMigration.runOnce("dbPass.test", defaults: defaults) { runs += 1; throw Failure() }
        }
        try DatabaseMigration.runOnce("dbPass.test", defaults: defaults) { runs += 1; return true }
        try DatabaseMigration.runOnce("dbPass.test", defaults: defaults) { runs += 1; return true }

        #expect(runs == 2, "it ran again after the failure, and not after it completed")
    }

    @Test("An empty store completes the pass too: the marker says nothing about the contacts", .ambientTestKeyManager)
    func emptyStoreCompletes() throws {
        let context = ModelContext(try makeContainer())
        let defaults = freshDefaults()

        try DatabaseMigration.migrateCountryOrphansOnce(
            modelContext: context, legacyCrypto: LegacyCryptoManager(), newCrypto: Manager.Crypto(), defaults: defaults
        )

        #expect(defaults.bool(forKey: DatabaseMigration.countryOrphansMarker))
    }
}

//
//  GlobalTrusteeRetirementTests.swift
//  OccultaTests
//
//  Global Trustees are retired (`decisions.md`, "Backup recovery lives only in the Vault tab;
//  Global Trustees retired"). A trustee's `globalTrusteeDepth` held the depth they were marked
//  at, readable without Face ID (`bugs.md` Bug 149), so `migrateRetireGlobalTrustees` resets
//  every live contact's stamp to a sealed, fixed-width -1, and `migrateDeleteGlobalShardConfig`
//  deletes the old depth-0 list without stamping anything.
//
//  Stamps are sealed under the ambient local key, so these run under
//  `.ambientTestKeyManager`, which supplies it.
//

import Testing
import Foundation
import SwiftData
import CryptoKit
@testable import Occulta
@testable import OccultaFormats

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

/// Inserts a contact whose trustee stamp is `stamp`, optionally soft-deleted; returns its identifier.
@MainActor
@discardableResult
private func insertContact(stamp: Data?, deleted: Bool = false, in container: ModelContainer) throws -> String {
    let identifier = UUID().uuidString
    let profile = Contact.Profile(
        identifier: identifier, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.globalTrusteeDepth = stamp
    if deleted { profile.deletionToken = try Data([1]).encrypt() }
    let context = ModelContext(container)
    context.insert(profile)
    try context.save()
    return identifier
}

@MainActor
private func stamp(of identifier: String, in container: ModelContainer) throws -> Data? {
    let rows = try ModelContext(container).fetch(FetchDescriptor<Contact.Profile>(predicate: #Predicate { $0.identifier == identifier }))
    return try #require(rows.first).globalTrusteeDepth
}

/// A sealed, fixed-width stamp for `value`, the form every live row should end up in.
private func sealed(_ value: Int) throws -> Data {
    try #require(try DepthCodec.encode(value).encrypt())
}

@MainActor
@Suite("Global Trustees retirement — stamps reset, old list deleted", .serialized, .ambientTestKeyManager)
struct GlobalTrusteeRetirementTests {

    private func readsNotATrustee(_ stamp: Data?) -> Bool {
        guard let stamp, stamp.count == DepthCodec.sealedSize, let plain = stamp.decrypt() else { return false }
        return DepthCodec.decode(plain) == -1
    }

    @Test("Marked, legacy-format and missing stamps all become a sealed -1")
    func resetsEveryStamp() throws {
        let container = try makeContainer()
        let atZero   = try insertContact(stamp: try sealed(0), in: container)
        let atTwo    = try insertContact(stamp: try sealed(2), in: container)
        let legacy   = try insertContact(stamp: try #require(try JSONEncoder().encode(2).encrypt()), in: container)
        let missing  = try insertContact(stamp: nil, in: container)

        try DatabaseMigration.migrateRetireGlobalTrustees(modelContext: ModelContext(container))

        for id in [atZero, atTwo, legacy, missing] {
            #expect(self.readsNotATrustee(try stamp(of: id, in: container)))
        }
    }

    @Test("A contact already at -1 is left byte-identical, and a second run changes nothing")
    func leavesBenignRowsAlone() throws {
        let container = try makeContainer()
        let benign  = try insertContact(stamp: try sealed(-1), in: container)
        let marked  = try insertContact(stamp: try sealed(3), in: container)
        let before  = try stamp(of: benign, in: container)

        try DatabaseMigration.migrateRetireGlobalTrustees(modelContext: ModelContext(container))
        let afterFirst = try stamp(of: marked, in: container)
        try DatabaseMigration.migrateRetireGlobalTrustees(modelContext: ModelContext(container))

        #expect(try stamp(of: benign, in: container) == before)
        #expect(try stamp(of: marked, in: container) == afterFirst, "an ordinary launch rewrites nothing")
    }

    /// A readable -1 among a row's unreadable fields is the mixed-readability row Bug 97 rejected.
    @Test("A stamp that doesn't decrypt is left byte-identical")
    func leavesUndecryptableStampAlone() throws {
        let container = try makeContainer()
        let unreadable = Data.randomBytes(DepthCodec.sealedSize)
        let id = try insertContact(stamp: unreadable, in: container)

        try DatabaseMigration.migrateRetireGlobalTrustees(modelContext: ModelContext(container))

        #expect(try stamp(of: id, in: container) == unreadable)
    }

    /// Soft-deleted rows are `migrateScrubDeletedDepthStamps`'s (Bug 97).
    @Test("Soft-deleted contacts are left to the deleted-row scrub")
    func skipsSoftDeletedRows() throws {
        let container = try makeContainer()
        let original = try sealed(2)
        let deleted  = try insertContact(stamp: original, deleted: true, in: container)

        try DatabaseMigration.migrateRetireGlobalTrustees(modelContext: ModelContext(container))

        #expect(try stamp(of: deleted, in: container) == original)
    }

    @Test("The old GlobalShardConfig list is deleted without marking anyone")
    func deletesOldListWithoutStamping() throws {
        let container = try makeContainer()
        let km        = TestKeyManager()
        let named     = try insertContact(stamp: try sealed(-1), in: container)
        let custodyKey = try #require(try km.deriveShardCustodyKey())
        let rowID     = UUID()
        let payload   = try JSONEncoder().encode(GlobalShardConfig.Payload(trusteeIDs: [named]))
        let box       = try AES.GCM.seal(payload, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: Data(rowID.uuidString.utf8))
        let context   = ModelContext(container)
        context.insert(GlobalShardConfig(id: rowID, encryptedPayload: try #require(box.combined)))
        try context.save()
        let before = try stamp(of: named, in: container)

        try DatabaseMigration.migrateDeleteGlobalShardConfig(modelContext: ModelContext(container))

        #expect(try ModelContext(container).fetch(FetchDescriptor<GlobalShardConfig>()).isEmpty)
        #expect(try stamp(of: named, in: container) == before, "the contact the old list named is not re-marked")
    }
}

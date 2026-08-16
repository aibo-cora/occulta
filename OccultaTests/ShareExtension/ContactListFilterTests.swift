//
//  ContactListFilterTests.swift
//  OccultaTests
//
//  `ContactListFilter` is what both the contacts tab and the share-recipient picker use to
//  decide who is on screen at the current depth. Those two lists showing different people at
//  the same depth is the Bug 25 / Bug 28 shape of failure, so the predicate is tested once
//  here rather than trusted twice in `View` bodies.
//
//  Encrypted round trips need the Enclave — `isVisible(atDepth:)` and `members(atDepth:)`
//  both decrypt.
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

/// `Contact.Profile`'s initialiser stores its name arguments verbatim, and every read goes
/// through `String.decrypt()` — so a fixture has to hand it ciphertext, base64-encoded, the
/// way the real insert path does. Passing plaintext yields "" from every accessor, which
/// silently collapses sort order rather than failing loudly.
@MainActor
private func sealed(_ value: String) throws -> String {
    guard let encrypted = try Data(value.utf8).encrypt() else {
        Issue.record("Could not encrypt fixture value")
        return ""
    }
    return encrypted.base64EncodedString()
}

@MainActor
private func makeProfile(
    given: String = "",
    family: String = "",
    organization: String = "",
    visibleThroughDepth: Int? = nil
) throws -> Contact.Profile {
    let profile = Contact.Profile(
        identifier: UUID().uuidString,
        givenName: try sealed(given), familyName: try sealed(family), middleName: "",
        nickname: "", organizationName: try sealed(organization), departmentName: "", jobTitle: ""
    )
    if let visibleThroughDepth {
        profile.visibleThroughDepth = try JSONEncoder().encode(visibleThroughDepth).encrypt()
    }
    return profile
}

// MARK: - Depth filtering

@MainActor
@Suite("ContactListFilter — depth", .enabled(if: secureEnclaveAvailable()), .serialized)
struct ContactListFilterDepthTests {

    /// The case the picker exists for: a contact classified as real-only is absent from the
    /// duress view and present at depth 0. Before Bug 84 the share sheet clamped to depth 1
    /// unconditionally, so this contact was unshareable from any depth.
    @Test func sensitiveContact_hiddenAtDepth1_visibleAtDepth0() throws {
        let sensitive = try makeProfile(given: "Real", family: "Only", visibleThroughDepth: 0)

        #expect(ContactListFilter.visibleContacts([sensitive], atDepth: 0).count == 1)
        #expect(ContactListFilter.visibleContacts([sensitive], atDepth: 1).isEmpty)
    }

    @Test func safeContact_visibleAtBothDepths() throws {
        let safe = try makeProfile(given: "Safe", family: "Contact", visibleThroughDepth: 1)

        #expect(ContactListFilter.visibleContacts([safe], atDepth: 0).count == 1)
        #expect(ContactListFilter.visibleContacts([safe], atDepth: 1).count == 1)
    }

    @Test func unclassifiedContact_visibleEverywhere() throws {
        let plain = try makeProfile(given: "No", family: "Classification")

        #expect(ContactListFilter.visibleContacts([plain], atDepth: 0).count == 1)
        #expect(ContactListFilter.visibleContacts([plain], atDepth: 2).count == 1)
    }
}

// MARK: - Search and sort

@MainActor
@Suite("ContactListFilter — search and sort", .enabled(if: secureEnclaveAvailable()), .serialized)
struct ContactListFilterSortTests {

    @Test func sortedContacts_ordersByFamilyName() throws {
        let zeta  = try makeProfile(given: "Ann",  family: "Zeta")
        let alpha = try makeProfile(given: "Bob",  family: "Alpha")

        let sorted = ContactListFilter.sortedContacts([zeta, alpha], matching: "")
        #expect(sorted.map { $0.familyName.decrypt() } == ["Alpha", "Zeta"])
    }

    @Test func sortedContacts_fallsBackToGivenName_whenNoFamilyNames() throws {
        let bea = try makeProfile(given: "Bea")
        let abe = try makeProfile(given: "Abe")

        let sorted = ContactListFilter.sortedContacts([bea, abe], matching: "")
        #expect(sorted.map { $0.givenName.decrypt() } == ["Abe", "Bea"])
    }

    @Test func sortedContacts_searchMatchesOrganization() throws {
        let one = try makeProfile(given: "Ann", family: "Zeta", organization: "Acme Logistics")
        let two = try makeProfile(given: "Bob", family: "Alpha", organization: "Other")

        let filtered = ContactListFilter.sortedContacts([one, two], matching: "acme")
        #expect(filtered.count == 1)
        #expect(filtered.first?.familyName.decrypt() == "Zeta")
    }

    @Test func sortedGroups_ordersByName_andFiltersBySearch() throws {
        let zulu  = try Group(name: "Zulu")
        let alpha = try Group(name: "Alpha")

        #expect(ContactListFilter.sortedGroups([zulu, alpha], matching: "").map { $0.readName() } == ["Alpha", "Zulu"])
        #expect(ContactListFilter.sortedGroups([zulu, alpha], matching: "zu").map { $0.readName() } == ["Zulu"])
    }
}

// MARK: - Group eligibility

@MainActor
@Suite("ContactListFilter — group eligibility", .enabled(if: secureEnclaveAvailable()), .serialized)
struct ContactListFilterGroupTests {

    @Test func groupWithMembersAtDepth_isOffered() throws {
        let group = try Group(name: "Field Team")
        try group.addMember(UUID().uuidString, atDepth: 0)

        #expect(ContactListFilter.groupsWithMembers([group], atDepth: 0).count == 1)
    }

    /// Membership is per-depth (Bug 73). A group populated only at depth 0 has nobody in it
    /// at depth 1, and `encryptGroupBundle` would throw `groupHasNoMembers` — so the picker
    /// must not offer it there.
    @Test func groupEmptyAtCurrentDepth_isNotOffered() throws {
        let group = try Group(name: "Field Team")
        try group.addMember(UUID().uuidString, atDepth: 0)

        #expect(ContactListFilter.groupsWithMembers([group], atDepth: 1).isEmpty)
    }

    @Test func groupWithNoMembersAnywhere_isNotOffered() throws {
        let group = try Group(name: "Empty")

        #expect(ContactListFilter.groupsWithMembers([group], atDepth: 0).isEmpty)
    }
}

//
//  TrustCheckPickerDepthTests.swift
//  OccultaTests
//
//  The Trust Check picker is a list of contacts, so it is a Bug 25 / Bug 28 surface: every row and the empty
//  state must come from the contacts visible at the current depth. A contact hidden at a duress depth must never
//  appear, and when every matching contact is hidden the screen must look like one with no matching contacts,
//  since a screen that differs tells a coercer hidden contacts exist.
//
//  Contacts here are real `Contact.Profile`s under `.ambientTestKeyManager`: a Verified one holds a key whose owner
//  hash is this device's, a Not verified one a key someone else's, a Pending one no key.
//

import Testing
import Foundation
import SwiftData
import OccultaFormats

@testable import Occulta

@MainActor
@Suite("Trust Check — picker follows the depth", .ambientTestKeyManager, .serialized)
struct TrustCheckPickerDepthTests {

    private enum Kind { case verified, notVerified, pending, revoked }

    private let container: ModelContainer

    init() throws {
        let schema = Schema([
            AppLayerConfig.self,
            Contact.Profile.self,
            Contact.Profile.PhoneNumber.self,
            Contact.Profile.EmailAddress.self,
            Contact.Profile.PostalAddress.self,
            Contact.Profile.URLAddress.self,
            Contact.Profile.Key.self,
        ])
        self.container = try ModelContainer(for: schema, configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)])
    }

    private func sealed(_ value: String) throws -> String {
        try #require(try Data(value.utf8).encrypt()).base64EncodedString()
    }

    /// `hiddenAtDuress`: classified so only depth 0 sees it.
    private func contact(_ name: String, _ kind: Kind, hiddenAtDuress: Bool = false) throws -> Contact.Profile {
        let context = ModelContext(self.container)
        let profile = Contact.Profile(
            identifier: UUID().uuidString,
            givenName: try self.sealed(name), familyName: try self.sealed("Test"), middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        profile.visibleThroughDepth = try DepthCodec.encode(hiddenAtDuress ? 0 : 1).encrypt()

        if kind != .pending {
            let owner = kind == .notVerified ? Data(repeating: 0x42, count: 32) : try Manager.Ambient.keyManager.retrieveIdentity().sha256
            let key = Contact.Profile.Key(
                material: try Data(count: 65).encrypt(),
                owner: try #require(try owner.encrypt()),
                date: try #require(try Data("0".utf8).encrypt())
            )
            if kind == .revoked { key.expiredOn = try Data("1".utf8).encrypt() }
            key.profile = profile
            profile.contactPublicKeys = [key]
        }

        context.insert(profile)
        try context.save()
        return profile
    }

    private func identifiers(_ rows: TrustCheckPicker.Rows) -> [String] {
        (rows.acting + rows.rest).map(\.identifier)
    }

    // MARK: - Visibility

    @Test("A contact hidden at the duress depth never appears there, in any scenario", arguments: TrustScenario.allCases)
    func hiddenContactNeverAppears(_ scenario: TrustScenario) throws {
        let verified = try self.contact("Visible", .verified)
        let hiddenVerified = try self.contact("Secret", .verified, hiddenAtDuress: true)
        let hiddenNotVerified = try self.contact("Quiet", .notVerified, hiddenAtDuress: true)
        let all = [verified, hiddenVerified, hiddenNotVerified]

        let atDuress = self.identifiers(TrustCheckPicker.rows(for: scenario, contacts: all, atDepth: 1, matching: ""))

        #expect(!atDuress.contains(hiddenVerified.identifier))
        #expect(!atDuress.contains(hiddenNotVerified.identifier))

        // Every row is in what the shared filter shows at that depth.
        let visible = Set(ContactListFilter.visibleContacts(all, atDepth: 1).map(\.identifier))
        #expect(Set(atDuress).isSubset(of: visible))
    }

    @Test("The same contacts all appear at the real depth, where the scenario lists them")
    func hiddenContactAppearsAtTheRealDepth() throws {
        let hidden = try self.contact("Secret", .verified, hiddenAtDuress: true)

        let rows = TrustCheckPicker.rows(for: .lostPhone, contacts: [hidden], atDepth: 0, matching: "")

        #expect(self.identifiers(rows) == [hidden.identifier])
    }

    // MARK: - Who each scenario lists

    @Test("The Not verified list holds only Not verified contacts")
    func notVerifiedListsOnlyNotVerified() throws {
        let verified = try self.contact("Verified", .verified)
        let notVerified = try self.contact("Shared", .notVerified)
        let pending = try self.contact("Pending", .pending)

        let rows = TrustCheckPicker.rows(for: .notVerified, contacts: [verified, notVerified, pending], atDepth: 0, matching: "")

        #expect(self.identifiers(rows) == [notVerified.identifier])
    }

    @Test("Every other contact scenario lists everyone, marking who it can't act on", arguments: [TrustScenario.suspiciousMessage, .lostPhone, .newPhone])
    func otherScenariosListEveryone(_ scenario: TrustScenario) throws {
        let all = [
            try self.contact("Verified", .verified), try self.contact("Shared", .notVerified),
            try self.contact("Pending", .pending), try self.contact("Revoked", .revoked),
        ]

        let rows = TrustCheckPicker.rows(for: scenario, contacts: all, atDepth: 0, matching: "")

        #expect(Set(self.identifiers(rows)) == Set(all.map(\.identifier)))
    }

    // MARK: - Rows

    @Test("Each row shows its TrustRemedy and the line for it", arguments: [TrustScenario.suspiciousMessage, .lostPhone, .newPhone, .notVerified])
    func rowsShowTheirRemedy(_ scenario: TrustScenario) throws {
        let all = [
            try self.contact("Verified", .verified), try self.contact("Shared", .notVerified),
            try self.contact("Pending", .pending), try self.contact("Revoked", .revoked),
        ]

        let rows = TrustCheckPicker.rows(for: scenario, contacts: all, atDepth: 0, matching: "")

        for row in rows.acting + rows.rest {
            let profile = try #require(all.first { $0.identifier == row.identifier })
            let remedy = TrustRemedy.make(for: scenario, profile: profile)

            #expect(row.remedy == remedy)
            #expect(row.status == profile.verificationStatus)
            #expect(row.line == remedy.line(for: scenario, status: row.status))
            #expect(!row.line.isEmpty)
        }
    }

    @Test("A revoked contact reads as Pending, with nothing to revoke")
    func revokedContactIsPending() throws {
        let revoked = try self.contact("Revoked", .revoked)

        let rows = TrustCheckPicker.rows(for: .lostPhone, contacts: [revoked], atDepth: 0, matching: "")
        let row = try #require(rows.rest.first)

        #expect(row.status == .pending)
        #expect(row.remedy == .meetInPerson)
    }

    @Test("Rows whose remedy acts come first; the rest follow")
    func actingRowsSortFirst() throws {
        let pending = try self.contact("Aaron", .pending)
        let verified = try self.contact("Zed", .verified)
        let notVerified = try self.contact("Mia", .notVerified)

        let rows = TrustCheckPicker.rows(for: .lostPhone, contacts: [pending, verified, notVerified], atDepth: 0, matching: "")

        #expect(Set(rows.acting.map(\.identifier)) == [verified.identifier, notVerified.identifier])
        #expect(rows.rest.map(\.identifier) == [pending.identifier])
        #expect(rows.acting.allSatisfy { $0.remedy.actsOnContact })
        #expect(rows.rest.allSatisfy { !$0.remedy.actsOnContact })
    }

    @Test("Search narrows the rows through the shared filter")
    func searchNarrows() throws {
        let alex = try self.contact("Alex", .verified)
        let blake = try self.contact("Blake", .verified)

        let rows = TrustCheckPicker.rows(for: .suspiciousMessage, contacts: [alex, blake], atDepth: 0, matching: "Blak")

        #expect(self.identifiers(rows) == [blake.identifier])
        #expect(!rows.isEmpty)
    }

    // MARK: - Empty state

    @Test("When every contact is hidden at the duress depth the picker is empty, in every scenario", arguments: TrustScenario.allCases)
    func everyContactHiddenIsEmpty(_ scenario: TrustScenario) throws {
        let all = [try self.contact("A", .verified, hiddenAtDuress: true), try self.contact("B", .notVerified, hiddenAtDuress: true)]

        #expect(TrustCheckPicker.rows(for: scenario, contacts: all, atDepth: 1, matching: "").isEmpty)
        #expect(!TrustCheckPicker.rows(for: scenario, contacts: all, atDepth: 0, matching: "").isEmpty)
    }

    @Test("Not verified contacts that are all hidden look like none at all")
    func notVerifiedAllHiddenIsEmpty() throws {
        let visibleVerified = try self.contact("Visible", .verified)
        let hiddenNotVerified = try self.contact("Quiet", .notVerified, hiddenAtDuress: true)
        let all = [visibleVerified, hiddenNotVerified]

        let atDuress = TrustCheckPicker.rows(for: .notVerified, contacts: all, atDepth: 1, matching: "")
        let genuinelyNone = TrustCheckPicker.rows(for: .notVerified, contacts: [visibleVerified], atDepth: 1, matching: "")

        #expect(atDuress.isEmpty)
        #expect(atDuress.isEmpty == genuinelyNone.isEmpty)
        #expect(self.identifiers(atDuress) == self.identifiers(genuinelyNone))
        #expect(!TrustCheckPicker.rows(for: .notVerified, contacts: all, atDepth: 0, matching: "").isEmpty)
        #expect(TrustScenario.notVerified.emptyListText == "No Not verified contacts")
    }

    @Test("A search with no match is not the empty state")
    func searchWithNoMatchIsNotEmpty() throws {
        let alex = try self.contact("Alex", .verified)

        let rows = TrustCheckPicker.rows(for: .lostPhone, contacts: [alex], atDepth: 0, matching: "zzz")

        #expect(self.identifiers(rows).isEmpty)
        #expect(!rows.isEmpty)
    }
}

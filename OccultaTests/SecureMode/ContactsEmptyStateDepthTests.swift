//
//  ContactsEmptyStateDepthTests.swift
//  OccultaTests
//
//  The contacts screen decides between its empty state (create-contact hint, no trust summary) and its
//  populated state. That decision must read what is visible at the current depth. Reading every stored
//  contact shows a coercer at a duress depth where all contacts are hidden a screen that a genuinely empty
//  install never shows: a 0/0/0 summary and no hint.
//

import Testing
import Foundation
import SwiftData
import OccultaFormats

@testable import Occulta

@MainActor
@Suite("Contacts screen — empty state follows the depth", .ambientTestKeyManager, .serialized)
struct ContactsEmptyStateDepthTests {

    private func makeContainer() throws -> ModelContainer {
        let schema = Schema([
            AppLayerConfig.self,
            Contact.Profile.self,
            Contact.Profile.PhoneNumber.self,
            Contact.Profile.EmailAddress.self,
            Contact.Profile.PostalAddress.self,
            Contact.Profile.URLAddress.self,
            Contact.Profile.Key.self,
        ])
        return try ModelContainer(for: schema, configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)])
    }

    /// A contact only the real depth sees.
    private func makeHiddenContact(in context: ModelContext) throws -> Contact.Profile {
        let profile = Contact.Profile(
            identifier: UUID().uuidString,
            givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        profile.visibleThroughDepth = try DepthCodec.encode(0).encrypt()
        context.insert(profile)
        return profile
    }

    @Test func everyContactHiddenAtDuressDepth_screenIsEmpty() throws {
        let container = try self.makeContainer()
        let security  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        let context   = ModelContext(container)

        _ = try self.makeHiddenContact(in: context)
        _ = try self.makeHiddenContact(in: context)
        try context.save()

        try security.configurePIN("123456")
        try security.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        security.applyVerifyState(for: try security.verify("999999"))
        #expect(security.currentDepth == 1)

        // What the screen's @Query holds: every contact at every depth.
        let stored = try context.fetch(Contact.Profile.descriptor)
        #expect(stored.count == 2)

        #expect(ContactListFilter.isEmptyList(stored, atDepth: security.currentDepth))
    }

    @Test func sameContacts_atRealDepth_screenIsNotEmpty() throws {
        let container = try self.makeContainer()
        let context   = ModelContext(container)

        _ = try self.makeHiddenContact(in: context)
        try context.save()

        let stored = try context.fetch(Contact.Profile.descriptor)
        #expect(!ContactListFilter.isEmptyList(stored, atDepth: 0))
    }

    @Test func noContacts_screenIsEmpty() {
        #expect(ContactListFilter.isEmptyList([], atDepth: 0))
        #expect(ContactListFilter.isEmptyList([], atDepth: 1))
    }
}

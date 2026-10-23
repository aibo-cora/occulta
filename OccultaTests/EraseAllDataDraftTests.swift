//
//  EraseAllDataDraftTests.swift
//  OccultaTests
//
//  Bug 179 — Erase All Data left every `Message.Draft` row and the `Drafts/` attachment files.
//
//  Runs the data half of `Manager.App.eraseAllData` (the contact and draft steps) against an
//  in-memory container. The full `eraseAllData` also calls the real `Manager.Key().deleteAllKeys()`,
//  so it stays out of the suite.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta

@MainActor
@Suite("Erase All Data — drafts", .serialized)
struct EraseAllDataDraftTests {

    private func makeContactManager() throws -> (ContactManager, ModelContainer) {
        let schema = Schema([
            Group.self,
            Contact.Profile.self,
            Contact.Profile.PhoneNumber.self,
            Contact.Profile.EmailAddress.self,
            Contact.Profile.PostalAddress.self,
            Contact.Profile.URLAddress.self,
            Contact.Profile.Key.self,
            Message.Draft.self,
        ])
        let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
        let security  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        return (ContactManager(modelContainer: container, security: security), container)
    }

    /// A draft row plus one attachment file in its folder. The ciphertext is opaque filler: the wipe
    /// must not need to open it.
    private func insertDraftWithAttachment(in container: ModelContainer) throws -> UUID {
        let id = UUID()
        let context = ModelContext(container)
        context.insert(Message.Draft(id: id, encryptedRecipientID: Data(repeating: 1, count: 60), encryptedContent: Data(repeating: 2, count: 90)))
        try context.save()

        let folder = Message.Draft.attachmentsFolder(for: id)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        try Data("sealed".utf8).write(to: folder.appendingPathComponent("\(UUID().uuidString).jpg"))
        return id
    }

    private var draftsRoot: URL { Message.Draft.attachmentsRoot }

    @Test("Erase All Data deletes draft rows, their attachment folders and the Drafts directory")
    func wipeDeletesDrafts() throws {
        let (contacts, container) = try self.makeContactManager()
        let id = try self.insertDraftWithAttachment(in: container)
        // A folder whose row is already gone: nothing else would ever remove it.
        let orphan = Message.Draft.attachmentsFolder(for: UUID())
        try FileManager.default.createDirectory(at: orphan, withIntermediateDirectories: true)
        try Data("sealed".utf8).write(to: orphan.appendingPathComponent("a.mp4"))

        try contacts.deleteAllContacts()
        try contacts.deleteAllDrafts()

        #expect(try ModelContext(container).fetchCount(FetchDescriptor<Message.Draft>()) == 0, "draft rows survived the wipe")
        #expect(!FileManager.default.fileExists(atPath: Message.Draft.attachmentsFolder(for: id).path), "the draft's attachment folder survived")
        #expect(!FileManager.default.fileExists(atPath: orphan.path), "an orphan attachment folder survived")
        #expect(!FileManager.default.fileExists(atPath: self.draftsRoot.path), "the Drafts directory survived")
    }

    @Test("Erase All Data with no drafts succeeds")
    func wipeWithNoDrafts() throws {
        let (contacts, _) = try self.makeContactManager()
        try? FileManager.default.removeItem(at: self.draftsRoot)

        try contacts.deleteAllDrafts()

        #expect(!FileManager.default.fileExists(atPath: self.draftsRoot.path))
    }

    /// Whether a batch delete of `Contact.Profile` cascades to its children is a runtime fact.
    @Test("Erase All Data leaves no contact child rows")
    func wipeDeletesContactChildren() throws {
        let (contacts, container) = try self.makeContactManager()
        let context = ModelContext(container)
        let profile = Contact.Profile(
            identifier: "c", givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        context.insert(profile)
        try context.save()

        try contacts.deleteAllContacts()

        let check = ModelContext(container)
        #expect(try check.fetchCount(FetchDescriptor<Contact.Profile>()) == 0)
        #expect(try check.fetchCount(FetchDescriptor<Contact.Profile.Key>()) == 0)
        #expect(try check.fetchCount(FetchDescriptor<Contact.Profile.PhoneNumber>()) == 0)
        #expect(try check.fetchCount(FetchDescriptor<Contact.Profile.EmailAddress>()) == 0)
        #expect(try check.fetchCount(FetchDescriptor<Contact.Profile.PostalAddress>()) == 0)
        #expect(try check.fetchCount(FetchDescriptor<Contact.Profile.URLAddress>()) == 0)
    }
}

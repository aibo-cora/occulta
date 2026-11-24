//
//  DraftKeysTests.swift
//  OccultaTests
//
//  Bug 202: `save(contact:)` installed whatever keys a `Contact.Draft` carried, and the draft decoded them from a file.
//  A key comes only from an in-person exchange (`update(key:for:)`), never from a draft: a draft that carries one saves
//  a contact with none, and a draft read from JSON holds none.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta

@MainActor
@Suite("Bug 202 — a draft carries no keys", .serialized)
struct DraftKeysTests {

    private func draftWithKey() throws -> Contact.Draft {
        let key = try #require(Contact.Draft.Key(material: try TestKeyManager().retrieveIdentity(), owner: Data(repeating: 1, count: 65), date: "1"))
        return Contact.Draft(identifier: UUID().uuidString, givenName: "A", familyName: "B", contactPublicKeys: [key])
    }

    @Test("Saving a new draft that carries a key leaves the contact with no key row", .ambientTestKeyManager)
    func saveInstallsNoKeys() throws {
        let cm = try TestSupport.makeContactManager()

        try cm.save(contact: try self.draftWithKey())

        let saved = try #require(try cm.fetchAllContacts().first)
        #expect(saved.contactPublicKeys?.isEmpty ?? true, "a key a draft carries must not become a trusted key")
    }

    @Test("A draft decoded from JSON that names keys holds none, and one written holds none either")
    func decodingReadsNoKeys() throws {
        let draft = try self.draftWithKey()
        var object = try #require(try JSONSerialization.jsonObject(with: JSONEncoder().encode(draft)) as? [String: Any])
        let key = try JSONSerialization.jsonObject(with: JSONEncoder().encode(try #require(draft.contactPublicKeys.first)))
        object["contactPublicKeys"] = [key]

        let decoded = try JSONDecoder().decode(Contact.Draft.self, from: JSONSerialization.data(withJSONObject: object))

        #expect(decoded.contactPublicKeys.isEmpty)
        #expect(!(String(data: try JSONEncoder().encode(draft), encoding: .utf8) ?? "").contains("contactPublicKeys"), "key material is left out of what a draft writes")
    }
}

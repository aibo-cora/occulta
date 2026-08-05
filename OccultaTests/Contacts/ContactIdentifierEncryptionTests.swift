//
//  ContactIdentifierEncryptionTests.swift
//  OccultaTests
//
//  Regression coverage for finding #11 (SecurityReview2026-07-24): ContactManager.save
//  stored a locally-created contact's identifier as a raw UUID string, while
//  createContacts encrypted it for imported contacts — a structural forensic tell
//  distinguishing "manually entered" from "imported" contacts by column format alone.
//
//  Uses TestKeyManager throughout — no Secure Enclave, simulator safe.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta

@MainActor
private func makeContainer() throws -> ModelContainer {
    let schema = Schema([
        AppLayerConfig.self,
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
        VaultEntry.self,
    ])
    return try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
}

@MainActor
private func makeContactManager() throws -> ContactManager {
    let container  = try makeContainer()
    let backend    = InMemoryLayerStoreBackend()
    let layerStore = Manager.LayerStore(backend: backend)
    let security   = Manager.Security(
        modelContainer: container,
        keyManager:     TestKeyManager(),
        layerStore:     layerStore
    )
    return ContactManager(modelContainer: container, security: security)
}

@MainActor
@Suite("ContactManager.save — identifier encryption")
struct ContactIdentifierEncryptionTests {

    @Test func newContact_identifierIsEncryptedNotStoredVerbatim() throws {
        let contacts = try makeContactManager()
        let crypto   = Manager.Crypto(keyManager: TestKeyManager())
        let rawIdentifier = UUID().uuidString

        try contacts.save(
            contact: Contact.Draft(identifier: rawIdentifier, givenName: "Ada"),
            using: crypto
        )

        let stored = try #require(try contacts.fetchAllContacts().first)
        #expect(stored.identifier != rawIdentifier)

        let decrypted = try crypto.decrypt(data: Data(base64Encoded: stored.identifier))
        #expect(decrypted.flatMap { String(data: $0, encoding: .utf8) } == rawIdentifier)
    }

    // The critical regression risk: save(contact:) is create-or-update, and a real edit's
    // Draft.identifier comes from convertToMutableCopy(using:), which passes the already-
    // stored identifier straight through unchanged (see its own doc comment: "The
    // encrypted unique identifier of the contact") — never the original plaintext UUID.
    // Encrypting it again before the lookup (rather than only when first creating it)
    // would never match the stored ciphertext, turning every edit into a
    // duplicate-creating "not found" instead of an update.
    @Test func editingExistingContact_updatesInPlace_doesNotCreateDuplicate() throws {
        let contacts = try makeContactManager()
        let crypto   = Manager.Crypto(keyManager: TestKeyManager())
        let rawIdentifier = UUID().uuidString

        try contacts.save(
            contact: Contact.Draft(identifier: rawIdentifier, givenName: "Ada"),
            using: crypto
        )

        // convertToMutableCopy always decrypts via the real (SE-backed) crypto manager,
        // not an injectable one, so it can't be used here — construct the edit draft
        // directly with the already-stored identifier instead, which is exactly what
        // convertToMutableCopy passes through unchanged in the real app.
        let created = try #require(try contacts.fetchAllContacts().first)
        let editedDraft = Contact.Draft(identifier: created.identifier, givenName: "Ada Lovelace")
        try contacts.save(contact: editedDraft, using: crypto)

        let allContacts = try contacts.fetchAllContacts()
        #expect(allContacts.count == 1, "editing an existing contact must not create a duplicate row")

        let updated = try #require(allContacts.first)
        let decryptedName = try crypto.decrypt(data: Data(base64Encoded: updated.givenName))
        #expect(decryptedName.flatMap { String(data: $0, encoding: .utf8) } == "Ada Lovelace")
    }
}

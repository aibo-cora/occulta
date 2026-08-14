//
//  DraftKeyRotationTests.swift
//  OccultaTests
//
//  `Message.Draft` rows must survive the local DB key rotation on **both** sides of Secure
//  Mode, not just activation.
//
//  Activation re-keyed drafts from the start, via `Message.Draft.reKeyOrPurgeAll` in Step 8.
//  Deactivation performs the identical rotation — stage, re-key, commit, delete the superseded
//  key — and had no draft pass at all, so every saved draft was left sealed under a key that
//  Step 9 then destroyed. `Message.Draft.find` could no longer open them, and the next
//  `reKeyOrPurgeAll` (which only runs on a duress PIN entry) took its delete branch for rows it
//  could not decrypt. Silent data loss on every deactivation.
//
//  These drive the real `deactivateSecureMode` rather than calling `reKeyOrPurgeAll` directly,
//  because the function was never the problem — the missing *call* was. A unit test of the
//  helper passes with the bug fully present.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta

/// True when this host can derive the real hybrid local DB key. False on GitHub-hosted CI
/// runners, which are VMs with no Secure Enclave.
private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

// MARK: - Harness

/// Own container rather than the shared activation one, because these need `Message.Draft`
/// and `Group` in the schema and nothing else in that file does.
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
        Message.Draft.self,
        Group.self,
        VaultEntry.self,
    ])
    return try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
}

@MainActor
private struct Harness {
    let security:   Manager.Security
    let container:  ModelContainer
    let contacts:   ContactManager
    let vault:      VaultManager
    let keyManager: TestKeyManager

    init() throws {
        self.container  = try makeContainer()
        self.keyManager = TestKeyManager()
        self.security   = Manager.Security(
            modelContainer: self.container,
            keyManager:     self.keyManager,
            layerStore:     Manager.LayerStore(backend: InMemoryLayerStoreBackend())
        )
        self.contacts = ContactManager(modelContainer: self.container, security: self.security)
        self.vault    = VaultManager(modelContainer: self.container, keyManager: TestKeyManager())
    }

    /// The canonical local DB key as the rotation sees it — same injected key manager the
    /// security manager derives `oldKey`/`stagedKey` from.
    func canonicalKey() throws -> SymmetricKey {
        try #require(try self.keyManager.createHybridLocalEncryptionKey())
    }

    func insertContact(identifier: String) {
        let ctx = ModelContext(self.container)
        ctx.insert(Contact.Profile(
            identifier: identifier, givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        ))
        try? ctx.save()
    }

    /// Seals a draft under `key` and inserts it, mirroring what `DraftStore` writes.
    @discardableResult
    func insertDraft(recipientID: String, text: String, under key: SymmetricKey) throws -> UUID {
        let id = UUID()
        let recipient = try #require(try AES.GCM.seal(
            Data(recipientID.utf8), using: key,
            authenticating: Message.Draft.aad(id: id, field: .recipientID)
        ).combined)
        let content = try #require(try AES.GCM.seal(
            Data(text.utf8), using: key,
            authenticating: Message.Draft.aad(id: id, field: .content)
        ).combined)

        let ctx = ModelContext(self.container)
        ctx.insert(Message.Draft(id: id, encryptedRecipientID: recipient, encryptedContent: content))
        try ctx.save()
        return id
    }

    /// The draft's content, opened under `key`, or nil if the row is gone or will not open.
    func draftText(id: UUID, under key: SymmetricKey) -> String? {
        let ctx = ModelContext(self.container)
        guard let row = (try? ctx.fetch(FetchDescriptor<Message.Draft>()))?.first(where: { $0.id == id }),
              let box = try? AES.GCM.SealedBox(combined: row.encryptedContent),
              let plain = try? AES.GCM.open(box, using: key, authenticating: row.aad(for: .content))
        else { return nil }
        return String(decoding: plain, as: UTF8.self)
    }

    func draftExists(id: UUID) -> Bool {
        let ctx = ModelContext(self.container)
        return ((try? ctx.fetch(FetchDescriptor<Message.Draft>())) ?? []).contains { $0.id == id }
    }
}

// MARK: - Tests

@Suite("Drafts survive the Secure Mode key rotation", .enabled(if: secureEnclaveAvailable()))
@MainActor
struct DraftKeyRotationTests {

    /// The regression. Deactivation rotates the key; a draft written before it must still open
    /// afterwards, under the new canonical key.
    @Test(.enabled(if: secureEnclaveAvailable()))
    func draftSurvivesDeactivation() async throws {
        let h = try Harness()
        h.insertContact(identifier: "alice")
        try h.security.configurePIN("111111")
        try await h.security.activateSecureMode(
            confirmingEntryPIN: "111111", duressPIN: "999999",
            contactManager: h.contacts, vaultManager: h.vault
        )

        // Written while Secure Mode is active, under the key that is canonical right now.
        let keyBefore = try h.canonicalKey()
        let draftID = try h.insertDraft(recipientID: "alice", text: "see you at six", under: keyBefore)

        try await h.security.deactivateSecureMode(
            confirmingEntryPIN: "111111",
            contactManager: h.contacts, vaultManager: h.vault
        )

        let keyAfter = try h.canonicalKey()
        #expect(h.draftExists(id: draftID), "the draft row was deleted by the deactivation")
        #expect(h.draftText(id: draftID, under: keyAfter) == "see you at six",
                "draft did not survive deactivation — still sealed under the destroyed key")
    }

    /// The rotation must actually have moved it, not merely left it readable because the key
    /// never changed. Without this, the test above would pass on a no-op rotation.
    @Test(.enabled(if: secureEnclaveAvailable()))
    func deactivationActuallyRotatesTheDraft() async throws {
        let h = try Harness()
        h.insertContact(identifier: "alice")
        try h.security.configurePIN("111111")
        try await h.security.activateSecureMode(
            confirmingEntryPIN: "111111", duressPIN: "999999",
            contactManager: h.contacts, vaultManager: h.vault
        )

        let keyBefore = try h.canonicalKey()
        let draftID = try h.insertDraft(recipientID: "alice", text: "moved", under: keyBefore)

        try await h.security.deactivateSecureMode(
            confirmingEntryPIN: "111111",
            contactManager: h.contacts, vaultManager: h.vault
        )

        #expect(h.draftText(id: draftID, under: keyBefore) == nil,
                "draft still opens under the pre-deactivation key — it was never re-keyed")
    }

    /// Activation's own pass, pinned alongside so the pair reads as one contract rather than
    /// two unrelated tests.
    @Test(.enabled(if: secureEnclaveAvailable()))
    func draftSurvivesActivation() async throws {
        let h = try Harness()
        h.insertContact(identifier: "alice")
        try h.security.configurePIN("111111")

        let keyBefore = try h.canonicalKey()
        let draftID = try h.insertDraft(recipientID: "alice", text: "before activating", under: keyBefore)

        try await h.security.activateSecureMode(
            confirmingEntryPIN: "111111", duressPIN: "999999",
            contactManager: h.contacts, vaultManager: h.vault
        )

        let keyAfter = try h.canonicalKey()
        #expect(h.draftText(id: draftID, under: keyAfter) == "before activating")
    }

    /// Deactivation must not become a blanket "keep everything": a draft whose recipient no
    /// longer exists still goes, which is what `reKeyOrPurgeAll` is for.
    @Test(.enabled(if: secureEnclaveAvailable()))
    func draftForUnknownRecipientIsPurgedOnDeactivation() async throws {
        let h = try Harness()
        h.insertContact(identifier: "alice")
        try h.security.configurePIN("111111")
        try await h.security.activateSecureMode(
            confirmingEntryPIN: "111111", duressPIN: "999999",
            contactManager: h.contacts, vaultManager: h.vault
        )

        let keyBefore = try h.canonicalKey()
        let orphan = try h.insertDraft(recipientID: "nobody", text: "orphan", under: keyBefore)
        let kept   = try h.insertDraft(recipientID: "alice",  text: "kept",   under: keyBefore)

        try await h.security.deactivateSecureMode(
            confirmingEntryPIN: "111111",
            contactManager: h.contacts, vaultManager: h.vault
        )

        #expect(!h.draftExists(id: orphan), "a draft for a non-existent recipient should be purged")
        #expect(h.draftExists(id: kept))
    }
}

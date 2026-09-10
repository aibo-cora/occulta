//
//  SecureModeActivationTests.swift
//  OccultaTests
//
//  Regression coverage for Secure Mode activation and deactivation, reworked for the
//  PIN-only shape (Removal Stages 0-3, `plan.md`): `activateSecureMode`/`deactivateSecureMode`
//  verify a PIN and write or clear `AppLayerConfig` verifiers — nothing else. They no longer
//  touch `Contact.Profile`, `VaultEntry`, `Message.Draft`, `Group`, or any of
//  `AppLayerConfig`'s other local-DB-key fields at all; there is no blob to seal sensitive
//  contacts into and no staged key to re-encrypt anything under.
//
//  This file used to test the opposite: that activation/deactivation correctly re-encrypted,
//  classified, and restored application data during a key rotation that no longer exists. That
//  content is gone. What replaces it:
//
//  1. Non-interference — a contact's, vault entry's, and key record's bytes must be
//     byte-identical before and after any activate/deactivate cycle, including a nested one.
//     The direct regression guard for the removal itself: if a future change reintroduces
//     data-touching in either function, this fails loudly.
//  2. WAL persistence (Bug 37, PIN-only shape) — the `AppLayerConfig` verifier writes
//     activate/deactivate still make are their entire remaining job; this confirms they reach
//     the persistent store, not just an in-memory `ModelContext`, by fetching from a
//     brand-new one afterward.
//
//  SE-availability guard — a helper checks whether `Manager.Key` can derive a key at runtime.
//  Every test here uses the injected `TestKeyManager` throughout and never the real
//  `Manager.Key()`, so none of them strictly need it; the gate is kept only for consistency
//  with the rest of the Secure Mode suite, which does depend on it for reasons unrelated to
//  what this file tests.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta

// MARK: - Container

/// Schema used by every test in this file. Includes `VaultEntry` so `vault.fetchAllEntries()`
/// does not throw.
@MainActor
private func makeActivationContainer() throws -> ModelContainer {
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

// MARK: - Component bundle

private struct ActivationComponents {
    let security:   Manager.Security
    let container:  ModelContainer
    let contacts:   ContactManager
    let vault:      VaultManager
    let keyManager: TestKeyManager
}

@MainActor
private func makeComponents() throws -> ActivationComponents {
    let container  = try makeActivationContainer()
    let keyManager = TestKeyManager()
    let security   = Manager.Security(modelContainer: container, keyManager: keyManager)
    let contacts   = ContactManager(modelContainer: container, security: security)
    let vault      = VaultManager(modelContainer: container, keyManager: TestKeyManager())
    return ActivationComponents(
        security: security, container: container, contacts: contacts, vault: vault,
        keyManager: keyManager
    )
}

/// True when this host can derive the real hybrid local DB key. False on the iOS Simulator or a
/// CI runner with no Secure Enclave.
private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

// MARK: - Contact helpers

/// Insert a `Contact.Profile` directly into the persistent store, with arbitrary — not
/// necessarily decryptable — bytes in its depth fields and key material. Activation and
/// deactivation no longer read or decrypt any of this, so what it contains is irrelevant to
/// every test in this file; only whether the bytes change matters.
@MainActor
private func insertContact(
    identifier: String,
    in container: ModelContainer,
    visibleThroughDepth: Data? = nil,
    globalTrusteeDepth: Data? = nil,
    originDepth: Data? = nil,
    keyMaterial: Data? = nil
) throws {
    let ctx = ModelContext(container)
    let profile = Contact.Profile(
        identifier: identifier, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.visibleThroughDepth = visibleThroughDepth
    profile.globalTrusteeDepth  = globalTrusteeDepth
    profile.originDepth         = originDepth
    if let keyMaterial {
        profile.contactPublicKeys = [
            Contact.Profile.Key(material: keyMaterial, owner: Data("owner".utf8), date: Data("date".utf8))
        ]
    }
    ctx.insert(profile)
    try ctx.save()
}

/// Fetch all non-deleted `Contact.Profile` rows from a fresh `ModelContext` — bypasses any
/// in-memory cache, so this sees exactly what reached the persistent store.
@MainActor
private func fetchAllProfiles(from container: ModelContainer) throws -> [Contact.Profile] {
    let ctx       = ModelContext(container)
    let predicate = #Predicate<Contact.Profile> { $0.deletionToken == nil }
    return try ctx.fetch(FetchDescriptor<Contact.Profile>(predicate: predicate))
}

// MARK: - Vault entry helpers

/// Insert a `VaultEntry` directly into the persistent store, mirroring `insertContact`. Returns
/// the entry's `id` so the caller can find it again after a fresh fetch (`VaultEntry` has no
/// string identifier field to match on).
@MainActor
private func insertVaultEntry(in container: ModelContainer, visibleThroughDepth: Data? = nil) throws -> UUID {
    let ctx   = ModelContext(container)
    let entry = VaultEntry(encryptedLabel: Data(), encryptedContent: Data())
    entry.visibleThroughDepth = visibleThroughDepth
    ctx.insert(entry)
    try ctx.save()
    return entry.id
}

/// Fetch all `VaultEntry` rows from a fresh `ModelContext` — same rationale as
/// `fetchAllProfiles`.
@MainActor
private func fetchAllVaultEntries(from container: ModelContainer) throws -> [VaultEntry] {
    try ModelContext(container).fetch(FetchDescriptor<VaultEntry>())
}

/// Fetch the single `AppLayerConfig` row from a fresh `ModelContext` — same rationale as
/// `fetchAllProfiles`, applied to the one model activation/deactivation still writes.
@MainActor
private func fetchConfig(from container: ModelContainer) throws -> AppLayerConfig? {
    try ModelContext(container).fetch(FetchDescriptor<AppLayerConfig>()).first
}

// MARK: - Non-interference

/// The direct regression guard for this removal: activation and deactivation must not read,
/// decrypt, or rewrite a single byte of application data — contacts, vault entries, or key
/// records — regardless of nesting depth or whether the bytes happen to be real ciphertext or
/// garbage nothing can decrypt. There is no classification, no blob, and no key rotation left
/// to make any of that matter.
@Suite("Secure Mode — activation and deactivation never touch application data", .serialized)
struct SecureModeNonInterferenceTests {

    @Test("A contact's depth fields and key material survive a single activate/deactivate cycle",
          .enabled(if: secureEnclaveAvailable()))
    @MainActor
    func contactSurvivesSingleCycle() throws {
        let c = try makeComponents()
        try c.security.configurePIN("111111")

        let id       = "contact-\(UUID().uuidString)"
        let visible  = Data([0x01, 0x02, 0x03])
        let trustee  = Data([0x04, 0x05])
        let origin   = Data([0x06])
        let material = Data([0x07, 0x08, 0x09, 0x0A])
        try insertContact(identifier: id, in: c.container, visibleThroughDepth: visible,
                          globalTrusteeDepth: trustee, originDepth: origin, keyMaterial: material)

        try c.security.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        try c.security.deactivateSecureMode(confirmingEntryPIN: "111111")

        let after = try #require(try fetchAllProfiles(from: c.container).first { $0.identifier == id })
        #expect(after.visibleThroughDepth == visible)
        #expect(after.globalTrusteeDepth == trustee)
        #expect(after.originDepth == origin)
        #expect(after.contactPublicKeys?.first?.material == material)
    }

    @Test("A contact survives a nested two-layer activate/deactivate cycle unchanged",
          .enabled(if: secureEnclaveAvailable()))
    @MainActor
    func contactSurvivesNestedCycle() throws {
        let c = try makeComponents()
        try c.security.configurePIN("111111")

        let id      = "contact-\(UUID().uuidString)"
        let visible = Data([0xAA, 0xBB])
        try insertContact(identifier: id, in: c.container, visibleThroughDepth: visible)

        try c.security.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        c.security.applyVerifyState(for: try c.security.verify("999999"))
        #expect(c.security.currentDepth == 1)
        try c.security.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "777777")
        c.security.applyVerifyState(for: try c.security.verify("777777"))
        #expect(c.security.currentDepth == 2)

        try c.security.deactivateSecureMode(confirmingEntryPIN: "777777")
        #expect(c.security.currentDepth == 1)
        try c.security.deactivateSecureMode(confirmingEntryPIN: "999999")
        #expect(!c.security.isSecureModeActive)

        let after = try #require(try fetchAllProfiles(from: c.container).first { $0.identifier == id })
        #expect(after.visibleThroughDepth == visible,
                "an unrelated nested layer's activation/deactivation must not touch a shallower contact")
    }

    @Test("A vault entry's visibility ceiling survives an activate/deactivate cycle",
          .enabled(if: secureEnclaveAvailable()))
    @MainActor
    func vaultEntrySurvivesCycle() throws {
        let c = try makeComponents()
        try c.security.configurePIN("111111")

        let ceiling = Data([0xC0, 0xC0])
        let entryID = try insertVaultEntry(in: c.container, visibleThroughDepth: ceiling)

        try c.security.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        try c.security.deactivateSecureMode(confirmingEntryPIN: "111111")

        let after = try #require(try fetchAllVaultEntries(from: c.container).first { $0.id == entryID })
        #expect(after.visibleThroughDepth == ceiling)
    }

    @Test("Bytes nothing can decrypt survive identically too — there is no decrypt-and-fallback path left",
          .enabled(if: secureEnclaveAvailable()))
    @MainActor
    func undecryptableBytesSurviveUnchanged() throws {
        let c = try makeComponents()
        try c.security.configurePIN("111111")

        let id      = "contact-\(UUID().uuidString)"
        let garbage = Data([0xDE, 0xAD, 0xBE, 0xEF])
        try insertContact(identifier: id, in: c.container, visibleThroughDepth: garbage)

        try c.security.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")

        let after = try #require(try fetchAllProfiles(from: c.container).first { $0.identifier == id })
        #expect(after.visibleThroughDepth == garbage, """
            Every prior activation used to decrypt-and-reseal or decrypt-and-fallback this \
            field, so unreadable bytes were a special case with their own failure mode (Bugs \
            37, 87). Now nothing reads it at all, so there is no special case: readable and \
            unreadable bytes behave identically, which this asserts directly.
            """)
    }
}

// MARK: - WAL persistence (Bug 37, PIN-only shape)

/// Guards a narrower version of the regression commit 70e1f77 fixed: that fix was
/// `contactManager.modelContext.save()` being skipped during a rotation this codebase no
/// longer has. What `activateSecureMode`/`deactivateSecureMode` still write — the
/// `AppLayerConfig` verifiers — goes through a different `modelContext`
/// (`Manager.Security`'s own) and a different call path entirely, so this is a fresh check,
/// not a resurrection of the old one: does that write reach the persistent store, verified
/// from a brand-new `ModelContext` that bypasses every in-memory cache, not just the
/// in-memory `AppLayerConfig` instance every other test in this file reads through
/// `c.security` directly.
@Suite("Secure Mode — verifier writes persist to the WAL (Bug 37, PIN-only shape)", .serialized)
struct SecureModeVerifierPersistenceTests {

    @Test("activateSecureMode's verifier write is readable from a fresh ModelContext",
          .enabled(if: secureEnclaveAvailable()))
    @MainActor
    func activationPersistsVerifiers() throws {
        let c = try makeComponents()
        try c.security.configurePIN("111111")

        try c.security.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")

        let config = try #require(try fetchConfig(from: c.container))
        #expect(config.sealedDuressVerifier != nil,
                "activateSecureMode's own state write did not reach the persistent store")
    }

    @Test("deactivateSecureMode's verifier clear is readable from a fresh ModelContext",
          .enabled(if: secureEnclaveAvailable()))
    @MainActor
    func deactivationPersistsClearedVerifiers() throws {
        let c = try makeComponents()
        try c.security.configurePIN("111111")
        try c.security.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")

        try c.security.deactivateSecureMode(confirmingEntryPIN: "111111")

        let config = try #require(try fetchConfig(from: c.container))
        #expect(config.sealedDuressVerifier == nil,
                "deactivateSecureMode's own state write did not reach the persistent store")
    }
}

// MARK: - Launch migration

/// `DatabaseMigration.migrateDepthFieldsToFixedWidth` runs in `App.init()`, independently of
/// Secure Mode activation entirely — it normalises the legacy JSON depth encoding to the
/// fixed-width one (Bug 85) regardless of PIN or duress state. Its one piece of coverage that
/// belongs in this file: a row sealed under a key the migration cannot derive (the same end
/// state a rotation used to leave stranded rows in, before rotation itself was removed) must
/// be left alone rather than resolved to a default.
@Suite("Launch migration — inert against undecryptable rows")
struct DepthMigrationInertnessTests {

    @Test("The migration is a no-op against rows it cannot decrypt",
          .enabled(if: secureEnclaveAvailable()))
    @MainActor
    func migrationIsInertAgainstForeignKeyRows() throws {
        let c  = try makeComponents()
        let id = "foreign-\(UUID().uuidString)"

        let foreignKey = SymmetricKey(size: .bits256)
        let foreign = try AES.GCM.seal(JSONEncoder().encode(0), using: foreignKey,
                                       authenticating: EncryptionScheme.v2_hybridPQ.aad).combined
        try insertContact(identifier: id, in: c.container, visibleThroughDepth: foreign)

        try DatabaseMigration.migrateDepthFieldsToFixedWidth(modelContext: ModelContext(c.container))

        let row = try fetchAllProfiles(from: c.container).first { $0.identifier == id }
        #expect(row?.visibleThroughDepth == foreign, """
            A row sealed under a key the migration cannot derive must be left byte-identical. \
            Rewriting it would need a decrypt that cannot succeed; resolving it to a default \
            would persist Int.max — visible at every duress depth.
            """)
    }
}

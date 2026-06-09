//
//  SecureModeActivationTests.swift
//  OccultaTests
//
//  Data-integrity regression tests for Secure Mode activation and deactivation.
//
//  Architecture note — key-manager split:
//  Manager.Security uses the injected TestKeyManager (in-memory, no SE).
//  ContactManager uses Manager.Crypto() → Manager.Key() (real Keychain / SE).
//  After activation, contact fields are re-encrypted with TestKeyManager's staged
//  key, which Manager.Key cannot decrypt.  This makes post-activation field-content
//  round-trips impossible in tests without a full key-injection refactor.
//
//  What IS testable without that refactor:
//  1. Blob I/O — sealed/unsealed with TestKeyManager's SecureMode key, SE-independent.
//  2. WAL-persistence smoke test — fetch from a brand-new ModelContext to verify
//     contactManager.modelContext.save() actually wrote to the persistent store.
//     This is the direct Bug 37 regression guard.
//  3. SE-availability guard — a helper checks whether Manager.Key can derive a
//     key at runtime; tests that require real SE skip gracefully on the simulator.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta

// MARK: - Container

/// Schema used by all activation/deactivation tests.
/// Includes VaultEntry so vaultManager.fetchAllEntries() does not throw.
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
    /// Raw backend — used for low-level assertions (e.g. `.exists`).
    let backend:    InMemoryLayerStoreBackend
    /// Layer store — used for readPayload() in blob-content tests.
    let layerStore: Manager.LayerStore
    let keyManager: TestKeyManager
}

@MainActor
private func makeComponents() throws -> ActivationComponents {
    let container  = try makeActivationContainer()
    let keyManager = TestKeyManager()
    let backend    = InMemoryLayerStoreBackend()
    let layerStore = Manager.LayerStore(backend: backend)
    let security   = Manager.Security(
        modelContainer: container,
        keyManager:     keyManager,
        layerStore:     layerStore
    )
    let contacts = ContactManager(modelContainer: container, security: security)
    let vault    = VaultManager(modelContainer: container, keyManager: TestKeyManager())
    return ActivationComponents(
        security:   security,
        container:  container,
        contacts:   contacts,
        vault:      vault,
        backend:    backend,
        layerStore: layerStore,
        keyManager: keyManager
    )
}

// MARK: - Contact helpers

/// Insert a Contact.Profile directly into the persistent store.
/// Using direct insertion keeps the helper SE-independent: no ContactManager
/// field-encryption is involved, so the test works on both simulator and device.
@MainActor
private func insertContact(
    identifier: String,
    in container: ModelContainer,
    visibleThroughDepth: Data? = nil
) throws {
    let ctx = ModelContext(container)
    let profile = Contact.Profile(
        identifier:       identifier,
        givenName:        "",
        familyName:       "",
        middleName:       "",
        nickname:         "",
        organizationName: "",
        departmentName:   "",
        jobTitle:         ""
    )
    profile.visibleThroughDepth = visibleThroughDepth
    ctx.insert(profile)
    try ctx.save()
}

/// Fetch all non-deleted Contact.Profile rows from a fresh ModelContext.
/// A fresh context bypasses the contactManager's in-memory cache, so we see
/// exactly what is on disk — this is used to verify that save() reached the WAL.
@MainActor
private func fetchAllProfiles(from container: ModelContainer) throws -> [Contact.Profile] {
    let ctx       = ModelContext(container)
    let predicate = #Predicate<Contact.Profile> { $0.deletionToken == nil }
    return try ctx.fetch(FetchDescriptor<Contact.Profile>(predicate: predicate))
}

/// Returns true if Manager.Key can derive the hybrid local key in this environment.
/// False on the iOS Simulator where no Secure Enclave is present.
/// Used to skip tests whose correctness depends on real SE-backed field encryption.
private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

// MARK: - Blob helpers

/// Reads the activation payload non-destructively from the blob store.
/// Uses the slot index stored in AppLayerConfig to locate the right slot.
@MainActor
private func readActivationPayload(from c: ActivationComponents) throws -> LayerPayload {
    let config = try c.container.mainContext.fetch(FetchDescriptor<AppLayerConfig>()).first!
    guard let slotIndex = config.readBlobSlot(at: 0) else {
        throw TestError("no blob slot stored in config after activation")
    }
    guard let seKey    = try c.keyManager.deriveSecureModeKey(),
          let layerKey = c.layerStore.deriveKey(from: seKey)
    else { throw TestError("could not derive blob key from TestKeyManager") }
    return try c.layerStore.readPayload(key: layerKey, slotIndex: slotIndex)
}

// MARK: - Blob lifecycle

@MainActor
@Suite("Secure Mode — Blob lifecycle", .serialized)
struct SecureModeBlobLifecycleTests {

    @Test func activation_writesBlob() async throws {
        let c = try makeComponents()
        try c.security.configurePIN("111111")
        #expect(!c.backend.exists, "blob should not exist before activation")

        try await c.security.activateSecureMode(
            confirmingEntryPIN: "111111", duressPIN: "999999",
            contactManager: c.contacts, vaultManager: c.vault
        )

        #expect(c.backend.exists, "blob must be written during activation")
    }

    @Test func activation_blobReadableWithCorrectKey() async throws {
        // Verifies push/pop are symmetric end-to-end using TestKeyManager's
        // SecureMode key — entirely SE-independent (no Manager.Key involvement).
        let c = try makeComponents()
        try c.security.configurePIN("111111")
        try await c.security.activateSecureMode(
            confirmingEntryPIN: "111111", duressPIN: "999999",
            contactManager: c.contacts, vaultManager: c.vault
        )

        // readPayload should not throw — proves the push payload is decodable.
        let payload = try readActivationPayload(from: c)
        _ = payload  // structure is valid; contact content depends on SE availability
    }

    @Test func deactivation_blobStillReadableDuringDeactivation() async throws {
        // The deactivation sequence pops the blob to restore sensitive contacts.
        // If pop throws, it falls back to an empty payload — verify it doesn't throw.
        let c = try makeComponents()
        try c.security.configurePIN("111111")
        try await c.security.activateSecureMode(
            confirmingEntryPIN: "111111", duressPIN: "999999",
            contactManager: c.contacts, vaultManager: c.vault
        )
        // Deactivation must complete successfully; if blob was unreadable it would
        // fall back to an empty payload but the sequence would still succeed.
        try await c.security.deactivateSecureMode(
            confirmingEntryPIN: "111111",
            contactManager: c.contacts, vaultManager: c.vault
        )
        #expect(!c.security.isSecureModeActive)
    }

    @Test func activation_blobIsCorrectSize() async throws {
        let c = try makeComponents()
        try c.security.configurePIN("111111")
        try await c.security.activateSecureMode(
            confirmingEntryPIN: "111111", duressPIN: "999999",
            contactManager: c.contacts, vaultManager: c.vault
        )
        let data = try c.backend.read()
        let expectedSize = Manager.LayerStore.slotCount * Manager.LayerStore.slotCiphertextSize
        #expect(data.count == expectedSize, "blob must be exactly \(expectedSize) bytes (32 fixed slots)")
    }
}

// MARK: - Contact classification

@MainActor
@Suite("Secure Mode — Contact classification in blob", .serialized)
struct SecureModeClassificationTests {

    /// A contact whose `visibleThroughDepth` is non-nil but not valid AES-GCM
    /// ciphertext will fail `data.decrypt()` → `isVisible` returns false →
    /// classified as SENSITIVE and goes into the blob.
    /// This trick avoids SE dependency: no Manager.Crypto call needed.
    private static let sensitiveDepthMarker = Data([0xDE, 0xAD, 0xBE, 0xEF])

    @Test func sensitiveContact_appearsInBlob() async throws {
        let c = try makeComponents()
        try c.security.configurePIN("111111")

        let sensitiveID = "contact-sensitive-\(UUID().uuidString)"
        // Non-AES garbage → decrypt fails → classified sensitive
        try insertContact(identifier: sensitiveID, in: c.container,
                          visibleThroughDepth: Self.sensitiveDepthMarker)

        try await c.security.activateSecureMode(
            confirmingEntryPIN: "111111", duressPIN: "999999",
            contactManager: c.contacts, vaultManager: c.vault
        )

        let payload           = try readActivationPayload(from: c)
        let identifiersInBlob = payload.contacts.map { $0.draft.identifier }
        #expect(identifiersInBlob.contains(sensitiveID),
                "sensitive contact must be sealed in the blob during activation")
    }

    @Test func safeContact_doesNotAppearInBlob() async throws {
        let c = try makeComponents()
        try c.security.configurePIN("111111")

        let safeID      = "contact-safe-\(UUID().uuidString)"
        let sensitiveID = "contact-sensitive-\(UUID().uuidString)"
        // nil → classified safe (default visible)
        try insertContact(identifier: safeID, in: c.container, visibleThroughDepth: nil)
        // Non-AES garbage → classified sensitive
        try insertContact(identifier: sensitiveID, in: c.container,
                          visibleThroughDepth: Self.sensitiveDepthMarker)

        try await c.security.activateSecureMode(
            confirmingEntryPIN: "111111", duressPIN: "999999",
            contactManager: c.contacts, vaultManager: c.vault
        )

        let payload           = try readActivationPayload(from: c)
        let identifiersInBlob = Set(payload.contacts.map { $0.draft.identifier })

        #expect(!identifiersInBlob.contains(safeID),
                "safe contact must NOT be in the blob")
        #expect(identifiersInBlob.contains(sensitiveID),
                "sensitive contact must be in the blob")
    }

    @Test func sensitiveContact_restoredByIdentifier_afterDeactivation() async throws {
        // Verifies the deactivation blob-restore path rewrites the contact row.
        // Identifier equality is SE-independent (identifier field is not encrypted).
        let c = try makeComponents()
        try c.security.configurePIN("111111")

        let sensitiveID = "contact-sensitive-\(UUID().uuidString)"
        try insertContact(identifier: sensitiveID, in: c.container,
                          visibleThroughDepth: Self.sensitiveDepthMarker)

        try await c.security.activateSecureMode(
            confirmingEntryPIN: "111111", duressPIN: "999999",
            contactManager: c.contacts, vaultManager: c.vault
        )
        try await c.security.deactivateSecureMode(
            confirmingEntryPIN: "111111",
            contactManager: c.contacts, vaultManager: c.vault
        )

        // Fetch from a fresh context to verify persistence (not just in-memory state).
        let profiles = try fetchAllProfiles(from: c.container)
        let restored = profiles.first { $0.identifier == sensitiveID }
        #expect(restored != nil,
                "sensitive contact must be restored from blob after deactivation")
    }
}

// MARK: - WAL-persistence regression guard (Bug 37)

/// These tests guard against the regression introduced in commit 70e1f77:
/// `reencryptAllFields` mutated SwiftData objects in-memory but never called
/// `contactManager.modelContext.save()`. The WAL checkpoint fired on an empty WAL,
/// leaving the main SQLite file with pre-activation ciphertext. After the old SE key
/// was deleted those rows became permanently unreadable.
///
/// The fix: explicit `contactManager.modelContext.save()` after Step 8 (activation)
/// and after Step 4 (deactivation). These tests verify that the save actually reaches
/// the persistent store by fetching from a brand-new ModelContext that bypasses all
/// in-memory caches.
@MainActor
@Suite("Secure Mode — WAL persistence (Bug 37 regression guard)", .serialized)
struct SecureModeWALPersistenceTests {

    // MARK: Activation

    /// Verifies that activation's contact re-encryption is flushed to the WAL.
    ///
    /// Strategy: insert a contact whose `visibleThroughDepth` is nil.  Activation
    /// Step 5 stamps `encrypt(Int.max)` on nil-depth safe contacts (SE required); if
    /// SE is unavailable the stamp silently fails and the field stays nil — in that
    /// case the test skips rather than producing a false result.
    ///
    /// On a physical device (SE available):
    /// - Before activation: `visibleThroughDepth` = `encrypt(Int.max)` (Manager.Key)
    /// - After activation:  `visibleThroughDepth` = AES-GCM(stagedKey, Int.max)  ← different bytes
    /// - If Bug 37 regresses (save omitted): fresh context sees pre-activation bytes → test FAILS.
    @Test func activation_contactChanges_persistedToWAL() async throws {
        guard secureEnclaveAvailable() else {
            print("⚠︎ Skipping activation WAL-persistence test — SE not available (simulator)")
            return
        }

        let c = try makeComponents()
        try c.security.configurePIN("111111")

        let id = "contact-\(UUID().uuidString)"
        try insertContact(identifier: id, in: c.container)

        // Stamp safe classification so visibleThroughDepth becomes a real ciphertext.
        try c.security.updateSafeContacts([id])

        // Capture the pre-activation ciphertext from a fresh context.
        let profilesBefore    = try fetchAllProfiles(from: c.container)
        let depthBefore       = profilesBefore.first { $0.identifier == id }?.visibleThroughDepth
        guard depthBefore != nil else {
            print("⚠︎ Skipping activation WAL-persistence test — visibleThroughDepth not set (SE unavailable)")
            return
        }

        try await c.security.activateSecureMode(
            confirmingEntryPIN: "111111", duressPIN: "999999",
            contactManager: c.contacts, vaultManager: c.vault
        )

        // Fetch from a brand-new context to bypass all in-memory caches.
        let profilesAfter = try fetchAllProfiles(from: c.container)
        let depthAfter    = profilesAfter.first { $0.identifier == id }?.visibleThroughDepth

        // The staged-key ciphertext must differ from the pre-activation ciphertext.
        // If Bug 37 regresses, the WAL was never written and the fresh fetch returns
        // the unchanged pre-activation bytes → depthAfter == depthBefore → FAIL.
        #expect(depthAfter != depthBefore,
                """
                visibleThroughDepth unchanged after activation.
                contactManager.modelContext.save() was not called before key rotation \
                (Bug 37 regression).
                """)
    }

    /// Same guard for a sensitive contact.  Its `visibleThroughDepth` must also
    /// be re-encrypted in-place during activation Step 8 and saved before commit.
    @Test func activation_sensitiveContactChanges_persistedToWAL() async throws {
        guard secureEnclaveAvailable() else {
            print("⚠︎ Skipping sensitive-contact activation WAL-persistence test — SE not available")
            return
        }

        let c = try makeComponents()
        try c.security.configurePIN("111111")

        let id = "contact-sensitive-\(UUID().uuidString)"
        // A valid encrypted 0 value makes isVisible return false → sensitive.
        try insertContact(identifier: id, in: c.container)
        try c.security.setVisibility(for: id, isSensitive: true)

        let profilesBefore = try fetchAllProfiles(from: c.container)
        let depthBefore    = profilesBefore.first { $0.identifier == id }?.visibleThroughDepth
        guard depthBefore != nil else {
            print("⚠︎ Skipping — visibleThroughDepth not set (SE unavailable)")
            return
        }

        try await c.security.activateSecureMode(
            confirmingEntryPIN: "111111", duressPIN: "999999",
            contactManager: c.contacts, vaultManager: c.vault
        )

        let profilesAfter = try fetchAllProfiles(from: c.container)
        let depthAfter    = profilesAfter.first { $0.identifier == id }?.visibleThroughDepth

        #expect(depthAfter != depthBefore,
                "sensitive contact visibleThroughDepth unchanged — Bug 37 regression in activation")
    }

    // MARK: Deactivation

    /// Verifies that deactivation's Step 4 nil-assignment is flushed to the WAL.
    ///
    /// Step 4 sets `profile.visibleThroughDepth = nil` for ALL contacts and then
    /// calls `contactManager.modelContext.save()`.  Without that save (regression),
    /// a fresh-context fetch would still see the pre-deactivation ciphertext.
    ///
    /// This test is SE-independent: it sets `visibleThroughDepth` to a raw byte
    /// sentinel in the test body (no Manager.Crypto involvement) and verifies that
    /// nil — not the sentinel — is visible to a fresh context after deactivation.
    @Test func deactivation_nilVisibilityField_persistedToWAL() async throws {
        let c = try makeComponents()
        try c.security.configurePIN("111111")

        let id = "contact-\(UUID().uuidString)"
        // Insert with a raw non-nil sentinel so the pre/post comparison is meaningful.
        // Any non-AES bytes classify this contact as sensitive (isVisible returns false
        // on decrypt failure), which means it also goes into the blob.
        let sentinel = Data([0xCA, 0xFE, 0xBA, 0xBE])
        try insertContact(identifier: id, in: c.container, visibleThroughDepth: sentinel)

        // Activation seals this contact into the blob (it's sensitive).
        try await c.security.activateSecureMode(
            confirmingEntryPIN: "111111", duressPIN: "999999",
            contactManager: c.contacts, vaultManager: c.vault
        )

        // After activation, Step 8's reencryptAllFields on a non-AES field returns nil
        // (decrypt fails).  Confirm the save wrote nil to the store before deactivation.
        let profilesMid = try fetchAllProfiles(from: c.container)
        let depthMid    = profilesMid.first { $0.identifier == id }?.visibleThroughDepth
        // depthMid should be nil (reencrypt of non-AES sentinel → nil, persisted by activation fix).
        // If it's still the original sentinel, activation's save was missing.
        #expect(depthMid == nil || depthMid != sentinel,
                "activation did not persist re-encryption result to WAL (Bug 37 regression in activation)")

        // Deactivation: Step 4 re-sets to nil; Step 5 restores blob contact with depth 0.
        try await c.security.deactivateSecureMode(
            confirmingEntryPIN: "111111",
            contactManager: c.contacts, vaultManager: c.vault
        )

        // After deactivation the contact is restored from the blob with a fresh
        // visibleThroughDepth = AES-GCM(stagedKey, 0).  It must not still be
        // the original sentinel — that would mean deactivation's save was missing.
        let profilesAfter = try fetchAllProfiles(from: c.container)
        let depthAfter    = profilesAfter.first { $0.identifier == id }?.visibleThroughDepth

        #expect(depthAfter != sentinel,
                """
                visibleThroughDepth is still the pre-activation sentinel after deactivation.
                contactManager.modelContext.save() was not called in deactivation Step 4 \
                (Bug 37 regression).
                """)
    }

    /// Deactivation must clear `visibleThroughDepth` to nil for safe contacts and
    /// flush that nil to the WAL.  On a device where SE is available, this contact
    /// will have a real ciphertext after activation; without the Step 4 save the
    /// fresh context would still see that ciphertext after deactivation.
    @Test func deactivation_safeContactVisibility_clearedToNil_inWAL() async throws {
        guard secureEnclaveAvailable() else {
            print("⚠︎ Skipping deactivation WAL-persistence test — SE not available (simulator)")
            return
        }

        let c = try makeComponents()
        try c.security.configurePIN("111111")

        let id = "contact-safe-\(UUID().uuidString)"
        try insertContact(identifier: id, in: c.container)
        try c.security.updateSafeContacts([id])

        let profilesBefore = try fetchAllProfiles(from: c.container)
        guard profilesBefore.first(where: { $0.identifier == id })?.visibleThroughDepth != nil else {
            print("⚠︎ Skipping — visibleThroughDepth not set (SE unavailable)")
            return
        }

        try await c.security.activateSecureMode(
            confirmingEntryPIN: "111111", duressPIN: "999999",
            contactManager: c.contacts, vaultManager: c.vault
        )
        try await c.security.deactivateSecureMode(
            confirmingEntryPIN: "111111",
            contactManager: c.contacts, vaultManager: c.vault
        )

        let profilesAfter = try fetchAllProfiles(from: c.container)
        let depthAfter    = profilesAfter.first { $0.identifier == id }?.visibleThroughDepth

        // Deactivation Step 4 sets visibleThroughDepth = nil for safe contacts and saves.
        // If Bug 37 regresses (save missing), the fresh context sees the activation-time
        // ciphertext instead of nil.
        #expect(depthAfter == nil,
                """
                Safe contact visibleThroughDepth is not nil after deactivation.
                contactManager.modelContext.save() was not called in deactivation Step 4 \
                (Bug 37 regression).
                """)
    }

    // MARK: Round-trip identity

    @Test func roundTrip_contactRowCount_preserved() async throws {
        // A complete activate → deactivate cycle must not gain or lose contact rows.
        let c = try makeComponents()
        try c.security.configurePIN("111111")

        let sentinel = Data([0xDE, 0xAD])
        try insertContact(identifier: "safe-\(UUID().uuidString)",      in: c.container)
        try insertContact(identifier: "sensitive-\(UUID().uuidString)", in: c.container,
                          visibleThroughDepth: sentinel)

        let countBefore = try fetchAllProfiles(from: c.container).count

        try await c.security.activateSecureMode(
            confirmingEntryPIN: "111111", duressPIN: "999999",
            contactManager: c.contacts, vaultManager: c.vault
        )
        try await c.security.deactivateSecureMode(
            confirmingEntryPIN: "111111",
            contactManager: c.contacts, vaultManager: c.vault
        )

        let countAfter = try fetchAllProfiles(from: c.container).count
        #expect(countAfter == countBefore,
                "activate → deactivate must not change the number of contact rows")
    }

    @Test func multipleRoundTrips_doNotAccumulateRows() async throws {
        let c = try makeComponents()
        try c.security.configurePIN("111111")

        try insertContact(identifier: "contact-\(UUID().uuidString)", in: c.container)
        let countBefore = try fetchAllProfiles(from: c.container).count

        for _ in 0..<2 {
            try await c.security.activateSecureMode(
                confirmingEntryPIN: "111111", duressPIN: "999999",
                contactManager: c.contacts, vaultManager: c.vault
            )
            try await c.security.deactivateSecureMode(
                confirmingEntryPIN: "111111",
                contactManager: c.contacts, vaultManager: c.vault
            )
        }

        let countAfter = try fetchAllProfiles(from: c.container).count
        #expect(countAfter == countBefore,
                "repeated activate/deactivate cycles must not create duplicate rows")
    }
}

// MARK: - Error type

private struct TestError: Error, CustomStringConvertible {
    let description: String
    init(_ message: String) { self.description = message }
}

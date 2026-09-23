//
//  PEKTrusteeRotationTests.swift
//  OccultaTests
//
//  Bug 124 — a trustee removed from the current distribution kept a permanently-valid
//  credential, since neither the shared secret nor the id tagging its shards ever
//  changed on an ordinary trustee-set mutation. For PEK, unlike BEK, `entryID` (=
//  `VaultEntry.id`) never changes between rounds — there is no second id to isolate a
//  stale round the way `restoreBackup`'s grouping-by-`entryID` does for BEK.
//  The fix instead regenerates the PEK value itself on every `prepareShards` call
//  (`rotatePEK(for:vaultKey:)`, `Vault+Manager+Shards.swift`) and re-seals the entry's
//  label/content under it, so a stale round's shares reconstruct a PEK that no longer
//  opens anything.
//
//  No Secure Enclave needed — `prepareShards`/`reconstructEntry`/`rotatePEK` only touch
//  the vault key (derived via the injected `TestKeyManager`) and `SecRandomCopyBytes`,
//  never the ambient `Manager.Key()` path `BackupTrusteeRotationTests` has to gate around.
//

import Testing
import CryptoKit
import SwiftData
import Foundation
import LocalAuthentication
@testable import Occulta

// MARK: - Helpers

@MainActor
private func makeVaultManager() throws -> (VaultManager, TestKeyManager) {
    let km        = TestKeyManager()
    let schema    = Schema([VaultEntry.self])
    let config    = ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)
    let container = try ModelContainer(for: schema, configurations: [config])
    let vm        = VaultManager(modelContainer: container, keyManager: km)
    return (vm, km)
}

/// Recipients only need a stable `identifier` — built in their own throwaway container,
/// mirroring `VaultTests.swift`'s own `makeProfiles(count:)` exactly.
@MainActor
private func makeProfiles(count: Int) throws -> [Contact.Profile] {
    let schema = Schema([
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
    ])
    let config    = ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)
    let container = try ModelContainer(for: schema, configurations: [config])
    let ctx       = ModelContext(container)

    return (0..<count).map { i in
        let p = Contact.Profile(
            identifier: "trustee-\(i)",
            givenName: "Trustee", familyName: "\(i)",
            middleName: "", nickname: "",
            organizationName: "", departmentName: "", jobTitle: ""
        )
        ctx.insert(p)
        return p
    }
}

@Suite("Per-entry key distribution — trustee-set mutation (Bug 124, PEK)")
@MainActor
struct PEKTrusteeRotationTests {

    /// **The load-bearing test.** Without `rotatePEK`, both rounds split the entry's one,
    /// never-changing PEK — a stale round's shares reconstruct the exact key that still
    /// opens `entry.encryptedContent`, since content is never re-sealed either. With the
    /// fix, redistributing re-seals content under a fresh PEK, so an old round's shares
    /// reconstruct a PEK that no longer opens anything. Confirmed by tracing both paths
    /// directly, not just by this test passing.
    @Test("A stale round's shares no longer reconstruct the entry's PEK after redistribution")
    func redistributionInvalidatesStalePEKShares() throws {
        let (vm, _)    = try makeVaultManager()
        vm.unlock(context: LAContext())
        let entry      = try vm.addEntry(label: "seed", content: Data("first-secret".utf8), type: .seedPhrase)
        let recipients = try makeProfiles(count: 2)

        // Round 1: Bob and Marla.
        let round1 = try vm.prepareShards(for: entry.id, threshold: 2, recipients: recipients)

        // Round 2: redistribute — rotatePEK mints a fresh PEK and re-seals content under it.
        let round2 = try vm.prepareShards(for: entry.id, threshold: 2, recipients: recipients)

        #expect(Set(round1.map(\.value)).isDisjoint(with: Set(round2.map(\.value))), """
            Two rounds splitting genuinely different PEKs must never coincide on a shard value.
            """)

        #expect(throws: VaultManager.VaultError.decryptionFailed) {
            try vm.reconstructEntry(entryID: entry.id, shards: round1, ownerIdentity: nil)
        }
    }

    /// The one thing the fix could plausibly have broken: that a legitimate restore,
    /// using only the current round's shares, still works after a redistribution.
    @Test("A clean restore using the current round's shares still succeeds after redistribution")
    func cleanRestoreStillSucceedsAfterRedistribution() throws {
        let (vm, km)   = try makeVaultManager()
        vm.unlock(context: LAContext())
        let secret     = Data("top-secret".utf8)
        let entry      = try vm.addEntry(label: "seed", content: secret, type: .seedPhrase)
        let recipients = try makeProfiles(count: 2)

        _ = try vm.prepareShards(for: entry.id, threshold: 2, recipients: recipients) // round 1
        let round2 = try vm.prepareShards(for: entry.id, threshold: 2, recipients: recipients) // round 2

        try vm.reconstructEntry(
            entryID: entry.id, shards: round2, ownerIdentity: try km.retrieveIdentity()
        )

        #expect(try vm.decryptContent(for: entry) == secret)
    }
}

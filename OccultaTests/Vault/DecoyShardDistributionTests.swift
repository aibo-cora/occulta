//
//  DecoyShardDistributionTests.swift
//  OccultaTests
//
//  Verifies shard distribution works end-to-end at a duress depth: a decoy vault
//  entry, a duress-depth trustee (Contact.Profile.globalTrusteeDepth, item 3), and
//  the real prepareShards/queueDistribute chain Vault+ShardSetup.swift runs on save —
//  confirms no depth-0 assumption blocks any of it. See
//  Docs/Bugs/v1.10.0/Shard-Custody-Not-Cleaned-Up-On-Contact-Deletion.md,
//  "Duress signaling for shard custody", item 2.
//

import Testing
import CryptoKit
import SwiftData
import Foundation
import LocalAuthentication
@testable import Occulta

// MARK: - Helpers

@MainActor
private func makeRig() throws -> (
    vault:     VaultManager,
    contacts:  ContactManager,
    custody:   ShardCustodyManager,
    security:  Manager.Security,
    container: ModelContainer
) {
    let km     = TestKeyManager()
    let schema = Schema([
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
        VaultEntry.self,
        BackupEncryptionKey.self,
        Vault.self,
        PendingShamirSecretRestore.self,
        CustodyShard.self,
        ReconstructShard.self,
        PendingShardDistribute.self,
        PendingShardStatusUpdate.self,
        PotentiallyLostShard.self,
        GlobalShardConfig.self,
        AppLayerConfig.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    let security  = try Manager.Security(modelContainer: container, keyManager: km)
    let contacts  = ContactManager(modelContainer: container, security: security)
    let vault     = VaultManager(modelContainer: container, keyManager: km)
    let custody   = ShardCustodyManager(modelContainer: container, keyManager: km)
    return (vault, contacts, custody, security, container)
}

@discardableResult
@MainActor
private func insertPlainProfile(identifier: String, in cm: ContactManager) throws -> Contact.Profile {
    let profile = Contact.Profile(
        identifier: identifier, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    try cm.insertProfile(profile)
    return profile
}

// MARK: - Tests

@MainActor
@Suite("Backup-key distribution at a duress depth", .serialized, .ambientTestKeyManager)
struct DecoyShardDistributionTests {

    /// Per-entry splitting was retired (decisions.md, "Retire per-entry splitting"); the
    /// duress-depth chain this pins is now the backup key's.
    @Test func duressTrustees_distributeBackup_worksAtDuressDepth() throws {
        let (vault, contacts, custody, security, container) = try makeRig()

        // Move to a duress depth — mirrors what a real coercion session looks like.
        security.applyVerifyState(for: .duress)
        #expect(security.currentDepth == 1)

        // Two decoy trustees — not real, pre-existing relationships, just what a coerced
        // setup would produce. Identifiers in the form the app stores (bugs.md Bug 145).
        let trustee1 = try insertPlainProfile(identifier: realFormatContactIdentifier(), in: contacts)
        let trustee2 = try insertPlainProfile(identifier: realFormatContactIdentifier(), in: contacts)

        // The chain Vault+ShardSetup.swift runs on save, at this depth.
        vault.unlock(context: LAContext())
        try vault.setupBackup(currentDepth: security.currentDepth)
        try custody.distributeBackup(
            threshold: 2, recipients: [trustee1.identifier, trustee2.identifier],
            currentDepth: security.currentDepth, vaultManager: vault
        )

        let queued = try ModelContext(container).fetch(FetchDescriptor<PendingShardDistribute>())
        #expect(queued.count == 2,
                "distributeBackup must succeed at a duress depth — no depth-0 assumption should block this chain")
    }
}

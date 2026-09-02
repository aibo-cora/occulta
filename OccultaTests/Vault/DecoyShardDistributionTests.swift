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

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

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
@Suite("Decoy vault entry shard distribution at a duress depth", .serialized)
struct DecoyShardDistributionTests {

    @Test func decoyEntry_duressTrustees_prepareShardsAndQueueDistribute_worksAtDuressDepth() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }

        let (vault, contacts, custody, security, container) = try makeRig()

        // Move to a duress depth — mirrors what a real coercion session looks like.
        security.applyVerifyState(for: .duress)
        #expect(security.currentDepth == 1)

        // Two decoy trustees, marked as global trustees at exactly this depth (item 3) —
        // not real, pre-existing relationships, just what a coerced setup would produce.
        let trustee1 = try insertPlainProfile(identifier: "trustee-1", in: contacts)
        let trustee2 = try insertPlainProfile(identifier: "trustee-2", in: contacts)
        try contacts.saveGlobalTrusteeDepth(selectedIDs: [trustee1.identifier, trustee2.identifier])
        #expect(contacts.isGlobalTrustee(trustee1.identifier))
        #expect(contacts.isGlobalTrustee(trustee2.identifier))

        // A decoy vault entry, stamped visible only at this exact duress depth.
        vault.unlock(context: LAContext(), currentDepth: 0)
        let entry = try vault.addEntry(
            label: "decoy note", content: Data("decoy".utf8), type: .note,
            currentDepth: security.currentDepth
        )

        // The real distribution chain Vault+ShardSetup.swift runs on save — no
        // depth parameter anywhere in this path, so nothing to route around.
        let attributes = try vault.prepareShards(for: entry.id, threshold: 2, recipients: [trustee1, trustee2])
        #expect(attributes.count == 2)
        for (contact, attribute) in zip([trustee1, trustee2], attributes) {
            try custody.queueDistribute(attribute: attribute, for: contact.identifier)
        }

        let queued = try ModelContext(container).fetch(FetchDescriptor<PendingShardDistribute>())
        #expect(queued.count == 2,
                "prepareShards/queueDistribute must succeed at a duress depth — no depth-0 assumption should block this chain")
    }
}

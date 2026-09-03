//
//  BEKTrusteeCapTests.swift
//  OccultaTests
//
//  VAULT_KEY_LAYERING.md §8 item 3 — shardMetadata is sealed inside the BEK record
//  in the per-depth vault-key-gated slot, so its size must be padded to a fixed
//  maximum trustee count rather than left to grow with the owner's selection.
//  prepareBEKShards guards recipients.count against VaultManager.maxBEKTrustees
//  before any I/O.
//

import Testing
import Foundation
import LocalAuthentication
import SwiftData
@testable import Occulta

@MainActor
private func makeUnlockedVault() throws -> (VaultManager, ModelContainer) {
    let schema = Schema([
        VaultEntry.self,
        BackupEncryptionKey.self,
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
    ])
    let container = try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
    let vault = VaultManager(modelContainer: container, keyManager: TestKeyManager())
    vault.unlock(context: LAContext(), currentDepth: 0)
    try vault.setupBEK()
    return (vault, container)
}

@MainActor
private func makeTrustees(_ count: Int, in container: ModelContainer) throws -> [Contact.Profile] {
    let contacts = (0..<count).map { i -> Contact.Profile in
        Contact.Profile(
            identifier: "trustee-\(i)", givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
    }
    for contact in contacts { container.mainContext.insert(contact) }
    try container.mainContext.save()
    return contacts
}

@Suite("VAULT_KEY_LAYERING §8 item 3 — BEK trustee cap")
@MainActor
struct BEKTrusteeCapTests {

    @Test("Exactly maxBEKTrustees recipients succeeds")
    func atCapSucceeds() throws {
        let (vault, container) = try makeUnlockedVault()
        let trustees = try makeTrustees(VaultManager.maxBEKTrustees, in: container)

        let attributes = try vault.prepareBEKShards(threshold: 2, recipients: trustees)
        #expect(attributes.count == VaultManager.maxBEKTrustees)
    }

    @Test("One more than maxBEKTrustees throws tooManyTrustees before any I/O")
    func overCapThrows() throws {
        let (vault, container) = try makeUnlockedVault()
        let trustees = try makeTrustees(VaultManager.maxBEKTrustees + 1, in: container)

        #expect(throws: VaultManager.BackupError.tooManyTrustees) {
            try vault.prepareBEKShards(threshold: 2, recipients: trustees)
        }
    }
}

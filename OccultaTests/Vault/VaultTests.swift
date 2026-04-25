//
//  VaultTests.swift
//  OccultaTests
//
//  Simulator-safe — uses TestKeyManager (in-memory P-256, no SE).
//
//  Coverage:
//  - Phase 3: deriveVaultKey determinism, distinction from other key paths.
//  - Phase 4: VaultManager unlock/lock/CRUD, AAD binding, locked-state errors.
//  - Phase 6: prepareShards signing, shard verification, metadata persistence.
//  - Security: lock-on-derivation-failure, inactivity timeout.
//

import Testing
import CryptoKit
import SwiftData
import Foundation
import LocalAuthentication
@testable import Occulta

// MARK: - Helpers

@MainActor
private func makeVaultManager(
    inactivityTimeout: TimeInterval = 5 * 60
) throws -> (VaultManager, TestKeyManager) {
    let km        = TestKeyManager()
    let schema    = Schema([VaultEntry.self])
    let config    = ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)
    let container = try ModelContainer(for: schema, configurations: [config])
    let vm        = VaultManager(modelContainer: container, keyManager: km, inactivityTimeout: inactivityTimeout)
    return (vm, km)
}

// MARK: - Phase 3: deriveVaultKey

@Suite("Phase 3 — vault key derivation")
@MainActor struct VaultKeyDerivationTests {

    @Test("deriveVaultKey() returns a 256-bit key")
    func derivedKeyIs256Bits() throws {
        let km  = TestKeyManager()
        let key = try km.deriveVaultKey(context: LAContext())
        #expect(key != nil)
        var byteCount = 0
        key?.withUnsafeBytes { byteCount = $0.count }
        #expect(byteCount == 32)
    }

    @Test("deriveVaultKey() is deterministic — same key manager yields same key")
    func deterministicDerivation() throws {
        let km = TestKeyManager()
        var b1 = Data(), b2 = Data()
        try km.deriveVaultKey(context: LAContext())?.withUnsafeBytes { b1 = Data($0) }
        try km.deriveVaultKey(context: LAContext())?.withUnsafeBytes { b2 = Data($0) }
        #expect(b1 == b2)
    }

    @Test("deriveVaultKey() differs from transport key (domain separation)")
    func vaultKeyDistinctFromTransportKey() throws {
        let km = TestKeyManager()
        guard
            let vaultKey     = try km.deriveVaultKey(context: LAContext()),
            let transportKey = km.createSharedSecret(using: try km.retrieveIdentity())
        else { return }

        var vb = Data(), tb = Data()
        vaultKey.withUnsafeBytes     { vb = Data($0) }
        transportKey.withUnsafeBytes { tb = Data($0) }
        #expect(vb != tb, "vault key must differ from transport key derived from same identity")
    }

    @Test("Two distinct TestKeyManagers produce different vault keys")
    func differentKeyManagersDifferentKeys() throws {
        let km1 = TestKeyManager()
        let km2 = TestKeyManager()

        var b1 = Data(), b2 = Data()
        try km1.deriveVaultKey(context: LAContext())?.withUnsafeBytes { b1 = Data($0) }
        try km2.deriveVaultKey(context: LAContext())?.withUnsafeBytes { b2 = Data($0) }
        #expect(b1 != b2)
    }
}

// MARK: - Phase 4: VaultManager lifecycle

@Suite("Phase 4 — VaultManager lifecycle")
@MainActor struct VaultManagerLifecycleTests {

    @Test("unlock() sets isUnlocked = true")
    func unlockSetsFlag() throws {
        let (vm, _) = try makeVaultManager()
        #expect(vm.isUnlocked == false)
        vm.unlock(context: LAContext())
        #expect(vm.isUnlocked == true)
    }

    @Test("lock() sets isUnlocked = false")
    func lockClearsFlag() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())
        vm.lock()
        #expect(vm.isUnlocked == false)
    }

    @Test("lock() is idempotent — safe to call when already locked")
    func lockIdempotent() throws {
        let (vm, _) = try makeVaultManager()
        vm.lock()
        vm.lock()
        #expect(vm.isUnlocked == false)
    }

    @Test("Vault locks automatically when key derivation fails (lock condition 5)")
    func locksOnDerivationFailure() throws {
        let (vm, km) = try makeVaultManager()
        vm.unlock(context: LAContext())
        let entry = try vm.addEntry(label: "test", content: Data(), type: .note)

        km.simulateVaultKeyFailure = true

        #expect(throws: VaultManager.VaultError.locked) {
            _ = try vm.decryptContent(for: entry)
        }
        #expect(vm.isUnlocked == false, "vault must auto-lock on derivation failure")
    }

    @Test("Vault locks after inactivity timeout (lock condition 4)")
    func locksAfterInactivity() async throws {
        let (vm, _) = try makeVaultManager(inactivityTimeout: 0.05)
        vm.unlock(context: LAContext())
        #expect(vm.isUnlocked == true)

        try await Task.sleep(for: .milliseconds(150))
        #expect(vm.isUnlocked == false, "vault must auto-lock after inactivity timeout")
    }
}

// MARK: - Phase 4: CRUD

@Suite("Phase 4 — VaultManager CRUD")
@MainActor struct VaultManagerCRUDTests {

    @Test("addEntry then decryptLabel round-trips the label")
    func addAndDecryptLabel() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())

        let entry = try vm.addEntry(label: "My Seed Phrase", content: Data("secret".utf8), type: .seedPhrase)
        let label = try vm.decryptLabel(for: entry)
        #expect(label == "My Seed Phrase")
    }

    @Test("addEntry then decryptContent round-trips the content")
    func addAndDecryptContent() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())

        let content   = Data("hunter2".utf8)
        let entry     = try vm.addEntry(label: "Password", content: content, type: .keyToken)
        let decrypted = try vm.decryptContent(for: entry)
        #expect(decrypted == content)
    }

    @Test("encryptedLabel stored in SwiftData is not plaintext")
    func labelIsNotPlaintext() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())

        let plainLabel = "Secret seed phrase"
        let entry      = try vm.addEntry(label: plainLabel, content: Data(), type: .seedPhrase)

        let labelData = plainLabel.data(using: .utf8)!
        let contains  = entry.encryptedLabel.range(of: labelData) != nil
        #expect(!contains, "plaintext label must not appear in stored ciphertext")
    }

    @Test("decryptLabel throws .locked when vault is not unlocked")
    func decryptLabelRequiresUnlock() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())
        let entry = try vm.addEntry(label: "test", content: Data(), type: .note)
        vm.lock()

        #expect(throws: VaultManager.VaultError.locked) {
            _ = try vm.decryptLabel(for: entry)
        }
    }

    @Test("decryptContent throws .locked when vault is not unlocked")
    func decryptContentRequiresUnlock() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())
        let entry = try vm.addEntry(label: "test", content: Data("secret".utf8), type: .note)
        vm.lock()

        #expect(throws: VaultManager.VaultError.locked) {
            _ = try vm.decryptContent(for: entry)
        }
    }

    @Test("addEntry throws .locked when vault is not unlocked")
    func addEntryRequiresUnlock() throws {
        let (vm, _) = try makeVaultManager()
        #expect(throws: VaultManager.VaultError.locked) {
            _ = try vm.addEntry(label: "test", content: Data(), type: .note)
        }
    }

    @Test("AAD binding — tampered entryType causes decryption failure")
    func aadBindsEntryType() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())

        let entry = try vm.addEntry(label: "test", content: Data("x".utf8), type: .note)

        // Tamper the stored entryType after encryption — AAD will no longer match.
        entry.entryType = Int(VaultEntryType.seedPhrase.rawValue)

        #expect(throws: VaultManager.VaultError.decryptionFailed) {
            _ = try vm.decryptContent(for: entry)
        }
    }

    @Test("fetchAllEntries returns inserted entries")
    func fetchAll() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())

        _ = try vm.addEntry(label: "A", content: Data(), type: .note)
        _ = try vm.addEntry(label: "B", content: Data(), type: .keyToken)

        let entries = try vm.fetchAllEntries()
        #expect(entries.count == 2)
    }

    @Test("deleteEntry removes the entry")
    func deleteEntry() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())

        let entry = try vm.addEntry(label: "to delete", content: Data(), type: .note)
        try vm.deleteEntry(id: entry.id)

        let entries = try vm.fetchAllEntries()
        #expect(entries.isEmpty)
    }

    @Test("deleteEntry throws .entryNotFound for unknown UUID")
    func deleteNonExistent() throws {
        let (vm, _) = try makeVaultManager()
        #expect(throws: VaultManager.VaultError.entryNotFound) {
            try vm.deleteEntry(id: UUID())
        }
    }
}

// MARK: - Phase 6: prepareShards

@Suite("Phase 6 — prepareShards")
@MainActor struct PrepareSharedsTests {

    private func makeProfiles(count: Int) throws -> [Contact.Profile] {
        let schema = Schema([
            Contact.Profile.self,
            Contact.Profile.PhoneNumber.self,
            Contact.Profile.EmailAddress.self,
            Contact.Profile.PostalAddress.self,
            Contact.Profile.URLAddress.self,
            Contact.Profile.Key.self
        ])
        let config    = ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)
        let container = try ModelContainer(for: schema, configurations: [config])
        let ctx       = ModelContext(container)

        return (0..<count).map { i in
            let p = Contact.Profile(
                identifier: "contact-\(i)",
                givenName: "Contact", familyName: "\(i)",
                middleName: "", nickname: "",
                organizationName: "", departmentName: "", jobTitle: ""
            )
            ctx.insert(p)
            return p
        }
    }

    @Test("prepareShards returns one SignedAttribute per recipient")
    func shardCountMatchesRecipients() throws {
        let (vm, _)  = try makeVaultManager()
        vm.unlock(context: LAContext())
        let entry      = try vm.addEntry(label: "seed", content: Data("secret".utf8), type: .seedPhrase)
        let recipients = try makeProfiles(count: 3)

        let attrs = try vm.prepareShards(for: entry.id, threshold: 2, recipients: recipients)
        #expect(attrs.count == 3)
    }

    @Test("Each SignedAttribute has category .shard")
    func categoryIsShard() throws {
        let (vm, _)  = try makeVaultManager()
        vm.unlock(context: LAContext())
        let entry      = try vm.addEntry(label: "seed", content: Data(), type: .seedPhrase)
        let recipients = try makeProfiles(count: 2)

        let attrs = try vm.prepareShards(for: entry.id, threshold: 2, recipients: recipients)
        #expect(attrs.allSatisfy { $0.category == .shard })
    }

    @Test("Each shard signature verifies against our identity public key")
    func shardSignaturesVerify() throws {
        let (vm, km) = try makeVaultManager()
        vm.unlock(context: LAContext())
        let entry      = try vm.addEntry(label: "seed", content: Data(), type: .seedPhrase)
        let recipients = try makeProfiles(count: 3)

        let attrs  = try vm.prepareShards(for: entry.id, threshold: 2, recipients: recipients)
        let ourPub = try km.retrieveIdentity()

        for attr in attrs {
            #expect(attr.verify(against: ourPub), "shard \(attr.label) signature must verify")
        }
    }

    @Test("Each shard has a distinct value (different x-coordinates)")
    func shardsAreDistinct() throws {
        let (vm, _)  = try makeVaultManager()
        vm.unlock(context: LAContext())
        let entry      = try vm.addEntry(label: "seed", content: Data(), type: .seedPhrase)
        let recipients = try makeProfiles(count: 3)

        let attrs  = try vm.prepareShards(for: entry.id, threshold: 2, recipients: recipients)
        let values = attrs.map { $0.value }
        #expect(Set(values).count == values.count, "all shard values must be distinct")
    }

    @Test("prepareShards persists encrypted ShardDistributionMetadata on the entry")
    func metadataPersistedOnEntry() throws {
        let (vm, _)  = try makeVaultManager()
        vm.unlock(context: LAContext())
        let entry      = try vm.addEntry(label: "seed", content: Data(), type: .seedPhrase)
        let recipients = try makeProfiles(count: 3)

        #expect(entry.shardDistributionEncrypted == nil)
        _ = try vm.prepareShards(for: entry.id, threshold: 2, recipients: recipients)
        #expect(entry.shardDistributionEncrypted != nil)
    }

    @Test("prepareShards throws .locked when vault is not unlocked")
    func prepareShardsRequiresUnlock() throws {
        let (vm, _)  = try makeVaultManager()
        vm.unlock(context: LAContext())
        let entry      = try vm.addEntry(label: "seed", content: Data(), type: .seedPhrase)
        let recipients = try makeProfiles(count: 2)
        vm.lock()

        #expect(throws: VaultManager.VaultError.locked) {
            _ = try vm.prepareShards(for: entry.id, threshold: 2, recipients: recipients)
        }
    }

    @Test("SSS reconstruction from threshold shards recovers the entry's PEK")
    func shardsReconstructPEK() throws {
        let (vm, km) = try makeVaultManager()
        vm.unlock(context: LAContext())
        let entry      = try vm.addEntry(label: "seed", content: Data("plaintext".utf8), type: .seedPhrase)
        let recipients = try makeProfiles(count: 3)

        let attrs = try vm.prepareShards(for: entry.id, threshold: 2, recipients: recipients)

        // Extract raw shard bytes from any 2 attributes.
        let rawShares = attrs.prefix(2).map { [UInt8]($0.value) }
        let reconstituted = try ShamirSecretSharing.reconstruct(shares: rawShares)

        // Compare against the entry's actual PEK — prepareShards splits the
        // per-entry key, not the vault key.
        let vaultKey  = try km.deriveVaultKey(context: LAContext())!
        var pekBytes  = Data()
        try vm.unwrapPEK(for: entry, vaultKey: vaultKey).withUnsafeBytes { pekBytes = Data($0) }

        #expect(reconstituted == pekBytes,
                "reconstructed secret must equal the entry's PEK")
    }
}

// MARK: - Phase 3 (device-only stub)

// device-only: deriveVaultKey(context:) on Manager.Key requires the SE vault key.
// Run this test only on a physical device with the SE provisioned.
//
// func testDeriveVaultKeyOnDevice() throws {
//     let ctx = LAContext()
//     try ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Test")
//     let km  = Manager.Key()
//     let key = try km.deriveVaultKey(context: ctx)
//     XCTAssertNotNil(key)
//     var byteCount = 0
//     key?.withUnsafeBytes { byteCount = $0.count }
//     XCTAssertEqual(byteCount, 32)
// }

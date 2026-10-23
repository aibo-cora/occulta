//
//  HybridUpgradeRecordTests.swift
//  OccultaTests
//
//  Bug 171, Stage 6 through the real `Manager.Key`: the operations the upgrade is built from (a pending record, an
//  in-place replacement, a derivation in the form of a given record) and, where the machine has a Secure Enclave and
//  ML-KEM (iOS 26+), a whole upgrade of real Enclave-bound keys from classical to hybrid.
//
//  The tier secrets and records are Keychain items of the test's own (`Manager.Key(items:)`), so the Simulator's canonical
//  ones, which other tests are using, are left alone. The Enclave keys behind them are the canonical ones. The record
//  operations need no Enclave; the derivations and the upgrade are gated on it, as the CI runners (VMs) have none.
//

import Testing
import CryptoKit
import Foundation
import LocalAuthentication
import SwiftData

@testable import Occulta
@testable import OccultaCore
@testable import OccultaFormats

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

private func hybridAvailable() -> Bool {
    PostQuantumProviderFactory.create() != nil
}

/// A real key manager on Keychain items of its own.
@MainActor
private func makeItems() -> (keys: Manager.Key, items: Manager.Key.Items) {
    let suffix = UUID().uuidString
    let items = Manager.Key.Items(
        enclaveTags: [],
        tierSecretU: "test.upgrade.ru.\(suffix)", tierSecretB: "test.upgrade.rb.\(suffix)",
        recordU: "test.upgrade.pqu.\(suffix)", recordB: "test.upgrade.pqb.\(suffix)"
    )
    return (Manager.Key(items: items), items)
}

@MainActor
private func remove(_ keys: Manager.Key, _ items: Manager.Key.Items) {
    for account in [items.tierSecretU, items.tierSecretB, items.recordU, items.recordB, items.recordU + Manager.Key.pendingSuffix, items.recordB + Manager.Key.pendingSuffix] {
        _ = keys.deleteTierSecret(account: account)
    }
}

/// The creation date of the generic-password item `account`.
private func creationDate(of account: String) -> Date? {
    var item: CFTypeRef?
    let status = SecItemCopyMatching([
        kSecClass as String:            kSecClassGenericPassword,
        kSecAttrAccount as String:      account,
        kSecReturnAttributes as String: true
    ] as CFDictionary, &item)
    guard status == errSecSuccess, let dict = item as? [String: Any] else { return nil }
    return dict[kSecAttrCreationDate as String] as? Date
}

@Suite("Hybrid upgrade — record operations on the real key manager", .serialized)
@MainActor
struct HybridUpgradeRecordOperationTests {

    @Test("A pending record is stored beside the tier's own, read back, never replaced by a second add, and deleted")
    func pendingRecord() throws {
        let (keys, items) = makeItems()
        defer { remove(keys, items) }
        let provider = try #require(PostQuantumProviderFactory.createForTesting())

        let first  = try #require(try keys.makeHybridPQRecord(provider: provider))
        let second = try #require(try keys.makeHybridPQRecord(provider: provider))
        #expect(first != second, "a fresh ML-KEM key each time")
        #expect(first.mode == .hybrid)

        for tier in [PostQuantumTier.deviceUnlock, .vault] {
            #expect(try keys.pendingTierPQRecord(tier) == nil)
            #expect(try keys.addPendingTierPQRecord(first, tier: tier))
            #expect(try keys.pendingTierPQRecord(tier) == first)

            #expect(try keys.addPendingTierPQRecord(second, tier: tier) == false, "a second add leaves the first")
            #expect(try keys.pendingTierPQRecord(tier) == first)

            #expect(keys.deletePendingTierPQRecord(tier))
            #expect(try keys.pendingTierPQRecord(tier) == nil)
            #expect(keys.deletePendingTierPQRecord(tier), "a missing one counts as deleted")
        }
    }

    @Test("A pending record is the same size as the tier's own, whichever mode, and is a separate item")
    func pendingRecordSize() throws {
        let (keys, items) = makeItems()
        defer { remove(keys, items) }
        let provider = try #require(PostQuantumProviderFactory.createForTesting())

        try keys.createTierPQRecordIfAbsent(account: items.recordU, provider: nil)
        let hybrid = try #require(try keys.makeHybridPQRecord(provider: provider))
        try keys.addPendingTierPQRecord(hybrid, tier: .deviceUnlock)

        func size(of account: String) -> Int? {
            var item: CFTypeRef?
            guard SecItemCopyMatching([kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: account, kSecReturnData as String: true] as CFDictionary, &item) == errSecSuccess else { return nil }
            return (item as? Data)?.count
        }
        #expect(size(of: items.recordU) == TierPQRecord.size)
        #expect(size(of: items.recordU + Manager.Key.pendingSuffix) == TierPQRecord.size)
        #expect(try keys.tierPQRecord(.deviceUnlock)?.mode == .classical, "the tier's own record is untouched")
    }

    @Test("Replacing the tier's record changes its data in place: same item, same creation date, and it never creates one")
    func replaceInPlace() throws {
        let (keys, items) = makeItems()
        defer { remove(keys, items) }
        let provider = try #require(PostQuantumProviderFactory.createForTesting())

        #expect(throws: (any Error).self) { try keys.replaceTierPQRecord(.deviceUnlock, with: .classical) }
        #expect(try keys.tierPQRecord(.deviceUnlock) == nil, "nothing was created")

        try keys.createTierPQRecordIfAbsent(account: items.recordU, provider: nil)
        let created = try #require(creationDate(of: items.recordU))
        let hybrid  = try #require(try keys.makeHybridPQRecord(provider: provider))

        try keys.replaceTierPQRecord(.deviceUnlock, with: hybrid)

        #expect(try keys.tierPQRecord(.deviceUnlock) == hybrid)
        #expect(creationDate(of: items.recordU) == created, "the item keeps its creation date: nothing new is dated")
    }

    @Test("No provider, no hybrid record")
    func noProvider() throws {
        let (keys, items) = makeItems()
        defer { remove(keys, items) }

        #expect(try keys.makeHybridPQRecord(provider: nil) == nil)
    }

    @Test("Erase All Data removes a pending record an interrupted upgrade left")
    func eraseRemovesPending() throws {
        let (keys, items) = makeItems()
        defer { remove(keys, items) }
        let provider = try #require(PostQuantumProviderFactory.createForTesting())

        let hybrid = try #require(try keys.makeHybridPQRecord(provider: provider))
        try keys.addPendingTierPQRecord(hybrid, tier: .deviceUnlock)
        try keys.addPendingTierPQRecord(hybrid, tier: .vault)

        _ = keys.deleteAllKeys()

        #expect(try keys.pendingTierPQRecord(.deviceUnlock) == nil)
        #expect(try keys.pendingTierPQRecord(.vault) == nil)
    }
}

@Suite("Hybrid upgrade — real Enclave", .serialized)
@MainActor
struct HybridUpgradeEnclaveTests {

    private static func bound<R>(_ keys: Manager.Key, _ body: () throws -> R) throws -> R {
        try Manager.Ambient.$override.withValue(Manager.Ambient.Override(keys)) { try body() }
    }

    @Test("A derivation in the form of a given record: the classical key from .classical equals the one the stored classical record gives, and the stored hybrid record changes nothing about it",
          .enabled(if: secureEnclaveAvailable() && hybridAvailable()))
    func derivationInTheFormOfARecord() throws {
        let (keys, items) = makeItems()
        defer { remove(keys, items) }
        try keys.createTierSecretIfAbsent(.deviceUnlock)
        try keys.createTierPQRecordIfAbsent(account: items.recordU, provider: nil)

        let classical = try #require(try keys.enclaveBoundKey(.localDB))
        let hybrid = try #require(try keys.makeHybridPQRecord())

        // Derived before the hybrid record is anything of the tier's: from the record itself.
        let fromRecord = try #require(try keys.enclaveBoundKey(.localDB, record: hybrid))
        #expect(keyBytes(fromRecord) != keyBytes(classical))
        #expect(keyBytes(try #require(try keys.enclaveBoundKey(.localDB, record: .classical))) == keyBytes(classical))

        // Once it is the tier's own, the stored record gives the same hybrid key, and .classical still gives the classical one.
        try keys.replaceTierPQRecord(.deviceUnlock, with: hybrid)
        #expect(keyBytes(try #require(try keys.enclaveBoundKey(.localDB))) == keyBytes(fromRecord))
        #expect(keyBytes(try #require(try keys.enclaveBoundKey(.localDB, record: .classical))) == keyBytes(classical))
    }

    @Test("The compose staging key on the real key manager: tier U's key, distinct from the others, and none in a legacy state",
          .enabled(if: secureEnclaveAvailable() && hybridAvailable()))
    func composeKey() throws {
        let (keys, items) = makeItems()
        defer { remove(keys, items) }
        try keys.createTierSecretIfAbsent(.deviceUnlock)
        try keys.createTierPQRecordIfAbsent(account: items.recordU, provider: nil)

        try Self.bound(keys) {
            let classical = try #require(try keys.enclaveBoundKey(.composeStaging))
            let local     = try #require(try keys.enclaveBoundKey(.localDB))
            let custody   = try #require(try keys.enclaveBoundKey(.shardCustody))
            #expect(classical.bitCount == 256)
            #expect(keyBytes(classical) != keyBytes(local) && keyBytes(classical) != keyBytes(custody))
            #expect(keyBytes(try #require(try keys.enclaveBoundKey(.composeStaging))) == keyBytes(classical), "stable")

            // The accessor follows tier U's process state.
            Manager.Ambient.setTierUKeys(.legacy)
            #expect(try keys.deriveComposeStagingKey() == nil)
            Manager.Ambient.setTierUKeys(.enclaveBound)
            #expect(keyBytes(try #require(try keys.deriveComposeStagingKey())) == keyBytes(classical))

            // The hybrid form, from a record that is not yet the tier's own, differs from the classical one.
            let hybridRecord = try #require(try keys.makeHybridPQRecord())
            let hybrid = try #require(try keys.enclaveBoundKey(.composeStaging, record: hybridRecord))
            #expect(keyBytes(hybrid) != keyBytes(classical))
            #expect(keyBytes(try #require(try keys.enclaveBoundKey(.composeStaging, record: .classical))) == keyBytes(classical))

            try keys.replaceTierPQRecord(.deviceUnlock, with: hybridRecord)
            #expect(keyBytes(try #require(try keys.deriveComposeStagingKey())) == keyBytes(hybrid))
        }
    }

    @Test("A whole upgrade of real Enclave-bound keys from classical to hybrid: every value moves and opens, the epoch is hybrid, the record is the real ML-KEM one, and nothing is left pending",
          .enabled(if: secureEnclaveAvailable() && hybridAvailable()))
    func realUpgrade() async throws {
        let (keys, items) = makeItems()
        defer { remove(keys, items) }
        try keys.createTierSecretIfAbsent(.deviceUnlock)
        try keys.createTierPQRecordIfAbsent(account: items.recordU, provider: nil)

        let container = try makeStore()
        let classicalLocal   = try #require(try keys.enclaveBoundKey(.localDB))
        let classicalCustody = try #require(try keys.enclaveBoundKey(.shardCustody))
        let classicalRestore = try #require(try keys.enclaveBoundKey(.restoreVault))

        let context = ModelContext(container)
        context.autosaveEnabled = false

        let profile = Contact.Profile(
            identifier: "", givenName: "", familyName: "", middleName: "", nickname: "",
            organizationName: "", departmentName: "", jobTitle: "", encryptionScheme: EncryptionScheme.v2_hybridPQ.rawValue
        )
        context.insert(profile)
        let name = Data("Alice".utf8)
        profile.givenName = Sealing.seal(name, key: classicalLocal, aad: Sealing.fixedAAD).base64EncodedString()

        let custodyID = UUID()
        let custodyPlain = Data("custody payload".utf8)
        let custodyRow = CustodyShard(id: custodyID, encryptedPayload: Sealing.seal(custodyPlain, key: classicalCustody, aad: Data(custodyID.uuidString.utf8)))
        context.insert(custodyRow)

        let vault = Vault()
        context.insert(vault)
        let restoreID = UUID()
        let restoreRow = PendingShamirSecretRestore(id: restoreID, vault: vault)
        context.insert(restoreRow)
        let shards = Sealing.random(PendingShamirSecretRestore.ShardsCodec.payloadSize)
        restoreRow.shards = Sealing.seal(shards, key: classicalRestore, aad: Data(restoreID.uuidString.utf8))

        let config = AppLayerConfig.seeded()
        context.insert(config)
        config.keyEpoch      = try KeyReseal.Epoch(number: 1, form: .classical).sealed(using: classicalLocal)
        config.vaultKeyEpoch = try KeyReseal.Epoch(number: 1, form: .classical).sealed(using: classicalLocal)
        try context.save()

        // A group draft's attachment, sealed under the real classical compose key.
        let appSupport = FileManager.default.temporaryDirectory.appendingPathComponent("real-upgrade-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: appSupport) }
        let folder = appSupport.appendingPathComponent("Drafts").appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let attachment = Sealing.random(300_000)
        let attachmentURL = folder.appendingPathComponent("\(UUID().uuidString).mp4")
        try AttachmentManager(contactKey: try #require(try keys.enclaveBoundKey(.composeStaging))).encrypt(attachment, to: attachmentURL)

        let report = try Self.bound(keys) {
            try KeyReseal.upgradeTierU(
                context: ModelContext(container), keyManager: keys,
                locations: KeyReseal.Locations(applicationSupport: appSupport, store: nil), batchSize: 2
            )
        }

        #expect(report.outcome == .upgraded)
        #expect(report.draftFiles.resealed == 1)
        let hybridCompose = try #require(try keys.enclaveBoundKey(.composeStaging))
        #expect(try await AttachmentManager(contactKey: hybridCompose).data(at: attachmentURL) == attachment, "the draft opens under the real hybrid compose key")
        let record = try #require(try keys.tierPQRecord(.deviceUnlock))
        #expect(record.mode == .hybrid, "the real Enclave ML-KEM record")
        #expect(try keys.pendingTierPQRecord(.deviceUnlock) == nil)

        let hybridLocal   = try #require(try keys.enclaveBoundKey(.localDB))
        let hybridCustody = try #require(try keys.enclaveBoundKey(.shardCustody))
        let hybridRestore = try #require(try keys.enclaveBoundKey(.restoreVault))
        #expect(keyBytes(hybridLocal) != keyBytes(classicalLocal))

        let check = ModelContext(container)
        let saved = try #require(try check.fetch(FetchDescriptor<Contact.Profile>()).first)
        #expect(Data(base64Encoded: saved.givenName).flatMap { Sealing.open($0, key: hybridLocal, aad: Sealing.fixedAAD) } == name)
        #expect(Data(base64Encoded: saved.givenName).flatMap { Sealing.open($0, key: classicalLocal, aad: Sealing.fixedAAD) } == nil)
        let savedCustody = try #require(try check.fetch(FetchDescriptor<CustodyShard>()).first)
        #expect(Sealing.open(savedCustody.encryptedPayload, key: hybridCustody, aad: Data(custodyID.uuidString.utf8)) == custodyPlain)
        let savedRestore = try #require(try check.fetch(FetchDescriptor<PendingShamirSecretRestore>()).first)
        #expect(savedRestore.shards.flatMap { Sealing.open($0, key: hybridRestore, aad: Data(restoreID.uuidString.utf8)) } == shards)

        let savedConfig = try #require(try check.fetch(FetchDescriptor<AppLayerConfig>()).first)
        #expect(KeyReseal.Epoch.opening(savedConfig.keyEpoch, using: hybridLocal) == KeyReseal.Epoch(number: 1, form: .hybrid))
        #expect(KeyReseal.Epoch.opening(savedConfig.vaultKeyEpoch, using: hybridLocal) == KeyReseal.Epoch(number: 1, form: .classical))

        // And a second run has nothing to do.
        let again = try Self.bound(keys) { try KeyReseal.upgradeTierU(context: ModelContext(container), keyManager: keys, batchSize: 2) }
        #expect(again.outcome == .alreadyDone)
    }
}

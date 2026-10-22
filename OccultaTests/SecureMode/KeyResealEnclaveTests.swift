//
//  KeyResealEnclaveTests.swift
//  OccultaTests
//
//  Bug 171, Stage 2 through the real `Manager.Key` and the Secure Enclave, in the classical form and, where the
//  runtime has an ML-KEM provider (iOS 26+), the hybrid one. Everything else about the reseal runs on
//  `TestKeyManager`; this is what only a real Enclave key can show: that the keys the pass names are the ones the
//  accessors then return, that the legacy ones are the keys the previous release sealed with, and what a derivation
//  costs.
//
//  The tier secrets and PQ records are items of the test's own (`Manager.Key(items:)`), so the Simulator's canonical
//  ones, which other tests are using, are left alone. The Enclave keys behind them are the canonical ones: the legacy
//  derivations are the previous release's, which is the point. Gated on the Enclave, as the CI runners (VMs) have none.
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

/// The forms this runtime can run: hybrid needs an ML-KEM provider.
private let availableForms: [KeyForm] = PostQuantumProviderFactory.create() == nil ? [.classical] : [.classical, .hybrid]

/// A real key manager on Keychain items of its own, in `form`, with `r_U` and the tier U record created.
@MainActor
private func makeRealKeys(form: KeyForm) throws -> (keys: Manager.Key, items: Manager.Key.Items) {
    let suffix = UUID().uuidString
    let items = Manager.Key.Items(
        enclaveTags: [],
        tierSecretU: "test.reseal.enclave.ru.\(suffix)", tierSecretB: "test.reseal.enclave.rb.\(suffix)",
        recordU: "test.reseal.enclave.pqu.\(suffix)", recordB: "test.reseal.enclave.pqb.\(suffix)"
    )
    let keys = Manager.Key(items: items)

    try keys.createTierSecretIfAbsent(.deviceUnlock)
    switch form {
    case .hybrid:    try keys.createTierPQRecordIfAbsent(.deviceUnlock)
    case .classical: try keys.createTierPQRecordIfAbsent(account: items.recordU, provider: nil)
    }
    return (keys, items)
}

@MainActor
private func removeRealItems(_ keys: Manager.Key, _ items: Manager.Key.Items) {
    for account in [items.tierSecretU, items.tierSecretB, items.recordU, items.recordB] { _ = keys.deleteTierSecret(account: account) }
}

/// Runs `body` with `keys` bound as the ambient key manager, as `.ambientTestKeyManager` binds a `TestKeyManager`.
@MainActor
private func bound<R>(_ keys: Manager.Key, _ body: () throws -> R) throws -> R {
    try Manager.Ambient.$override.withValue(Manager.Ambient.Override(keys)) {
        try body()
    }
}

private func verifierReportOrNil(_ report: LaunchSequence.Report) -> KeyReseal.VerifierReport? {
    if case .success(let value) = report.verifiers { return value }
    return nil
}

@Suite("Key reseal — real Enclave", .serialized)
@MainActor
struct KeyResealEnclaveTests {

    @Test("The pass moves values sealed under the real legacy keys onto the real Enclave-bound ones, and the accessors then return them",
          .enabled(if: secureEnclaveAvailable()), arguments: availableForms)
    func roundTrip(form: KeyForm) throws {
        let (keys, items) = try makeRealKeys(form: form)
        defer { removeRealItems(keys, items) }

        let container = try makeStore()
        let local   = try #require(try keys.legacyKey(.localDB))
        let custody = try #require(try keys.legacyKey(.shardCustody))
        let restore = try #require(try keys.legacyKey(.restoreVault))

        // What the previous release holds: each under its own key, with the AAD it used.
        struct Seeded {
            let name: String
            let owner: KeyOwner
            let plaintext: Data
            let aad: Data?
            /// Reads the value from `context`, so that a later read sees what the pass committed and not this test's own copy.
            let load: (ModelContext) -> Data?
        }
        var seeded: [Seeded] = []

        try bound(keys) {
            let context = ModelContext(container)
            context.autosaveEnabled = false

            let profile = Contact.Profile(
                identifier: "", givenName: "", familyName: "", middleName: "", nickname: "",
                organizationName: "", departmentName: "", jobTitle: "", encryptionScheme: EncryptionScheme.v2_hybridPQ.rawValue
            )
            context.insert(profile)
            let name = Data("Alice".utf8)
            profile.givenName = Sealing.seal(name, key: local, aad: Sealing.fixedAAD).base64EncodedString()
            let prekeys = Sealing.random(PrekeyRecordCodec.capacity)
            profile.prekeyRecordEncrypted = Sealing.seal(prekeys, key: local, aad: Sealing.fixedAAD)
            try context.save()
            let profileID = profile.persistentModelID
            seeded.append(Seeded(name: "Profile.givenName", owner: .local, plaintext: name, aad: Sealing.fixedAAD,
                                 load: { ($0.model(for: profileID) as? Contact.Profile).flatMap { Data(base64Encoded: $0.givenName) } }))
            seeded.append(Seeded(name: "Profile.prekeyRecordEncrypted", owner: .local, plaintext: prekeys, aad: Sealing.fixedAAD,
                                 load: { ($0.model(for: profileID) as? Contact.Profile)?.prekeyRecordEncrypted }))

            let custodyID = UUID()
            let custodyPlain = Data("custody payload".utf8)
            let custodyRow = CustodyShard(id: custodyID, encryptedPayload: Sealing.seal(custodyPlain, key: custody, aad: Data(custodyID.uuidString.utf8)))
            context.insert(custodyRow)
            try context.save()
            let custodyRowID = custodyRow.persistentModelID
            seeded.append(Seeded(name: "CustodyShard", owner: .custody, plaintext: custodyPlain, aad: Data(custodyID.uuidString.utf8),
                                 load: { ($0.model(for: custodyRowID) as? CustodyShard)?.encryptedPayload }))

            let reconstructID = UUID()
            let reconstructPlain = Data("reconstruct payload".utf8)
            let reconstructRow = ReconstructShard(id: reconstructID, encryptedPayload: Sealing.seal(reconstructPlain, key: restore, aad: Data(reconstructID.uuidString.utf8)))
            context.insert(reconstructRow)
            try context.save()
            let reconstructRowID = reconstructRow.persistentModelID
            seeded.append(Seeded(name: "ReconstructShard", owner: .restore, plaintext: reconstructPlain, aad: Data(reconstructID.uuidString.utf8),
                                 load: { ($0.model(for: reconstructRowID) as? ReconstructShard)?.encryptedPayload }))

            let vault = Vault()
            context.insert(vault)
            let restoreID = UUID()
            let restoreRow = PendingShamirSecretRestore(id: restoreID, vault: vault)
            context.insert(restoreRow)
            let shards = Sealing.random(PendingShamirSecretRestore.ShardsCodec.payloadSize)
            restoreRow.shards = Sealing.seal(shards, key: restore, aad: Data(restoreID.uuidString.utf8))
            try context.save()
            let restoreRowID = restoreRow.persistentModelID
            seeded.append(Seeded(name: "PendingShamirSecretRestore.shards", owner: .restore, plaintext: shards, aad: Data(restoreID.uuidString.utf8),
                                 load: { ($0.model(for: restoreRowID) as? PendingShamirSecretRestore)?.shards }))

            // The config row, as `Manager.Security` made it under the previous release's keys: the gate lowered at depth 2.
            let config = AppLayerConfig.seeded()
            context.insert(config)
            let depth = DepthCodec.encode(2)
            config.persistedDepth = Sealing.seal(depth, key: local, aad: Sealing.fixedAAD)
            try context.save()
            let configID = config.persistentModelID
            seeded.append(Seeded(name: "AppLayerConfig.persistedDepth", owner: .local, plaintext: depth, aad: Sealing.fixedAAD,
                                 load: { ($0.model(for: configID) as? AppLayerConfig)?.persistedDepth }))

            // Before the launch: every value opens under the legacy key and the tier's record is the form under test.
            for item in seeded {
                #expect(item.load(ModelContext(container)).flatMap { Sealing.open($0, key: item.owner == .local ? local : item.owner == .custody ? custody : restore, aad: item.aad) } == item.plaintext, "\(item.name) before")
            }
            #expect(try keys.tierPQRecord(.deviceUnlock)?.mode == (form == .hybrid ? .hybrid : .classical))
        }

        try bound(keys) {
            let report = LaunchSequence.run(context: ModelContext(container), keyManager: keys, batchSize: 3)

            let resealed = resealReport(report)
            #expect(resealed?.outcome == .completed)
            #expect(resealed?.total.failed == 0 && resealed?.total.left == 0)
            #expect(Manager.Ambient.tierUKeys == .enclaveBound)

            let newLocal   = try #require(try keys.enclaveBoundKey(.localDB))
            let newCustody = try #require(try keys.enclaveBoundKey(.shardCustody))
            let newRestore = try #require(try keys.enclaveBoundKey(.restoreVault))

            for item in seeded {
                let key: (new: SymmetricKey, old: SymmetricKey) =
                    item.owner == .local ? (newLocal, local) : item.owner == .custody ? (newCustody, custody) : (newRestore, restore)
                let current = item.load(ModelContext(container))
                #expect(current.flatMap { Sealing.open($0, key: key.new, aad: item.aad) } == item.plaintext, "\(item.name): under the Enclave-bound key, same plaintext")
                #expect(current.flatMap { Sealing.open($0, key: key.old, aad: item.aad) } == nil, "\(item.name): no longer under the legacy key")
            }

            // The accessors are the keys the data is under; the derivations differ from the legacy ones.
            #expect(keyBytes(try #require(try keys.createHybridLocalEncryptionKey())) == keyBytes(newLocal))
            #expect(keyBytes(try #require(try keys.deriveShardCustodyKey())) == keyBytes(newCustody))
            #expect(keyBytes(try #require(try keys.deriveRestoreVaultKey())) == keyBytes(newRestore))
            #expect(keyBytes(newLocal) != keyBytes(local) && keyBytes(newCustody) != keyBytes(custody) && keyBytes(newRestore) != keyBytes(restore))

            // The epoch says which form, and Manager.Security, now after the pass, reads the persisted depth it was given.
            let config = try #require(try ModelContext(container).fetch(FetchDescriptor<AppLayerConfig>()).first)
            #expect(KeyReseal.Epoch.opening(config.keyEpoch, using: newLocal) == KeyReseal.Epoch(number: 1, form: form == .hybrid ? .hybrid : .classical))
            #expect(config.readPersistedDepth() == 2)
            _ = Manager.Security(modelContainer: container, keyManager: keys)
            #expect(try #require(try ModelContext(container).fetch(FetchDescriptor<AppLayerConfig>()).first).readPersistedDepth() == 2)
        }
    }

    @Test("Stage 3: PIN verifiers made with the real PIN key are wrapped under the real wrap key, and the PINs verify afterwards",
          .enabled(if: secureEnclaveAvailable()), arguments: availableForms)
    func verifiersWrapWithRealKeys(form: KeyForm) throws {
        let (keys, items) = try makeRealKeys(form: form)
        defer { removeRealItems(keys, items) }

        let container = try makeStore()
        try bound(keys) {
            // The previous release's verifiers: 53 bytes, under the real inner key.
            let inner = try #require(try keys.deriveSecureModeKey())
            let master = FrozenPIN.plain("111111", label: FrozenPIN.normalLabel, inner: inner)
            let duress = FrozenPIN.plain("999999", label: FrozenPIN.duressLabel, inner: inner)
            let alias  = FrozenPIN.plain("999999", label: FrozenPIN.normalLabel, inner: inner)

            let context = ModelContext(container)
            let config  = AppLayerConfig()
            var normals = AppLayerConfig.verifierFillerArray()
            var duresses = AppLayerConfig.verifierFillerArray()
            normals[0] = master; normals[1] = alias; duresses[0] = duress
            config.sealedNormalVerifiers = normals
            config.sealedDuressVerifiers = duresses
            config.sealedNormalVerifier  = master
            config.sealedDuressVerifier  = duress
            context.insert(config)
            try context.save()

            let report = LaunchSequence.run(context: ModelContext(container), keyManager: keys, batchSize: 3)

            #expect(verifierReportOrNil(report)?.outcome == .wrapped)
            #expect(Manager.Ambient.pinVerifiers == .wrapped)

            let stored = try #require(try ModelContext(container).fetch(FetchDescriptor<AppLayerConfig>()).first)
            #expect(Set((stored.sealedNormalVerifiers + stored.sealedDuressVerifiers).map(\.count)) == [81])

            // The wrap is under the real wrap key, around exactly the verifier that was there.
            let wrapKey = try #require(try keys.enclaveBoundKey(.secureModeWrap))
            #expect(Sealing.open(stored.sealedNormalVerifiers[0], key: wrapKey, aad: nil) == master)
            #expect(Sealing.open(stored.sealedNormalVerifiers[0], key: inner, aad: nil) == nil, "the inner key alone doesn't open it")

            let security = Manager.Security(modelContainer: container, keyManager: keys)
            #expect(try security.verify("111111") == .normal(depth: 0))
            #expect(try security.verify("999999") == .normal(depth: 1))
            #expect(try security.verify("000000") == .wrong)
        }
    }

    @Test("A real key manager with no tier secret gets none from the pass: it aborts, and the bootstrap is what creates it",
          .enabled(if: secureEnclaveAvailable()))
    func passNeverCreatesTheSecret() throws {
        let (keys, items) = try makeRealKeys(form: .classical)
        defer { removeRealItems(keys, items) }
        _ = keys.deleteTierSecret(account: items.tierSecretU)

        let container = try makeStore()
        try bound(keys) {
            let context = ModelContext(container)
            context.insert(AppLayerConfig.seeded())
            try context.save()

            let report = try KeyReseal.run(context: ModelContext(container), keyManager: keys)
            #expect(report.outcome == .aborted(.tierSecretMissing))
            #expect(try keys.tierSecret(.deviceUnlock) == nil, "the pass created nothing")

            let bootstrap = try KeyReseal.bootstrap(context: ModelContext(container), keyManager: keys)
            #expect(bootstrap.createdTierSecret)
            #expect(try keys.tierSecret(.deviceUnlock)?.count == 32)
        }
    }

    // MARK: - Cost

    @Test("Cost on the Simulator's Enclave: legacy against Enclave-bound classical and hybrid, per derivation and for a contact list of String.decrypt() (attached; nothing asserted)",
          .enabled(if: secureEnclaveAvailable()))
    func cost() throws {
        func milliseconds(_ duration: Duration) -> Double {
            Double(duration.components.seconds) * 1_000 + Double(duration.components.attoseconds) / 1e15
        }
        func timed(_ iterations: Int, _ body: () throws -> Void) rethrows -> Double {
            let start = ContinuousClock.now
            for _ in 0..<iterations { try body() }
            return milliseconds(ContinuousClock.now - start) / Double(iterations)
        }

        var lines = [
            "Real Manager.Key on the Simulator's Secure Enclave, on a Keychain record and secret of the test's own.",
            "A device's Enclave is not the Simulator's: these are a floor to measure against on a phone, not a figure for one.",
            "",
        ]

        let iterations = 100
        let listFields = 1_500         // 500 contacts x 3 name fields
        let projected = 6_000          // 2,000 contacts x 3 name fields

        for form in availableForms {
            let (keys, items) = try makeRealKeys(form: form)
            defer { removeRealItems(keys, items) }

            try bound(keys) {
                _ = try keys.legacyKey(.localDB)
                _ = try keys.enclaveBoundKey(.localDB)        // warm: the first call creates nothing, but loads the Enclave key

                let legacy = try timed(iterations) { _ = try keys.legacyKey(.localDB) }
                let enclaveBound = try timed(iterations) { _ = try keys.enclaveBoundKey(.localDB) }
                lines.append("\(form.rawValue): per derivation, legacy \(String(format: "%.3f", legacy)) ms; Enclave-bound \(String(format: "%.3f", enclaveBound)) ms (\(String(format: "%.1f", enclaveBound / legacy))x)")

                for state in [Manager.Ambient.TierUKeys.legacy, .enclaveBound] {
                    Manager.Ambient.setTierUKeys(state)
                    defer { Manager.Ambient.setTierUKeys(.legacy) }

                    let key = try #require(try keys.createHybridLocalEncryptionKey())
                    let strings = (0..<listFields).map { Sealing.seal(Data("Contact \($0)".utf8), key: key, aad: Sealing.fixedAAD).base64EncodedString() }
                    var opened = 0
                    let total = milliseconds(ContinuousClock().measure {
                        for string in strings where !string.decrypt().isEmpty { opened += 1 }
                    })
                    lines.append("\(form.rawValue), \(state == .legacy ? "legacy" : "Enclave-bound"): \(listFields) x String.decrypt() \(String(format: "%.0f", total)) ms total, \(String(format: "%.3f", total / Double(listFields))) ms each, \(String(format: "%.1f", total / Double(listFields) * Double(projected) / 1_000)) s for \(projected) fields (\(opened) opened)")
                }
            }
        }

        Attachment.record(lines.joined(separator: "\n"), named: "key-derivation-cost-enclave.txt")
    }
}

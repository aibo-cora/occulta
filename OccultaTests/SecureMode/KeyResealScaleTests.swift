//
//  KeyResealScaleTests.swift
//  OccultaTests
//
//  Bug 171, Stage 2: what the reseal costs, and what Erase All Data leaves behind. The migration test matrix of the
//  plan, rows 12 to 14:
//
//    - volume: 2,000 contacts with every field and a full prekey record. Time and memory are attached; the test
//      asserts that the pass completes and a bound loose enough that only a runaway fails it;
//    - derivation cost: legacy against Enclave-bound classical and hybrid, per derivation and for a contact list's
//      worth of `String.decrypt()`. Attached, nothing asserted. These are `TestKeyManager`'s software keys, so they
//      measure the work around the Enclave and not the Enclave: a device is needed for those numbers;
//    - Erase All Data, through the seam on `Manager.App.eraseAllData(...)`: no `r_U`, `r_B`, `r_S`, tier PQ record
//      or epoch remains, and the next launch starts as a fresh install.
//

import Testing
import CryptoKit
import Foundation
import LocalAuthentication
import SwiftData

@testable import Occulta
@testable import OccultaCore
@testable import OccultaFormats

// MARK: - Measuring

/// The process's physical footprint now and its resident-size peak so far, in bytes.
private func memory() -> (footprint: UInt64, peak: UInt64) {
    var info  = task_vm_info_data_t()
    var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
    let status = withUnsafeMutablePointer(to: &info) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
        }
    }
    guard status == KERN_SUCCESS else { return (0, 0) }
    return (UInt64(info.phys_footprint), UInt64(info.resident_size_peak))
}

private func megabytes(_ bytes: UInt64) -> String {
    String(format: "%.1f MB", Double(bytes) / 1_048_576)
}

private func milliseconds(_ duration: Duration) -> Double {
    Double(duration.components.seconds) * 1_000 + Double(duration.components.attoseconds) / 1e15
}

// MARK: - Volume

/// `count` contacts with every field and a full prekey record, sealed under `legacy`, and an `AppLayerConfig` row, in one
/// context and one save: the volume of matrix row 10.
@MainActor
func seedVolumeContacts(_ count: Int, into store: LegacyStore, sealedUnder legacy: SymmetricKey) throws {
    let context = store.newContext()
    let config  = AppLayerConfig()
    context.insert(config)

    func seal(_ plaintext: Data) -> Data { Sealing.seal(plaintext, key: legacy, aad: Sealing.fixedAAD) }
    func sealed(_ text: String) -> String { seal(Data(text.utf8)).base64EncodedString() }

    let thumbnail = Sealing.random(2_000)
    let image     = Sealing.random(9_000)
    let prekeys   = Sealing.random(PrekeyRecordCodec.capacity)
    let card      = Sealing.random(CardStateCodec.capacity)
    let challenge = Sealing.random(ChallengeStateCodec.capacity)

    for index in 0..<count {
        let profile = Contact.Profile(
            identifier: sealed("id \(index)"), givenName: sealed("Given \(index)"), familyName: sealed("Family \(index)"),
            middleName: sealed("Middle"), nickname: sealed("Nick"), organizationName: sealed("Organization"),
            departmentName: sealed("Department"), jobTitle: sealed("Title"),
            encryptionScheme: EncryptionScheme.v2_hybridPQ.rawValue
        )
        context.insert(profile)

        profile.namePrefix = sealed("Dr");  profile.nameSuffix = sealed("PhD")
        profile.phoneticGivenName = sealed("a"); profile.phoneticMiddleName = sealed("b"); profile.phoneticFamilyName = sealed("c")
        profile.birthday = sealed("1/1/90"); profile.note = sealed("A note about contact \(index)")
        profile.thumbnailImageData = seal(thumbnail); profile.imageData = seal(image)
        profile.prekeyRecordEncrypted = seal(prekeys); profile.introductionCardEncrypted = seal(card)
        profile.challengeStateEncrypted = seal(challenge)
        profile.signedAttributes = seal(Data("attributes".utf8))
        profile.globalTrusteeDepth = seal(DepthCodec.encode(-1)); profile.maxBundleVersion = seal(Data([3]))
        profile.visibleThroughDepth = seal(DepthCodec.encode(Int.max)); profile.originDepth = seal(DepthCodec.encode(0))

        let phone = Contact.Profile.PhoneNumber(label: sealed("mobile"), value: sealed("+1 555 \(index)"))
        phone.profile = profile
        context.insert(phone)

        let email = Contact.Profile.EmailAddress(label: sealed("work"), value: sealed("c\(index)@example.com"))
        email.profile = profile
        context.insert(email)

        let postal = Contact.Profile.PostalAddress(
            label: sealed("home"), street: sealed("1 Street"), city: sealed("City"), state: sealed("State"),
            postalCode: sealed("12345"), country: sealed("Country"), isoCountryCode: sealed("XX")
        )
        postal.profile = profile
        context.insert(postal)

        let url = Contact.Profile.URLAddress(label: sealed("site"), value: sealed("https://example.com/\(index)"))
        url.profile = profile
        context.insert(url)

        let key = Contact.Profile.Key(material: seal(Sealing.random(65)), owner: seal(Data("owner".utf8)), date: seal(Data("date".utf8)))
        key.profile = profile
        context.insert(key)
    }
    try context.save()
}


@Suite("Key reseal — volume", .ambientFrozenTestKeyManager)
@MainActor
struct KeyResealVolumeTests {

    private static let contacts = 2_000

    @Test("2,000 contacts with every field and a full prekey record: the pass completes; time and memory are attached")
    func twoThousandContacts() throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        let store = try LegacyStore(keys: keys)

        // The seeding, once, in one context and one save.
        let seedingStarted = ContinuousClock.now
        try seedVolumeContacts(Self.contacts, into: store, sealedUnder: Frozen.legacyKey(.local))
        let seedingTime = ContinuousClock.now - seedingStarted

        // The pass, with the production batch size.
        let before = memory()
        let started = ContinuousClock.now
        let report = try KeyReseal.run(context: store.newContext(), keyManager: keys)
        let elapsed = ContinuousClock.now - started
        let after = memory()

        let lines = [
            "contacts:                \(Self.contacts), every field, a full prekey record",
            "seeding:                 \(String(format: "%.0f", milliseconds(seedingTime))) ms",
            "reseal (batch of \(KeyReseal.defaultBatchSize)):     \(String(format: "%.0f", milliseconds(elapsed))) ms",
            "per contact:             \(String(format: "%.2f", milliseconds(elapsed) / Double(Self.contacts))) ms",
            "footprint before/after:  \(megabytes(before.footprint)) / \(megabytes(after.footprint))",
            "resident peak so far:    \(megabytes(before.peak)) before, \(megabytes(after.peak)) after (the process's, seeding included)",
            "outcome:                 \(report.outcome)",
            "resealed/skipped/left/failed: \(report.total.resealed) / \(report.total.skipped) / \(report.total.left) / \(report.total.failed)",
            "These are the Simulator's, with software keys; a device has the Enclave's cost per derivation on top, once per batch.",
        ]
        Attachment.record(lines.joined(separator: "\n"), named: "key-reseal-volume.txt")

        #expect(report.outcome == .completed)
        #expect(report.entries["Profile.givenName"]?.resealed == Self.contacts)
        #expect(report.entries["Profile.prekeyRecordEncrypted"]?.resealed == Self.contacts)
        #expect(report.entries["Key.material"]?.resealed == Self.contacts)
        #expect(report.total.failed == 0)

        // Spot check: three contacts, opened under the new key.
        let newKey = Frozen.newKey(.local, form: .hybrid)
        let checked = try store.newContext().fetch(FetchDescriptor<Contact.Profile>()).prefix(3)
        for profile in checked {
            let name = Data(base64Encoded: profile.givenName).flatMap { Sealing.open($0, key: newKey, aad: Sealing.fixedAAD) }
            #expect(name.flatMap { String(data: $0, encoding: .utf8) }?.hasPrefix("Given ") == true)
            #expect(profile.prekeyRecordEncrypted.flatMap { Sealing.open($0, key: newKey, aad: Sealing.fixedAAD) }?.count == PrekeyRecordCodec.capacity)
        }
        #expect(try store.newContext().fetchCount(FetchDescriptor<Contact.Profile>()) == Self.contacts)

        // Loose: only a runaway fails these. The numbers are in the attachment.
        #expect(elapsed < .seconds(600), "the pass took \(elapsed)")
        #expect(after.peak < 3 * 1_073_741_824, "resident peak \(megabytes(after.peak))")
    }
}

// MARK: - Derivation cost

@Suite("Key reseal — derivation cost", .ambientFrozenTestKeyManager)
@MainActor
struct KeyDerivationCostTests {

    @Test("Legacy against Enclave-bound classical and hybrid, per derivation and for a contact list of String.decrypt() (attached; nothing asserted)")
    func cost() throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)

        func perCall(_ iterations: Int, _ body: () throws -> Void) rethrows -> Double {
            let start = ContinuousClock.now
            for _ in 0..<iterations { try body() }
            return milliseconds(ContinuousClock.now - start) / Double(iterations)
        }

        let iterations = 300
        var lines = ["TestKeyManager, software keys: the Enclave's own cost is not in these numbers.", ""]

        keys.become(.hybrid)
        let legacy = try perCall(iterations) { _ = try keys.legacyKey(.localDB) }
        lines.append("per derivation, legacy (ECDH against G):           \(String(format: "%.3f", legacy)) ms")

        keys.become(.classical)
        let classical = try perCall(iterations) { _ = try keys.enclaveBoundKey(.localDB) }
        lines.append("per derivation, Enclave-bound classical:           \(String(format: "%.3f", classical)) ms")

        keys.become(.hybrid)
        let hybrid = try perCall(iterations) { _ = try keys.enclaveBoundKey(.localDB) }
        lines.append("per derivation, Enclave-bound hybrid (ML-KEM):     \(String(format: "%.3f", hybrid)) ms")

        // A contact list: `String.decrypt()` derives the key afresh on every call, through the accessor the epoch
        // decides: legacy before it, Enclave-bound after.
        let contacts = 2_000
        let fieldsPerRow = 3
        func listCost(_ label: String, state: Manager.Ambient.TierUKeys, form: KeyForm) throws {
            keys.become(form)
            Manager.Ambient.setTierUKeys(state)
            defer { Manager.Ambient.setTierUKeys(.legacy) }

            let key = try #require(try keys.createHybridLocalEncryptionKey())
            let strings = (0..<contacts * fieldsPerRow).map { index in
                Sealing.seal(Data("Contact \(index)".utf8), key: key, aad: Sealing.fixedAAD).base64EncodedString()
            }
            var decrypted = 0
            let started = ContinuousClock.now
            for string in strings where !string.decrypt().isEmpty { decrypted += 1 }
            let total = milliseconds(ContinuousClock.now - started)
            lines.append("\(contacts) contacts x \(fieldsPerRow) fields, String.decrypt(), \(label): \(String(format: "%.0f", total)) ms total, \(String(format: "%.3f", total / Double(strings.count))) ms each (\(decrypted) opened)")
        }
        try listCost("legacy", state: .legacy, form: .hybrid)
        try listCost("Enclave-bound classical", state: .enclaveBound, form: .classical)
        try listCost("Enclave-bound hybrid", state: .enclaveBound, form: .hybrid)
        Attachment.record(lines.joined(separator: "\n"), named: "key-derivation-cost.txt")
    }
}

// MARK: - Erase All Data

@Suite("Key reseal — Erase All Data", .ambientFrozenTestKeyManager)
@MainActor
struct KeyResealEraseTests {

    /// Whether a generic-password item for `account` exists, asked for its attributes only so a protected item
    /// (`r_B`) is found without authenticating.
    private func keychainHas(account: String) -> Bool {
        let context = LAContext()
        context.interactionNotAllowed = true
        let query: [String: Any] = [
            kSecClass as String:                    kSecClassGenericPassword,
            kSecAttrAccount as String:              account,
            kSecReturnAttributes as String:         true,
            kSecUseAuthenticationContext as String: context,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    /// The Keychain items of this test's own, in every place the app keeps one, and the manager that deletes them.
    private struct Items {
        let accounts: [String]
        let erasing: Manager.Key
        let staging: ShareStagingKeyManager
    }

    private func createItems() throws -> Items {
        let suffix = UUID().uuidString
        let items = Manager.Key.Items(
            enclaveTags: [],
            tierSecretU: "test.erase.ru.\(suffix)", tierSecretB: "test.erase.rb.\(suffix)",
            recordU: "test.erase.pqu.\(suffix)", recordB: "test.erase.pqb.\(suffix)"
        )
        let erasing = Manager.Key(items: items)
        try erasing.createTierSecretIfAbsent(.deviceUnlock, account: items.tierSecretU)
        try erasing.createTierSecretIfAbsent(.biometry(LAContext()), account: items.tierSecretB)
        try erasing.createTierPQRecordIfAbsent(account: items.recordU, provider: nil)
        try erasing.createTierPQRecordIfAbsent(account: items.recordB, provider: nil)

        let staging = ShareStagingKeyManager(
            keyTag: "test.erase.key.\(suffix)",
            tierSecretAccount: "test.erase.rs.\(suffix)", tierPQRecordAccount: "test.erase.pqs.\(suffix)",
            postQuantum: { nil }
        )
        try staging.createTierSecretIfAbsent()
        try staging.createTierPQRecordIfAbsent()

        return Items(accounts: [items.tierSecretU, items.tierSecretB, items.recordU, items.recordB], erasing: erasing, staging: staging)
    }

    /// Erase All Data over a seeded store that has an epoch, with `items` in the Keychain.
    private func erase(_ store: LegacyStore, keys: TestKeyManager, items: Items) throws {
        let security = Manager.Security(modelContainer: store.container, keyManager: keys)
        let app = Manager.App(
            contacts: ContactManager(modelContainer: store.container, security: security),
            vault: VaultManager(modelContainer: store.container, keyManager: keys)
        )
        let drafts = FileManager.default.temporaryDirectory.appendingPathComponent("drafts-\(UUID().uuidString)", isDirectory: true)
        try app.eraseAllData(erasePrekeys: {}, draftsRoot: drafts, stagingContainer: nil, staging: items.staging, keys: items.erasing)
    }

    @Test("Erase All Data leaves no r_U, r_B, r_S, tier PQ record or epoch (passes today: Stage 1 made deleteAllKeys and deleteKey remove them)", .enabled(if: keychainAvailable() && sharedKeychainAvailable()))
    func eraseLeavesNothing() throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        let items = try createItems()

        let store = try LegacyStore(keys: keys)
        try store.seed()
        try writeEpoch(store, form: .hybrid)
        #expect(appConfig(store)?.keyEpoch != nil, "precondition: an epoch exists")

        // Every item exists before, so that "none remains" means something.
        #expect(items.accounts.allSatisfy { self.keychainHas(account: $0) }, "the test's own items were created")
        #expect(try items.staging.tierSecret() != nil && items.staging.tierPQRecord() != nil)

        try erase(store, keys: keys, items: items)

        #expect(items.accounts.filter { self.keychainHas(account: $0) }.isEmpty, "Keychain items left: \(items.accounts.filter { self.keychainHas(account: $0) })")
        #expect(try items.staging.tierSecret() == nil, "r_S")
        #expect(try items.staging.tierPQRecord() == nil, "the staging record")

        let context = store.newContext()
        #expect(try context.fetchCount(FetchDescriptor<AppLayerConfig>()) == 0, "the config row, and with it both epochs")
        #expect(try context.fetchCount(FetchDescriptor<Contact.Profile>()) == 0)
    }

    @Test("After Erase All Data the next launch finds no epoch and no secret and starts as a fresh install, creating them again", .enabled(if: keychainAvailable() && sharedKeychainAvailable()))
    func launchAfterEraseIsFresh() throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        let items = try createItems()

        let store = try LegacyStore(keys: keys)
        try store.seed()
        try writeEpoch(store, form: .hybrid)
        try erase(store, keys: keys, items: items)

        // The in-memory manager stands in for the erased Keychain.
        keys.tierSecretU   = nil
        keys.tierPQRecordU = nil
        keys.tierSecretB   = nil

        let launch = LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        guard case .success(let bootstrap) = launch.bootstrap else {
            Issue.record("the bootstrap failed: \(launch.bootstrap)")
            return
        }
        #expect(bootstrap.createdTierSecret && bootstrap.createdTierPQRecord && bootstrap.createdConfig, "\(bootstrap)")
        #expect(bootstrap.refusals.isEmpty, "an erased install must not read as a tier whose secret was lost after an epoch")
        #expect(keys.tierSecretU != nil && keys.tierPQRecordU != nil)
    }
}

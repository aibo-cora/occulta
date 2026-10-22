//
//  ShareStagingEnclaveBoundTests.swift
//  OccultaTests
//
//  Bug 171, Stage 5: share staging seals under the Enclave-bound key, in the form its PQ record says (hybrid on iOS 26+,
//  classical below), and opens in that order: the current form, then classical (when the record is hybrid), then the
//  legacy ECDH-against-G key. So a session staged by the previous build, or just before the device reached iOS 26,
//  isn't lost to an update. The classical and legacy fallbacks go one release after 2.0.0.
//
//  What these run on: a software P-256 key standing in for the Enclave key (`ShareStagingKeyManager.init(enclaveKey:)`),
//  two instances sharing it and the Keychain items of one test, as the app and the extension share the Enclave key and
//  the shared access group. No Secure Enclave is needed; the real Enclave round trips are in `ShareStagingKeyManagerTests`.
//
//  The fixtures are sealed with CryptoKit rebuilds (`rebuildLegacy`, `rebuildEnclaveBound`) and not through the code
//  under test, so a change to that code can't make a test agree with itself.
//
//  Written first: against the stubs `encrypt` still sealed under the legacy key, `createTierItemsIfAbsent()` did
//  nothing and the launch sequence created no staging items.
//

import Testing
import CryptoKit
import Foundation
import Security
import SwiftData

@testable import Occulta
@testable import OccultaCore
@testable import OccultaFormats

private let legacyInfo = Data("Occulta-v1-share-index-2026".utf8)

private func seal(_ plaintext: Data, key: SymmetricKey) throws -> Data {
    try #require(AES.GCM.seal(plaintext, using: key).combined)
}

private func opens(_ sealed: Data, key: SymmetricKey) -> Data? {
    (try? AES.GCM.SealedBox(combined: sealed)).flatMap { try? AES.GCM.open($0, using: key) }
}

/// One phone: the staging Enclave key (a software key here), and the Keychain accounts of `r_S` and the PQ record in
/// the shared group. `process(...)` is the app or the extension: two of them are two instances on the same items.
@MainActor
private struct Device {
    static let group = "group.com.occulta.shared"

    let key: SecKey
    let keyTag      = "test.stage5.key.\(UUID().uuidString)"
    let secretAccount = "test.stage5.rs.\(UUID().uuidString)"
    let recordAccount = "test.stage5.pqs.\(UUID().uuidString)"

    init() throws {
        self.key = try softwareP256Key(scalar: katScalar)
    }

    /// The legacy key, rebuilt with CryptoKit from the scalar.
    func legacyKey() throws -> SymmetricKey {
        SymmetricKey(data: try rebuildLegacy(scalar: katScalar, secret: nil, info: legacyInfo))
    }

    /// The classical Enclave-bound key for `secret`, rebuilt with CryptoKit.
    func classicalKey(secret: Data) throws -> SymmetricKey {
        SymmetricKey(data: try rebuildEnclaveBound(scalar: katScalar, secret: secret, info: katStaging.info))
    }

    /// An app or extension process on this phone. `postQuantum` is its ML-KEM: in-memory for a device on iOS 26+, nil below.
    func process(postQuantum: @escaping () -> (any StagingPostQuantum)?) -> ShareStagingKeyManager {
        let key = self.key
        return ShareStagingKeyManager(
            keyTag: self.keyTag, tierSecretAccount: self.secretAccount, tierPQRecordAccount: self.recordAccount,
            postQuantum: postQuantum, enclaveKey: { key }
        )
    }

    func hybridProcess() -> ShareStagingKeyManager { self.process { InMemoryStagingPostQuantum() } }
    func classicalProcess() -> ShareStagingKeyManager { self.process { nil } }

    func clean() {
        let manager = self.classicalProcess()
        manager.deleteTierSecret()
        manager.deleteTierPQRecord()
    }

    /// The stored item of `account`, as the Keychain reports it, or nil.
    static func raw(account: String) -> (data: Data, attributes: [String: Any])? {
        var item: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrAccount as String:      account,
            kSecAttrAccessGroup as String:  Self.group,
            kSecReturnData as String:       true,
            kSecReturnAttributes as String: true
        ] as CFDictionary, &item)
        guard status == errSecSuccess, let dict = item as? [String: Any], let data = dict[kSecValueData as String] as? Data else { return nil }
        return (data, dict)
    }
}

@Suite("Share staging — sealed under the Enclave-bound key", .serialized, .ambientFrozenTestKeyManager)
@MainActor
struct ShareStagingEnclaveBoundTests {

    private let plaintext = Data("staged: the files and the manifest of a share session".utf8)

    /// The hybrid key of `manager`'s record, rebuilt: the static derivation over what the Keychain holds and the
    /// provider's decapsulation, independent of `encrypt` and `decrypt`.
    private func hybridKey(of manager: ShareStagingKeyManager, device: Device) throws -> SymmetricKey {
        let secret   = try #require(try manager.tierSecret())
        let record   = try #require(try manager.tierPQRecord())
        let provider = try #require(InMemoryStagingPostQuantum())
        let shared   = try #require(provider.decapsulate(ciphertext: record.ciphertext, keyBlob: record.keyBlob))

        return try ShareStagingKeyManager.enclaveBoundKey(exchangingWith: device.key, secret: secret, postQuantum: (shared, record.ciphertext))
    }

    // MARK: - Sealing

    @Test("A hybrid device seals under the hybrid key: not the classical one, not the legacy one, and the legacy derivation never runs")
    func hybridDeviceSealsHybrid() throws {
        let device = try Device()
        defer { device.clean() }
        let manager = device.hybridProcess()

        let sealed = try manager.encrypt(data: self.plaintext)

        #expect(opens(sealed, key: try self.hybridKey(of: manager, device: device)) == self.plaintext, "opens under the hybrid key")
        #expect(opens(sealed, key: try device.classicalKey(secret: try #require(try manager.tierSecret()))) == nil, "not under the classical key")
        #expect(opens(sealed, key: try device.legacyKey()) == nil, "not under the legacy key")
        #expect(try manager.tierPQRecord()?.mode == .hybrid)
        #if DEBUG
        #expect(manager.legacyDerivationCount == 0)
        #endif
    }

    @Test("A classical device seals under the classical key, not the legacy one")
    func classicalDeviceSealsClassical() throws {
        let device = try Device()
        defer { device.clean() }
        let manager = device.classicalProcess()

        let sealed = try manager.encrypt(data: self.plaintext)

        let secret = try #require(try manager.tierSecret())
        #expect(opens(sealed, key: try device.classicalKey(secret: secret)) == self.plaintext)
        #expect(opens(sealed, key: try device.legacyKey()) == nil)
        #expect(try manager.tierPQRecord()?.mode == .classical)
        #if DEBUG
        #expect(manager.legacyDerivationCount == 0)
        #endif
    }

    @Test("Each call seals with a fresh nonce, and a tampered ciphertext is rejected in every form",
          arguments: [true, false])
    func nonceAndTamper(hybrid: Bool) throws {
        let device = try Device()
        defer { device.clean() }
        let manager = hybrid ? device.hybridProcess() : device.classicalProcess()

        let first  = try manager.encrypt(data: self.plaintext)
        let second = try manager.encrypt(data: self.plaintext)
        #expect(first != second)

        var tampered = first
        tampered[tampered.count - 1] ^= 0x01
        #expect(throws: (any Error).self) { try manager.decrypt(data: tampered) }
        #expect(try manager.decrypt(data: first) == self.plaintext)
    }

    // MARK: - Opening

    @Test("A session the previous build staged (legacy key) opens, whether the items exist yet or not, and opening creates nothing",
          arguments: [true, false], [true, false])
    func legacySessionOpens(hybrid: Bool, itemsExist: Bool) throws {
        let device = try Device()
        defer { device.clean() }
        let manager = hybrid ? device.hybridProcess() : device.classicalProcess()
        if itemsExist { try manager.createTierItemsIfAbsent() }
        let recordBefore = try manager.tierPQRecord()

        let sealed = try seal(self.plaintext, key: try device.legacyKey())

        #expect(try manager.decrypt(data: sealed) == self.plaintext)
        #expect(try manager.tierPQRecord() == recordBefore, "decrypt made no record, and replaced none")
        #expect((try manager.tierSecret() != nil) == itemsExist, "decrypt made no secret")
    }

    @Test("A classical-sealed session opens after the record became hybrid; sealing under the classical form no longer happens")
    func classicalSessionOpensAfterTheRecordBecameHybrid() throws {
        let device = try Device()
        defer { device.clean() }

        // The device was below iOS 26 when this was staged: classical record, classical key.
        let before = device.classicalProcess()
        try before.createTierItemsIfAbsent()
        let secret = try #require(try before.tierSecret())
        let sealed = try seal(self.plaintext, key: try device.classicalKey(secret: secret))
        #expect(try before.decrypt(data: sealed) == self.plaintext, "control: it opens while the record is classical")

        // The device reaches iOS 26 and the record is rewritten to hybrid (Stage 6).
        before.deleteTierPQRecord()
        let after = device.hybridProcess()
        try after.createTierPQRecordIfAbsent()
        #expect(try after.tierPQRecord()?.mode == .hybrid)

        #expect(try after.decrypt(data: sealed) == self.plaintext, "still opens: the classical fallback")

        // And what it seals now is hybrid only.
        let fresh = try after.encrypt(data: self.plaintext)
        #expect(opens(fresh, key: try device.classicalKey(secret: secret)) == nil)
        #expect(opens(fresh, key: try self.hybridKey(of: after, device: device)) == self.plaintext)

        // A hybrid record is never read as classical when sealing: a process without ML-KEM throws.
        let without = device.classicalProcess()
        #expect(throws: ShareStagingKeyManager.KeyError.postQuantumFailed) { try without.encrypt(data: self.plaintext) }
    }

    @Test("A new session opens under no key but the current one: not the legacy key, not the classical key on a hybrid device, and not another phone's")
    func newSessionsOpenUnderTheCurrentKeyOnly() throws {
        let device = try Device(), other = try Device()
        defer { device.clean(); other.clean() }

        let manager = device.hybridProcess()
        let sealed  = try manager.encrypt(data: self.plaintext)

        #expect(opens(sealed, key: try device.legacyKey()) == nil)
        #expect(opens(sealed, key: try device.classicalKey(secret: try #require(try manager.tierSecret()))) == nil)

        // A phone with the same Enclave key bytes but its own r_S and record can't open it.
        let impostor = other.hybridProcess()
        try impostor.createTierItemsIfAbsent()
        #expect(throws: (any Error).self) { try impostor.decrypt(data: sealed) }
    }

    @Test("An older build, which derives the legacy key only, can open its own sessions and none of the new ones")
    func olderBuildOpensOnlyLegacySessions() throws {
        let device = try Device()
        defer { device.clean() }

        let legacy = try device.legacyKey()
        let theirs = try seal(self.plaintext, key: legacy)
        let ours   = try device.hybridProcess().encrypt(data: self.plaintext)

        #expect(opens(theirs, key: legacy) == self.plaintext)
        #expect(opens(ours, key: legacy) == nil, "a session staged by this build is lost to an older app, and is swept there within the hour")
    }

    // MARK: - The app and the extension

    @Test("What the extension seals the app opens, and the reverse, in both forms", arguments: [true, false])
    func appAndExtensionAgree(hybrid: Bool) throws {
        let device = try Device()
        defer { device.clean() }
        let app       = hybrid ? device.hybridProcess() : device.classicalProcess()
        let extension_ = hybrid ? device.hybridProcess() : device.classicalProcess()

        try app.createTierItemsIfAbsent()
        let fromExtension = try extension_.encrypt(data: self.plaintext)
        let fromApp       = try app.encrypt(data: self.plaintext)

        #expect(try app.decrypt(data: fromExtension) == self.plaintext)
        #expect(try extension_.decrypt(data: fromApp) == self.plaintext)
    }

    @Test("A missing secret and record are created by the app's bootstrap, and the extension then uses them without changing them",
          arguments: [true, false])
    func appCreatesThem(hybrid: Bool) throws {
        let device = try Device()
        defer { device.clean() }
        let app       = hybrid ? device.hybridProcess() : device.classicalProcess()
        let extension_ = hybrid ? device.hybridProcess() : device.classicalProcess()

        #expect(try app.tierSecret() == nil && app.tierPQRecord() == nil)
        try app.createTierItemsIfAbsent()

        let secret = try #require(try app.tierSecret()), record = try #require(try app.tierPQRecord())
        #expect(secret.count == 32)
        #expect(record.mode == (hybrid ? .hybrid : .classical))

        _ = try extension_.encrypt(data: self.plaintext)
        #expect(try extension_.tierSecret() == secret)
        #expect(try extension_.tierPQRecord() == record)
    }

    @Test("A missing secret and record are created by the extension on first use, and the app then uses them without changing them",
          arguments: [true, false])
    func extensionCreatesThem(hybrid: Bool) throws {
        let device = try Device()
        defer { device.clean() }
        let app       = hybrid ? device.hybridProcess() : device.classicalProcess()
        let extension_ = hybrid ? device.hybridProcess() : device.classicalProcess()

        let sealed = try extension_.encrypt(data: self.plaintext)
        let secret = try #require(try extension_.tierSecret()), record = try #require(try extension_.tierPQRecord())

        try app.createTierItemsIfAbsent()
        #expect(try app.tierSecret() == secret, "the app's bootstrap adds nothing and replaces nothing")
        #expect(try app.tierPQRecord() == record)
        #expect(try app.decrypt(data: sealed) == self.plaintext)
    }

    @Test("Items are in the shared group, WhenUnlockedThisDeviceOnly, and the record is the one size in both forms")
    func itemAttributes() throws {
        let hybridDevice = try Device(), classicalDevice = try Device()
        defer { hybridDevice.clean(); classicalDevice.clean() }

        try hybridDevice.hybridProcess().createTierItemsIfAbsent()
        try classicalDevice.classicalProcess().createTierItemsIfAbsent()

        for device in [hybridDevice, classicalDevice] {
            let secret = try #require(Device.raw(account: device.secretAccount))
            let record = try #require(Device.raw(account: device.recordAccount))
            #expect(secret.data.count == 32)
            #expect(record.data.count == TierPQRecord.size)
            for item in [secret, record] {
                #expect(item.attributes[kSecAttrAccessGroup as String] as? String == Device.group)
                #expect(item.attributes[kSecAttrAccessible as String] as? String == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
            }
        }
    }

    @Test("Two processes creating at once end with one secret and one record, and neither is replaced")
    func racingCreators() throws {
        let device = try Device()
        defer { device.clean() }
        let first = device.hybridProcess(), second = device.hybridProcess()

        try first.createTierItemsIfAbsent()
        let secret = try #require(try first.tierSecret()), record = try #require(try first.tierPQRecord())

        try second.createTierItemsIfAbsent()
        #expect(try second.tierSecret() == secret)
        #expect(try second.tierPQRecord() == record)

        // The same, through the duplicate-item path of the adders.
        #expect(try second.createTierSecretIfAbsent() == false)
        #expect(try second.createTierPQRecordIfAbsent() == false)
    }

    @Test("A provider that can't make the key stores nothing, and sealing then fails instead of using a lower form")
    func refusedRecordFailsLoudly() throws {
        let device = try Device()
        defer { device.clean() }
        let manager = device.process { RefusingStagingPostQuantum() }

        #expect(throws: ShareStagingKeyManager.KeyError.postQuantumUnavailable) { try manager.encrypt(data: self.plaintext) }
        #expect(Device.raw(account: device.recordAccount) == nil, "no classical record in its place")
    }

    // MARK: - Fresh install, erase, sweep

    @Test("A fresh install: the app's launch creates the items, and the first session is sealed under them with no legacy derivation",
          arguments: [true, false])
    func freshInstall(hybrid: Bool) throws {
        let device = try Device()
        defer { device.clean() }
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(hybrid ? .hybrid : .classical)
        keys.tierSecretU   = nil
        keys.tierPQRecordU = nil
        let store = try LegacyStore(keys: keys)

        let app = hybrid ? device.hybridProcess() : device.classicalProcess()
        let launch = LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7, staging: app)

        guard case .success = try #require(launch.staging) else {
            Issue.record("the staging items were not created: \(String(describing: launch.staging))")
            return
        }
        #expect(!launch.blocked)
        #expect(try app.tierSecret()?.count == 32)
        #expect(try app.tierPQRecord()?.mode == (hybrid ? .hybrid : .classical))

        let extension_ = hybrid ? device.hybridProcess() : device.classicalProcess()
        let sealed = try extension_.encrypt(data: self.plaintext)
        #expect(try app.decrypt(data: sealed) == self.plaintext)
        #if DEBUG
        #expect(extension_.legacyDerivationCount == 0 && app.legacyDerivationCount == 0)
        #endif
    }

    @Test("The launch carries on when the items can't be created, and the next share is where it fails")
    func launchSurvivesARefusedRecord() throws {
        let device = try Device()
        defer { device.clean() }
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        let store = try LegacyStore(keys: keys)

        let refusing = device.process { RefusingStagingPostQuantum() }
        let launch = LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7, staging: refusing)

        guard case .failure = try #require(launch.staging) else {
            Issue.record("the creation was to fail")
            return
        }
        #expect(resealReport(launch) != nil, "the reseal still ran")
        #expect(!launch.blocked)
    }

    @Test("A launch without a staging manager creates nothing in the shared group")
    func launchWithoutStagingCreatesNothing() throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        let store = try LegacyStore(keys: keys)

        let launch = LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)

        #expect(launch.staging == nil)
    }

    @Test("A blocked launch (Stage 2c) writes no staging items")
    func blockedLaunchWritesNoStagingItems() throws {
        let device = try Device()
        defer { device.clean() }
        let (keys, store) = try prepare(.hybrid)
        let app = device.hybridProcess()

        let launch = KeyReseal.$faults.withValue(KeyReseal.Faults(interruptAt: .midBatch)) {
            LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7, staging: app)
        }

        #expect(launch.blocked)
        #expect(launch.staging == nil)
        #expect(try app.tierSecret() == nil && app.tierPQRecord() == nil)
    }

    @Test("Erase All Data removes r_S and the record, and the next session is sealed under new ones: nothing sealed before opens")
    func eraseRemovesThemAndTheNextSessionStartsOver() throws {
        let device = try Device()
        defer { device.clean() }
        let manager = device.hybridProcess()

        let before = try manager.encrypt(data: self.plaintext)
        #expect(Device.raw(account: device.secretAccount) != nil && Device.raw(account: device.recordAccount) != nil)

        #expect(manager.deleteKey())
        #expect(Device.raw(account: device.secretAccount) == nil)
        #expect(Device.raw(account: device.recordAccount) == nil)

        let after = try manager.encrypt(data: self.plaintext)
        #expect(try manager.decrypt(data: after) == self.plaintext)
        #expect(throws: (any Error).self) { try manager.decrypt(data: before) }
    }

    // MARK: - The stale-session sweep

    private func makeContainer() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ShareStagingStage5-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// A session directory with a manifest sealed by `sealing`, or none, or a corrupt one.
    private func stage(in container: URL, createdAt: Date, sealing: ((Data) throws -> Data)?, corrupt: Bool = false) throws -> String {
        let id  = UUID().uuidString
        let dir = ShareSession.directory(for: id, in: container)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        if corrupt {
            try Data((0..<64).map { _ in UInt8.random(in: 0...255) }).write(to: dir.appendingPathComponent("manifest.enc"))
        } else if let sealing {
            let manifest = ShareManifest(files: [], createdAt: createdAt)
            try sealing(try JSONEncoder().encode(manifest)).write(to: dir.appendingPathComponent("manifest.enc"))
        }
        return id
    }

    private func exists(_ id: String, in container: URL) -> Bool {
        FileManager.default.fileExists(atPath: ShareSession.directory(for: id, in: container).path)
    }

    @Test("The sweep is unchanged: it keeps a fresh session in any form, and deletes a stale one, one without a manifest and a corrupt one",
          arguments: [true, false])
    func sweepIsUnchanged(hybrid: Bool) throws {
        let device = try Device()
        defer { device.clean() }
        let manager = hybrid ? device.hybridProcess() : device.classicalProcess()
        try manager.createTierItemsIfAbsent()
        let secret = try #require(try manager.tierSecret())
        let container = try self.makeContainer()
        defer { try? FileManager.default.removeItem(at: container) }

        let hour: TimeInterval = 3600
        let legacy = try device.legacyKey(), classical = try device.classicalKey(secret: secret)

        let freshCurrent   = try self.stage(in: container, createdAt: .now) { try manager.encrypt(data: $0) }
        let freshLegacy    = try self.stage(in: container, createdAt: .now) { try seal($0, key: legacy) }
        let freshClassical = try self.stage(in: container, createdAt: .now) { try seal($0, key: classical) }
        let staleCurrent   = try self.stage(in: container, createdAt: .now.addingTimeInterval(-2 * hour)) { try manager.encrypt(data: $0) }
        let staleLegacy    = try self.stage(in: container, createdAt: .now.addingTimeInterval(-2 * hour)) { try seal($0, key: legacy) }
        let noManifest     = try self.stage(in: container, createdAt: .now, sealing: nil)
        let corrupt        = try self.stage(in: container, createdAt: .now, sealing: nil, corrupt: true)

        ShareSession.sweep(in: container, keyManager: manager)

        #expect(self.exists(freshCurrent, in: container) && self.exists(freshLegacy, in: container) && self.exists(freshClassical, in: container),
                "fresh sessions stay, whichever key sealed them")
        #expect(!self.exists(staleCurrent, in: container) && !self.exists(staleLegacy, in: container), "stale sessions go")
        #expect(!self.exists(noManifest, in: container) && !self.exists(corrupt, in: container), "so do half-written and unreadable ones")
    }
}

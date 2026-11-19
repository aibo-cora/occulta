//
//  EraseAllDataFailureTests.swift
//  OccultaTests
//
//  Bug 209: Erase All Data deletes rows first and keys last, with no `defer`, and Settings calls it with `try?`. A row
//  step that throws therefore leaves every key, and the App Group's staged files, in place. Deleting the keys is what
//  makes the rows that remain unreadable, so it must happen whatever a row step does.
//
//  Runs on Keychain items of the test's own (`Manager.Key(items:)`, as `KeyResealEraseTests` does), never the
//  Simulator's canonical ones.
//

import Testing
import Foundation
import SwiftData
import LocalAuthentication

@testable import Occulta

/// A contact manager whose row step fails, as a failed SwiftData save would.
private final class FailingContactManager: ContactManager {
    struct RowStepFailed: Error {}
    override func deleteAllContacts() throws { throw RowStepFailed() }
}

@Suite("Erase All Data — a failed row step (Bug 209)", .ambientFrozenTestKeyManager)
@MainActor
struct EraseAllDataFailureTests {

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

    @Test("A row step that throws still deletes the keys and the App Group's staged files",
          .enabled(if: keychainAvailable() && sharedKeychainAvailable()))
    func rowStepThrows_keysAreStillDeleted() throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)

        let suffix = UUID().uuidString
        let items = Manager.Key.Items(
            enclaveTags: [],
            tierSecretU: "test.erasefail.ru.\(suffix)", tierSecretB: "test.erasefail.rb.\(suffix)",
            recordU: "test.erasefail.pqu.\(suffix)", recordB: "test.erasefail.pqb.\(suffix)"
        )
        let erasing = Manager.Key(items: items)
        try erasing.createTierSecretIfAbsent(.deviceUnlock, account: items.tierSecretU)
        try erasing.createTierSecretIfAbsent(.biometry(LAContext()), account: items.tierSecretB)
        try erasing.createTierPQRecordIfAbsent(account: items.recordU, provider: nil)
        try erasing.createTierPQRecordIfAbsent(account: items.recordB, provider: nil)
        let accounts = [items.tierSecretU, items.tierSecretB, items.recordU, items.recordB]
        defer { _ = erasing.deleteAllKeys() }

        let staging = ShareStagingKeyManager(
            keyTag: "test.erasefail.key.\(suffix)",
            tierSecretAccount: "test.erasefail.rs.\(suffix)", tierPQRecordAccount: "test.erasefail.pqs.\(suffix)",
            postQuantum: { nil }
        )
        try staging.createTierSecretIfAbsent()
        try staging.createTierPQRecordIfAbsent()
        defer { _ = staging.deleteKey() }

        // An App Group of the test's own, with a staged share in it.
        let group = FileManager.default.temporaryDirectory.appendingPathComponent("erasefail-group-\(suffix)", isDirectory: true)
        let pending = group.appendingPathComponent("pending", isDirectory: true)
        try FileManager.default.createDirectory(at: pending, withIntermediateDirectories: true)
        try Data("sealed".utf8).write(to: pending.appendingPathComponent("manifest.enc"))
        defer { try? FileManager.default.removeItem(at: group) }
        // A Drafts directory of the test's own, with an attachment in it: the step after the one that fails.
        let drafts = FileManager.default.temporaryDirectory.appendingPathComponent("erasefail-drafts-\(suffix)", isDirectory: true)
        try FileManager.default.createDirectory(at: drafts, withIntermediateDirectories: true)
        try Data("sealed".utf8).write(to: drafts.appendingPathComponent("a.jpg"))
        defer { try? FileManager.default.removeItem(at: drafts) }

        #expect(accounts.allSatisfy { self.keychainHas(account: $0) }, "precondition: the test's own items exist")
        #expect(try staging.tierSecret() != nil, "precondition: r_S exists")

        let store = try LegacyStore(keys: keys)
        let security = Manager.Security(modelContainer: store.container, keyManager: keys)
        let app = Manager.App(
            contacts: FailingContactManager(modelContainer: store.container, security: security),
            vault: VaultManager(modelContainer: store.container, keyManager: keys)
        )

        #expect(throws: FailingContactManager.RowStepFailed.self) {
            try app.eraseAllData(erasePrekeys: {}, draftsRoot: drafts, stagingContainer: group, staging: staging, keys: erasing)
        }

        let left = accounts.filter { self.keychainHas(account: $0) }
        #expect(left.isEmpty, "Keychain items left after a failed row step: \(left)")
        #expect(try staging.tierSecret() == nil, "r_S left after a failed row step")
        #expect(!FileManager.default.fileExists(atPath: pending.path), "the App Group's staged share left after a failed row step")
        #expect(!FileManager.default.fileExists(atPath: drafts.path), "the row steps after the one that failed did not run")
    }
}

// MARK: - A key deletion that reports failure

@Suite("Erase All Data — a key that could not be deleted (Bug 209 follow-up)", .ambientFrozenTestKeyManager)
@MainActor
struct EraseAllDataKeyResultTests {

    private func makeApp() throws -> Manager.App {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        let store = try LegacyStore(keys: keys)
        let security = Manager.Security(modelContainer: store.container, keyManager: keys)
        return Manager.App(
            contacts: ContactManager(modelContainer: store.container, security: security),
            vault: VaultManager(modelContainer: store.container, keyManager: keys)
        )
    }

    private func erase(
        _ app: Manager.App, staging: Bool, keys: Bool, ran: Ran
    ) throws {
        let drafts = FileManager.default.temporaryDirectory.appendingPathComponent("erasekeys-drafts-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: drafts) }
        // Items of the test's own, and closures that stand in for the deletions: nothing here touches the Keychain.
        let suffix = UUID().uuidString
        let items = Manager.Key.Items(
            enclaveTags: [], tierSecretU: "test.erasekeys.ru.\(suffix)", tierSecretB: "test.erasekeys.rb.\(suffix)",
            recordU: "test.erasekeys.pqu.\(suffix)", recordB: "test.erasekeys.pqb.\(suffix)"
        )
        try app.eraseAllData(
            erasePrekeys: {}, draftsRoot: drafts, stagingContainer: nil, keys: Manager.Key(items: items),
            deleteStagingKey: { _ in ran.staging = true; return staging },
            deleteKeys: { _ in ran.keys = true; return keys }
        )
    }

    final class Ran { var staging = false; var keys = false }

    @Test("A key deletion that returns false is a failure, so the Settings alert covers it")
    func keysReturnedFalse() throws {
        let ran = Ran()
        #expect(throws: Manager.App.EraseError.self) { try self.erase(try self.makeApp(), staging: true, keys: false, ran: ran) }
        #expect(ran.staging && ran.keys, "both deletions ran: one failing must not skip the other")
    }

    @Test("A share-staging key deletion that returns false is a failure too")
    func stagingReturnedFalse() throws {
        let ran = Ran()
        #expect(throws: Manager.App.EraseError.self) { try self.erase(try self.makeApp(), staging: false, keys: true, ran: ran) }
        #expect(ran.staging && ran.keys)
    }

    @Test("When both deletions succeed nothing is thrown")
    func bothSucceed() throws {
        try self.erase(try self.makeApp(), staging: true, keys: true, ran: Ran())
    }
}

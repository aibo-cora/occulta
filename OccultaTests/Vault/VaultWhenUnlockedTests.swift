//
//  VaultWhenUnlockedTests.swift
//  OccultaTests
//
//  `VaultManager.whenUnlocked` runs a restore with the vault unlocked, asking for Face ID first if
//  it has locked. The prompt itself can't run in a test; what is pinned is that an unlocked vault
//  runs the action at once, and a locked one never runs it before the prompt succeeds.
//

import Testing
import Foundation
import LocalAuthentication
import SwiftData
@testable import Occulta

@MainActor
private func makeVault() throws -> VaultManager {
    let schema = Schema([VaultEntry.self, BackupEncryptionKey.self, Vault.self, PendingShamirSecretRestore.self])
    let container = try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
    return VaultManager(modelContainer: container, keyManager: TestKeyManager())
}

@Suite("whenUnlocked — restore after the vault may have locked")
@MainActor
struct VaultWhenUnlockedTests {

    @Test("An unlocked vault runs the action at once, with no prompt")
    func unlockedRunsImmediately() throws {
        let vault = try makeVault()
        vault.unlock(context: LAContext())
        var ran = false

        vault.whenUnlocked { ran = true }

        #expect(ran)
    }

    /// The restore must not run against a locked vault: it waits for Face ID, and never runs if
    /// the prompt fails or is cancelled.
    @Test("A locked vault doesn't run the action before Face ID")
    func lockedWaitsForFaceID() throws {
        let vault = try makeVault()
        #expect(!vault.isUnlocked)
        var ran = false

        vault.whenUnlocked { ran = true }

        #expect(!ran)
        #expect(!vault.isUnlocked)
    }
}

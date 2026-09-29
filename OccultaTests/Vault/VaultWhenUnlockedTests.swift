//
//  VaultWhenUnlockedTests.swift
//  OccultaTests
//
//  `VaultManager.whenUnlocked` runs a restore with the vault unlocked, asking for Face ID first if
//  it has locked. What is pinned is that an unlocked vault runs the action at once.
//
//  The locked path is not tested here: it calls `LAContext.evaluatePolicy`, and on a host with
//  Face ID enrolled that raises a real system prompt in the test process, which resigns the app
//  active and locks every `VaultManager` in it, breaking concurrent vault tests (found by the
//  branch code review). It is a device check instead (`decisions.md`, "Restore discoverability",
//  the 2026-09-25 note).
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
}

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
@testable import OccultaFormats

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

/// Separate minimal container for standing up a `Manager.Security` in isolation —
/// `visibleVaultEntries(from:)` is a pure function of the passed `[VaultEntry]` plus
/// `currentDepth`, so it doesn't need to share a container/context with the
/// `VaultManager` that created the entries.
@MainActor
private func makeContainer() throws -> ModelContainer {
    let schema = Schema([
        Group.self,
        Contact.Profile.self, Contact.Profile.PhoneNumber.self, Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self, Contact.Profile.Key.self,
    ])
    return try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
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

        // Well past the 50 ms deadline, so another test holding the main thread in a full run
        // can't leave this check running before the timer (Bug 136).
        try await Task.sleep(for: .seconds(1))
        #expect(vm.isUnlocked == false, "vault must auto-lock after inactivity timeout")
    }

    /// Bug 140: locking ends the session, including the depth-scoped values computed for it.
    /// `backupStaleness` was the one `lock()` left behind.
    @Test("lock clears the backup staleness report along with the other depth-scoped values")
    func lockClearsStaleness() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())
        vm.backupStaleness = VaultManager.BackupStalenessReport(bekRotated: false, newEntryCount: 1, trusteeSetChanged: false)

        vm.lock()

        #expect(vm.backupStaleness == nil)
        #expect(vm.backupErosion == nil)
        #expect(!vm.postRestorePromptPending)
    }

    @Test("unlock starts the session: the lock is due one timeout from now")
    func unlockSetsDeadline() throws {
        let (vm, _) = try makeVaultManager(inactivityTimeout: 60)
        let start = Date()

        vm.unlock(context: LAContext())

        let deadline = try #require(vm.inactivityDeadline)
        #expect(abs(deadline.timeIntervalSince(start) - 60) < 1)
    }

    /// Bug 136: deriving the key is not vault activity. It used to reset the timer, so every
    /// automatic use of the key (the save hook, incoming and outgoing messages, redraws)
    /// kept the vault unlocked.
    @Test("currentKey doesn't extend the session")
    func currentKeyDoesNotExtend() async throws {
        let (vm, _) = try makeVaultManager(inactivityTimeout: 60)
        vm.unlock(context: LAContext())
        try await Task.sleep(for: .milliseconds(50))

        let before = try #require(vm.inactivityDeadline)
        _ = try vm.currentKey()
        let after = try #require(vm.inactivityDeadline)

        #expect(after == before)
    }

    /// Bug 136 as filed: a save anywhere ran `recomputeRecoveryHealth()` through the save hook,
    /// which used the key and so pushed the lock back.
    @Test("A save on an unrelated context doesn't extend the session")
    func unrelatedSaveDoesNotExtend() async throws {
        let (vm, _) = try makeVaultManager(inactivityTimeout: 60)
        vm.unlock(context: LAContext())
        try await Task.sleep(for: .milliseconds(50))
        let before = try #require(vm.inactivityDeadline)

        let (other, _) = try makeVaultManager()
        other.unlock(context: LAContext())
        _ = try other.addEntry(label: "elsewhere", content: Data("x".utf8), type: .note)
        // The hook is delivered on the main queue; let it run.
        try await Task.sleep(for: .milliseconds(200))

        #expect(vm.inactivityDeadline == before)
    }

    /// Bugs 135, 136: the vault screens call this for the person's deliberate actions. Read
    /// from the timer's own deadline, before and after in one synchronous step, so nothing can
    /// interleave. That the lock fires at its deadline is `locksAfterInactivity`.
    @Test("extendSession pushes the inactivity lock back while unlocked")
    func extendSessionPushesLockBack() async throws {
        let (vm, _) = try makeVaultManager(inactivityTimeout: 60)
        vm.unlock(context: LAContext())
        try await Task.sleep(for: .milliseconds(50))

        let before = try #require(vm.inactivityDeadline)
        vm.extendSession()
        let after = try #require(vm.inactivityDeadline)

        #expect(after > before)
    }

    @Test("extendSession on a locked vault leaves it locked, with no timer")
    func extendSessionWhileLockedDoesNothing() throws {
        let (vm, _) = try makeVaultManager(inactivityTimeout: 60)

        vm.extendSession()

        #expect(!vm.isUnlocked)
        #expect(vm.inactivityDeadline == nil)
    }
}

// MARK: - Phase 4: CRUD

@Suite("Phase 4 — VaultManager CRUD")
@MainActor struct VaultManagerCRUDTests {

    /// The Vault tab builds its rows with this once per data change. It used to decrypt each row
    /// in the row's own body, deriving the vault key once or more per row on every redraw.
    @Test("entryListRows decrypts every row with one vault-key derivation")
    func entryListRowsDerivesOnce() throws {
        let (vm, km) = try makeVaultManager()
        vm.unlock(context: LAContext())
        let seed  = try vm.addEntry(label: "Seed", content: Data("a b c".utf8), type: .seedPhrase)
        let note  = try vm.addEntry(label: "Note", content: Data("hello".utf8), type: .note)
        let before = km.vaultKeyDerivations

        let rows = vm.entryListRows(for: [seed, note])

        #expect(km.vaultKeyDerivations - before == 1)
        #expect(rows.map(\.id) == [seed.id, note.id])
        #expect(rows.map(\.label) == ["Seed", "Note"])
        #expect(rows.map(\.type) == [.seedPhrase, .note])
        #expect(rows[0].createdAt == seed.createdAt)
    }

    @Test("entryListRows is empty while the vault is locked")
    func entryListRowsLocked() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())
        let entry = try vm.addEntry(label: "Seed", content: Data("a".utf8), type: .seedPhrase)
        vm.lock()

        #expect(vm.entryListRows(for: [entry]).isEmpty)
    }

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

    @Test("Field discriminator — cross-field ciphertext swap is rejected")
    func fieldDiscriminatorPreventsSwap() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())

        let entry = try vm.addEntry(label: "test", content: Data("x".utf8), type: .note)

        // Swap encryptedLabel and encryptedContent. Each was sealed with a different
        // field discriminator in the AAD, so GCM authentication rejects the swap.
        let tmp = entry.encryptedLabel
        entry.encryptedLabel   = entry.encryptedContent
        entry.encryptedContent = tmp

        #expect(throws: VaultManager.VaultError.decryptionFailed) {
            _ = try vm.decryptContent(for: entry)
        }
    }

    /// `fetchAllEntries` filters orphans with the ambient local key (Bug 110), so this and the
    /// next test run under `.ambientTestKeyManager`, which supplies it.
    @Test("fetchAllEntries returns inserted entries", .ambientTestKeyManager)
    func fetchAll() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())

        _ = try vm.addEntry(label: "A", content: Data(), type: .note)
        _ = try vm.addEntry(label: "B", content: Data(), type: .keyToken)

        let entries = try vm.fetchAllEntries()
        #expect(entries.count == 2)
    }

    @Test("deleteEntry removes the entry", .ambientTestKeyManager)
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

// MARK: - Depth-aware visibility
//
// Covers the fix for Vault+NewEntrySheet never passing currentDepth — see
// Docs/Bugs/v1.10.0/Decoy-Vault-Entries-Unreachable-New-Entry-Sheet-Ignores-Depth.md.
// Note what this fix does NOT achieve: visibleThroughDepth is a one-directional
// ceiling (visible from depth 0 up through N, hidden beyond N) — the same shape as
// Contact.Profile's sensitivity model, not Group's independent-per-depth-array decoy
// model. An entry stamped depth 2 is visible at depths 0, 1, and 2; it never hides
// from the real (depth 0) view. The fix here only stops an entry created while at a
// duress depth from being wrongly stamped 0 (which would hide it even at the depth
// it was just created at) — it does not create "decoy-only" vault entries.
//
// visibleThroughDepth is sealed under the global local-DB key (same as
// Contact.Profile's field of the same name), not VaultManager's injected key
// manager, so these run under `.ambientTestKeyManager`, like the Group tests.

@Suite("VaultEntry — depth-aware visibility")
@MainActor struct VaultEntryDepthVisibilityTests {

    @Test(.ambientTestKeyManager) func addEntry_stampsGivenDepth_readableBack() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())

        let entry = try vm.addEntry(label: "entry", content: Data(), type: .note, currentDepth: 2)

        guard let data = entry.visibleThroughDepth,
              let plain = data.decrypt(),
              let value = DepthCodec.decode(plain)
        else { Issue.record("visibleThroughDepth did not decrypt"); return }
        #expect(value == 2)
    }

    @Test(.ambientTestKeyManager) func addEntry_defaultsToDepth0_whenNotSpecified() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())

        let entry = try vm.addEntry(label: "entry", content: Data(), type: .note)

        guard let data = entry.visibleThroughDepth,
              let plain = data.decrypt(),
              let value = DepthCodec.decode(plain)
        else { Issue.record("visibleThroughDepth did not decrypt"); return }
        #expect(value == 0)
    }

    // visibleThroughDepth is an exact-depth match, not a ceiling: an entry is
    // visible only at exactly the depth it was created at (nil = never
    // classified — visible at the real depth 0 only, since Bug 113; hidden at
    // every duress depth). Deliberately not "visible 0 through N" — see
    // Docs/Bugs/v1.10.0/Vault-Entries-Created-At-A-Duress-Depth-Leak-Into-The-Real-Vault.md
    // for why a ceiling let an entry created at a duress depth leak into every
    // shallower depth, including the real depth 0.
    //
    // These test `Manager.Security.visibleVaultEntries(from:)` directly — the same
    // function `Vault+Tab.swift`'s `visibleEntries` calls. Bug 113: the previous
    // per-entry `isEntryVisible(_:)` this suite tested was itself correct, but the
    // SwiftUI call site never invoked it at depth 0, so none of this coverage ever
    // reached production. Testing the shared function both suites call closes that gap.

    @Test(.ambientTestKeyManager) func visibleVaultEntries_stampedDepth0_onlyVisibleAtDepth0() throws {
        let (vm, _)  = try makeVaultManager()
        vm.unlock(context: LAContext())
        let entry    = try vm.addEntry(label: "entry", content: Data(), type: .note, currentDepth: 0)

        let security = try Manager.Security(modelContainer: try makeContainer(), keyManager: TestKeyManager())

        security.applyVerifyState(for: .normal(depth: 0))
        #expect(security.visibleVaultEntries(from: [entry]).map(\.id) == [entry.id])
        security.applyVerifyState(for: .normal(depth: 1))
        #expect(security.visibleVaultEntries(from: [entry]).isEmpty, "an entry stamped depth 0 must hide at any other depth")
        security.applyVerifyState(for: .normal(depth: 3))
        #expect(security.visibleVaultEntries(from: [entry]).isEmpty)
    }

    @Test(.ambientTestKeyManager) func visibleVaultEntries_stampedDepthN_onlyVisibleAtN_hiddenElsewhere() throws {
        let (vm, _)  = try makeVaultManager()
        vm.unlock(context: LAContext())
        let entry    = try vm.addEntry(label: "entry", content: Data(), type: .note, currentDepth: 2)

        let security = try Manager.Security(modelContainer: try makeContainer(), keyManager: TestKeyManager())

        security.applyVerifyState(for: .normal(depth: 0))
        #expect(security.visibleVaultEntries(from: [entry]).isEmpty,
                "an entry stamped depth 2 must NOT leak into the real (depth 0) view — Bug 113")
        security.applyVerifyState(for: .normal(depth: 2))
        #expect(security.visibleVaultEntries(from: [entry]).map(\.id) == [entry.id], "visible at its own stamped depth")
        security.applyVerifyState(for: .normal(depth: 3))
        #expect(security.visibleVaultEntries(from: [entry]).isEmpty, "hidden at any other depth too, including deeper ones")
    }

    /// A legacy entry with no `visibleThroughDepth` (pre-dating the field) is a real,
    /// persistent state — not swept away before a duress depth exists (confirmed by grep:
    /// no code anywhere stamps existing nil entries; `PQmigration.migrateDepthFieldsToFixedWidth`'s
    /// own doc comment calls it "a legitimate steady state"). It must fail closed — hidden —
    /// at any duress depth. `entriesVisible` (backup export) needs the opposite answer at
    /// the real depth it runs at — see `VaultBackupRoundTripTests` for that side, and Bug
    /// 113's write-up for why `entriesVisible` itself may share this gap at a duress depth.
    @Test func visibleVaultEntries_legacyNilVisibleThroughDepth_hiddenAtRestrictedDepth() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())
        let entry   = try vm.addEntry(label: "pre-existing", content: Data(), type: .note)
        entry.visibleThroughDepth = nil

        let security = try Manager.Security(modelContainer: try makeContainer(), keyManager: TestKeyManager())
        security.applyVerifyState(for: .normal(depth: 3))
        #expect(security.visibleVaultEntries(from: [entry]).isEmpty,
                "a row with no visibleThroughDepth must fail closed at a restricted depth")
    }

    /// The other half of the case above, and the specific behavior Bug 113 adds: at the
    /// real depth 0, a legacy nil entry must stay visible — only the restricted-depth side
    /// needed to change.
    @Test(.ambientTestKeyManager) func visibleVaultEntries_legacyNilVisibleThroughDepth_visibleAtRealDepth0() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())
        let entry   = try vm.addEntry(label: "pre-existing", content: Data(), type: .note)
        entry.visibleThroughDepth = nil

        let security = try Manager.Security(modelContainer: try makeContainer(), keyManager: TestKeyManager())
        security.applyVerifyState(for: .normal(depth: 0))
        #expect(security.visibleVaultEntries(from: [entry]).map(\.id) == [entry.id],
                "a legacy unclassified entry must stay visible at the real depth 0")
    }

    /// Bug 113's second harm: an entry orphaned by `orphanVaultEntries` (Secure Mode
    /// deactivation's eviction sweep) must never reappear, even at the depth its
    /// (untouched) `visibleThroughDepth` stamp still names — orphan status wins.
    @Test(.ambientTestKeyManager) func visibleVaultEntries_excludesOrphanedEntries() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())
        let entry   = try vm.addEntry(label: "orphaned", content: Data(), type: .note, currentDepth: 0)
        entry.deletionToken = try VaultEntry.orphanedToken.encrypt()

        let security = try Manager.Security(modelContainer: try makeContainer(), keyManager: TestKeyManager())
        security.applyVerifyState(for: .normal(depth: 0))
        #expect(security.visibleVaultEntries(from: [entry]).isEmpty,
                "an orphaned entry must not show even at the depth it was originally stamped with")
    }

    @Test(.ambientTestKeyManager) func visibleVaultEntries_endToEnd_exactMatchOnly() throws {
        let (vm, _) = try makeVaultManager()
        vm.unlock(context: LAContext())

        let real  = try vm.addEntry(label: "real",  content: Data(), type: .note, currentDepth: 0)
        let decoy = try vm.addEntry(label: "decoy", content: Data(), type: .note, currentDepth: 3)

        let security = try Manager.Security(modelContainer: try makeContainer(), keyManager: TestKeyManager())
        let all      = try vm.fetchAllEntries()

        security.applyVerifyState(for: .normal(depth: 0))
        var visible = security.visibleVaultEntries(from: all)
        #expect(visible.map(\.id) == [real.id], "at the real depth, only the real entry shows — the duress-depth entry must not leak in")

        security.applyVerifyState(for: .normal(depth: 1))
        visible = security.visibleVaultEntries(from: all)
        #expect(visible.isEmpty, "at depth 1, neither entry was stamped here")

        security.applyVerifyState(for: .normal(depth: 3))
        visible = security.visibleVaultEntries(from: all)
        #expect(visible.map(\.id) == [decoy.id], "at depth 3, only the entry stamped exactly there shows")

        security.applyVerifyState(for: .normal(depth: 4))
        visible = security.visibleVaultEntries(from: all)
        #expect(visible.isEmpty, "at depth 4, neither entry was stamped here")
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

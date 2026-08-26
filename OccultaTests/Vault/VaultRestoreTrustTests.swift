//
//  VaultRestoreTrustTests.swift
//  OccultaTests
//
//  Bug 94 — the restore path lets attacker-supplied material authenticate itself.
//  Bug 96 — traps and unbounded growth on the same path.
//
//  Needs no Secure Enclave: `TestKeyManager` supplies the vault key and the recovery
//  buffer key, so every test here runs anywhere.
//
//  Bug 96's two trap tests were originally written `.disabled` rather than wrapped in
//  `withKnownIssue`: `UInt8(300)` and `UInt64(-1.0)` crash the process rather than throw,
//  and a crash is not an issue Swift Testing can record — it takes the whole run with it,
//  reporting the disguised green "Executed 0 tests" that CLAUDE.md documents for
//  `Manager.Key` in `setUpWithError`. Both traps are fixed now (guards in `importBackup`,
//  ahead of the conversions that used to crash) and the tests run as ordinary assertions.
//

import Testing
import Foundation
import CryptoKit
import LocalAuthentication
import SwiftData
@testable import Occulta

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

// MARK: - Harness

/// Duplicated from `Vault+Manager+Backup.swift`, where both are `private static`.
/// If either changes there, these tests go quietly wrong rather than failing — the
/// AAD would produce `decryptionFailed` and the paths would clean nothing.
private let backupFileAAD = Data("occulta-backup-v1".utf8)
private let appSupport    = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
private let pendingRestoreURL       = appSupport.appendingPathComponent("backup-import-cache.occbak")
private let pendingRestoreShardsURL = appSupport.appendingPathComponent("backup-import-cache-shards.dat")

/// Both restore files live at fixed global paths, so a leftover from one test changes
/// what `unlock(context:)` does in the next — it calls `refreshPendingRestoreState()`
/// and then `attemptBEKRestore()`. Clear them around every test in this suite.
private func clearRestoreFiles() {
    try? FileManager.default.removeItem(at: pendingRestoreURL)
    try? FileManager.default.removeItem(at: pendingRestoreShardsURL)
}

private func makeContainer() throws -> ModelContainer {
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
    return try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
}

/// A vault with a BEK and enough *confirmed* shards that `exportBackup` will run.
/// Returns the shard attributes too — the restore path consumes them, and
/// `prepareBEKShards` is the only way to obtain shares that reconstruct this BEK.
@MainActor
private func makeBackupReadyVault() throws -> (vault: VaultManager,
                                               container: ModelContainer,
                                               shards: [SignedAttribute]) {
    let container = try makeContainer()
    try? FileManager.default.createDirectory(at: appSupport, withIntermediateDirectories: true)

    let vault = VaultManager(modelContainer: container, keyManager: TestKeyManager())
    vault.unlock(context: LAContext(), currentDepth: 0)
    try vault.setupBEK()

    let recipients = (0..<2).map { i -> Contact.Profile in
        let p = Contact.Profile(
            identifier: "trustee-\(i)", givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        container.mainContext.insert(p)
        return p
    }
    try container.mainContext.save()

    let shards = try vault.prepareBEKShards(threshold: 2, recipients: recipients)
    for shard in shards {
        try vault.updateBEKShardStatus(attributeID: shard.id, to: .confirmed)
    }
    return (vault, container, shards)
}

/// A vault with no BEK at all — the genuine new-device restore target. `setupBEK()` has
/// exactly one production caller (`Vault+ShardSetup.swift:553`, `.backup` mode only), so
/// a device that has never configured backup reaches a restore in precisely this state.
@MainActor
private func makeFreshVault() throws -> (vault: VaultManager, container: ModelContainer) {
    let container = try makeContainer()
    try? FileManager.default.createDirectory(at: appSupport, withIntermediateDirectories: true)
    let vault = VaultManager(modelContainer: container, keyManager: TestKeyManager())
    vault.unlock(context: LAContext(), currentDepth: 0)
    return (vault, container)
}

@MainActor
private func bekBytes(of vault: VaultManager) throws -> Data {
    var bytes = Data()
    try vault.currentBEK().withUnsafeBytes { bytes = Data($0) }
    return bytes
}

// MARK: - Bug 94

@Suite("Bug 94 — restore must not trust attacker-supplied material", .serialized)
@MainActor
struct VaultRestoreTrustTests {

    /// The attack, end to end, in the one call that decides it.
    ///
    /// `attemptBEKRestore` passes `ownerIdentity: nil`, so the GCM tag is the only check —
    /// and it only proves the shards match the file. Here the *same* party produced both,
    /// so the tag proves nothing about whose backup this is. Remedy 1 (`reconstructBEK`'s
    /// step 0) refuses before any of that runs, purely because the victim already has a row.
    @Test("A foreign backup and its own shards must not replace an existing BEK")
    func foreignShardsCannotReplaceExistingBEK() throws {
        clearRestoreFiles()
        defer { clearRestoreFiles() }

        let victim   = try makeBackupReadyVault()
        let attacker = try makeBackupReadyVault()

        let victimBEKBefore = try bekBytes(of: victim.vault)
        let attackerBEK     = try bekBytes(of: attacker.vault)
        #expect(victimBEKBefore != attackerBEK, "the two vaults must hold different BEKs")

        // The attacker seals their own file under their own BEK and splits that BEK.
        // Nothing here is forged — it is simply not the victim's.
        let attackerBackup = try attacker.vault.exportBackup(currentDepth: 0)

        #expect(throws: VaultManager.BackupError.bekAlreadyPresent) {
            try victim.vault.reconstructBEK(
                shards:        attacker.shards,
                backupData:    attackerBackup,
                ownerIdentity: nil
            )
        }

        let victimBEKAfter = try bekBytes(of: victim.vault)
        #expect(victimBEKAfter == victimBEKBefore, """
            The victim's BEK was replaced by one reconstructed from a stranger's shards. \
            Every backup file sealed under the old key is now permanently unrestorable, \
            and the trustees' real shards reconstruct a key that matches nothing.
            """)
    }

    /// The second half of the same harm: once the BEK has been replaced, `importBackup`
    /// decrypts the attacker's file with it and inserts their rows into the user's vault.
    /// With remedy 1 in place, `reconstructBEK` never gets far enough to replace anything,
    /// so `importBackup` is never even reached on this path — asserted directly below rather
    /// than via `attemptBEKRestore`, since that already stops calling it once the first throws.
    @Test("A foreign backup's entries must not be inserted into an existing vault")
    func foreignEntriesAreNotInserted() throws {
        clearRestoreFiles()
        defer { clearRestoreFiles() }

        let victim   = try makeBackupReadyVault()
        let attacker = try makeBackupReadyVault()

        _ = try victim.vault.addEntry(label: "mine", content: Data("mine".utf8), type: .note)
        _ = try attacker.vault.addEntry(label: "planted", content: Data("planted".utf8), type: .note)

        let attackerBackup = try attacker.vault.exportBackup(currentDepth: 0)

        #expect(throws: VaultManager.BackupError.bekAlreadyPresent) {
            try victim.vault.reconstructBEK(shards: attacker.shards,
                                            backupData: attackerBackup, ownerIdentity: nil)
        }
        // importBackup still decrypts with whatever BEK is installed — the victim's own,
        // unchanged — so the attacker's ciphertext must fail to open at all, not just fail
        // to name the entry "planted".
        #expect(throws: VaultManager.BackupError.decryptionFailed) {
            try victim.vault.importBackup(attackerBackup, currentDepth: 0)
        }

        let labels = try ModelContext(victim.container)
            .fetch(FetchDescriptor<VaultEntry>())
            .compactMap { try? victim.vault.decryptLabelPayload(for: $0).label }

        #expect(!labels.contains("planted"), """
            A stranger's vault entry was inserted into the user's vault. Labels now: \
            \(labels.sorted()).
            """)
    }

    /// **The regression guard, and the reason it outranks the two above.**
    ///
    /// Bug 94's remedy refuses to overwrite an existing BEK. If that guard is written a
    /// notch too wide it also blocks the only path this system exists for — a device that
    /// lost everything, restoring from trustees. That failure is silent, and surfaces when
    /// the user has no device left to discover it on. This test must pass before the fix
    /// and after it.
    /// The only test in this suite that needs a real Enclave. The other thirteen assert that
    /// something is *refused*, and a refusal still happens when the depth stamp silently
    /// fails to seal. This one asserts a restore succeeds end to end, which needs
    /// `importBackup`'s stamp to actually be written — see `VaultBackupRoundTripTests` for
    /// why the injected key manager does not reach it.
    @Test("A device with no BEK can still restore — the new-device path stays open",
          .enabled(if: secureEnclaveAvailable()))
    func freshDeviceCanStillRestore() throws {
        clearRestoreFiles()
        defer { clearRestoreFiles() }

        let owner = try makeBackupReadyVault()
        _ = try owner.vault.addEntry(label: "recovered", content: Data("recovered".utf8), type: .note)
        let backup    = try owner.vault.exportBackup(currentDepth: 0)
        let ownerBEK  = try bekBytes(of: owner.vault)

        // The replacement device: vault set up, backup never configured, so no BEK row.
        let fresh = try makeFreshVault()
        #expect((try? fresh.vault.currentBEK()) == nil, "a fresh device must start with no BEK")

        try fresh.vault.reconstructBEK(shards: owner.shards, backupData: backup, ownerIdentity: nil)
        #expect(try bekBytes(of: fresh.vault) == ownerBEK,
                "reconstruction must install the owner's BEK on a device that had none")

        try fresh.vault.importBackup(backup, currentDepth: 0)
        let labels = try ModelContext(fresh.container)
            .fetch(FetchDescriptor<VaultEntry>())
            .compactMap { try? fresh.vault.decryptLabelPayload(for: $0).label }
        #expect(labels.contains("recovered"), """
            The new-device restore path is broken. This is the path the whole shard system \
            exists for, and its failure mode is discovered only when the device is gone.
            """)
    }

    /// `storePendingRestore` now refuses outright when a BEK already exists (Bug 93's own
    /// two-signal check, reusing remedy 1's `fetchDecodedBEK`) — a hostile file on an
    /// existing-BEK device is rejected before it is ever written, not armed-then-cleaned-up.
    /// This is what `existingBEKRestoreDoesNotStallForever` below used to test by calling
    /// `storePendingRestore` directly; that path is no longer reachable, so it now
    /// constructs its scenario by writing straight to disk instead.
    @Test("storePendingRestore refuses outright when a BEK already exists")
    func storePendingRestoreRefusesWhenBEKAlreadyExists() throws {
        clearRestoreFiles()
        defer { clearRestoreFiles() }

        let victim   = try makeBackupReadyVault()
        let attacker = try makeBackupReadyVault()
        let attackerBackup = try attacker.vault.exportBackup(currentDepth: 0)

        #expect(throws: VaultManager.BackupError.alreadyProcessed) {
            try victim.vault.storePendingRestore(attackerBackup, currentDepth: 0)
        }
        #expect(!FileManager.default.fileExists(atPath: pendingRestoreURL.path),
                "nothing should be written at all — refused before the write, not after")
        #expect(!victim.vault.pendingRestoreActive)
    }

    /// The third outcome of the two-signal check, and the baseline the two refusal tests
    /// are measured against: neither signal is true, so the call must succeed silently.
    @Test("storePendingRestore accepts a genuinely new file when nothing is pending or done")
    func storePendingRestoreAcceptsAGenuinelyNewFile() throws {
        clearRestoreFiles()
        defer { clearRestoreFiles() }

        let owner  = try makeBackupReadyVault()
        let backup = try owner.vault.exportBackup(currentDepth: 0)

        let fresh = try makeFreshVault()
        try fresh.vault.storePendingRestore(backup, currentDepth: 0)

        #expect(FileManager.default.fileExists(atPath: pendingRestoreURL.path))
        #expect(fresh.vault.pendingRestoreActive)
    }

    /// Found while writing this test: the original ordering wrote the second file's bytes
    /// to disk *before* checking whether one was already pending, then threw afterward — so
    /// a second, different `.occbak` silently replaced a genuine in-flight restore while the
    /// caller saw the same reassuring `alreadyProcessed`. Fixed to check-then-refuse,
    /// symmetric with the BEK-exists branch above. Asserts both halves: the throw, and that
    /// the original bytes on disk are untouched by the second call.
    @Test("storePendingRestore refuses a second file without overwriting the one already pending")
    func storePendingRestoreRefusesWithoutOverwritingWhenAlreadyPending() throws {
        clearRestoreFiles()
        defer { clearRestoreFiles() }

        let firstOwner  = try makeBackupReadyVault()
        let secondOwner = try makeBackupReadyVault()
        let firstBackup  = try firstOwner.vault.exportBackup(currentDepth: 0)
        let secondBackup = try secondOwner.vault.exportBackup(currentDepth: 0)
        #expect(firstBackup != secondBackup,
                "the two backups must actually differ for this test to mean anything")

        let fresh = try makeFreshVault()
        try fresh.vault.storePendingRestore(firstBackup, currentDepth: 0)

        #expect(throws: VaultManager.BackupError.alreadyProcessed) {
            try fresh.vault.storePendingRestore(secondBackup, currentDepth: 0)
        }

        let onDisk = try Data(contentsOf: pendingRestoreURL)
        #expect(onDisk == firstBackup, """
            The second call overwrote the genuinely pending restore with a different file's \
            bytes before throwing — the caller sees "already processed" as if nothing changed, \
            while the recovery target was silently replaced underneath it.
            """)
    }

    /// The consequence of remedy 1 that motivated it: on an existing-BEK device, every group
    /// `reconstructBEK` sees now fails immediately via `bekAlreadyPresent` — so the "success"
    /// branch that clears `pendingRestoreActive` and deletes the restore files can never run.
    /// Without the early check in `attemptBEKRestore`, a single stale `.occbak` would leave
    /// the device permanently in "restoring" state: the banner never clears, and every future
    /// shard arrival keeps appending to a file nothing will ever read successfully again.
    ///
    /// Constructed by writing directly to the restore paths, bypassing `storePendingRestore` —
    /// that path now refuses outright on an existing-BEK device (see the test above), so this
    /// scenario is only reachable the way it would be in practice: a file already pending
    /// *before* a BEK existed (attacker-armed, or simply stale), with `setupBEK()` called
    /// afterward through ordinary use while it still sat there.
    @Test("A stale restore on an existing-BEK device cleans itself up, not stalls forever")
    func existingBEKRestoreDoesNotStallForever() throws {
        clearRestoreFiles()
        defer { clearRestoreFiles() }

        let victim   = try makeBackupReadyVault()
        let attacker = try makeBackupReadyVault()
        let attackerBackup = try attacker.vault.exportBackup(currentDepth: 0)

        try attackerBackup.write(to: pendingRestoreURL, options: [.atomic, .completeFileProtection])
        try victim.vault.storeRestoreShard(attacker.shards[0], attestation: nil, senderIdentifier: "trustee-0")
        victim.vault.refreshPendingRestoreState(currentDepth: 0)
        #expect(victim.vault.pendingRestoreActive, "arming the file must still set the flag")
        #expect(victim.vault.pendingRestoreShardCount == 1)

        victim.vault.attemptBEKRestore(currentDepth: 0)

        #expect(!victim.vault.pendingRestoreActive, """
            pendingRestoreActive is stuck true — every future unlock will retry against a \
            file that can never succeed, and the "Restoring your vault" banner never clears.
            """)
        #expect(victim.vault.pendingRestoreShardCount == 0)
        #expect(!FileManager.default.fileExists(atPath: pendingRestoreURL.path),
                "the pending .occbak must be removed, not retried forever")
        #expect(!FileManager.default.fileExists(atPath: pendingRestoreShardsURL.path),
                "the shard file must be removed — nothing will ever clear it otherwise")
    }
}

// MARK: - Bug 93

/// Depth-gating for the automatic restore path. `attemptBEKRestore` must never complete
/// above depth 0 (defer), and `refreshPendingRestoreState` must never publish real state
/// above depth 0 (hide) — the two ship together, since deferring without hiding turns a
/// disclosure into a self-contradicting oracle.
@Suite("Bug 93 — recovery must not run or announce itself above depth 0", .serialized)
@MainActor
struct VaultRestoreDepthGatingTests {

    /// The regression guard, and the reason it outranks the deferral test below: a fix
    /// that defers correctly but never lets a genuine recovery complete at depth 0 either
    /// is worse than the bug it replaces.
    @Test("A genuine restore still completes at depth 0")
    func genuineRestoreCompletesAtDepthZero() throws {
        clearRestoreFiles()
        defer { clearRestoreFiles() }

        let owner  = try makeBackupReadyVault()
        _ = try owner.vault.addEntry(label: "recovered", content: Data("recovered".utf8), type: .note)
        let backup = try owner.vault.exportBackup(currentDepth: 0)

        let fresh = try makeFreshVault()
        try fresh.vault.storePendingRestore(backup, currentDepth: 0)
        for (i, shard) in owner.shards.enumerated() { try fresh.vault.storeRestoreShard(shard, attestation: nil, senderIdentifier: "trustee-\(i)") }

        fresh.vault.attemptBEKRestore(currentDepth: 0)

        #expect((try? fresh.vault.currentBEK()) != nil, "the BEK must be installed at depth 0")
        #expect(!fresh.vault.pendingRestoreActive, "a completed restore must clear the flag")
    }

    /// The deferral itself: the same genuine restore, reaching threshold while the caller
    /// reports a duress depth, must not complete.
    @Test("The same genuine restore does not complete above depth 0")
    func genuineRestoreDoesNotCompleteAboveDepthZero() throws {
        clearRestoreFiles()
        defer { clearRestoreFiles() }

        let owner  = try makeBackupReadyVault()
        _ = try owner.vault.addEntry(label: "recovered", content: Data("recovered".utf8), type: .note)
        let backup = try owner.vault.exportBackup(currentDepth: 0)

        let fresh = try makeFreshVault()
        try fresh.vault.storePendingRestore(backup, currentDepth: 0)
        for (i, shard) in owner.shards.enumerated() { try fresh.vault.storeRestoreShard(shard, attestation: nil, senderIdentifier: "trustee-\(i)") }

        fresh.vault.attemptBEKRestore(currentDepth: 2)

        #expect((try? fresh.vault.currentBEK()) == nil, """
            The restore completed while the caller reported a duress depth — a recovered \
            real-layer vault was just filed into whichever layer the coercer happened to \
            be looking at.
            """)
    }

    /// Shards must keep accumulating above depth 0 — "defer" is not "stop collecting".
    /// The deferred restore must still complete once depth 0 is reached, using shards
    /// gathered while at a duress depth.
    @Test("Shards still accumulate above depth 0, and the deferred restore completes later")
    func shardsStillAccumulateAboveDepthZero() throws {
        clearRestoreFiles()
        defer { clearRestoreFiles() }

        let owner  = try makeBackupReadyVault()
        let backup = try owner.vault.exportBackup(currentDepth: 0)

        let fresh = try makeFreshVault()
        try fresh.vault.storePendingRestore(backup, currentDepth: 0)
        for (i, shard) in owner.shards.enumerated() { try fresh.vault.storeRestoreShard(shard, attestation: nil, senderIdentifier: "trustee-\(i)") }

        fresh.vault.attemptBEKRestore(currentDepth: 3)
        #expect((try? fresh.vault.currentBEK()) == nil, "must not complete above depth 0")

        fresh.vault.attemptBEKRestore(currentDepth: 0)
        #expect((try? fresh.vault.currentBEK()) != nil, """
            Shards collected while at a duress depth must not be lost — the deferred \
            restore must complete on the next depth-0 attempt using the same shards.
            """)
    }

    /// `refreshPendingRestoreState` must publish false above depth 0 regardless of what is
    /// actually on disk — not "hidden if pending," genuinely false, so a coercer watching
    /// across multiple unlocks sees the same nothing every time. Not a one-way ratchet
    /// either: depth 0 still sees the truth afterward.
    @Test("Published pending-restore state is forced false above depth 0, and recovers at depth 0")
    func publishedStateIsForcedFalseAboveDepthZero() throws {
        clearRestoreFiles()
        defer { clearRestoreFiles() }

        let owner  = try makeBackupReadyVault()
        let backup = try owner.vault.exportBackup(currentDepth: 0)

        let fresh = try makeFreshVault()
        try fresh.vault.storePendingRestore(backup, currentDepth: 0)
        try fresh.vault.storeRestoreShard(owner.shards[0], attestation: nil, senderIdentifier: "trustee-0")

        fresh.vault.refreshPendingRestoreState(currentDepth: 0)
        #expect(fresh.vault.pendingRestoreActive, "depth 0 must reflect the real, pending state")
        #expect(fresh.vault.pendingRestoreShardCount == 1)

        fresh.vault.refreshPendingRestoreState(currentDepth: 2)
        #expect(!fresh.vault.pendingRestoreActive, """
            A genuinely pending restore must publish as inactive above depth 0 — this is \
            what keeps the duress view coherent across repeated unlocks.
            """)
        #expect(fresh.vault.pendingRestoreShardCount == 0)

        fresh.vault.refreshPendingRestoreState(currentDepth: 0)
        #expect(fresh.vault.pendingRestoreActive, "returning to depth 0 must restore the real state")
    }
}

// MARK: - Bug 96

@Suite("Bug 96 — restore path robustness", .serialized)
@MainActor
struct VaultRestoreRobustnessTests {

    /// Seal an arbitrary `VaultBackup` under a vault's BEK, producing a file that vault
    /// will accept. Reaching the traps below requires exactly this — which is why Bug 94
    /// is what makes them exploitable rather than theoretical.
    @MainActor
    private func sealedBackup(_ backup: VaultManager.VaultBackup,
                              under vault: VaultManager) throws -> Data {
        let json   = try JSONEncoder().encode(backup)
        let sealed = try AES.GCM.seal(json, using: try vault.currentBEK(),
                                      nonce: AES.GCM.Nonce(), authenticating: backupFileAAD)
        var out = Data("OCBK".utf8)
        out.append(sealed.combined!)
        return out
    }

    /// `VaultEntryType(rawValue: UInt8(backupEntry.entryType))` — the `?? .note` guards
    /// the `rawValue:` lookup, but `UInt8(_: Int)` traps first on anything outside 0...255.
    @Test("An out-of-range entryType is rejected, not trapped")
    func outOfRangeEntryTypeThrows() throws {
        clearRestoreFiles()
        defer { clearRestoreFiles() }

        let victim = try makeBackupReadyVault()
        let hostile = VaultManager.VaultBackup(
            version: 1, createdAt: Date(),
            entries: [.init(id: UUID(), entryType: 300, createdAt: Date(),
                            label: Data("x".utf8), content: Data())]
        )
        let data = try self.sealedBackup(hostile, under: victim.vault)

        #expect(throws: (any Error).self) {
            try victim.vault.importBackup(data, currentDepth: 0)
        }
    }

    /// `VaultEntry.aad(for:)` does `UInt64(self.createdAt.timeIntervalSince1970)`, which
    /// traps on any date before 1970. The fix belongs at import: `aad` is read by every
    /// vault path, and changing its byte layout would strand every existing entry.
    @Test("A pre-1970 createdAt is rejected, not trapped")
    func preEpochCreatedAtThrows() throws {
        clearRestoreFiles()
        defer { clearRestoreFiles() }

        let victim = try makeBackupReadyVault()
        let hostile = VaultManager.VaultBackup(
            version: 1, createdAt: Date(),
            entries: [.init(id: UUID(), entryType: 1,
                            createdAt: Date(timeIntervalSince1970: -1),
                            label: Data("x".utf8), content: Data())]
        )
        let data = try self.sealedBackup(hostile, under: victim.vault)

        #expect(throws: (any Error).self) {
            try victim.vault.importBackup(data, currentDepth: 0)
        }
    }

    /// `storeRestoreShard` deduplicates by `SignedAttribute.id`, and an attacker picks a
    /// fresh UUID each time. The file is re-encoded and rewritten on every call and fully
    /// decoded on every unlock, so growth is both unbounded and quadratic.
    ///
    /// **Scoped to a fresh, no-BEK vault deliberately.** On an existing-BEK device, the early
    /// check added to `attemptBEKRestore` bounds this to roughly one shard per arming cycle in
    /// real usage — `acceptReturnedShard` calls it immediately after every `storeRestoreShard`
    /// — so this test would no longer reflect production behaviour if run against
    /// `makeBackupReadyVault()`. The no-BEK population has no equivalent early-out (there is no
    /// BEK to detect), so growth there is still genuinely unbounded — but a realistic attack
    /// costs the attacker real inbound-bundle volume for modest payoff (300 shards ≈ 1s to
    /// store; this is a nice-to-have hardening item, not an urgent one). Pins only that *a*
    /// bound exists — the value is the fix's choice. Any cap near a realistic trustee count
    /// (single digits; threshold ≥ 2) sits far below this ceiling.
    @Test("The restore-shard file does not grow without bound, on a device that still needs one")
    func restoreShardFileIsBounded() throws {
        clearRestoreFiles()
        defer { clearRestoreFiles() }

        let victim   = try makeFreshVault()
        let attempts = 300

        for i in 0..<attempts {
            let junk = SignedAttribute(
                id: UUID(), label: "vault-bek-shard",
                value: Data(repeating: UInt8(i % 251), count: 33),
                category: .shard, signature: Data(), entryID: UUID()
            )
            try? victim.vault.storeRestoreShard(junk, attestation: nil, senderIdentifier: "junk-sender-\(i)")
        }

        withKnownIssue("Bug 96: storeRestoreShard has no cap") {
            #expect(victim.vault.pendingRestoreShardCount < attempts, """
                \(victim.vault.pendingRestoreShardCount) shards accepted from \(attempts) \
                attempts. Anyone able to send a bundle can grow this file without limit, and \
                every unlock reads and decodes all of it.
                """)
        }
    }
}

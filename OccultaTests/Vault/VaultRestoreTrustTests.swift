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
//  `Manager.Key` in `setUpWithError`. Both traps are fixed now (guards in `decodedBackup`,
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

/// Duplicated from `Vault+Manager+Backup.swift`, where it is `private static`. If it
/// changes there, these tests go quietly wrong rather than failing — the AAD would
/// produce `decryptionFailed`.
private let backupFileAAD = Data("occulta-backup-v1".utf8)
private let appSupport    = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]

/// Where older builds held a pending restore (`bugs.md` Bug 127). Nothing writes these any
/// more; `deleteLegacyRestoreState` removes them. Duplicated from there, like the AAD above.
private let legacyRestoreFiles = ["backup-import-cache.occbak", "pending-restore.occbak", "pending-restore-shards.dat"]
    .map { appSupport.appendingPathComponent($0) }

/// The legacy files live at fixed global paths, so clear them around every test that
/// seeds or checks them.
private func clearRestoreFiles() {
    for url in legacyRestoreFiles { try? FileManager.default.removeItem(at: url) }
}

private func makeContainer() throws -> ModelContainer {
    let schema = Schema([
        VaultEntry.self,
        BackupEncryptionKey.self,
        // BEK restore shards are PendingShamirSecretRestore rows now (RECOVERY_BUFFER_LAYERING.md
        // §9.3) — a container without these two models cannot store one, and every test here
        // that collects shards fails at the insert.
        Vault.self,
        PendingShamirSecretRestore.self,
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
/// `prepareBackupShards` is the only way to obtain shares that reconstruct this BEK.
@MainActor
private func makeBackupReadyVault(threshold: Int = 2, trustees: Int = 2) throws -> (vault: VaultManager,
                                                                                   container: ModelContainer,
                                                                                   shards: [SignedAttribute]) {
    let container = try makeContainer()
    try? FileManager.default.createDirectory(at: appSupport, withIntermediateDirectories: true)

    let vault = VaultManager(
        modelContainer: container, keyManager: TestKeyManager()
    )
    vault.unlock(context: LAContext())
    try vault.setupBackup(currentDepth: 0)

    // Real UUID strings, not "trustee-N" labels — BEKPayloadCodec's fixed-width wire
    // format stores contactIdentifier as raw UUID bytes (item 3). No Contact.Profile
    // needed here any more — prepareBackupShards takes identifiers directly.
    let recipients = (0..<trustees).map { _ in UUID().uuidString }

    let shards = try vault.prepareBackupShards(threshold: threshold, recipients: recipients, currentDepth: 0)
    try vault.setBackupShardStatuses(Dictionary(uniqueKeysWithValues: shards.map { ($0.id, .confirmed) }), currentDepth: 0)
    return (vault, container, shards)
}

/// A vault with no BEK at all — the genuine new-device restore target. `setupBackup()` has
/// exactly one production caller (`Vault+ShardSetup.swift:553`, `.backup` mode only), so
/// a device that has never configured backup reaches a restore in precisely this state.
@MainActor
private func makeFreshVault() throws -> (vault: VaultManager, container: ModelContainer) {
    let container = try makeContainer()
    try? FileManager.default.createDirectory(at: appSupport, withIntermediateDirectories: true)
    let vault = VaultManager(
        modelContainer: container, keyManager: TestKeyManager()
    )
    vault.unlock(context: LAContext())
    return (vault, container)
}

/// The backup key held at `depth`. `restoreBackup` writes it at the depth the file was
/// opened at.
@MainActor
private func bekBytes(of vault: VaultManager, atDepth depth: Int = 0) throws -> Data {
    var bytes = Data()
    try vault.currentBackupKey(currentDepth: depth).withUnsafeBytes { bytes = Data($0) }
    return bytes
}

/// Banks each share as if handed back by its own sender, and returns those senders: the
/// visible-contact set under which all of them count.
@MainActor
@discardableResult
private func bank(_ shards: [SignedAttribute], in vault: VaultManager, senderPrefix: String = "trustee") throws -> Set<String> {
    var senders = Set<String>()
    for (i, shard) in shards.enumerated() {
        let sender = "\(senderPrefix)-\(i)"
        try vault.absorbShard(shard, senderIdentifier: sender)
        senders.insert(sender)
    }
    return senders
}

/// Labels of the entries visible at `depth`. Vault entries are exact-match, so an entry
/// restored at one depth appears at that depth only.
@MainActor
private func labels(in vault: VaultManager, _ container: ModelContainer, atDepth depth: Int) throws -> [String] {
    try ModelContext(container).fetch(FetchDescriptor<VaultEntry>())
        .filter { $0.isVisible(atDepth: depth, whenUnclassified: depth == 0) }
        .compactMap { try? vault.decryptLabelPayload(for: $0).label }
}

// MARK: - Bug 94

// Every test in this suite goes through makeBackupReadyVault()/exportBackup()/addEntry(),
// which stamp visibleThroughDepth through the bare, uninjectable Data.encrypt() extension
// (Manager.Key(), not TestKeyManager) — no seam reaches it. Gated at the suite level rather
// than per test since there is no test here that doesn't depend on this.
@Suite("Bug 94 — restore must not trust attacker-supplied material", .serialized, .enabled(if: secureEnclaveAvailable()))
@MainActor
struct VaultRestoreTrustTests {

    /// The attack, end to end, through the one production restore path.
    ///
    /// `restoreBackup` passes `ownerIdentity: nil`, so the GCM tag is the only check — and it
    /// only proves the shards match the file. Here the *same* party produced both, so the tag
    /// proves nothing about whose backup this is. Remedy 1 refuses before any of that runs,
    /// purely because the victim's layer already has a backup key.
    @Test("A foreign backup and its own shards must not replace an existing BEK")
    func foreignShardsCannotReplaceExistingBEK() throws {
        let victim   = try makeBackupReadyVault()
        let attacker = try makeBackupReadyVault()

        let victimBEKBefore = try bekBytes(of: victim.vault)
        let attackerBEK     = try bekBytes(of: attacker.vault)
        #expect(victimBEKBefore != attackerBEK, "the two vaults must hold different BEKs")

        // The attacker seals their own file under their own BEK and splits that BEK.
        // Nothing here is forged — it is simply not the victim's.
        let attackerBackup = try attacker.vault.exportBackup(currentDepth: 0)
        let senders        = try bank(attacker.shards, in: victim.vault)

        let imported = try victim.vault.restoreBackup(from: attackerBackup, currentDepth: 0, visibleContactIdentifiers: senders)

        #expect(!imported)
        #expect(try bekBytes(of: victim.vault) == victimBEKBefore, """
            The victim's BEK was replaced by one reconstructed from a stranger's shards. \
            Every backup file sealed under the old key is now permanently unrestorable, \
            and the trustees' real shards reconstruct a key that matches nothing.
            """)
    }

    /// The second half of the same harm: had the BEK been replaced, the attacker's entries
    /// would have been inserted into the user's vault.
    @Test("A foreign backup's entries must not be inserted into an existing vault")
    func foreignEntriesAreNotInserted() throws {
        let victim   = try makeBackupReadyVault()
        let attacker = try makeBackupReadyVault()

        _ = try victim.vault.addEntry(label: "mine", content: Data("mine".utf8), type: .note)
        _ = try attacker.vault.addEntry(label: "planted", content: Data("planted".utf8), type: .note)

        let attackerBackup = try attacker.vault.exportBackup(currentDepth: 0)
        let senders        = try bank(attacker.shards, in: victim.vault)

        #expect(try !victim.vault.restoreBackup(from: attackerBackup, currentDepth: 0, visibleContactIdentifiers: senders))

        let allLabels = try ModelContext(victim.container)
            .fetch(FetchDescriptor<VaultEntry>())
            .compactMap { try? victim.vault.decryptLabelPayload(for: $0).label }

        #expect(!allLabels.contains("planted"), """
            A stranger's vault entry was inserted into the user's vault. Labels now: \
            \(allLabels.sorted()).
            """)
    }

    /// **The regression guard, and the reason it outranks the two above.**
    ///
    /// Bug 94's remedy refuses to overwrite an existing BEK. If that guard is written a
    /// notch too wide it also blocks the only path this system exists for — a device that
    /// lost everything, restoring from trustees. That failure is silent, and surfaces when
    /// the user has no device left to discover it on.
    @Test("A device with no BEK can still restore — the new-device path stays open")
    func freshDeviceCanStillRestore() throws {
        let owner = try makeBackupReadyVault()
        _ = try owner.vault.addEntry(label: "recovered", content: Data("recovered".utf8), type: .note)
        let backup   = try owner.vault.exportBackup(currentDepth: 0)
        let ownerBEK = try bekBytes(of: owner.vault)

        // The replacement device: vault set up, backup never configured, so no BEK row.
        let fresh = try makeFreshVault()
        #expect((try? fresh.vault.currentBackupKey(currentDepth: 0)) == nil, "a fresh device must start with no BEK")
        let senders = try bank(owner.shards, in: fresh.vault)

        #expect(try fresh.vault.restoreBackup(from: backup, currentDepth: 0, visibleContactIdentifiers: senders))
        #expect(try bekBytes(of: fresh.vault) == ownerBEK,
                "restore must install the owner's BEK on a device that had none")
        #expect(try labels(in: fresh.vault, fresh.container, atDepth: 0).contains("recovered"), """
            The new-device restore path is broken. This is the path the whole shard system \
            exists for, and its failure mode is discovered only when the device is gone.
            """)
        #expect(fresh.vault.postRestorePromptPending)
    }

    /// Collection is depth-blind, so banked shards may belong to a restore another layer is
    /// waiting on. A refusal here must not wipe them; the old pending-file design did, which
    /// would let one layer destroy another's recovery.
    @Test("A refusal leaves banked shards in place")
    func refusalLeavesBankedShards() throws {
        let victim         = try makeBackupReadyVault()
        let attacker       = try makeBackupReadyVault()
        let attackerBackup = try attacker.vault.exportBackup(currentDepth: 0)
        let senders        = try bank(attacker.shards, in: victim.vault)
        let distributionID = try #require(attacker.shards.first?.entryID)

        _ = try victim.vault.restoreBackup(from: attackerBackup, currentDepth: 0, visibleContactIdentifiers: senders)

        #expect(try victim.vault.collectedShards(forAttributeID: distributionID).count == attacker.shards.count)
    }

    /// The file is used once, from memory. Nothing is written to the sandbox, whether the
    /// attempt fails or succeeds (`RECOVERY_BUFFER_LAYERING.md` §9.4, Bug 100 remedy 3).
    @Test("Opening a backup never writes it to the sandbox")
    func restoreNeverWritesTheFile() throws {
        clearRestoreFiles()
        defer { clearRestoreFiles() }

        let owner  = try makeBackupReadyVault()
        let backup = try owner.vault.exportBackup(currentDepth: 0)
        let fresh  = try makeFreshVault()

        #expect(try !fresh.vault.restoreBackup(from: backup, currentDepth: 0, visibleContactIdentifiers: []))
        for url in legacyRestoreFiles { #expect(!FileManager.default.fileExists(atPath: url.path)) }

        let senders = try bank(owner.shards, in: fresh.vault)
        #expect(try fresh.vault.restoreBackup(from: backup, currentDepth: 0, visibleContactIdentifiers: senders))
        for url in legacyRestoreFiles { #expect(!FileManager.default.fileExists(atPath: url.path)) }
    }

    /// The one failure that reports: it turns on the file's own bytes, not on vault state or
    /// depth, so it tells a coercer nothing about the session.
    @Test("A file that isn't a backup throws")
    func malformedFileThrows() throws {
        let fresh = try makeFreshVault()
        #expect(throws: VaultManager.BackupError.invalidFormat) {
            _ = try fresh.vault.restoreBackup(from: Data("nope".utf8), currentDepth: 0, visibleContactIdentifiers: [])
        }
    }
}

// MARK: - Bug 95

/// A well-formed piece for `distributionID` carrying random values: what a trustee running a
/// modified app can hand back. Its signature is valid for some key, just not the owner's, which
/// the new-device path can't check anyway (`ownerIdentity: nil`).
@MainActor
private func poisonedShard(for distributionID: UUID, x: UInt8) throws -> SignedAttribute {
    var value = Data([x])
    value.append(Data((0..<32).map { _ in UInt8.random(in: 0...255) }))
    let id        = UUID()
    let createdAt = Date()
    let payload   = SignedAttribute.signingPayload(
        id: id, category: .shard, value: value, entryID: distributionID, createdAt: createdAt, expiresAt: nil
    )
    return SignedAttribute(
        id: id, label: "vault-bek-shard", value: value, category: .shard,
        signature: try TestKeyManager().signData(payload), createdAt: createdAt, entryID: distributionID
    )
}

/// One owner backup with `trustees` honest pieces at threshold `threshold`, restored on a fresh
/// device after banking `honest` of them plus `poisoned`. Returns whether the restore imported.
@MainActor
private func restoreWithPoison(
    threshold: Int, trustees: Int, honest: Int? = nil, poisoned: (UUID) throws -> [SignedAttribute]
) throws -> (imported: Bool, fresh: (vault: VaultManager, container: ModelContainer), ownerBEK: Data) {
    let owner = try makeBackupReadyVault(threshold: threshold, trustees: trustees)
    _ = try owner.vault.addEntry(label: "recovered", content: Data("recovered".utf8), type: .note)
    let backup         = try owner.vault.exportBackup(currentDepth: 0)
    let distributionID = try #require(owner.shards.first?.entryID)

    let fresh   = try makeFreshVault()
    var senders = try bank(Array(owner.shards.prefix(honest ?? trustees)), in: fresh.vault)
    senders.formUnion(try bank(try poisoned(distributionID), in: fresh.vault, senderPrefix: "hostile"))

    let imported = try fresh.vault.restoreBackup(from: backup, currentDepth: 0, visibleContactIdentifiers: senders)
    return (imported, fresh, try bekBytes(of: owner.vault))
}

/// A hostile trustee who hands back a wrong piece can do no more than one who withholds theirs.
// Same Enclave dependency as the suites around it: makeBackupReadyVault()/exportBackup().
@Suite("Bug 95 — a poisoned piece doesn't block recovery", .serialized, .enabled(if: secureEnclaveAvailable()))
@MainActor
struct PoisonedShardTests {

    @Test("One poisoned piece with a fresh x among enough honest ones still restores")
    func onePoisonedPieceRestores() throws {
        let result = try restoreWithPoison(threshold: 2, trustees: 3) { id in [try poisonedShard(for: id, x: 200)] }
        #expect(result.imported)
        #expect(try bekBytes(of: result.fresh.vault) == result.ownerBEK)
        #expect(try labels(in: result.fresh.vault, result.fresh.container, atDepth: 0) == ["recovered"])
    }

    /// Reusing an honest piece's x makes the full set fail on a duplicate coordinate rather
    /// than on the tag. Either way the piece has to be left out.
    @Test("A poisoned piece reusing an honest piece's x still restores")
    func duplicateXRestores() throws {
        let result = try restoreWithPoison(threshold: 2, trustees: 3) { id in [try poisonedShard(for: id, x: 1)] }
        #expect(result.imported)
        #expect(try bekBytes(of: result.fresh.vault) == result.ownerBEK)
    }

    @Test("Two poisoned pieces still restore")
    func twoPoisonedPiecesRestore() throws {
        let result = try restoreWithPoison(threshold: 3, trustees: 5) { id in
            [try poisonedShard(for: id, x: 200), try poisonedShard(for: id, x: 201)]
        }
        #expect(result.imported)
        #expect(try bekBytes(of: result.fresh.vault) == result.ownerBEK)
    }

    /// Below the threshold no subset can work, which is the same outcome as withholding.
    @Test("Too few honest pieces plus a poisoned one restores nothing and keeps the pieces")
    func tooFewHonestPiecesFails() throws {
        let result = try restoreWithPoison(threshold: 3, trustees: 3, honest: 2) { id in [try poisonedShard(for: id, x: 200)] }
        #expect(!result.imported)
        #expect((try? result.fresh.vault.currentBackupKey(currentDepth: 0)) == nil)
        #expect(try ModelContext(result.fresh.container).fetch(FetchDescriptor<VaultEntry>()).isEmpty)
    }

    /// The cap, pinned from both sides whatever order the pieces arrive in. Three bad among 18
    /// needs at most 1 + 18 + 153 + 816 = 988 tries; four bad among 20 needs at least
    /// 1 + 20 + 190 + 1,140 + 1 = 1,352.
    @Test("Three poisoned among 18 restores; four among 20 exceeds the cap")
    func capBoundsTheSearch() throws {
        #expect(VaultManager.Backup.maxReconstructionAttempts == 1024)

        let within = try restoreWithPoison(threshold: 2, trustees: 15) { id in
            try (0..<3).map { try poisonedShard(for: id, x: UInt8(200 + $0)) }
        }
        #expect(within.imported)

        let beyond = try restoreWithPoison(threshold: 2, trustees: 16) { id in
            try (0..<4).map { try poisonedShard(for: id, x: UInt8(200 + $0)) }
        }
        #expect(!beyond.imported)
    }
}

// MARK: - Bug 99

/// A restore completes at the depth its file is opened at, counting only shards from contacts
/// visible there (`RECOVERY_BUFFER_LAYERING.md` §9.4). Replaces the Bug 93 suite that pinned
/// completion to depth 0: that pin was the oracle Bug 99 describes, since a coercer's own,
/// self-sufficient restore never completing in duress told him where he was.
// Same reason as VaultRestoreTrustTests above — every test here goes through
// makeBackupReadyVault()/exportBackup() and absorbShard, which need the real Manager.Key().
@Suite("Bug 99 — a restore completes at the depth its file is opened at", .serialized, .enabled(if: secureEnclaveAvailable()))
@MainActor
struct VaultRestoreDepthTests {

    /// Bug 99's fix. The coercer's own restore (his file, his trustees paired in his layer)
    /// completes in his layer, as it would in any working app, so watching it tells him
    /// nothing. His entries stay in that layer; vault entries are exact-match.
    @Test("A restore opened at a duress depth completes there, and not at depth 0")
    func restoreCompletesAtTheOpeningDepth() throws {
        let coercer = try makeBackupReadyVault()
        _ = try coercer.vault.addEntry(label: "planted", content: Data("planted".utf8), type: .note)
        let backup  = try coercer.vault.exportBackup(currentDepth: 0)

        let victim  = try makeFreshVault()
        let senders = try bank(coercer.shards, in: victim.vault, senderPrefix: "coercer")

        #expect(try victim.vault.restoreBackup(from: backup, currentDepth: 2, visibleContactIdentifiers: senders))
        #expect((try? victim.vault.currentBackupKey(currentDepth: 2)) != nil, "the key must land at the opening depth")
        #expect((try? victim.vault.currentBackupKey(currentDepth: 0)) == nil, "the real layer must be untouched")
        #expect(try labels(in: victim.vault, victim.container, atDepth: 2).contains("planted"))
        #expect(try !labels(in: victim.vault, victim.container, atDepth: 0).contains("planted"))
    }

    /// The hole §9.4 closes, for trustees the owner hid from the duress layer: their banked
    /// shards don't count there, so the owner's real file can't complete in that layer.
    @Test("Shards from contacts hidden at the depth don't count there")
    func hiddenTrusteesDoNotCountAtDuressDepth() throws {
        let owner   = try makeBackupReadyVault()
        let backup  = try owner.vault.exportBackup(currentDepth: 0)
        let fresh   = try makeFreshVault()
        let senders = try bank(owner.shards, in: fresh.vault)

        #expect(try !fresh.vault.restoreBackup(from: backup, currentDepth: 2, visibleContactIdentifiers: ["someone-else"]))
        #expect((try? fresh.vault.currentBackupKey(currentDepth: 2)) == nil)

        #expect(try fresh.vault.restoreBackup(from: backup, currentDepth: 0, visibleContactIdentifiers: senders),
                "the same shards must still count where their senders are visible")
    }

    /// The residual §9.4 accepts, pinned so it can't pass unnoticed: trustees the owner left
    /// visible in the duress layer (the default for a contact) count there, so the owner's
    /// real backup completes in that layer. See `decisions.md`, "Filter restore shards by
    /// trustee visibility at completion".
    @Test("Residual: trustees left visible at a duress depth count there")
    func visibleTrusteesCountAtDuressDepth() throws {
        let owner   = try makeBackupReadyVault()
        let backup  = try owner.vault.exportBackup(currentDepth: 0)
        let fresh   = try makeFreshVault()
        let senders = try bank(owner.shards, in: fresh.vault)

        #expect(try fresh.vault.restoreBackup(from: backup, currentDepth: 2, visibleContactIdentifiers: senders))
        #expect((try? fresh.vault.currentBackupKey(currentDepth: 2)) != nil)
    }

    /// Success consumes the shards, so the same set can't complete a second restore anywhere.
    @Test("Consumed shards can't be replayed at another depth")
    func consumedShardsCannotBeReplayed() throws {
        let owner   = try makeBackupReadyVault()
        let backup  = try owner.vault.exportBackup(currentDepth: 0)
        let fresh   = try makeFreshVault()
        let senders = try bank(owner.shards, in: fresh.vault)

        #expect(try fresh.vault.restoreBackup(from: backup, currentDepth: 0, visibleContactIdentifiers: senders))
        #expect(try !fresh.vault.restoreBackup(from: backup, currentDepth: 3, visibleContactIdentifiers: senders))
        #expect((try? fresh.vault.currentBackupKey(currentDepth: 3)) == nil)
    }

    /// Too few shares: nothing happens and nothing is kept. Opening the same file again once
    /// the rest arrive completes.
    @Test("Too few shares fails cleanly, and a later attempt completes")
    func partialSharesThenRetry() throws {
        let owner  = try makeBackupReadyVault()
        let backup = try owner.vault.exportBackup(currentDepth: 0)
        let fresh  = try makeFreshVault()

        try fresh.vault.absorbShard(owner.shards[0], senderIdentifier: "trustee-0")
        #expect(try !fresh.vault.restoreBackup(from: backup, currentDepth: 0, visibleContactIdentifiers: ["trustee-0"]))
        #expect((try? fresh.vault.currentBackupKey(currentDepth: 0)) == nil)

        try fresh.vault.absorbShard(owner.shards[1], senderIdentifier: "trustee-1")
        #expect(try fresh.vault.restoreBackup(from: backup, currentDepth: 0, visibleContactIdentifiers: ["trustee-0", "trustee-1"]))
    }

    /// In-memory state reset on lock. Changing depth means entering the PIN again, which the
    /// vault locks before, so an import in one layer can't prompt in another layer's session.
    @Test("The post-restore prompt is cleared on lock")
    func postRestorePromptClearsOnLock() throws {
        let owner   = try makeBackupReadyVault()
        let backup  = try owner.vault.exportBackup(currentDepth: 0)
        let fresh   = try makeFreshVault()
        let senders = try bank(owner.shards, in: fresh.vault)

        _ = try fresh.vault.restoreBackup(from: backup, currentDepth: 2, visibleContactIdentifiers: senders)
        #expect(fresh.vault.postRestorePromptPending)

        fresh.vault.lock()
        #expect(!fresh.vault.postRestorePromptPending)
    }
}

// MARK: - Bug 96

// Needs a real Secure Enclave for two independent reasons: outOfRangeEntryTypeThrows/
// preEpochCreatedAtThrows go through makeBackupReadyVault()/exportBackup(), which stamp
// visibleThroughDepth through the bare, uninjectable Data.encrypt() extension (same
// reason VaultRestoreTrustTests above is gated); restoreShardBufferIsUnbounded goes
// through absorbShard, which seals PendingShamirSecretRestore.attributeID/.deletionToken
// under the ambient Manager.Key() local key. Previously ungated — a pre-existing gap for
// the first two tests, surfaced while adding the gate this file's third test now needs.
@Suite("Bug 96 — restore path robustness", .serialized, .enabled(if: secureEnclaveAvailable()))
@MainActor
struct VaultRestoreRobustnessTests {

    /// Seal arbitrary bytes under `owner`'s BEK as a `.occbak`. The owner's shards open it,
    /// so it passes the GCM check — which is why Bug 94 is what makes a hostile file
    /// reachable rather than theoretical.
    @MainActor
    private func sealed(_ plaintext: Data, under owner: VaultManager) throws -> Data {
        let box = try AES.GCM.seal(plaintext, using: try owner.currentBackupKey(currentDepth: 0),
                                   nonce: AES.GCM.Nonce(), authenticating: backupFileAAD)
        var out = Data("OCBK".utf8)
        out.append(box.combined!)
        return out
    }

    @MainActor
    private func sealedBackup(_ entries: [VaultManager.VaultBackupEntry], under owner: VaultManager) throws -> Data {
        try self.sealed(JSONEncoder().encode(VaultManager.VaultBackup(version: 1, createdAt: Date(), entries: entries)),
                        under: owner)
    }

    /// Restores `data` onto a fresh vault holding all of `owner`'s shards, and checks the
    /// Bug 129 guarantee: a file that matches the shards but fails later leaves no backup key,
    /// no entries, and every shard still banked.
    @MainActor
    private func expectRestoreLeavesNothing(_ data: Data, owner: (vault: VaultManager, container: ModelContainer, shards: [SignedAttribute])) throws {
        let fresh          = try makeFreshVault()
        let senders        = try bank(owner.shards, in: fresh.vault)
        let distributionID = try #require(owner.shards.first?.entryID)

        #expect(try !fresh.vault.restoreBackup(from: data, currentDepth: 0, visibleContactIdentifiers: senders))
        #expect((try? fresh.vault.currentBackupKey(currentDepth: 0)) == nil, "a failed restore must not leave a backup key")
        #expect(try fresh.vault.collectedShards(forAttributeID: distributionID).count == owner.shards.count,
                "a file that matches the shards but fails to decode must not consume them")

        // A later save anywhere must not commit anything the failed attempt staged.
        _ = try fresh.vault.addEntry(label: "later", content: Data("later".utf8), type: .note)
        #expect(try labels(in: fresh.vault, fresh.container, atDepth: 0) == ["later"])

        // The layer can still be restored from a good copy.
        let good = try owner.vault.exportBackup(currentDepth: 0)
        #expect(try fresh.vault.restoreBackup(from: good, currentDepth: 0, visibleContactIdentifiers: senders))
    }

    /// `VaultEntryType(rawValue: UInt8(backupEntry.entryType))` — the `?? .note` guards
    /// the `rawValue:` lookup, but `UInt8(_: Int)` traps first on anything outside 0...255.
    @Test("An out-of-range entryType is rejected, not trapped, and leaves nothing behind")
    func outOfRangeEntryTypeLeavesNothing() throws {
        let owner = try makeBackupReadyVault()
        let data  = try self.sealedBackup(
            [.init(id: UUID(), entryType: 300, createdAt: Date(), label: Data("x".utf8), content: Data())],
            under: owner.vault
        )
        try self.expectRestoreLeavesNothing(data, owner: owner)
    }

    /// `VaultEntry.aad(for:)` does `UInt64(self.createdAt.timeIntervalSince1970)`, which
    /// traps on any date before 1970. The fix belongs at import: `aad` is read by every
    /// vault path, and changing its byte layout would strand every existing entry.
    @Test("A pre-1970 createdAt is rejected, not trapped, and leaves nothing behind")
    func preEpochCreatedAtLeavesNothing() throws {
        let owner = try makeBackupReadyVault()
        let data  = try self.sealedBackup(
            [.init(id: UUID(), entryType: 1, createdAt: Date(timeIntervalSince1970: -1), label: Data("x".utf8), content: Data())],
            under: owner.vault
        )
        try self.expectRestoreLeavesNothing(data, owner: owner)
    }

    /// Bug 129: the key used to be committed before the file was decoded, so a file that
    /// passed the GCM check but didn't decode installed its author's key with nothing imported,
    /// and every later attempt at that depth was refused.
    @Test("A file that matches the shards but isn't a backup leaves no key behind")
    func undecodableFileLeavesNothing() throws {
        let owner = try makeBackupReadyVault()
        try self.expectRestoreLeavesNothing(try self.sealed(Data("junk".utf8), under: owner.vault), owner: owner)
    }

    /// Bug 129's second half: entries were checked inside the insert loop, so a bad second
    /// entry was found after the first had been inserted, and the next save anywhere committed
    /// that first entry.
    @Test("An invalid second entry leaves the first one uninserted")
    func invalidSecondEntryLeavesNothing() throws {
        let owner = try makeBackupReadyVault()
        let data  = try self.sealedBackup([
            .init(id: UUID(), entryType: 1, createdAt: Date(), label: Data("first".utf8), content: Data("first".utf8)),
            .init(id: UUID(), entryType: 300, createdAt: Date(), label: Data("second".utf8), content: Data()),
        ], under: owner.vault)
        try self.expectRestoreLeavesNothing(data, owner: owner)
    }

    /// **Reversed, 2026-09-21 — `RECOVERY_BUFFER_LAYERING.md` §9.3's final decision.** The
    /// 255-per-depth cap this test used to pin (`bugs.md` Bug 96 item 2's original remedy)
    /// was reconsidered and deliberately not adopted: capping only orphaned rows leaves live
    /// ones exploitable exactly as before, and capping live rows reopens a cross-layer denial
    /// channel this container was built to avoid (§9.3's own "counting oracle" finding, `bugs.md`
    /// Bug 122). The decision is "no cap, ever, on this population" — Bug 96 item 2 stays open,
    /// permanently accepted. Each junk shard below carries a distinct `entryID` (a fake
    /// distribution of its own), so each claims its own `PendingShamirSecretRestore` row rather
    /// than competing for slots in a shared pool the way the old per-depth design worked — this
    /// test now confirms growth is genuinely unbounded, not capped at 255.
    @Test("The restore-shard buffer accepts every distinct distribution, genuinely unbounded")
    func restoreShardBufferIsUnbounded() throws {
        clearRestoreFiles()
        defer { clearRestoreFiles() }

        let victim   = try makeFreshVault()
        let attempts = 300

        for i in 0..<attempts {
            let junk = SignedAttribute(
                id: UUID(), label: "vault-bek-shard",
                value: Data(repeating: UInt8(i % 251), count: 33),
                category: .shard,
                // A minimal valid DER SEQUENCE (tag + zero-length content) — a genuinely
                // empty signature doesn't round-trip through SignedAttributeCodec, which
                // requires the signature region to start with a real DER tag to recover
                // where the real bytes end within the fixed 72-byte slot. No real shard
                // is ever actually signed this way; this is junk data to begin with.
                signature: Data([0x30, 0x00]),
                entryID: UUID()
            )
            try victim.vault.absorbShard(junk, senderIdentifier: "junk-sender-\(i)")
        }

        let count = try victim.vault.bekRestoreDistributionIDs().count
        #expect(count == attempts, """
            \(count) distributions held from \(attempts) junk shards — expected all of them, \
            since each names a distinct distribution and this population is permanently uncapped.
            """)
    }
}

// MARK: - Bug 100 remedy 1, Bug 127

/// The export-metadata file is written into Application Support, which
/// `excludeStoreFromBackup` does not cover — it takes the SQLite store and its `-wal`/`-shm`
/// sidecars only. So it was copied into iTunes/Finder/iCloud backups: sealed and device-bound,
/// but existence, length and timestamps travel with the copy, and a backup is obtainable without
/// the passcode prompt `.completeFileProtection` depends on. The pending `.occbak` this suite
/// used to cover is never written any more (`RECOVERY_BUFFER_LAYERING.md` §9.4); what's left of
/// it is the legacy cleanup below.
@Suite("Bug 100/127 — backup and restore files on disk", .serialized, .enabled(if: secureEnclaveAvailable()))
@MainActor
struct RestoreArtifactBackupExclusionTests {

    private func isExcluded(_ url: URL) throws -> Bool {
        try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup ?? false
    }

    @Test("Exporting writes export metadata excluded from backup")
    func exportMetadataIsExcluded() throws {
        let owner = try makeBackupReadyVault()
        _ = try owner.vault.addEntry(label: "e", content: Data("e".utf8), type: .note)
        _ = try owner.vault.exportBackup(currentDepth: 0)

        let metaURL = appSupport.appendingPathComponent("backup-export-meta.dat")
        #expect(try self.isExcluded(metaURL),
                "the export-metadata file is copied into device backups")
    }

    /// **The assertion that matters, and the one a wrong implementation passes without.**
    ///
    /// `isExcludedFromBackup` is a `URLResourceValues` attribute on the file, and `.atomic`
    /// writes rename a fresh temp file over the target — so the inode holding the attribute is
    /// discarded on every write. Setting the flag once at launch reads back correct exactly
    /// once. Only a rewrite catches that, which is why this test exports twice rather than
    /// checking the value after a single write.
    @Test("The exclusion survives the file being rewritten by a second export")
    func exclusionSurvivesRewrite() throws {
        let owner = try makeBackupReadyVault()
        _ = try owner.vault.addEntry(label: "e", content: Data("e".utf8), type: .note)
        _ = try owner.vault.exportBackup(currentDepth: 0)
        _ = try owner.vault.exportBackup(currentDepth: 0)

        let metaURL = appSupport.appendingPathComponent("backup-export-meta.dat")
        #expect(try self.isExcluded(metaURL), """
            The exclusion did not survive a rewrite. An implementation that sets the attribute \
            at launch rather than at each write passes the first-write test and fails here, \
            then ships silently unprotected from the second export onward.
            """)
    }

    /// Bug 127: the held `.occbak` under both its names, the old shard file, and the persisted
    /// post-restore flag are all deleted on unlock, without a restore attempt. Banked shard rows
    /// are untouched. `unlock(context:)` takes no depth, so this holds in every layer.
    @Test("Unlock deletes legacy restore state and keeps banked shards")
    func unlockDeletesLegacyRestoreState() throws {
        clearRestoreFiles()
        defer { clearRestoreFiles() }

        let owner = try makeBackupReadyVault()
        let fresh = try makeFreshVault()
        try bank(owner.shards, in: fresh.vault)
        let distributionID = try #require(owner.shards.first?.entryID)

        for url in legacyRestoreFiles { try Data("legacy".utf8).write(to: url) }
        UserDefaults.standard.set(true, forKey: "vault.postRestoreActionNeeded")

        fresh.vault.lock()
        fresh.vault.unlock(context: LAContext())

        for url in legacyRestoreFiles {
            #expect(!FileManager.default.fileExists(atPath: url.path), "\(url.lastPathComponent) survived unlock")
        }
        #expect(UserDefaults.standard.object(forKey: "vault.postRestoreActionNeeded") == nil)
        #expect(try fresh.vault.collectedShards(forAttributeID: distributionID).count == owner.shards.count)
    }
}

// MARK: - Bug 96 item 3

/// Export and restore zero every entry's decrypted label and content through
/// `VaultManager.zeroPlaintext`. Freed memory can't be read back safely, so this pins the
/// property the fix depends on instead: the zeroing happens in the original buffers, not in
/// copies made on write. A caller that kept a second reference to the entries would make this
/// silently zero a copy; the address check catches that.
@Suite("Bug 96 item 3 — backup plaintext is zeroed in place")
struct BackupPlaintextZeroingTests {

    /// 64 bytes, not a short literal: Data keeps anything up to 14 bytes inline, where the
    /// address `withUnsafeBytes` reports is a temporary and can't be compared.
    private static let plaintext = Data(repeating: 0xAB, count: 64)

    private func address(of data: Data) -> UInt {
        data.withUnsafeBytes { UInt(bitPattern: $0.baseAddress) }
    }

    @Test("Labels and contents are zeroed in their original buffers")
    func zeroesInPlace() {
        var entries = [VaultManager.VaultBackupEntry(
            id: UUID(), entryType: 1, createdAt: Date(), label: Self.plaintext, content: Self.plaintext
        )]
        // Detach from the shared static so each buffer has one owner, as it does in production.
        entries[0].label.append(0xAB)
        entries[0].content.append(0xAB)
        let labelAddress   = self.address(of: entries[0].label)
        let contentAddress = self.address(of: entries[0].content)

        VaultManager.zeroPlaintext(&entries)

        #expect(entries[0].label.allSatisfy { $0 == 0 })
        #expect(entries[0].content.allSatisfy { $0 == 0 })
        #expect(self.address(of: entries[0].label) == labelAddress, "the label was zeroed in a copy, not in place")
        #expect(self.address(of: entries[0].content) == contentAddress, "the content was zeroed in a copy, not in place")
    }
}

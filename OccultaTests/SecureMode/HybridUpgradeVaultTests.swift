//
//  HybridUpgradeVaultTests.swift
//  OccultaTests
//
//  Bug 171, Stage 6, tier B: a vault that was rewrapped onto the classical form (epoch 2, form classical) when its device
//  was below iOS 26, and whose device has since reached it. At that launch the tier B record moves to hybrid in place
//  (`HybridUpgradeOtherTiersTests`); the vault's data stays under the classical key until the next unlock, where the
//  Stage 4 rewrap runs again with the classical form as the "legacy" key and sets the epoch to (2, hybrid).
//
//  So between the launch and that unlock the record says hybrid while the data is classical, and the vault key must follow
//  the epoch's form and not the record: `Manager.Ambient.vaultKeys == .enclaveBoundClassical`.
//
//  Frozen: the pinned vault keys of `VaultPins`, classical and hybrid (the hybrid one with `Frozen.recordU` as the record).
//  The real vault access control is device-only (Bug 171, 0b), as in `VaultRewrapTests`.
//
//  Written first (Stage 6a), against a stub: the classical-form vault never moves.
//

import Testing
import CryptoKit
import Foundation
import LocalAuthentication
import SwiftData

@testable import Occulta
@testable import OccultaFormats

// MARK: - Helpers

private enum VaultForm: Equatable, CustomStringConvertible {
    case classical, hybrid, neither, absent

    var description: String {
        switch self {
        case .classical: return "classical"
        case .hybrid:    return "hybrid"
        case .neither:   return "neither"
        case .absent:    return "absent"
        }
    }
}

@MainActor
private func vaultForm(of sealed: Data?, aad: Data) -> VaultForm {
    guard let sealed else { return .absent }

    if Sealing.open(sealed, key: VaultPins.newKey(.hybrid), aad: aad) != nil { return .hybrid }
    if Sealing.open(sealed, key: VaultPins.newKey(.classical), aad: aad) != nil { return .classical }
    return .neither
}

extension VaultStore {

    fileprivate func entryForms() -> [UUID: VaultForm] {
        let context = self.newContext()
        var out: [UUID: VaultForm] = [:]
        for item in self.entries {
            guard let entry = context.model(for: item.id) as? VaultEntry else { out[item.uuid] = .absent; continue }
            out[item.uuid] = vaultForm(of: entry.encryptedEntryKey, aad: entry.aad(for: .entryKey))
        }
        return out
    }

    fileprivate func backupForms() -> [UUID: VaultForm] {
        let context = self.newContext()
        var out: [UUID: VaultForm] = [:]
        for item in self.backupRows where item.payload != nil {
            guard let row = context.model(for: item.id) as? BackupEncryptionKey else { out[item.uuid] = .absent; continue }
            out[item.uuid] = vaultForm(of: row.encryptedPayload, aad: row.aad())
        }
        return out
    }

    fileprivate func fileForm() -> VaultForm {
        guard let bytes = try? Data(contentsOf: self.exportMetaURL) else { return .absent }
        return vaultForm(of: bytes, aad: VaultPins.exportMetaAAD)
    }

    /// The vault epoch as stored, opened under the hybrid local key the frozen manager derives.
    fileprivate func vaultEpoch() -> KeyReseal.Epoch? {
        KeyReseal.Epoch.opening(self.config()?.vaultKeyEpoch, using: Frozen.newKey(.local, form: self.localForm))
    }
}

/// A vault on a device below iOS 26 whose first unlock has already run: the data under the classical vault key, the epoch
/// (2, classical), the tier B record classical. Then the device reaches iOS 26 and the launch moves the record to hybrid;
/// nothing else has happened yet.
@MainActor
private func classicalVaultAfterTheLaunch(
    entries: Int = 12, backupDepths: [Int] = [0, 2, 5], file: Bool = true
) throws -> (keys: TestKeyManager, store: VaultStore) {
    let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
    let store = try VaultStore(keys: keys, form: .classical, entries: entries, backupDepths: backupDepths, file: file, epoch: 1)

    let first = try store.rewrap()
    try #require(first.outcome == .rewrapped && first.form == .classical)

    // The device reaches iOS 26; the launch makes the tier B record hybrid.
    keys.hybridRecordToMake = VaultPins.record(.hybrid)
    let records = KeyReseal.upgradeRecords(keyManager: keys, staging: nil)
    try #require(records.vault)
    try #require(keys.tierPQRecordB == VaultPins.record(.hybrid))
    Manager.Ambient.setVaultKeys(.legacy)
    return (keys, store)
}

@Suite("Hybrid upgrade — the vault", .ambientFrozenTestKeyManager, .serialized)
@MainActor
struct HybridUpgradeVaultTests {

    @Test("Until the first unlock the vault is untouched and readable under the classical key: the record has moved, the data has not")
    func staysClassicalUntilTheFirstUnlock() throws {
        let (keys, store) = try classicalVaultAfterTheLaunch()

        #expect(Set(store.entryForms().values) == [.classical])
        #expect(Set(store.backupForms().values) == [.classical])
        #expect(store.fileForm() == .classical)
        #expect(store.vaultEpoch() == KeyReseal.Epoch(number: 2, form: .classical))
        #expect(keys.tierPQRecordB?.mode == .hybrid)

        // What the launch does to the vault: nothing.
        let before = store.snapshot()
        LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        let after = store.snapshot()
        let changed = before.filter { $0.key.hasPrefix("entryKey:") || $0.key.hasPrefix("backup:") || $0.key == "file" }.filter { after[$0.key] != $0.value }
        #expect(changed.isEmpty, "the vault's own values: \(shown(changed.keys.sorted()))")
    }

    @Test("The first unlock after the launch moves the vault to the hybrid key, once: the key follows the epoch's form until then and the new one after")
    func firstUnlockMovesItOnce() throws {
        let (keys, store) = try classicalVaultAfterTheLaunch()
        let vault = store.vaultManager()

        let faults = KeyReseal.Faults()
        KeyReseal.$faults.withValue(faults) { vault.unlock(context: LAContext()) }

        #expect(Set(store.entryForms().values) == [.hybrid])
        #expect(Set(store.backupForms().values) == [.hybrid])
        #expect(store.fileForm() == .hybrid)
        #expect(store.vaultEpoch() == KeyReseal.Epoch(number: 2, form: .hybrid))
        #expect(Manager.Ambient.vaultKeys == .enclaveBound)
        #expect(keyBytes(try #require(try keys.deriveVaultKey(context: LAContext()))) == keyBytes(VaultPins.newKey(.hybrid)))
        #expect(faults.reachedVault.filter { $0 == .beforeCommit }.count == 1)

        // The entries open through the vault's own API.
        for item in store.entries {
            let entry = try #require(try vault.fetchEntry(by: item.uuid))
            #expect(try vault.decryptLabel(for: entry) == item.label)
            #expect(try vault.decryptContent(for: entry) == item.content)
        }

        // Exactly once: a lock and another unlock, and a fresh manager, write nothing.
        let done = store.snapshot()
        vault.lock()
        KeyReseal.$faults.withValue(faults) { vault.unlock(context: LAContext()) }
        KeyReseal.$faults.withValue(faults) { store.vaultManager().unlock(context: LAContext()) }
        #expect(faults.reachedVault.filter { $0 == .beforeCommit }.count == 1, "the rewrap ran exactly once")
        #expect(store.snapshot() == done)
    }

    @Test("Before the rewrap has run, an unlock derives the classical key whatever the record says, and the vault opens")
    func classicalKeyWhileTheRecordIsHybrid() throws {
        let (keys, store) = try classicalVaultAfterTheLaunch()

        // The epoch's form is what decides, so that the vault is readable even if the rewrap can't run.
        keys.simulatesVaultSecretUnreadable = false
        let vault = store.vaultManager()
        let faults = KeyReseal.Faults(interruptAtVault: .beforeCommit)
        KeyReseal.$faults.withValue(faults) { vault.unlock(context: LAContext()) }

        #expect(Manager.Ambient.vaultKeys == .enclaveBoundClassical)
        #expect(keyBytes(try #require(try keys.deriveVaultKey(context: LAContext()))) == keyBytes(VaultPins.newKey(.classical)))
        #expect(Set(store.entryForms().values) == [.classical], "the failed rewrap rolled back")
        #expect(store.vaultEpoch() == KeyReseal.Epoch(number: 2, form: .classical))
        for item in store.entries {
            let entry = try #require(try vault.fetchEntry(by: item.uuid))
            #expect(try vault.decryptLabel(for: entry) == item.label, "readable under the classical key")
        }

        // The next unlock retries and finishes.
        vault.lock()
        vault.unlock(context: LAContext())
        #expect(Set(store.entryForms().values) == [.hybrid] && Manager.Ambient.vaultKeys == .enclaveBound)
    }

    @Test("Interrupted at each point of the rewrap: nothing is lost, the file is back as it was, and the next unlock moves everything once",
          arguments: KeyReseal.VaultFaultPoint.allCases)
    func interrupted(point: KeyReseal.VaultFaultPoint) throws {
        let (_, store) = try classicalVaultAfterTheLaunch()
        let before = store.snapshot()

        let stopped = KeyReseal.$faults.withValue(KeyReseal.Faults(interruptAtVault: point)) {
            try? store.rewrap()
        }

        #expect(stopped == nil, "\(point): the rewrap was to be stopped")
        #expect(store.snapshot() == before, "\(point): a stopped run changes nothing")

        let report = try store.rewrap()
        #expect(report.outcome == .rewrapped)
        #expect(Set(store.entryForms().values) == [.hybrid] && Set(store.backupForms().values) == [.hybrid] && store.fileForm() == .hybrid)
        #expect(store.vaultEpoch() == KeyReseal.Epoch(number: 2, form: .hybrid))
    }

    @Test("A kill between the file and the commit (the file under the hybrid key, every row and the epoch still classical): nothing the vault needs is unreadable, and the next run finishes")
    func killBetweenTheFileAndTheCommit() throws {
        let (_, store) = try classicalVaultAfterTheLaunch()

        // What a kill leaves: the file renamed into place, nothing committed.
        let hybridFile = Sealing.seal(store.exportMetaPlain, key: VaultPins.newKey(.hybrid), aad: VaultPins.exportMetaAAD)
        try store.writeExportMeta(hybridFile)
        #expect(store.fileForm() == .hybrid && Set(store.entryForms().values) == [.classical])

        let report = try store.rewrap()

        #expect(report.outcome == .rewrapped)
        #expect(report.exportMetadata == false, "the file was already moved")
        #expect(Set(store.entryForms().values) == [.hybrid] && store.fileForm() == .hybrid)
    }

    @Test("Each new ciphertext is opened and compared before it replaces the old: a corrupt sealer leaves the classical vault as it was")
    func readBack() throws {
        let (_, store) = try classicalVaultAfterTheLaunch()
        let before = store.snapshot()

        let report = try KeyReseal.$faults.withValue(KeyReseal.Faults(corruptsNewCiphertext: true)) { try store.rewrap() }

        #expect(report.outcome == .incomplete)
        #expect(store.snapshot() == before)
    }

    @Test("r_B unreadable at the unlock: nothing is written, nothing is created, and the vault stays on the classical key")
    func secretUnreadable() throws {
        let (keys, store) = try classicalVaultAfterTheLaunch()
        let before = store.snapshot()
        keys.simulatesVaultSecretUnreadable = true

        let report = try store.rewrap()

        #expect(report.outcome == .aborted(.tierSecretUnreadable))
        #expect(store.snapshot() == before)
    }

    @Test("A device with no ML-KEM never runs it: a classical record and a classical epoch are the end state, and nothing is written")
    func noProviderNoRewrap() throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(.classical)
        let store = try VaultStore(keys: keys, form: .classical, epoch: 1, localForm: .classical)
        try store.rewrap()
        let done = store.snapshot()

        let again = try store.rewrap()
        #expect(again.outcome == .alreadyDone)
        #expect(KeyReseal.upgradeRecords(keyManager: keys, staging: nil).vault == false)
        #expect(keys.tierPQRecordB == .classical)

        let vault = store.vaultManager()
        vault.unlock(context: LAContext())
        #expect(Manager.Ambient.vaultKeys == .enclaveBoundClassical)
        #expect(store.snapshot() == done)
    }

    @Test("Once hybrid it stays: with the epoch (2, hybrid) a second rewrap does nothing, and with no ML-KEM (which an OS can't do) it writes nothing and the record stays hybrid")
    func neverGoesBack() throws {
        let (keys, store) = try classicalVaultAfterTheLaunch()
        store.vaultManager().unlock(context: LAContext())
        let done = store.snapshot()

        #expect(try store.rewrap().outcome == .alreadyDone)

        keys.simulatesNoPostQuantum = true
        _ = try? store.rewrap()
        #expect(store.snapshot() == done)
        #expect(keys.tierPQRecordB?.mode == .hybrid)
        #expect(KeyReseal.upgradeRecords(keyManager: keys, staging: nil).vault == false)
    }

    @Test("1,000 entries at every depth, orphaned ones included: the rewrap from classical to hybrid completes; time is attached")
    func thousandEntries() throws {
        let (_, store) = try classicalVaultAfterTheLaunch(entries: 1_000, backupDepths: [0, 1, 2, 3, 4, 5, 6, 7])

        let started = ContinuousClock.now
        let report = try store.rewrap()
        let elapsed = ContinuousClock.now - started

        let milliseconds = Double(elapsed.components.seconds) * 1_000 + Double(elapsed.components.attoseconds) / 1e15
        Attachment.record(
            "classical to hybrid: 1,000 entries (depths 0...5, every 7th orphaned), 8 backup keys, 24 filler rows, the export file\n"
            + "rewrap: \(String(format: "%.1f", milliseconds)) ms (\(String(format: "%.3f", milliseconds / 1_000)) ms an entry)\n"
            + "outcome: \(report.outcome); entry keys \(report.entryKeys); backup payloads \(report.backupPayloads)\n"
            + "Software keys on the Simulator; a device adds the Enclave's cost of two derivations, once.",
            named: "vault-rewrap-1000-classical-to-hybrid.txt"
        )

        #expect(report.outcome == .rewrapped)
        #expect(report.entryKeys.resealed == 1_000 && report.entryKeys.failed == 0)
        #expect(Set(store.entryForms().values) == [.hybrid])
        #expect(elapsed < .seconds(60), "the pass took \(elapsed)")
    }

    @Test("Backups: a file exported while the vault was classical imports after the upgrade, one exported after imports too, and the backup key comes back from returned shards")
    func backupsSurvive() throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.tierPQRecordB = .classical
        let appSupport = Manager.Paths.applicationSupport
        try? FileManager.default.createDirectory(at: appSupport, withIntermediateDirectories: true)

        // A phone below iOS 26: the vault has epoch (1, classical) and the first unlock moves it onto the classical key.
        let store = try VaultStore(keys: keys, form: .classical, entries: 0, backupDepths: [], file: false, epoch: 1)
        let owner = store.vaultManager()
        owner.unlock(context: LAContext())
        #expect(store.vaultEpoch() == KeyReseal.Epoch(number: 2, form: .classical))

        try owner.setupBackup(currentDepth: 0)
        let recipients = (0..<2).map { _ in realFormatContactIdentifier() }
        let pieces = try owner.prepareBackupShards(threshold: 2, recipients: recipients, currentDepth: 0)
        try owner.setBackupShardStatuses(Dictionary(uniqueKeysWithValues: pieces.map { ($0.id, ShardStatus.confirmed) }), currentDepth: 0)
        _ = try owner.addEntry(label: "before", content: Data("while classical".utf8), type: .note)
        let exportedBefore = try owner.exportBackup(currentDepth: 0)

        // The OS update and the next launch and unlock.
        keys.hybridRecordToMake = VaultPins.record(.hybrid)
        try #require(KeyReseal.upgradeRecords(keyManager: keys, staging: nil).vault)
        owner.lock()
        owner.unlock(context: LAContext())
        #expect(store.vaultEpoch() == KeyReseal.Epoch(number: 2, form: .hybrid) && Manager.Ambient.vaultKeys == .enclaveBound)

        _ = try owner.addEntry(label: "after", content: Data("after the upgrade".utf8), type: .note)
        let exportedAfter = try owner.exportBackup(currentDepth: 0)
        #expect(try owner.currentBackupKey(currentDepth: 0).withUnsafeBytes { $0.count } == 32, "the owner's key opens under the hybrid vault key")

        for (name, file, entries) in [("exported before", exportedBefore, 1), ("exported after", exportedAfter, 2)] {
            let phoneStore = try VaultStore(keys: keys, form: .classical, entries: 0, backupDepths: [], file: false, epoch: nil)
            keys.tierPQRecordB = VaultPins.record(.hybrid)
            let phone = phoneStore.vaultManager()
            phone.unlock(context: LAContext())
            var senders = Set<String>()
            for piece in pieces {
                let sender = realFormatContactIdentifier()
                try phone.absorbShard(piece, senderIdentifier: sender)
                senders.insert(sender)
            }
            let imported = try phone.restoreBackup(from: file, currentDepth: 0, visibleContactIdentifiers: senders)
            #expect(imported, "\(name): the restore itself worked")
            #expect(try ModelContext(phoneStore.container).fetchCount(FetchDescriptor<VaultEntry>()) == entries, "\(name): entries")
        }
    }
}

//
//  HybridUpgradeTests.swift
//  OccultaTests
//
//  Bug 171, Stage 6: a device that was classical (below iOS 26) when 2.0.0 first resealed it, and has since reached
//  iOS 26, is upgraded to the hybrid form at its next launch. The trigger: an ML-KEM provider exists, tier U's stored
//  record is classical and tier U's epoch says classical. Then, with the classical form as the "legacy" key:
//
//    - a hybrid record is made and written as a *pending* item before anything is sealed under it, so the new ML-KEM
//      key is never held in memory only;
//    - every tier U value is resealed from the classical key to the hybrid one, in batches, as Stage 2 does it;
//    - one commit then holds the epoch (form hybrid), the vault epoch resealed under the new local key, and every PIN
//      verifier unwrapped with the classical wrap key and wrapped with the hybrid one;
//    - the stored record is replaced by the pending one, and the pending item deleted.
//
//  A relaunch that finds the epoch hybrid and the stored record classical finishes the swap from the pending record. Tier B
//  and tier S have no data to reseal at launch: their records move to hybrid in place. The vault's data moves at the next
//  unlock (`HybridUpgradeVaultTests`).
//
//  Frozen: the classical fixtures are sealed with the pinned classical keys, the hybrid expectation is the pinned hybrid key
//  of `Frozen.recordU` (the upgrade is told to make that record: `TestKeyManager.hybridRecordToMake`), and the upgrade of
//  the real `Manager.Key` is in `HybridUpgradeEnclaveTests`.
//
//  Written first (Stage 6a), against a stub that does nothing: nothing moves, no record changes, no launch is blocked.
//

import Testing
import CryptoKit
import Foundation
import LocalAuthentication
import SwiftData

@testable import Occulta
@testable import OccultaCore
@testable import OccultaFormats

// MARK: - Helpers

/// The form a tier U value is in now.
private enum UpgradeForm: Equatable, CustomStringConvertible {
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
private func upgradeForm(of slot: LegacyStore.Slot, in context: ModelContext) -> UpgradeForm {
    guard let current = slot.load(context) else { return .absent }

    if let opened = Sealing.open(current, key: Frozen.newKey(slot.owner, form: .hybrid), aad: slot.aad), opened == slot.plaintext { return .hybrid }
    if let opened = Sealing.open(current, key: Frozen.newKey(slot.owner, form: .classical), aad: slot.aad), opened == slot.plaintext { return .classical }
    return .neither
}

/// Every slot the launch passes leave in place, by name.
@MainActor
private func forms(_ store: LegacyStore) -> [String: UpgradeForm] {
    let context = store.newContext()
    var out: [String: UpgradeForm] = [:]
    for slot in store.slots where !LegacyStore.consumedByLaunchPasses.contains(slot.entry) {
        out[slot.name] = upgradeForm(of: slot, in: context)
    }
    return out
}

/// The slots that are not in `form`, as `name=form`.
@MainActor
private func slots(_ store: LegacyStore, notIn form: UpgradeForm) -> [String] {
    forms(store).filter { $0.value != form }.map { "\($0.key)=\($0.value)" }.sorted()
}

/// A store sealed the way the release before the fix sealed it, on a device below iOS 26, after the launch that completed
/// the Stage 2 pass in the classical form: every value under the pinned classical keys, the epoch (1, classical).
@MainActor
private func classicalDevice() throws -> (keys: TestKeyManager, store: LegacyStore) {
    let (keys, store) = try prepare(.classical)
    let first = LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
    try #require(resealReport(first)?.outcome == .completed)
    return (keys, store)
}

/// The device reaches iOS 26. Nothing stored changes: the record is still classical, and the upgrade is told to make the
/// frozen hybrid record, so that the key it ends up with is a pinned one.
@MainActor
private func reachesIOS26(_ keys: TestKeyManager) {
    keys.simulatesNoPostQuantum = false
    keys.hybridRecordToMake = Frozen.recordU
}

@MainActor
@discardableResult
private func launch(
    _ keys: TestKeyManager, _ store: LegacyStore, faults: KeyReseal.Faults? = nil, staging: ShareStagingKeyManager? = nil,
    locations: KeyReseal.Locations = .production
) -> LaunchSequence.Report {
    KeyReseal.$faults.withValue(faults) {
        LaunchSequence.run(context: store.newContext(), keyManager: keys, locations: locations, batchSize: 7, staging: staging)
    }
}

@MainActor
private func upgradeReport(_ report: LaunchSequence.Report, sourceLocation: SourceLocation = #_sourceLocation) -> KeyReseal.UpgradeReport? {
    switch report.upgrade {
    case .success(let value)?:
        return value
    case .failure(let error)?:
        Issue.record("the upgrade failed: \(error)", sourceLocation: sourceLocation)
        return nil
    case nil:
        Issue.record("the launch did not run the upgrade", sourceLocation: sourceLocation)
        return nil
    }
}

/// `keyEpoch` as the form it opens under says, or nil.
@MainActor
private func epochForm(_ store: LegacyStore) -> KeyForm? {
    for form in KeyForm.allCases {
        if let epoch = KeyReseal.Epoch.opening(appConfig(store)?.keyEpoch, using: Frozen.newKey(.local, form: form)) {
            precondition(epoch.number == 1)
            return epoch.form == .hybrid ? .hybrid : .classical
        }
    }
    return nil
}

/// The vault epoch as the local key of `form` opens it.
@MainActor
private func vaultEpoch(_ store: LegacyStore, under form: KeyForm) -> KeyReseal.Epoch? {
    KeyReseal.Epoch.opening(appConfig(store)?.vaultKeyEpoch, using: Frozen.newKey(.local, form: form))
}

// MARK: - The trigger and the happy path

@Suite("Hybrid upgrade — tier U", .ambientFrozenTestKeyManager)
@MainActor
struct HybridUpgradeTierUTests {

    @Test("The fixture is a classical device: every value under the classical key, the epoch classical, no pending record (passes today)")
    func fixtureIsClassical() throws {
        let (keys, store) = try classicalDevice()

        #expect(slots(store, notIn: .classical).isEmpty, "\(slots(store, notIn: .classical))")
        #expect(epochForm(store) == .classical)
        #expect(vaultEpoch(store, under: .classical) == KeyReseal.Epoch(number: 1, form: .classical))
        #expect(keys.tierPQRecordU == .classical && keys.pendingPQRecordU == nil)
        #expect(!keys.postQuantumAvailable)
    }

    @Test("While no ML-KEM provider exists nothing runs: no write, no pending record, the record stays classical")
    func neverRunsWithoutAProvider() throws {
        let (keys, store) = try classicalDevice()
        let before = snapshot(store)

        let report = launch(keys, store)

        #expect(upgradeReport(report)?.outcome == .notNeeded)
        #expect(snapshot(store) == before)
        #expect(keys.tierPQRecordU == .classical && keys.pendingPQRecordU == nil)
        #expect(!report.blocked)
    }

    @Test("Every inventory entry ends up hybrid with the plaintext unchanged, the counts and sizes the same, and nothing opens under the classical key")
    func everyEntryEndsHybrid() throws {
        let (keys, store) = try classicalDevice()
        let rowsBefore = try store.rowCounts(in: store.newContext())
        let sizesBefore = Dictionary(uniqueKeysWithValues: store.slots.compactMap { slot in
            LegacyStore.consumedByLaunchPasses.contains(slot.entry) ? nil : slot.load(store.newContext()).map { (slot.name, $0.count) }
        })
        reachesIOS26(keys)

        let report = try KeyReseal.upgradeTierU(context: store.newContext(), keyManager: keys, batchSize: 7)

        #expect(report.outcome == .upgraded)
        #expect(slots(store, notIn: .hybrid).isEmpty, "not hybrid: \(shown(slots(store, notIn: .hybrid)))")
        #expect(try store.rowCounts(in: store.newContext()) == rowsBefore)

        let context = store.newContext()
        let resized = store.slots.filter { sizesBefore[$0.name] != nil && sizesBefore[$0.name] != $0.load(context)?.count }.map(\.name)
        #expect(resized.isEmpty, "changed length: \(shown(resized))")

        // No value that moved still opens under the classical key.
        let leftBehind = store.slots.filter { slot in
            guard !LegacyStore.consumedByLaunchPasses.contains(slot.entry), let current = slot.load(context) else { return false }
            return Sealing.open(current, key: Frozen.newKey(slot.owner, form: .classical), aad: slot.aad) != nil
        }.map(\.name)
        #expect(leftBehind.isEmpty, "still under the classical key: \(shown(leftBehind))")

        #expect(report.total.failed == 0 && report.total.left == 0)
        // At least what was seeded: the launch passes that ran before may have backfilled a value or two of their own.
        for (entry, seeded) in store.seededCounts where !LegacyStore.consumedByLaunchPasses.contains(entry) {
            #expect((report.entries[entry]?.resealed ?? 0) >= seeded, "\(entry): seeded \(seeded), report \(String(describing: report.entries[entry]))")
        }

        #expect(epochForm(store) == .hybrid && report.epochWritten)
        #expect(keys.tierPQRecordU == Frozen.recordU, "the stored record is now the hybrid one")
        #expect(keys.pendingPQRecordU == nil, "and the pending item is gone")
    }

    @Test("The vault epoch comes across under the new local key with its number and form unchanged, and a missing one stays missing",
          arguments: [true, false])
    func vaultEpochFollows(present: Bool) throws {
        let (keys, store) = try classicalDevice()
        if !present {
            let context = store.newContext()
            try #require(try context.fetch(FetchDescriptor<AppLayerConfig>()).first).vaultKeyEpoch = nil
            try context.save()
        }
        reachesIOS26(keys)

        let report = try KeyReseal.upgradeTierU(context: store.newContext(), keyManager: keys, batchSize: 7)

        #expect(report.outcome == .upgraded)
        #expect(report.vaultEpochMoved == present)
        if present {
            #expect(vaultEpoch(store, under: .hybrid) == KeyReseal.Epoch(number: 1, form: .classical))
            #expect(vaultEpoch(store, under: .classical) == nil, "it no longer opens under the classical key")
        } else {
            #expect(appConfig(store)?.vaultKeyEpoch == nil)
        }
    }

    @Test("Through the launch sequence: the process derives the hybrid keys, the report says so, and the launch is not blocked")
    func throughTheLaunchSequence() throws {
        let (keys, store) = try classicalDevice()
        reachesIOS26(keys)

        let report = launch(keys, store)

        #expect(upgradeReport(report)?.outcome == .upgraded)
        #expect(!report.blocked && report.screen == .app)
        #expect(Manager.Ambient.tierUKeys == .enclaveBound)
        #expect(keyBytes(try #require(try keys.createHybridLocalEncryptionKey())) == keyBytes(Frozen.newKey(.local, form: .hybrid)))
        #expect(keyBytes(try #require(try keys.deriveShardCustodyKey())) == keyBytes(Frozen.newKey(.custody, form: .hybrid)))
        #expect(keyBytes(try #require(try keys.deriveRestoreVaultKey())) == keyBytes(Frozen.newKey(.restore, form: .hybrid)))
        #expect(slots(store, notIn: .hybrid).isEmpty)

        // Manager.Security reads its gate under the key it is sealed under, as at any launch.
        let security = Manager.Security(modelContainer: store.container, keyManager: keys)
        #expect(security.currentDepth == 2 && security.pinEnabled == false)
    }

    @Test("A second launch finds the epoch hybrid and the record hybrid and writes nothing")
    func secondLaunchWritesNothing() throws {
        let (keys, store) = try classicalDevice()
        reachesIOS26(keys)
        launch(keys, store)
        let done = snapshot(store)
        let record = keys.tierPQRecordU
        keys.hybridRecordToMake = nil

        let second = launch(keys, store)

        #expect(upgradeReport(second)?.outcome == .alreadyDone)
        #expect(snapshot(store) == done)
        #expect(keys.tierPQRecordU == record && keys.pendingPQRecordU == nil)
    }

    @Test("The mode never goes back: once hybrid, a launch with no ML-KEM changes nothing and the record stays hybrid")
    func neverGoesBack() throws {
        let (keys, store) = try classicalDevice()
        reachesIOS26(keys)
        launch(keys, store)
        let done = snapshot(store)

        keys.simulatesNoPostQuantum = true
        let report = launch(keys, store)

        #expect(snapshot(store) == done)
        #expect(keys.tierPQRecordU?.mode == .hybrid)
        #expect(upgradeReport(report)?.outcome == .alreadyDone || upgradeReport(report)?.outcome == .notNeeded)
        #expect(try keys.createHybridLocalEncryptionKey() == nil, "a hybrid record that can't be decapsulated gives no key, never a classical one")
    }

    @Test("A device that was hybrid from the start has nothing to upgrade")
    func hybridFromTheStart() throws {
        let (keys, store) = try prepare(.hybrid)
        launch(keys, store)
        let done = snapshot(store)

        let again = launch(keys, store)

        #expect(upgradeReport(again)?.outcome == .alreadyDone)
        #expect(snapshot(store) == done)
        #expect(keys.pendingPQRecordU == nil)
    }

    @Test("Nothing is upgraded before tier U has an epoch: the reseal comes first, and nothing is pending")
    func notBeforeTheEpoch() throws {
        let (keys, store) = try prepare(.classical)
        reachesIOS26(keys)

        // No launch has run: the store is the previous release's, the epoch missing.
        let report = try KeyReseal.upgradeTierU(context: store.newContext(), keyManager: keys, batchSize: 7)

        #expect(report.outcome == .notNeeded)
        #expect(keys.pendingPQRecordU == nil && keys.tierPQRecordU == .classical)
    }
}

// MARK: - Crash safety

/// Where the launch that upgrades is stopped, as a kill would: before anything is sealed, part-way through the batches,
/// between the batches and the commit, between the commit and the record swap, and after the swap.
enum UpgradeCrash: CaseIterable, CustomStringConvertible {
    case afterPendingWritten
    case afterFirstRow
    case midBatch
    case afterLastBatchBeforeEpoch
    case beforeCommit
    case afterCommitBeforeSwap
    case afterSwapBeforePendingDeleted

    var description: String {
        switch self {
        case .afterPendingWritten:           return "after the pending record is written"
        case .afterFirstRow:                 return "after the first row"
        case .midBatch:                      return "mid-batch"
        case .afterLastBatchBeforeEpoch:     return "after the last batch, before the epoch"
        case .beforeCommit:                  return "before the commit"
        case .afterCommitBeforeSwap:         return "after the commit, before the record swap"
        case .afterSwapBeforePendingDeleted: return "after the swap, before the pending record is deleted"
        }
    }

    var faults: KeyReseal.Faults {
        switch self {
        case .afterPendingWritten:           return KeyReseal.Faults(interruptAtUpgrade: .afterPendingWritten)
        case .afterFirstRow:                 return KeyReseal.Faults(interruptAt: .afterFirstRow)
        case .midBatch:                      return KeyReseal.Faults(interruptAt: .midBatch)
        case .afterLastBatchBeforeEpoch:     return KeyReseal.Faults(interruptAt: .afterLastBatchBeforeEpoch)
        case .beforeCommit:                  return KeyReseal.Faults(interruptAtUpgrade: .beforeCommit)
        case .afterCommitBeforeSwap:         return KeyReseal.Faults(interruptAtUpgrade: .afterCommitBeforeSwap)
        case .afterSwapBeforePendingDeleted: return KeyReseal.Faults(interruptAtUpgrade: .afterSwapBeforePendingDeleted)
        }
    }

    /// Whether the launch that stopped here is blocked: values were moved while the process would still be on the form
    /// the stored record names. Nothing moved before the first batch, and after the swap the stored record is the new one.
    var blocked: Bool {
        switch self {
        case .afterPendingWritten, .afterFirstRow, .afterSwapBeforePendingDeleted: return false
        case .midBatch, .afterLastBatchBeforeEpoch, .beforeCommit, .afterCommitBeforeSwap: return true
        }
    }

    /// What the next launch reports.
    var relaunchOutcome: KeyReseal.UpgradeOutcome {
        switch self {
        case .afterCommitBeforeSwap:         return .swapFinished
        case .afterSwapBeforePendingDeleted: return .alreadyDone
        default:                             return .upgraded
        }
    }

    /// Whether the commit had been made.
    var committed: Bool {
        switch self {
        case .afterCommitBeforeSwap, .afterSwapBeforePendingDeleted: return true
        default:                                                     return false
        }
    }
}

@Suite("Hybrid upgrade — crash safety", .ambientFrozenTestKeyManager)
@MainActor
struct HybridUpgradeCrashTests {

    @Test("Stopped at each point: nothing is unreadable then, the launch is blocked exactly when values moved under the old form, and the next launch finishes with the same pending key",
          arguments: UpgradeCrash.allCases)
    func crashPoint(crash: UpgradeCrash) throws {
        let (keys, store) = try classicalDevice()
        reachesIOS26(keys)

        let stopped = launch(keys, store, faults: crash.faults)

        // The fault fired (the upgrade is what the launch was running).
        guard case .failure? = stopped.upgrade else {
            Issue.record("the upgrade was to be stopped \(crash)")
            return
        }
        #expect(stopped.blocked == crash.blocked, "\(crash)")
        #expect(stopped.screen == (crash.blocked ? .storageError : .app))
        if crash.blocked {
            #expect(stopped.records == nil, "a blocked launch changes no other record")
        }

        // Everything is openable, under one form or the other.
        let during = forms(store)
        let unreadable = during.filter { $0.value == .neither || $0.value == .absent }.map(\.key)
        #expect(unreadable.isEmpty, "unreadable \(crash): \(shown(unreadable.sorted()))")
        #expect(epochForm(store) == (crash.committed ? .hybrid : .classical))
        #expect(keys.pendingPQRecordU != nil, "the hybrid key is in the Keychain before anything is sealed under it, and stays until the swap is done")
        #expect(keys.tierPQRecordU?.mode == (crash == .afterSwapBeforePendingDeleted ? .hybrid : .classical))
        if crash == .midBatch {
            #expect(Set(during.values) == [.classical, .hybrid], "a batch committed and the rest did not")
        }
        if crash == .afterLastBatchBeforeEpoch || crash == .beforeCommit {
            #expect(Set(during.values) == [.hybrid], "every batch committed")
        }

        // The next launch. A fresh key made now would strand what the first launch already moved, so it must reuse the pending one.
        keys.hybridRecordToMake = nil
        let relaunch = launch(keys, store)

        #expect(upgradeReport(relaunch)?.outcome == crash.relaunchOutcome, "\(crash)")
        #expect(!relaunch.blocked && relaunch.screen == .app)
        #expect(slots(store, notIn: .hybrid).isEmpty, "not hybrid after the relaunch: \(shown(slots(store, notIn: .hybrid)))")
        #expect(epochForm(store) == .hybrid)
        #expect(vaultEpoch(store, under: .hybrid) == KeyReseal.Epoch(number: 1, form: .classical))
        #expect(keys.tierPQRecordU == Frozen.recordU, "the pending record is the tier's own now")
        #expect(keys.pendingPQRecordU == nil)
        #expect(Manager.Ambient.tierUKeys == .enclaveBound)
        #expect(keyBytes(try #require(try keys.createHybridLocalEncryptionKey())) == keyBytes(Frozen.newKey(.local, form: .hybrid)))

        // And once more: nothing left to do.
        let done = snapshot(store)
        #expect(upgradeReport(launch(keys, store))?.outcome == .alreadyDone)
        #expect(snapshot(store) == done)
    }

    @Test("The commit and the record swap are one thing to the user: after the commit the data is hybrid, and a process started then finishes the swap before it derives anything")
    func relaunchInTheWindowDerivesHybrid() throws {
        let (keys, store) = try classicalDevice()
        reachesIOS26(keys)
        launch(keys, store, faults: UpgradeCrash.afterCommitBeforeSwap.faults)
        #expect(keys.tierPQRecordU == .classical && epochForm(store) == .hybrid)

        keys.hybridRecordToMake = nil
        let relaunch = launch(keys, store)

        #expect(upgradeReport(relaunch)?.outcome == .swapFinished)
        #expect(keyBytes(try #require(try keys.createHybridLocalEncryptionKey())) == keyBytes(Frozen.newKey(.local, form: .hybrid)))
        let security = Manager.Security(modelContainer: store.container, keyManager: keys)
        #expect(security.currentDepth == 2 && security.pinEnabled == false)
    }

    @Test("A swap that fails after the commit blocks the launch: the data is hybrid and the stored record is not yet, and the next launch finishes")
    func swapFailureBlocks() throws {
        let (keys, store) = try classicalDevice()
        reachesIOS26(keys)
        // The Keychain refuses the record update: the pending record is not replaceable.
        keys.simulatesRecordReplacementFailure = true

        let first = launch(keys, store)

        #expect(first.blocked && first.screen == .storageError)
        #expect(epochForm(store) == .hybrid && keys.tierPQRecordU == .classical && keys.pendingPQRecordU != nil)

        keys.simulatesRecordReplacementFailure = false
        keys.hybridRecordToMake = nil
        let second = launch(keys, store)

        #expect(upgradeReport(second)?.outcome == .swapFinished && !second.blocked)
        #expect(keys.tierPQRecordU == Frozen.recordU && keys.pendingPQRecordU == nil)
        #expect(slots(store, notIn: .hybrid).isEmpty)
    }
}

// MARK: - Failure

@Suite("Hybrid upgrade — failures", .ambientFrozenTestKeyManager)
@MainActor
struct HybridUpgradeFailureTests {

    enum Failure: CaseIterable, CustomStringConvertible {
        case providerCannotMakeTheKey
        case lockedDevice
        case tierSecretMissing
        case vaultEpochUnreadable
        case noConfigRow

        var description: String {
            switch self {
            case .providerCannotMakeTheKey: return "the provider can't make the key"
            case .lockedDevice:             return "the device is locked"
            case .tierSecretMissing:        return "r_U is missing"
            case .vaultEpochUnreadable:     return "the vault epoch doesn't open"
            case .noConfigRow:              return "there is no config row"
            }
        }
    }

    @Test("A failure writes nothing: no data, no epoch, no record, no pending item, and the launch is not blocked", arguments: Failure.allCases)
    func nothingIsWritten(failure: Failure) throws {
        let (keys, store) = try classicalDevice()
        reachesIOS26(keys)

        switch failure {
        case .providerCannotMakeTheKey: keys.simulatesHybridRecordFailure = true
        case .lockedDevice:             keys.simulatesLockedDevice = true
        case .tierSecretMissing:        keys.simulatesTierSecretMissing = true
        case .vaultEpochUnreadable:
            let context = store.newContext()
            try #require(try context.fetch(FetchDescriptor<AppLayerConfig>()).first).vaultKeyEpoch = Sealing.random(30)
            try context.save()
        case .noConfigRow:
            let context = store.newContext()
            try context.delete(model: AppLayerConfig.self)
            try context.save()
        }
        let before = snapshot(store)

        let report = try KeyReseal.upgradeTierU(context: store.newContext(), keyManager: keys, batchSize: 7)

        guard case .aborted = report.outcome else {
            Issue.record("\(failure): expected an abort, got \(report.outcome)")
            return
        }
        keys.simulatesLockedDevice = false
        #expect(snapshot(store) == before, "\(failure)")
        #expect(keys.pendingPQRecordU == nil && keys.tierPQRecordU == .classical)
        #expect(report.total == KeyReseal.Counts())
    }

    @Test("The specific reasons", arguments: [
        (Failure.providerCannotMakeTheKey, KeyReseal.UpgradeAbort.postQuantumUnavailable),
        (Failure.lockedDevice, KeyReseal.UpgradeAbort.recordUnreadable),
        (Failure.tierSecretMissing, KeyReseal.UpgradeAbort.epochUnreadable),
        (Failure.vaultEpochUnreadable, KeyReseal.UpgradeAbort.vaultEpochUnreadable),
        (Failure.noConfigRow, KeyReseal.UpgradeAbort.configMissing),
    ])
    func reasons(failure: Failure, reason: KeyReseal.UpgradeAbort) throws {
        let (keys, store) = try classicalDevice()
        reachesIOS26(keys)

        switch failure {
        case .providerCannotMakeTheKey: keys.simulatesHybridRecordFailure = true
        case .lockedDevice:             keys.simulatesLockedDevice = true
        case .tierSecretMissing:        keys.simulatesTierSecretMissing = true
        case .vaultEpochUnreadable:
            let context = store.newContext()
            try #require(try context.fetch(FetchDescriptor<AppLayerConfig>()).first).vaultKeyEpoch = Sealing.random(30)
            try context.save()
        case .noConfigRow:
            let context = store.newContext()
            try context.delete(model: AppLayerConfig.self)
            try context.save()
        }

        let report = try KeyReseal.upgradeTierU(context: store.newContext(), keyManager: keys, batchSize: 7)
        #expect(report.outcome == .aborted(reason))
    }

    @Test("A launch that can't upgrade carries on with the classical keys and a classical store: the data still opens, and the next launch tries again")
    func launchCarriesOn() throws {
        let (keys, store) = try classicalDevice()
        reachesIOS26(keys)
        keys.simulatesHybridRecordFailure = true

        let first = launch(keys, store)

        #expect(!first.blocked)
        #expect(Manager.Ambient.tierUKeys == .enclaveBound)
        #expect(slots(store, notIn: .classical).isEmpty)
        #expect(keyBytes(try #require(try keys.createHybridLocalEncryptionKey())) == keyBytes(Frozen.newKey(.local, form: .classical)))

        keys.simulatesHybridRecordFailure = false
        let second = launch(keys, store)

        #expect(upgradeReport(second)?.outcome == .upgraded)
        #expect(slots(store, notIn: .hybrid).isEmpty)
    }

    @Test("Each new ciphertext is opened and compared before it replaces the old: a corrupt sealer from the first value commits nothing, and the launch is not blocked")
    func readBackFromTheStart() throws {
        let (keys, store) = try classicalDevice()
        reachesIOS26(keys)
        let before = snapshot(store)

        let report = launch(keys, store, faults: KeyReseal.Faults(corruptsNewCiphertext: true))

        #expect(upgradeReport(report)?.outcome == .incomplete)
        #expect(!report.blocked)
        #expect(snapshot(store) == before)
        #expect(epochForm(store) == .classical && keys.tierPQRecordU == .classical)

        let next = launch(keys, store)
        #expect(upgradeReport(next)?.outcome == .upgraded)
        #expect(slots(store, notIn: .hybrid).isEmpty)
    }

    @Test("A read-back that fails after the first batch leaves a mix, writes no epoch, blocks the launch, and the next launch finishes")
    func readBackAfterTheFirstBatch() throws {
        let (keys, store) = try classicalDevice()
        reachesIOS26(keys)

        let report = launch(keys, store, faults: KeyReseal.Faults(corruptsNewCiphertext: true, corruptsFromBatch: 1))

        #expect(upgradeReport(report)?.outcome == .incomplete)
        #expect(report.blocked)
        #expect(epochForm(store) == .classical)
        #expect(Set(forms(store).values) == [.classical, .hybrid])

        keys.hybridRecordToMake = nil
        let next = launch(keys, store)
        #expect(upgradeReport(next)?.outcome == .upgraded && !next.blocked)
        #expect(slots(store, notIn: .hybrid).isEmpty)
    }
}

// MARK: - The other tiers

@Suite("Hybrid upgrade — tiers B and S", .ambientFrozenTestKeyManager)
@MainActor
struct HybridUpgradeOtherTiersTests {

    /// A share-staging key manager on a phone's items, with a software Enclave key: the app or the extension.
    @MainActor
    private struct Phone {
        let key: SecKey
        let tag = "test.s6.key.\(UUID().uuidString)"
        let secret = "test.s6.rs.\(UUID().uuidString)"
        let record = "test.s6.pqs.\(UUID().uuidString)"

        init() throws { self.key = try softwareP256Key(scalar: katScalar) }

        func process(hybrid: Bool) -> ShareStagingKeyManager {
            let key = self.key
            return ShareStagingKeyManager(
                keyTag: self.tag, tierSecretAccount: self.secret, tierPQRecordAccount: self.record,
                postQuantum: { hybrid ? InMemoryStagingPostQuantum() : nil }, enclaveKey: { key }
            )
        }

        func clean() {
            let manager = self.process(hybrid: false)
            manager.deleteTierSecret()
            manager.deleteTierPQRecord()
        }
    }

    @Test("Tier B's record moves to hybrid in place at the launch, once, and a device without ML-KEM leaves it alone")
    func tierBRecord() throws {
        let (keys, store) = try classicalDevice()
        #expect(keys.tierPQRecordB == .classical)

        launch(keys, store)
        #expect(keys.tierPQRecordB == .classical, "no provider: nothing moves")

        reachesIOS26(keys)
        let report = launch(keys, store)

        #expect(report.records?.vault == true)
        #expect(keys.tierPQRecordB == Frozen.recordU, "the hybrid record, in place")
        #expect(keys.pendingPQRecordB == nil)

        // Once: a second launch replaces nothing, and the mode never goes back.
        keys.hybridRecordToMake = nil
        let second = launch(keys, store)
        #expect(second.records?.vault == false && keys.tierPQRecordB == Frozen.recordU)
        keys.simulatesNoPostQuantum = true
        launch(keys, store)
        #expect(keys.tierPQRecordB?.mode == .hybrid)
    }

    @Test("Tier S's record moves to hybrid at the launch, and a session sealed in the classical form still opens", .enabled(if: sharedKeychainAvailable()))
    func tierSRecord() throws {
        let (keys, store) = try classicalDevice()
        let phone = try Phone()
        defer { phone.clean() }

        // The previous run, below iOS 26: the extension seals a session under the classical form.
        let classical = phone.process(hybrid: false)
        try classical.createTierItemsIfAbsent()
        let session = try classical.encrypt(data: Data("a staged session".utf8))
        #expect(try classical.tierPQRecord()?.mode == .classical)

        // The device reaches iOS 26, and the app launches.
        reachesIOS26(keys)
        let app = phone.process(hybrid: true)
        let report = launch(keys, store, staging: app)

        #expect(report.records?.staging == true)
        #expect(try app.tierPQRecord()?.mode == .hybrid)
        #expect(try app.decrypt(data: session) == Data("a staged session".utf8), "the classical fallback opens it")
        #expect(try phone.process(hybrid: true).decrypt(data: try app.encrypt(data: Data("new".utf8))) == Data("new".utf8))

        let again = launch(keys, store, staging: app)
        #expect(again.records?.staging == false)
    }

    @Test("A blocked launch changes no other record: tier B and tier S stay classical", .enabled(if: sharedKeychainAvailable()))
    func blockedLaunchLeavesTheRecords() throws {
        let (keys, store) = try classicalDevice()
        let phone = try Phone()
        defer { phone.clean() }
        let classical = phone.process(hybrid: false)
        try classical.createTierItemsIfAbsent()
        reachesIOS26(keys)

        let report = launch(keys, store, faults: UpgradeCrash.midBatch.faults, staging: phone.process(hybrid: true))

        #expect(report.blocked && report.records == nil)
        #expect(keys.tierPQRecordB == .classical)
        #expect(try classical.tierPQRecord()?.mode == .classical)
    }
}

// MARK: - PIN verifiers

@Suite("Hybrid upgrade — PIN verifiers", .ambientFrozenTestKeyManager)
@MainActor
struct HybridUpgradeVerifierTests {

    private func classicalPINs() throws -> (keys: TestKeyManager, store: VerifierStore) {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(.classical)
        let store = try VerifierStore(keys: keys)
        store.launch()
        try #require(store.sizes() == [81])
        return (keys, store)
    }

    @Test("Every verifier is unwrapped with the classical wrap key and wrapped with the hybrid one in the same upgrade: all slots change together, the inner verifier is unchanged, and every PIN verifies at every depth")
    func rewrapped() throws {
        let (keys, store) = try classicalPINs()
        let before = store.verifiers()
        let real = before.filter { FrozenPIN.unwrapped($0.value, form: .classical) != nil }
        #expect(real.count >= 7, "precondition: the real verifiers are wrapped under the classical wrap key (\(real.count))")
        reachesIOS26(keys)

        let report = store.launch()

        #expect(report.upgrade != nil)
        let after = store.verifiers()
        #expect(store.sizes() == [81])
        #expect(Set(after.keys) == Set(before.keys))
        let kept = after.filter { before[$0.key] == $0.value }.map(\.key)
        #expect(kept.isEmpty, "a verifier slot kept its bytes next to the ones that changed: \(shown(kept.sorted()))")

        // The real ones open under the hybrid wrap key to the same inner verifier as before, and not under the classical one.
        for (name, bytes) in after {
            #expect(FrozenPIN.unwrapped(bytes, form: .classical) == nil, "\(name) still opens under the classical wrap key")
            if let inner = FrozenPIN.unwrapped(bytes, form: .hybrid), let old = FrozenPIN.unwrapped(before[name] ?? Data(), form: .classical) {
                #expect(inner == old, "\(name): the inner layer is exactly what it was")
            }
        }

        let security = store.security()
        for (depth, pin) in VerifierStore.pins.enumerated() {
            #expect(try security.verify(pin) == .normal(depth: depth), "PIN \(depth) after the upgrade")
        }
        #expect(try security.verify("000000") == .wrong, "a wrong PIN stays wrong")
        #expect(Manager.Ambient.pinVerifiers == .wrapped)
    }

    @Test("Stopped at each point, every PIN verifies after the next launch, and the verifiers were never unreadable by the key the process derives",
          arguments: UpgradeCrash.allCases)
    func pinsSurviveEveryCrash(crash: UpgradeCrash) throws {
        let (keys, store) = try classicalPINs()
        reachesIOS26(keys)

        KeyReseal.$faults.withValue(crash.faults) { _ = store.launch() }

        // At the crash the stored record and the verifiers agree, or the launch was stopped before it could be asked: the
        // wrap key the stored record gives opens every verifier, or the commit has not happened.
        let committed = crash.committed
        let recordIsHybrid = keys.tierPQRecordU?.mode == .hybrid
        let wrapKey = Frozen.pinWrapKey(recordIsHybrid ? .hybrid : .classical)
        let opening = store.verifiers().values.filter { Sealing.open($0, key: wrapKey, aad: nil) != nil }.count
        if !committed || recordIsHybrid {
            #expect(opening >= 4, "the stored record's wrap key opens the real verifiers (\(opening))")
        }

        keys.hybridRecordToMake = nil
        store.launch()

        let security = store.security()
        for (depth, pin) in VerifierStore.pins.enumerated() {
            #expect(try security.verify(pin) == .normal(depth: depth), "PIN \(depth) after \(crash)")
        }
        #expect(try security.verify("000000") == .wrong)
        #expect(store.sizes() == [81])
        let hybrid = store.verifiers().values.filter { FrozenPIN.unwrapped($0, form: .hybrid) != nil }
        #expect(hybrid.count >= 7, "and they are wrapped under the hybrid wrap key now (\(hybrid.count))")
    }

    @Test("Without the wrap keys the upgrade does not start: nothing is written and no pending item is left")
    func wrapKeyUnavailable() throws {
        let (keys, store) = try classicalPINs()
        reachesIOS26(keys)
        keys.simulatesWrapKeyUnavailable = true
        let before = store.verifiers()

        let report = store.launch()

        guard case .success(let upgrade)? = report.upgrade else {
            Issue.record("the launch was to report the upgrade, not throw: \(String(describing: report.upgrade))")
            return
        }
        #expect(upgrade.outcome == .aborted(.keyUnavailable))
        #expect(store.verifiers() == before)
        #expect(keys.pendingPQRecordU == nil && keys.tierPQRecordU == .classical)
    }

    @Test("Verifiers still plain (the wrap pass has not run) are left to it: the upgrade moves the data, and the wrap pass then wraps them under the hybrid key in the same launch")
    func plainVerifiersAreWrappedHybrid() throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(.classical)
        let store = try VerifierStore(keys: keys)

        // The classical Stage 2 pass only: the wrap pass is held back by a key it can't derive.
        keys.simulatesWrapKeyUnavailable = true
        store.launch()
        keys.simulatesWrapKeyUnavailable = false
        #expect(store.sizes() == [53])

        reachesIOS26(keys)
        store.launch()

        #expect(store.sizes() == [81])
        let security = store.security()
        for (depth, pin) in VerifierStore.pins.enumerated() {
            #expect(try security.verify(pin) == .normal(depth: depth))
        }
        let real = store.verifiers().values.filter { FrozenPIN.unwrapped($0, form: .hybrid) != nil }
        #expect(real.count >= 7, "wrapped under the hybrid wrap key, not the classical one")
    }
}

// MARK: - Backups

@Suite("Hybrid upgrade — backups", .ambientFrozenTestKeyManager)
@MainActor
struct HybridUpgradeBackupTests {

    @Test("A backup exported before the upgrade imports after it, one exported after imports too, and the backup key comes back from banked and returned pieces")
    func backupsSurvive() throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(.classical)

        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: appSupport, withIntermediateDirectories: true)

        // Two phones, each launched below iOS 26: the pass has run in the classical form on both.
        let ownerStore = try makeStore()
        let phoneStore = try makeStore()
        LaunchSequence.run(context: ModelContext(ownerStore), keyManager: keys, batchSize: 7)
        LaunchSequence.run(context: ModelContext(phoneStore), keyManager: keys, batchSize: 7)

        let owner = VaultManager(modelContainer: ownerStore, keyManager: keys)
        owner.unlock(context: LAContext())
        try owner.setupBackup(currentDepth: 0)
        let recipients = (0..<2).map { _ in realFormatContactIdentifier() }
        let pieces = try owner.prepareBackupShards(threshold: 2, recipients: recipients, currentDepth: 0)
        try owner.setBackupShardStatuses(Dictionary(uniqueKeysWithValues: pieces.map { ($0.id, ShardStatus.confirmed) }), currentDepth: 0)
        _ = try owner.addEntry(label: "before", content: Data("before the upgrade".utf8), type: .note)
        let exportedBefore = try owner.exportBackup(currentDepth: 0)

        let custody = ShardCustodyManager(modelContainer: ownerStore, keyManager: keys)
        let friend  = TestKeyManager()
        for _ in 0..<2 {
            _ = custody.handleInbound(
                shardOperations: [.init(kind: .distribute, attribute: try signedShard(signer: friend, entryID: UUID()))],
                custodyManifest: nil,
                senderPublicKey: try friend.retrieveIdentity(),
                senderIdentifier: realFormatContactIdentifier(),
                vaultManager: owner
            )
        }
        #expect(try ModelContext(ownerStore).fetch(FetchDescriptor<CustodyShard>()).count == 2, "precondition: the trustee holds two pieces")

        let phone = VaultManager(modelContainer: phoneStore, keyManager: keys)
        phone.unlock(context: LAContext())
        var senders = Set<String>()
        for piece in pieces {
            let sender = realFormatContactIdentifier()
            try phone.absorbShard(piece, senderIdentifier: sender)
            senders.insert(sender)
        }
        let classicalRestore = Frozen.newKey(.restore, form: .classical)
        let bankedBefore = try ModelContext(phoneStore).fetch(FetchDescriptor<PendingShamirSecretRestore>())
        #expect(bankedBefore.count == 1)
        for row in bankedBefore {
            #expect(row.shards.flatMap { Sealing.open($0, key: classicalRestore, aad: row.aad()) } != nil, "precondition: the banked pieces are under the classical restore key")
        }

        // The OS update: both phones launch on iOS 26. They are two phones, so each has its own Keychain: the second starts
        // from the classical records again.
        reachesIOS26(keys)
        let phoneLaunch = LaunchSequence.run(context: ModelContext(phoneStore), keyManager: keys, batchSize: 7)
        keys.tierPQRecordU = .classical
        keys.tierPQRecordB = .classical
        let ownerLaunch = LaunchSequence.run(context: ModelContext(ownerStore), keyManager: keys, batchSize: 7)
        #expect(upgradeReport(ownerLaunch)?.outcome == .upgraded)
        #expect(upgradeReport(phoneLaunch)?.outcome == .upgraded)
        // A relaunch means new managers and a new unlock: the vault follows its own epoch from then on.
        owner.lock()
        phone.lock()
        owner.unlock(context: LAContext())
        phone.unlock(context: LAContext())

        // The rows are on the hybrid keys.
        let custodyKey = Frozen.newKey(.custody, form: .hybrid)
        for row in try ModelContext(ownerStore).fetch(FetchDescriptor<CustodyShard>()) {
            #expect(Sealing.open(row.encryptedPayload, key: custodyKey, aad: row.aad()) != nil, "a custody row opens under the hybrid custody key")
        }
        let restoreKey = Frozen.newKey(.restore, form: .hybrid)
        for row in try ModelContext(phoneStore).fetch(FetchDescriptor<PendingShamirSecretRestore>()) {
            #expect(row.shards.flatMap { Sealing.open($0, key: restoreKey, aad: row.aad()) } != nil, "the banked pieces open under the hybrid restore key")
        }

        // The file exported before restores from the banked pieces; the owner exports another and a third phone restores that.
        let imported = try phone.restoreBackup(from: exportedBefore, currentDepth: 0, visibleContactIdentifiers: senders)
        #expect(imported, "exported before the upgrade: the restore worked")
        #expect(try ModelContext(phoneStore).fetchCount(FetchDescriptor<VaultEntry>()) == 1)

        _ = try owner.addEntry(label: "after", content: Data("after the upgrade".utf8), type: .note)
        let exportedAfter = try owner.exportBackup(currentDepth: 0)
        let thirdStore = try makeStore()
        LaunchSequence.run(context: ModelContext(thirdStore), keyManager: keys, batchSize: 7)
        let third = VaultManager(modelContainer: thirdStore, keyManager: keys)
        third.unlock(context: LAContext())
        var thirdSenders = Set<String>()
        for piece in pieces {
            let sender = realFormatContactIdentifier()
            try third.absorbShard(piece, senderIdentifier: sender)
            thirdSenders.insert(sender)
        }
        #expect(try third.restoreBackup(from: exportedAfter, currentDepth: 0, visibleContactIdentifiers: thirdSenders), "exported after the upgrade")
        #expect(try ModelContext(thirdStore).fetchCount(FetchDescriptor<VaultEntry>()) == 2)
    }
}

// MARK: - Volume

@Suite("Hybrid upgrade — volume", .ambientFrozenTestKeyManager)
@MainActor
struct HybridUpgradeVolumeTests {

    @Test("2,000 contacts with every field and a full prekey record: the upgrade completes; time and memory are attached")
    func twoThousandContacts() throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(.classical)
        let store = try LegacyStore(keys: keys)
        try seedVolumeContacts(2_000, into: store, sealedUnder: Frozen.legacyKey(.local))

        // The classical pass first (the previous launch), then the OS update.
        let classical = try KeyReseal.run(context: store.newContext(), keyManager: keys)
        #expect(classical.outcome == .completed)
        reachesIOS26(keys)

        let started = ContinuousClock.now
        let report = try KeyReseal.upgradeTierU(context: store.newContext(), keyManager: keys)
        let elapsed = ContinuousClock.now - started
        let milliseconds = Double(elapsed.components.seconds) * 1_000 + Double(elapsed.components.attoseconds) / 1e15

        Attachment.record(
            "2,000 contacts, every field, a full prekey record; classical to hybrid (batch of \(KeyReseal.defaultBatchSize))\n"
            + "upgrade: \(String(format: "%.0f", milliseconds)) ms (\(String(format: "%.2f", milliseconds / 2_000)) ms a contact)\n"
            + "outcome: \(report.outcome); resealed/skipped/left/failed: \(report.total.resealed) / \(report.total.skipped) / \(report.total.left) / \(report.total.failed)\n"
            + "Software keys on the Simulator; a device adds the Enclave's cost of two derivations per batch.",
            named: "hybrid-upgrade-volume.txt"
        )

        #expect(report.outcome == .upgraded)
        #expect(report.entries["Profile.givenName"]?.resealed == 2_000)
        #expect(report.entries["Profile.prekeyRecordEncrypted"]?.resealed == 2_000)
        #expect(report.total.failed == 0 && report.total.left == 0)

        let hybrid = Frozen.newKey(.local, form: .hybrid)
        for profile in try store.newContext().fetch(FetchDescriptor<Contact.Profile>()).prefix(3) {
            let name = Data(base64Encoded: profile.givenName).flatMap { Sealing.open($0, key: hybrid, aad: Sealing.fixedAAD) }
            #expect(name.flatMap { String(data: $0, encoding: .utf8) }?.hasPrefix("Given ") == true)
        }
        #expect(elapsed < .seconds(600), "the upgrade took \(elapsed)")
    }
}


// MARK: - Draft attachments sealed under the compose key (Stage 8)

/// A temporary Application Support whose `Drafts/` folder holds what the upgrade has to tell apart: files sealed under the
/// compose staging key of the group and key-less drafts (a streamed one of several chunks, one of an exact chunk multiple,
/// a small one, an empty one), a file sealed under a per-contact key, and a plaintext file an earlier build left.
@MainActor
private final class DraftFiles {

    enum Kind { case compose, contactKey, plaintext }

    struct Item {
        let url: URL
        let plaintext: Data
        let kind: Kind
        let before: Data
    }

    let root: URL
    private(set) var items: [Item] = []

    /// A per-contact file key, which no compose key is.
    static let contactKey = SymmetricKey(data: Data(repeating: 0x77, count: 32))

    var locations: KeyReseal.Locations {
        KeyReseal.Locations(applicationSupport: self.root, store: nil)
    }

    var composeItems: [Item] { self.items.filter { $0.kind == .compose } }
    var otherItems: [Item] { self.items.filter { $0.kind != .compose } }

    init(composeKey: SymmetricKey) throws {
        self.root = FileManager.default.temporaryDirectory.appendingPathComponent("draft-files-\(UUID().uuidString)")
        let first  = self.root.appendingPathComponent("Drafts").appendingPathComponent(UUID().uuidString)
        let second = self.root.appendingPathComponent("Drafts").appendingPathComponent(UUID().uuidString)
        for folder in [first, second] { try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true) }

        let compose = AttachmentManager(contactKey: composeKey)
        let chunk = 262_144

        // A video, staged in chunks as the import does.
        let video = Sealing.random(2 * chunk + 12_345)
        let videoURL = first.appendingPathComponent("\(UUID().uuidString).mp4")
        let encryptor = try compose.streamingEncryptor(to: videoURL)
        var offset = 0
        while offset < video.count {
            let next = min(offset + 100_000, video.count)
            try encryptor.append(Data(video[offset..<next]))
            offset = next
        }
        try encryptor.finalize()
        try self.record(videoURL, video, .compose)

        // An exact multiple of the chunk size, through the streaming path: no short last chunk.
        let exact = Sealing.random(2 * chunk)
        let exactURL = first.appendingPathComponent("\(UUID().uuidString).mov")
        let exactEncryptor = try compose.streamingEncryptor(to: exactURL)
        try exactEncryptor.append(exact)
        try exactEncryptor.finalize()
        try self.record(exactURL, exact, .compose)

        // An image through the in-memory path, and an empty file.
        let image = Sealing.random(40_000)
        let imageURL = second.appendingPathComponent("\(UUID().uuidString).jpg")
        try compose.encrypt(image, to: imageURL)
        try self.record(imageURL, image, .compose)

        let empty = Data()
        let emptyURL = second.appendingPathComponent(UUID().uuidString)
        try compose.encrypt(empty, to: emptyURL)
        try self.record(emptyURL, empty, .compose)

        // A contact's draft: sealed under that contact's file key, which the upgrade must not touch.
        let contactData = Sealing.random(300_000)
        let contactURL = second.appendingPathComponent("\(UUID().uuidString).mp4")
        try AttachmentManager(contactKey: Self.contactKey).encrypt(contactData, to: contactURL)
        try self.record(contactURL, contactData, .contactKey)

        // What an earlier build staged as plaintext: not an attachment at all.
        let plain = Data("a plaintext draft file".utf8)
        let plainURL = first.appendingPathComponent("\(UUID().uuidString).txt")
        try plain.write(to: plainURL)
        try self.record(plainURL, plain, .plaintext)
    }

    deinit {
        try? FileManager.default.removeItem(at: self.root)
    }

    private func record(_ url: URL, _ plaintext: Data, _ kind: Kind) throws {
        self.items.append(Item(url: url, plaintext: plaintext, kind: kind, before: try Data(contentsOf: url)))
    }

    /// Whether `item` opens, to its plaintext, under the compose key of `form`.
    func opens(_ item: Item, under form: KeyForm) async -> Bool {
        let opened = try? await AttachmentManager(contactKey: Frozen.composeKey(form)).data(at: item.url)
        return opened == item.plaintext
    }

    func form(of item: Item) async -> UpgradeForm {
        if await self.opens(item, under: .hybrid) { return .hybrid }
        if await self.opens(item, under: .classical) { return .classical }
        return .neither
    }

    /// Everything under `Drafts/` that is a temporary of the upgrade.
    func temporaries() -> [URL] {
        let enumerator = FileManager.default.enumerator(at: self.root, includingPropertiesForKeys: nil)
        return (enumerator?.allObjects as? [URL] ?? []).filter { $0.lastPathComponent.hasSuffix(".resealing") }
    }

    /// The bytes of every file that is not sealed under a compose key, as they are now.
    func othersAreUntouched() -> Bool {
        self.otherItems.allSatisfy { (try? Data(contentsOf: $0.url)) == $0.before }
    }
}

/// Where the launch that upgrades a device holding group drafts is stopped: the points of `UpgradeCrash`, and the two the
/// draft files add (after the first file, and after all of them, before any row).
enum ComposeCrash: CaseIterable, CustomStringConvertible {
    case afterPendingWritten
    case afterFirstFile
    case afterFilesBeforeBatches
    case afterFirstRow
    case midBatch
    case afterLastBatchBeforeEpoch
    case beforeCommit
    case afterCommitBeforeSwap
    case afterSwapBeforePendingDeleted

    var description: String {
        switch self {
        case .afterPendingWritten:           return "after the pending record"
        case .afterFirstFile:                return "after the first draft file"
        case .afterFilesBeforeBatches:       return "after the draft files, before the first row"
        case .afterFirstRow:                 return "after the first row"
        case .midBatch:                      return "mid-batch"
        case .afterLastBatchBeforeEpoch:     return "after the last batch"
        case .beforeCommit:                  return "before the commit"
        case .afterCommitBeforeSwap:         return "after the commit, before the swap"
        case .afterSwapBeforePendingDeleted: return "after the swap"
        }
    }

    var faults: KeyReseal.Faults {
        switch self {
        case .afterPendingWritten:           return KeyReseal.Faults(interruptAtUpgrade: .afterPendingWritten)
        case .afterFirstFile:                return KeyReseal.Faults(interruptAtUpgrade: .afterFirstFile)
        case .afterFilesBeforeBatches:       return KeyReseal.Faults(interruptAt: .afterFilesBeforeBatches)
        case .afterFirstRow:                 return KeyReseal.Faults(interruptAt: .afterFirstRow)
        case .midBatch:                      return KeyReseal.Faults(interruptAt: .midBatch)
        case .afterLastBatchBeforeEpoch:     return KeyReseal.Faults(interruptAt: .afterLastBatchBeforeEpoch)
        case .beforeCommit:                  return KeyReseal.Faults(interruptAtUpgrade: .beforeCommit)
        case .afterCommitBeforeSwap:         return KeyReseal.Faults(interruptAtUpgrade: .afterCommitBeforeSwap)
        case .afterSwapBeforePendingDeleted: return KeyReseal.Faults(interruptAtUpgrade: .afterSwapBeforePendingDeleted)
        }
    }

    /// Blocked once a file was moved (or anything else) while the stored record is still classical.
    var blocked: Bool {
        switch self {
        case .afterPendingWritten, .afterSwapBeforePendingDeleted: return false
        default:                                                   return true
        }
    }

    var committed: Bool {
        self == .afterCommitBeforeSwap || self == .afterSwapBeforePendingDeleted
    }

    var relaunchOutcome: KeyReseal.UpgradeOutcome {
        switch self {
        case .afterCommitBeforeSwap:         return .swapFinished
        case .afterSwapBeforePendingDeleted: return .alreadyDone
        default:                             return .upgraded
        }
    }
}

@Suite("Hybrid upgrade — draft attachments", .ambientFrozenTestKeyManager)
@MainActor
struct HybridUpgradeDraftFileTests {

    private func device() throws -> (keys: TestKeyManager, store: LegacyStore, drafts: DraftFiles) {
        let (keys, store) = try classicalDevice()
        let drafts = try DraftFiles(composeKey: Frozen.composeKey(.classical))
        return (keys, store, drafts)
    }

    @Test("The fixture: every compose file opens under the classical compose key and not the hybrid one, and the others open under neither (passes today)")
    func fixture() async throws {
        let (_, _, drafts) = try self.device()

        #expect(drafts.composeItems.count == 4 && drafts.otherItems.count == 2)
        for item in drafts.composeItems {
            #expect(await drafts.opens(item, under: .classical))
            #expect(!(await drafts.opens(item, under: .hybrid)))
        }
        for item in drafts.otherItems {
            #expect(await drafts.form(of: item) == .neither)
        }
    }

    @Test("Every draft file sealed under the compose key moves from the classical key to the hybrid one, whatever its size, and the others are left byte for byte")
    func filesMove() async throws {
        let (keys, store, drafts) = try self.device()
        reachesIOS26(keys)

        let report = try KeyReseal.upgradeTierU(context: store.newContext(), keyManager: keys, locations: drafts.locations, batchSize: 7)

        #expect(report.outcome == .upgraded)
        for item in drafts.composeItems {
            #expect(await drafts.opens(item, under: .hybrid), "\(item.url.lastPathComponent) under the hybrid compose key")
            #expect(!(await drafts.opens(item, under: .classical)), "\(item.url.lastPathComponent) no longer under the classical one")
            #expect((try? Data(contentsOf: item.url)) != item.before, "the bytes changed")
        }
        #expect(drafts.othersAreUntouched(), "a per-contact-key file and a plaintext file stay as they are")
        #expect(report.draftFiles.resealed == 4 && report.draftFiles.left == 2 && report.draftFiles.failed == 0)
        #expect(drafts.temporaries().isEmpty)
        #expect(report.epochWritten && keys.tierPQRecordU == Frozen.recordU)
    }

    @Test("Through the launch: the default provider then derives the hybrid compose key and a view model opens the draft")
    func throughTheLaunch() async throws {
        let (keys, store, drafts) = try self.device()
        reachesIOS26(keys)

        let report = launch(keys, store, locations: drafts.locations)

        #expect(upgradeReport(report)?.outcome == .upgraded && !report.blocked)
        #expect(keyBytes(try TierUComposeStagingKey().deriveComposeStagingKey()) == keyBytes(Frozen.composeKey(.hybrid)))

        let vm = ComposeViewModel(recipient: .group(UUID()))
        vm.setup(contactManager: try composeContactManager())
        let item = try #require(drafts.composeItems.first)
        await vm.adopt(draftMessages: [OccultaFormats.File(url: item.url, format: .file(.init(name: "clip", extension: "mp4")), date: Date())])
        #expect(vm.messages.count == 1)
        #expect(try await vm.attachmentManager?.data(at: item.url) == item.plaintext)
    }

    @Test("Stopped at each point, every draft file opens under the classical or the hybrid key then, and under the hybrid key after the next launch, with the same pending key",
          arguments: ComposeCrash.allCases)
    func crashPoint(crash: ComposeCrash) async throws {
        let (keys, store, drafts) = try self.device()
        reachesIOS26(keys)

        let stopped = launch(keys, store, faults: crash.faults, locations: drafts.locations)

        guard case .failure? = stopped.upgrade else {
            Issue.record("the upgrade was to be stopped \(crash)")
            return
        }
        #expect(stopped.blocked == crash.blocked, "\(crash)")

        var forms: [UpgradeForm] = []
        for item in drafts.composeItems { forms.append(await drafts.form(of: item)) }
        #expect(!forms.contains(.neither), "a draft file opens under neither key \(crash): \(forms)")
        switch crash {
        case .afterPendingWritten: #expect(Set(forms) == [.classical], "nothing was moved yet")
        case .afterFirstFile:      #expect(forms.filter { $0 == .hybrid }.count == 1, "exactly the first file")
        default:                   #expect(Set(forms) == [.hybrid], "every file was moved before the first row")
        }
        #expect(drafts.othersAreUntouched())
        #expect(drafts.temporaries().isEmpty)

        // The next launch finishes the job. A fresh key would strand the files already moved, so it reuses the pending one.
        keys.hybridRecordToMake = nil
        let relaunch = launch(keys, store, locations: drafts.locations)

        #expect(upgradeReport(relaunch)?.outcome == crash.relaunchOutcome, "\(crash)")
        #expect(!relaunch.blocked)
        for item in drafts.composeItems {
            #expect(await drafts.opens(item, under: .hybrid), "\(item.url.lastPathComponent) after the relaunch")
        }
        #expect(drafts.othersAreUntouched())
        #expect(keys.tierPQRecordU == Frozen.recordU && keys.pendingPQRecordU == nil)
        #expect(keyBytes(try TierUComposeStagingKey().deriveComposeStagingKey()) == keyBytes(Frozen.composeKey(.hybrid)))
    }

    @Test("Each new file is read back before it replaces the old: a bad write leaves every file as it was, the upgrade uncommitted, and nothing blocked")
    func readBack() async throws {
        let (keys, store, drafts) = try self.device()
        reachesIOS26(keys)

        let report = launch(keys, store, faults: KeyReseal.Faults(corruptsNewCiphertext: true), locations: drafts.locations)

        #expect(upgradeReport(report)?.outcome == .incomplete)
        #expect(!report.blocked)
        for item in drafts.composeItems {
            #expect((try? Data(contentsOf: item.url)) == item.before, "\(item.url.lastPathComponent) is as it was")
        }
        #expect(drafts.othersAreUntouched() && drafts.temporaries().isEmpty)
        #expect(epochForm(store) == .classical && keys.tierPQRecordU == .classical)

        let next = launch(keys, store, locations: drafts.locations)
        #expect(upgradeReport(next)?.outcome == .upgraded)
        for item in drafts.composeItems { #expect(await drafts.opens(item, under: .hybrid)) }
    }

    @Test("An upgrade that aborts before it writes anything leaves the draft files alone")
    func abortLeavesFiles() async throws {
        let (keys, store, drafts) = try self.device()
        reachesIOS26(keys)
        keys.simulatesHybridRecordFailure = true

        let report = try KeyReseal.upgradeTierU(context: store.newContext(), keyManager: keys, locations: drafts.locations, batchSize: 7)

        #expect(report.outcome == .aborted(.postQuantumUnavailable))
        for item in drafts.composeItems { #expect((try? Data(contentsOf: item.url)) == item.before) }
        #expect(drafts.othersAreUntouched() && report.draftFiles == KeyReseal.Counts())
    }

    @Test("A temporary file a killed run left is removed, and its file is moved all the same")
    func staleTemporary() async throws {
        let (keys, store, drafts) = try self.device()
        reachesIOS26(keys)
        let item = try #require(drafts.composeItems.first)
        let stale = item.url.appendingPathExtension("resealing")
        try Data("half a file".utf8).write(to: stale)

        try KeyReseal.upgradeTierU(context: store.newContext(), keyManager: keys, locations: drafts.locations, batchSize: 7)

        #expect(!FileManager.default.fileExists(atPath: stale.path))
        #expect(await drafts.opens(item, under: .hybrid))
    }

    @Test("A second run finds the files under the hybrid key and writes nothing")
    func idempotent() async throws {
        let (keys, store, drafts) = try self.device()
        reachesIOS26(keys)
        try KeyReseal.upgradeTierU(context: store.newContext(), keyManager: keys, locations: drafts.locations, batchSize: 7)
        let done = drafts.composeItems.map { try? Data(contentsOf: $0.url) }

        let again = try KeyReseal.upgradeTierU(context: store.newContext(), keyManager: keys, locations: drafts.locations, batchSize: 7)

        #expect(again.outcome == .alreadyDone)
        #expect(drafts.composeItems.map { try? Data(contentsOf: $0.url) } == done)
    }

    @Test("A device with no Drafts folder upgrades without a file to move")
    func noDraftsFolder() async throws {
        let (keys, store) = try classicalDevice()
        reachesIOS26(keys)
        let empty = FileManager.default.temporaryDirectory.appendingPathComponent("no-drafts-\(UUID().uuidString)")

        let report = try KeyReseal.upgradeTierU(
            context: store.newContext(), keyManager: keys, locations: KeyReseal.Locations(applicationSupport: empty, store: nil), batchSize: 7
        )

        #expect(report.outcome == .upgraded && report.draftFiles == KeyReseal.Counts())
    }

    @Test("A device that was hybrid from the start has its draft files left alone")
    func hybridFromTheStart() async throws {
        let (keys, store) = try prepare(.hybrid)
        let drafts = try DraftFiles(composeKey: Frozen.composeKey(.hybrid))
        launch(keys, store, locations: drafts.locations)

        let again = launch(keys, store, locations: drafts.locations)

        #expect(upgradeReport(again)?.outcome == .alreadyDone)
        for item in drafts.composeItems { #expect((try? Data(contentsOf: item.url)) == item.before) }
        #expect(drafts.othersAreUntouched())
    }

    @Test("Draft files of several chunks: the upgrade completes; time is attached")
    func volume() async throws {
        let (keys, store, drafts) = try self.device()
        reachesIOS26(keys)

        let started = ContinuousClock.now
        let report = try KeyReseal.upgradeTierU(context: store.newContext(), keyManager: keys, locations: drafts.locations, batchSize: 7)
        let elapsed = ContinuousClock.now - started
        let milliseconds = Double(elapsed.components.seconds) * 1_000 + Double(elapsed.components.attoseconds) / 1e15
        let bytes = drafts.composeItems.reduce(0) { $0 + $1.plaintext.count }

        Attachment.record(
            "\(drafts.composeItems.count) compose-sealed draft files of several chunks, \(bytes) plaintext bytes, with the tier U store of the fixture\n"
            + "upgrade: \(String(format: "%.0f", milliseconds)) ms; files \(report.draftFiles)\n"
            + "Software keys on the Simulator; the files are the cost that grows with the size of the drafts.",
            named: "hybrid-upgrade-draft-files.txt"
        )
        #expect(report.outcome == .upgraded && report.draftFiles.resealed == 4)
    }
}


@MainActor
private func composeContactManager() throws -> ContactManager {
    let schema = Schema([
        Group.self, Contact.Profile.self, Contact.Profile.PhoneNumber.self, Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self, Contact.Profile.Key.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    return ContactManager(modelContainer: container, security: Manager.Security(modelContainer: container, keyManager: TestKeyManager()))
}

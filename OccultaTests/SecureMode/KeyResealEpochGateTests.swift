//
//  KeyResealEpochGateTests.swift
//  OccultaTests
//
//  Bug 171, Stage 2: the keys follow the epoch. `createHybridLocalEncryptionKey()`, `deriveShardCustodyKey()` and
//  `deriveRestoreVaultKey()` return the Enclave-bound derivation only once `AppLayerConfig.keyEpoch` exists, and the
//  legacy one before. `LaunchSequence` decides it once per process, after the pass. So a pass that aborts or doesn't
//  finish leaves the whole process on the legacy keys, consistent with a store still sealed under them, and ordinary
//  use afterwards reads and writes without losing anything. The next launch retries.
//
//  Each scenario here is a launch in which the pass does not complete, followed by the things that would destroy
//  data if the keys had switched anyway: the `migrate()` passes, a vault unlock (`migrateReconstructShardsIfNeeded`
//  deletes a row it can't open), `absorbShard` (reads an unopenable slot array as empty and overwrites it) and a
//  prekey record read followed by a write (an unreadable record starts over).
//

import Testing
import CryptoKit
import Foundation
import LocalAuthentication
import SwiftData

@testable import Occulta
@testable import OccultaCore
@testable import OccultaFormats

@Suite("Key reseal — the keys follow the epoch", .ambientFrozenTestKeyManager)
@MainActor
struct KeyResealEpochGateTests {

    /// A launch in which the pass does not complete, and writes nothing.
    enum Failure: CaseIterable, CustomStringConvertible {
        /// The Keychain refuses every read: the device is locked.
        case deviceLocked
        /// No Enclave key to derive from.
        case localKeyUnavailable
        /// The new ciphertexts don't read back.
        case readBackFails

        var description: String {
            switch self {
            case .deviceLocked:         return "device locked"
            case .localKeyUnavailable:  return "local key unavailable"
            case .readBackFails:        return "read-back fails"
            }
        }
    }

    private func launch(_ failure: Failure?, keys: TestKeyManager, store: LegacyStore) -> LaunchSequence.Report {
        switch failure {
        case .deviceLocked?:
            keys.simulatesLockedDevice = true
            defer { keys.simulatesLockedDevice = false }
            return LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        case .localKeyUnavailable?:
            keys.simulatesLocalKeyUnavailable = true
            defer { keys.simulatesLocalKeyUnavailable = false }
            return LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        case .readBackFails?:
            return KeyReseal.$faults.withValue(KeyReseal.Faults(corruptsNewCiphertext: true)) {
                LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
            }
        case nil:
            return LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        }
    }

    private func derived(_ keys: TestKeyManager) throws -> [KeyOwner: Data] {
        [
            .local:   keyBytes(try #require(try keys.createHybridLocalEncryptionKey())),
            .custody: keyBytes(try #require(try keys.deriveShardCustodyKey())),
            .restore: keyBytes(try #require(try keys.deriveRestoreVaultKey())),
        ]
    }

    // MARK: - After a completed pass

    @Test("A completed pass switches the three accessors to the Enclave-bound keys, and so does every launch after it",
          arguments: KeyForm.allCases)
    func completedPassSwitches(form: KeyForm) throws {
        let (keys, store) = try prepare(form)
        #expect(Manager.Ambient.tierUKeys == .legacy, "the default, before any launch")
        #expect(try derived(keys) == [.local: keyBytes(Frozen.legacyKey(.local)), .custody: keyBytes(Frozen.legacyKey(.custody)), .restore: keyBytes(Frozen.legacyKey(.restore))])

        let first = LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        #expect(resealReport(first)?.outcome == .completed)
        #expect(Manager.Ambient.tierUKeys == .enclaveBound)
        #expect(try derived(keys) == [.local: keyBytes(Frozen.newKey(.local, form: form)), .custody: keyBytes(Frozen.newKey(.custody, form: form)), .restore: keyBytes(Frozen.newKey(.restore, form: form))])

        let second = LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        #expect(resealReport(second)?.outcome == .alreadyDone)
        #expect(Manager.Ambient.tierUKeys == .enclaveBound)
    }

    @Test("The vault key is not tier U's: it stays the legacy derivation after the pass")
    func vaultKeyStaysLegacy() throws {
        let (keys, store) = try prepare(.hybrid)
        let context = LAContext()
        let before = keyBytes(try #require(try keys.deriveVaultKey(context: context)))

        LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)

        #expect(keyBytes(try #require(try keys.deriveVaultKey(context: context))) == before)
    }

    // MARK: - After a pass that does not complete

    @Test("A pass that doesn't complete leaves the accessors on the legacy keys, and everything ordinary use does loses nothing; the next launch completes",
          arguments: Failure.allCases, KeyForm.allCases)
    func abortedPassLeavesTheProcessOnLegacy(failure: Failure, form: KeyForm) throws {
        let (keys, store) = try prepare(form)
        let carrier = try store.addPrekeyCarrier()
        let before = snapshot(store)

        // The launch whose pass does not complete.
        let report = launch(failure, keys: keys, store: store)

        let outcome = try #require(resealReport(report)).outcome
        switch failure {
        case .deviceLocked:         #expect(outcome == .aborted(.tierSecretUnreadable))
        case .localKeyUnavailable:  #expect(outcome == .aborted(.localKeyUnavailable))
        case .readBackFails:        #expect(outcome == .incomplete)
        }
        #expect(appConfig(store)?.keyEpoch == nil, "no epoch")
        #expect(Manager.Ambient.tierUKeys == .legacy, "so the process stays on the legacy keys")
        #expect(try derived(keys) == [.local: keyBytes(Frozen.legacyKey(.local)), .custody: keyBytes(Frozen.legacyKey(.custody)), .restore: keyBytes(Frozen.legacyKey(.restore))])

        // The migrate() passes ran on data they can read: nothing is unreadable, and what they consume is gone.
        let unreadable = slots(store, notIn: .legacy, form: form, afterLaunchPasses: true)
        #expect(unreadable.isEmpty, "after the launch: \(shown(unreadable))")
        let after = snapshot(store)
        let changed = store.slots
            .filter { !LegacyStore.consumedByLaunchPasses.contains($0.entry) }
            .filter { after[$0.name] != before[$0.name] }
            .map(\.name)
        #expect(changed.isEmpty, "bytes changed by a launch whose pass wrote nothing: \(shown(changed))")
        if failure != .localKeyUnavailable {
            // With no key at all the pass can't seal anything and leaves the row for ContactManager to carry over,
            // which the read below does.
            #expect(store.prekeyRecord(of: carrier.id, openedWith: Frozen.legacyKey(.local)) == carrier.expected,
                    "migratePrekeyRecords carried the contact's keys over, on the key the process uses")
        }

        // A vault unlock: the banked piece stays, and the retired row's piece is absorbed instead of deleted.
        let vault = VaultManager(modelContainer: store.container, keyManager: keys)
        vault.unlock(context: LAContext())
        #expect(try vault.collectedShards(forAttributeID: store.restoreDistributionID).map(\.attribute.id) == [store.restoreAttributeID])
        #expect(try vault.collectedShards(forAttributeID: store.reconstructDistributionID).map(\.attribute.id) == [store.reconstructAttributeID])
        #expect(try ModelContext(store.container).fetchCount(FetchDescriptor<ReconstructShard>()) == 0)

        // absorbShard: a second piece joins the first and doesn't replace it.
        let second = try signedShard(signer: keys, entryID: store.restoreDistributionID)
        try vault.absorbShard(second, senderIdentifier: realFormatContactIdentifier())
        let banked = try vault.collectedShards(forAttributeID: store.restoreDistributionID).map(\.attribute.id)
        #expect(Set(banked) == [store.restoreAttributeID, second.id], "both pieces are in the buffer: \(banked)")

        // A prekey record read, then written back, as a received message does.
        let security = Manager.Security(modelContainer: store.container, keyManager: keys)
        let contacts = ContactManager(modelContainer: store.container, security: security)
        let profile = try #require(contacts.modelContext.model(for: carrier.id) as? Contact.Profile)
        let record = try contacts.prekeyRecord(for: profile)
        #expect(record == carrier.expected, "read as the contact's record, not as an empty one with legacy keys in use")
        try contacts.store(record, for: profile)
        try contacts.modelContext.save()
        #expect(try contacts.prekeyRecord(for: profile) == carrier.expected)

        // The next launch, with the condition gone, completes the pass and switches the process.
        let next = launch(nil, keys: keys, store: store)
        #expect(resealReport(next)?.outcome == .completed)
        #expect(Manager.Ambient.tierUKeys == .enclaveBound)
        // Ordinary use changed three of the rows on purpose: the unlock deleted the status update and absorbed the
        // retired shard, and absorbShard added a piece to the restore buffer. They are checked by what they hold, below.
        let usedUp = ["PendingShardStatusUpdate.encryptedPayload", "ReconstructShard.encryptedPayload", "PendingShamirSecretRestore.shards"]
        let notNew = slots(store, notIn: .new, form: form, afterLaunchPasses: true).filter { described in !usedUp.contains { described.hasPrefix($0) } }
        #expect(notNew.isEmpty, "after the next launch: \(shown(notNew))")
        #expect(keyEpoch(store, form: form) == Frozen.epoch(form))
        #expect(store.prekeyRecord(of: carrier.id, openedWith: Frozen.newKey(.local, form: form)) == carrier.expected)

        // And what ordinary use added in between survived the move: the second piece is still banked.
        let afterwards = VaultManager(modelContainer: store.container, keyManager: keys)
        afterwards.unlock(context: LAContext())
        #expect(Set(try afterwards.collectedShards(forAttributeID: store.restoreDistributionID).map(\.attribute.id)) == [store.restoreAttributeID, second.id])
    }

    @Test("A launch whose pass is cut short by a failed save runs no migrate() pass, and the next launch finishes the pass first",
          arguments: KeyForm.allCases)
    func interruptedPassWaitsForTheNextLaunch(form: KeyForm) throws {
        let (keys, store) = try prepare(form)
        let rowsBefore = try store.rowCounts(in: store.newContext())

        let faults = KeyReseal.Faults(interruptAt: .midBatch)
        let report = KeyReseal.$faults.withValue(faults) {
            LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        }

        guard case .failure(let error) = report.reseal else {
            Issue.record("the pass was to be cut short")
            return
        }
        #expect((error as? KeyReseal.InjectedFault)?.point == .midBatch)
        #expect(Manager.Ambient.tierUKeys == .legacy)
        #expect(appConfig(store)?.keyEpoch == nil)
        #expect(try store.rowCounts(in: store.newContext()) == rowsBefore, "the passes that delete rows (GlobalShardConfig, ReconstructShard at unlock) did not run")

        let next = launch(nil, keys: keys, store: store)
        #expect(resealReport(next)?.outcome == .completed)
        #expect(slots(store, notIn: .new, form: form, afterLaunchPasses: true).isEmpty)
        #expect(Manager.Ambient.tierUKeys == .enclaveBound)
    }

    @Test("A launch decides again: a pass that aborts after an earlier launch switched the process puts it back on the legacy keys")
    func eachLaunchDecidesAgain() throws {
        let (keys, store) = try prepare(.hybrid)

        LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        #expect(Manager.Ambient.tierUKeys == .enclaveBound)

        // The previous release ran over the store and dropped the epoch; the device is locked at this launch.
        try store.downgrade()
        let report = launch(.deviceLocked, keys: keys, store: store)

        #expect(resealReport(report)?.outcome == .aborted(.tierSecretUnreadable))
        #expect(Manager.Ambient.tierUKeys == .legacy)
    }

    @Test("A missing secret after the epoch leaves the accessors on the Enclave-bound keys, which fail loudly: nothing is recreated and nothing falls back to the legacy key")
    func missingSecretAfterEpochFailsLoudly() throws {
        let (keys, store) = try prepare(.hybrid)
        LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        #expect(Manager.Ambient.tierUKeys == .enclaveBound)

        keys.tierSecretU = nil
        let launch = LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)

        guard case .success(let bootstrap) = launch.bootstrap else {
            Issue.record("the bootstrap failed: \(launch.bootstrap)")
            return
        }
        #expect(bootstrap.refusals.contains(.tierSecretMissingAfterEpoch))
        #expect(!bootstrap.createdTierSecret && keys.tierSecretU == nil)
        #expect(Manager.Ambient.tierUKeys == .enclaveBound, "the data is under the new keys; the legacy ones would read nothing")
        #expect(try keys.createHybridLocalEncryptionKey() == nil)
        #expect(try keys.deriveShardCustodyKey() == nil)
        #expect(try keys.deriveRestoreVaultKey() == nil)
    }
}

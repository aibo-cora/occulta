//
//  KeyReseal.swift
//  Occulta
//
//  The key reseal of Bug 171 (`Docs/Features/Secure Mode/bugs.md`), Stage 2: every value sealed under a tier-U legacy
//  key (the local DB key, the shard custody key, the restore buffer key) is moved onto its Enclave-bound key, at
//  launch, before `Manager.Security` reads anything. The inventory (`KeyReseal+Inventory.swift`) says what there is
//  to move and how each value is sealed.
//
//  The bootstrap and the pass are in `KeyReseal+Run.swift`. `OccultaTests/SecureMode/KeyResealTests.swift` and the
//  suites beside it were written against this shape first (Stage 2a), and the three accessors that follow the epoch
//  (`createHybridLocalEncryptionKey()`, `deriveShardCustodyKey()`, `deriveRestoreVaultKey()`) switch with it.
//
//  What the pass does (the plan, "Stage 2"):
//    - open a value under the new key: skip it; under the legacy key: reseal it with the same AAD and the same
//      length, and open the new ciphertext and compare it before it replaces the old one; under neither: leave the
//      bytes alone;
//    - files first, then the rows in batches of `batchSize`, each batch one `save()`, with autosave off;
//    - after the last batch, a final write sets the sealed `AppLayerConfig.keyEpoch`; only then do later launches
//      skip the pass;
//    - a key, a tier secret or a PQ record that can't be read means no writes and no epoch, and a reason in the
//      report;
//    - `Contact.Profile.identifier` and everything that stores it as a value stay byte-identical.
//

import Foundation
import SwiftData
import CryptoKit

extension KeyReseal {

    // MARK: - Where things are

    /// Where the pass looks for files sealed outside SwiftData. Tier U owns no file: the one resealed file,
    /// `backup-export-meta.dat`, is under the vault key and belongs to Stage 4. The parameter is here so that Stage 4
    /// adds a path and not a signature, and the fault point `afterFilesBeforeBatches` still marks the place.
    nonisolated struct Locations: Equatable {
        var applicationSupport: URL
        /// The SwiftData store, whose WAL is checkpointed after the epoch is written so no legacy ciphertext lingers
        /// in it. nil for an in-memory store.
        var store: URL?

        static var production: Locations {
            Locations.production(store: nil)
        }

        static func production(store: URL?) -> Locations {
            Locations(applicationSupport: FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0], store: store)
        }
    }

    /// Rows per `save()`. A launch that is killed part-way keeps the batches already committed, and the next launch
    /// finishes the rest, so a big store can't make every launch exceed the watchdog and be killed again.
    nonisolated static let defaultBatchSize = 200

    // MARK: - The epoch

    /// What `AppLayerConfig.keyEpoch` and `vaultKeyEpoch` hold, sealed: two bytes, the same on every install.
    nonisolated struct Epoch: Equatable {

        /// 1 once tier U's data is under the Enclave-bound keys; for the vault epoch, 1 until the rewrap, then 2.
        let number: UInt8

        /// Which form the data is under, so the upgrade pass of a device that reaches iOS 26 knows what to do.
        let form: TierPQRecord.Mode

        static let size = 2

        func encoded() -> Data {
            Data([self.number, self.form.rawValue])
        }

        init(number: UInt8, form: TierPQRecord.Mode) {
            self.number = number
            self.form   = form
        }

        init?(decoding data: Data) {
            guard data.count == Self.size, let form = TierPQRecord.Mode(rawValue: data[data.startIndex + 1]) else { return nil }

            self.number = data[data.startIndex]
            self.form   = form
        }

        /// Sealed as every local value is: `Data.encrypt(using:)`, AAD `[2]`. 30 bytes.
        @MainActor
        func sealed(using key: SymmetricKey) throws -> Data? {
            try self.encoded().encrypt(using: key)
        }

        /// nil unless `sealed` opens under `key` to a two-byte epoch.
        @MainActor
        static func opening(_ sealed: Data?, using key: SymmetricKey) -> Epoch? {
            sealed?.decrypt(using: key).flatMap { Epoch(decoding: $0) }
        }
    }

    // MARK: - What a run reports

    /// What happened to the values of one inventory entry.
    nonisolated struct Counts: Equatable {
        /// Already under the new key.
        var skipped = 0
        /// Opened under the legacy key and moved.
        var resealed = 0
        /// Opened under neither key, and left as they were.
        var left = 0
        /// Opened under the legacy key but couldn't be moved: the new ciphertext didn't read back, or sealing failed.
        /// The old bytes stay.
        var failed = 0
        /// Random filler that opens under no key, rewritten as fresh random bytes of the same length, so that in a
        /// container mixing real and filler members every member changes (the uniform-change rule).
        var refreshed = 0

        static func + (lhs: Counts, rhs: Counts) -> Counts {
            Counts(
                skipped: lhs.skipped + rhs.skipped, resealed: lhs.resealed + rhs.resealed, left: lhs.left + rhs.left,
                failed: lhs.failed + rhs.failed, refreshed: lhs.refreshed + rhs.refreshed
            )
        }
    }

    /// Why a run wrote nothing.
    nonisolated enum AbortReason: Equatable {
        /// `Manager.Ambient`'s local key can't be derived: no Enclave.
        case localKeyUnavailable
        /// The shard custody or the restore buffer key can't be derived.
        case custodyKeyUnavailable
        case restoreKeyUnavailable
        /// `r_U` isn't in the Keychain. The pass never creates it: a new one would leave everything sealed under the
        /// old one unreadable.
        case tierSecretMissing
        /// `r_U` couldn't be read for a reason other than absence: a locked device.
        case tierSecretUnreadable
        /// The tier U PQ record isn't in the Keychain. Never created by the pass.
        case tierPQRecordMissing
        case tierPQRecordUnreadable
        /// There is no `AppLayerConfig` row to hold the epoch.
        case configMissing
    }

    nonisolated enum Outcome: Equatable {
        /// The pass didn't run: the default of a report nothing has filled in.
        case notRun
        /// The pass ran to its end and set the epoch.
        case completed
        /// The epoch was already set, so nothing was read or written.
        case alreadyDone
        /// The pass ran but couldn't move every value (the read-back caught a bad ciphertext): the old bytes stay, no
        /// epoch is written, and the next launch tries again.
        case incomplete
        /// Nothing was written and no epoch was set.
        case aborted(AbortReason)
    }

    /// Per inventory entry (`"Model.attribute"`) counts of what the run did. DEBUG tooling and tests read it; nothing
    /// is logged in Release.
    nonisolated struct Report: Equatable {
        var outcome: Outcome = .notRun
        var entries: [String: Counts] = [:]

        /// Whether the run wrote the epoch.
        var epochWritten = false

        var total: Counts {
            self.entries.values.reduce(Counts(), +)
        }
    }

    /// How far a run got, readable after it threw. `Report` is lost with the throw, and a launch needs to know whether
    /// the run that ended without an epoch had already committed a batch (`LaunchSequence`, Stage 2c): the store is then
    /// a mix of both keys.
    final class Progress {
        /// Batches whose `save()` succeeded.
        private(set) var committedBatches = 0

        func batchCommitted() {
            self.committedBatches += 1
        }
    }

    // MARK: - The bootstrap

    /// Why the bootstrap created nothing it would otherwise have created.
    nonisolated enum Refusal: Equatable {
        /// An epoch exists, so tier U's data is sealed under `r_U` and `r_U` is gone: a new one would make it all
        /// unreadable. Left missing, for every derivation to fail loudly.
        case tierSecretMissingAfterEpoch
        case tierPQRecordMissingAfterEpoch
        /// The vault's epoch is 2, so the vault is sealed under a key that includes the tier B record, and it is gone.
        case vaultRecordMissingAfterEpoch
        /// A Keychain read failed (a locked device): nothing is created on a guess.
        case unreadable
    }

    nonisolated struct BootstrapReport: Equatable {
        var createdTierSecret = false
        var createdTierPQRecord = false
        /// The tier B (vault) PQ record. `r_B` is not made here: adding it needs no evaluation, but the first unlock
        /// makes it with the vault's context, and a new vault key makes it at its own creation.
        var createdVaultRecord = false
        /// The `AppLayerConfig` row didn't exist (a fresh install) and the bootstrap made it, as `Manager.Security`
        /// would have, so there is somewhere to write the epochs before `Manager.Security` runs.
        var createdConfig = false
        var seededVaultKeyEpoch = false
        var refusals: [Refusal] = []
    }
}

// MARK: - Fault injection

#if DEBUG
extension KeyReseal {

    /// Where a test can have the pass stop, as a kill would.
    nonisolated enum FaultPoint: String, CaseIterable {
        /// After the first row of the first batch is rewritten in memory, before any `save()`.
        case afterFirstRow
        /// Part-way through the second batch, before its `save()`: the first batch is committed and this one is not.
        /// Needs a `batchSize` smaller than the number of rows.
        case midBatch
        /// After the files and before the first batch. Tier U has no file, so nothing is written yet; the point is
        /// here for Stage 4, and the pass reaches it all the same.
        case afterFilesBeforeBatches
        /// After the last batch is saved, before the epoch is written.
        case afterLastBatchBeforeEpoch
    }

    nonisolated struct InjectedFault: Error, Equatable {
        let point: FaultPoint
    }

    /// The same, for the verifier wrap pass (`wrapVerifiers`), which has its own points: it is one transaction on one
    /// row, and a test that stops the tier U pass at `afterFirstRow` must not stop this one.
    nonisolated enum WrapFaultPoint: String, CaseIterable {
        /// After the first value is sealed in memory.
        case afterFirstValue
        /// After about half of them are, before any is assigned.
        case midWrap
        /// After every new value is assigned to the row, before the one `save()`.
        case beforeSave
    }

    nonisolated struct InjectedWrapFault: Error, Equatable {
        let point: WrapFaultPoint
    }

    /// The same, for the vault rewrap (`rewrapVault`): one transaction, with a file written before it.
    nonisolated enum VaultFaultPoint: String, CaseIterable {
        /// After the first value is worked out in memory.
        case afterFirstValue
        /// After about half of them are, before any file or row is written.
        case midRewrap
        /// After `backup-export-meta.dat` has been renamed into place, before any row is assigned or committed. A kill
        /// here leaves the file under the new key and every row under the old one, and the next unlock finishes.
        case afterFileBeforeCommit
        /// After every row and the epoch are assigned in memory, before the one `save()`.
        case beforeCommit
    }

    nonisolated struct InjectedVaultFault: Error, Equatable {
        let point: VaultFaultPoint
    }

    /// What a test binds around a run, as `Manager.Ambient.override` is bound: task-local, so tests that run in
    /// parallel don't see each other's. Release has no hook at all.
    ///
    /// The pass calls `reach(_:)` at each `FaultPoint` and seals every new ciphertext through `corrupted(_:)` before
    /// the read-back check. A pass that never reaches a point it was asked to stop at leaves it out of `reached`,
    /// which is how a test knows the point exists.
    final class Faults {
        let interruptAt: FaultPoint?
        let interruptAtWrap: WrapFaultPoint?
        let interruptAtVault: VaultFaultPoint?
        let corruptsNewCiphertext: Bool
        /// With `corruptsNewCiphertext`: only once this many batches have been committed, so a read-back failure can
        /// come part-way through the pass instead of at its first value.
        let corruptsFromBatch: Int
        private(set) var reached: [FaultPoint] = []
        private(set) var reachedWrap: [WrapFaultPoint] = []
        private(set) var reachedVault: [VaultFaultPoint] = []

        init(
            interruptAt: FaultPoint? = nil, interruptAtWrap: WrapFaultPoint? = nil, interruptAtVault: VaultFaultPoint? = nil,
            corruptsNewCiphertext: Bool = false, corruptsFromBatch: Int = 0
        ) {
            self.interruptAt           = interruptAt
            self.interruptAtWrap       = interruptAtWrap
            self.interruptAtVault      = interruptAtVault
            self.corruptsNewCiphertext = corruptsNewCiphertext
            self.corruptsFromBatch     = corruptsFromBatch
        }

        /// Records the point and throws `InjectedVaultFault` if it is the one asked for.
        func reachVault(_ point: VaultFaultPoint) throws {
            self.reachedVault.append(point)
            if self.interruptAtVault == point { throw InjectedVaultFault(point: point) }
        }

        /// Records the point and throws `InjectedWrapFault` if it is the one asked for.
        func reachWrap(_ point: WrapFaultPoint) throws {
            self.reachedWrap.append(point)
            if self.interruptAtWrap == point { throw InjectedWrapFault(point: point) }
        }

        /// Records the point and throws `InjectedFault` if it is the one asked for.
        func reach(_ point: FaultPoint) throws {
            self.reached.append(point)
            if self.interruptAt == point { throw InjectedFault(point: point) }
        }

        /// `ciphertext` as the sealer under test produced it: with the last byte (the GCM tag's) flipped when
        /// `corruptsNewCiphertext` is set, so the read-back check has something to catch.
        func corrupted(_ ciphertext: Data, committedBatches: Int = 0) -> Data {
            guard self.corruptsNewCiphertext, committedBatches >= self.corruptsFromBatch, !ciphertext.isEmpty else { return ciphertext }

            var out = ciphertext
            out[out.count - 1] ^= 0x01
            return out
        }
    }

    @TaskLocal static var faults: Faults?
}
#endif

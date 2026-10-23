//
//  KeyReseal+Upgrade.swift
//  Occulta
//
//  The upgrade of Bug 171, Stage 6 (`Docs/Features/Secure Mode/bugs.md`): a device that was below iOS 26 when 2.0.0 first
//  resealed it holds the *classical* form (`HKDF(t ‖ r)`, a classical tier record). When it reaches iOS 26 the next launch
//  moves it to the hybrid form (`HKDF(t ‖ ss ‖ r)`, with the Enclave's ML-KEM secret), which is the second reseal on those
//  devices only. Images taken while it was classical stay classical: no reseal protects what is already copied.
//
//  Tier U, in this order, with the classical form as the "legacy" key (`upgradeTierU`):
//
//    1. A hybrid record is made and written to a second Keychain item, the *pending* record, **before any key is derived
//       from it to seal with**. The new ML-KEM key is never only in memory: a kill after the data commit must not lose it.
//       A pending record that is already there (a kill earlier) is reused, because rows already moved are under its key.
//    2. Every draft attachment sealed under the classical compose staging key is resealed under the hybrid one, file by
//       file (Stage 8), and then every tier U value (the inventory of Stage 2) from the classical key to the hybrid
//       one, in batches, each batch one `save()`, each new ciphertext opened and compared before it replaces the old.
//    3. One commit, one `save()` on the config row: the epoch (form hybrid), the vault epoch (resealed under the new local
//       key, same number and form), and every PIN verifier (unwrapped with the classical wrap key and wrapped with the
//       hybrid one). The stored record is classical until step 4, and the data and the verifiers are hybrid from here.
//    4. The tier's own record is replaced by the pending one, in place, and the pending item is deleted.
//
//  A launch that finds the epoch hybrid and the stored record classical is between 3 and 4: it finishes the swap from the
//  pending record before anything derives a key. The pending item exists only during one upgrade, on a device that is
//  being upgraded; once the swap is done there is none.
//
//  Tier B's and tier S's records move to hybrid in place (`upgradeRecords`): they hold no data at launch, so no pending
//  record is needed. The vault's data moves at the next unlock, through the Stage 4 rewrap with classical as its "legacy"
//  key (`rewrapVault`); the key the vault derives follows the vault epoch's form meanwhile (`Manager.Ambient.vaultKeys`).
//
//  Never run while no ML-KEM provider exists, and a record never goes back to classical.
//
//  `OccultaTests/SecureMode/HybridUpgradeTests.swift` was written against a stub of this first (Stage 6a).
//

import Foundation
import SwiftData
import CryptoKit

extension KeyReseal {

    nonisolated enum UpgradeAbort: Equatable {
        /// There is no `AppLayerConfig` row.
        case configMissing
        /// The epoch opens under neither the classical local key nor a hybrid one, or contradicts the record.
        case epochUnreadable
        /// The vault epoch doesn't open under the classical local key. Committing the new epoch would strand it.
        case vaultEpochUnreadable
        /// The tier U record can't be read (a locked device) or is missing.
        case recordUnreadable
        /// The pending record couldn't be stored, or read back as it was stored.
        case pendingUnreadable
        /// A provider exists but can't make the ML-KEM key.
        case postQuantumUnavailable
        /// A classical or hybrid key (local, custody, restore, PIN wrap) can't be derived.
        case keyUnavailable
    }

    nonisolated enum UpgradeOutcome: Equatable {
        /// The upgrade didn't run.
        case notRun
        /// Nothing to do: no epoch yet, or no ML-KEM provider.
        case notNeeded
        /// Moved, committed and swapped.
        case upgraded
        /// A launch found the commit made and the record not swapped, and swapped it.
        case swapFinished
        /// The epoch and the record are hybrid already (a stale pending item, if any, was deleted).
        case alreadyDone
        /// A new ciphertext didn't read back: nothing was committed, and the next launch tries again.
        case incomplete
        /// Nothing was written (the pending record apart, if it was already stored).
        case aborted(UpgradeAbort)
    }

    nonisolated struct UpgradeReport: Equatable {
        var outcome = UpgradeOutcome.notRun
        var entries: [String: Counts] = [:]
        /// The PIN verifiers: unwrapped and wrapped again (`resealed`), sealed again with a fresh nonce because they were
        /// under the hybrid wrap key already (`skipped`), random filler replaced (`refreshed`), another size (`left`).
        var verifiers = Counts()
        /// Draft attachment files sealed under the compose staging key (Stage 8): `resealed` moved to the hybrid key,
        /// `skipped` already under it, `left` under neither key (a per-contact key, or plaintext), `failed` that didn't read back.
        var draftFiles = Counts()
        var vaultEpochMoved = false
        /// The pending record was there from an earlier launch and was used.
        var pendingReused = false
        var epochWritten = false

        var total: Counts {
            self.entries.values.reduce(Counts(), +)
        }
    }

    /// What `upgradeRecords` did to the records that hold no data at launch.
    nonisolated struct RecordUpgradeReport: Equatable {
        /// Tier B's record was classical and is hybrid now.
        var vault = false
        /// Tier S's record was classical and is hybrid now.
        var staging = false
        var failures: [String] = []
    }

    private struct UpgradeAborted: Error {
        let reason: UpgradeAbort
    }

    // MARK: - Where the upgrade stands

    /// Where tier U's upgrade stands, from the store and the Keychain.
    enum UpgradeState: Equatable {
        /// The reseal hasn't completed: nothing to upgrade yet.
        case epochMissing
        /// The epoch and the record are classical, and there is no ML-KEM provider: nothing to do, and the mode stays.
        case waiting
        /// The epoch and the record are classical and a provider exists. `pending` is a hybrid record an earlier launch
        /// wrote and that rows may already be sealed under.
        case needsUpgrade(pending: TierPQRecord?)
        /// The epoch is hybrid and the stored record is classical: the commit was made and the swap was not.
        case finishSwap(pending: TierPQRecord)
        /// The stored record is hybrid. `stalePending` is a pending item left by a kill between the swap and its deletion.
        case current(stalePending: Bool)
    }

    /// Reads the state. Throws `UpgradeAborted` for what it can't read.
    ///
    /// A hybrid stored record means the epoch is hybrid: the record is replaced only after the commit. So the epoch is
    /// opened only to tell the two classical-record cases apart, with the classical local key (the upgrade has not been
    /// committed) or the hybrid one the pending record gives (it has).
    @MainActor
    private static func upgradeState(config: AppLayerConfig, keyManager: any KeyManagerProtocol) throws -> UpgradeState {
        guard config.keyEpoch != nil else { return .epochMissing }

        let main: TierPQRecord?
        do { main = try keyManager.tierPQRecord(.deviceUnlock) } catch { throw UpgradeAborted(reason: .recordUnreadable) }
        let pending: TierPQRecord?
        do { pending = try keyManager.pendingTierPQRecord(.deviceUnlock) } catch { throw UpgradeAborted(reason: .pendingUnreadable) }

        guard let main else { throw UpgradeAborted(reason: .recordUnreadable) }

        if main.mode == .hybrid { return .current(stalePending: pending != nil) }

        let ambient = Manager.Ambient.keyManager

        if
            let classicalLocal = try? ambient.enclaveBoundKey(.localDB, record: .classical),
            let epoch = Epoch.opening(config.keyEpoch, using: classicalLocal)
        {
            guard epoch.form == .classical else { throw UpgradeAborted(reason: .epochUnreadable) }
            guard keyManager.postQuantumAvailable else { return .waiting }
            return .needsUpgrade(pending: pending?.mode == .hybrid ? pending : nil)
        }

        if
            let pending, pending.mode == .hybrid,
            let hybridLocal = try? ambient.enclaveBoundKey(.localDB, record: pending),
            let epoch = Epoch.opening(config.keyEpoch, using: hybridLocal), epoch.form == .hybrid
        {
            return .finishSwap(pending: pending)
        }

        throw UpgradeAborted(reason: .epochUnreadable)
    }

    /// Whether the upgrade, as it ended (by returning or by throwing), left the store where the process can't read it: values
    /// were moved to the hybrid form while the stored record, which the process derives from, is still classical. Then the
    /// launch is blocked, as a reseal that stopped partway is (Stage 2c).
    ///
    /// - A commit made and the record not swapped is stranded however the launch got there.
    /// - Before the commit, the upgrade is stranded once a batch was saved: some rows are hybrid and the epoch says classical.
    ///   One that stopped before saving anything left the store as it was.
    @MainActor
    static func upgradeIsStranded(context: ModelContext, keyManager: any KeyManagerProtocol, progress: Progress) -> Bool {
        guard let config = (try? context.fetch(FetchDescriptor<AppLayerConfig>()).first) ?? nil else { return false }

        switch try? Self.upgradeState(config: config, keyManager: keyManager) {
        case .needsUpgrade?:                      return progress.movedAnything
        case .finishSwap?:                        return true
        case .current?, .waiting?, .epochMissing?: return false
        case nil:                                 return progress.movedAnything
        }
    }

    // MARK: - Tier U

    /// Upgrades tier U from the classical form to the hybrid one. See the header for the order.
    ///
    /// - Nothing runs while the epoch is missing or no ML-KEM provider exists (`.notNeeded`), or once the stored record is
    ///   hybrid (`.alreadyDone`, which deletes a stale pending item).
    /// - A state that can't be read, a key that can't be derived, a vault epoch that doesn't open or a provider that can't
    ///   make the key means no writes (`.aborted`); the pending record is the one exception, written once the keys derive.
    /// - A new ciphertext that doesn't read back means no commit (`.incomplete`).
    ///
    /// Throws what an interruption looks like (`InjectedFault` or `InjectedUpgradeFault` in a test, a SwiftData error from a
    /// `save()`, an error from the Keychain). Batches already saved stay, every value in them readable under the hybrid key
    /// the pending record gives, and the next launch finishes; `progress` says whether any were.
    @MainActor
    @discardableResult
    static func upgradeTierU(
        context: ModelContext, keyManager: any KeyManagerProtocol, locations: Locations = .production,
        batchSize: Int = KeyReseal.defaultBatchSize, progress: Progress? = nil
    ) throws -> UpgradeReport {
        var report = UpgradeReport()

        do {
            try Self.performUpgrade(
                context: context, keyManager: keyManager, locations: locations, batchSize: max(1, batchSize),
                progress: progress, report: &report
            )
        } catch let aborted as UpgradeAborted {
            context.rollback()
            report = UpgradeReport(outcome: .aborted(aborted.reason))
        } catch {
            context.rollback()
            throw error
        }
        return report
    }

    @MainActor
    private static func performUpgrade(
        context: ModelContext, keyManager: any KeyManagerProtocol, locations: Locations, batchSize: Int, progress: Progress?,
        report: inout UpgradeReport
    ) throws {
        guard let config = try context.fetch(FetchDescriptor<AppLayerConfig>()).first else {
            throw UpgradeAborted(reason: .configMissing)
        }

        let existing: TierPQRecord?
        switch try Self.upgradeState(config: config, keyManager: keyManager) {
        case .epochMissing, .waiting:
            report.outcome = .notNeeded
            return
        case .current(let stalePending):
            if stalePending { keyManager.deletePendingTierPQRecord(.deviceUnlock) }
            report.outcome = .alreadyDone
            return
        case .finishSwap(let pending):
            try Self.swap(pending, keyManager: keyManager, faults: false)
            report.outcome = .swapFinished
            return
        case .needsUpgrade(let pending):
            existing = pending
        }

        // The hybrid record: the one an earlier launch stored (rows may be under it), or a new one.
        let pending: TierPQRecord
        if let existing {
            pending = existing
            report.pendingReused = true
        } else {
            let made: TierPQRecord?
            do { made = try keyManager.makeHybridPQRecord() } catch { throw UpgradeAborted(reason: .postQuantumUnavailable) }
            guard let made else {
                report.outcome = .notNeeded
                return
            }
            pending = made
        }

        // Every key the pass needs is derived, and has to be, before anything is written: a record that won't decapsulate
        // leaves nothing behind. The hybrid ones come from the record itself, which is not yet the tier's own.
        let ambient = Manager.Ambient.keyManager
        guard
            let classicalLocal   = try? ambient.enclaveBoundKey(.localDB, record: .classical),
            let hybridLocal      = try? ambient.enclaveBoundKey(.localDB, record: pending),
            let classicalCustody = try? keyManager.enclaveBoundKey(.shardCustody, record: .classical),
            let hybridCustody    = try? keyManager.enclaveBoundKey(.shardCustody, record: pending),
            let classicalRestore = try? keyManager.enclaveBoundKey(.restoreVault, record: .classical),
            let hybridRestore    = try? keyManager.enclaveBoundKey(.restoreVault, record: pending),
            let classicalCompose = try? keyManager.enclaveBoundKey(.composeStaging, record: .classical),
            let hybridCompose    = try? keyManager.enclaveBoundKey(.composeStaging, record: pending)
        else { throw UpgradeAborted(reason: .keyUnavailable) }

        // The vault epoch is sealed under the local key and has to come across with it, or the vault is unreadable.
        var vaultEpoch: Epoch?
        if let sealed = config.vaultKeyEpoch {
            guard let opened = Epoch.opening(sealed, using: classicalLocal) else { throw UpgradeAborted(reason: .vaultEpochUnreadable) }
            vaultEpoch = opened
        }

        // The PIN verifiers: the wrap keys are needed only if any verifier is wrapped.
        let wrappedSize = Manager.PINManager.wrappedVerifierSize
        let hasWrapped = Self.pinVerifiers(of: config).contains { $0.count == wrappedSize }
        var wrapKeys: (classical: SymmetricKey, hybrid: SymmetricKey)?
        if hasWrapped {
            guard
                let classicalWrap = try? keyManager.enclaveBoundKey(.secureModeWrap, record: .classical),
                let hybridWrap    = try? keyManager.enclaveBoundKey(.secureModeWrap, record: pending)
            else { throw UpgradeAborted(reason: .keyUnavailable) }
            wrapKeys = (classicalWrap, hybridWrap)
        }

        // Persisted before anything is sealed under it.
        if existing == nil {
            do {
                try keyManager.addPendingTierPQRecord(pending, tier: .deviceUnlock)
            } catch {
                throw UpgradeAborted(reason: .pendingUnreadable)
            }
            guard (try? keyManager.pendingTierPQRecord(.deviceUnlock)) == pending else { throw UpgradeAborted(reason: .pendingUnreadable) }
        }

        #if DEBUG
        try Self.faults?.reachUpgrade(.afterPendingWritten)
        #endif

        // The files first, then the rows: a draft attachment sealed under the compose key moves to the hybrid compose key before
        // anything in the store does, so the epoch is only ever committed over files that are already there.
        var fileCounts = Counts()
        let filesMoved = try Self.resealDraftFiles(
            in: locations.applicationSupport, from: classicalCompose, to: hybridCompose, progress: progress, counts: &fileCounts
        )
        report.draftFiles = fileCounts

        let pass = Pass(
            context: context, batchSize: batchSize, progress: progress,
            new: [.local: hybridLocal, .custody: hybridCustody, .restore: hybridRestore],
            legacy: { key in
                switch key {
                case .local:   return classicalLocal
                case .custody: return classicalCustody
                case .restore: return classicalRestore
                default:       return nil
                }
            }
        )

        #if DEBUG
        try Self.faults?.reach(.afterFilesBeforeBatches)
        #endif

        guard filesMoved else {
            report.outcome = .incomplete
            return
        }

        do {
            try pass.run()
        } catch is Abort {
            report.entries = pass.entries
            throw UpgradeAborted(reason: .keyUnavailable)
        }
        report.entries = pass.entries

        #if DEBUG
        try Self.faults?.reach(.afterLastBatchBeforeEpoch)
        #endif

        if pass.entries.values.reduce(0, { $0 + $1.failed }) > 0 {
            report.outcome = .incomplete
            return
        }

        // The commit, worked out in memory first: the new epoch, the vault epoch, and every verifier. Any that doesn't read
        // back means nothing is assigned.
        guard
            let sealedEpoch = try Epoch(number: 1, form: .hybrid).sealed(using: hybridLocal),
            Epoch.opening(sealedEpoch, using: hybridLocal) == Epoch(number: 1, form: .hybrid)
        else {
            report.outcome = .incomplete
            return
        }

        var sealedVaultEpoch: Data?
        if let vaultEpoch {
            guard
                let resealed = try vaultEpoch.sealed(using: hybridLocal),
                Epoch.opening(resealed, using: hybridLocal) == vaultEpoch
            else {
                report.outcome = .incomplete
                return
            }
            sealedVaultEpoch = resealed
        }

        var verifiers = Self.pinVerifiers(of: config)
        if let wrapKeys {
            guard let converted = Self.rewrapVerifiers(verifiers, from: wrapKeys.classical, to: wrapKeys.hybrid, counts: &report.verifiers) else {
                report.verifiers.failed = max(1, report.verifiers.failed)
                report.outcome = .incomplete
                return
            }
            verifiers = converted
        }

        #if DEBUG
        try Self.faults?.reachUpgrade(.beforeCommit)
        #endif

        config.keyEpoch = sealedEpoch
        if let sealedVaultEpoch { config.vaultKeyEpoch = sealedVaultEpoch }
        Self.assign(verifiers, to: config)
        try context.save()

        report.epochWritten = true
        report.vaultEpochMoved = sealedVaultEpoch != nil
        if let store = locations.store { OccultaApp.walCheckpoint(at: store) }

        #if DEBUG
        try Self.faults?.reachUpgrade(.afterCommitBeforeSwap)
        #endif

        try Self.swap(pending, keyManager: keyManager, faults: true)
        report.outcome = .upgraded
    }

    /// Makes the pending record the tier's own, in place, and deletes the pending item.
    private static func swap(_ pending: TierPQRecord, keyManager: any KeyManagerProtocol, faults: Bool) throws {
        try keyManager.replaceTierPQRecord(.deviceUnlock, with: pending)

        #if DEBUG
        if faults { try Self.faults?.reachUpgrade(.afterSwapBeforePendingDeleted) }
        #endif

        keyManager.deletePendingTierPQRecord(.deviceUnlock)
    }

    // MARK: - Draft attachments

    /// Moves every draft attachment sealed under the classical compose staging key to the hybrid one (Bug 171, Stage 8).
    ///
    /// The files are `Application Support/Drafts/<draft id>/<file>`, each in the attachment format (`Attachment+Manager`),
    /// and found by trial: one whose header authenticates under the classical compose key is a group or key-less draft's and
    /// is moved (`AttachmentManager.reseal`: streamed, written to a temporary, read back, renamed); one that already opens
    /// under the hybrid key was moved by an earlier run; one that opens under neither is sealed under a per-contact file key,
    /// or is plaintext from an earlier build, and is left alone. A temporary a killed run left is removed.
    ///
    /// A file that won't reseal stops the pass: it returns false with the file as it was, because committing the epoch over a
    /// draft file that still needs the classical key would leave it unreadable. Files moved so far stay moved and are counted
    /// in `progress`, as the process is then on the classical key over files under the hybrid one.
    ///
    /// A device with no `Drafts` folder has nothing to do.
    @MainActor
    private static func resealDraftFiles(
        in applicationSupport: URL, from classical: SymmetricKey, to hybrid: SymmetricKey, progress: Progress?, counts: inout Counts
    ) throws -> Bool {
        let manager = FileManager.default
        let drafts = applicationSupport.appendingPathComponent("Drafts", isDirectory: true)
        guard let folders = try? manager.contentsOfDirectory(at: drafts, includingPropertiesForKeys: [.isDirectoryKey]) else { return true }

        let old = AttachmentManager(contactKey: classical)
        let new = AttachmentManager(contactKey: hybrid)
        var moved = 0

        for folder in folders.sorted(by: { $0.path < $1.path }) {
            guard (try? folder.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true else { continue }
            let files = (try? manager.contentsOfDirectory(at: folder, includingPropertiesForKeys: [.isRegularFileKey])) ?? []

            for file in files.sorted(by: { $0.path < $1.path }) {
                if file.pathExtension == AttachmentManager.resealingSuffix {
                    try? manager.removeItem(at: file)
                    continue
                }
                guard (try? file.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true else { continue }

                if old.opens(at: file) {
                    do {
                        #if DEBUG
                        let corrupt: ((URL) -> Void)? = Self.faults.map { faults in { url in faults.corruptedFile(at: url) } }
                        try old.reseal(at: file, to: new, beforeReadBack: corrupt)
                        #else
                        try old.reseal(at: file, to: new)
                        #endif
                    } catch {
                        counts.failed += 1
                        return false
                    }
                    counts.resealed += 1
                    progress?.fileMoved()
                    moved += 1

                    #if DEBUG
                    if moved == 1 { try Self.faults?.reachUpgrade(.afterFirstFile) }
                    #endif
                } else if new.opens(at: file) {
                    counts.skipped += 1
                } else {
                    counts.left += 1
                }
            }
        }
        return true
    }

    // MARK: - The PIN verifiers

    /// Every verifier the config holds, in a fixed order: the two scalars (when present), then both arrays.
    @MainActor
    private static func pinVerifiers(of config: AppLayerConfig) -> [Data] {
        [config.sealedNormalVerifier, config.sealedDuressVerifier].compactMap { $0 }
            + config.sealedNormalVerifiers + config.sealedDuressVerifiers
    }

    /// `verifiers` in the order `pinVerifiers(of:)` gives them, with every wrapped (81-byte) one moved from `from` to `to`,
    /// each read back; nil if any doesn't. A value that opens under `to` already is sealed again with a fresh nonce; one that
    /// opens under neither (random filler) is replaced by fresh random bytes, so the row changes whole. Another size is left.
    @MainActor
    private static func rewrapVerifiers(_ verifiers: [Data], from: SymmetricKey, to: SymmetricKey, counts: inout Counts) -> [Data]? {
        let wrappedSize = Manager.PINManager.wrappedVerifierSize

        func open(_ sealed: Data, using key: SymmetricKey) -> Data? {
            guard let box = try? AES.GCM.SealedBox(combined: sealed) else { return nil }
            return try? AES.GCM.open(box, using: key)
        }

        /// `plain` sealed under `to`, opened and compared before it is returned.
        func sealed(_ plain: Data) -> Data? {
            guard var fresh = try? AES.GCM.seal(plain, using: to, nonce: AES.GCM.Nonce()).combined else { return nil }
            #if DEBUG
            fresh = Self.faults?.corrupted(fresh) ?? fresh
            #endif
            return open(fresh, using: to) == plain ? fresh : nil
        }

        var out: [Data] = []
        for value in verifiers {
            guard value.count == wrappedSize else {
                counts.left += 1
                out.append(value)
                continue
            }
            if let inner = open(value, using: from) {
                guard let fresh = sealed(inner) else { counts.failed += 1; return nil }
                counts.resealed += 1
                out.append(fresh)
            } else if let inner = open(value, using: to) {
                guard let fresh = sealed(inner) else { counts.failed += 1; return nil }
                counts.skipped += 1
                out.append(fresh)
            } else {
                var bytes = [UInt8](repeating: 0, count: wrappedSize)
                _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
                counts.refreshed += 1
                out.append(Data(bytes))
            }
        }
        return out
    }

    /// Writes `verifiers`, in `pinVerifiers(of:)`'s order, back to the config row.
    @MainActor
    private static func assign(_ verifiers: [Data], to config: AppLayerConfig) {
        var rest = verifiers[...]

        if config.sealedNormalVerifier != nil, let first = rest.popFirst() { config.sealedNormalVerifier = first }
        if config.sealedDuressVerifier != nil, let first = rest.popFirst() { config.sealedDuressVerifier = first }

        let normalCount = config.sealedNormalVerifiers.count
        config.sealedNormalVerifiers = Array(rest.prefix(normalCount))
        rest = rest.dropFirst(normalCount)
        config.sealedDuressVerifiers = Array(rest)
    }

    // MARK: - Tiers B and S

    /// Moves the records that hold no data at launch to the hybrid form, in place, when a provider exists and they are
    /// classical: tier B's (the vault's data moves at its next unlock) and tier S's (sessions sealed in the classical form open
    /// through `ShareStagingKeyManager.decrypt`'s fallback until they are swept). One atomic update of the item each; the
    /// record's key is persisted before anything is sealed under it, because nothing is.
    ///
    /// A failure leaves the record as it was and is listed in the report; the next launch tries again. Never run while no
    /// provider exists, and never replaces a hybrid record.
    @discardableResult
    static func upgradeRecords(keyManager: any KeyManagerProtocol, staging: ShareStagingKeyManager?) -> RecordUpgradeReport {
        var report = RecordUpgradeReport()

        if keyManager.postQuantumAvailable {
            do {
                if let record = try keyManager.tierPQRecord(.vault), record.mode == .classical, let hybrid = try keyManager.makeHybridPQRecord() {
                    try keyManager.replaceTierPQRecord(.vault, with: hybrid)
                    report.vault = true
                }
            } catch {
                report.failures.append("vault")
            }
        }

        if let staging {
            do { report.staging = try staging.upgradeTierPQRecordIfClassical() } catch { report.failures.append("staging") }
        }
        return report
    }
}

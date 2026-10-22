//
//  KeyReseal+Run.swift
//  Occulta
//
//  The bootstrap and the pass of Bug 171, Stage 2 (`Docs/Features/Secure Mode/bugs.md`). The types and the fault
//  hooks are in `KeyReseal.swift`; what there is to move, and how each value is sealed, is in the inventory
//  (`KeyReseal+Inventory.swift`).
//
//  Order of a launch (`LaunchSequence`): the bootstrap, the pass, then the process is told which keys tier U's
//  accessors return (`Manager.Ambient.tierUKeys`), then everything else. Neither function here derives a key through
//  those accessors: the pass names its keys (`legacyKey(_:)`, `enclaveBoundKey(_:)`), so it works whatever state
//  the process is in.
//

import Foundation
import SwiftData
import CryptoKit

extension KeyReseal {

    // MARK: - The bootstrap

    /// Creates what the pass needs while tier U has no epoch, and nothing once it has one.
    ///
    /// - With no epoch: `r_U` and the tier U PQ record if the Keychain has none, the `AppLayerConfig` row if the store
    ///   has none (a fresh install; `Manager.Security.init` made it before the pass moved ahead of it, and
    ///   `AppLayerConfig.seeded()` is the same code), and the sealed `vaultKeyEpoch` = 1 if it is nil. The row and the
    ///   epoch are sealed under the new local key, named explicitly, so a fresh install's row is born new.
    /// - With an epoch: nothing is created. A secret or record that is missing now is not recreated, because a new
    ///   one would leave everything sealed under the old one unreadable; the report says so, and every derivation
    ///   fails loudly.
    /// - A Keychain read that throws (a locked device) is not a missing item: nothing is created on a guess.
    ///
    /// The epoch counts as present when `keyEpoch != nil`. It is not opened, because opening needs the key whose
    /// secret may be what is missing.
    @discardableResult
    static func bootstrap(context: ModelContext, keyManager: any KeyManagerProtocol) throws -> BootstrapReport {
        var report = BootstrapReport()
        let existing = try context.fetch(FetchDescriptor<AppLayerConfig>()).first

        if existing?.keyEpoch != nil {
            do {
                if try keyManager.tierSecret(.deviceUnlock) == nil { report.refusals.append(.tierSecretMissingAfterEpoch) }
                if try keyManager.tierPQRecord(.deviceUnlock) == nil { report.refusals.append(.tierPQRecordMissingAfterEpoch) }
            } catch {
                report.refusals.append(.unreadable)
            }
            return report
        }

        let secret: Data?
        let record: TierPQRecord?
        do {
            secret = try keyManager.tierSecret(.deviceUnlock)
            record = try keyManager.tierPQRecord(.deviceUnlock)
        } catch {
            report.refusals.append(.unreadable)
            return report
        }

        if secret == nil { report.createdTierSecret = try keyManager.createTierSecretIfAbsent(.deviceUnlock) }
        if record == nil { report.createdTierPQRecord = try keyManager.createTierPQRecordIfAbsent(.deviceUnlock) }

        // The row and the vault epoch are sealed under the new local key, so they need it. Without it (the record
        // is hybrid and won't decapsulate, say) the pass will report why, and `Manager.Security` makes the row
        // under the legacy key as it always did.
        guard let localKey = try? Manager.Ambient.keyManager.enclaveBoundKey(.localDB) else { return report }

        let config: AppLayerConfig
        if let existing {
            config = existing
        } else {
            // Born under the new local key, and with wrapped-size verifier filler: a fresh install ends uniform.
            let seed = Manager.Ambient.withTierUKeys(.enclaveBound) {
                Manager.Ambient.withPINVerifiers(.wrapped) { AppLayerConfig.seeded() }
            }
            context.insert(seed)
            config = seed
            report.createdConfig = true
        }

        // Form is classical until Stage 4 rewraps the vault: its data is under the legacy key until then.
        if config.vaultKeyEpoch == nil, let sealed = try Epoch(number: 1, form: .classical).sealed(using: localKey) {
            config.vaultKeyEpoch = sealed
            report.seededVaultKeyEpoch = true
        }

        if context.hasChanges { try context.save() }
        return report
    }

    // MARK: - The pass

    /// The pass. `keyManager` derives the custody and restore keys; the local key comes through `Manager.Ambient`.
    ///
    /// - An epoch already set: nothing is read or written (`.alreadyDone`).
    /// - A key, `r_U` or the PQ record that can't be read: no writes, no epoch, the reason in the report
    ///   (`.aborted`). Never a throw, and nothing is created.
    /// - Otherwise every value of tier U that opens under the legacy key is resealed under the new one, with the same
    ///   AAD and the same length, in batches of `batchSize` rows, each batch one `save()`. A value that opens under
    ///   the new key is skipped; one that opens under neither is left as it is. Each new ciphertext is opened and
    ///   compared before it replaces the old: one that doesn't read back leaves the old bytes, is counted as failed,
    ///   and holds back the epoch (`.incomplete`).
    /// - After the last batch, the epoch is written, and the store's WAL is checkpointed.
    ///
    /// Throws what an interruption looks like: `InjectedFault` in a test, and a SwiftData error from a `save()`.
    /// The batches already saved stay (every value in them is readable under the new key) and the next launch
    /// finishes; the batch in flight is rolled back.
    @discardableResult
    static func run(
        context: ModelContext,
        keyManager: any KeyManagerProtocol,
        locations: Locations = .production,
        batchSize: Int = KeyReseal.defaultBatchSize
    ) throws -> Report {
        var report = Report()

        do {
            try Self.perform(context: context, keyManager: keyManager, locations: locations, batchSize: max(1, batchSize), report: &report)
        } catch let abort as Abort {
            context.rollback()
            report.outcome = .aborted(abort.reason)
        } catch {
            context.rollback()
            throw error
        }
        return report
    }

    private struct Abort: Error {
        let reason: AbortReason
    }

    private static func perform(
        context: ModelContext, keyManager: any KeyManagerProtocol, locations: Locations, batchSize: Int, report: inout Report
    ) throws {
        guard let config = try context.fetch(FetchDescriptor<AppLayerConfig>()).first else { throw Abort(reason: .configMissing) }

        if config.keyEpoch != nil {
            report.outcome = .alreadyDone
            return
        }

        // What the new keys are made of must be readable, or nothing is written.
        do {
            guard try keyManager.tierSecret(.deviceUnlock) != nil else { throw Abort(reason: .tierSecretMissing) }
        } catch let abort as Abort {
            throw abort
        } catch {
            throw Abort(reason: .tierSecretUnreadable)
        }

        let record: TierPQRecord
        do {
            guard let found = try keyManager.tierPQRecord(.deviceUnlock) else { throw Abort(reason: .tierPQRecordMissing) }
            record = found
        } catch let abort as Abort {
            throw abort
        } catch {
            throw Abort(reason: .tierPQRecordUnreadable)
        }

        let ambient = Manager.Ambient.keyManager
        guard let local = try? ambient.enclaveBoundKey(.localDB) else { throw Abort(reason: .localKeyUnavailable) }
        guard let custody = try? keyManager.enclaveBoundKey(.shardCustody) else { throw Abort(reason: .custodyKeyUnavailable) }
        guard let restore = try? keyManager.enclaveBoundKey(.restoreVault) else { throw Abort(reason: .restoreKeyUnavailable) }

        let pass = Pass(
            context: context, batchSize: batchSize,
            new: [.local: local, .custody: custody, .restore: restore],
            legacy: { key in
                switch key {
                case .local:   return (try? ambient.legacyKey(.localDB)) ?? nil
                case .custody: return (try? keyManager.legacyKey(.shardCustody)) ?? nil
                case .restore: return (try? keyManager.legacyKey(.restoreVault)) ?? nil
                default:       return nil
                }
            }
        )

        // Files first. Tier U owns none (`backup-export-meta.dat` is the vault's, Stage 4's); the point is here so
        // that a file added to the pass has a place that is already tested.
        #if DEBUG
        try Self.faults?.reach(.afterFilesBeforeBatches)
        #endif

        do {
            try pass.run()
        } catch let abort as Abort {
            // A legacy key that can't be derived, found part-way: the batches saved so far stay, and no epoch is written.
            report.entries = pass.entries
            throw abort
        }
        report.entries = pass.entries

        #if DEBUG
        try Self.faults?.reach(.afterLastBatchBeforeEpoch)
        #endif

        if pass.entries.values.reduce(0, { $0 + $1.failed }) > 0 {
            report.outcome = .incomplete
            return
        }

        guard let sealed = try Epoch(number: 1, form: record.mode).sealed(using: local) else {
            report.outcome = .incomplete
            return
        }
        config.keyEpoch = sealed
        try context.save()
        report.epochWritten = true
        report.outcome = .completed

        if let store = locations.store { OccultaApp.walCheckpoint(at: store) }
    }

    /// Whether tier U has an epoch in `context`'s store. The launch sequence decides the process's keys by this.
    static func epochExists(in context: ModelContext) -> Bool {
        ((try? context.fetch(FetchDescriptor<AppLayerConfig>()).first) ?? nil)?.keyEpoch != nil
    }

    // MARK: - One value

    /// What the pass decided for one sealed value.
    private enum Verdict {
        /// Already under the new key.
        case skipped
        /// Opened under the legacy key; here is the same plaintext under the new one, read back.
        case resealed(Data)
        /// Already under the new key, in a container that changes whole: here is the same plaintext sealed again with
        /// a fresh nonce, so this member changes with the rest. Counted as skipped.
        case rewritten(Data)
        /// Opens under no key, and is random filler by construction: here is fresh random of the same length.
        case refreshed(Data)
        /// Opens under no key.
        case left
        /// Opened under the legacy key, but the new ciphertext didn't read back.
        case failed
    }

    /// Everything the pass holds while it runs.
    @MainActor
    private final class Pass {
        let context: ModelContext
        let batchSize: Int
        private let new: [Key: SymmetricKey]
        private let deriveLegacy: (Key) -> SymmetricKey?
        private var legacyKeys: [Key: SymmetricKey] = [:]

        private(set) var entries: [String: Counts] = [:]

        private var rowsInBatch = 0
        private var batchesSaved = 0
        private var firstRowReached = false
        private var midBatchReached = false

        /// `EncryptionScheme.v2_hybridPQ.aad`, which every value sealed by `Data.encrypt()` carries.
        static let fixedAAD = EncryptionScheme.v2_hybridPQ.aad

        init(context: ModelContext, batchSize: Int, new: [Key: SymmetricKey], legacy: @escaping (Key) -> SymmetricKey?) {
            self.context      = context
            self.batchSize    = batchSize
            self.new          = new
            self.deriveLegacy = legacy
        }

        // MARK: Keys

        /// The legacy key, derived the first time a value needs it: a store with nothing under the legacy keys (a
        /// fresh install) never derives one. One that can't be derived stops the pass without an epoch.
        private func legacy(_ key: Key) throws -> SymmetricKey {
            if let cached = self.legacyKeys[key] { return cached }
            guard let derived = self.deriveLegacy(key) else {
                switch key {
                case .custody: throw Abort(reason: .custodyKeyUnavailable)
                case .restore: throw Abort(reason: .restoreKeyUnavailable)
                default:       throw Abort(reason: .localKeyUnavailable)
                }
            }
            self.legacyKeys[key] = derived
            return derived
        }

        // MARK: Sealing

        private static func open(_ sealed: Data, using key: SymmetricKey, aad: Data?) -> Data? {
            guard let box = try? AES.GCM.SealedBox(combined: sealed) else { return nil }

            if let aad { return try? AES.GCM.open(box, using: key, authenticating: aad) }
            return try? AES.GCM.open(box, using: key)
        }

        private static func seal(_ plaintext: Data, using key: SymmetricKey, aad: Data?) -> Data? {
            let box: AES.GCM.SealedBox?
            if let aad {
                box = try? AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(), authenticating: aad)
            } else {
                box = try? AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce())
            }
            return box?.combined
        }

        private static func random(_ count: Int) -> Data {
            var rng = SystemRandomNumberGenerator()
            return Data((0..<count).map { _ in UInt8.random(in: 0...255, using: &rng) })
        }

        /// `plaintext` sealed under `key`, opened and compared before it is handed back; nil if it doesn't read back.
        private func sealedAgain(_ plaintext: Data, using key: SymmetricKey, aad: Data?) -> Data? {
            guard var fresh = Self.seal(plaintext, using: key, aad: aad) else { return nil }
            #if DEBUG
            fresh = KeyReseal.faults?.corrupted(fresh) ?? fresh
            #endif
            return Self.open(fresh, using: key, aad: aad) == plaintext ? fresh : nil
        }

        /// The verdict for one non-empty sealed value. Empty is not a sealed value at all, and the caller skips it.
        ///
        /// - Parameter rewriteCurrent: For a member of a container that changes whole (see `group(_:)`): a value
        ///   already under the new key is sealed again with a fresh nonce instead of being skipped, so that a run
        ///   which finds the real members done (a re-upgrade after a downgrade) still changes them with the filler.
        func decide(_ value: Data, key: Key, aad: Data?, filler: Filler, rewriteCurrent: Bool = false) throws -> Verdict {
            guard let newKey = self.new[key] else { return .left }

            if let current = Self.open(value, using: newKey, aad: aad) {
                guard rewriteCurrent else { return .skipped }
                return self.sealedAgain(current, using: newKey, aad: aad).map { .rewritten($0) } ?? .failed
            }

            if let plaintext = Self.open(value, using: try self.legacy(key), aad: aad) {
                return self.sealedAgain(plaintext, using: newKey, aad: aad).map { .resealed($0) } ?? .failed
            }

            if filler == .random { return .refreshed(Self.random(value.count)) }
            return .left
        }

        // MARK: Counting

        func tally(_ entry: String, _ verdict: Verdict, written: Bool = true) {
            var counts = self.entries[entry] ?? Counts()

            switch verdict {
            case .skipped, .rewritten: counts.skipped += 1
            case .resealed:  if written { counts.resealed += 1 } else { counts.failed += 1 }
            case .refreshed: if written { counts.refreshed += 1 }
            case .left:      counts.left += 1
            case .failed:    counts.failed += 1
            }
            self.entries[entry] = counts
        }

        // MARK: Batches

        /// A row is done. After the first row that changed, and part-way through the second batch, a test can stop the
        /// pass here; when `batchSize` rows are done, the batch is saved.
        func rowDone(changed: Bool) throws {
            #if DEBUG
            if changed, !self.firstRowReached {
                self.firstRowReached = true
                try KeyReseal.faults?.reach(.afterFirstRow)
            }
            #endif

            self.rowsInBatch += 1

            #if DEBUG
            if !self.midBatchReached, self.batchesSaved >= 1, self.rowsInBatch >= max(1, self.batchSize / 2) {
                self.midBatchReached = true
                try KeyReseal.faults?.reach(.midBatch)
            }
            #endif

            if self.rowsInBatch >= self.batchSize { try self.endBatch() }
        }

        func endBatch() throws {
            if self.context.hasChanges {
                try self.context.save()
                self.batchesSaved += 1
            }
            self.rowsInBatch = 0
        }

        // MARK: Rows

        /// Runs `fields` on every row of `type`, one row at a time, and counts the row toward the batch.
        func rows<M: PersistentModel>(_ type: M.Type, _ fields: (Row<M>) throws -> Void) throws {
            for model in try self.context.fetch(FetchDescriptor<M>()) {
                let row = Row(pass: self, model: model)
                try fields(row)
                try self.rowDone(changed: row.changed)
            }
        }

        /// The Group's three kinds of slot arrays are one container: every slot of every depth, real and filler, or
        /// none of them. A group the pass looks at is rewritten whole each time: the real members are resealed (or,
        /// if already under the new key, sealed again with a fresh nonce) and the filler is re-randomised. A run
        /// that changed only the filler, or only the members that were still legacy, would show a diff which slots
        /// are real, and in which depth arrays.
        func group(_ group: Group) throws -> Bool {
            let sources: [(String, [Data])] =
                [("Group.realMemberSlots", group.realMemberSlots), ("Group.duressMemberSlots", group.duressMemberSlots)]
                + group.deeperMemberSlots.map { ("Group.deeperMemberSlots", $0) }

            var verdicts: [[(String, Verdict)]] = []
            for (entry, slots) in sources {
                verdicts.append(try slots.map { (entry, try self.decide($0, key: .local, aad: Self.fixedAAD, filler: .random, rewriteCurrent: true)) })
            }
            let flat = verdicts.flatMap { $0 }
            let ok = !flat.contains { if case .failed = $0.1 { return true } else { return false } }

            for (entry, verdict) in flat { self.tally(entry, verdict, written: ok) }
            guard ok else { return false }

            func replaced(_ index: Int) -> [Data] {
                zip(sources[index].1, verdicts[index]).map { old, decided in
                    switch decided.1 {
                    case .resealed(let data), .refreshed(let data), .rewritten(let data): return data
                    default:                                                              return old
                    }
                }
            }
            // Every member is rewritten (real ones, current or not, and filler), or the group is left whole.
            let rewritten = !flat.isEmpty
            if rewritten {
                group.replaceSlots(real: replaced(0), duress: replaced(1), deeper: (2..<sources.count).map(replaced))
            }
            return rewritten
        }

        // MARK: Every model

        func run() throws {
            try self.contacts()
            try self.messages()
            try self.groups()
            try self.vaultEntries()
            try self.custody()
            try self.restoreBuffer()
            try self.backupKeys()
            try self.config()

            try self.endBatch()
        }

        private func contacts() throws {
            try self.rows(Contact.Profile.self) { row in
                // `identifier` is a reference key, stored as a value in other records: left as it is.
                try row.text("Profile.givenName", \.givenName)
                try row.text("Profile.familyName", \.familyName)
                try row.text("Profile.middleName", \.middleName)
                try row.text("Profile.namePrefix", \.namePrefix)
                try row.text("Profile.nameSuffix", \.nameSuffix)
                try row.text("Profile.nickname", \.nickname)
                try row.text("Profile.organizationName", \.organizationName)
                try row.text("Profile.departmentName", \.departmentName)
                try row.text("Profile.jobTitle", \.jobTitle)
                try row.text("Profile.phoneticGivenName", \.phoneticGivenName)
                try row.text("Profile.phoneticMiddleName", \.phoneticMiddleName)
                try row.text("Profile.phoneticFamilyName", \.phoneticFamilyName)
                try row.text("Profile.birthday", \.birthday)
                try row.text("Profile.note", \.note)

                try row.data("Profile.thumbnailImageData", \.thumbnailImageData)
                try row.data("Profile.imageData", \.imageData)
                try row.data("Profile.prekeyRecordEncrypted", \.prekeyRecordEncrypted)
                try row.data("Profile.introductionCardEncrypted", \.introductionCardEncrypted)
                try row.data("Profile.forwardSecrecyEncrypted", \.retiredForwardSecrecyEncrypted)
                try row.data("Profile.signedAttributes", \.signedAttributes)
                try row.data("Profile.deletionToken", \.deletionToken)
                try row.data("Profile.visibleThroughDepth", \.visibleThroughDepth)
                try row.data("Profile.globalTrusteeDepth", \.globalTrusteeDepth)
                try row.data("Profile.maxBundleVersion", \.maxBundleVersion)
                try row.data("Profile.originDepth", \.originDepth)
            }

            try self.rows(Contact.Profile.PhoneNumber.self) { row in
                try row.text("PhoneNumber.label", \.label)
                try row.text("PhoneNumber.value", \.value)
            }
            try self.rows(Contact.Profile.EmailAddress.self) { row in
                try row.text("EmailAddress.label", \.label)
                try row.text("EmailAddress.value", \.value)
            }
            try self.rows(Contact.Profile.PostalAddress.self) { row in
                try row.text("PostalAddress.label", \.label)
                try row.text("PostalAddress.street", \.street)
                try row.text("PostalAddress.city", \.city)
                try row.text("PostalAddress.state", \.state)
                try row.text("PostalAddress.postalCode", \.postalCode)
                try row.text("PostalAddress.country", \.country)
                try row.text("PostalAddress.isoCountryCode", \.isoCountryCode)
            }
            try self.rows(Contact.Profile.URLAddress.self) { row in
                try row.text("URLAddress.label", \.label)
                try row.text("URLAddress.value", \.value)
            }
            try self.rows(Contact.Profile.Key.self) { row in
                try row.data("Key.material", \.material)
                try row.data("Key.acquiredAt", \.acquiredAt)
                try row.data("Key.owner", \.owner)
                try row.data("Key.expiredOn", \.expiredOn)
                try row.data("Key.quantumKeyMaterialEncrypted", \.quantumKeyMaterialEncrypted)
            }
        }

        private func messages() throws {
            // Retired: nothing reads or writes `Contact.Message`, but a row that exists is moved like any other.
            try self.rows(Contact.Message.self) { row in
                try row.text("Message.origin", \.origin)
                try row.array("Message.recipients", \.recipients)
                try row.data("Message.content", \.content)
            }

            try self.rows(Message.Draft.self) { row in
                try row.data("Draft.encryptedRecipientID", \.encryptedRecipientID, aad: .row(row.model.aad(for: .recipientID)))
                try row.data("Draft.encryptedContent", \.encryptedContent, aad: .row(row.model.aad(for: .content)))
            }
        }

        private func groups() throws {
            try self.rows(Group.self) { row in
                try row.data("Group.encryptedID", \.encryptedID)
                try row.data("Group.encryptedName", \.encryptedName)
                try row.data("Group.encryptedCreatedAt", \.encryptedCreatedAt)
                if try self.group(row.model) { row.changed = true }
            }
        }

        private func vaultEntries() throws {
            // The per-entry key and the label and content under it are the vault's (Stage 4) and not touched.
            try self.rows(VaultEntry.self) { row in
                try row.data("VaultEntry.visibleThroughDepth", \.visibleThroughDepth)
                try row.data("VaultEntry.deletionToken", \.deletionToken)
            }
        }

        private func custody() throws {
            try self.rows(CustodyShard.self) { row in
                try row.data("CustodyShard.encryptedPayload", \.encryptedPayload, key: .custody, aad: .row(row.model.aad()))
            }
            try self.rows(PendingShardDistribute.self) { row in
                try row.data("PendingShardDistribute.encryptedPayload", \.encryptedPayload, key: .custody, aad: .row(row.model.aad()))
            }
            try self.rows(PendingShardStatusUpdate.self) { row in
                try row.data("PendingShardStatusUpdate.encryptedPayload", \.encryptedPayload, key: .custody, aad: .row(row.model.aad()))
            }
            try self.rows(PotentiallyLostShard.self) { row in
                try row.data("PotentiallyLostShard.encryptedPayload", \.encryptedPayload, key: .custody, aad: .row(row.model.aad()))
            }
            // Retired: `migrateDeleteGlobalShardConfig` deletes these at launch, after this pass.
            try self.rows(GlobalShardConfig.self) { row in
                try row.data("GlobalShardConfig.encryptedPayload", \.encryptedPayload, key: .custody, aad: .row(row.model.aad()))
            }
        }

        private func restoreBuffer() throws {
            // Retired: `VaultManager.unlock` moves these into `PendingShamirSecretRestore` and deletes any it can't open.
            try self.rows(ReconstructShard.self) { row in
                try row.data("ReconstructShard.encryptedPayload", \.encryptedPayload, key: .restore, aad: .row(row.model.aad()))
            }
            try self.rows(PendingShamirSecretRestore.self) { row in
                try row.data("PendingShamirSecretRestore.attributeID", \.attributeID)
                try row.data("PendingShamirSecretRestore.deletionToken", \.deletionToken)
                try row.data("PendingShamirSecretRestore.shards", \.shards, key: .restore, aad: .row(row.model.aad()))
            }
        }

        /// `depth` and `deletionToken` of every backup-key row, real and filler, are one container: a filler row's
        /// random bytes change with the real row's seals, or none of them does. `encryptedPayload` is the vault's.
        private func backupKeys() throws {
            struct Decided {
                let entry: String
                let verdict: Verdict
                let assign: (Data) -> Void
            }

            let rows = try self.context.fetch(FetchDescriptor<BackupEncryptionKey>())
            var decided: [Decided] = []
            for row in rows {
                if let value = row.depth, !value.isEmpty {
                    decided.append(Decided(entry: "BackupEncryptionKey.depth", verdict: try self.decide(value, key: .local, aad: Self.fixedAAD, filler: .random, rewriteCurrent: true), assign: { row.depth = $0 }))
                }
                if let value = row.deletionToken, !value.isEmpty {
                    decided.append(Decided(entry: "BackupEncryptionKey.deletionToken", verdict: try self.decide(value, key: .local, aad: Self.fixedAAD, filler: .random, rewriteCurrent: true), assign: { row.deletionToken = $0 }))
                }
            }

            let ok = !decided.contains { if case .failed = $0.verdict { return true } else { return false } }
            var changed = false
            for item in decided {
                self.tally(item.entry, item.verdict, written: ok)
                guard ok else { continue }

                switch item.verdict {
                case .resealed(let data), .refreshed(let data), .rewritten(let data):
                    item.assign(data)
                    changed = true
                default:
                    break
                }
            }
            for _ in rows { try self.rowDone(changed: changed) }
        }

        private func config() throws {
            // `keyEpoch` and `vaultKeyEpoch` are born under the new key and never moved. The PIN verifiers are Stage 3's.
            try self.rows(AppLayerConfig.self) { row in
                try row.data("AppLayerConfig.persistedDepth", \.persistedDepth)
                try row.data("AppLayerConfig.pinEnabled", \.pinEnabled)
                try row.array("AppLayerConfig.pinEnabledPerDepth", \.pinEnabledPerDepth)
                try row.data("AppLayerConfig.coercerBaseDepth", \.coercerBaseDepth)
                try row.data("AppLayerConfig.lockoutCountEncrypted", \.lockoutCountEncrypted)
                try row.data("AppLayerConfig.lockoutAnchorUptimeEncrypted", \.lockoutAnchorUptimeEncrypted)
            }
        }
    }

    /// The fields of one row. Each call decides one value and, if it changes, writes it back to the model in memory;
    /// the batch's `save()` is what commits it.
    /// What a value's authenticated data is bound to.
    private enum Bound {
        /// The scheme's one byte, `EncryptionScheme.v2_hybridPQ.aad`: every value sealed by `Data.encrypt()`.
        case scheme
        /// The row's own `aad()`, which carries its id.
        case row(Data)

        @MainActor
        var data: Data {
            switch self {
            case .scheme:        return Pass.fixedAAD
            case .row(let data): return data
            }
        }
    }

    @MainActor
    private final class Row<M: PersistentModel> {
        unowned let pass: Pass
        let model: M
        var changed = false

        init(pass: Pass, model: M) {
            self.pass  = pass
            self.model = model
        }

        // MARK: Data

        func data(_ entry: String, _ path: ReferenceWritableKeyPath<M, Data?>, key: Key = .local, aad: Bound = .scheme, filler: Filler = .none) throws {
            guard let value = self.model[keyPath: path], !value.isEmpty else { return }
            try self.apply(entry, try self.pass.decide(value, key: key, aad: aad.data, filler: filler)) { self.model[keyPath: path] = $0 }
        }

        func data(_ entry: String, _ path: ReferenceWritableKeyPath<M, Data>, key: Key = .local, aad: Bound = .scheme, filler: Filler = .none) throws {
            let value = self.model[keyPath: path]
            guard !value.isEmpty else { return }
            try self.apply(entry, try self.pass.decide(value, key: key, aad: aad.data, filler: filler)) { self.model[keyPath: path] = $0 }
        }

        // MARK: Strings (base64 of a sealed value; "" is empty and was never sealed)

        func text(_ entry: String, _ path: ReferenceWritableKeyPath<M, String>) throws {
            try self.text(entry, value: self.model[keyPath: path]) { self.model[keyPath: path] = $0 }
        }

        func text(_ entry: String, _ path: ReferenceWritableKeyPath<M, String?>) throws {
            try self.text(entry, value: self.model[keyPath: path] ?? "") { self.model[keyPath: path] = $0 }
        }

        private func text(_ entry: String, value: String, assign: (String) -> Void) throws {
            guard !value.isEmpty else { return }
            guard let bytes = Data(base64Encoded: value), !bytes.isEmpty else {
                self.pass.tally(entry, .left)
                return
            }
            try self.apply(entry, try self.pass.decide(bytes, key: .local, aad: Pass.fixedAAD, filler: .none)) { assign($0.base64EncodedString()) }
        }

        // MARK: Arrays

        /// A `[Data]` whose members are all real seals (no filler): moved together, or none of it.
        func array(_ entry: String, _ path: ReferenceWritableKeyPath<M, [Data]>, key: Key = .local) throws {
            try self.array(entry, self.model[keyPath: path], key: key) { self.model[keyPath: path] = $0 }
        }

        func array(_ entry: String, _ path: ReferenceWritableKeyPath<M, [Data]?>, key: Key = .local) throws {
            guard let values = self.model[keyPath: path] else { return }
            try self.array(entry, values, key: key) { self.model[keyPath: path] = $0 }
        }

        private func array(_ entry: String, _ values: [Data], key: Key, assign: ([Data]) -> Void) throws {
            let verdicts = try values.map { $0.isEmpty ? nil : try self.pass.decide($0, key: key, aad: Pass.fixedAAD, filler: .none) }
            let ok = !verdicts.contains { if case .failed = $0 { return true } else { return false } }

            for case let verdict? in verdicts { self.pass.tally(entry, verdict, written: ok) }
            guard ok else { return }

            var rewritten = false
            let result = zip(values, verdicts).map { old, verdict -> Data in
                if case .resealed(let data) = verdict { rewritten = true; return data }
                return old
            }
            if rewritten {
                assign(result)
                self.changed = true
            }
        }

        // MARK: Applying

        private func apply(_ entry: String, _ verdict: Verdict, assign: (Data) -> Void) throws {
            self.pass.tally(entry, verdict)

            switch verdict {
            case .resealed(let data), .refreshed(let data), .rewritten(let data):
                assign(data)
                self.changed = true
            case .skipped, .left, .failed:
                break
            }
        }
    }
}

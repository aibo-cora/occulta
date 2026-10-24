//
//  KeyReseal+Vault.swift
//  Occulta
//
//  The vault rewrap of Bug 171, Stage 4 (`Docs/Features/Secure Mode/bugs.md`). The vault key is
//  `HKDF(ECDH(vault_priv, G) …)`, a function of the vault Enclave key's public point, so the per-entry keys it wraps
//  and the backup keys it seals are only as strong as that point is secret. After the rewrap they are sealed under
//  `enclaveBoundKey(.vault)`, which also needs `r_B` (and, on iOS 26+, the Enclave's ML-KEM secret from the tier B record).
//
//  It runs inside `VaultManager.unlock(context:)`, the first time the vault is opened after the upgrade, because both
//  the vault Enclave key and `r_B` need the evaluated `LAContext`. The epoch that says whether it has run is
//  `AppLayerConfig.vaultKeyEpoch`, sealed under the tier U key: 1 until the rewrap, then 2.
//
//  `OccultaTests/SecureMode/VaultRewrapTests.swift` was written against a stub of this first (Stage 4a). Stage 6 runs it
//  once more, with the classical form of the key as the "legacy" one, for a vault whose device reached iOS 26 after it
//  had been rewrapped onto the classical form (`HybridUpgradeVaultTests`).
//

import Foundation
import SwiftData
import CryptoKit
import LocalAuthentication

extension KeyReseal {

    nonisolated enum VaultAbort: Equatable {
        /// There is no `AppLayerConfig` row.
        case configMissing
        /// The vault epoch can't be read: the tier U key isn't there, or the column is nil or doesn't open.
        case epochUnreadable
        /// `r_B` can't be read (a locked device, a failed evaluation). Never created on a guess.
        case tierSecretUnreadable
        /// The tier B record can't be read.
        case tierPQRecordUnreadable
        /// Neither the legacy vault key nor the Enclave-bound one can be derived.
        case vaultKeyUnavailable
    }

    nonisolated enum VaultOutcome: Equatable {
        /// The pass didn't run.
        case notRun
        /// Every vault value was moved and the epoch is 2, in one commit.
        case rewrapped
        /// The epoch was already 2: nothing was read or written.
        case alreadyDone
        /// A new ciphertext didn't read back: nothing was written.
        case incomplete
        /// Nothing was written.
        case aborted(VaultAbort)
    }

    nonisolated struct VaultReport: Equatable {
        var outcome = VaultOutcome.notRun
        /// `VaultEntry.encryptedEntryKey`.
        var entryKeys = Counts()
        /// `BackupEncryptionKey.encryptedPayload`: a container, so the whole table changes or none of it does.
        var backupPayloads = Counts()
        /// Whether `backup-export-meta.dat` was moved. nil: there was none.
        var exportMetadata: Bool?
        /// The form the epoch was set to.
        var form: TierPQRecord.Mode?

        var total: Counts { self.entryKeys + self.backupPayloads }
    }

    /// The file a rewrap writes `backup-export-meta.dat` to before it renames it into place.
    static func exportMetadataTemporaryURL(in directory: URL) -> URL {
        directory.appendingPathComponent("backup-export-meta.dat.rewrap")
    }

    private struct VaultAborted: Error {
        let reason: VaultAbort
    }

    /// What the rewrap decided for one sealed value.
    private enum VaultVerdict {
        case skipped
        case resealed(Data)
        /// Already under the new key, in a container that changes whole: sealed again with a fresh nonce.
        case rewritten(Data)
        /// Random filler that opens under no key: fresh random of the same length.
        case refreshed(Data)
        case left
        case failed
    }

    /// Moves the vault's data onto the Enclave-bound vault key, in one transaction.
    ///
    /// - The epoch must be 1 (`.alreadyDone` at 2, with nothing read or written beyond the epoch and the tier B record).
    ///   Only then are `r_B` and the tier B record created if absent: once it is 2 the vault is sealed under keys that
    ///   include them, and a new one would make it unreadable. The one exception to "at 2 nothing runs" is Stage 6: epoch
    ///   (2, classical) with a hybrid tier B record, a device that reached iOS 26 after its first unlock. The data then moves
    ///   from the classical key to the hybrid one, in the same way, and the epoch becomes (2, hybrid).
    /// - Every `VaultEntry.encryptedEntryKey` (AAD `aad(for: .entryKey)`), every `BackupEncryptionKey.encryptedPayload`
    ///   (AAD `aad()`) and `backup-export-meta.dat` (the constant AAD): opens under the new key, skip; under the legacy
    ///   key, reseal; under neither, leave. All depths, orphaned rows and filler rows are covered. The backup-key
    ///   table is a container: its real payloads are resealed and its filler is re-randomised, and a payload already
    ///   under the new key is sealed again, so the whole table changes or none of it does. Labels, contents and `.occbak`
    ///   files are under keys this doesn't touch.
    /// - Each new ciphertext is opened and compared before it is used. One that doesn't read back means no writes at
    ///   all (`.incomplete`).
    /// - Everything is worked out in memory first. Then the file is written to a temp file next to it, read back, and
    ///   renamed over it, and only then are the rows assigned and the epoch (2, with the form of the tier B record) set
    ///   in the one `save()`. So the file never lags the epoch: a kill between the two leaves the file under the new key
    ///   and everything else old, and the next run, which skips what is already moved, finishes. A failure after the
    ///   file was renamed puts the old file back.
    /// - A key, `r_B` or the record that can't be read means no writes (`.aborted`).
    ///
    /// Does not switch `Manager.Ambient.vaultKeys`: `VaultManager.unlock` does, on `.rewrapped` and `.alreadyDone`.
    @discardableResult
    static func rewrapVault(
        context: ModelContext, keyManager: any KeyManagerProtocol, authContext: LAContext, locations: Locations = .production
    ) throws -> VaultReport {
        var report = VaultReport()

        do {
            try Self.performRewrap(context: context, keyManager: keyManager, authContext: authContext, locations: locations, report: &report)
        } catch let aborted as VaultAborted {
            context.rollback()
            report = VaultReport(outcome: .aborted(aborted.reason))
        } catch {
            context.rollback()
            throw error
        }
        return report
    }

    private static let exportMetadataName = "backup-export-meta.dat"

    private static func performRewrap(
        context: ModelContext, keyManager: any KeyManagerProtocol, authContext: LAContext, locations: Locations, report: inout VaultReport
    ) throws {
        guard let config = try context.fetch(FetchDescriptor<AppLayerConfig>()).first else {
            throw VaultAborted(reason: .configMissing)
        }

        // The epoch is sealed under the new tier U key, named explicitly: it must open whichever state the process is in.
        guard
            let localKey = try? Manager.Ambient.keyManager.enclaveBoundKey(.localDB),
            let epoch = Epoch.opening(config.vaultKeyEpoch, using: localKey)
        else { throw VaultAborted(reason: .epochUnreadable) }

        // The key the data is under now, and the record the new key is in the form of.
        let record: TierPQRecord
        let legacy: SymmetricKey

        if epoch.number >= 2 {
            // Stage 6: a vault rewrapped onto the classical form on a device below iOS 26, whose tier B record has since
            // become hybrid. Only then is there anything to do; the classical key is derived from `.classical`, not from
            // the stored record, which no longer says classical. Nothing is created: the secret and the record exist.
            guard epoch.form == .classical, let found = try? keyManager.tierPQRecord(.vault), found.mode == .hybrid else {
                report.outcome = .alreadyDone
                return
            }
            record = found

            do {
                guard try keyManager.tierSecret(.biometry(authContext)) != nil else { throw VaultAborted(reason: .tierSecretUnreadable) }
            } catch {
                throw VaultAborted(reason: .tierSecretUnreadable)
            }
            guard let classical = try? keyManager.enclaveBoundKey(.vault(authContext), record: .classical) else {
                throw VaultAborted(reason: .vaultKeyUnavailable)
            }
            legacy = classical
        } else {
            // Creation follows the rule: only here, while the epoch is 1.
            do {
                if try keyManager.tierSecret(.biometry(authContext)) == nil {
                    try keyManager.createTierSecretIfAbsent(.biometry(authContext))
                }
            } catch {
                throw VaultAborted(reason: .tierSecretUnreadable)
            }

            do {
                if let found = try keyManager.tierPQRecord(.vault) {
                    record = found
                } else {
                    try keyManager.createTierPQRecordIfAbsent(.vault)
                    guard let made = try keyManager.tierPQRecord(.vault) else { throw VaultAborted(reason: .tierPQRecordUnreadable) }
                    record = made
                }
            } catch let aborted as VaultAborted {
                throw aborted
            } catch {
                throw VaultAborted(reason: .tierPQRecordUnreadable)
            }

            guard let derived = try? keyManager.legacyKey(.vault(authContext)) else { throw VaultAborted(reason: .vaultKeyUnavailable) }
            legacy = derived
        }

        guard let new = try? keyManager.enclaveBoundKey(.vault(authContext)) else { throw VaultAborted(reason: .vaultKeyUnavailable) }

        func open(_ sealed: Data, key: SymmetricKey, aad: Data) -> Data? {
            guard let box = try? AES.GCM.SealedBox(combined: sealed) else { return nil }
            return try? AES.GCM.open(box, using: key, authenticating: aad)
        }

        /// `plaintext` sealed under the new key, opened and compared before it is handed back; nil if it doesn't read back.
        func sealedAgain(_ plaintext: Data, aad: Data) -> Data? {
            guard var fresh = try? AES.GCM.seal(plaintext, using: new, nonce: AES.GCM.Nonce(), authenticating: aad).combined else { return nil }
            #if DEBUG
            fresh = Self.faults?.corrupted(fresh) ?? fresh
            #endif
            return open(fresh, key: new, aad: aad) == plaintext ? fresh : nil
        }

        func decide(_ value: Data, aad: Data, filler: Bool, rewriteCurrent: Bool) -> VaultVerdict {
            if let current = open(value, key: new, aad: aad) {
                guard rewriteCurrent else { return .skipped }
                return sealedAgain(current, aad: aad).map { .rewritten($0) } ?? .failed
            }
            if let plaintext = open(value, key: legacy, aad: aad) {
                return sealedAgain(plaintext, aad: aad).map { .resealed($0) } ?? .failed
            }
            if filler {
                var bytes = [UInt8](repeating: 0, count: value.count)
                _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
                return .refreshed(Data(bytes))
            }
            return .left
        }

        let entries = try context.fetch(FetchDescriptor<VaultEntry>())
        let rows    = try context.fetch(FetchDescriptor<BackupEncryptionKey>())
        let url     = locations.applicationSupport.appendingPathComponent(Self.exportMetadataName)
        let temp    = Self.exportMetadataTemporaryURL(in: locations.applicationSupport)

        // A temp file a killed run left behind is not read: it is replaced below, or removed here if there is no file to move.
        try? FileManager.default.removeItem(at: temp)

        var processed = 0
        let total = entries.count + rows.count
        func progress() throws {
            #if DEBUG
            if processed == 1 { try Self.faults?.reachVault(.afterFirstValue) }
            if processed == max(1, total / 2) { try Self.faults?.reachVault(.midRewrap) }
            #endif
        }

        // Worked out first, assigned only if every one read back.
        var entryVerdicts: [(VaultEntry, VaultVerdict)] = []
        for entry in entries where !entry.encryptedEntryKey.isEmpty {
            entryVerdicts.append((entry, decide(entry.encryptedEntryKey, aad: entry.aad(for: .entryKey), filler: false, rewriteCurrent: false)))
            processed += 1
            try progress()
        }

        var rowVerdicts: [(BackupEncryptionKey, VaultVerdict)] = []
        for row in rows where !row.encryptedPayload.isEmpty {
            rowVerdicts.append((row, decide(row.encryptedPayload, aad: row.aad(), filler: true, rewriteCurrent: true)))
            processed += 1
            try progress()
        }

        var fileOld: Data?
        var fileNew: Data?
        var fileFailed = false
        if let current = try? Data(contentsOf: url) {
            fileOld = current
            switch decide(current, aad: Self.exportMetadataAAD, filler: false, rewriteCurrent: false) {
            case .resealed(let data): fileNew = data
            case .failed:             fileFailed = true
            default:                  break
            }
            report.exportMetadata = fileNew != nil
        }

        func isFailed(_ verdict: VaultVerdict) -> Bool { if case .failed = verdict { return true } else { return false } }
        let failed = entryVerdicts.contains { isFailed($0.1) } || rowVerdicts.contains { isFailed($0.1) } || fileFailed

        func tally(_ counts: inout Counts, _ verdict: VaultVerdict, written: Bool) {
            switch verdict {
            case .skipped, .rewritten: counts.skipped += 1
            case .resealed:            if written { counts.resealed += 1 } else { counts.failed += 1 }
            case .refreshed:           if written { counts.refreshed += 1 }
            case .left:                counts.left += 1
            case .failed:              counts.failed += 1
            }
        }
        for (_, verdict) in entryVerdicts { tally(&report.entryKeys, verdict, written: !failed) }
        for (_, verdict) in rowVerdicts { tally(&report.backupPayloads, verdict, written: !failed) }

        if failed {
            report.outcome = .incomplete
            report.exportMetadata = nil
            return
        }

        guard let sealedEpoch = try Epoch(number: 2, form: record.mode).sealed(using: localKey) else {
            report.outcome = .incomplete
            return
        }

        // The file first, then the rows and the epoch in one commit. A failure from here on puts the old file back.
        var replacedFile = false
        do {
            if let fileNew {
                try Self.replaceFile(at: url, with: fileNew, temporary: temp)
                replacedFile = true
            }
            #if DEBUG
            try Self.faults?.reachVault(.afterFileBeforeCommit)
            #endif

            for (entry, verdict) in entryVerdicts {
                if case .resealed(let data) = verdict { entry.encryptedEntryKey = data }
            }
            for (row, verdict) in rowVerdicts {
                switch verdict {
                case .resealed(let data), .rewritten(let data), .refreshed(let data): row.encryptedPayload = data
                default: break
                }
            }
            config.vaultKeyEpoch = sealedEpoch

            #if DEBUG
            try Self.faults?.reachVault(.beforeCommit)
            #endif
            try context.save()
        } catch {
            try? FileManager.default.removeItem(at: temp)
            if replacedFile, let fileOld { try? VaultManager.writeExcludedFromBackup(fileOld, to: url) }
            throw error
        }

        if let store = locations.store { OccultaApp.walCheckpoint(at: store) }
        report.form = record.mode
        report.outcome = .rewrapped
    }

    /// The constant `backup-export-meta.dat` is sealed with.
    private static let exportMetadataAAD = Data("occulta.backup-export-meta-v1".utf8)

    /// Writes `data` to `temporary`, reads it back, and renames it over `url`. The file keeps what the vault gives it:
    /// complete file protection and exclusion from backups.
    private static func replaceFile(at url: URL, with data: Data, temporary: URL) throws {
        try? FileManager.default.removeItem(at: temporary)
        try data.write(to: temporary, options: [.completeFileProtection])

        var target = temporary
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? target.setResourceValues(values)

        guard (try? Data(contentsOf: temporary)) == data else {
            try? FileManager.default.removeItem(at: temporary)
            throw CocoaError(.fileReadCorruptFile)
        }
        _ = try FileManager.default.replaceItemAt(url, withItemAt: temporary)
    }

    /// The vault's epoch in `context`'s store: 1 or 2, or nil if it can't be read. Sealed under the new tier U key, which
    /// is named explicitly: the accessor follows tier U's own epoch, and this must open whichever state the process is in.
    static func vaultEpoch(in context: ModelContext) -> Epoch? {
        guard
            let config = (try? context.fetch(FetchDescriptor<AppLayerConfig>()).first) ?? nil,
            let localKey = (try? Manager.Ambient.keyManager.enclaveBoundKey(.localDB)) ?? nil
        else { return nil }

        return Epoch.opening(config.vaultKeyEpoch, using: localKey)
    }
}

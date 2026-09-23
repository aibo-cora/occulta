//
//  Vault+Manager+Backup.swift
//  Occulta
//
//  Vault backup — export, import, restore from an opened backup file, and the legacy
//  Backup Encryption Key row's migration (all of which need `modelContext`, which
//  belongs to `VaultManager`, not to `Backup`). The key's own lifecycle (setup,
//  access, shard distribution, reconstruction, rotation) lives in `VaultManager.Backup`
//  below — restructured 2026-09-09 (VAULT_KEY_LAYERING.md item 13) to hold no
//  reference back to `VaultManager` at all: every method takes `vaultKey` explicitly,
//  mirroring `Manager.LayerStore.push(key:...)` one layer down, rather than deriving
//  it itself. `Backup` holds only `backend` and `keyManager`, both plain injected
//  values, the same shape `backend` already had — not a back-reference to its owner.
//
//  All operations require the vault to be unlocked (currentKey() enforces this).
//  Backup key bytes only exist in memory during an active operation and are zeroed via
//  defer where they appear as raw [UInt8] or Data buffers. The vault plaintext that export
//  and restore handle (each entry's label and content, and the JSON around them) is zeroed
//  the same way (`zeroPlaintext`, bugs.md Bug 96 item 3). What can't be reached stays:
//  JSONEncoder/JSONDecoder internals, and labels while they pass through Swift Strings.
//
//  File format (.occbak):
//    magic (4 bytes: "OCBK") ∥ AES-GCM combined (nonce(12) ∥ ciphertext ∥ tag(16))
//  The magic prefix allows fast format detection without attempting decryption.
//

import Foundation
import SwiftData
import CryptoKit

extension VaultManager {

    // MARK: - Errors

    enum BackupError: Error {
        /// No backup key exists — call `backup.setup()` first.
        case bekNotSetup
        /// Backup key shard distribution is absent or below threshold.
        case belowThreshold
        /// File does not start with the "OCBK" magic prefix.
        case invalidFormat
        /// AES-GCM open failed — wrong backup key or corrupt/tampered file.
        case decryptionFailed
        /// AES-GCM seal or SecRandomCopyBytes failed.
        case encryptionFailed
        /// Shamir reconstruction or shard validation failed.
        case bekReconstructionFailed
        /// A backup key already exists — this device is not a fresh restore target.
        case bekAlreadyPresent
    }

    // MARK: - Wire format constants

    /// Not `private` — `Backup.verifiedKey` also seals/opens against this exact
    /// format, and needs to reference it. A plain constant reference, not a stored
    /// dependency — costs `Backup` nothing in coupling; the value never changes and
    /// carries no state.
    static let backupMagic:   Data = Data("OCBK".utf8)
    static let backupFileAAD: Data = Data("occulta-backup-v1".utf8)

    // MARK: - Transient models

    /// In-memory encoding of the full vault, immediately sealed under the backup key.
    /// Never stored in SwiftData — plaintext fields are safe for the same reason
    /// SealedPayload carries a plaintext message field.
    struct VaultBackup: Codable {
        let version:   Int
        let createdAt: Date
        var entries:   [VaultBackupEntry]   // var so the plaintext can be zeroed in place
    }

    /// One entry's plaintext within VaultBackup. Transient — see VaultBackup above.
    struct VaultBackupEntry: Codable {
        let id:        UUID
        let entryType: Int    // VaultEntryType.rawValue
        let createdAt: Date
        var label:     Data   // plaintext UTF-8 label string; var so it can be zeroed in place
        var content:   Data   // plaintext entry content; var so it can be zeroed in place
    }

    /// Zeroes every entry's label and content in place (`bugs.md` Bug 96 item 3). Only
    /// effective while each buffer is held by `entries` alone: a buffer still shared elsewhere
    /// is copied on write, and the copy is zeroed instead of the original.
    static func zeroPlaintext(_ entries: inout [VaultBackupEntry]) {
        for i in entries.indices {
            entries[i].label.resetBytes(in: entries[i].label.startIndex..<entries[i].label.endIndex)
            entries[i].content.resetBytes(in: entries[i].content.startIndex..<entries[i].content.endIndex)
        }
    }

    // MARK: - Backup export metadata (staleness tracking, per depth)

    /// Decoded content of one depth's slot in the export-metadata file. Written alongside
    /// each export, one record per depth. Used to determine whether the vault state at
    /// *that depth* has drifted since *that depth's* last backup — never compared across
    /// depths, since all slots share one vault key and depth-indexing is the only thing
    /// keeping them apart. Never stored in plaintext — always AES-GCM sealed as part of
    /// the whole 32-slot array, under backupExportMetaAAD.
    struct BackupExportMetadata: Codable {
        /// When the export was performed.
        let exportedAt:     Date
        /// Backup key distributionID at export time. A mismatch means `backup.rotate()`
        /// was called.
        let distributionID: UUID
        /// Trustee count at export time. A count change means trustees were added/removed.
        /// NOTE: count-based — does not detect a same-size trustee swap in V1.
        let shardCount:     Int
        /// Vault entry count at export time. A higher current count means new entries exist.
        let entryCount:     Int
    }

    /// Reasons the last backup may no longer cover the current vault state.
    /// All three fields are independent — multiple reasons can be true simultaneously.
    struct BackupStalenessReport {
        /// `backup.rotate()` was called since the last export. The existing file is
        /// permanently unrestorable — the old backup key no longer exists.
        let bekRotated:        Bool
        /// Number of vault entries created after the last export. Zero = none.
        let newEntryCount:     Int
        /// The trustee set size differs from what was in place at export time.
        let trusteeSetChanged: Bool

        var isStale: Bool { bekRotated || newEntryCount > 0 || trusteeSetChanged }
    }

    // MARK: - Export

    /// Decrypt vault entries visible at `currentDepth` and seal them under the backup key
    /// as a `.occbak` file.
    ///
    /// Depth-scoped, not vault-wide — vault entries are exact-match partitioned, not
    /// nested (unlike contacts), so "what is visible here" is exactly "what depth ==
    /// currentDepth", and a file never needs to record which depth it came from. No
    /// default: a forgotten argument must be a compile error, not a silent leak of
    /// every layer into whichever depth happened to call this (Bug 88).
    ///
    /// Blocked if the backup key is not set up or its shard distribution is below
    /// threshold. The caller presents the returned bytes via UIDocumentPickerViewController.
    func exportBackup(currentDepth: Int) throws -> Data {
        let vaultKey = try self.currentKey()

        guard let decoded = try self.backup.fetchDecoded(vaultKey: vaultKey, currentDepth: currentDepth, modelContext: self.modelContext) else {
            throw BackupError.bekNotSetup
        }

        // Guard: confirmed shard count must meet a valid threshold before allowing export.
        // Only .confirmed shards count — .pending delivery is unconfirmed and may be lost.
        // threshold < 2 indicates corrupted metadata (split() rejects k < 2 at generation time).
        if let meta = decoded.payload.shardMetadata {
            guard meta.threshold >= 2 else { throw BackupError.belowThreshold }
            let active = meta.shards.filter { $0.status == .confirmed }.count
            guard active >= meta.threshold else { throw BackupError.belowThreshold }
        } else {
            throw BackupError.belowThreshold
        }

        let entries = try self.entriesVisible(atDepth: currentDepth)
        var backupEntries = [VaultBackupEntry]()
        backupEntries.reserveCapacity(entries.count)
        defer { Self.zeroPlaintext(&backupEntries) }

        for entry in entries {
            // decryptLabelPayload and decryptContent are internal — they call currentKey()
            // internally which is redundant but harmless (resets inactivity timer only).
            let labelPayload = try self.decryptLabelPayload(for: entry)
            let content      = try self.decryptContent(for: entry)
            backupEntries.append(VaultBackupEntry(
                id:        entry.id,
                entryType: Int(labelPayload.type.rawValue),
                createdAt: entry.createdAt,
                label:     labelPayload.label.data(using: .utf8) ?? Data(),
                content:   content
            ))
        }

        // Built inside the call so no second reference to the entries outlives it, which
        // is what lets the defer above zero them in place.
        var json = try JSONEncoder().encode(VaultBackup(version: 1, createdAt: Date(), entries: backupEntries))
        defer { json.resetBytes(in: json.startIndex..<json.endIndex) }

        let sealed = try AES.GCM.seal(
            json,
            using:          decoded.bek,
            nonce:          AES.GCM.Nonce(),
            authenticating: Self.backupFileAAD
        )
        guard let combined = sealed.combined else { throw BackupError.encryptionFailed }

        var result = Self.backupMagic
        result.append(combined)

        // Seal a snapshot of this depth's vault state at export time. Used by
        // refreshBackupStaleness() to detect drift on subsequent unlocks at this
        // same depth — entryCount here is this depth's count, not the vault's.
        let exportMeta = BackupExportMetadata(
            exportedAt:     Date(),
            distributionID: decoded.payload.distributionID,
            shardCount:     decoded.payload.shardMetadata?.shards.count ?? 0,
            entryCount:     entries.count
        )
        try self.writeBackupExportMetadata(exportMeta, at: currentDepth, vaultKey: vaultKey)
        self.refreshBackupStaleness(currentDepth: currentDepth)

        return result
    }

    /// Vault entries visible at `depth`, per `VaultEntry.isVisible(atDepth:whenUnclassified:usingKey:)`.
    ///
    /// Derives the local DB hybrid key once and reuses it across every entry,
    /// rather than letting each entry's `.decrypt()` re-derive an identical key
    /// via a fresh Secure Enclave round trip — this runs on every unlock and
    /// every Vault tab appearance (`refreshBackupStaleness`), on the main actor.
    ///
    /// `whenUnclassified: depth == 0` (Bug 114) — true only at the real depth, matching
    /// the display path (`Manager.Security.visibleVaultEntries(from:)`). A legacy nil
    /// entry is real content that predates duress depths existing at all: it must still
    /// be included in an export made at the real depth 0 (the ordinary, ever-real-depth-
    /// only user this was originally protected against dropping it for), and must not be
    /// swept into a backup exported from a duress depth (`exportBackup(currentDepth:)`
    /// forwards its caller's live `currentDepth`, whatever that is). A single fixed value
    /// can't get both right — see Bug 113's identical reasoning on the display side.
    private func entriesVisible(atDepth depth: Int) throws -> [VaultEntry] {
        guard let key = try Manager.Key().createHybridLocalEncryptionKey() else {
            throw VaultError.keyDerivationFailed
        }
        return try self.fetchAllEntries().filter {
            $0.isVisible(atDepth: depth, whenUnclassified: depth == 0, usingKey: key)
        }
    }

    // MARK: - Restore helpers
    //
    // `restoreBackup` checks everything before writing anything (`bugs.md` Bug 129):
    // `decodedBackup` does every check that can reject a file, and `insertEntries` only
    // stages rows, so the backup key and the entries commit in one save or not at all.

    /// Decrypts `data` with `bek`, decodes it, and checks every entry, without touching the
    /// store. Every check that can reject a file happens here, before any write.
    private func decodedBackup(_ data: Data, using bek: SymmetricKey) throws -> VaultBackup {
        guard data.prefix(4) == Self.backupMagic else { throw BackupError.invalidFormat }

        let box  = try AES.GCM.SealedBox(combined: data.dropFirst(4))
        var json: Data
        do {
            json = try AES.GCM.open(box, using: bek, authenticating: Self.backupFileAAD)
        } catch {
            throw BackupError.decryptionFailed
        }
        defer { json.resetBytes(in: json.startIndex..<json.endIndex) }

        var backup = try JSONDecoder().decode(VaultBackup.self, from: json)

        // Checked before zeroing, not inside a loop over the entries: the loop would hold its own
        // reference to the array, so zeroing from inside it would zero a copy.
        guard backup.entries.allSatisfy(Self.isWellFormed) else {
            Self.zeroPlaintext(&backup.entries)
            throw BackupError.invalidFormat
        }
        return backup
    }

    /// Whether an entry's fields can be converted without trapping.
    private static func isWellFormed(_ entry: VaultBackupEntry) -> Bool {
        // UInt8(_: Int) traps outside 0...255 — VaultEntryType(rawValue:) is the safe
        // conversion, but only once the Int is known to fit. Anything that doesn't isn't
        // a future version's entry type, it's malformed.
        guard UInt8(exactly: entry.entryType) != nil else { return false }

        // UInt64(_: Double) traps outside its representable range — negative (pre-1970)
        // or large enough to overflow. aad(for:) does this exact conversion and cannot be
        // changed to guard it (sealed contract, see its doc comment), so the check has to
        // happen before createdAt is ever assigned. A plain range check rather than
        // UInt64(exactly:) — the latter requires exact integer representability, which
        // would reject every legitimate sub-second timestamp along with the bad ones.
        let createdAtSeconds = entry.createdAt.timeIntervalSince1970
        return createdAtSeconds >= 0 && createdAtSeconds < Double(UInt64.max)
    }

    /// Inserts `backup`'s entries at `currentDepth` **without saving**, preserving each
    /// original id and createdAt so entry history survives. Stamps every entry with
    /// `currentDepth` (Bug 88's import half) — the depth the file was opened at.
    /// Expects `decodedBackup` to have checked every entry already.
    private func insertEntries(_ backup: VaultBackup, currentDepth: Int, vaultKey: SymmetricKey) throws {
        for backupEntry in backup.entries {
            // Skip entries that already exist — prevents double-insertion when the same
            // entries are already in the store.
            if (try? self.fetchEntry(by: backupEntry.id)) != nil { continue }

            let entryType   = UInt8(exactly: backupEntry.entryType).flatMap(VaultEntryType.init(rawValue:)) ?? .note
            let labelString = String(data: backupEntry.label, encoding: .utf8) ?? ""

            // Build the entry with the original id and createdAt so that AAD is
            // consistent with the original device and entry history is preserved.
            let entry = VaultEntry(encryptedLabel: Data(), encryptedContent: Data())
            entry.id        = backupEntry.id
            entry.createdAt = backupEntry.createdAt

            // Stamp depth ceiling — always encrypted, never nil, same as addEntry
            // (Vault+Manager.swift:223). A backup file only ever holds one layer's
            // entries (Bug 88 remedy 4), so the depth to stamp is simply "here."
            entry.visibleThroughDepth = try DepthCodec.encode(currentDepth).encrypt()
            // Always-populated orphan flag (Bug 110), same as addEntry.
            entry.deletionToken = try VaultEntry.liveToken.encrypt()

            var pekBytes = [UInt8](repeating: 0, count: 32)
            guard SecRandomCopyBytes(kSecRandomDefault, 32, &pekBytes) == errSecSuccess else {
                throw BackupError.encryptionFailed
            }
            defer { for i in pekBytes.indices { pekBytes[i] = 0 } }

            let pek = SymmetricKey(data: Data(pekBytes))

            let sealedKey = try AES.GCM.seal(
                Data(pekBytes), using: vaultKey, nonce: AES.GCM.Nonce(),
                authenticating: entry.aad(for: .entryKey)
            )
            guard let combinedKey = sealedKey.combined else { throw BackupError.encryptionFailed }

            let labelData     = try JSONEncoder().encode(SealedLabelPayload(type: entryType, label: labelString))
            let sealedLabel   = try AES.GCM.seal(labelData,            using: pek, nonce: AES.GCM.Nonce(), authenticating: entry.aad(for: .label))
            let sealedContent = try AES.GCM.seal(backupEntry.content,  using: pek, nonce: AES.GCM.Nonce(), authenticating: entry.aad(for: .content))

            guard
                let combinedLabel   = sealedLabel.combined,
                let combinedContent = sealedContent.combined
            else { throw BackupError.encryptionFailed }

            entry.encryptedEntryKey = combinedKey
            entry.encryptedLabel    = combinedLabel
            entry.encryptedContent  = combinedContent

            self.modelContext.insert(entry)
        }
    }

    // MARK: - Backup-excluded writes

    /// Write sealed bytes, then mark the result as excluded from device backups.
    ///
    /// **Per write, never once at launch, and `.atomic` is why that is not merely prudent.**
    /// `isExcludedFromBackup` is a `URLResourceValues` attribute on the *file*. An atomic write
    /// stages a temp file and renames it over the target, so the inode carrying the attribute is
    /// discarded by the very next write — and both call sites rewrite routinely: every arming
    /// replaces the pending file, every export replaces the metadata. A bootstrap-time version
    /// would read back correct on the device it was tested on and be wrong from the second write
    /// onward, with nothing observable to say so. `excludeStoreFromBackup` re-applies on every
    /// `reapplyFileProtection` for the same reason, phrased there as "sidecar files may be
    /// recreated by SQLite" (Bug 100 remedy 1).
    ///
    /// Failure to set the attribute is swallowed deliberately. It is best-effort metadata
    /// hygiene, and failing an export or an arming because a backup flag would not stick trades a
    /// working recovery for a marginal one. Tests assert on reading the value back rather than on
    /// this not throwing.
    ///
    /// What this does and does not buy: the payloads are already sealed and device-bound, so a
    /// backup copy was never readable off-device. What travelled with it was existence, length and
    /// timestamps — and a backup is a far softer target than the device, obtainable without the
    /// passcode prompt `.completeFileProtection` depends on. See Bug 101 for the same content in a
    /// worse place; this remedy is incomplete without it.
    static func writeExcludedFromBackup(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: [.atomic, .completeFileProtection])

        var target = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? target.setResourceValues(values)
    }

    // MARK: - Restore from a backup file

    /// Restores from an opened `.occbak`: one reconstruction attempt at `currentDepth`,
    /// against the shards already banked. The file is never kept. A failed attempt stores
    /// nothing, and the owner opens the file again once more pieces have arrived.
    /// See `RECOVERY_BUFFER_LAYERING.md` §9.4.
    ///
    /// Tries each banked BEK-restore distribution against the file; the GCM tag inside
    /// `Backup.verifiedKey` picks the one that matches. Only shards whose sender is in
    /// `visibleContactIdentifiers` count. A real backup opened in a layer that hides its
    /// trustees can't complete there, and a coercer's own trustees, created in his layer,
    /// don't count at depth 0 (`bugs.md` Bug 99).
    ///
    /// **Checks everything before writing anything, then writes once** (`bugs.md` Bug 129):
    /// the key is verified and the whole file decoded and checked first; only then are the
    /// key and the entries staged and committed in one save. Any failure rolls the staged
    /// changes back, so a bad file leaves no key and no entries behind, and the layer can
    /// still be restored from a good copy.
    ///
    /// Returns whether entries were imported. Every failure returns `false` the same way —
    /// this depth already has a backup key (Bug 94 remedy 1), too few shards, no matching
    /// distribution, or a file that matches but won't decode. Throws only for a file that
    /// isn't a backup, or when the vault is locked.
    ///
    /// Banked shards are consumed only on success. They're left alone when this depth
    /// already has a key (collection is depth-blind, so they may belong to another layer's
    /// restore) and when the file matches but won't decode (only that copy is bad).
    func restoreBackup(from data: Data, currentDepth: Int, visibleContactIdentifiers: Set<String>) throws -> Bool {
        guard data.prefix(4) == Self.backupMagic else { throw BackupError.invalidFormat }
        let vaultKey = try self.currentKey()

        if (try? self.backup.fetchDecoded(vaultKey: vaultKey, currentDepth: currentDepth, modelContext: self.modelContext)) != nil {
            return false
        }

        for distributionID in (try? self.bekRestoreDistributionIDs()) ?? [] {
            let shards = ((try? self.collectedShards(forAttributeID: distributionID)) ?? [])
                .filter { visibleContactIdentifiers.contains($0.senderIdentifier) }
            guard !shards.isEmpty else { continue }

            guard var verified = try? self.backup.verifiedKey(
                vaultKey: vaultKey, shards: shards.map { $0.attribute }, backupData: data,
                ownerIdentity: nil, currentDepth: currentDepth, modelContext: self.modelContext
            ) else { continue }
            defer { for i in verified.bekBytes.indices { verified.bekBytes[i] = 0 } }

            // The key opened this file, so no other distribution will. From here any failure
            // ends the attempt with nothing written.
            do {
                var backup = try self.decodedBackup(data, using: SymmetricKey(data: verified.bekBytes))
                defer { Self.zeroPlaintext(&backup.entries) }
                try self.backup.stage(
                    BackupEncryptionKey.Payload(
                        bekBytes: verified.bekBytes, distributionID: verified.distributionID, shardMetadata: nil
                    ),
                    vaultKey: vaultKey, currentDepth: currentDepth, modelContext: self.modelContext
                )
                try self.insertEntries(backup, currentDepth: currentDepth, vaultKey: vaultKey)
                try self.modelContext.save()
            } catch {
                // Staged rows would otherwise be committed by the next save anywhere.
                self.modelContext.rollback()
                return false
            }

            self.orphanShards(forAttributeID: distributionID)
            self.postRestorePromptPending = true
            return true
        }
        return false
    }

    /// Deletes restore state left by versions before the one-shot design, without attempting
    /// it (`RECOVERY_BUFFER_LAYERING.md` §8):
    /// - the held `.occbak`, under its v1.10.3 name and its v1.10.2-and-earlier name;
    /// - the old shard file (`bugs.md` Bug 127);
    /// - the persisted post-restore flag.
    ///
    /// Called on every unlock and on wipe; after the first run there's nothing left to delete.
    /// Takes no depth, so it behaves the same in every layer.
    func deleteLegacyRestoreState() {
        let directory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        for name in ["backup-import-cache.occbak", "pending-restore.occbak", "pending-restore-shards.dat"] {
            try? FileManager.default.removeItem(at: directory.appendingPathComponent(name))
        }
        UserDefaults.standard.removeObject(forKey: "vault.postRestoreActionNeeded")
    }

    // MARK: - Backup key wrappers
    //
    // `Backup`'s own methods all take `vaultKey` explicitly — it holds no reference to
    // `VaultManager` and cannot derive one itself. These wrappers are the view-model
    // surface: they derive `vaultKey` via `self.currentKey()` and call through to
    // `self.backup`, so UI code (and tests) never handle raw key material directly and
    // never call `self.backup.X` themselves. Mirrors the pre-rename flat methods
    // (`bekSetupState`, `setupBEK`, `bekShardMetadata`, `prepareBEKShards`, `currentBEK`,
    // `reconstructBEK`) — same shape, "BEK" replaced with "Backup".

    /// `currentDepth`'s backup key distribution state. `.notSetup` when locked or when
    /// that depth has no backup key.
    func backupSetupState(currentDepth: Int) -> Backup.SetupState {
        guard let vaultKey = try? self.currentKey() else { return .notSetup }
        return self.backup.setupState(vaultKey: vaultKey, currentDepth: currentDepth, modelContext: self.modelContext)
    }

    /// `currentDepth`'s backup key shard distribution metadata, or `nil` if that depth's
    /// backup key has not been distributed yet.
    func backupShardMetadata(currentDepth: Int) throws -> ShardDistributionMetadata? {
        let vaultKey = try self.currentKey()
        return try self.backup.shardMetadata(vaultKey: vaultKey, currentDepth: currentDepth, modelContext: self.modelContext)
    }

    /// Generate and persist a new backup key at `currentDepth`, if that depth does
    /// not already have one. No-op if present at that depth.
    func setupBackup(currentDepth: Int) throws {
        let vaultKey = try self.currentKey()
        try self.backup.setup(vaultKey: vaultKey, currentDepth: currentDepth, modelContext: self.modelContext)
    }

    /// Split `currentDepth`'s backup key into signed shards, one per identifier in
    /// `recipients`, and persist the distribution metadata.
    func prepareBackupShards(threshold: Int, recipients: [String], currentDepth: Int) throws -> [SignedAttribute] {
        let vaultKey = try self.currentKey()
        return try self.backup.prepareShards(
            vaultKey: vaultKey, threshold: threshold, recipients: recipients, currentDepth: currentDepth, modelContext: self.modelContext
        )
    }

    /// `currentDepth`'s backup key as a `SymmetricKey`.
    func currentBackupKey(currentDepth: Int) throws -> SymmetricKey {
        let vaultKey = try self.currentKey()
        return try self.backup.current(vaultKey: vaultKey, currentDepth: currentDepth, modelContext: self.modelContext)
    }

    // MARK: - Backup key filler baseline

    /// Tops up the `BackupEncryptionKey` table to `AppLayerConfig.maxDepthCount` filler
    /// rows, inserting whatever is missing. Idempotent — a device already at or past that
    /// count (whether from a prior run of this function, or from claimed/migrated rows)
    /// does nothing.
    ///
    /// Filler rows carry `depth`, `deletionToken`, and `encryptedPayload` as plain
    /// `Data.randomBytes` of the correct fixed length — never run through a real
    /// seal, so they never decrypt (`BackupEncryptionKey.isUnclaimed(usingKey:)` is
    /// what checks for this). Random bytes of the right length are cryptographically
    /// indistinguishable from genuine ciphertext+tag without the key, so no key
    /// material — local or vault — is needed to generate them, and this can run
    /// unconditionally at `VaultManager` construction, before Secure Mode is ever
    /// configured. This reproduces the property the old 32-slot array's "always 32
    /// slots, real or filler" design gave for free, per-row instead of
    /// per-file-offset.
    ///
    /// Each field's filler is sized to match exactly what a *claimed* row of that
    /// field would be — using the wrong length here would itself be the structural,
    /// zero-decryption tell this whole design exists to avoid (a filler row
    /// distinguishable from a real one purely by field byte-count, no key needed).
    ///
    /// 32 is a starting baseline, not a hard cap — `Backup.persist` claims a filler
    /// row when one is available and inserts a fresh row past the baseline once none
    /// remain. Uncapped beyond that, deliberately: a row is only ever created by an
    /// explicit "set up backup at this depth" action, not everyday use, so unbounded
    /// growth past 32 is accepted as simpler than reusing `VaultEntry`'s cap-and-evict
    /// shape for a population that grows this much more slowly.
    func ensureBackupKeyFillerRows() {
        let target = AppLayerConfig.maxDepthCount
        guard let count = try? self.modelContext.fetchCount(FetchDescriptor<BackupEncryptionKey>()),
              count < target
        else { return }

        let depthFillerSize   = DepthCodec.sealedSize
        let tokenFillerSize   = BackupEncryptionKey.liveToken.count + 28
        let payloadFillerSize = Backup.PayloadCodec.payloadSize + 28

        for _ in count..<target {
            let filler = BackupEncryptionKey(
                depth:            Data.randomBytes(depthFillerSize),
                deletionToken:    Data.randomBytes(tokenFillerSize),
                encryptedPayload: Data.randomBytes(payloadFillerSize)
            )
            self.modelContext.insert(filler)
        }
        try? self.modelContext.save()
    }

    // MARK: - Legacy storage migration

    /// Migrates real content out of the two storage generations this replaces, into
    /// the current per-depth row model — see `VAULT_KEY_LAYERING.md` for the full
    /// history. Lives on `VaultManager`, not inside `Backup` — needs `modelContext`,
    /// which is `VaultManager`'s own resource. Called once per unlock
    /// (`unlock(context:)`); both steps are independently idempotent, so
    /// running this every unlock costs nothing once migration is complete.
    ///
    /// Three possible starting states, handled in order, each a no-op once done:
    ///
    /// 1. **The old 32-slot array file**, if it still exists. Its payload was never
    ///    depth-derived-key-sealed, so one `vaultKey` derivation — available at any
    ///    unlock, any depth — decodes all 32 slots in one pass; no need to wait for
    ///    the user to separately visit each duress depth. Every slot with a real
    ///    (non-filler) payload where no live row yet exists for that depth gets
    ///    claimed via `Backup.persist`. The file is deleted once fully read —
    ///    deliberately, not tombstoned: see `migrateBackupArrayIfNeeded`'s own doc
    ///    comment for why this diverges from the "never hard-delete" convention.
    /// 2. **The original single-row legacy `BackupEncryptionKey`**, identifiable
    ///    unambiguously as the one row with *literally nil* `depth` and
    ///    `deletionToken` — every row this codebase creates now, real or filler,
    ///    always populates both, so nil/nil can only be that original pre-refactor
    ///    row. Only migrated to depth 0, and only if depth 0 still has no live row
    ///    after step 1 — reproduces the original precedence (array data always wins
    ///    over the legacy row).
    /// 3. **Neither** — nothing to do.
    ///
    /// One accepted behavior change carried forward from the migration this
    /// replaces: a migration failure (a row exists, decrypts, but fails to decode —
    /// a real anomaly, not "nothing to migrate") is swallowed by `unlock()`'s `try?`
    /// rather than surfaced to whatever UI action first touched the backup key. The
    /// affected row simply stays un-migrated and the next unlock tries again — safe,
    /// not silent data loss, but a diagnostic regression for that one rare case.
    /// `legacyArrayBackend` is injectable — defaults to the real production location —
    /// purely so tests can substitute `InMemoryLayerStoreBackend` and exercise the
    /// array-migration path without touching the real app-group container. Production
    /// callers never pass this explicitly.
    func migrateLegacyBackupStorageIfNeeded(vaultKey: SymmetricKey, legacyArrayBackend: any LayerStoreBackend = AppGroupLayerStoreBackend(directory: "cache")) throws {
        try self.migrateBackupArrayIfNeeded(vaultKey: vaultKey, backend: legacyArrayBackend)
        try self.migrateLegacyBackupRowIfNeeded(vaultKey: vaultKey)
    }

    /// AAD the old array sealed each slot under (`Backup.SlotAAD`, deleted along with
    /// the array itself) — kept here, read-only, purely so this one-time migration
    /// can still open slots that were sealed under it before the type existed to
    /// compute this for us. Never used for anything but reading legacy data.
    private static func legacyArraySlotAAD(slotIndex: Int) -> Data {
        var out = Data("occulta-bek-slot-v1".utf8)
        out.append(UInt8(slotIndex))
        return out
    }

    /// Reads every slot of the old 32-slot array file in one pass and claims a row
    /// for each real (non-filler) slot with no live row yet at that depth. Deletes
    /// the file once fully read, real slots or not.
    ///
    /// **Deletes rather than tombstones, deliberately diverging from this
    /// codebase's "never hard-delete a legacy security artifact" convention.** That
    /// convention exists so a downgraded build fails *closed* — sees something,
    /// refuses to reinitialize silently. The array is different: once
    /// `Manager.Security.orphanBackupKeys` starts operating purely against the new
    /// rows, a frozen leftover array file would fail a downgraded build *open* onto
    /// stale data — rotations and orphan events that happen after migration are
    /// invisible to a file nothing writes to anymore, so it would present
    /// trustee/shard state that no longer matches reality. Presenting nothing (file
    /// absent, same as a device that never had one) is safer than presenting a
    /// convincing lie.
    private func migrateBackupArrayIfNeeded(vaultKey: SymmetricKey, backend: any LayerStoreBackend) throws {
        guard backend.exists, let fileData = try? backend.read() else { return }

        let slotCiphertextSize = Backup.PayloadCodec.payloadSize + 28
        guard fileData.count == 32 * slotCiphertextSize else {
            // Not a well-formed array file for this shape — leave it for manual
            // investigation rather than guessing at a different layout.
            return
        }

        for slotIndex in 0..<32 {
            let start = slotIndex * slotCiphertextSize
            let slotCiphertext = fileData.subdata(in: start..<(start + slotCiphertextSize))
            guard let box       = try? AES.GCM.SealedBox(combined: slotCiphertext),
                  let plaintext = try? AES.GCM.open(box, using: vaultKey, authenticating: Self.legacyArraySlotAAD(slotIndex: slotIndex)),
                  let payload   = Backup.PayloadCodec.decode(plaintext)
            else { continue }   // filler slot, or unreadable under this key — nothing to migrate

            guard try self.backup.fetchDecoded(vaultKey: vaultKey, currentDepth: slotIndex, modelContext: self.modelContext) == nil else {
                continue   // already migrated, or independently claimed since — idempotent
            }
            try self.backup.persist(payload, vaultKey: vaultKey, currentDepth: slotIndex, modelContext: self.modelContext)
        }

        // Only reached once every slot has been read and any real ones committed —
        // a crash before this point just retries next unlock; the per-slot
        // idempotency check above makes the retry a no-op for anything already
        // migrated.
        backend.delete()
    }

    /// Migrates the original single-row legacy `BackupEncryptionKey` to depth 0, if
    /// one still exists and depth 0 has no live row yet.
    ///
    /// Folds the legacy row into an ordinary filler row *before* calling
    /// `Backup.persist` — not after, and not left to `persist`'s own filler-claiming
    /// to handle incidentally. `BackupEncryptionKey.isUnclaimed(usingKey:)` reports
    /// `true` for a nil `depth` exactly as it does for genuine filler (both fail
    /// safe the same way), so the legacy row *would* be a valid candidate for
    /// `persist`'s own claim logic to pick — but only sometimes, depending on fetch
    /// order, since real filler rows are equally valid candidates. Folding first
    /// makes the outcome deterministic instead of order-dependent: whichever row
    /// `persist` ends up claiming for depth 0, the legacy row is unconditionally
    /// blended into the filler pool either way, never left holding its original
    /// real ciphertext un-tombstoned because a different row happened to be claimed
    /// instead.
    private func migrateLegacyBackupRowIfNeeded(vaultKey: SymmetricKey) throws {
        guard try self.backup.fetchDecoded(vaultKey: vaultKey, currentDepth: 0, modelContext: self.modelContext) == nil else {
            return
        }
        let rows = try self.modelContext.fetch(FetchDescriptor<BackupEncryptionKey>())
        guard let legacyRow = rows.first(where: { $0.depth == nil && $0.deletionToken == nil }) else {
            return
        }

        // Decode before folding — folding overwrites the only copy of this row's
        // real content.
        let legacyPayload: BackupEncryptionKey.Payload? = {
            guard let box       = try? AES.GCM.SealedBox(combined: legacyRow.encryptedPayload),
                  let plaintext = try? AES.GCM.open(box, using: vaultKey, authenticating: legacyRow.aad())
            else { return nil }
            return try? JSONDecoder().decode(BackupEncryptionKey.Payload.self, from: plaintext)
        }()

        self.foldLegacyRowIntoFiller(legacyRow)
        try self.modelContext.save()

        guard let legacyPayload else { return }   // already tombstoned, or genuinely corrupt — nothing to carry forward
        try self.backup.persist(legacyPayload, vaultKey: vaultKey, currentDepth: 0, modelContext: self.modelContext)
    }

    /// Overwrites a nil/nil legacy row's three fields with fresh random bytes of
    /// their correct fixed lengths, indistinguishable from any other filler row —
    /// see `ensureBackupKeyFillerRows()` for why each length matters. Never deletes
    /// the row.
    private func foldLegacyRowIntoFiller(_ row: BackupEncryptionKey) {
        row.encryptedPayload = Data.randomBytes(row.encryptedPayload.count)
        row.depth            = Data.randomBytes(DepthCodec.sealedSize)
        row.deletionToken    = Data.randomBytes(BackupEncryptionKey.liveToken.count + 28)
    }

    // MARK: - Export metadata slot codec

    /// Fixed-width plaintext codec for one `BackupExportMetadata` slot, and the
    /// 32-slot layout that holds one per depth.
    ///
    /// One slot per depth so a slot's presence or absence never varies the file's
    /// total length — the same reasoning as `DepthCodec`, applied to this file's own
    /// format rather than to `Contact.Profile`'s depth fields. `slotCount` reuses
    /// `AppLayerConfig.maxDepthCount` deliberately, not as a borrowed number: that
    /// constant is the actual, enforced ceiling on nesting in this codebase — the
    /// verifier arrays themselves no-op past it — confirmed independently by
    /// `DepthCodec`'s own doc comment, which calls it out as "the real structural
    /// limit," distinct from `DepthCodec.maxEncodableDepth`'s far larger, deliberately
    /// generous encoding ceiling.
    ///
    /// ```
    /// byte 0      presence tag: 0xA5 = real record, anything else = absent/filler
    /// byte 1–8    exportedAt   — UInt64 seconds since 1970, big-endian
    /// byte 9–24   distributionID — UUID's raw 16 bytes
    /// byte 25     shardCount   — UInt8, saturating
    /// byte 26–27  entryCount   — UInt16, big-endian, saturating
    /// ```
    ///
    /// Filler is random bytes at the same 28-byte width, not a structured "empty"
    /// marker — matching `AppLayerConfig`/`Manager.LayerStore`'s house style. Unlike
    /// those arrays, indistinguishability under decryption isn't load-bearing here
    /// (these slots are only ever read by index, in context, never scanned or
    /// inspected in isolation) — random filler is chosen for consistency with the
    /// rest of Secure Mode, not because this format specifically requires it.
    private enum ExportMetaSlotCodec {
        static let slotCount:     Int = AppLayerConfig.maxDepthCount
        static let slotPlainSize: Int = 28

        private static let presenceTag: UInt8 = 0xA5

        /// `nil` encodes to random filler — total, matches `DepthCodec.encode`'s own
        /// "must not trap" requirement. `shardCount`/`entryCount` saturate via
        /// `clamping:` rather than a plain cast, which would trap outside range —
        /// exactly the class of bug fixed twice in backup import, now `decodedBackup` (Bug 96).
        static func encodeSlot(_ meta: BackupExportMetadata?) -> Data {
            guard let meta else { return Data.randomBytes(Self.slotPlainSize) }

            var out = Data(capacity: Self.slotPlainSize)
            out.append(Self.presenceTag)

            var ts = UInt64(max(0, meta.exportedAt.timeIntervalSince1970)).bigEndian
            withUnsafeBytes(of: &ts) { out.append(contentsOf: $0) }

            out.append(Self.uuidBytes(meta.distributionID))
            out.append(UInt8(clamping: meta.shardCount))

            var entryCount = UInt16(clamping: meta.entryCount).bigEndian
            withUnsafeBytes(of: &entryCount) { out.append(contentsOf: $0) }

            return out
        }

        /// `nil` for filler or a malformed slot — same "absent" meaning either way,
        /// since a genuinely-never-written slot and random filler are indistinguishable
        /// by construction.
        static func decodeSlot(_ plain: Data) -> BackupExportMetadata? {
            guard plain.count == Self.slotPlainSize, plain.first == Self.presenceTag else {
                return nil
            }
            let bytes = [UInt8](plain)

            let ts = bytes[1..<9].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            let exportedAt = Date(timeIntervalSince1970: TimeInterval(ts))

            guard let distributionID = Self.uuid(fromBytes: Array(bytes[9..<25])) else { return nil }

            let shardCount = Int(bytes[25])
            let entryCount = Int(bytes[26]) << 8 | Int(bytes[27])

            return BackupExportMetadata(
                exportedAt:     exportedAt,
                distributionID: distributionID,
                shardCount:     shardCount,
                entryCount:     entryCount
            )
        }

        private static func uuidBytes(_ id: UUID) -> Data {
            withUnsafeBytes(of: id.uuid) { Data($0) }
        }

        private static func uuid(fromBytes bytes: [UInt8]) -> UUID? {
            guard bytes.count == 16 else { return nil }
            return UUID(uuid: (
                bytes[0], bytes[1], bytes[2],  bytes[3],  bytes[4],  bytes[5],  bytes[6],  bytes[7],
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
            ))
        }
    }

    // MARK: - Export metadata helpers

    private static let backupExportMetaURL: URL =
        FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("backup-export-meta.dat")

    private static let backupExportMetaAAD: Data =
        Data("occulta.backup-export-meta-v1".utf8)

    /// Removes the export metadata file. Only the wipe calls this (`bugs.md` Bug 128).
    func deleteBackupExportMetadata() {
        try? FileManager.default.removeItem(at: Self.backupExportMetaURL)
    }

    /// Recompute `backupStaleness` for `currentDepth` by comparing that depth's sealed
    /// export snapshot against that depth's current vault entries. Never derived from
    /// another depth's record or entry count — the file holds 32 slots under one vault
    /// key, and depth-indexing is the only thing keeping them apart, so reading anything
    /// but slot[currentDepth] here would leak cross-depth state into a single depth's
    /// signal (the same failure shape Bug 93 was filed over, on the restore side).
    /// Sets `backupStaleness` to `nil` when this depth has never been exported.
    func refreshBackupStaleness(currentDepth: Int) {
        guard let vaultKey = try? self.currentKey() else {
            self.backupStaleness = nil
            return
        }
        // try? on a `throws -> T?` flattens to `T?` — nil covers both "threw" and
        // "decoded fine, no record for this depth" identically, which is the
        // intended behaviour (see loadBackupExportMetadata's doc comment).
        guard let meta = try? self.loadBackupExportMetadata(at: currentDepth, vaultKey: vaultKey) else {
            self.backupStaleness = nil
            return
        }

        let decoded = try? self.backup.fetchDecoded(vaultKey: vaultKey, currentDepth: currentDepth, modelContext: self.modelContext)

        let bekRotated        = decoded.map { $0.payload.distributionID != meta.distributionID } ?? false
        let currentEntryCount = (try? self.entriesVisible(atDepth: currentDepth).count) ?? 0
        let newEntryCount     = max(0, currentEntryCount - meta.entryCount)
        let currentShardCount = decoded?.payload.shardMetadata?.shards.count ?? 0
        let trusteeSetChanged = currentShardCount != meta.shardCount

        let report = BackupStalenessReport(
            bekRotated:        bekRotated,
            newEntryCount:     newEntryCount,
            trusteeSetChanged: trusteeSetChanged
        )
        self.backupStaleness = report.isStale ? report : nil
    }

    /// Write `meta` into `depth`'s slot only. Every other slot's plaintext is carried
    /// through byte-for-byte. Out-of-range depths no-op, matching
    /// `AppLayerConfig.writeDuressVerifier`'s own convention for the same situation.
    private func writeBackupExportMetadata(_ meta: BackupExportMetadata, at depth: Int, vaultKey: SymmetricKey) throws {
        var slots = (try? self.loadAllExportMetaSlots(vaultKey: vaultKey))
            ?? Array<BackupExportMetadata?>(repeating: nil, count: ExportMetaSlotCodec.slotCount)
        guard depth >= 0, depth < slots.count else { return }
        slots[depth] = meta

        var plain = Data(capacity: ExportMetaSlotCodec.slotCount * ExportMetaSlotCodec.slotPlainSize)
        for slot in slots { plain.append(ExportMetaSlotCodec.encodeSlot(slot)) }

        let sealed = try AES.GCM.seal(
            plain, using: vaultKey,
            nonce: AES.GCM.Nonce(),
            authenticating: Self.backupExportMetaAAD
        )
        guard let combined = sealed.combined else { throw BackupError.encryptionFailed }
        try Self.writeExcludedFromBackup(combined, to: Self.backupExportMetaURL)
    }

    /// `depth`'s slot, or `nil` if that depth has never been exported (a genuinely empty
    /// slot decodes the same as filler — see `ExportMetaSlotCodec.decodeSlot`).
    private func loadBackupExportMetadata(at depth: Int, vaultKey: SymmetricKey) throws -> BackupExportMetadata? {
        let slots = try self.loadAllExportMetaSlots(vaultKey: vaultKey)
        guard depth >= 0, depth < slots.count else { return nil }
        return slots[depth]
    }

    private func loadAllExportMetaSlots(vaultKey: SymmetricKey) throws -> [BackupExportMetadata?] {
        let combined = try Data(contentsOf: Self.backupExportMetaURL)
        let box       = try AES.GCM.SealedBox(combined: combined)
        let plain     = try AES.GCM.open(box, using: vaultKey, authenticating: Self.backupExportMetaAAD)
        let slotSize  = ExportMetaSlotCodec.slotPlainSize
        guard plain.count == ExportMetaSlotCodec.slotCount * slotSize else {
            throw BackupError.invalidFormat
        }
        return (0..<ExportMetaSlotCodec.slotCount).map { i in
            let start = plain.startIndex + i * slotSize
            return ExportMetaSlotCodec.decodeSlot(plain.subdata(in: start..<(start + slotSize)))
        }
    }
}

// MARK: - VaultManager.Backup

extension VaultManager {

    /// Everything about the device's Backup Encryption Key: setup, access, shard
    /// distribution, reconstruction, rotation, and the per-depth rows it lives in.
    ///
    /// Holds no reference to `VaultManager` itself — every method takes `vaultKey:
    /// SymmetricKey` explicitly, and now `modelContext: ModelContext` explicitly too,
    /// the same shape. `Backup` never derives either, never asks where they came from.
    /// `keyManager` is a plain injected value, not a back-reference.
    ///
    /// Restructured again 2026-09-11 (`VAULT_KEY_LAYERING.md`, BEK-to-database
    /// migration): the 32-slot fixed-width array (`VaultManager.Backup.LayerStore`,
    /// deleted) is gone, replaced by ordinary `BackupEncryptionKey` SwiftData rows —
    /// one per claimed depth, 32 prefilled as filler at launch (see
    /// `VaultManager`'s launch sequence), uncapped beyond that. `backend`/
    /// `LayerStoreBackend` are gone from this class entirely; SwiftData access needs
    /// `modelContext`, which this class was deliberately never given a stored
    /// reference to (2026-09-09's restructure) — so it's threaded through per-call
    /// instead, preserving the "no ambient state" property rather than reintroducing
    /// the coupling that restructure removed.
    ///
    /// **Local-key derivation trap, worth restating on every method that hits it**:
    /// `depth`/`deletionToken` are sealed under the local DB key, ambiently derived via
    /// `Manager.Key().createHybridLocalEncryptionKey()` — never via `self.keyManager`.
    /// `Manager.Security.orphanBackupKeys` (the deactivation-time orphaning this design
    /// exists to enable) derives its local key the same ambient way, un-injected. If
    /// this class instead read `self.keyManager` for local-key derivation, its writes
    /// and `Manager.Security`'s orphan-reads would disagree under any injected test key
    /// manager — every existing test uses one — and orphaning would silently never
    /// match anything, since `isOrphaned`/`isUnclaimed` fail safe rather than crash.
    ///
    /// Not called directly outside `VaultManager` — the "Backup key wrappers" section
    /// above (`backupSetupState`, `setupBackup`, `backupShardMetadata`,
    /// `prepareBackupShards`, `currentBackupKey`) is the surface UI
    /// code and tests use; each one derives `vaultKey` via `self.currentKey()`, already
    /// has `self.modelContext`, and calls through. `rotate` and `distributeShards` have
    /// no caller yet and get no wrapper — add one only once something actually calls
    /// them.
    final class Backup {

        private let keyManager: any KeyManagerProtocol

        init(keyManager: any KeyManagerProtocol) {
            self.keyManager = keyManager
        }

        // MARK: - Local-key row lookup

        /// Derives the local DB key ambiently — see the class doc comment for why this
        /// must never go through `self.keyManager`.
        private func localKey() throws -> SymmetricKey {
            guard let key = try? Manager.Key().createHybridLocalEncryptionKey() else {
                throw BackupError.decryptionFailed
            }
            return key
        }

        /// Every row currently live (claimed, not orphaned, not filler). Both the
        /// per-depth lookup below and `updateShardStatus`'s full scan go through this,
        /// so there is exactly one place that knows "live vs. everything else," and a
        /// filler or orphaned row can never be read as a candidate for either.
        private func liveRows(modelContext: ModelContext) throws -> (rows: [BackupEncryptionKey], key: SymmetricKey) {
            let key  = try self.localKey()
            let rows = try modelContext.fetch(FetchDescriptor<BackupEncryptionKey>())
            let live = rows.filter { !$0.isOrphaned(usingKey: key) && !$0.isUnclaimed(usingKey: key) }
            return (live, key)
        }

        /// The live row claimed for `depth`, if any.
        private func liveRow(forDepth depth: Int, modelContext: ModelContext) throws -> (row: BackupEncryptionKey, key: SymmetricKey)? {
            let (rows, key) = try self.liveRows(modelContext: modelContext)
            for row in rows {
                guard let data  = row.depth, let plain = data.decrypt(using: key),
                      let value = DepthCodec.decode(plain), value == depth
                else { continue }
                return (row, key)
            }
            return nil
        }

        /// A never-claimed filler row, or a freshly inserted one if none remain — the
        /// uncapped-overflow case once all 32 prefilled rows have been claimed at least
        /// once. Filler rows are never reclaimed once orphaned (one-way: filler → live
        /// → orphaned), so running out is expected eventually, not an error.
        private func claimFillerRow(modelContext: ModelContext, key: SymmetricKey) throws -> BackupEncryptionKey {
            let rows = try modelContext.fetch(FetchDescriptor<BackupEncryptionKey>())
            if let filler = rows.first(where: { $0.isUnclaimed(usingKey: key) }) {
                return filler
            }
            let fresh = BackupEncryptionKey(encryptedPayload: Data.randomBytes(PayloadCodec.payloadSize + 28))
            modelContext.insert(fresh)
            return fresh
        }

        /// Seals `payload` into `row.encryptedPayload` under `vaultKey`, AAD-bound to
        /// `row.id`. Shared by `persist` (find-or-claim, then seal) and
        /// `updateShardStatus` (already holds the row, no lookup needed).
        private func seal(_ payload: BackupEncryptionKey.Payload, vaultKey: SymmetricKey, into row: BackupEncryptionKey) throws {
            let plaintext = try PayloadCodec.encode(payload)
            let sealed = try AES.GCM.seal(plaintext, using: vaultKey, nonce: AES.GCM.Nonce(), authenticating: row.aad())
            guard let combined = sealed.combined else { throw BackupError.encryptionFailed }
            row.encryptedPayload = combined
        }

        // MARK: - Setup

        /// Generate and persist a new backup key at `currentDepth`, if that depth does
        /// not already have one. No-op if present at that depth.
        func setup(vaultKey: SymmetricKey, currentDepth: Int, modelContext: ModelContext) throws {
            guard try self.fetchDecoded(vaultKey: vaultKey, currentDepth: currentDepth, modelContext: modelContext) == nil else {
                return
            }

            var bekBytes = [UInt8](repeating: 0, count: 32)
            guard SecRandomCopyBytes(kSecRandomDefault, 32, &bekBytes) == errSecSuccess else {
                throw BackupError.encryptionFailed
            }
            defer { for i in bekBytes.indices { bekBytes[i] = 0 } }

            try self.persist(
                BackupEncryptionKey.Payload(
                    bekBytes:      Data(bekBytes),
                    distributionID: UUID(),
                    shardMetadata: nil
                ),
                vaultKey: vaultKey,
                currentDepth: currentDepth,
                modelContext: modelContext
            )
        }

        // MARK: - Access

        /// Return `currentDepth`'s backup key as a SymmetricKey.
        func current(vaultKey: SymmetricKey, currentDepth: Int, modelContext: ModelContext) throws -> SymmetricKey {
            guard let decoded = try self.fetchDecoded(vaultKey: vaultKey, currentDepth: currentDepth, modelContext: modelContext) else {
                throw BackupError.bekNotSetup
            }
            return decoded.bek
        }

        // MARK: - Setup state (read by VaultTab)

        enum SetupState: Equatable {
            case notSetup
            case waitingForConfirmations(confirmed: Int, threshold: Int)
            case ready
        }

        /// `currentDepth`'s backup key distribution state. Returns `.notSetup` when
        /// that depth's backup key is absent.
        func setupState(vaultKey: SymmetricKey, currentDepth: Int, modelContext: ModelContext) -> SetupState {
            guard let meta = try? self.shardMetadata(vaultKey: vaultKey, currentDepth: currentDepth, modelContext: modelContext) else { return .notSetup }
            let confirmed = meta.shards.filter { $0.status == .confirmed }.count
            return confirmed >= meta.threshold
                ? .ready
                : .waitingForConfirmations(confirmed: confirmed, threshold: meta.threshold)
        }

        /// `currentDepth`'s backup key shard distribution metadata, or `nil` if that
        /// depth's backup key has not been distributed yet.
        func shardMetadata(vaultKey: SymmetricKey, currentDepth: Int, modelContext: ModelContext) throws -> ShardDistributionMetadata? {
            try self.fetchDecoded(vaultKey: vaultKey, currentDepth: currentDepth, modelContext: modelContext)?.payload.shardMetadata
        }

        // MARK: - Shard distribution

        /// Split the backup key into signed shards and persist the distribution metadata.
        ///
        /// Parallel to `prepareShards` for per-entry PEKs. Returns one SignedAttribute
        /// per recipient in the same order as `recipients`. The caller feeds these into
        /// `distributeShards` or the .occ basket pipeline.
        ///
        /// Takes contact identifiers, not `[Contact.Profile]` — the only field this ever
        /// read off a recipient was `.identifier`. `Backup` holds no reference to
        /// `VaultManager` or `modelContext`; accepting live SwiftData managed objects here
        /// would reintroduce exactly that coupling one parameter over; `[String]` is the
        /// full extent of what this actually needs.
        ///
        /// Mints a fresh `distributionID` on every call — `bugs.md` Bug 124, 2026-09-14.
        /// Previously reused `decoded.payload.distributionID` across every redistribution,
        /// so a trustee removed from `recipients` kept a permanently-valid credential:
        /// neither their old, genuinely-signed share nor the id it carried ever expired.
        /// `restoreBackup` already groups collected shards by `entryID` before
        /// attempting reconstruction (built for Bug 95) — that grouping is what makes this
        /// sufficient on its own: a stale submission now lands in its own group under an id
        /// nothing else is tagged with, never reaches threshold, and never touches a live
        /// restore. `bekBytes` is deliberately untouched — regenerating the key itself would
        /// orphan every already-exported `.occbak` (`decisions.md`'s "reuse the same BEK
        /// across trustee-set changes"); the id costs nothing there since
        /// `VaultManager.backupFileAAD` never depends on it.
        func prepareShards(
            vaultKey: SymmetricKey, threshold: Int, recipients: [String], currentDepth: Int, modelContext: ModelContext
        ) throws -> [SignedAttribute] {
            guard let decoded = try self.fetchDecoded(vaultKey: vaultKey, currentDepth: currentDepth, modelContext: modelContext) else {
                throw BackupError.bekNotSetup
            }

            let n              = recipients.count
            let distributionID = UUID()

            var bekBytes = Data()
            decoded.bek.withUnsafeBytes { bekBytes = Data($0) }
            defer { for i in bekBytes.indices { bekBytes[i] = 0 } }

            var rawShares = try ShamirSecretSharing.split(secret: bekBytes, threshold: threshold, shares: n)
            defer {
                for i in rawShares.indices {
                    for j in rawShares[i].indices { rawShares[i][j] = 0 }
                }
            }

            var attributes = [SignedAttribute]()
            attributes.reserveCapacity(n)

            for i in 0..<n {
                let shardData = Data(rawShares[i])
                let attrID    = UUID()
                let createdAt = Date()

                let sigPayload = SignedAttribute.signingPayload(
                    id:        attrID,
                    category:  .shard,
                    value:     shardData,
                    entryID:   distributionID,
                    createdAt: createdAt,
                    expiresAt: nil
                )
                let signature = try self.keyManager.signData(sigPayload)

                attributes.append(SignedAttribute(
                    id:        attrID,
                    label:     "vault-bek-shard",
                    value:     shardData,
                    category:  .shard,
                    signature: signature,
                    createdAt: createdAt,
                    entryID:   distributionID
                ))
            }

            let now    = Date()
            let shards = (0..<n).map { i in
                ShardRecord(
                    contactIdentifier: recipients[i],
                    attributeID:            attributes[i].id,
                    status:            .pending,
                    distributedAt:     now
                )
            }

            try self.persist(
                BackupEncryptionKey.Payload(
                    bekBytes:      decoded.payload.bekBytes,
                    distributionID: distributionID,
                    shardMetadata: ShardDistributionMetadata(threshold: threshold, shards: shards)
                ),
                vaultKey: vaultKey,
                currentDepth: currentDepth,
                modelContext: modelContext
            )

            return attributes
        }

        /// Prepare backup-key shards and encrypt each as a `.occ` bundle ready for sharing.
        ///
        /// Parallel to `distributeShards` for per-entry PEKs.
        /// Returns one `(contactIdentifier, occData)` tuple per recipient.
        ///
        /// Takes contact identifiers, not `[Contact.Profile]` — see `prepareShards`'s own
        /// doc comment for why.
        func distributeShards(
            vaultKey:       SymmetricKey,
            threshold:      Int,
            recipients:     [String],
            contactManager: ContactManager,
            currentDepth:   Int,
            modelContext:   ModelContext
        ) throws -> [(contactIdentifier: String, occData: Data)] {
            // Capture existing attrIDs before re-split: existing trustees get .replace,
            // new trustees get .distribute.
            let oldAttrIDs: [String: UUID]
            if let decoded = try? self.fetchDecoded(vaultKey: vaultKey, currentDepth: currentDepth, modelContext: modelContext),
               let meta    = decoded.payload.shardMetadata {
                oldAttrIDs = Dictionary(uniqueKeysWithValues: meta.shards.map { ($0.contactIdentifier, $0.attributeID) })
            } else {
                oldAttrIDs = [:]
            }

            let attributes = try self.prepareShards(
                vaultKey: vaultKey, threshold: threshold, recipients: recipients, currentDepth: currentDepth, modelContext: modelContext
            )

            return try zip(recipients, attributes).map { contactIdentifier, attribute in
                let oldID = oldAttrIDs[contactIdentifier]
                let op    = OccultaBundle.ShardOperation(
                    kind:        oldID != nil ? .replace : .distribute,
                    attribute:   attribute,
                    attributeID: oldID
                )
                let occ = try contactManager.encryptBundle(for: contactIdentifier, shardOperations: [op])
                return (contactIdentifier, occ)
            }
        }

        // MARK: - Reconstruction

        /// Rebuilds the backup key from ≥ k shards and returns it once it has opened
        /// `backupData`. **Writes nothing**: `VaultManager.restoreBackup` decodes and checks
        /// the whole file with this key before staging anything, so a file that fails
        /// later leaves no key behind (`bugs.md` Bug 129). The caller owns the returned
        /// bytes and zeroes them.
        ///
        /// Steps:
        ///   0. Refuse if `currentDepth` already has a backup key row — that layer is
        ///      not a fresh restore target (Bug 94).
        ///   1. Verify all shards share a single distributionID.
        ///   2. If `ownerIdentity` is provided, ECDSA-verify each shard.
        ///      Pass nil on new-device path (old key non-migratable); GCM tag substitutes.
        ///   3. Shamir.reconstruct → candidate backup key.
        ///   4. AES.GCM.open(backupFile, using: candidate) — GCM tag validates.
        ///   5. If the full set fails, retry with shards left out, fewest first, until a
        ///      candidate opens the file or `maxReconstructionAttempts` is reached.
        ///
        /// Step 5 is `bugs.md` Bug 95. On the new-device path no shard can be checked on its
        /// own (the key that signed them is gone), so one well-formed but wrong shard from a
        /// hostile trustee made every attempt fail, even with k honest shards present. Extra
        /// honest shards never change the result, so the first subset that opens the file is
        /// the full set minus the bad ones, and the GCM tag is an exact check for it. A
        /// hostile trustee can now do no more than withhold. The threshold is unknown here,
        /// so the search runs down to pairs; a subset below k just yields a wrong key.
        func verifiedKey(
            vaultKey:      SymmetricKey,
            shards:        [SignedAttribute],
            backupData:    Data,
            ownerIdentity: Data?,
            currentDepth:  Int,
            modelContext:  ModelContext
        ) throws -> (bekBytes: Data, distributionID: UUID) {
            guard try self.fetchDecoded(vaultKey: vaultKey, currentDepth: currentDepth, modelContext: modelContext) == nil else {
                throw BackupError.bekAlreadyPresent
            }

            let entryIDs = Set(shards.compactMap { $0.entryID })
            guard entryIDs.count == 1, let distributionID = entryIDs.first else {
                throw BackupError.bekReconstructionFailed
            }

            if let pubKey = ownerIdentity {
                guard shards.allSatisfy({ $0.verify(against: pubKey) }) else {
                    throw BackupError.bekReconstructionFailed
                }
            }

            guard backupData.prefix(4) == VaultManager.backupMagic else { throw BackupError.invalidFormat }
            let box = try AES.GCM.SealedBox(combined: backupData.dropFirst(4))

            let rawShares = shards.map { Array($0.value) }
            var attempts  = 0
            for leftOutCount in 0...max(0, rawShares.count - 2) {
                var leftOut = Array(0..<leftOutCount)
                repeat {
                    guard attempts < Self.maxReconstructionAttempts else { throw BackupError.bekReconstructionFailed }
                    attempts += 1

                    let subset = rawShares.indices.filter { !leftOut.contains($0) }.map { rawShares[$0] }
                    if let bekData = Self.keyOpening(box, from: subset) {
                        return (bekData, distributionID)
                    }
                } while Self.advance(&leftOut, below: rawShares.count)
            }
            throw BackupError.bekReconstructionFailed
        }

        /// The most reconstructions `verifiedKey` tries for one distribution. One bad shard
        /// needs at most n + 1 tries (n ≤ 255), so this only binds with several bad shards at
        /// once: two among up to 44 shards, three among up to 18, always fit.
        static let maxReconstructionAttempts = 1024

        /// The key `shares` reconstruct, if it opens `box`; nil otherwise, with the wrong
        /// candidate zeroed.
        private static func keyOpening(_ box: AES.GCM.SealedBox, from shares: [[UInt8]]) -> Data? {
            guard var bekData = try? ShamirSecretSharing.reconstruct(shares: shares) else { return nil }
            if bekData.count == 32,
               var plaintext = try? AES.GCM.open(box, using: SymmetricKey(data: bekData), authenticating: VaultManager.backupFileAAD) {
                plaintext.resetBytes(in: plaintext.indices)
                return bekData
            }
            bekData.resetBytes(in: bekData.indices)
            return nil
        }

        /// Steps `indices`, a strictly increasing set of positions below `count`, to the next
        /// such set in lexicographic order. False once there is none, so an empty set runs once.
        private static func advance(_ indices: inout [Int], below count: Int) -> Bool {
            var i = indices.count - 1
            while i >= 0 && indices[i] == count - indices.count + i { i -= 1 }
            guard i >= 0 else { return false }
            indices[i] += 1
            for j in (i + 1)..<indices.count { indices[j] = indices[j - 1] + 1 }
            return true
        }

        // MARK: - Rotation

        /// Generate a fresh backup key and replace `currentDepth`'s row.
        ///
        /// All existing shard distribution at that depth is invalidated (new
        /// distributionID). The caller must revoke old shards and call
        /// `distributeShards` to restore coverage. Any backup file sealed under the
        /// old key remains decryptable until overwritten — warn the user.
        func rotate(vaultKey: SymmetricKey, currentDepth: Int, modelContext: ModelContext) throws {
            var newBEKBytes = [UInt8](repeating: 0, count: 32)
            guard SecRandomCopyBytes(kSecRandomDefault, 32, &newBEKBytes) == errSecSuccess else {
                throw BackupError.encryptionFailed
            }
            defer { for i in newBEKBytes.indices { newBEKBytes[i] = 0 } }

            try self.persist(
                BackupEncryptionKey.Payload(
                    bekBytes:      Data(newBEKBytes),
                    distributionID: UUID(),
                    shardMetadata: nil
                ),
                vaultKey: vaultKey,
                currentDepth: currentDepth,
                modelContext: modelContext
            )
        }

        // MARK: - Shard status

        /// Update the status of one ShardRecord identified by `attributeID`, in
        /// whichever depth's own shard metadata actually contains it.
        ///
        /// Called from `updateShardStatus(attributeID:)` (`Vault+Manager+Shards.swift`,
        /// the per-entry version) as a fallback when no per-entry shard row matches.
        /// Backup-key and per-entry shards share the same attrID namespace; the
        /// caller need not know which kind a given attrID is.
        ///
        /// **Deliberately does not take a `currentDepth` parameter — found 2026-09-08
        /// that "whatever depth is current" is not a reliable way to find where an
        /// attrID lives, even in the ordinary, non-adversarial case.** A trustee's
        /// confirmation arrives whenever they respond, independent of which depth
        /// the owner happens to have active at that moment — distribute from depth
        /// 0, switch depths for an unrelated reason, and a depth-0 confirmation
        /// arriving while depth 2 is current would silently fail to apply if this
        /// only checked `currentDepth`'s own row. Scans every live row instead —
        /// only on this relatively rare, async confirmation path, not a hot path. A
        /// row that fails to open here is skipped, not fatal to the search — the
        /// attrID being sought may live in a different, perfectly healthy row; that
        /// should never actually happen for a row `liveRows` already vouched for as
        /// live, but the search stays lenient rather than fatal on one bad row.
        ///
        /// Still takes `vaultKey`, unlike the rest of this file's `currentDepth`
        /// omission pattern — the *depth* is what's unreliable to guess here, not
        /// the key; `vaultKey` itself is derived from biometric auth, not from a
        /// depth, so the caller always has exactly one to hand regardless of which
        /// row this ends up matching.
        func updateShardStatus(vaultKey: SymmetricKey, attributeID: UUID, to newStatus: ShardStatus, modelContext: ModelContext) throws {
            let (rows, _) = try self.liveRows(modelContext: modelContext)

            for row in rows {
                guard let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                      let plaintext = try? AES.GCM.open(box, using: vaultKey, authenticating: row.aad()),
                      let payload   = PayloadCodec.decode(plaintext)
                else { continue }
                guard var meta = payload.shardMetadata else { continue }
                guard let idx = meta.shards.firstIndex(where: { $0.attributeID == attributeID }) else { continue }

                // Reject illegal state machine transitions — prevents inbound
                // traffic from un-revoking a shard or moving confirmed back to
                // pending.
                guard ShardStatus.isValidTransition(from: meta.shards[idx].status, to: newStatus) else { return }

                meta.shards[idx].status = newStatus

                try self.seal(
                    BackupEncryptionKey.Payload(
                        bekBytes:      payload.bekBytes,
                        distributionID: payload.distributionID,
                        shardMetadata: meta
                    ),
                    vaultKey: vaultKey,
                    into: row
                )
                try modelContext.save()
                return
            }
        }

        // MARK: - Payload codec
        //
        // Fixed-width plaintext codec for `BackupEncryptionKey.Payload`. See
        // `VAULT_KEY_LAYERING.md` §8 item 3 for the design; this is item 3's wire
        // format, exactly.
        //
        // JSON's variable length leaks trustee count and shard status through
        // ciphertext size alone, before any key is ever involved — measured directly
        // against this app's own `JSONEncoder()` output in the design doc. Fixed byte
        // offsets close this structurally instead of by computed padding, the same
        // reasoning as `ExportMetaSlotCodec` (`VaultManager`, same concern applied to
        // that file's own format).
        //
        // Storage capacity (255) and write policy (10, enforced in `prepareShards`)
        // are different numbers, on purpose. 255 is the Shamir ceiling itself
        // (`ShamirSecretSharing`'s `UInt8` x-coordinates), not a guess, so a legacy
        // distribution created before any cap existed always fits.
        //
        // ```
        // byte 0–1        formatVersion   — UInt16, big-endian
        // byte 2–33       bekBytes        — 32 bytes, raw
        // byte 34–49      distributionID  — UUID's raw 16 bytes
        // byte 50         threshold       — UInt8; 0 means shardMetadata is nil
        //                                   (never distributed / just rotated) — a real
        //                                   threshold is always 2...255, so 0 is an
        //                                   unambiguous sentinel, not a heuristic
        // byte 51–10,760  shards          — 255 × 42-byte ShardRecord, in order
        // ```
        // Total: 10,761 bytes, always — whether 0 shards are in use or 255.
        //
        // Per-`ShardRecord`, 42 bytes:
        // ```
        // byte 0–15   contactIdentifier — raw UUID bytes, not the 36-char string
        // byte 16–31  attributeID       — raw UUID bytes
        // byte 32     status            — UInt8 tag; 0 = unused capacity slot, never a
        //                                 real `ShardStatus` (those are 1...5)
        // byte 33     distributedAt presence — 1 = set, 0 = absent
        // byte 34–41  distributedAt value    — UInt64 epoch seconds, big-endian,
        //                                      zero-filled when absent
        // ```
        // A slot with status 0 is filler (random bytes past the status tag) for a
        // capacity slot with no shard in it — matching `ExportMetaSlotCodec`'s house
        // style of random rather than structured filler, chosen for consistency with
        // the rest of Secure Mode.
        enum PayloadCodec {
            /// The version every `encode(_:)` call writes. Bumping this alone is not how
            /// you ship a new format — see the note on `decode(_:)` below.
            static let formatVersion:   UInt16 = 1
            static let shardCapacity:   Int    = 255
            static let shardRecordSize: Int    = 42
            /// Size of the version this codec currently *writes*. A future version is
            /// free to be a different size — `decode(_:)` reads the version tag before
            /// it ever assumes a length, precisely so that isn't a breaking change.
            static let payloadSize:     Int    = Self.payloadSizeV1

            private static let payloadSizeV1: Int = 2 + 32 + 16 + 1 + (shardRecordSize * shardCapacity)

            enum CodecError: Error, Equatable {
                /// More shards than the Shamir ceiling could ever produce. Refuses to
                /// silently truncate real trustee records — the one thing this codec
                /// must never do.
                case tooManyShards(count: Int)
                /// `ShardRecord.contactIdentifier` wasn't a valid UUID string.
                case invalidContactIdentifier(String)
            }

            /// Always writes `formatVersion` — dispatches on that constant the same way
            /// `decode(_:)` dispatches on whatever version tag it reads, so the two stay
            /// symmetric by construction rather than by remembering to update both.
            /// Encoding an old version on purpose is never needed: every write is either
            /// a fresh record or a migration re-seal, and both want the newest shape.
            static func encode(_ payload: BackupEncryptionKey.Payload) throws -> Data {
                switch Self.formatVersion {
                case 1:  return try Self.encodeV1(payload)
                default: preconditionFailure("formatVersion \(Self.formatVersion) has no encoder")
                }
            }

            /// Dispatches on the version tag *before* checking length, not after — a
            /// future version is free to have a different `payloadSizeV2` &c., and this
            /// ordering is what lets `decodeV1` keep reading existing on-disk data once
            /// `formatVersion` above has moved on to a newer one. This is the actual
            /// mechanism behind `VAULT_KEY_LAYERING.md`'s "bump `formatVersion`, read the
            /// old fixed shape, re-seal into the new one" migration pattern — bumping the
            /// constant alone does nothing without a decode path that still recognises
            /// the version it's replacing.
            ///
            /// **To add a version 2 later:** write `encodeV2`/`decodeV2` against whatever
            /// `payloadSizeV2` the new shape needs, add `case 2:` to both switches above
            /// and below, bump `formatVersion` to `2`, and leave `encodeV1`/`decodeV1`
            /// exactly as they are — `decodeV1` must keep reading existing version-1
            /// files for as long as any could still be on disk; `encodeV1` only stays
            /// referenced by `decodeV1`'s round-trip tests once `encode` no longer calls
            /// it, and is safe to delete once nothing does.
            ///
            /// `nil` for anything malformed — wrong length for its version, or a version
            /// tag nothing below recognises. Never partially decodes.
            static func decode(_ data: Data) -> BackupEncryptionKey.Payload? {
                guard data.count >= 2 else { return nil }
                let version = UInt16(data[data.startIndex]) << 8 | UInt16(data[data.startIndex + 1])

                switch version {
                case 1:  return Self.decodeV1(data)
                default: return nil
                }
            }

            private static func encodeV1(_ payload: BackupEncryptionKey.Payload) throws -> Data {
                let shards = payload.shardMetadata?.shards ?? []
                guard shards.count <= Self.shardCapacity else {
                    throw CodecError.tooManyShards(count: shards.count)
                }

                var out = Data(capacity: Self.payloadSizeV1)

                var version = UInt16(1).bigEndian
                withUnsafeBytes(of: &version) { out.append(contentsOf: $0) }

                out.append(payload.bekBytes)
                out.append(Self.uuidBytes(payload.distributionID))
                out.append(UInt8(clamping: payload.shardMetadata?.threshold ?? 0))

                for shard in shards {
                    out.append(try Self.encodeShard(shard))
                }
                for _ in shards.count..<Self.shardCapacity {
                    out.append(Self.emptyShardSlot())
                }

                return out
            }

            private static func decodeV1(_ data: Data) -> BackupEncryptionKey.Payload? {
                guard data.count == Self.payloadSizeV1 else { return nil }
                // `[UInt8](data)` always rebases to 0-based indices regardless of `data`'s
                // own indices (unlike `data.subdata(in:)`, which is relative to `data`'s
                // own index space and would misbehave on a non-zero-based slice). Slicing
                // `bytes` for every extraction below, rather than mixing it with `data`
                // directly, keeps this consistent throughout.
                var bytes = [UInt8](data)
                // This is the one raw copy of `bekBytes` (and the rest of the decrypted
                // payload) that exists purely as a working buffer — zeroed once extraction
                // is done, matching this file's own stated convention (top of file) and
                // the pattern every other backup-key-handling function here already follows.
                defer { for i in bytes.indices { bytes[i] = 0 } }

                let bekBytes = Data(bytes[2..<34])
                guard let distributionID = Self.uuid(fromBytes: Array(bytes[34..<50])) else { return nil }
                let threshold = Int(bytes[50])

                var shards: [ShardRecord] = []
                var offset = 51
                for _ in 0..<Self.shardCapacity {
                    let slot = Data(bytes[offset..<(offset + Self.shardRecordSize)])
                    if let shard = Self.decodeShard(slot) {
                        shards.append(shard)
                    }
                    offset += Self.shardRecordSize
                }

                let shardMetadata = threshold == 0
                    ? nil
                    : ShardDistributionMetadata(threshold: threshold, shards: shards)

                return BackupEncryptionKey.Payload(
                    bekBytes:       bekBytes,
                    distributionID: distributionID,
                    shardMetadata:  shardMetadata
                )
            }

            // MARK: Per-shard record

            private static let emptyStatusTag: UInt8 = 0

            /// Exhaustive `switch`, not a dictionary literal — a future `ShardStatus`
            /// case fails this at compile time instead of silently falling through.
            private static func tag(for status: ShardStatus) -> UInt8 {
                switch status {
                case .pending:       return 1
                case .confirmed:     return 2
                case .revokePending: return 3
                case .revoked:       return 4
                case .lost:          return 5
                }
            }

            private static func status(fromTag tag: UInt8) -> ShardStatus? {
                switch tag {
                case 1: return .pending
                case 2: return .confirmed
                case 3: return .revokePending
                case 4: return .revoked
                case 5: return .lost
                default: return nil
                }
            }

            private static func encodeShard(_ shard: ShardRecord) throws -> Data {
                guard let contactID = UUID(uuidString: shard.contactIdentifier) else {
                    throw CodecError.invalidContactIdentifier(shard.contactIdentifier)
                }

                var out = Data(capacity: Self.shardRecordSize)
                out.append(Self.uuidBytes(contactID))
                out.append(Self.uuidBytes(shard.attributeID))
                out.append(Self.tag(for: shard.status))

                if let distributedAt = shard.distributedAt {
                    out.append(1)
                    var ts = UInt64(max(0, distributedAt.timeIntervalSince1970)).bigEndian
                    withUnsafeBytes(of: &ts) { out.append(contentsOf: $0) }
                } else {
                    out.append(0)
                    out.append(Data(repeating: 0, count: 8))
                }

                return out
            }

            /// `nil` for a genuinely-unused capacity slot (status tag 0) or a malformed
            /// one — both mean "no shard here," the same "absent" convention
            /// `ExportMetaSlotCodec.decodeSlot` uses.
            private static func decodeShard(_ slot: Data) -> ShardRecord? {
                let bytes = [UInt8](slot)
                guard let status = Self.status(fromTag: bytes[32]) else { return nil }
                guard let contactID = Self.uuid(fromBytes: Array(bytes[0..<16])) else { return nil }
                guard let attributeID = Self.uuid(fromBytes: Array(bytes[16..<32])) else { return nil }

                let hasDistributedAt = bytes[33] == 1
                let ts = bytes[34..<42].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
                let distributedAt = hasDistributedAt ? Date(timeIntervalSince1970: TimeInterval(ts)) : nil

                return ShardRecord(
                    contactIdentifier: contactID.uuidString,
                    attributeID:       attributeID,
                    status:            status,
                    distributedAt:     distributedAt
                )
            }

            private static func emptyShardSlot() -> Data {
                var out = Data(capacity: Self.shardRecordSize)
                out.append(Data.randomBytes(32))   // contactIdentifier + attributeID region, filler
                out.append(Self.emptyStatusTag)
                out.append(Data.randomBytes(9))    // distributedAt presence + value region, filler
                return out
            }

            private static func uuidBytes(_ id: UUID) -> Data {
                withUnsafeBytes(of: id.uuid) { Data($0) }
            }

            private static func uuid(fromBytes bytes: [UInt8]) -> UUID? {
                guard bytes.count == 16 else { return nil }
                return UUID(uuid: (
                    bytes[0], bytes[1], bytes[2],  bytes[3],  bytes[4],  bytes[5],  bytes[6],  bytes[7],
                    bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
                ))
            }
        }

        // MARK: - Private

        struct Decoded {
            let payload: BackupEncryptionKey.Payload
            let bek:     SymmetricKey
        }

        /// Fetch and decrypt `currentDepth`'s row. Returns nil if nothing is set up at
        /// that depth (including "nothing has ever claimed a row for this depth yet").
        ///
        /// A live row whose payload fails to open or decode is a genuine anomaly, not
        /// a legitimate empty state — unlike the old array, a filler row here was
        /// never actually sealed, so it's already excluded by `liveRow`'s
        /// `isUnclaimed` check before this ever runs; a row that passes that check but
        /// still fails to open/decode means real corruption, so this throws rather
        /// than silently returning nil for that case.
        ///
        /// Internal, not private — `VaultManager`'s own `exportBackup`,
        /// `refreshBackupStaleness`, `restoreBackup`, and
        /// `migrateLegacyBEKStorageIfNeeded` all call this directly, since they need
        /// both `payload` and `bek`, more than the public
        /// `current(vaultKey:currentDepth:modelContext:)` accessor returns.
        func fetchDecoded(vaultKey: SymmetricKey, currentDepth: Int, modelContext: ModelContext) throws -> Decoded? {
            guard let (row, _) = try self.liveRow(forDepth: currentDepth, modelContext: modelContext) else {
                return nil
            }
            guard let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                  let plaintext = try? AES.GCM.open(box, using: vaultKey, authenticating: row.aad()),
                  let payload   = PayloadCodec.decode(plaintext)
            else {
                throw BackupError.decryptionFailed
            }
            return Decoded(payload: payload, bek: SymmetricKey(data: payload.bekBytes))
        }

        /// Writes `payload` into `currentDepth`'s row and saves. See `stage`.
        ///
        /// Internal, not private — same reason as `fetchDecoded` above.
        func persist(
            _ payload: BackupEncryptionKey.Payload, vaultKey: SymmetricKey, currentDepth: Int, modelContext: ModelContext
        ) throws {
            try self.stage(payload, vaultKey: vaultKey, currentDepth: currentDepth, modelContext: modelContext)
            try modelContext.save()
        }

        /// Writes `payload` into `currentDepth`'s row — the already-live row if one
        /// exists, otherwise a claimed filler row (or a freshly inserted one, past the
        /// 32-row baseline) — **without saving**, so a caller can commit it together with
        /// other changes, or roll it back (`VaultManager.restoreBackup`, `bugs.md` Bug 129).
        func stage(
            _ payload: BackupEncryptionKey.Payload, vaultKey: SymmetricKey, currentDepth: Int, modelContext: ModelContext
        ) throws {
            let row: BackupEncryptionKey
            if let (existing, _) = try self.liveRow(forDepth: currentDepth, modelContext: modelContext) {
                row = existing
            } else {
                let key = try self.localKey()
                row = try self.claimFillerRow(modelContext: modelContext, key: key)
                row.depth         = try? DepthCodec.encode(currentDepth).encrypt(using: key)
                row.deletionToken = try? BackupEncryptionKey.liveToken.encrypt(using: key)
                guard row.depth != nil, row.deletionToken != nil else { throw BackupError.encryptionFailed }
            }
            try self.seal(payload, vaultKey: vaultKey, into: row)
        }
    }
}

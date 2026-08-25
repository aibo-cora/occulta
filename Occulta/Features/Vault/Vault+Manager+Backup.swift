//
//  Vault+Manager+Backup.swift
//  Occulta
//
//  Vault backup — export, import, BEK lifecycle, and BEK shard operations.
//
//  All operations require the vault to be unlocked (currentKey() enforces this).
//  BEK bytes only exist in memory during an active operation and are zeroed via
//  defer where they appear as raw [UInt8] or Data buffers.
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
        /// No BackupEncryptionKey row exists — call setupBEK() first.
        case bekNotSetup
        /// BEK shard distribution is absent or below threshold.
        case belowThreshold
        /// File does not start with the "OCBK" magic prefix.
        case invalidFormat
        /// AES-GCM open failed — wrong BEK or corrupt/tampered file.
        case decryptionFailed
        /// AES-GCM seal or SecRandomCopyBytes failed.
        case encryptionFailed
        /// Shamir reconstruction or shard validation failed.
        case bekReconstructionFailed
        /// A BEK row already exists — this device is not a fresh restore target.
        case bekAlreadyPresent
        /// A restore is already pending, or already completed (a BEK exists). Not a
        /// failure — the caller shows a neutral, depth-safe acknowledgment rather than
        /// the generic error path. See Bug 93.
        case alreadyProcessed
    }

    // MARK: - Wire format constants

    private static let backupMagic:   Data = Data("OCBK".utf8)
    private static let backupFileAAD: Data = Data("occulta-backup-v1".utf8)

    // MARK: - Transient models

    /// In-memory encoding of the full vault, immediately sealed under the BEK.
    /// Never stored in SwiftData — plaintext fields are safe for the same reason
    /// SealedPayload carries a plaintext message field.
    struct VaultBackup: Codable {
        let version:   Int
        let createdAt: Date
        let entries:   [VaultBackupEntry]
    }

    /// One entry's plaintext within VaultBackup. Transient — see VaultBackup above.
    struct VaultBackupEntry: Codable {
        let id:        UUID
        let entryType: Int    // VaultEntryType.rawValue
        let createdAt: Date
        let label:     Data   // plaintext UTF-8 label string
        let content:   Data   // plaintext entry content
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
        /// BEK distributionID at export time. A mismatch means rotateBEK() was called.
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
        /// `rotateBEK()` was called since the last export. The existing file is
        /// permanently unrestorable — the old BEK no longer exists.
        let bekRotated:        Bool
        /// Number of vault entries created after the last export. Zero = none.
        let newEntryCount:     Int
        /// The trustee set size differs from what was in place at export time.
        let trusteeSetChanged: Bool

        var isStale: Bool { bekRotated || newEntryCount > 0 || trusteeSetChanged }
    }

    // MARK: - BEK setup

    /// Generate and persist a new BEK if one does not already exist. No-op if present.
    func setupBEK() throws {
        let vaultKey = try self.currentKey()
        let existing = try self.modelContext.fetch(FetchDescriptor<BackupEncryptionKey>())
        guard existing.isEmpty else { return }

        var bekBytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, 32, &bekBytes) == errSecSuccess else {
            throw BackupError.encryptionFailed
        }
        defer { for i in bekBytes.indices { bekBytes[i] = 0 } }

        try self.persistBEKPayload(
            BackupEncryptionKey.Payload(
                bekBytes:      Data(bekBytes),
                distributionID: UUID(),
                shardMetadata: nil
            ),
            vaultKey: vaultKey
        )
    }

    // MARK: - BEK access

    /// Return the current BEK as a SymmetricKey. Vault must be unlocked.
    func currentBEK() throws -> SymmetricKey {
        let vaultKey = try self.currentKey()
        guard let decoded = try self.fetchDecodedBEK(vaultKey: vaultKey) else {
            throw BackupError.bekNotSetup
        }
        return decoded.bek
    }

    // MARK: - BEK setup state (read by VaultTab)

    enum BEKSetupState: Equatable {
        case notSetup
        case waitingForConfirmations(confirmed: Int, threshold: Int)
        case ready
    }

    /// Current BEK distribution state. Returns `.notSetup` when locked or BEK absent.
    var bekSetupState: BEKSetupState {
        guard let meta = try? self.bekShardMetadata() else { return .notSetup }
        let confirmed = meta.shards.filter { $0.status == .confirmed }.count
        return confirmed >= meta.threshold
            ? .ready
            : .waitingForConfirmations(confirmed: confirmed, threshold: meta.threshold)
    }

    /// BEK shard distribution metadata, or `nil` if BEK has not been distributed yet.
    func bekShardMetadata() throws -> ShardDistributionMetadata? {
        let vaultKey = try self.currentKey()
        
        return try self.fetchDecodedBEK(vaultKey: vaultKey)?.payload.shardMetadata
    }

    // MARK: - Export

    /// Decrypt vault entries visible at `currentDepth` and seal them under the BEK as a
    /// `.occbak` file.
    ///
    /// Depth-scoped, not vault-wide — vault entries are exact-match partitioned, not
    /// nested (unlike contacts), so "what is visible here" is exactly "what depth ==
    /// currentDepth", and a file never needs to record which depth it came from. No
    /// default: a forgotten argument must be a compile error, not a silent leak of
    /// every layer into whichever depth happened to call this (Bug 88).
    ///
    /// Blocked if the BEK is not set up or BEK shard distribution is below threshold.
    /// The caller presents the returned bytes via UIDocumentPickerViewController.
    func exportBackup(currentDepth: Int) throws -> Data {
        let vaultKey = try self.currentKey()

        guard let decoded = try self.fetchDecodedBEK(vaultKey: vaultKey) else {
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

        let backup = VaultBackup(version: 1, createdAt: Date(), entries: backupEntries)
        let json   = try JSONEncoder().encode(backup)

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

    /// Vault entries whose decrypted `visibleThroughDepth` ceiling equals `depth`,
    /// exactly. Mirrors `Manager.Security.isEntryVisible(_:)`'s semantics without
    /// depending on `Manager.Security` — VaultManager has no dependency on Secure Mode
    /// internals, and `visibleThroughDepth` is sealed under the ordinary local DB key,
    /// not anything Secure-Mode-specific, so nothing here needs `isEntryVisible` doesn't
    /// already have available through `Data.decrypt()`.
    private func entriesVisible(atDepth depth: Int) throws -> [VaultEntry] {
        try self.fetchAllEntries().filter { entry in
            guard let sealed = entry.visibleThroughDepth,
                  let plain  = sealed.decrypt(),
                  let value  = DepthCodec.decode(plain)
            else { return false }  // unreadable ceiling — exclude, same as isEntryVisible
            return value == depth
        }
    }

    // MARK: - Import

    /// Open a `.occbak` file with the current BEK and restore all entries.
    ///
    /// Requires the BEK to be set up — call `reconstructBEK(shards:backupData:ownerIdentity:)`
    /// first on a new device. Inserts new VaultEntry rows preserving the original
    /// id and createdAt from the backup so entry history is maintained.
    func importBackup(_ data: Data) throws {
        let vaultKey = try self.currentKey()

        guard let decoded = try self.fetchDecodedBEK(vaultKey: vaultKey) else {
            throw BackupError.bekNotSetup
        }

        guard data.prefix(4) == Self.backupMagic else { throw BackupError.invalidFormat }

        let box  = try AES.GCM.SealedBox(combined: data.dropFirst(4))
        let json: Data
        do {
            json = try AES.GCM.open(box, using: decoded.bek, authenticating: Self.backupFileAAD)
        } catch {
            throw BackupError.decryptionFailed
        }

        let backup = try JSONDecoder().decode(VaultBackup.self, from: json)

        for backupEntry in backup.entries {
            // Skip entries that already exist — prevents double-insertion on interrupted
            // restore (e.g. app crash after some entries were saved but before file cleanup).
            if (try? self.fetchEntry(by: backupEntry.id)) != nil { continue }

            // UInt8(_: Int) traps outside 0...255 — VaultEntryType(rawValue:) is the safe
            // conversion, but only once the Int is known to fit. Anything that doesn't isn't
            // a future version's entry type, it's malformed.
            guard let entryTypeRaw = UInt8(exactly: backupEntry.entryType) else {
                throw BackupError.invalidFormat
            }
            let entryType   = VaultEntryType(rawValue: entryTypeRaw) ?? .note
            let labelString = String(data: backupEntry.label, encoding: .utf8) ?? ""

            // UInt64(_: Double) traps outside its representable range — negative (pre-1970)
            // or large enough to overflow. aad(for:) does this exact conversion and cannot be
            // changed to guard it (sealed contract, see its doc comment), so the check has to
            // happen here, before createdAt is ever assigned. A plain range check rather than
            // UInt64(exactly:) — the latter requires exact integer representability, which
            // would reject every legitimate sub-second timestamp along with the bad ones.
            let createdAtSeconds = backupEntry.createdAt.timeIntervalSince1970
            guard createdAtSeconds >= 0, createdAtSeconds < Double(UInt64.max) else {
                throw BackupError.invalidFormat
            }

            // Build the entry with the original id and createdAt so that AAD is
            // consistent with the original device and entry history is preserved.
            let entry = VaultEntry(encryptedLabel: Data(), encryptedContent: Data())
            entry.id        = backupEntry.id
            entry.createdAt = backupEntry.createdAt

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

        try self.modelContext.save()
    }

    // MARK: - BEK shard distribution

    /// Split the BEK into signed shards and persist the distribution metadata.
    ///
    /// Parallel to `prepareShards` for per-entry PEKs. Returns one SignedAttribute
    /// per recipient in the same order as `recipients`. The caller feeds these into
    /// `distributeBEKShards` or the .occ basket pipeline.
    func prepareBEKShards(threshold: Int, recipients: [Contact.Profile]) throws -> [SignedAttribute] {
        let vaultKey = try self.currentKey()

        guard let decoded = try self.fetchDecodedBEK(vaultKey: vaultKey) else {
            throw BackupError.bekNotSetup
        }

        let n              = recipients.count
        let distributionID = decoded.payload.distributionID

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
                contactIdentifier: recipients[i].identifier,
                attributeID:            attributes[i].id,
                status:            .pending,
                distributedAt:     now
            )
        }

        try self.persistBEKPayload(
            BackupEncryptionKey.Payload(
                bekBytes:      decoded.payload.bekBytes,
                distributionID: distributionID,
                shardMetadata: ShardDistributionMetadata(threshold: threshold, shards: shards)
            ),
            vaultKey: vaultKey
        )

        return attributes
    }

    /// Prepare BEK shards and encrypt each as a `.occ` bundle ready for sharing.
    ///
    /// Parallel to `distributeShards` for per-entry PEKs.
    /// Returns one `(contactIdentifier, occData)` tuple per recipient.
    func distributeBEKShards(
        threshold:      Int,
        recipients:     [Contact.Profile],
        contactManager: ContactManager
    ) throws -> [(contactIdentifier: String, occData: Data)] {
        let vaultKey = try self.currentKey()

        // Capture existing attrIDs before re-split: existing trustees get .replace,
        // new trustees get .distribute.
        let oldAttrIDs: [String: UUID]
        if let decoded = try? self.fetchDecodedBEK(vaultKey: vaultKey),
           let meta    = decoded.payload.shardMetadata {
            oldAttrIDs = Dictionary(uniqueKeysWithValues: meta.shards.map { ($0.contactIdentifier, $0.attributeID) })
        } else {
            oldAttrIDs = [:]
        }

        let attributes = try self.prepareBEKShards(threshold: threshold, recipients: recipients)

        return try zip(recipients, attributes).map { contact, attribute in
            let oldID = oldAttrIDs[contact.identifier]
            let op    = OccultaBundle.ShardOperation(
                kind:        oldID != nil ? .replace : .distribute,
                attribute:   attribute,
                attributeID: oldID
            )
            let occ = try contactManager.encryptBundle(for: contact.identifier, shardOperations: [op])
            return (contact.identifier, occ)
        }
    }

    // MARK: - BEK reconstruction

    /// Reconstruct the BEK from ≥ k shards, validate against the backup file,
    /// and re-wrap under the current vault key.
    ///
    /// Steps:
    ///   0. Refuse if a BEK row already exists — this device is not a fresh restore
    ///      target, and reconstruction only ever fires automatically (Bug 94).
    ///   1. Verify all shards share a single distributionID.
    ///   2. If `ownerIdentity` is provided, ECDSA-verify each shard.
    ///      Pass nil on new-device path (old key non-migratable); GCM tag substitutes.
    ///   3. Shamir.reconstruct → candidate BEK.
    ///   4. AES.GCM.open(backupFile, using: candidateBEK) — GCM tag validates.
    ///   5. Persist new BackupEncryptionKey row sealed under current vault key.
    ///      shardMetadata is cleared — redistribution prompt handles rebuild.
    ///
    /// On success, call `importBackup(_:)` to restore vault entries.
    func reconstructBEK(
        shards:        [SignedAttribute],
        backupData:    Data,
        ownerIdentity: Data?
    ) throws {
        let vaultKey = try self.currentKey()

        guard try self.fetchDecodedBEK(vaultKey: vaultKey) == nil else {
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

        let rawShares = shards.map { Array($0.value) }
        var bekData: Data
        do {
            bekData = try ShamirSecretSharing.reconstruct(shares: rawShares)
        } catch {
            throw BackupError.bekReconstructionFailed
        }
        defer { for i in bekData.indices { bekData[i] = 0 } }

        guard bekData.count == 32 else { throw BackupError.bekReconstructionFailed }
        let candidateBEK = SymmetricKey(data: bekData)

        // Validate: GCM authentication tag proves the reconstructed BEK is correct.
        guard backupData.prefix(4) == Self.backupMagic else { throw BackupError.invalidFormat }
        let box = try AES.GCM.SealedBox(combined: backupData.dropFirst(4))
        guard (try? AES.GCM.open(box, using: candidateBEK, authenticating: Self.backupFileAAD)) != nil else {
            throw BackupError.bekReconstructionFailed
        }

        try self.persistBEKPayload(
            BackupEncryptionKey.Payload(
                bekBytes:      bekData,
                distributionID: distributionID,
                shardMetadata: nil
            ),
            vaultKey: vaultKey
        )
    }

    // MARK: - BEK rotation

    /// Generate a fresh BEK and replace the existing BackupEncryptionKey row.
    ///
    /// All existing BEK shard distribution is invalidated (new distributionID).
    /// The caller must revoke old BEK shards and call distributeBEKShards to
    /// restore coverage. Any backup file sealed under the old BEK remains
    /// decryptable until overwritten — warn the user.
    func rotateBEK() throws {
        let vaultKey = try self.currentKey()

        var newBEKBytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, 32, &newBEKBytes) == errSecSuccess else {
            throw BackupError.encryptionFailed
        }
        defer { for i in newBEKBytes.indices { newBEKBytes[i] = 0 } }

        try self.persistBEKPayload(
            BackupEncryptionKey.Payload(
                bekBytes:      Data(newBEKBytes),
                distributionID: UUID(),
                shardMetadata: nil
            ),
            vaultKey: vaultKey
        )
    }

    // MARK: - BEK shard status

    /// Update the status of one BEK ShardRecord identified by `attributeID`.
    ///
    /// Called from `updateShardStatus(attributeID:)` as a fallback when no
    /// per-entry shard row matches. BEK and per-entry shards share the same
    /// attrID namespace; the caller need not know which kind a given attrID is.
    func updateBEKShardStatus(attributeID: UUID, to newStatus: ShardStatus) throws {
        let vaultKey = try self.currentKey()
        guard let decoded = try self.fetchDecodedBEK(vaultKey: vaultKey) else { return }
        guard var meta = decoded.payload.shardMetadata else { return }
        guard let idx  = meta.shards.firstIndex(where: { $0.attributeID == attributeID }) else { return }

        // Reject illegal state machine transitions — prevents inbound traffic from
        // un-revoking a BEK shard or moving confirmed back to pending.
        guard ShardStatus.isValidTransition(from: meta.shards[idx].status, to: newStatus) else { return }

        meta.shards[idx].status = newStatus

        try self.persistBEKPayload(
            BackupEncryptionKey.Payload(
                bekBytes:      decoded.payload.bekBytes,
                distributionID: decoded.payload.distributionID,
                shardMetadata: meta
            ),
            vaultKey: vaultKey
        )
    }

    // MARK: - Pending restore

    private static let pendingRestoreURL: URL =
        FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("pending-restore.occbak")

    private static let pendingRestoreShardsURL: URL =
        FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("pending-restore-shards.dat")

    private static let pendingRestoreShardsAAD: Data =
        Data("occulta.pending-bek-restore-shards".utf8)

    /// Whether a restore file genuinely exists on disk — independent of depth, and
    /// independent of the published `pendingRestoreActive`, which is deliberately
    /// depth-gated for display (Bug 93). **Functional callers deciding whether to store
    /// a shard, or whether to relax signature checking, must use this, never the
    /// published property** — depth-gating `pendingRestoreActive` above depth 0 would
    /// otherwise make a genuine, in-progress recovery silently stop accepting shards, or
    /// reject a legitimate new-device handback outright instead of deferring it.
    var isRestorePending: Bool {
        FileManager.default.fileExists(atPath: Self.pendingRestoreURL.path)
    }

    /// Sync `pendingRestoreActive` and `pendingRestoreShardCount` from the filesystem.
    /// Called on every vault unlock so state is correct after app restarts.
    ///
    /// Above depth 0 the published state is forced to inactive regardless of what is
    /// actually on disk — not "hidden if something's pending," genuinely false, so a
    /// coercer watching across multiple unlocks sees the same nothing every time. See
    /// Bug 93 — this is one half of "defer and hide together"; `attemptBEKRestore`'s own
    /// depth guard is the other.
    func refreshPendingRestoreState(currentDepth: Int) {
        guard currentDepth == 0 else {
            self.pendingRestoreActive     = false
            self.pendingRestoreShardCount = 0
            return
        }
        self.pendingRestoreActive = FileManager.default.fileExists(atPath: Self.pendingRestoreURL.path)
        self.pendingRestoreShardCount = self.pendingRestoreActive
            ? ((try? self.loadRestoreShards())?.count ?? 0)
            : 0
    }

    /// Validate and persist an incoming `.occbak` file. Called when the user opens a
    /// `.occbak` file from Files.
    ///
    /// Checks whether *any* restore state already exists — a pending file already on
    /// disk, or a BEK already present (remedy 1's own check, reused rather than
    /// duplicated) — before deciding what the caller sees. Deliberately not "is this the
    /// same file": a different `.occbak` shown while one is already pending or done gets
    /// the same honest `alreadyProcessed`, so the signal is never a lie and needs no new
    /// persisted history to stay truthful. See Bug 93, "The design, settled".
    ///
    /// If a BEK already exists there is nothing to arm — refuses before writing anything.
    /// Otherwise the file is always written (so a later depth-0 unlock can still act on
    /// it), and `pendingRestoreActive`/`pendingRestoreShardCount` are only ever set at
    /// depth 0 — above that, published state stays whatever `refreshPendingRestoreState`
    /// already forced it to.
    func storePendingRestore(_ data: Data, currentDepth: Int) throws {
        guard data.prefix(4) == Self.backupMagic else { throw BackupError.invalidFormat }

        let vaultKey       = try? self.currentKey()
        let alreadyHasBEK  = vaultKey.flatMap { try? self.fetchDecodedBEK(vaultKey: $0) } != nil
        guard !alreadyHasBEK else { throw BackupError.alreadyProcessed }

        let alreadyPending = FileManager.default.fileExists(atPath: Self.pendingRestoreURL.path)
        try data.write(to: Self.pendingRestoreURL, options: [.atomic, .completeFileProtection])

        if currentDepth == 0 {
            self.pendingRestoreActive     = true
            self.pendingRestoreShardCount = (try? self.loadRestoreShards())?.count ?? 0
        }

        if alreadyPending { throw BackupError.alreadyProcessed }
    }

    /// Append one incoming BEK shard to the restore-shard file. Deduplicates by id.
    /// Safe to call while the vault is locked — uses the recovery buffer key.
    func storeRestoreShard(_ attribute: SignedAttribute) throws {
        guard let bufferKey = try self.keyManager.deriveRecoveryBufferKey() else {
            throw VaultError.keyDerivationFailed
        }
        var shards = (try? self.loadRestoreShards()) ?? []
        guard !shards.contains(where: { $0.id == attribute.id }) else { return }
        shards.append(attribute)

        let plain  = try JSONEncoder().encode(shards)
        let sealed = try AES.GCM.seal(
            plain, using: bufferKey,
            nonce: AES.GCM.Nonce(),
            authenticating: Self.pendingRestoreShardsAAD
        )
        guard let combined = sealed.combined else { throw VaultError.encryptionFailed }
        try combined.write(to: Self.pendingRestoreShardsURL, options: [.atomic, .completeFileProtection])
        self.pendingRestoreShardCount = shards.count
    }

    /// Attempt BEK reconstruction from all collected restore shards.
    ///
    /// Groups shards by `entryID` and tries `reconstructBEK` on each group.
    /// `AES.GCM` authentication inside `reconstructBEK` is the oracle — the
    /// correct group decrypts successfully; all others throw. Runs silently
    /// when not enough shards are present. Requires vault to be unlocked.
    ///
    /// Checks for an existing BEK before touching the shard file at all (Bug 94 remedy 1
    /// would refuse every group anyway, at the `reconstructBEK` level) — because that
    /// per-group refusal has no path back to the cleanup below. A device that already has
    /// a BEK can never reach the success branch, so without this check `pendingRestoreActive`
    /// would stay stuck true forever, and the shard file would keep accepting new entries on
    /// every arrival with nothing left to ever clear it (Bug 96).
    ///
    /// Never completes above depth 0 (Bug 93) — the other half of "defer and hide
    /// together" alongside `refreshPendingRestoreState`'s own depth guard. Shards keep
    /// accumulating silently regardless (`storeRestoreShard` doesn't check depth), so
    /// nothing is lost, only postponed to the next depth-0 unlock.
    func attemptBEKRestore(currentDepth: Int) {
        guard self.isUnlocked, self.pendingRestoreActive else { return }
        guard currentDepth == 0 else { return }

        if let vaultKey = try? self.currentKey(),
           (try? self.fetchDecodedBEK(vaultKey: vaultKey)) != nil {
            try? FileManager.default.removeItem(at: Self.pendingRestoreShardsURL)
            try? FileManager.default.removeItem(at: Self.pendingRestoreURL)
            self.pendingRestoreActive     = false
            self.pendingRestoreShardCount = 0
            return
        }

        guard let backupData = try? Data(contentsOf: Self.pendingRestoreURL) else { return }
        guard let shards     = try? self.loadRestoreShards(), !shards.isEmpty else { return }

        // Update counter as a side effect (covers the on-unlock path).
        self.pendingRestoreShardCount = shards.count

        var groups: [UUID: [SignedAttribute]] = [:]
        for shard in shards {
            guard let eid = shard.entryID else { continue }
            groups[eid, default: []].append(shard)
        }

        for (_, group) in groups {
            do {
                // reconstructBEK: Shamir combine → GCM oracle → persist BEK row.
                try self.reconstructBEK(shards: group, backupData: backupData, ownerIdentity: nil)
                // importBackup: read persisted BEK row → decrypt file → insert entries.
                try self.importBackup(backupData)
            } catch {
                continue    // Wrong group or not enough shards — try next.
            }

            // Success — clean up both restore files and reset state.
            try? FileManager.default.removeItem(at: Self.pendingRestoreShardsURL)
            try? FileManager.default.removeItem(at: Self.pendingRestoreURL)
            self.pendingRestoreActive     = false
            self.pendingRestoreShardCount = 0
            // Signal the vault list to show post-restore guidance on next unlock.
            UserDefaults.standard.set(true, forKey: "vault.postRestoreActionNeeded")
            return
        }
    }

    /// Decrypt the restore-shard file. Returns empty array when the file is absent.
    private func loadRestoreShards() throws -> [SignedAttribute] {
        guard FileManager.default.fileExists(atPath: Self.pendingRestoreShardsURL.path) else {
            return []
        }
        guard let bufferKey = try self.keyManager.deriveRecoveryBufferKey() else {
            throw VaultError.keyDerivationFailed
        }
        let combined = try Data(contentsOf: Self.pendingRestoreShardsURL)
        let box      = try AES.GCM.SealedBox(combined: combined)
        let plain    = try AES.GCM.open(box, using: bufferKey, authenticating: Self.pendingRestoreShardsAAD)
        return try JSONDecoder().decode([SignedAttribute].self, from: plain)
    }

    // MARK: - Export metadata slot codec

    /// Fixed-width plaintext codec for one `BackupExportMetadata` slot, and the
    /// 32-slot layout that holds one per depth.
    ///
    /// One slot per depth so a slot's presence or absence never varies the file's
    /// total length — the same reasoning as `DepthCodec`, applied to this file's own
    /// format rather than to `Contact.Profile`'s depth fields. `slotCount` reuses
    /// `AppLayerConfig.maxVerifierCount` deliberately, not as a borrowed number: that
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
        static let slotCount:     Int = AppLayerConfig.maxVerifierCount
        static let slotPlainSize: Int = 28

        private static let presenceTag: UInt8 = 0xA5

        /// `nil` encodes to random filler — total, matches `DepthCodec.encode`'s own
        /// "must not trap" requirement. `shardCount`/`entryCount` saturate via
        /// `clamping:` rather than a plain cast, which would trap outside range —
        /// exactly the class of bug fixed twice in `importBackup` (Bug 96).
        static func encodeSlot(_ meta: BackupExportMetadata?) -> Data {
            guard let meta else { return Self.randomFiller() }

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

        private static func randomFiller() -> Data {
            var bytes = [UInt8](repeating: 0, count: Self.slotPlainSize)
            _ = SecRandomCopyBytes(kSecRandomDefault, Self.slotPlainSize, &bytes)
            return Data(bytes)
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

        let decoded = try? self.fetchDecodedBEK(vaultKey: vaultKey)

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
        try combined.write(to: Self.backupExportMetaURL, options: [.atomic, .completeFileProtection])
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

    // MARK: - Private helpers

    private struct DecodedBEK {
        let row:     BackupEncryptionKey
        let payload: BackupEncryptionKey.Payload
        let bek:     SymmetricKey
    }

    /// Fetch and decrypt the BackupEncryptionKey row. Returns nil if no row exists.
    private func fetchDecodedBEK(vaultKey: SymmetricKey) throws -> DecodedBEK? {
        guard let row = try self.modelContext.fetch(FetchDescriptor<BackupEncryptionKey>()).first else {
            return nil
        }
        let box       = try AES.GCM.SealedBox(combined: row.encryptedPayload)
        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(box, using: vaultKey, authenticating: row.aad())
        } catch {
            throw VaultError.decryptionFailed
        }
        let payload = try JSONDecoder().decode(BackupEncryptionKey.Payload.self, from: plaintext)
        return DecodedBEK(row: row, payload: payload, bek: SymmetricKey(data: payload.bekBytes))
    }

    /// Delete-and-replace the BackupEncryptionKey row with a freshly sealed payload.
    /// Every write generates a new row id, keeping the AAD contract simple.
    private func persistBEKPayload(_ payload: BackupEncryptionKey.Payload, vaultKey: SymmetricKey) throws {
        let payloadData = try JSONEncoder().encode(payload)
        let rowID       = UUID()
        let aad         = rowID.uuidString.data(using: .utf8)!
        let sealed      = try AES.GCM.seal(payloadData, using: vaultKey, nonce: AES.GCM.Nonce(), authenticating: aad)
        guard let combined = sealed.combined else { throw BackupError.encryptionFailed }

        let existing = try self.modelContext.fetch(FetchDescriptor<BackupEncryptionKey>())
        for row in existing { self.modelContext.delete(row) }

        self.modelContext.insert(BackupEncryptionKey(id: rowID, encryptedPayload: combined))
        try self.modelContext.save()
    }
}

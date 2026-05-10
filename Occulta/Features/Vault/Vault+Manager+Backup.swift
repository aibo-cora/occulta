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

    // MARK: - Backup export metadata (staleness tracking)

    /// Snapshot sealed under the vault key and written alongside each export.
    /// Used to determine whether the vault state has drifted since the last backup.
    /// Never stored in plaintext — always AES-GCM sealed with backupExportMetaAAD.
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

    /// Decrypt all vault entries and seal them under the BEK as a `.occbak` file.
    ///
    /// Blocked if the BEK is not set up or BEK shard distribution is below threshold.
    /// The caller presents the returned bytes via UIDocumentPickerViewController.
    func exportBackup() throws -> Data {
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

        let entries = try self.fetchAllEntries()
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

        // Seal a snapshot of the vault state at export time. Used by
        // refreshBackupStaleness() to detect drift on subsequent unlocks.
        let exportMeta = BackupExportMetadata(
            exportedAt:     Date(),
            distributionID: decoded.payload.distributionID,
            shardCount:     decoded.payload.shardMetadata?.shards.count ?? 0,
            entryCount:     entries.count
        )
        try self.writeBackupExportMetadata(exportMeta, vaultKey: vaultKey)
        self.refreshBackupStaleness()

        return result
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

            let entryType   = VaultEntryType(rawValue: UInt8(backupEntry.entryType)) ?? .note
            let labelString = String(data: backupEntry.label, encoding: .utf8) ?? ""

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
        self.recomputeRecoveryHealth()
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

        self.recomputeRecoveryHealth()
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

    /// Sync `pendingRestoreActive` and `pendingRestoreShardCount` from the filesystem.
    /// Called on every vault unlock so state is correct after app restarts.
    func refreshPendingRestoreState() {
        self.pendingRestoreActive = FileManager.default.fileExists(atPath: Self.pendingRestoreURL.path)
        self.pendingRestoreShardCount = self.pendingRestoreActive
            ? ((try? self.loadRestoreShards())?.count ?? 0)
            : 0
    }

    /// Validate and persist an incoming `.occbak` file. Marks restore as active.
    /// Called when the user opens a `.occbak` file from Files.
    func storePendingRestore(_ data: Data) throws {
        guard data.prefix(4) == Self.backupMagic else { throw BackupError.invalidFormat }
        try data.write(to: Self.pendingRestoreURL, options: [.atomic, .completeFileProtection])
        self.pendingRestoreActive     = true
        self.pendingRestoreShardCount = (try? self.loadRestoreShards())?.count ?? 0
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
    func attemptBEKRestore() {
        guard self.isUnlocked, self.pendingRestoreActive else { return }
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

    // MARK: - Export metadata helpers

    private static let backupExportMetaURL: URL =
        FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("backup-export-meta.dat")

    private static let backupExportMetaAAD: Data =
        Data("occulta.backup-export-meta-v1".utf8)

    /// Recompute `backupStaleness` by comparing the sealed export snapshot against
    /// current vault state. Called on every unlock and after each successful export.
    /// Sets `backupStaleness` to `nil` when no export has been done on this device.
    func refreshBackupStaleness() {
        guard let vaultKey = try? self.currentKey() else {
            self.backupStaleness = nil
            return
        }
        guard let meta = try? self.loadBackupExportMetadata(vaultKey: vaultKey) else {
            self.backupStaleness = nil
            return
        }

        let decoded = try? self.fetchDecodedBEK(vaultKey: vaultKey)

        let bekRotated        = decoded.map { $0.payload.distributionID != meta.distributionID } ?? false
        let currentEntryCount = (try? self.modelContext.fetchCount(FetchDescriptor<VaultEntry>())) ?? 0
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

    private func writeBackupExportMetadata(_ meta: BackupExportMetadata, vaultKey: SymmetricKey) throws {
        let plain  = try JSONEncoder().encode(meta)
        let sealed = try AES.GCM.seal(
            plain, using: vaultKey,
            nonce: AES.GCM.Nonce(),
            authenticating: Self.backupExportMetaAAD
        )
        guard let combined = sealed.combined else { throw BackupError.encryptionFailed }
        try combined.write(to: Self.backupExportMetaURL, options: [.atomic, .completeFileProtection])
    }

    private func loadBackupExportMetadata(vaultKey: SymmetricKey) throws -> BackupExportMetadata {
        let combined = try Data(contentsOf: Self.backupExportMetaURL)
        let box      = try AES.GCM.SealedBox(combined: combined)
        let plain    = try AES.GCM.open(box, using: vaultKey, authenticating: Self.backupExportMetaAAD)
        return try JSONDecoder().decode(BackupExportMetadata.self, from: plain)
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

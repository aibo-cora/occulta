//
//  Vault+Manager+ReturnBuffer.swift
//  Occulta
//
//  Owner-side reconstruction buffer.
//  Absorbs `.respond` shards into encrypted ReconstructShard rows, finalises
//  reconstruction once a per-entry threshold is reached.
//
//  All buffer rows are sealed under the recovery buffer key (device-unlock
//  level, no biometric) so `.respond` bundles can be absorbed even while the
//  vault is locked. Finalisation itself requires the vault unlocked because
//  it re-wraps the recovered PEK under the vault key.
//

import Foundation
import SwiftData
import CryptoKit

extension VaultManager {

    // MARK: - Public surface

    /// Absorb one returned shard into the reconstruction buffer.
    ///
    /// `attestation`/`senderIdentifier` come from `handleHandback`'s own Branch A/B
    /// check (Bug 94 remedy 2) — verification already happened there; this function
    /// no longer re-checks the signature itself. `senderIdentifier` must be the
    /// *receiver's own* resolution of who sent this, never sender-asserted — see
    /// `AttestedShard`'s doc comment.
    ///
    /// Steps:
    ///   1. Per-entry buffer: only for entries this device actually split
    ///      (`VaultEntry.shardDistributionEncrypted != nil`) — excludes BEK shards
    ///      by construction, since no `VaultEntry.id` is ever a `distributionID`,
    ///      and refuses shards for an `entryID` with no outstanding distribution at
    ///      all. At most one buffered row per `(entryID, senderIdentifier)`: a
    ///      second share from the same sender replaces the first rather than
    ///      accumulating, so a threshold-reaching group structurally requires
    ///      distinct senders, not just distinct `SignedAttribute.id`s.
    ///   2. Opportunistically call `tryFinalizeReconstruction(entryID:)` —
    ///      if the vault is locked, the call returns without touching state
    ///      and finalisation is retried on the next vault unlock.
    ///   3. BEK restore — same one-per-sender rule, applied in `storeRestoreShard`.
    func acceptReturnedShard(
        _ attribute: SignedAttribute,
        attestation: SignedAttribute?,
        senderIdentifier: String,
        currentDepth: Int
    ) throws {
        guard attribute.category == .shard, let entryID = attribute.entryID else {
            throw VaultError.decryptionFailed
        }

        // ── 1. Per-entry buffer ───────────────────────────────────────────
        if let entry = try? self.fetchEntry(by: entryID), entry.shardDistributionEncrypted != nil {
            guard let key = try self.keyManager.deriveRecoveryBufferKey() else {
                throw VaultError.keyDerivationFailed
            }
            let existing = try self.decryptAllReconstructShards(usingKey: key)
            if let dup = existing.first(where: {
                $0.payload.entryID == entryID && $0.payload.senderIdentifier == senderIdentifier
            }) {
                if dup.payload.attrID == attribute.id { return } // identical re-delivery
                self.modelContext.delete(dup.row)                // sender is replacing their prior share
            }

            try self.insertReconstructRow(
                entryID:          entryID,
                attribute:        attribute,
                attestation:      attestation,
                senderIdentifier: senderIdentifier,
                usingKey:         key
            )

            // ── 2. Opportunistic finalise ──────────────────────────────────
            try? self.tryFinalizeReconstruction(entryID: entryID)
        }

        // ── 3. BEK restore — store shard + attempt reconstruction ────────
        // Only active when a .occbak file is awaiting recovery. storeRestoreShard
        // is safe while locked (recovery buffer key); attemptBEKRestore no-ops if locked.
        //
        // isRestorePending, not pendingRestoreActive — the shard must still be stored
        // above depth 0, or a genuine recovery silently stops accumulating shards the
        // moment the user is at a duress depth (Bug 93). Kept as the BEK-specific gate
        // deliberately (Bug 94 remedy 2) — a fresh device can't know the expected
        // distributionID any more precisely than this before reconstruction succeeds.
        if self.isRestorePending {
            try? self.storeRestoreShard(attribute, attestation: attestation, senderIdentifier: senderIdentifier)
            self.attemptBEKRestore(currentDepth: currentDepth)
        }
    }

    /// Attempt to finalise reconstruction for one entry: collect buffered shards,
    /// run `reconstructEntry`, and clear the buffer rows on success.
    ///
    /// No-op when:
    ///   - the vault is locked (vault key needed to read distribution metadata
    ///     and to re-wrap the recovered PEK),
    ///   - the entry has no distribution metadata (was never split),
    ///   - fewer than `threshold` shards are buffered,
    ///   - reconstruction throws (e.g. wrong shards, tampered bytes — GCM tag
    ///     rejects the candidate PEK in `reconstructEntry`).
    ///
    /// On success, all buffer rows whose payload references this `entryID`
    /// are deleted in one save.
    func tryFinalizeReconstruction(entryID: UUID) throws {
        guard self.isUnlocked else { return }

        let vaultKey    = try self.currentKey()
        guard let entry = try self.fetchEntry(by: entryID) else { return }
        guard let metaCipher = entry.shardDistributionEncrypted else { return }

        let metaBox       = try AES.GCM.SealedBox(combined: metaCipher)
        let metaPlaintext = try AES.GCM.open(metaBox, using: vaultKey, authenticating: entry.aad(for: .shardDistribution))
        let meta          = try JSONDecoder().decode(ShardDistributionMetadata.self, from: metaPlaintext)

        let buffered = try self.decryptAllReconstructShards()
        let mine     = buffered.filter { $0.payload.entryID == entryID }
        guard mine.count >= meta.threshold else { return }

        let attributes = mine.map { $0.payload.signedAttribute }
        let identity   = try? self.keyManager.retrieveIdentity()

        // reconstructEntry handles GCM authentication — wrong shards fail there.
        try self.reconstructEntry(
            entryID:       entryID,
            shards:        attributes,
            ownerIdentity: identity
        )

        for row in mine {
            self.modelContext.delete(row.row)
        }
        try self.modelContext.save()
    }

    /// Sweep all entries with distribution metadata on vault unlock; finalise
    /// any that reached threshold while the vault was locked.
    func tryFinalizeAllReconstructions() {
        guard self.isUnlocked else { return }
        let entries = (try? self.fetchAllEntries()) ?? []
        for entry in entries where entry.shardDistributionEncrypted != nil {
            try? self.tryFinalizeReconstruction(entryID: entry.id)
        }
    }

    /// User cancels recovery for one entry — drop all buffered shards for it.
    /// Cheap because the buffer is small; rows that don't decrypt are skipped.
    func cancelReconstruction(entryID: UUID) throws {
        let buffered = try self.decryptAllReconstructShards()
        for entry in buffered where entry.payload.entryID == entryID {
            self.modelContext.delete(entry.row)
        }
        try self.modelContext.save()
    }

    // MARK: - Private

    /// Seal one buffered shard and insert it as a `ReconstructShard` row.
    ///
    /// Shared by both buffers — the per-entry one above and the BEK restore one below. They
    /// differ only in what selects the rows back out again, never in how a row is written.
    private func insertReconstructRow(
        entryID:          UUID,
        attribute:        SignedAttribute,
        attestation:      SignedAttribute?,
        senderIdentifier: String
    ) throws {
        guard let bufferKey = try self.keyManager.deriveRecoveryBufferKey() else {
            throw VaultError.keyDerivationFailed
        }
        try self.insertReconstructRow(
            entryID: entryID, attribute: attribute,
            attestation: attestation, senderIdentifier: senderIdentifier,
            usingKey: bufferKey
        )
    }

    /// Same as `insertReconstructRow(entryID:attribute:attestation:senderIdentifier:)` but
    /// decrypts with an already-derived key instead of deriving one fresh — for callers that
    /// already hold the recovery buffer key and would otherwise pay a redundant Secure Enclave
    /// round trip (see `storeRestoreShard`, which calls this alongside two other buffer
    /// operations that all need the identical key).
    private func insertReconstructRow(
        entryID:          UUID,
        attribute:        SignedAttribute,
        attestation:      SignedAttribute?,
        senderIdentifier: String,
        usingKey bufferKey: SymmetricKey
    ) throws {
        let rowID   = UUID()
        let aad     = Self.reconstructRowAAD(id: rowID)
        let payload = ReconstructShard.Payload(
            entryID:          entryID,
            attrID:           attribute.id,
            signedAttribute:  attribute,
            senderIdentifier: senderIdentifier,
            attestation:      attestation
        )
        let plaintext = try JSONEncoder().encode(payload)
        let sealed    = try AES.GCM.seal(plaintext, using: bufferKey, nonce: AES.GCM.Nonce(), authenticating: aad)
        guard let combined = sealed.combined else { throw VaultError.encryptionFailed }

        self.modelContext.insert(ReconstructShard(id: rowID, encryptedPayload: combined))
        try self.modelContext.save()
    }

    // MARK: - BEK restore shards

    /// BEK restore shards are `ReconstructShard` rows too, not a file of their own (Bug 100).
    ///
    /// The file they used to live in leaked through its length: AES-GCM preserves it, elements
    /// are near-constant size, so `ls -l` divided out to the number of recovery pieces
    /// collected — the same number deliberately removed from the vault tab for being a live
    /// report on real depth-0 activity. Padding it to fixed-width slots was the obvious fix and
    /// the wrong one; the file did not need to exist.
    ///
    /// `ReconstructShard`'s own doc justifies its separation from `CustodyShard` on three
    /// grounds — different key, different lifecycle, different payload. None of the three
    /// separates BEK restore shards from it. They seal under the same recovery buffer key,
    /// which is the criterion that doc leads with; they are the same kind of transient buffer,
    /// cleared when their recovery completes; and `Payload` already carries every field they
    /// need.
    ///
    /// A row belongs to this path when its `entryID` resolves to no `VaultEntry`, because BEK
    /// shards carry the `distributionID` and no `VaultEntry.id` is ever one. That is not a new
    /// invariant — `acceptReturnedShard`'s per-entry step already relies on it in the opposite
    /// direction to exclude these very shards.
    private func bekRestoreRows() throws -> [DecodedReconstructRow] {
        guard let key = try self.keyManager.deriveRecoveryBufferKey() else {
            throw VaultError.keyDerivationFailed
        }
        return try self.bekRestoreRows(usingKey: key)
    }

    /// Same as `bekRestoreRows()` but decrypts with an already-derived key — see
    /// `insertReconstructRow(...usingKey:)`'s doc comment for why this exists.
    private func bekRestoreRows(usingKey key: SymmetricKey) throws -> [DecodedReconstructRow] {
        try self.decryptAllReconstructShards(usingKey: key).filter { row in
            ((try? self.fetchEntry(by: row.payload.entryID)) ?? nil) == nil
        }
    }

    /// Append one incoming BEK shard to the restore buffer.
    ///
    /// At most one stored shard per `(entryID, senderIdentifier)` (Bug 94 remedy 2) — a second
    /// share from the same sender replaces the first rather than accumulating, so
    /// `attemptBEKRestore`'s grouping reflects distinct senders, not just distinct
    /// `SignedAttribute.id`s. Safe to call while the vault is locked: the recovery buffer key
    /// is derived from the Secure Enclave, not from the vault key.
    ///
    /// The floor this produces is **two** senders, not `threshold` — see `AttestedShard` for
    /// why a device with no BEK cannot know the owner's `threshold`, and why the restore
    /// confirmation rather than this count is what gates an unsolicited restore.
    func storeRestoreShard(_ attribute: SignedAttribute, attestation: SignedAttribute?, senderIdentifier: String) throws {
        guard let entryID = attribute.entryID else { throw VaultError.decryptionFailed }
        try? self.migrateLegacyRestoreShardFile()

        // Derived once and reused below — decryptAllReconstructShards, insertReconstructRow,
        // and bekRestoreRows all need this same recovery buffer key; deriving it three times
        // here was three redundant Secure Enclave round trips for one shard delivery.
        guard let key = try self.keyManager.deriveRecoveryBufferKey() else {
            throw VaultError.keyDerivationFailed
        }

        let existing = try self.decryptAllReconstructShards(usingKey: key)
        if let dup = existing.first(where: {
            $0.payload.entryID == entryID && $0.payload.senderIdentifier == senderIdentifier
        }) {
            if dup.payload.attrID == attribute.id { return }  // identical re-delivery
            self.modelContext.delete(dup.row)                 // sender is replacing their prior share
        }

        try self.insertReconstructRow(
            entryID:          entryID,
            attribute:        attribute,
            attestation:      attestation,
            senderIdentifier: senderIdentifier,
            usingKey:         key
        )
        self.pendingRestoreShardCount = (try? self.bekRestoreRows(usingKey: key).count) ?? 0
    }

    /// Every BEK restore shard collected so far. Empty when none have arrived.
    func loadRestoreShards() throws -> [AttestedShard] {
        guard let key = try self.keyManager.deriveRecoveryBufferKey() else {
            throw VaultError.keyDerivationFailed
        }
        return try self.loadRestoreShards(usingKey: key)
    }

    /// Same as `loadRestoreShards()` but decrypts with an already-derived key — for
    /// `attemptBEKRestore` (`Vault+Manager+Backup.swift`), which also calls
    /// `clearBEKRestoreShards(usingKey:)` on success and would otherwise re-derive the
    /// identical key for that second call. Not `private`: it's called from that other file.
    func loadRestoreShards(usingKey key: SymmetricKey) throws -> [AttestedShard] {
        try? self.migrateLegacyRestoreShardFile()
        return try self.bekRestoreRows(usingKey: key).map {
            AttestedShard(
                attribute:        $0.payload.signedAttribute,
                attestation:      $0.payload.attestation,
                senderIdentifier: $0.payload.senderIdentifier
            )
        }
    }

    /// Drop every BEK restore shard. Called when a restore completes or is abandoned; leaves
    /// per-entry reconstruction rows untouched.
    func clearBEKRestoreShards() {
        guard let key = try? self.keyManager.deriveRecoveryBufferKey() else { return }
        self.clearBEKRestoreShards(usingKey: key)
    }

    /// Same as `clearBEKRestoreShards()` but decrypts with an already-derived key — see
    /// `loadRestoreShards(usingKey:)`'s doc comment. Not `private` for the same reason.
    func clearBEKRestoreShards(usingKey key: SymmetricKey) {
        guard let rows = try? self.bekRestoreRows(usingKey: key) else { return }
        for row in rows { self.modelContext.delete(row.row) }
        try? self.modelContext.save()
        self.pendingRestoreShardCount = 0
    }

    // MARK: - Legacy shard-file import

    private static let legacyRestoreShardsURL: URL =
        FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("backup-import-cache-shards.dat")

    private static let legacyRestoreShardsAAD: Data =
        Data("occulta.pending-bek-restore-shards".utf8)

    /// Move a pre-Bug-100 shard file into rows, then delete it.
    ///
    /// Exists for one population: devices upgrading mid-restore. Dropping the file instead
    /// would strand a genuine recovery — the shards are already spent from the trustees' side,
    /// so re-collecting means asking every one of them to hand back again.
    ///
    /// Called from the two entry points that read or write the buffer rather than from launch,
    /// so it needs no ordering guarantee and runs exactly when the data is first wanted.
    private func migrateLegacyRestoreShardFile() throws {
        let url = Self.legacyRestoreShardsURL
        guard FileManager.default.fileExists(atPath: url.path) else { return }

        defer { try? FileManager.default.removeItem(at: url) }

        guard let bufferKey = try self.keyManager.deriveRecoveryBufferKey() else {
            throw VaultError.keyDerivationFailed
        }
        let combined = try Data(contentsOf: url)
        let box      = try AES.GCM.SealedBox(combined: combined)
        let plain    = try AES.GCM.open(box, using: bufferKey, authenticating: Self.legacyRestoreShardsAAD)
        let shards   = try JSONDecoder().decode([AttestedShard].self, from: plain)

        for shard in shards {
            guard let entryID = shard.attribute.entryID else { continue }
            try self.insertReconstructRow(
                entryID:          entryID,
                attribute:        shard.attribute,
                attestation:      shard.attestation,
                senderIdentifier: shard.senderIdentifier,
                usingKey:         bufferKey
            )
        }
    }

    private struct DecodedReconstructRow {
        let row:     ReconstructShard
        let payload: ReconstructShard.Payload
    }

    /// Mirrors `ReconstructShard.aad()` — used at seal time before the @Model
    /// is constructed.
    private static func reconstructRowAAD(id: UUID) -> Data {
        id.uuidString.data(using: .utf8)!
    }

    /// Decrypt every ReconstructShard row using the recovery buffer key.
    /// Rows that fail to decrypt are silently dropped — they're either corrupt,
    /// from an old key generation, or tampered. Either way they're useless.
    private func decryptAllReconstructShards() throws -> [DecodedReconstructRow] {
        guard let bufferKey = try self.keyManager.deriveRecoveryBufferKey() else {
            throw VaultError.keyDerivationFailed
        }
        return try self.decryptAllReconstructShards(usingKey: bufferKey)
    }

    /// Same as `decryptAllReconstructShards()` but decrypts with an already-derived key — see
    /// `insertReconstructRow(...usingKey:)`'s doc comment for why this exists.
    private func decryptAllReconstructShards(usingKey bufferKey: SymmetricKey) throws -> [DecodedReconstructRow] {
        let rows = try self.modelContext.fetch(FetchDescriptor<ReconstructShard>())
        var out  = [DecodedReconstructRow]()
        out.reserveCapacity(rows.count)

        for row in rows {
            guard
                let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                let plaintext = try? AES.GCM.open(box, using: bufferKey, authenticating: row.aad()),
                let payload   = try? JSONDecoder().decode(ReconstructShard.Payload.self, from: plaintext)
            else { continue }
            out.append(DecodedReconstructRow(row: row, payload: payload))
        }
        return out
    }
}

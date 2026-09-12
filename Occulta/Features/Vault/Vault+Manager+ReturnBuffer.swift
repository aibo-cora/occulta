//
//  Vault+Manager+ReturnBuffer.swift
//  Occulta
//
//  Owner-side reconstruction buffer.
//  Absorbs `.handback` shards into encrypted ReconstructShard rows, finalises
//  reconstruction once a per-entry threshold is reached.
//
//  All buffer rows are sealed under the restore vault key (device-unlock
//  level, no biometric) so `.handback` bundles can be absorbed even while the
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
            guard let key = try self.keyManager.deriveRestoreVaultKey() else {
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
            try? self.tryFinalizeReconstruction(entryID: entryID, usingKey: key)
        }

        // ── 3. BEK restore — store shard + attempt reconstruction ────────
        // Only active when a .occbak file is awaiting recovery. storeRestoreShard
        // is safe while locked (restore vault key); attemptBackupRestore no-ops if locked.
        //
        // isRestorePending, not pendingRestoreActive — the shard must still be stored
        // above depth 0, or a genuine recovery silently stops accumulating shards the
        // moment the user is at a duress depth (Bug 93). Kept as the BEK-specific gate
        // deliberately (Bug 94 remedy 2) — a fresh device can't know the expected
        // distributionID any more precisely than this before reconstruction succeeds.
        if self.isRestorePending {
            try? self.storeRestoreShard(attribute, attestation: attestation, senderIdentifier: senderIdentifier, currentDepth: currentDepth)
            self.attemptBackupRestore(currentDepth: currentDepth)
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
        guard let key = try self.keyManager.deriveRestoreVaultKey() else {
            throw VaultError.keyDerivationFailed
        }
        try self.tryFinalizeReconstruction(entryID: entryID, usingKey: key)
    }

    /// Same as `tryFinalizeReconstruction(entryID:)` but decrypts the buffered shards with an
    /// already-derived restore vault key — for `acceptReturnedShard`'s per-entry branch,
    /// which already holds this key from its own dup-check and insert a few lines earlier and
    /// would otherwise pay a third redundant Secure Enclave round trip calling this. (The vault
    /// key below is a separate, unrelated key — always derived here regardless.)
    func tryFinalizeReconstruction(entryID: UUID, usingKey key: SymmetricKey) throws {
        guard self.isUnlocked else { return }

        let vaultKey    = try self.currentKey()
        guard let entry = try self.fetchEntry(by: entryID) else { return }
        guard let metaCipher = entry.shardDistributionEncrypted else { return }

        let metaBox       = try AES.GCM.SealedBox(combined: metaCipher)
        let metaPlaintext = try AES.GCM.open(metaBox, using: vaultKey, authenticating: entry.aad(for: .shardDistribution))
        let meta          = try JSONDecoder().decode(ShardDistributionMetadata.self, from: metaPlaintext)

        let buffered = try self.decryptAllReconstructShards(usingKey: key)
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
        guard let restoreKey = try self.keyManager.deriveRestoreVaultKey() else {
            throw VaultError.keyDerivationFailed
        }
        try self.insertReconstructRow(
            entryID: entryID, attribute: attribute,
            attestation: attestation, senderIdentifier: senderIdentifier,
            usingKey: restoreKey
        )
    }

    /// Same as `insertReconstructRow(entryID:attribute:attestation:senderIdentifier:)` but
    /// decrypts with an already-derived key instead of deriving one fresh — for callers that
    /// already hold the restore vault key and would otherwise pay a redundant Secure Enclave
    /// round trip (see `storeRestoreShard`, which calls this alongside two other buffer
    /// operations that all need the identical key).
    private func insertReconstructRow(
        entryID:          UUID,
        attribute:        SignedAttribute,
        attestation:      SignedAttribute?,
        senderIdentifier: String,
        usingKey restoreKey: SymmetricKey
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
        let sealed    = try AES.GCM.seal(plaintext, using: restoreKey, nonce: AES.GCM.Nonce(), authenticating: aad)
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
    /// separates BEK restore shards from it. They seal under the same restore vault key,
    /// which is the criterion that doc leads with; they are the same kind of transient buffer,
    /// cleared when their recovery completes; and `Payload` already carries every field they
    /// need.
    ///
    /// A row belongs to this path when its `entryID` resolves to no `VaultEntry`, because BEK
    /// shards carry the `distributionID` and no `VaultEntry.id` is ever one. That is not a new
    /// invariant — `acceptReturnedShard`'s per-entry step already relies on it in the opposite
    /// direction to exclude these very shards.
    ///
    /// Depth-scoped (`RECOVERY_BUFFER_LAYERING.md` §6 item 9.1) — a row belongs to `currentDepth`'s
    /// restore only if `payload.depth` decodes to exactly that value. `depth` lives inside the
    /// encrypted payload, never a plaintext column, so this filter (like every read below) only
    /// ever runs after the row has already been opened with the restore vault key.
    private func bekRestoreRows(currentDepth: Int) throws -> [DecodedReconstructRow] {
        guard let key = try self.keyManager.deriveRestoreVaultKey() else {
            throw VaultError.keyDerivationFailed
        }
        return try self.bekRestoreRows(usingKey: key, currentDepth: currentDepth)
    }

    /// Same as `bekRestoreRows(currentDepth:)` but decrypts with an already-derived key — see
    /// `insertReconstructRow(...usingKey:)`'s doc comment for why this exists.
    private func bekRestoreRows(usingKey key: SymmetricKey, currentDepth: Int) throws -> [DecodedReconstructRow] {
        try self.decryptAllReconstructShards(usingKey: key).filter { row in
            guard ((try? self.fetchEntry(by: row.payload.entryID)) ?? nil) == nil else { return false }
            guard let depthData = row.payload.depth, DepthCodec.decode(depthData) == currentDepth else { return false }
            return true
        }
    }

    /// A row whose `encryptedPayload` fails to open at all under the restore vault key —
    /// genuine, never-claimed filler, indistinguishable from a live row without this key.
    /// Claiming reuses the row's own `id` (and therefore its AAD) rather than inserting a new
    /// one, so the shared pool's total row count never changes — the same property
    /// `BackupEncryptionKey.claimFillerRow` gives BEK's own rows, applied to one shared pool
    /// instead of one row per depth (`RECOVERY_BUFFER_LAYERING.md` §6 item 9.1: this model's
    /// `depth` lives inside the encrypted payload, so it cannot be pre-assigned per depth the
    /// way BEK's local-key-sealed `depth` column can — filler here is anonymous until claimed).
    /// Falls back to inserting a fresh row only if the pool is somehow exhausted — should not
    /// happen given the pool is sized to the worst case (255 × `AppLayerConfig.maxVerifierCount`),
    /// but fails open into "insert" rather than "throw" so a shard is never lost to an
    /// under-provisioned pool.
    private func claimBEKRestoreFillerRow(usingKey key: SymmetricKey) throws -> ReconstructShard {
        let rows = try self.modelContext.fetch(FetchDescriptor<ReconstructShard>())
        for row in rows {
            guard let box = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                  (try? AES.GCM.open(box, using: key, authenticating: row.aad())) == nil
            else { continue }
            return row
        }
        let fresh = ReconstructShard(encryptedPayload: Data())
        self.modelContext.insert(fresh)
        return fresh
    }

    /// Seals a BEK-restore `Payload` into `row.encryptedPayload`, reusing `row`'s own AAD.
    /// Shared by claiming a filler row and by resealing an existing live row in place (a
    /// sender replacing their prior share never frees the row back to the pool — see
    /// `storeRestoreShard`).
    private func sealBEKRestorePayload(
        into row:         ReconstructShard,
        entryID:          UUID,
        attribute:        SignedAttribute,
        attestation:      SignedAttribute?,
        senderIdentifier: String,
        depth:            Data,
        usingKey key:     SymmetricKey
    ) throws {
        let payload = ReconstructShard.Payload(
            entryID:          entryID,
            attrID:           attribute.id,
            signedAttribute:  attribute,
            senderIdentifier: senderIdentifier,
            attestation:      attestation,
            depth:            depth
        )
        let plaintext = try JSONEncoder().encode(payload)
        let sealed    = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(), authenticating: row.aad())
        guard let combined = sealed.combined else { throw VaultError.encryptionFailed }
        row.encryptedPayload = combined
    }

    /// Append one incoming BEK shard to `currentDepth`'s restore buffer.
    ///
    /// At most one stored shard per `(entryID, senderIdentifier, currentDepth)` (Bug 94 remedy 2,
    /// extended for depth-partitioning) — a second share from the same sender at the same depth
    /// replaces the first rather than accumulating, so `attemptBackupRestore`'s grouping reflects
    /// distinct senders, not just distinct `SignedAttribute.id`s. The same sender delivering at two
    /// different depths (possible — contact visibility is a ceiling, not exact-match) produces two
    /// independent rows, one per depth, never colliding. Safe to call while the vault is locked:
    /// the restore vault key is derived from the Secure Enclave, not from the vault key.
    ///
    /// Cap: 255 distinct-sender rows per depth — the Shamir ceiling, so no genuine distribution,
    /// past or future, can ever be rejected by it (`RECOVERY_BUFFER_LAYERING.md` §6 item 9.1).
    /// Once a depth's live count reaches it, further distinct senders are silently dropped — not
    /// stored, not counted, no error. Rejecting rather than evicting: evicting the oldest row to
    /// make room would itself be an attack (flood to knock out a real trustee's already-banked
    /// share).
    func storeRestoreShard(_ attribute: SignedAttribute, attestation: SignedAttribute?, senderIdentifier: String, currentDepth: Int) throws {
        guard let entryID = attribute.entryID else { throw VaultError.decryptionFailed }

        // Derived once and reused below — migrateLegacyRestoreShardFile, decryptAllReconstructShards,
        // and bekRestoreRows all need this same restore vault key; deriving it separately at each
        // of those was several redundant Secure Enclave round trips for one shard delivery.
        guard let key = try self.keyManager.deriveRestoreVaultKey() else {
            throw VaultError.keyDerivationFailed
        }
        try? self.migrateLegacyRestoreShardFile(usingKey: key)

        let depthBytes = DepthCodec.encode(currentDepth)
        let existingForDepth = try self.bekRestoreRows(usingKey: key, currentDepth: currentDepth)

        if let dup = existingForDepth.first(where: { $0.payload.senderIdentifier == senderIdentifier }) {
            if dup.payload.attrID == attribute.id { return }   // identical re-delivery
            // Sender is replacing their prior share for this depth — reseal the same row in
            // place. Never delete-then-insert here: that would shrink the shared pool below its
            // fixed size, the exact row-count camouflage this design exists to hold constant.
            try self.sealBEKRestorePayload(
                into: dup.row, entryID: entryID, attribute: attribute, attestation: attestation,
                senderIdentifier: senderIdentifier, depth: depthBytes, usingKey: key
            )
            try self.modelContext.save()
            self.pendingRestoreShardCount = existingForDepth.count
            return
        }

        guard existingForDepth.count < 255 else { return }   // cap — silently drop past it

        let target = try self.claimBEKRestoreFillerRow(usingKey: key)
        try self.sealBEKRestorePayload(
            into: target, entryID: entryID, attribute: attribute, attestation: attestation,
            senderIdentifier: senderIdentifier, depth: depthBytes, usingKey: key
        )
        try self.modelContext.save()
        self.pendingRestoreShardCount = existingForDepth.count + 1
    }

    /// Every BEK restore shard collected so far for `currentDepth`. Empty when none have arrived.
    func loadRestoreShards(currentDepth: Int) throws -> [AttestedShard] {
        guard let key = try self.keyManager.deriveRestoreVaultKey() else {
            throw VaultError.keyDerivationFailed
        }
        return try self.loadRestoreShards(usingKey: key, currentDepth: currentDepth)
    }

    /// Same as `loadRestoreShards(currentDepth:)` but decrypts with an already-derived key — for
    /// `attemptBackupRestore` (`Vault+Manager+Backup.swift`), which also calls
    /// `clearBEKRestoreShards(usingKey:currentDepth:)` on success and would otherwise re-derive the
    /// identical key for that second call. Not `private`: it's called from that other file.
    func loadRestoreShards(usingKey key: SymmetricKey, currentDepth: Int) throws -> [AttestedShard] {
        try? self.migrateLegacyRestoreShardFile(usingKey: key)
        return try self.bekRestoreRows(usingKey: key, currentDepth: currentDepth).map {
            AttestedShard(
                attribute:        $0.payload.signedAttribute,
                attestation:      $0.payload.attestation,
                senderIdentifier: $0.payload.senderIdentifier
            )
        }
    }

    /// Drop every BEK restore shard banked for `currentDepth`. Called when that depth's restore
    /// completes or is cancelled; leaves per-entry reconstruction rows, and every other depth's
    /// own banked shards, untouched.
    ///
    /// Resets each row's `encryptedPayload` to fresh random bytes — returning it to genuine filler
    /// — rather than deleting it. Deleting would shrink the shared pool below its fixed size, the
    /// same reasoning `storeRestoreShard`'s reseal-in-place already relies on.
    func clearBEKRestoreShards(currentDepth: Int) {
        guard let key = try? self.keyManager.deriveRestoreVaultKey() else { return }
        self.clearBEKRestoreShards(usingKey: key, currentDepth: currentDepth)
    }

    /// Same as `clearBEKRestoreShards(currentDepth:)` but decrypts with an already-derived key —
    /// see `loadRestoreShards(usingKey:currentDepth:)`'s doc comment. Not `private` for the same
    /// reason.
    func clearBEKRestoreShards(usingKey key: SymmetricKey, currentDepth: Int) {
        guard let rows = try? self.bekRestoreRows(usingKey: key, currentDepth: currentDepth) else { return }
        for row in rows { row.row.encryptedPayload = Data.randomBytes(row.row.encryptedPayload.count) }
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
    /// Stamps every migrated shard with depth 0 — this file predates depth-partitioning
    /// entirely, and §8's own migration strategy already establishes that a legacy in-flight
    /// restore is depth-0-destined by construction. Claims filler rows from the shared pool the
    /// same way a live delivery would, rather than inserting fresh rows, so this migration
    /// doesn't grow the pool past its fixed size.
    ///
    /// Called from the two entry points that read or write the buffer rather than from launch,
    /// so it needs no ordering guarantee and runs exactly when the data is first wanted. Both
    /// of those callers already derive the restore vault key for their own purposes, so this
    /// takes it as a parameter rather than deriving a fourth, redundant copy of it.
    private func migrateLegacyRestoreShardFile(usingKey restoreKey: SymmetricKey) throws {
        let url = Self.legacyRestoreShardsURL
        guard FileManager.default.fileExists(atPath: url.path) else { return }

        defer { try? FileManager.default.removeItem(at: url) }

        let combined = try Data(contentsOf: url)
        let box      = try AES.GCM.SealedBox(combined: combined)
        let plain    = try AES.GCM.open(box, using: restoreKey, authenticating: Self.legacyRestoreShardsAAD)
        let shards   = try JSONDecoder().decode([AttestedShard].self, from: plain)

        let depthZero = DepthCodec.encode(0)
        for shard in shards {
            guard let entryID = shard.attribute.entryID else { continue }
            let target = try self.claimBEKRestoreFillerRow(usingKey: restoreKey)
            try self.sealBEKRestorePayload(
                into: target, entryID: entryID, attribute: shard.attribute, attestation: shard.attestation,
                senderIdentifier: shard.senderIdentifier, depth: depthZero, usingKey: restoreKey
            )
        }
        try self.modelContext.save()
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

    /// Decrypt every ReconstructShard row using the restore vault key.
    /// Rows that fail to decrypt are silently dropped — they're either corrupt,
    /// from an old key generation, or tampered. Either way they're useless.
    private func decryptAllReconstructShards() throws -> [DecodedReconstructRow] {
        guard let restoreKey = try self.keyManager.deriveRestoreVaultKey() else {
            throw VaultError.keyDerivationFailed
        }
        return try self.decryptAllReconstructShards(usingKey: restoreKey)
    }

    /// Same as `decryptAllReconstructShards()` but decrypts with an already-derived key — see
    /// `insertReconstructRow(...usingKey:)`'s doc comment for why this exists.
    private func decryptAllReconstructShards(usingKey restoreKey: SymmetricKey) throws -> [DecodedReconstructRow] {
        let rows = try self.modelContext.fetch(FetchDescriptor<ReconstructShard>())
        var out  = [DecodedReconstructRow]()
        out.reserveCapacity(rows.count)

        for row in rows {
            guard
                let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                let plaintext = try? AES.GCM.open(box, using: restoreKey, authenticating: row.aad()),
                let payload   = try? JSONDecoder().decode(ReconstructShard.Payload.self, from: plaintext)
            else { continue }
            out.append(DecodedReconstructRow(row: row, payload: payload))
        }
        return out
    }
}

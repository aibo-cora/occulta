//
//  Vault+Manager+ReturnBuffer.swift
//  Occulta
//
//  Owner-side reconstruction buffer.
//  Absorbs `.handback` shards into `PendingShamirSecretRestore` rows, finalises
//  reconstruction once a secret's threshold is reached.
//
//  Replaces the `ReconstructShard`-based mechanism (RECOVERY_BUFFER_LAYERING.md §9.3,
//  2026-09-21) — one model instead of two, keyed by the secret's own identity
//  (`attributeID`: a BEK `distributionID`, or a PEK's `VaultEntry.id`) rather than
//  BEK/PEK living in separate shapes. Collection is depth-blind by design — see
//  `PendingShamirSecretRestore`'s own doc comment for why that's safe: the model
//  carries no depth information at all, so a coercer who fully decrypts every row
//  still learns only "a secret was restored," never which depth.
//
//  `bugs.md` Bug 99, addendum 2026-09-21: this depth-blind collection ships ahead of
//  that bug's own fix (binding completion to the depth a restore was attempted at),
//  which is a separate, deferred change. `attemptBackupRestore`'s `currentDepth == 0`
//  completion guard (`Vault+Manager+Backup.swift`) is untouched here — building the
//  depth-blind shape twice (once temporarily scoped, once final) costs more than the
//  narrow interim gap this accepts. See that bug's addendum for the exact trace.
//
//  All buffer rows are readable/writable while the vault is locked — `attributeID`/
//  `deletionToken` sealed under the local DB key, `shards` under the restore vault
//  key, neither requiring biometric access. Finalisation itself requires the vault
//  unlocked because it re-wraps the recovered PEK (or BEK) under the vault key.
//

import Foundation
import SwiftData
import CryptoKit

extension VaultManager {

    // MARK: - Public surface

    /// Absorb one returned shard into the reconstruction buffer.
    ///
    /// `senderIdentifier` comes from `handleHandback`, resolved on the receiving
    /// device's own side — never sender-asserted — see `AttestedShard`'s doc
    /// comment. Verification (such as it is — Branch A when it can run; unconditional
    /// acceptance otherwise, `bugs.md` Bug 125) already happened there.
    ///
    /// Steps:
    ///   1. `absorbShard` — find or create the row for `attribute.entryID`, write the
    ///      shard into it. At most one buffered slot per `(attributeID, senderIdentifier)`:
    ///      a second share from the same sender replaces the first rather than
    ///      accumulating, so a threshold-reaching group structurally requires distinct
    ///      senders, not just distinct `SignedAttribute.id`s.
    ///   2. Opportunistically try to finalise — for a per-entry PEK if this device
    ///      split that entry itself, for a BEK restore if a `.occbak` file is already
    ///      pending. Both no-op harmlessly if their own preconditions aren't met.
    func acceptReturnedShard(
        _ attribute: SignedAttribute,
        senderIdentifier: String,
        currentDepth: Int
    ) throws {
        guard attribute.category == .shard, let attributeID = attribute.entryID else {
            throw VaultError.decryptionFailed
        }

        // Drains a pre-Bug-100 shard file into rows on the first delivery that
        // notices it — harmless no-op once migrated, or if never present.
        try? self.migrateLegacyRestoreShardFile()

        try self.absorbShard(attribute, senderIdentifier: senderIdentifier)

        // ── Per-entry PEK reconstruction ──────────────────────────────────
        if let entry = try? self.fetchEntry(by: attributeID), entry.shardDistributionEncrypted != nil {
            try? self.tryFinalizeReconstruction(entryID: attributeID)
        }

        // ── BEK restore ────────────────────────────────────────────────────
        // Only meaningful when a .occbak file is awaiting recovery — attemptBackupRestore
        // no-ops otherwise (locked, no pending file, or currentDepth != 0).
        if self.isRestorePending {
            self.attemptBackupRestore(currentDepth: currentDepth)
        }
    }

    /// Attempt to finalise reconstruction for one entry: collect buffered shards,
    /// run `reconstructEntry`, and orphan the buffer row on success.
    ///
    /// No-op when:
    ///   - the vault is locked (vault key needed to read distribution metadata
    ///     and to re-wrap the recovered PEK),
    ///   - the entry has no distribution metadata (was never split),
    ///   - fewer than `threshold` shards are buffered,
    ///   - reconstruction throws (e.g. wrong shards, tampered bytes — GCM tag
    ///     rejects the candidate PEK in `reconstructEntry`).
    func tryFinalizeReconstruction(entryID: UUID) throws {
        guard self.isUnlocked else { return }

        let vaultKey = try self.currentKey()
        guard let entry = try self.fetchEntry(by: entryID) else { return }
        guard let metaCipher = entry.shardDistributionEncrypted else { return }

        let metaBox       = try AES.GCM.SealedBox(combined: metaCipher)
        let metaPlaintext = try AES.GCM.open(metaBox, using: vaultKey, authenticating: entry.aad(for: .shardDistribution))
        let meta          = try JSONDecoder().decode(ShardDistributionMetadata.self, from: metaPlaintext)

        let collected = try self.collectedShards(forAttributeID: entryID)
        guard collected.count >= meta.threshold else { return }

        let attributes = collected.map { $0.attribute }
        let identity   = try? self.keyManager.retrieveIdentity()

        // reconstructEntry handles GCM authentication — wrong shards fail there.
        try self.reconstructEntry(entryID: entryID, shards: attributes, ownerIdentity: identity)

        self.orphanShards(forAttributeID: entryID)
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

    /// User cancels reconstruction for one entry — drop all buffered shards for it.
    func cancelReconstruction(entryID: UUID) throws {
        self.orphanShards(forAttributeID: entryID)
    }

    // MARK: - Absorb / read / orphan
    //
    // The one mechanism both BEK restore and per-entry PEK reconstruction share —
    // PendingShamirSecretRestore already disambiguates by attributeID, so neither
    // needs its own branch here the way the old ReconstructShard split required.

    /// Absorb `attribute` into the row for `attribute.entryID` — creating one if none
    /// exists yet. At most one slot per `(attributeID, senderIdentifier)`: a second
    /// share from the same sender replaces the first (`bugs.md` Bug 94 remedy 2), an
    /// identical re-delivery (same `SignedAttribute.id`) is a silent no-op.
    ///
    /// Safe to call while the vault is locked — the local DB key and the restore
    /// vault key are both device-unlock level, no biometric.
    func absorbShard(_ attribute: SignedAttribute, senderIdentifier: String) throws {
        guard let attributeID = attribute.entryID else { throw VaultError.decryptionFailed }

        let localKey   = try Self.localKey()
        let restoreKey = try self.restoreVaultKey()

        let row = try self.findOrCreateRestoreRow(forAttributeID: attributeID, localKey: localKey)

        var slots = try Self.decodedSlots(from: row, usingKey: restoreKey)

        if let dupIndex = slots.firstIndex(where: { $0.senderIdentifier == senderIdentifier }) {
            if slots[dupIndex].signedAttribute?.id == attribute.id { return }   // identical re-delivery
            slots[dupIndex] = PendingRestoreShardSlot(signedAttribute: attribute, senderIdentifier: senderIdentifier)
        } else {
            slots.append(PendingRestoreShardSlot(signedAttribute: attribute, senderIdentifier: senderIdentifier))
        }

        let encoded = try PendingShamirSecretRestore.ShardsCodec.encode(slots)
        let sealed  = try AES.GCM.seal(encoded, using: restoreKey, nonce: AES.GCM.Nonce(), authenticating: row.aad())
        guard let combined = sealed.combined else { throw VaultError.encryptionFailed }

        row.shards = combined
        try self.modelContext.save()
    }

    /// Every shard collected so far toward reconstructing the secret identified by
    /// `attributeID` — a BEK `distributionID` or a PEK's `VaultEntry.id`, whichever
    /// this row was opened for.
    ///
    /// Empty if no row exists yet, or if the row exists but has already been
    /// orphaned (`orphanShards` already consumed it) — a completed or abandoned
    /// restore's shards are never returned here again.
    func collectedShards(forAttributeID attributeID: UUID) throws -> [AttestedShard] {
        let localKey   = try Self.localKey()
        let restoreKey = try self.restoreVaultKey()

        guard let row = try self.liveRestoreRow(forAttributeID: attributeID, localKey: localKey) else { return [] }
        let slots = try Self.decodedSlots(from: row, usingKey: restoreKey)

        return slots.compactMap { slot in
            guard let attribute = slot.signedAttribute, let sender = slot.senderIdentifier else { return nil }
            return AttestedShard(attribute: attribute, senderIdentifier: sender)
        }
    }

    /// Mark `attributeID`'s row consumed — called the moment its secret is
    /// successfully reconstructed, never on a mere failed attempt (a wrong guess
    /// leaves the row live for the next real one).
    ///
    /// Resets `shards` to fresh random bytes and flips `deletionToken` to orphaned,
    /// rather than deleting the row — the same orphan-in-place convention
    /// `PendingShamirSecretRestore`'s own doc comment already establishes.
    func orphanShards(forAttributeID attributeID: UUID) {
        guard let localKey = try? Self.localKey() else { return }
        guard let row = try? self.liveRestoreRow(forAttributeID: attributeID, localKey: localKey) else { return }

        row.shards        = Data.randomBytes(PendingShamirSecretRestore.ShardsCodec.payloadSize + 28)
        row.deletionToken = try? PendingShamirSecretRestore.orphanedToken.encrypt(using: localKey)
        try? self.modelContext.save()
    }

    // MARK: - Private

    /// Derives the local DB key ambiently, never via `self.keyManager` — the same
    /// trap `Backup`'s own `localKey()` documents. `Manager.Security`'s own future
    /// orphaning sweeps (if this model ever gets one) derive it the same ambient
    /// way; disagreeing here would mean writes and reads silently never match under
    /// any injected key manager, which every test uses.
    private static func localKey() throws -> SymmetricKey {
        guard let key = try Manager.Key().createHybridLocalEncryptionKey() else {
            throw VaultError.keyDerivationFailed
        }
        return key
    }

    private func restoreVaultKey() throws -> SymmetricKey {
        guard let key = try self.keyManager.deriveRestoreVaultKey() else {
            throw VaultError.keyDerivationFailed
        }
        return key
    }

    /// `row.shards`, decrypted and decoded — `[]` if the field is `nil` (nothing
    /// absorbed yet) or fails to open (corrupt or from a stale key generation).
    private static func decodedSlots(from row: PendingShamirSecretRestore, usingKey restoreKey: SymmetricKey) throws -> [PendingRestoreShardSlot] {
        guard let data = row.shards,
              let box   = try? AES.GCM.SealedBox(combined: data),
              let plain = try? AES.GCM.open(box, using: restoreKey, authenticating: row.aad())
        else { return [] }
        return PendingShamirSecretRestore.ShardsCodec.decode(plain) ?? []
    }

    /// The live (not orphaned) row for `attributeID`, if any.
    private func liveRestoreRow(forAttributeID attributeID: UUID, localKey: SymmetricKey) throws -> PendingShamirSecretRestore? {
        let rows = try self.modelContext.fetch(FetchDescriptor<PendingShamirSecretRestore>())
        for row in rows {
            guard !row.isOrphaned(usingKey: localKey),
                  let data = row.attributeID, let plain = data.decrypt(using: localKey),
                  Self.uuid(fromBytes: [UInt8](plain)) == attributeID
            else { continue }
            return row
        }
        return nil
    }

    /// The live row for `attributeID`, or a freshly-inserted one — genuinely
    /// unbounded, no filler pool, no cap (`RECOVERY_BUFFER_LAYERING.md` §6 item 9.3's
    /// final decision; `bugs.md` Bug 96 item 2 stays open, permanently accepted).
    private func findOrCreateRestoreRow(forAttributeID attributeID: UUID, localKey: SymmetricKey) throws -> PendingShamirSecretRestore {
        if let existing = try self.liveRestoreRow(forAttributeID: attributeID, localKey: localKey) {
            return existing
        }

        let vault = try self.requireVault()
        guard let sealedID    = try Self.uuidBytes(attributeID).encrypt(using: localKey),
              let sealedToken = try PendingShamirSecretRestore.liveToken.encrypt(using: localKey)
        else { throw VaultError.encryptionFailed }

        let row = PendingShamirSecretRestore(attributeID: sealedID, deletionToken: sealedToken, vault: vault)
        self.modelContext.insert(row)
        return row
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

    // MARK: - Legacy shard-file import

    private static let legacyRestoreShardsURL: URL =
        FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("backup-import-cache-shards.dat")

    private static let legacyRestoreShardsAAD: Data =
        Data("occulta.pending-bek-restore-shards".utf8)

    /// Move a pre-Bug-100 shard file straight into `PendingShamirSecretRestore` rows
    /// via `absorbShard`, then delete it.
    ///
    /// Exists for one population: devices upgrading mid-restore, from a build old
    /// enough to predate Bug 100's move off this file entirely. Dropping the file
    /// instead would strand a genuine recovery — the shards are already spent from
    /// the trustees' side, so re-collecting means asking every one of them to hand
    /// back again.
    ///
    /// No depth stamping — this file predates depth-partitioning entirely, and
    /// collection is depth-blind now regardless (see this file's own header).
    func migrateLegacyRestoreShardFile() throws {
        let url = Self.legacyRestoreShardsURL
        guard FileManager.default.fileExists(atPath: url.path) else { return }

        defer { try? FileManager.default.removeItem(at: url) }

        guard let restoreKey = try self.keyManager.deriveRestoreVaultKey() else {
            throw VaultError.keyDerivationFailed
        }

        let combined = try Data(contentsOf: url)
        let box      = try AES.GCM.SealedBox(combined: combined)
        let plain    = try AES.GCM.open(box, using: restoreKey, authenticating: Self.legacyRestoreShardsAAD)
        let shards   = try JSONDecoder().decode([AttestedShard].self, from: plain)

        for shard in shards {
            try? self.absorbShard(shard.attribute, senderIdentifier: shard.senderIdentifier)
        }
    }

    // MARK: - Legacy ReconstructShard migration

    /// One-time migration of any leftover `ReconstructShard` rows (the pre-§9.3
    /// mechanism, `RECOVERY_BUFFER_LAYERING.md`, retired 2026-09-21) into
    /// `PendingShamirSecretRestore` via `absorbShard` — not a 1:1 row copy. Up to 255
    /// `ReconstructShard` rows (one per distinct sender) could belong to a single
    /// secret's restore under the old shared-pool design; each decoded payload is
    /// absorbed individually, and `absorbShard`'s own find-or-create-by-attributeID
    /// logic collapses them into the shard slots of one target row, exactly as if
    /// they'd arrived one at a time under the new mechanism.
    ///
    /// No arming depth to carry forward — completion depth is decided at file-open
    /// time under the current design, not recorded per restore, so the legacy rows'
    /// own per-shard *arrival* depth (already known to not be the same thing as
    /// arming depth — `bugs.md` Bug 100's own remedy-2 note) is simply dropped.
    ///
    /// Idempotent and crash-safe without needing an all-or-nothing transaction:
    /// `absorbShard` already saves after every call, and re-migrating an
    /// already-absorbed payload against the same target row is a safe no-op
    /// (identical re-delivery, matched by `SignedAttribute.id`) — so a source row is
    /// only ever deleted *after* its payload has been durably absorbed, and interrupting
    /// this partway just means some source rows are still around to retry next unlock.
    /// A row that fails to decrypt or decode is deleted anyway — matching
    /// `decryptAllReconstructShards`'s own established "either way, useless" precedent
    /// for corrupt buffer rows — and a payload whose `SignedAttribute.value` somehow
    /// isn't a genuine 33-byte Shamir share (never true for real legacy data, only
    /// possible for something already corrupt) is skipped the same way, not treated
    /// as fatal.
    func migrateReconstructShardsIfNeeded() throws {
        let rows = try self.modelContext.fetch(FetchDescriptor<ReconstructShard>())
        guard !rows.isEmpty else { return }

        guard let restoreKey = try self.keyManager.deriveRestoreVaultKey() else {
            throw VaultError.keyDerivationFailed
        }

        for row in rows {
            defer { self.modelContext.delete(row) }

            guard let box     = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                  let plain   = try? AES.GCM.open(box, using: restoreKey, authenticating: row.aad()),
                  let payload = try? JSONDecoder().decode(ReconstructShard.Payload.self, from: plain)
            else { continue }

            try? self.absorbShard(payload.signedAttribute, senderIdentifier: payload.senderIdentifier)
        }

        try self.modelContext.save()
    }

    // MARK: - BEK restore distribution enumeration
    //
    // absorbShard/collectedShards/orphanShards are all scoped to one attributeID.
    // attemptBackupRestore (Vault+Manager+Backup.swift) doesn't know which
    // distributionID its pending .occbak belongs to until reconstruction against it
    // actually succeeds, so it needs to enumerate every currently-live BEK-restore
    // distribution and try each in turn — the same "group and try every group" shape
    // the old grouping-by-entryID logic had, just already grouped by construction now
    // that each row is one distributionID instead of a shared pool.

    /// Every currently-live BEK-restore `distributionID` with at least one collected
    /// shard. A row belongs to this population when its `attributeID` resolves to no
    /// real `VaultEntry` — no `VaultEntry.id` is ever a `distributionID` — mirroring
    /// the old `bekRestoreRows`'s own heuristic exactly.
    func bekRestoreDistributionIDs() throws -> [UUID] {
        let localKey = try Self.localKey()
        let rows = try self.modelContext.fetch(FetchDescriptor<PendingShamirSecretRestore>())
        var ids: [UUID] = []
        for row in rows {
            guard !row.isOrphaned(usingKey: localKey),
                  let data = row.attributeID, let plain = data.decrypt(using: localKey),
                  let id = Self.uuid(fromBytes: [UInt8](plain)),
                  ((try? self.fetchEntry(by: id)) ?? nil) == nil
            else { continue }
            ids.append(id)
        }
        return ids
    }

    /// Total shards collected so far across every currently-live BEK-restore
    /// distribution — the UI-facing progress count. Unlike the old per-depth count,
    /// this can now sum across more than one concurrently-collecting distribution
    /// (collection is depth-blind); `Vault+Tab`'s own display already treats this as
    /// a static "in progress" signal, not a rendered number — see
    /// `refreshPendingRestoreState`'s doc comment.
    func bekRestoreShardCount() throws -> Int {
        try self.bekRestoreDistributionIDs().reduce(0) { total, id in
            total + (try self.collectedShards(forAttributeID: id).count)
        }
    }
}

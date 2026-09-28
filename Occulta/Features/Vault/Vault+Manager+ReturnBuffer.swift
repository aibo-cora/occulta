//
//  Vault+Manager+ReturnBuffer.swift
//  Occulta
//
//  Owner-side reconstruction buffer.
//  Banks `.handback` backup-key pieces in `PendingShamirSecretRestore` rows until the owner
//  opens a `.occbak` (`restoreBackup`). Per-entry reconstruction was retired 2026-09-27
//  (`decisions.md`, "Retire per-entry splitting").
//
//  Replaces the `ReconstructShard`-based mechanism (RECOVERY_BUFFER_LAYERING.md §9.3,
//  2026-09-21) — one model instead of two, keyed by the secret's own identity
//  (`attributeID`: a backup key's `distributionID`). Collection is depth-blind by design — see
//  `PendingShamirSecretRestore`'s own doc comment for why that's safe: the model
//  carries no depth information at all, so a coercer who fully decrypts every row
//  still learns only "a secret was restored," never which depth.
//
//  BEK restore completes only when the owner opens a `.occbak` (`restoreBackup`,
//  `Vault+Manager+Backup.swift`), at the depth it's opened at, counting only shards
//  from contacts visible there — which is what keeps depth-blind collection from
//  letting a real backup complete in a duress layer (`bugs.md` Bug 99,
//  RECOVERY_BUFFER_LAYERING.md §9.4). Nothing here triggers it.
//
//  All buffer rows are readable/writable while the vault is locked — `attributeID`/
//  `deletionToken` sealed under the local DB key, `shards` under the restore vault
//  key, neither requiring biometric access. Completion requires the vault unlocked
//  because it stores the recovered backup key under the vault key.
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
    ///   2. Nothing more: completion happens when the owner opens the `.occbak`
    ///      (`restoreBackup`).
    ///
    /// Only backup-key pieces are banked. A trustee hands back every piece it holds
    /// under the owner's old key, including per-entry pieces from before that splitting
    /// was retired, and `restoreBackup` would try each such group against the whole
    /// `.occbak` for nothing, on every attempt, forever. The label is the only thing that
    /// tells the kinds apart and it isn't signed, but a trustee who changes it can only
    /// get a real piece ignored, the same as withholding it (`decisions.md`, "Retire
    /// per-entry splitting").
    func acceptReturnedShard(
        _ attribute: SignedAttribute,
        senderIdentifier: String
    ) throws {
        guard attribute.category == .shard, attribute.entryID != nil else {
            throw VaultError.decryptionFailed
        }
        guard attribute.label == SignedAttribute.backupKeyPieceLabel else { return }

        try self.absorbShard(attribute, senderIdentifier: senderIdentifier)
    }

    // MARK: - Absorb / read / orphan

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

        var slots  = try Self.decodedSlots(from: row, usingKey: restoreKey)
        let sender = TrusteeTag(identifier: senderIdentifier)

        if let dupIndex = slots.firstIndex(where: { $0.sender == sender }) {
            if slots[dupIndex].signedAttribute?.id == attribute.id { return }   // identical re-delivery
            slots[dupIndex] = PendingRestoreShardSlot(signedAttribute: attribute, sender: sender)
        } else {
            slots.append(PendingRestoreShardSlot(signedAttribute: attribute, sender: sender))
        }

        let encoded = try PendingShamirSecretRestore.ShardsCodec.encode(slots)
        let sealed  = try AES.GCM.seal(encoded, using: restoreKey, nonce: AES.GCM.Nonce(), authenticating: row.aad())
        guard let combined = sealed.combined else { throw VaultError.encryptionFailed }

        row.shards = combined
        try self.modelContext.save()
    }

    /// Every shard collected so far toward reconstructing the secret identified by
    /// `attributeID`, a backup key's `distributionID`.
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
            guard let attribute = slot.signedAttribute, let sender = slot.sender else { return nil }
            return AttestedShard(attribute: attribute, sender: sender)
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

    /// Orphans, in place, every live row whose secret is in `attributeIDs`. Doesn't save;
    /// returns whether anything changed. Used by `retireEntrySplittingIfNeeded`.
    func orphanRestoreRows(forAttributeIDs attributeIDs: Set<UUID>) -> Bool {
        guard !attributeIDs.isEmpty, let localKey = try? Self.localKey() else { return false }
        var changed = false
        for row in (try? self.modelContext.fetch(FetchDescriptor<PendingShamirSecretRestore>())) ?? [] {
            guard !row.isOrphaned(usingKey: localKey),
                  let data = row.attributeID, let plain = data.decrypt(using: localKey),
                  let id = Self.uuid(fromBytes: [UInt8](plain)), attributeIDs.contains(id)
            else { continue }
            row.shards        = Data.randomBytes(PendingShamirSecretRestore.ShardsCodec.payloadSize + 28)
            row.deletionToken = try? PendingShamirSecretRestore.orphanedToken.encrypt(using: localKey)
            changed = true
        }
        return changed
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
    // restoreBackup (Vault+Manager+Backup.swift) doesn't know which
    // distributionID an opened .occbak belongs to until reconstruction against it
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
}

//
//  Vault+Manager+Shards.swift
//  Occulta
//
//  Phase 6: SSS shard preparation for VaultManager.
//  Splits the vault key for a given entry into signed shards ready for delivery
//  via the existing .occ basket pipeline. Does NOT deliver shards.
//

import Foundation
import SwiftData
import CryptoKit

extension VaultManager {

    // MARK: - Shard preparation

    /// Split the per-entry key (PEK) for `entryID` into signed shards — one per recipient.
    ///
    /// Each returned `SignedAttribute` has `category: .shard`, is signed with the
    /// SE identity key, and contains the raw GF(2^8) shard bytes as its value.
    /// The caller feeds these into the .occ basket pipeline for delivery.
    ///
    /// Steps (in order):
    ///   1. Assert vault is unlocked.
    ///   2. Unwrap the entry's PEK (via unwrapPEK — handles legacy migration).
    ///   3. SSS-split the PEK (not the vault key) into n shards.
    ///   4. For each shard: compute the SignedAttribute signing payload, sign
    ///      with the SE identity key, build a SignedAttribute(.shard).
    ///   5. Encrypt and persist ShardDistributionMetadata on the entry.
    ///   6. Zero all intermediate PEK and shard buffers via defer.
    ///   7. Return the signed attributes.
    ///
    /// - Parameters:
    ///   - entryID:    The VaultEntry whose PEK is being split.
    ///   - threshold:  Minimum shards for reconstruction (k ≥ 2).
    ///   - recipients: Contacts receiving one shard each (n = count).
    /// - Returns: `[SignedAttribute]` in the same order as `recipients`.
    func prepareShards(
        for entryID: UUID,
        threshold: Int,
        recipients: [Contact.Profile]
    ) throws -> [SignedAttribute] {
        let vaultKey    = try self.currentKey()
        guard let entry = try self.fetchEntry(by: entryID) else { throw VaultError.entryNotFound }

        let n = recipients.count

        // ── 1. Unwrap PEK ────────────────────────────────────────────────────
        let pek = try self.unwrapPEK(for: entry, vaultKey: vaultKey)

        // ⚠️ pekBytes is cleared by defer below.
        var pekBytes = Data()
        pek.withUnsafeBytes { pekBytes = Data($0) }

        defer {
            for i in pekBytes.indices { pekBytes[i] = 0 }
        }

        // ── 2. Split the PEK ─────────────────────────────────────────────────
        var rawShares = try ShamirSecretSharing.split(
            secret: pekBytes,
            threshold: threshold,
            shares: n
        )
        defer {
            // Zero all shard buffers.
            for i in rawShares.indices {
                for j in rawShares[i].indices { rawShares[i][j] = 0 }
            }
        }

        // ── 3. Sign each shard and wrap as SignedAttribute ───────────────────
        var attributes = [SignedAttribute]()
        attributes.reserveCapacity(n)

        for i in 0..<n {
            let shardData = Data(rawShares[i])
            let attrID    = UUID()
            let createdAt = Date()

            // Build the signing payload using the canonical static method —
            // the same bytes that verify(against:) will reconstruct later.
            // entryID binds this shard to the specific key generation; a shard
            // from a previous prepareShards() call for the same entry (or a
            // different entry) will fail verify() even if the key bytes match.
            let payload = SignedAttribute.signingPayload(
                id:        attrID,
                category:  .shard,
                value:     shardData,
                entryID:   entryID,
                createdAt: createdAt,
                expiresAt: nil
            )
            let signature = try self.keyManager.signData(payload)

            attributes.append(SignedAttribute(
                id:        attrID,
                label:     "vault-shard",
                value:     shardData,
                category:  .shard,
                signature: signature,
                createdAt: createdAt,
                entryID:   entryID
            ))
        }

        // ── 4. Persist encrypted ShardDistributionMetadata on the entry ──────
        let now    = Date()
        let shards = (0..<n).map { i in
            ShardRecord(
                contactIdentifier: recipients[i].identifier,
                attributeID:            attributes[i].id,
                status:            .pending,
                distributedAt:     now
            )
        }
        let meta = ShardDistributionMetadata(threshold: threshold, shards: shards)
        let metaData = try JSONEncoder().encode(meta)
        let sealed   = try AES.GCM.seal(
            metaData,
            using:          vaultKey,
            nonce:          AES.GCM.Nonce(),
            authenticating: entry.aad(for: .shardDistribution)
        )
        
        guard let combined = sealed.combined else { throw VaultError.encryptionFailed }
        
        entry.shardDistributionEncrypted = combined
        try self.modelContext.save()

        return attributes
    }

    // MARK: - Shard status reader

    /// Read the ShardDistributionMetadata for an entry without modifying it.
    ///
    /// Returns nil when no distribution exists or when the vault is locked.
    func shardDistributionMetadata(for entryID: UUID) throws -> ShardDistributionMetadata? {
        guard let entry   = try self.fetchEntry(by: entryID) else { return nil }
        guard let cipher  = entry.shardDistributionEncrypted else { return nil }
        let vaultKey  = try self.currentKey()
        let box       = try AES.GCM.SealedBox(combined: cipher)
        let plaintext = try AES.GCM.open(box, using: vaultKey, authenticating: entry.aad(for: .shardDistribution))
        return try JSONDecoder().decode(ShardDistributionMetadata.self, from: plaintext)
    }

    // MARK: - Delivery tracking

    /// Mark every active ShardRecord distributed to `contactIdentifier` as `.lost`.
    ///
    /// Called when `ContactManager` emits `contactKeyRotated` for a contact while
    /// the vault is unlocked. The contact's new identity key makes their stored
    /// shard bytes permanently inaccessible — the trustee's app auto-returns them
    /// via `.handback`, but Alice's recovery health should degrade immediately
    /// rather than waiting for the next `.inquire` probe cycle.
    ///
    /// Only targets `.pending` and `.confirmed` shards — `.revokePending`,
    /// `.revoked`, and `.lost` are already in a terminal or in-flight state.
    ///
    /// Silent no-op when the vault is locked (`.inquire` probes will resolve the
    /// status once Alice unlocks and the next outbound bundle is sent to Bob).
    func markShardsLost(forContact contactIdentifier: String) {
        guard let vaultKey = try? self.currentKey() else { return }
        let entries = (try? self.fetchAllEntries()) ?? []
        var changed = false

        for entry in entries {
            guard let cipher = entry.shardDistributionEncrypted else { continue }
            guard
                let box       = try? AES.GCM.SealedBox(combined: cipher),
                let plaintext = try? AES.GCM.open(box, using: vaultKey, authenticating: entry.aad(for: .shardDistribution)),
                var meta      = try? JSONDecoder().decode(ShardDistributionMetadata.self, from: plaintext)
            else { continue }

            var modified = false
            for i in meta.shards.indices
                where meta.shards[i].contactIdentifier == contactIdentifier
                   && (meta.shards[i].status == .pending || meta.shards[i].status == .confirmed) {
                meta.shards[i].status = .lost
                modified = true
            }
            guard modified else { continue }

            guard
                let updated  = try? JSONEncoder().encode(meta),
                let sealed   = try? AES.GCM.seal(updated, using: vaultKey, nonce: AES.GCM.Nonce(), authenticating: entry.aad(for: .shardDistribution)),
                let combined = sealed.combined
            else { continue }

            entry.shardDistributionEncrypted = combined
            changed = true
        }

        if changed {
            try? self.modelContext.save()
        }
    }

    /// Update the status of one ShardRecord identified by its `attributeID`.
    ///
    /// Walks every entry's encrypted ShardDistributionMetadata until a matching
    /// `attributeID` is found, applies `newStatus`, and re-seals. No-op if no match.
    /// Requires the vault unlocked.
    ///
    /// Used by ShardCustodyManager for `.acknowledge` (`.confirmed`) and
    /// `.notFound` (`.lost`) inbound traffic.
    func updateShardStatus(attributeID: UUID, to newStatus: ShardStatus) throws {
        let vaultKey = try self.currentKey()
        let entries  = try self.fetchAllEntries()

        for entry in entries {
            guard let cipher = entry.shardDistributionEncrypted else { continue }
            guard
                let box       = try? AES.GCM.SealedBox(combined: cipher),
                let plaintext = try? AES.GCM.open(box, using: vaultKey, authenticating: entry.aad(for: .shardDistribution)),
                var meta      = try? JSONDecoder().decode(ShardDistributionMetadata.self, from: plaintext)
            else { continue }

            guard let idx = meta.shards.firstIndex(where: { $0.attributeID == attributeID }) else { continue }

            // Reject illegal state machine transitions — prevents inbound traffic from
            // un-revoking a shard or degrading a confirmed one back to pending.
            guard ShardStatus.isValidTransition(from: meta.shards[idx].status, to: newStatus) else { return }

            meta.shards[idx].status = newStatus

            let updated = try JSONEncoder().encode(meta)
            let sealed  = try AES.GCM.seal(updated, using: vaultKey, nonce: AES.GCM.Nonce(), authenticating: entry.aad(for: .shardDistribution))
            guard let combined = sealed.combined else { throw VaultError.encryptionFailed }

            entry.shardDistributionEncrypted = combined
            try self.modelContext.save()

            return
        }

        // No per-entry shard matched — check BEK shard metadata.
        try? self.updateBEKShardStatus(attributeID: attributeID, to: newStatus)
    }

    // MARK: - Deferred status updates

    /// Apply any `PendingShardStatusUpdate` rows that were queued while the vault
    /// was locked.
    ///
    /// Called from `unlock()` after the auth context is set. Each row is decrypted
    /// with the shard custody key, applied via `updateShardStatus`, then deleted.
    /// Rows that fail to apply (entry no longer exists, decryption error) are also
    /// deleted — they can never succeed on retry.
    func drainPendingShardStatusUpdates() {
        guard let custodyKey = try? self.keyManager.deriveShardCustodyKey() else { return }

        let rows = (try? self.modelContext.fetch(FetchDescriptor<PendingShardStatusUpdate>())) ?? []
        var changed = false

        for row in rows {
            guard
                let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                let plaintext = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
                let payload   = try? JSONDecoder().decode(PendingShardStatusUpdate.Payload.self, from: plaintext)
            else {
                self.modelContext.delete(row)
                changed = true
                continue
            }

            // Apply regardless of result — a missing entry is not retryable.
            try? self.updateShardStatus(attributeID: payload.attributeID, to: payload.newStatus)
            self.modelContext.delete(row)
            changed = true
        }

        if changed { try? self.modelContext.save() }
    }

    // MARK: - Potentially lost shards

    /// Check shards that disappeared from a trustee's custodyManifest while the vault
    /// was locked and mark confirmed ones as .lost.
    ///
    /// Called from unlock() after drainPendingShardStatusUpdates() so all queued
    /// .confirmed transitions are applied first — ensuring .lost only replaces
    /// .confirmed, never .pending (can't lose something the trustee never had).
    ///
    /// All PotentiallyLostShard rows are deleted regardless of outcome; the vault
    /// is now unlocked and serves as the authoritative source of truth.
    func drainPotentiallyLostShards() {
        let rows = (try? self.modelContext.fetch(FetchDescriptor<PotentiallyLostShard>())) ?? []
        guard !rows.isEmpty else { return }

        guard let custodyKey = try? self.keyManager.deriveShardCustodyKey() else {
            for row in rows { self.modelContext.delete(row) }
            try? self.modelContext.save()
            return
        }

        for row in rows {
            guard
                let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                let plaintext = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
                let payload   = try? JSONDecoder().decode(PotentiallyLostShard.Payload.self, from: plaintext),
                payload.isAbsent
            else { continue }

            let records = self.shardRecordsForTrustee(payload.contactIdentifier)
            if records.first(where: { $0.attributeID == payload.attributeID })?.status == .confirmed {
                try? self.updateShardStatus(attributeID: payload.attributeID, to: .lost)
            }
        }

        for row in rows { self.modelContext.delete(row) }
        try? self.modelContext.save()
    }

    // MARK: - Recovery health

    /// Count of shards in a distribution that are still active (pending or confirmed).
    /// Shared by PEK and BEK erosion logic so the definition of "active" is one place.
    private func activeShardCount(in meta: ShardDistributionMetadata) -> Int {
        meta.shards.filter { $0.status == .pending || $0.status == .confirmed }.count
    }

    /// Recompute `recoveryHealth` (PEK) and `bekErosion` (BEK) in one pass.
    ///
    /// Best-effort: silently skips entries that fail to decrypt (corrupted or
    /// from a concurrent lock). Sets both properties to nil if the vault is locked.
    /// Called directly from unlock() (no save occurs there) and automatically
    /// via the ModelContext.didSave observer for all other mutations.
    func recomputeRecoveryHealth() {
        guard let vaultKey = try? self.currentKey() else {
            self.recoveryHealth = nil
            self.bekErosion     = nil
            return
        }

        // — PEK health —
        let entries = (try? self.fetchAllEntries()) ?? []
        var affected: [RecoveryHealthSummary.AffectedEntry] = []

        for entry in entries {
            guard let cipher = entry.shardDistributionEncrypted else { continue }
            guard
                let box       = try? AES.GCM.SealedBox(combined: cipher),
                let plaintext = try? AES.GCM.open(box, using: vaultKey, authenticating: entry.aad(for: .shardDistribution)),
                let meta      = try? JSONDecoder().decode(ShardDistributionMetadata.self, from: plaintext)
            else {
                // Shard distribution data exists but is unreadable — tampered or corrupt.
                // Surface as critical so the user knows this entry's recovery is broken.
                let labelPayload  = try? self.decryptLabelPayload(for: entry)
                affected.append(RecoveryHealthSummary.AffectedEntry(
                    entryID:   entry.id,
                    label:     labelPayload?.label ?? "–",
                    entryType: labelPayload?.type  ?? .note,
                    status:    .critical,
                    active:    0,
                    threshold: 1
                ))
                continue
            }

            let active = self.activeShardCount(in: meta)
            guard active < meta.threshold else { continue }

            let payload   = try? self.decryptLabelPayload(for: entry)
            let status: RecoveryHealthSummary.EntryStatus = active == 0 ? .critical : .degraded
            affected.append(RecoveryHealthSummary.AffectedEntry(
                entryID:   entry.id,
                label:     payload?.label ?? "–",
                entryType: payload?.type  ?? .note,
                status:    status,
                active:    active,
                threshold: meta.threshold
            ))
        }

        affected.sort {
            if $0.status == $1.status { return $0.label < $1.label }
            return $0.status == .critical
        }

        self.recoveryHealth = RecoveryHealthSummary(affected: affected)

        // — BEK erosion —
        if let meta = try? self.bekShardMetadata() {
            let active = self.activeShardCount(in: meta)
            self.bekErosion = active < meta.threshold ? (active, meta.threshold) : nil
        } else {
            self.bekErosion = nil
        }
    }

    // MARK: - Trustee record lookup

    /// Return all ShardRecord stubs for shards distributed to `contactIdentifier`.
    ///
    /// Used by `ShardCustodyManager` to build manifest fields and process
    /// inbound manifests without holding a direct reference to VaultManager internals.
    /// Returns an empty array when the vault is locked or no matching shards exist.
    func shardRecordsForTrustee(_ contactIdentifier: String) -> [(attributeID: UUID, status: ShardStatus)] {
        guard let vaultKey = try? self.currentKey() else { return [] }
        
        let entries = (try? self.fetchAllEntries()) ?? []
        var result: [(attributeID: UUID, status: ShardStatus)] = []

        for entry in entries {
            guard let cipher = entry.shardDistributionEncrypted else { continue }
            guard
                let box       = try? AES.GCM.SealedBox(combined: cipher),
                let plaintext = try? AES.GCM.open(box, using: vaultKey, authenticating: entry.aad(for: .shardDistribution)),
                let meta      = try? JSONDecoder().decode(ShardDistributionMetadata.self, from: plaintext)
            else { continue }

            for shard in meta.shards where shard.contactIdentifier == contactIdentifier {
                result.append((shard.attributeID, shard.status))
            }
        }
        return result
    }

}

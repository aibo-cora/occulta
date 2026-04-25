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

    /// Absorb one `.respond` shard into the reconstruction buffer.
    ///
    /// Steps:
    ///   1. Best-effort signature verification against the owner's current
    ///      identity public key. A mismatch is logged but does not abort —
    ///      on a new device the SE identity key has rotated and every
    ///      verification fails by design. The GCM authentication tag at
    ///      finalisation is the real integrity check.
    ///   2. Reject duplicates: if a row already encodes the same
    ///      `signedAttribute.id`, drop the new copy silently.
    ///   3. Seal `ReconstructShard.Payload` under the recovery buffer key
    ///      with AAD = row.aad(); insert.
    ///   4. Opportunistically call `tryFinalizeReconstruction(entryID:)` —
    ///      if the vault is locked, the call returns without touching state
    ///      and finalisation is retried on the next vault unlock.
    func acceptReturnedShard(_ attribute: SignedAttribute) throws {
        guard attribute.category == .shard, let entryID = attribute.entryID else {
            throw VaultError.decryptionFailed
        }

        // ── 1. Best-effort signature verification ────────────────────────
        if let identity = try? self.keyManager.retrieveIdentity(),
           !attribute.verify(against: identity) {
            #if DEBUG
            debugPrint("acceptReturnedShard: signature did not verify against current identity (new-device path or tampered shard).")
            #endif
        }

        // ── 2. Deduplicate by SignedAttribute.id within the buffer ──────
        let existing = try self.decryptAllReconstructShards()
        if existing.contains(where: { $0.payload.attrID == attribute.id }) {
            return
        }

        // ── 3. Seal + insert ─────────────────────────────────────────────
        guard let bufferKey = try self.keyManager.deriveRecoveryBufferKey() else {
            throw VaultError.keyDerivationFailed
        }

        let rowID   = UUID()
        let aad     = Self.reconstructRowAAD(id: rowID)
        let payload = ReconstructShard.Payload(
            entryID:         entryID,
            attrID:          attribute.id,
            signedAttribute: attribute
        )
        let plaintext = try JSONEncoder().encode(payload)
        let sealed    = try AES.GCM.seal(plaintext, using: bufferKey, nonce: AES.GCM.Nonce(), authenticating: aad)
        guard let combined = sealed.combined else { throw VaultError.encryptionFailed }

        let row = ReconstructShard(id: rowID, encryptedPayload: combined)
        self.modelContext.insert(row)
        try self.modelContext.save()

        // ── 4. Opportunistic finalise ────────────────────────────────────
        try? self.tryFinalizeReconstruction(entryID: entryID)
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
        let metaPlaintext = try AES.GCM.open(metaBox, using: vaultKey, authenticating: entry.aad())
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

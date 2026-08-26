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
            let existing = try self.decryptAllReconstructShards()
            if let dup = existing.first(where: {
                $0.payload.entryID == entryID && $0.payload.senderIdentifier == senderIdentifier
            }) {
                if dup.payload.attrID == attribute.id { return } // identical re-delivery
                self.modelContext.delete(dup.row)                // sender is replacing their prior share
            }

            guard let bufferKey = try self.keyManager.deriveRecoveryBufferKey() else {
                throw VaultError.keyDerivationFailed
            }

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

            let row = ReconstructShard(id: rowID, encryptedPayload: combined)
            self.modelContext.insert(row)
            try self.modelContext.save()

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

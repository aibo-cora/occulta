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
                attrID:            attributes[i].id,
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
            authenticating: entry.aad()
        )
        
        guard let combined = sealed.combined else { throw VaultError.encryptionFailed }
        
        entry.shardDistributionEncrypted = combined
        
        try self.modelContext.save()

        return attributes
    }

    // MARK: - Outbound delivery

    /// Prepare shards and encrypt each as a `.occ` bundle ready for sharing.
    ///
    /// Returns one `(contactIdentifier, occData)` tuple per recipient, in the
    /// same order as `recipients`. The caller writes each blob to a temp `.occ`
    /// file and presents the share sheet for the corresponding contact.
    ///
    /// Requires the vault unlocked. Requires each recipient to have ML-KEM key
    /// material — `encryptBundle` throws `trusteeLacksQuantumMaterial` if absent.
    func distributeShards(
        for entryID: UUID,
        threshold: Int,
        recipients: [Contact.Profile],
        contactManager: ContactManager
    ) throws -> [(contactIdentifier: String, occData: Data)] {
        // Capture old attrIDs per contact before prepareShards replaces the distribution.
        // Contacts found here receive a .replace op; new contacts receive .distribute.
        let oldAttrIDs: [String: UUID] = {
            guard let meta = try? self.shardDistributionMetadata(for: entryID) else { return [:] }
            return Dictionary(uniqueKeysWithValues: meta.shards.map { ($0.contactIdentifier, $0.attrID) })
        }()

        let attributes = try self.prepareShards(for: entryID, threshold: threshold, recipients: recipients)

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

    // MARK: - Shard status reader

    /// Read the ShardDistributionMetadata for an entry without modifying it.
    ///
    /// Returns nil when no distribution exists or when the vault is locked.
    func shardDistributionMetadata(for entryID: UUID) throws -> ShardDistributionMetadata? {
        guard let entry   = try self.fetchEntry(by: entryID) else { return nil }
        guard let cipher  = entry.shardDistributionEncrypted else { return nil }
        let vaultKey  = try self.currentKey()
        let box       = try AES.GCM.SealedBox(combined: cipher)
        let plaintext = try AES.GCM.open(box, using: vaultKey, authenticating: entry.aad())
        return try JSONDecoder().decode(ShardDistributionMetadata.self, from: plaintext)
    }

    // MARK: - Delivery tracking

    /// Update the status of one ShardRecord identified by its `attrID`.
    ///
    /// Walks every entry's encrypted ShardDistributionMetadata until a matching
    /// `attrID` is found, applies `newStatus`, and re-seals. No-op if no match.
    /// Requires the vault unlocked.
    ///
    /// Used by ShardCustodyManager for `.acknowledge` (`.confirmed`) and
    /// `.notFound` (`.lost`) inbound traffic.
    func updateShardStatus(attrID: UUID, to newStatus: ShardStatus) throws {
        let vaultKey = try self.currentKey()
        let entries  = try self.fetchAllEntries()

        for entry in entries {
            guard let cipher = entry.shardDistributionEncrypted else { continue }
            guard
                let box       = try? AES.GCM.SealedBox(combined: cipher),
                let plaintext = try? AES.GCM.open(box, using: vaultKey, authenticating: entry.aad()),
                var meta      = try? JSONDecoder().decode(ShardDistributionMetadata.self, from: plaintext)
            else { continue }

            guard let idx = meta.shards.firstIndex(where: { $0.attrID == attrID }) else { continue }
            meta.shards[idx].status = newStatus

            let updated = try JSONEncoder().encode(meta)
            let sealed  = try AES.GCM.seal(updated, using: vaultKey, nonce: AES.GCM.Nonce(), authenticating: entry.aad())
            guard let combined = sealed.combined else { throw VaultError.encryptionFailed }

            entry.shardDistributionEncrypted = combined
            try self.modelContext.save()
            return
        }
    }

    // MARK: - Reconciliation probing

    /// Build `.inquire` operations for every stale shard owed to `contactIdentifier`.
    ///
    /// A shard is probe-eligible when:
    ///   • status is `.pending` and `distributedAt` is more than 7 days ago, OR
    ///   • status is `.confirmed` and `lastProbedAt` is nil or more than 90 days ago.
    ///
    /// Stamps `lastProbedAt = now` on every eligible ShardRecord and re-seals the
    /// metadata before returning so the probe timer is reset even if the bundle is
    /// never delivered (prevents rapid re-probing).
    ///
    /// Returns `nil` when no eligible shards exist for this contact.
    func pendingInquireOperations(for contactIdentifier: String) throws -> [OccultaBundle.ShardOperation]? {
        let vaultKey = try self.currentKey()
        let entries  = try self.fetchAllEntries()
        let now      = Date()
        let sevenDaysAgo   = now.addingTimeInterval(-7  * 24 * 3600)
        let ninetyDaysAgo  = now.addingTimeInterval(-90 * 24 * 3600)

        var ops = [OccultaBundle.ShardOperation]()

        for entry in entries {
            guard let cipher = entry.shardDistributionEncrypted else { continue }
            guard
                let box       = try? AES.GCM.SealedBox(combined: cipher),
                let plaintext = try? AES.GCM.open(box, using: vaultKey, authenticating: entry.aad()),
                var meta      = try? JSONDecoder().decode(ShardDistributionMetadata.self, from: plaintext)
            else { continue }

            var dirty = false
            for i in meta.shards.indices where meta.shards[i].contactIdentifier == contactIdentifier {
                let shard = meta.shards[i]
                let eligible: Bool
                switch shard.status {
                case .pending:
                    eligible = (shard.distributedAt.map { $0 < sevenDaysAgo } ?? true)
                case .confirmed:
                    eligible = (shard.lastProbedAt.map { $0 < ninetyDaysAgo } ?? true)
                default:
                    eligible = false
                }
                guard eligible else { continue }

                ops.append(OccultaBundle.ShardOperation(kind: .inquire, attributeID: shard.attrID))
                meta.shards[i].lastProbedAt = now
                dirty = true
            }

            guard dirty else { continue }
            let updated = try JSONEncoder().encode(meta)
            let sealed  = try AES.GCM.seal(updated, using: vaultKey, nonce: AES.GCM.Nonce(), authenticating: entry.aad())
            guard let combined = sealed.combined else { throw VaultError.encryptionFailed }
            entry.shardDistributionEncrypted = combined
        }

        if !ops.isEmpty { try self.modelContext.save() }
        return ops.isEmpty ? nil : ops
    }

    // MARK: - Delivery tracking

    /// Mark a shard as delivered for a specific contact.
    ///
    /// Call this after the .occ bundle containing the shard has been handed
    /// to the basket pipeline. Updates the encrypted ShardDistributionMetadata.
    func markShardDelivered(for entryID: UUID, contactIdentifier: String) throws {
        let vaultKey    = try self.currentKey()
        guard let entry = try self.fetchEntry(by: entryID) else { throw VaultError.entryNotFound }
        guard let encrypted = entry.shardDistributionEncrypted else { return }

        let box       = try AES.GCM.SealedBox(combined: encrypted)
        let plaintext = try AES.GCM.open(box, using: vaultKey, authenticating: entry.aad())

        var meta = try JSONDecoder().decode(ShardDistributionMetadata.self, from: plaintext)
        if let idx = meta.shards.firstIndex(where: { $0.contactIdentifier == contactIdentifier }) {
            meta.shards[idx].status = .confirmed
        }

        let updated = try JSONEncoder().encode(meta)
        let sealed  = try AES.GCM.seal(updated, using: vaultKey, nonce: AES.GCM.Nonce(), authenticating: entry.aad())
        
        guard let combined = sealed.combined else { throw VaultError.encryptionFailed }
        
        entry.shardDistributionEncrypted = combined
        
        try self.modelContext.save()
    }
}

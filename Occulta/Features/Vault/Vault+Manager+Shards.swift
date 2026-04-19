//
//  Vault+Manager+Shards.swift
//  Occulta
//
//  Phase 6: SSS shard preparation for VaultManager.
//  Splits the vault key for a given entry into signed shards ready for delivery
//  via the existing .occ basket pipeline. Does NOT deliver shards.
//

import Foundation
import CryptoKit

extension VaultManager {

    // MARK: - Shard preparation

    /// Split the vault key for `entryID` into signed shards — one per recipient.
    ///
    /// Each returned `SignedAttribute` has `category: .shard`, is signed with the
    /// SE identity key, and contains the raw GF(2^8) shard bytes as its value.
    /// The caller feeds these into the .occ basket pipeline for delivery.
    ///
    /// Steps (in order):
    ///   1. Assert vault is unlocked.
    ///   2. Extract 32-byte vault key bytes into a local buffer.
    ///   3. SSS-split into n shards (one per recipient).
    ///   4. For each shard: compute the SignedAttribute signing payload, sign
    ///      with the SE identity key, build a SignedAttribute(.shard).
    ///   5. Encrypt and persist ShardDistributionMetadata on the entry.
    ///   6. Zero all intermediate key and shard buffers via defer.
    ///   7. Return the signed attributes.
    ///
    /// - Parameters:
    ///   - entryID:    The VaultEntry whose key is being split.
    ///   - threshold:  Minimum shards for reconstruction (k ≥ 2).
    ///   - recipients: Contacts receiving one shard each (n = count).
    /// - Returns: `[SignedAttribute]` in the same order as `recipients`.
    func prepareShards(
        for entryID: UUID,
        threshold: Int,
        recipients: [Contact.Profile]
    ) throws -> [SignedAttribute] {
        guard let key   = vaultKey                        else { throw VaultError.locked }
        guard let entry = try fetchEntry(by: entryID)     else { throw VaultError.entryNotFound }

        let n = recipients.count

        // ── 1. Extract raw vault key bytes ───────────────────────────────────
        // ⚠️ vaultKeyBytes is cleared by defer below — do not return early
        // between here and the end of the function without ensuring defer fires.
        var vaultKeyBytes = Data()
        key.withUnsafeBytes { vaultKeyBytes = Data($0) }

        defer {
            // Zero the local key copy. Swift Data uses COW; this clears the
            // buffer that withUnsafeBytes gave us, not vaultKey itself.
            for i in vaultKeyBytes.indices { vaultKeyBytes[i] = 0 }
        }

        // ── 2. Split ─────────────────────────────────────────────────────────
        var rawShares = try ShamirSecretSharing.split(
            secret: vaultKeyBytes,
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
            let payload = SignedAttribute.signingPayload(
                id: attrID, category: .shard, value: shardData
            )
            let signature = try keyManager.signData(payload)

            attributes.append(SignedAttribute(
                id:        attrID,
                label:     "vault-shard-\(i + 1)-of-\(n)",
                value:     shardData,
                category:  .shard,
                signature: signature,
                createdAt: createdAt
            ))
        }

        // ── 4. Persist encrypted ShardDistributionMetadata on the entry ──────
        let contactIDs = recipients.map { $0.identifier }
        let meta = ShardDistributionMetadata(
            threshold:          threshold,
            total:              n,
            contactIdentifiers: contactIDs,
            deliveryStatus:     Dictionary(uniqueKeysWithValues: contactIDs.map { ($0, false) })
        )
        let metaData = try JSONEncoder().encode(meta)
        let sealed   = try AES.GCM.seal(
            metaData,
            using:          key,
            nonce:          AES.GCM.Nonce(),
            authenticating: entry.aad()
        )
        guard let combined = sealed.combined else { throw VaultError.encryptionFailed }
        entry.shardDistributionEncrypted = combined
        try modelContext.save()

        return attributes
    }

    // MARK: - Delivery tracking

    /// Mark a shard as delivered for a specific contact.
    ///
    /// Call this after the .occ bundle containing the shard has been handed
    /// to the basket pipeline. Updates the encrypted ShardDistributionMetadata.
    func markShardDelivered(for entryID: UUID, contactIdentifier: String) throws {
        guard let key   = vaultKey                    else { throw VaultError.locked }
        guard let entry = try fetchEntry(by: entryID) else { throw VaultError.entryNotFound }
        guard let encrypted = entry.shardDistributionEncrypted else { return }

        let box       = try AES.GCM.SealedBox(combined: encrypted)
        let plaintext = try AES.GCM.open(box, using: key, authenticating: entry.aad())

        var meta = try JSONDecoder().decode(ShardDistributionMetadata.self, from: plaintext)
        meta.deliveryStatus[contactIdentifier] = true

        let updated = try JSONEncoder().encode(meta)
        let sealed  = try AES.GCM.seal(updated, using: key, nonce: AES.GCM.Nonce(), authenticating: entry.aad())
        guard let combined = sealed.combined else { throw VaultError.encryptionFailed }
        entry.shardDistributionEncrypted = combined
        try modelContext.save()
    }
}

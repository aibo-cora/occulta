//
//  BackupEncryptionKey+Model.swift
//  Occulta
//
//  SwiftData model for the vault-level Backup Encryption Key (BEK).
//
//  The BEK is a random 32-byte key used to seal the `.occbak` export file.
//  It is Shamir-split and distributed to trustees so a new device can
//  reconstruct it from k shards and decrypt a backup file to restore the vault.
//
//  Privacy model — encryption at rest:
//  - `id` (plaintext) — random per row, bound into AAD.
//  - `encryptedPayload` — AES-GCM sealed under the vault key (biometric-gated).
//    Contains the raw 32-byte BEK, a stable distributionID for shard routing,
//    and the SSS shard distribution metadata for BEK shards.
//  - Cold-disk forensics learns "a BEK exists" — nothing about the key bytes,
//    trustees, or threshold. Resolving requires a biometric unlock.
//
//  Lifecycle:
//  - Inserted by VaultManager.setupBEK() on first backup configuration.
//  - Delete-and-replace on every write (same convention as GlobalShardConfig):
//    the new row gets a fresh id, keeping the AAD contract simple.
//  - Updated on distribution (new shard metadata), status transitions,
//    reconstruction (post-device-migration re-wrap), and rotation.
//  - At most one row exists at any time.
//

import Foundation
import SwiftData

@Model
final class BackupEncryptionKey {

    // MARK: Persisted fields

    /// Random per-row identifier. Bound into AAD; mutating invalidates decryption.
    var id: UUID = UUID()

    /// Sealed `Payload`: nonce(12B) ∥ ciphertext ∥ tag(16B) — CryptoKit .combined.
    /// AAD = aad(). Key = vault key (biometric-gated, same wrapping as per-entry PEKs).
    var encryptedPayload: Data = Data()

    // MARK: Init

    init(id: UUID = UUID(), encryptedPayload: Data) {
        self.id               = id
        self.encryptedPayload = encryptedPayload
    }

    // MARK: AAD

    /// Authenticated additional data for AES-GCM seal/open of `encryptedPayload`.
    ///
    ///   id.uuidString (UTF-8)   — 36 bytes
    ///
    /// ⚠️ Sealed contract. Any change makes existing ciphertext unreadable.
    func aad() -> Data {
        self.id.uuidString.data(using: .utf8)!
    }

    // MARK: Sealed payload

    /// Plaintext sealed inside `encryptedPayload`.
    struct Payload: Codable {
        /// Raw 32-byte BEK. Sealed under vault key; never persisted in plaintext.
        let bekBytes: Data
        /// Stable UUID used as `entryID` in every BEK `SignedAttribute(.shard)`.
        /// Changes only on explicit BEK rotation, invalidating the prior distribution.
        let distributionID: UUID
        /// SSS shard distribution state for BEK shards. nil until first distribution.
        var shardMetadata: ShardDistributionMetadata?
    }
}

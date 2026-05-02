//
//  PendingShardRevoke+Model.swift
//  Occulta
//
//  SwiftData model for queued `.revoke` operations Alice owes to trustees.
//
//  Created in two situations:
//  1. Alice deletes a vault entry that has distributed shards — one row is
//     inserted per active shard (one shard = one row).
//  2. Alice manually revokes a single shard via `queueRevoke(attributeID:for:)` —
//     used when the user removes a trustee from a live distribution without
//     deleting the entry.
//
//  One row per attributeID. Batching across shards to the same trustee happens
//  at the bundle level via `SealedPayload.shardOperations` — no merge logic here.
//
//  Privacy model — encryption at rest:
//  - Plaintext columns (`id`) carry no identifying data.
//  - `ownerID` and `attributeID` live inside `encryptedPayload`,
//    sealed under the shard custody key with AAD = aad().
//  - Cold-disk forensics learns "Alice has N pending revocations" — nothing
//    about which contacts or which shards. Resolving requires the SE-protected
//    custody key.
//
//  Lifecycle:
//  - Inserted when a vault entry with shard distribution is deleted.
//  - Read before every outbound bundle to each trustee; `.revoke` operations
//    are included in `SealedPayload.shardOperations`.
//  - Deleted on send (fire-and-forget). There is no `.revokeAcknowledged`
//    response — trustees silently delete the matching CustodyShard row.
//    Missed revocations leave cryptographically inert orphan shards on the
//    trustee's device; this is safe since the deleted entry's content is gone.
//

import Foundation
import SwiftData

@Model
final class PendingShardRevoke {

    // MARK: Persisted fields

    /// Random per-row identifier. Bound into AAD; mutating invalidates decryption.
    var id: UUID = UUID()

    /// Sealed `Payload`: nonce(12B) ∥ ciphertext ∥ tag(16B) — CryptoKit .combined.
    /// AAD = aad(). Key = `KeyManagerProtocol.deriveShardCustodyKey()`.
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

    // MARK: - Sealed payload

    /// Plaintext sealed inside `encryptedPayload`.
    ///
    /// `ownerID` is `Contact.Profile.identifier` of the trustee.
    /// `attributeID` is the `SignedAttribute.id` of the shard to revoke.
    struct Payload: Codable {
        let ownerID:     String
        let attributeID: UUID
    }
}

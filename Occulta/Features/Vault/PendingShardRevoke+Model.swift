//
//  PendingShardRevoke+Model.swift
//  Occulta
//
//  SwiftData model for queued `.revoke` operations Alice owes to trustees.
//
//  Created in two situations:
//  1. Alice deletes a vault entry that has distributed shards — one row is
//     upserted per trustee who holds a shard for that entry.
//  2. Alice manually revokes a single shard via `queueRevoke(attrID:for:)` —
//     used when the user removes a trustee from a live distribution without
//     deleting the entry.
//
//  Multiple attrIDs (e.g. Alice deletes several entries or revokes several
//  shards before sending a message to Bob) are merged into the same row so
//  revocations for the same trustee travel together in one bundle.
//
//  Privacy model — encryption at rest:
//  - Plaintext columns (`id`, `createdAt`) carry no identifying data.
//  - `contactIdentifier` and `attrIDs` live inside `encryptedPayload`,
//    sealed under the shard custody key with AAD = aad().
//  - Cold-disk forensics learns "Alice has N pending revocations" — nothing
//    about which contacts or which shards. Resolving requires the SE-protected
//    custody key.
//
//  Lifecycle:
//  - Inserted (or updated) when a vault entry with shard distribution is deleted.
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
    /// `contactIdentifier` is `Contact.Profile.identifier` of the trustee.
    /// `attrIDs` are the `SignedAttribute.id` values of all shards to revoke
    /// for this trustee — accumulated across multiple entry deletions before
    /// the next outbound bundle is sent.
    struct Payload: Codable {
        let contactIdentifier: String
        let attrIDs:           [UUID]
    }
}

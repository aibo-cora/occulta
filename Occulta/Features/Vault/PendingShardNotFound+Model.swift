//
//  PendingShardNotFound+Model.swift
//  Occulta
//
//  SwiftData model for queued `.notFound` operations Bob owes to Alice after
//  receiving a `.inquire` probe for a shard he no longer holds.
//
//  Created when `ShardCustodyManager.handleInquire` processes a probe for an
//  attributeID with no matching CustodyShard row. Bob piggybacks the response
//  on his next outbound bundle to Alice.
//  The row is deleted on send (fire-and-forget). Alice's `handleNotFound` calls
//  `updateShardStatus(attrID:to:.lost)`, which is idempotent, so duplicate
//  delivery is safe.
//
//  Privacy model — encryption at rest:
//  - Plaintext columns (`id`) carry no identifying data.
//  - `ownerContactIdentifier` and `attributeIDs` live inside `encryptedPayload`,
//    sealed under the shard custody key with AAD = aad().
//  - Cold-disk forensics learns "Bob has N pending not-found responses" — nothing
//    about which contacts or shards. Resolving requires the SE-protected custody key.
//
//  Lifecycle:
//  - Inserted (or updated) when `handleInquire` finds no CustodyShard for a probed attrID.
//  - One row per owner contact. Multiple unknown shards from the same owner are
//    merged into one row so responses travel together in one bundle.
//  - Read before every outbound bundle to Alice; `.notFound` operations
//    (one per attributeID) are added to `SealedPayload.shardOperations`.
//  - Deleted on send. If never sent, retried on the next outbound bundle.
//

import Foundation
import SwiftData

@Model
final class PendingShardNotFound {

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

    // MARK: Sealed payload

    /// Plaintext sealed inside `encryptedPayload`.
    ///
    /// `ownerContactIdentifier` is `Contact.Profile.identifier` of the shard owner (Alice).
    /// Used to route the response to the correct outbound bundle.
    ///
    /// `attributeIDs` are the `SignedAttribute.id` values from the `.inquire` probes
    /// for which no matching CustodyShard was found. Alice's `handleNotFound` marks
    /// each corresponding ShardRecord status as `.lost` on receipt.
    struct Payload: Codable {
        let ownerContactIdentifier: String
        let attributeIDs:           [UUID]
    }
}

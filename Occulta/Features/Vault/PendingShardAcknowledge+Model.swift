//
//  PendingShardAcknowledge+Model.swift
//  Occulta
//
//  SwiftData model for queued `.acknowledge` operations Bob owes to Alice
//  after receiving one or more `.distribute` shard operations from her.
//
//  Created when `ShardCustodyManager.handleDistribute` stores a shard.
//  Bob piggybacks the acknowledgement on his next outbound bundle to Alice.
//  The row is deleted on send (fire-and-forget). Alice's `handleAcknowledge`
//  calls `updateShardStatus(attrID:to:.confirmed)`, which is idempotent, so
//  duplicate delivery (e.g. from the immediate-ack path in `OccultaApp`) is safe.
//
//  Privacy model — encryption at rest:
//  - Plaintext columns (`id`) carry no identifying data.
//  - `ownerContactIdentifier` and `attrIDs` live inside `encryptedPayload`,
//    sealed under the shard custody key with AAD = aad().
//  - Cold-disk forensics learns "Bob has N pending shard acks" — nothing about
//    which contacts or shards. Resolving requires the SE-protected custody key.
//
//  Lifecycle:
//  - Inserted (or updated) on every successful `handleDistribute`.
//  - One row per owner contact. Multiple shards from the same owner are merged
//    into the same row so acks travel together in one bundle.
//  - Read before every outbound bundle to Alice; `.acknowledge` operations
//    (one per attrID) are added to `SealedPayload.shardOperations`.
//  - Deleted on send. If never sent, retried on the next outbound bundle.
//

import Foundation
import SwiftData

@Model
final class PendingShardAcknowledge {

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
    /// Used to route the ack to the correct outbound bundle.
    ///
    /// `attrIDs` are the `SignedAttribute.id` values of the received shards.
    /// Accumulated across multiple `.distribute` ops before the next outbound
    /// bundle is sent. Alice's `handleAcknowledge` updates each shard's status
    /// to `.confirmed` on receipt.
    struct Payload: Codable {
        let ownerContactIdentifier: String
        let attrIDs:                [UUID]
    }
}

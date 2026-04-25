//
//  PendingShardRequest+Model.swift
//  Occulta
//
//  SwiftData model for the shard-request queue.
//
//  Privacy model — encryption at rest:
//  - The only plaintext columns are `id` (random per row) and `createdAt`
//    (coarse timestamp). Neither links the row to a contact or a specific shard.
//  - The requester's identifier, the target attrID, receivedAt, and status
//    all live inside `encryptedPayload`, sealed under the shard custody key
//    with AAD = aad(). Mirrors the CustodyShard / ReconstructShard pattern.
//  - Cold-disk forensics learns "Bob has N pending shard requests". Nothing
//    about who is asking or which shards are involved.
//
//  Lifecycle:
//  - Inserted on .request ShardOperation arrival; deduplicated by attrID
//    (decrypt all rows, find match, re-seal updated payload).
//  - Not deleted after completion — retained for audit. Prune records older
//    than 90 days in a terminal state in a future pass.
//

import Foundation
import SwiftData

// MARK: - RequestStatus

/// Lifecycle state of a shard request from a contact.
///
/// Raw strings are stable identifiers — never rename or reorder.
enum RequestStatus: String, Codable {
    /// Request arrived, Bob has not yet acted on it.
    case pending
    /// Bob confirmed he sent the .respond bundle.
    case sent
    /// Bob explicitly chose not to respond.
    case declined
    /// Bob's app could not find a CustodyShard matching the requested attrID.
    case notFound
}

// MARK: - PendingShardRequest

@Model
final class PendingShardRequest {

    // MARK: Persisted fields

    /// Random per-row identifier. Bound into AAD so any row-id mutation
    /// invalidates decryption. Not equal to the shard's attrID (that lives
    /// inside the sealed payload).
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
    struct Payload: Codable {
        /// Which shard is being requested (SignedAttribute.id).
        var attrID: UUID
        /// Contact.Profile.identifier of the requester — used to address the reply bundle.
        var requesterContactIdentifier: String
        /// Timestamp of the most recent request for this attrID.
        /// Updated on duplicate arrivals; the row's `createdAt` does not change.
        var receivedAt: Date
        var status: RequestStatus
    }
}

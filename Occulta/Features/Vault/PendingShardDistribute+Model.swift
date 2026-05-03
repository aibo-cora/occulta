//
//  PendingShardDistribute+Model.swift
//  Occulta
//
//  SwiftData model for queued `.distribute` / `.replace` operations Alice owes
//  to a trustee after calling `prepareShards`.
//
//  Inserted by `ShardCustodyManager.queueDistribute` when `markForDistribution`
//  prepares a fresh shard batch. Alice piggybacks the op on her next outbound
//  bundle to each trustee. The row is deleted on send (fire-and-forget); if
//  the bundle never reaches the trustee, the next outbound message retries
//  automatically because the row was already deleted on this call — and the
//  7-day `.inquire` probe will recover from prolonged silence.
//
//  One row per attributeID. Two ops for the same contact (rare: two rapid
//  markForDistribution calls) produce two rows and two ops in the same bundle.
//
//  Privacy model — encryption at rest:
//  - Plaintext columns (`id`) carry no identifying data.
//  - `contactIdentifier`, `signedAttribute` (contains raw shard bytes), and
//    `oldAttributeID` live inside `encryptedPayload`, sealed under the shard
//    custody key with AAD = aad().
//  - Cold-disk forensics learns "Alice has N pending shard distributes" —
//    nothing about which contacts or entries. Resolving requires the
//    SE-protected custody key.
//
//  Lifecycle:
//  - Inserted by `ShardCustodyManager.queueDistribute` after `prepareShards`.
//  - Read before every outbound bundle; `.distribute` / `.replace` operations
//    are added to `SealedPayload.shardOperations`.
//  - Deleted on send.
//

import Foundation
import SwiftData

@Model
final class PendingShardDistribute {

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
    /// `contactIdentifier` routes the op to the correct outbound bundle.
    /// `signedAttribute` is the shard to deliver (contains raw shard bytes).
    /// `oldAttributeID` non-nil → emit `.replace`; nil → emit `.distribute`.
    struct Payload: Codable {
        let contactIdentifier: String
        let signedAttribute:   SignedAttribute
        let oldAttributeID:    UUID?
    }
}

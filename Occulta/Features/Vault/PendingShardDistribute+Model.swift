//
//  PendingShardDistribute+Model.swift
//  Occulta
//
//  SwiftData model for queued `.distribute` / `.replace` operations Alice owes
//  to a trustee after calling `prepareShards`.
//
//  Inserted by `ShardCustodyManager.queueDistribute` when `markForDistribution`
//  prepares a fresh shard batch. Alice piggybacks the op on her next outbound
//  bundle to each trustee, and every one after that — the row is deleted only
//  once the trustee's own `custodyManifest` confirms the ID
//  (`processInboundManifest`), not on send, so a bundle lost in transit or a
//  shard the trustee's device dropped for any reason is retried automatically
//  on every subsequent bundle with no separate tracking needed. The 7-day
//  `.inquire` probe is a backstop for prolonged silence, not the retry path
//  itself.
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
//  - Read (never deleted) before every outbound bundle; `.distribute` /
//    `.replace` operations are added to `SealedPayload.shardOperations`.
//  - Deleted only in `processInboundManifest`, once the trustee's own
//    `custodyManifest` shows this attributeID present.
//

import Foundation
import SwiftData
import OccultaFormats

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

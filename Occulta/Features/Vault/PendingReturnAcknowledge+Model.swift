//
//  PendingReturnAcknowledge+Model.swift
//  Occulta
//
//  SwiftData model for a queued `.returnAcknowledged` operation Alice owes to Bob.
//
//  Created when Alice's ShardCustodyManager absorbs one or more `.handback`
//  operations (Bob returning shards). Alice piggybacks the acknowledgement
//  on her next outbound bundle to Bob. The row is deleted on send — not on
//  Bob's receipt — because Bob's cleanup is idempotent: if he resends shards
//  and Alice re-inserts them, reconstruction produces the same PEK, and Bob
//  will eventually receive the ack and delete his custody rows.
//
//  Privacy model — encryption at rest:
//  - Plaintext columns (`id`) carry no identifying data.
//  - `contactIdentifier` and `attrIDs` live inside `encryptedPayload`,
//    sealed under the recovery buffer key with AAD = aad().
//  - Cold-disk forensics learns "Alice has N pending acks" — nothing about
//    which contacts or shards. Resolving requires the SE-protected buffer key.
//
//  Lifecycle:
//  - Inserted after `acceptReturnedShard` stores shards in `ReconstructShard`.
//  - One row per trustee contact. Multiple returned shards from the same
//    trustee are batched into one row (all `attrIDs` together).
//  - Read before every outbound bundle to Bob; if present, a `.returnAcknowledged`
//    operation is added to `SealedPayload.shardOperations`.
//  - Deleted immediately on send. If never sent, retried on next outbound bundle.
//

import Foundation
import SwiftData

@Model
final class PendingReturnAcknowledge {

    // MARK: Persisted fields

    /// Random per-row identifier. Bound into AAD; mutating invalidates decryption.
    var id: UUID = UUID()

    /// Sealed `Payload`: nonce(12B) ∥ ciphertext ∥ tag(16B) — CryptoKit .combined.
    /// AAD = aad(). Key = `KeyManagerProtocol.deriveRecoveryBufferKey()`.
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
    /// `contactIdentifier` is `Contact.Profile.identifier` of the trustee (Bob)
    /// who returned the shards. Used to route the ack to the correct outbound bundle.
    ///
    /// `attrIDs` are the `SignedAttribute.id` values of the returned shards;
    /// carried verbatim in the `.returnAcknowledged` operation so Bob can match
    /// and delete exactly those `CustodyShard` rows.
    struct Payload: Codable {
        let contactIdentifier: String
        let attrIDs:           [UUID]
    }
}

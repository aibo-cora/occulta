//
//  ReconstructShard+Model.swift
//  Occulta
//
//  Transient SwiftData buffer for shards Alice's device collects during
//  per-entry PEK reconstruction. One row per `.respond` bundle absorbed;
//  deleted in bulk once a per-entry threshold is reached and reconstruction
//  succeeds.
//
//  Scope: this model handles per-entry PEK recovery only (the payload carries
//  an `entryID`). It is NOT used for vault-level BEK reconstruction on a new
//  device — that path collects KEY_B shards via the auto-handback flow
//  triggered by proximity re-exchange. See VAULT_BACKUP_GUIDE.md.
//
//  Privacy model — encryption at rest:
//  - The target entryID, the SignedAttribute.id (`attrID`), and the full
//    SignedAttribute live inside `encryptedPayload`, sealed under the recovery
//    buffer key with AAD = aad().
//  - Cold-disk forensics learns "Alice has N rows in the reconstruct buffer".
//    No entry identifiers, no shard counts per entry, no signature material.
//  - Querying "shards for entry X" requires decrypting every row. The buffer is
//    transient and small (active recoveries only), so the cost is negligible.
//
//  Lifecycle:
//  - Inserted on each `.respond` ShardOperation routed by ShardCustodyManager.
//  - Bulk-deleted after VaultManager runs reconstruction for the matching
//    entryID and re-wraps the recovered PEK under the current vault key.
//  - User-cancelled recovery: bulk-delete by walking and matching entryID.
//  - Stale rows (e.g. > 30 days, never reaching threshold) — periodic prune in a
//    future pass; not part of this scaffolding.
//
//  Why a separate model from CustodyShard:
//  - Different encryption keys (recovery buffer vs. shard custody) — the type
//    system enforces "you can't decrypt one with the other".
//  - Different lifecycles (transient queue vs. long-lived custody store).
//  - Different sealed payloads (reconstruct must carry entryID + attrID; custody
//    only carries the owner fingerprint + the signed attribute).
//

import Foundation
import SwiftData

@Model
final class ReconstructShard {

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
    /// `entryID` is needed to group shards toward the correct entry's threshold.
    /// `attrID` lets us deduplicate within an entry's group (one shard per
    /// trustee, identified by the SignedAttribute.id from the original split).
    struct Payload: Codable {
        let entryID: UUID
        let attrID:  UUID
        let signedAttribute: SignedAttribute
    }
}

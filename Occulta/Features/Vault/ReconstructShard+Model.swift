//
//  ReconstructShard+Model.swift
//  Occulta
//
//  Transient SwiftData buffer for shards Alice's device collects during
//  per-entry PEK reconstruction, and for BEK restore shards collected during
//  device recovery — the same recovery-buffer-keyed store, not two separate
//  mechanisms. One row per `.handback` bundle absorbed; bulk-deleted once a
//  group reaches its threshold and reconstruction succeeds.
//
//  Scope: a row belongs to the BEK-restore path when its `entryID` resolves to
//  no real `VaultEntry` — no `VaultEntry.id` is ever a BEK `distributionID`, so
//  the two populations never collide. BEK restore shards used to live in a
//  separate encrypted file (`backup-import-cache-shards.dat`); Bug 100 moved
//  them into this model instead, for the identical reason described below —
//  see `Vault+Manager+ReturnBuffer.swift`'s "BEK restore shards" section and
//  VAULT_BACKUP_GUIDE.md.
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
//  - Inserted on each `.handback` ShardOperation routed by ShardCustodyManager.
//  - Bulk-deleted after VaultManager runs reconstruction for the matching
//    entryID and re-wraps the recovered PEK under the current vault key.
//  - User-cancelled recovery: bulk-delete by walking and matching entryID.
//  - Stale rows (e.g. > 30 days, never reaching threshold) — periodic prune in a
//    future pass; not part of this scaffolding.
//
//  Why a separate model from CustodyShard:
//  - Different encryption keys (restore vault vs. shard custody) — the type
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
    /// AAD = aad(). Key = `KeyManagerProtocol.deriveRestoreVaultKey()`.
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
    /// `senderIdentifier`/`attestation` are Bug 94 remedy 2: at most one stored
    /// row per (entryID, senderIdentifier) is kept, so a threshold-reaching group
    /// requires distinct senders, not just distinct attrIDs.
    ///
    /// Unlike the BEK path, a per-entry group *does* reach the entry's real threshold:
    /// the entry is one this device split itself, so its `shardDistributionEncrypted`
    /// is on hand and `tryFinalizeReconstruction` verifies every shard against the
    /// owner identity. `AttestedShard` documents why the BEK path cannot do the same.
    struct Payload: Codable {
        let entryID: UUID
        let attrID:  UUID
        let signedAttribute:  SignedAttribute
        let senderIdentifier: String
        let attestation:      SignedAttribute?
        /// BEK-restore rows only (`entryID` resolves to no real `VaultEntry`) — which
        /// depth's restore this shard belongs to, `DepthCodec`-encoded (2 bytes, never a
        /// raw `Int`: see `RECOVERY_BUFFER_LAYERING.md` §6 item 9.1 for why a raw `Int`
        /// would make ciphertext length correlate with the depth's value). `nil` for
        /// per-entry PEK-reconstruction rows, which aren't depth-partitioned.
        let depth: Data?

        /// Explicit init, not the synthesized memberwise one — a `let` property with a
        /// declaration-site default (`= nil`) is fixed forever and never actually settable
        /// (Swift excludes it from Codable decoding too), which is the opposite of what a
        /// per-row value needs. A default *parameter* here gives every existing call site
        /// (which never mentions `depth`) the same free `nil` without that trap.
        init(
            entryID:          UUID,
            attrID:           UUID,
            signedAttribute:  SignedAttribute,
            senderIdentifier: String,
            attestation:      SignedAttribute?,
            depth:            Data? = nil
        ) {
            self.entryID          = entryID
            self.attrID           = attrID
            self.signedAttribute  = signedAttribute
            self.senderIdentifier = senderIdentifier
            self.attestation      = attestation
            self.depth            = depth
        }
    }
}

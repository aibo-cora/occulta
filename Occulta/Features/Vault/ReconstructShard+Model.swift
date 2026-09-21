//
//  ReconstructShard+Model.swift
//  Occulta
//
//  RETIRED, 2026-09-21 — RECOVERY_BUFFER_LAYERING.md §9.3. This was the live
//  reconstruction buffer for both per-entry PEK reconstruction and BEK restore;
//  `PendingShamirSecretRestore` (`Vault+Model.swift`) replaced it, keyed by the
//  secret's own identity instead of this model's shared, sender-keyed pool.
//
//  Kept permanently, migration-only — deliberately, not an oversight. Unlike the
//  BEK array's own retirement (a plain file, readable by hand-decoding raw bytes
//  without needing its old Swift type to survive), rows of this type live inside
//  the SwiftData-backed store itself: fetching and decoding them requires the
//  `@Model` type and `OccultaApp.schema` entry to still exist. Deleting either
//  would strand any device that upgrades straight into a build past this one with
//  a genuine in-flight restore still sitting in `ReconstructShard` rows — the
//  same "never strand a genuine recovery" principle
//  `Vault+Manager+ReturnBuffer.swift`'s `migrateLegacyRestoreShardFile` already
//  states for the file this model itself once replaced (Bug 100). Nothing writes
//  to this model anymore; `VaultManager.migrateReconstructShardsIfNeeded()` (called
//  from `unlock()`) is the only remaining reader, and it deletes every row it
//  touches — so the live population only ever shrinks, never grows, from here on.
//
//  Privacy model — encryption at rest (historical, while any rows remain):
//  - The target entryID, the SignedAttribute.id (`attrID`), and the full
//    SignedAttribute live inside `encryptedPayload`, sealed under the recovery
//    buffer key with AAD = aad().
//  - Cold-disk forensics learns "N rows remain in the retired reconstruct
//    buffer" — no entry identifiers, no shard counts per entry, no signature
//    material, without the restore vault key.
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
    /// `senderIdentifier` is Bug 94 remedy 2: at most one stored row per
    /// (entryID, senderIdentifier) is kept, so a threshold-reaching group requires
    /// distinct senders, not just distinct attrIDs. No longer carries an
    /// `attestation` — `bugs.md` Bug 125 removed it from the wire format entirely;
    /// it never verified content authenticity, only sender identity, which the
    /// bundle's own transport already establishes.
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
            depth:            Data? = nil
        ) {
            self.entryID          = entryID
            self.attrID           = attrID
            self.signedAttribute  = signedAttribute
            self.senderIdentifier = senderIdentifier
            self.depth            = depth
        }
    }
}

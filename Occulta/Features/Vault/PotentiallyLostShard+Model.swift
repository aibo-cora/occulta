//
//  PotentiallyLostShard+Model.swift
//  Occulta
//
//  Watches a delivered backup-key piece: whether the trustee's latest custodyManifest
//  still lists it. Written while the vault may be locked (custody key only); read by the
//  owning depth's `ShardCustodyManager.reconcileBackupPieces`.
//
//  Lifecycle:
//  - Inserted by ShardCustodyManager.processInboundManifest when a PendingShardDistribute
//    row is confirmed (ID appears in trustee's custodyManifest) and the distribute row
//    is deleted.
//  - isAbsent is set to true when a subsequent manifest does not include the ID,
//    and reset to false when a manifest includes it again.
//  - Rows for per-entry pieces, from before per-entry splitting was retired, are no longer
//    read or deleted (`decisions.md`, "Retire per-entry splitting").
//  - Backup-key rows persist until their split is replaced
//    (`ShardCustodyManager.distributeBackup`). Each depth reads them at its own unlock
//    (`reconcileBackupPieces`): present → confirmed, absent → re-sent (`bugs.md` Bug 141).
//    Also inserted there for a confirmed piece that has none.
//
//  Privacy model — encryption at rest:
//  - Plaintext column (id) carries no identifying data.
//  - attributeID, contactIdentifier, and isAbsent live inside encryptedPayload,
//    sealed under the shard custody key with AAD = aad().
//  - Key derivation requires no biometrics, so rows can be sealed and updated
//    while the vault is locked (during inbound bundle processing).
//

import Foundation
import SwiftData

@Model
final class PotentiallyLostShard {

    var id: UUID = UUID()

    /// Sealed `Payload`: nonce(12B) ∥ ciphertext ∥ tag(16B) — CryptoKit .combined.
    /// AAD = aad(). Key = `KeyManagerProtocol.deriveShardCustodyKey()`.
    var encryptedPayload: Data = Data()

    init(id: UUID = UUID(), encryptedPayload: Data) {
        self.id               = id
        self.encryptedPayload = encryptedPayload
    }

    func aad() -> Data {
        self.id.uuidString.data(using: .utf8)!
    }

    struct Payload: Codable {
        let attributeID:       UUID
        let contactIdentifier: String
        /// true after a manifest for this contact did not include attributeID.
        /// Reset to false when a manifest includes it again.
        var isAbsent: Bool
    }
}

//
//  PendingShardStatusUpdate+Model.swift
//  Occulta
//
//  SwiftData model for shard-status updates that arrived while the vault was locked.
//
//  When an inbound `.acknowledge` or `.notFound` operation reaches
//  `ShardCustodyManager` while the vault is locked, `updateShardStatus` throws
//  `.locked` and the update cannot be applied immediately. One
//  `PendingShardStatusUpdate` row is queued per pending update. On the next
//  `VaultManager.unlock()`, all rows are drained and each `updateShardStatus`
//  call is replayed.
//
//  Privacy model — encryption at rest:
//  - Plaintext columns (`id`) carry no identifying data.
//  - `attributeID` and `newStatus` live inside `encryptedPayload`, sealed under
//    the shard custody key with AAD = aad().
//  - Cold-disk forensics learns "N status updates are pending" — nothing about
//    which entries or contacts. Resolving requires the SE-protected custody key.
//
//  Lifecycle:
//  - Inserted by `ShardCustodyManager.handleAcknowledge` / `handleNotFound`
//    when `updateShardStatus` throws `.locked`.
//  - Drained by `VaultManager.drainPendingShardStatusUpdates()` inside `unlock()`.
//  - Deleted on successful application. If `updateShardStatus` fails (e.g.,
//    entry no longer exists), the row is deleted anyway — retrying an orphaned
//    status update would never succeed.
//

import Foundation
import SwiftData

@Model
final class PendingShardStatusUpdate {

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
    /// `attributeID` is the `SignedAttribute.id` of the shard whose status is changing.
    /// `newStatus` is the target `ShardStatus` to write via `updateShardStatus`.
    struct Payload: Codable {
        let attributeID: UUID
        let newStatus:   ShardStatus
    }
}

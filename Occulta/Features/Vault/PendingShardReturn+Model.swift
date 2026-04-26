//
//  PendingShardReturn+Model.swift
//  Occulta
//
//  SwiftData model for a queued shard-return bundle Bob owes to Alice.
//
//  Created when Bob detects that Alice's key fingerprint changed during a
//  proximity exchange (owner key rotation = new device, lost vault). One row
//  per owner contact — covers all shards Bob holds for that contact.
//  Upsert semantics: if a row already exists for this contact (e.g. Alice
//  re-exchanged again before delivery), only `scheduledAt` is updated; no
//  second row is inserted.
//
//  Privacy model — encryption at rest:
//  - Plaintext columns (`id`, `createdAt`) carry no contact-linking data.
//  - `contactIdentifier` and `scheduledAt` live inside `encryptedPayload`,
//    sealed under the shard custody key with AAD = aad().
//  - Cold-disk forensics learns "Bob has N pending shard returns" — nothing
//    about which contacts are involved. Resolving contact identity requires
//    the SE-protected custody key.
//
//  Lifecycle:
//  - Inserted (or updated) on owner key-change detection in ExchangeManager.
//  - Read before every outbound bundle to Alice; if present, all matching
//    CustodyShard rows are packed as `.respond` operations.
//  - Deleted only after Bob receives `.returnAcknowledged` from Alice
//    confirming she stored the returned shards.
//

import Foundation
import SwiftData

@Model
final class PendingShardReturn {

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

    // MARK: - Sealed payload

    /// Plaintext sealed inside `encryptedPayload`.
    ///
    /// `contactIdentifier` is `Contact.Profile.identifier` — a stable SwiftData
    /// UUID that survives key re-exchanges. Used to match `CustodyShard` rows
    /// whose `ownerContactIdentifier` equals this value.
    ///
    /// `scheduledAt` is the timestamp of the most recent trigger; overwritten
    /// on each upsert so delivery retries use the freshest exchange time.
    struct Payload: Codable {
        let contactIdentifier: String
        let scheduledAt:       Date
    }
}

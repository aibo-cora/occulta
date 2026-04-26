//
//  CustodyShard+Model.swift
//  Occulta
//
//  SwiftData model for a shard Bob holds on behalf of a contact (Alice).
//
//  Privacy model — encryption at rest:
//  - The only plaintext columns are `id` (random per row) and `createdAt`
//    (coarse timestamp). Neither links the row to a contact.
//  - The owner's identity (SHA-256 of their public key) and the entire
//    SignedAttribute live inside `encryptedPayload`, sealed under the shard
//    custody key with AAD = aad().
//  - Cold-disk forensics learns "Bob holds N shards" — nothing about which
//    contacts those shards belong to. Resolving owner identity requires the
//    Secure Enclave-protected custody key.
//
//  Lifecycle:
//  - Inserted on .distribute. Deleted on .revoke from the owner or when the
//    owner's contact key changes (shard becomes cryptographically unreachable).
//  - Stale shards from old PEK rotations are cryptographically inert — GCM
//    decryption of the entry will fail if Alice tries to use them. No proactive
//    cleanup needed.
//

import Foundation
import SwiftData

@Model
final class CustodyShard {

    // MARK: Persisted fields

    /// Random per-row identifier. Bound into AAD so any row-id mutation
    /// invalidates decryption. Not equal to SignedAttribute.id (that lives
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

    /// Plaintext layout sealed inside `encryptedPayload`.
    ///
    /// Putting the owner fingerprint here (rather than in a plaintext column)
    /// removes the contact-linkage signal from the on-disk schema. Looking up
    /// "all shards from contact X" requires decrypting every row — acceptable
    /// for the realistic N (low hundreds at most).
    struct Payload: Codable {
        /// SHA-256(ownerPublicKey) — used to detect key changes at re-exchange.
        let ownerKeyFingerprint: Data
        /// `Contact.Profile.identifier` of the owner in Bob's contact book.
        /// Used to look up all shards for a given owner at auto-return time.
        /// Optional for backward-compat with rows sealed before this field was added.
        let ownerContactIdentifier: String?
        /// The owner-signed shard attribute (category == .shard).
        let signedAttribute: SignedAttribute
    }
}

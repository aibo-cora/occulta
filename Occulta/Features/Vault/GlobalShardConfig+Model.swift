//
//  GlobalShardConfig+Model.swift
//  Occulta
//
//  SwiftData model for the user's global (default) Secret Sharing trustee
//  configuration. A single row acts as a singleton — reads always return the
//  first row found; writes delete all existing rows then insert a fresh one.
//
//  This is configuration, not shard material: it stores which contacts the
//  user has designated as default trustees and their preferred threshold.
//  Even so, it reveals relationship metadata ("Alice trusts Bob and Charlie
//  for vault recovery"), so it is sealed at rest under the shard custody key.
//
//  Privacy model:
//  - `id` (plaintext) — row identifier bound into AAD; carries no PII.
//  - `encryptedPayload` — AES-GCM sealed Payload; key = deriveShardCustodyKey().
//  - Cold-disk forensics learns "a global shard config exists" — nothing about
//    which contacts or threshold.
//
//  Lifecycle:
//  - Written when the user saves a selection in VaultGlobalTrustees.
//  - Read in VaultGlobalTrustees (populate working state on appear) and in
//    VaultShardSetup (seed selectedIDs for new entries).
//  - Deleted and replaced on every save (singleton semantics).
//

import Foundation
import SwiftData

@Model
final class GlobalShardConfig {

    // MARK: Persisted fields

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
    /// `trusteeIDs` — `Contact.Profile.identifier` values of global trustees.
    /// Threshold (k) is a per-entry decision set in VaultShardSetup, not here.
    struct Payload: Codable {
        let trusteeIDs: [String]
    }
}

//
//  GlobalShardConfig+Model.swift
//  Occulta
//
//  ORPHANED as of item 3's consolidation (see the shard-custody bug doc), and Global
//  Trustees are now retired entirely (`decisions.md`). No app code reads or writes this
//  model; `DatabaseMigration.migrateDeleteGlobalShardConfig` deletes any remaining row
//  without stamping anything (`bugs.md` Bug 149). Kept declared in the schema for one release only, to avoid betting on
//  SwiftData's untested automatic entity-removal migration with real user data —
//  slated for outright removal once that migration has had time to run in the wild.
//
//  Original design, preserved for context: SwiftData model for the user's global
//  (default) Secret Sharing trustee configuration. A single row acted as a
//  singleton — reads always returned the first row found; writes deleted all
//  existing rows then inserted a fresh one, sealed under the shard custody key.
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

//
//  HeldShard+Model.swift
//  Occulta
//
//  SwiftData model for a shard Bob holds on behalf of a contact (Alice).
//
//  Design:
//  - `encryptedAttribute` is a JSONEncoder(SignedAttribute) blob sealed under the
//    shard custody key (deriveShardCustodyKey). Never stored in plaintext.
//  - The shard custody key has device-unlock-level access (no biometric), so
//    shard processing can be fully automatic on bundle receipt.
//  - Deletion policy: only on .revoke from the owner or when the owner's contact
//    key changes (shard becomes cryptographically unreachable). Stale shards from
//    old PEK rotations are cryptographically inert — GCM decryption will fail if
//    Alice tries to use them. No proactive cleanup needed.
//  - `aad()` binds the ciphertext to the specific record identity; modifying
//    `id`, `ownerKeyFingerprint`, or `receivedAt` breaks decryption.
//

import Foundation
import SwiftData

@Model
final class HeldShard {

    // MARK: Persisted fields

    /// Matches SignedAttribute.id — used to match an incoming `replacesID` from the owner.
    var id: UUID = UUID()

    /// SHA-256(ownerPublicKey) — stable contact identifier across app restarts.
    var ownerKeyFingerprint: Data = Data()

    /// JSONEncoder(SignedAttribute) sealed under the shard custody key.
    /// nonce(12B) ∥ ciphertext ∥ tag(16B) — CryptoKit .combined format.
    var encryptedAttribute: Data = Data()

    var receivedAt: Date = Date()

    // MARK: Init

    init(id: UUID, ownerKeyFingerprint: Data, encryptedAttribute: Data, receivedAt: Date = Date()) {
        self.id                   = id
        self.ownerKeyFingerprint  = ownerKeyFingerprint
        self.encryptedAttribute   = encryptedAttribute
        self.receivedAt           = receivedAt
    }

    // MARK: AAD construction

    /// Authenticated additional data for AES-GCM seal/open of `encryptedAttribute`.
    ///
    /// Wire encoding (concatenated, no length prefixes):
    ///
    ///   id.uuidString (UTF-8)                               — always 36 bytes
    ///   ∥ ownerKeyFingerprint (SHA-256 raw bytes)           — 32 bytes
    ///   ∥ UInt64(receivedAt.timeIntervalSince1970).bigEndian — 8 bytes
    ///
    /// Total: 76 bytes.
    ///
    /// ⚠️ This layout is a sealed contract. Any change makes existing ciphertext
    /// permanently unreadable.
    func aad() -> Data {
        var data = Data()
        data.append(self.id.uuidString.data(using: .utf8)!)  // 36 bytes
        data.append(self.ownerKeyFingerprint)                  // 32 bytes
        var ts = UInt64(self.receivedAt.timeIntervalSince1970).bigEndian
        data.append(Data(bytes: &ts, count: 8))               //  8 bytes
        return data                                            // 76 bytes total
    }
}

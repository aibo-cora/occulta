//
//  SignedAttribute.swift
//  Occulta
//
//  Implements Issue #6 — Signed Attributes.
//
//  A SignedAttribute is a label/value pair attested by the owner's SE identity
//  key. The struct holds plaintext fields. Encryption before SwiftData
//  persistence is the caller's responsibility (serialize with JSONEncoder, then
//  AES-GCM seal the blob and store it in Contact.Profile.signedAttributes).
//
//  Signing payload layout (see signingPayload(id:category:value:entryID:createdAt:expiresAt:)):
//    "occulta-signed-attribute-v2" (UTF-8 domain prefix)
//    ∥ id.uuidString (UTF-8, always 36 bytes)
//    ∥ category.rawValue (UTF-8)
//    ∥ entryID.uuidString (UTF-8, 36 bytes — only for .shard; absent otherwise)
//    ∥ createdAt as UInt64 big-endian (8 bytes, seconds since Unix epoch)
//    ∥ 0x00 if expiresAt == nil; 0x01 ∥ UInt64 BE if expiresAt != nil (1 or 9 bytes)
//    ∥ value (raw bytes)
//
//  Including `category` prevents a category-substitution attack.
//  Including `id` prevents cross-attribute signature transplants.
//  Including `entryID` for shards binds them to a specific key generation.
//  Including `createdAt` and `expiresAt` prevents a trustee from modifying the
//  expiry field in stored JSON to extend a shard's validity past its intended
//  lifetime. Without this, expiry-based revocation would be unenforceable.
//
//  v1 → v2 is a breaking wire change. All v1 signatures fail verification
//  against the v2 payload by design. SSS was not shipped in v1 (feature-flagged
//  off), so no migration of existing signed shards is required.
//

import Foundation
import Security

// MARK: - SignedAttribute

struct SignedAttribute: Codable, Identifiable {

    // MARK: Category

    /// The semantic type of the attribute value.
    ///
    /// Raw string values are stable wire identifiers — never rename or reorder
    /// without a migration plan.
    enum Category: String, Codable {
        case financial
        case identity
        case medical
        case access
        case emergency
        case communication
        case crypto
        /// An SSS vault-key shard delivered to a trusted contact (Issue #34).
        case shard
        /// A trustee's vouching signature over `SHA256(signingPayload())` of a
        /// `.shard` attribute they hold, made with the trustee's *current* identity
        /// key. Lets a rotated-identity owner accept a shard their new device
        /// structurally cannot verify — the trustee checked it against their own
        /// retained copy of the owner's old key instead (Bug 94 remedy 2).
        case attestation
        case other
    }

    // MARK: Fields

    let id: UUID
    /// Human-readable label. Plaintext in this struct; the containing layer
    /// encrypts before writing to SwiftData.
    let label: String
    /// The sensitive value being attested. For `.shard`, these are the raw
    /// GF(2^8) shard bytes from ShamirSecretSharing.split().
    ///
    /// ⚠️ For `.shard` attributes: these bytes are plaintext key material.
    /// Encrypt this struct (via JSONEncoder + AES-GCM) to the recipient's public
    /// key immediately — never queue it in plaintext or persist it unencrypted.
    let value: Data
    let category: Category
    /// DER-encoded ECDSA-P256 signature over signingPayload(id:category:value:entryID:).
    let signature: Data
    let createdAt: Date
    /// Optional expiry. nil means the attribute never expires.
    let expiresAt: Date?
    /// For `.shard` category: the VaultEntry.id this shard belongs to.
    /// Included in the signing payload, binding the shard to a specific key
    /// generation. nil for all other categories.
    let entryID: UUID?

    // MARK: Init

    init(
        id: UUID = UUID(),
        label: String,
        value: Data,
        category: Category,
        signature: Data,
        createdAt: Date = Date(),
        expiresAt: Date? = nil,
        entryID: UUID? = nil
    ) {
        self.id        = id
        self.label     = label
        self.value     = value
        self.category  = category
        self.signature = signature
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.entryID   = entryID
    }

    // MARK: Signing payload

    /// The canonical byte sequence the SE identity key signs.
    ///
    /// This static form is the single authoritative definition of the payload.
    /// Both the instance helper and prepareShards() delegate here so sign and
    /// verify always produce the same bytes.
    ///
    /// Layout:
    ///   "occulta-signed-attribute-v2" ∥ id (36 B) ∥ category ∥ [entryID (36 B)]
    ///   ∥ createdAt UInt64 BE (8 B) ∥ expiry flag (1 B) ∥ [expiresAt UInt64 BE (8 B)] ∥ value
    ///
    /// Timestamps are encoded as UInt64 big-endian seconds since Unix epoch.
    /// expiresAt flag: 0x00 = no expiry; 0x01 = has expiry (followed by 8 bytes).
    ///
    /// - Parameters:
    ///   - entryID:   Pass the VaultEntry.id for `.shard` attributes; nil otherwise.
    ///   - createdAt: The attribute's creation timestamp (from the stored field).
    ///   - expiresAt: The attribute's expiry (from the stored field); nil if none.
    static func signingPayload(
        id:        UUID,
        category:  Category,
        value:     Data,
        entryID:   UUID?  = nil,
        createdAt: Date,
        expiresAt: Date?  = nil
    ) -> Data {
        var payload = Data()
        
        payload.append("occulta-signed-attribute-v2".data(using: .utf8)!)
        payload.append(id.uuidString.data(using: .utf8)!)              // 36 bytes
        payload.append(category.rawValue.data(using: .utf8)!)
        
        if let entryID {
            payload.append(entryID.uuidString.data(using: .utf8)!)     // 36 bytes — shard only
        }
        let createdSeconds = UInt64(createdAt.timeIntervalSince1970).bigEndian
        
        withUnsafeBytes(of: createdSeconds) { payload.append(contentsOf: $0) }  // 8 bytes
        
        if let expiresAt {
            payload.append(0x01)
            
            let expiresSeconds = UInt64(expiresAt.timeIntervalSince1970).bigEndian
            
            withUnsafeBytes(of: expiresSeconds) { payload.append(contentsOf: $0) }  // 8 bytes
        } else {
            payload.append(0x00)
        }
        payload.append(value)
        
        return payload
    }

    /// Convenience wrapper over the static form. Uses all stored fields automatically.
    func signingPayload() -> Data {
        SignedAttribute.signingPayload(
            id:        id,
            category:  category,
            value:     value,
            entryID:   entryID,
            createdAt: createdAt,
            expiresAt: expiresAt
        )
    }

    // MARK: Verification

    /// Verify this attribute's signature against a known contact public key.
    ///
    /// Returns false — not throws — on any failure: wrong key, bad signature,
    /// or expired attribute. Callers must treat false as an untrusted attribute
    /// and never surface the value to the user.
    ///
    /// - Parameter publicKeyData: x963-uncompressed P-256 public key (65 bytes).
    func verify(against publicKeyData: Data) -> Bool {
        guard publicKeyData.count == 65 else { return false }

        // Expiry check before crypto — fast-path rejection, no SE access.
        if let exp = self.expiresAt, exp < Date() { return false }

        let attrs: [String: Any] = [
            kSecAttrKeyType      as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass     as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard let pubKey = SecKeyCreateWithData(publicKeyData as CFData, attrs as CFDictionary, &error)
        else { return false }

        return SecKeyVerifySignature(
            pubKey,
            .ecdsaSignatureMessageX962SHA256,
            self.signingPayload() as CFData,
            self.signature as CFData,
            &error
        )
    }
}

// MARK: - AttestedShard

/// A `.shard` attribute together with who delivered it and, when the sender's
/// identity has rotated since original distribution, the trustee's attestation
/// vouching for it.
///
/// Threading `senderIdentifier` through storage is the load-bearing piece of
/// Bug 94 remedy 2: reconstruction counts *distinct senders*, not distinct
/// `SignedAttribute.id`s, so one identity cannot self-attest a whole group of
/// fabricated shares.
///
/// **This raises the floor to two senders, not to `threshold`.** The BEK restore
/// path cannot do better, and the reason is worth keeping: on the device that
/// needs it — one with no BEK of its own — the owner's chosen `threshold` does
/// not survive anywhere. It lives in the BEK payload's `ShardDistributionMetadata`,
/// which that device does not have, and it is not part of what a trustee is given,
/// so it cannot be recovered from them either. Reading it out of the `.occbak`
/// would be reading it from whoever authored the file. So the only floor left is
/// `ShamirSecretSharing.reconstruct`'s own `shares.count >= 2`. What actually gates
/// an unsolicited restore is the depth-0 confirmation in `OccultaApp`, not this
/// count. Do not build on this as if it were `threshold`-strength.
/// See `Docs/Features/Secure Mode/bugs.md`, Bug 94.
struct AttestedShard: Codable {
    /// The owner-signed shard. Verifies directly against the owner's current
    /// identity (Branch A, unrotated case) or is accompanied by `attestation`
    /// (Branch B, rotated case).
    let attribute: SignedAttribute
    /// Present only on the rotated-identity path: the trustee's own signature,
    /// category `.attestation`, over `SHA256(attribute.signingPayload())`.
    let attestation: SignedAttribute?
    /// The contact identifier this shard arrived from, as resolved by the
    /// *receiving* device's own lookup — never sender-asserted. See
    /// `ShardCustodyManager.handleInbound`'s callers in `OccultaApp.swift`,
    /// where `senderIdentifier` comes from `contactManager.openGroup(...)`
    /// resolving the decrypting key against the receiver's own contacts, not
    /// from anything the bundle's payload claims.
    let senderIdentifier: String
}

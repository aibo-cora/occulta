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
//  Signing payload layout (see signingPayload(id:category:value:)):
//    "occulta-signed-attribute-v1" (UTF-8 domain prefix)
//    ∥ id.uuidString (UTF-8, always 36 bytes)
//    ∥ category.rawValue (UTF-8)
//    ∥ value (raw bytes)
//
//  Including `category` in the payload prevents a category-substitution attack
//  (e.g. changing .financial to .shard without invalidating the signature).
//  Including `id` prevents cross-attribute signature transplants.
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
        case other
    }

    // MARK: Fields

    let id: UUID
    /// Human-readable label. Plaintext in this struct; the containing layer
    /// encrypts before writing to SwiftData.
    let label: String
    /// The sensitive value being attested. For `.shard`, these are the raw
    /// GF(2^8) shard bytes from ShamirSecretSharing.split().
    let value: Data
    let category: Category
    /// DER-encoded ECDSA-P256 signature over signingPayload(id:category:value:).
    let signature: Data
    let createdAt: Date
    /// Optional expiry. nil means the attribute never expires.
    let expiresAt: Date?

    // MARK: Init

    init(
        id: UUID = UUID(),
        label: String,
        value: Data,
        category: Category,
        signature: Data,
        createdAt: Date = Date(),
        expiresAt: Date? = nil
    ) {
        self.id        = id
        self.label     = label
        self.value     = value
        self.category  = category
        self.signature = signature
        self.createdAt = createdAt
        self.expiresAt = expiresAt
    }

    // MARK: Signing payload

    /// The canonical byte sequence the SE identity key signs.
    ///
    /// This static form is the single authoritative definition of the payload.
    /// Both the instance helper and prepareShards() delegate here so sign and
    /// verify always produce the same bytes.
    static func signingPayload(id: UUID, category: Category, value: Data) -> Data {
        var payload = Data()
        payload.append("occulta-signed-attribute-v1".data(using: .utf8)!)
        payload.append(id.uuidString.data(using: .utf8)!)        // always 36 bytes
        payload.append(category.rawValue.data(using: .utf8)!)
        payload.append(value)
        return payload
    }

    /// Convenience wrapper over the static form.
    func signingPayload() -> Data {
        SignedAttribute.signingPayload(id: id, category: category, value: value)
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
        if let exp = expiresAt, exp < Date() { return false }

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
            signingPayload() as CFData,
            signature as CFData,
            &error
        )
    }
}

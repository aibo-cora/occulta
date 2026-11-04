//
//  PairingSecret.swift
//  Occulta
//
//  A 32-byte secret per pairing: each slot's routing routing tag, mixed into the slot's key, and the key to the
//  slot's sender proof (`bugs.md` Bug 196). Held only in the contact's sealed record; the functions here are
//  the wire half, pinned by the interop vectors.
//

import Foundation
import CryptoKit

/// The wire constants and pure functions of a pairing secret.
public enum PairingSecret {

    public static let size = 32

    public enum SecretError: Error, Equatable {
        /// `SecRandomCopyBytes` failed. Nothing is generated from a predictable source.
        case entropyUnavailable
    }

    // MARK: - Derivation at a pairing

    /// The secret two phones derive at an exchange: HKDF-SHA256 over the identity ECDH output and, where the exchange had
    /// them, both ML-KEM secrets sorted, salted with the ECDH salt (the two public keys XORed), with both exchange nonces
    /// sorted after `deriveDomain` as the info. Both phones get the same bytes. The domain is not the verification
    /// words', so what a screen shows reveals nothing of it.
    ///
    /// - Returns: `nil` for a nonce that isn't 16 bytes, two equal nonces, or ML-KEM secrets that aren't 32 bytes.
    public static func derive(
        rawECDH: Data, salt: Data, mlkemSecrets: (Data, Data)?, ourNonce: Data, peerNonce: Data
    ) -> Data? {
        guard ourNonce.count == 16, peerNonce.count == 16, ourNonce != peerNonce else { return nil }

        var ikm = rawECDH
        if let (one, other) = mlkemSecrets {
            guard one.count == Self.size, other.count == Self.size else { return nil }
            let (low, high) = one.lexicographicallyPrecedes(other) ? (one, other) : (other, one)
            ikm.append(low)
            ikm.append(high)
        }

        let (lowNonce, highNonce) = ourNonce.lexicographicallyPrecedes(peerNonce) ? (ourNonce, peerNonce) : (peerNonce, ourNonce)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: Self.deriveDomain + lowNonce + highNonce,
            outputByteCount: Self.size
        ).withUnsafeBytes { Data($0) }
    }

    // MARK: - Routing

    /// HMAC(secret, "occulta-pairing-routing-tag-v1" ‖ nonce) — 32 bytes. The routing tag a slot carries, readable before
    /// decryption. `nonce` is the bundle's `fingerprintNonce`, so every file's routing tag is new.
    public static func routingTag(secret: Data, nonce: Data) -> Data {
        Self.mac(secret, domain: Self.routingTagDomain, nonce)
    }

    /// A routing tag-sized value that matches no secret: the filler in a slot that carries no real routing tag.
    public static func fillerTag() throws -> Data { try Self.random(Self.size) }

    // MARK: - Sender proof

    /// HMAC(secret, "occulta-pairing-proof-v1" ‖ routing tag ‖ senderPublicKey). Sits in the slot, so it covers the
    /// slot's routing tag: a routing tag swapped in the clear no longer verifies. Keyed by the pairing secret, not the
    /// session key, which every member of a group holds.
    public static func slotProof(secret: Data, routingTag: Data, senderPublicKey: Data) -> Data {
        Self.mac(secret, domain: Self.proofDomain, routingTag + senderPublicKey)
    }

    /// Whether `proof` is the slot proof for this secret, routing tag and sender key. Constant time.
    public static func isValidSlotProof(_ proof: Data, secret: Data, routingTag: Data, senderPublicKey: Data) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(
            proof, authenticating: Self.domainInput(Self.proofDomain, routingTag + senderPublicKey),
            using: SymmetricKey(data: secret)
        )
    }

    // MARK: - Key binding

    /// `key` with the secret mixed in: HKDF-SHA256(ikm: key, salt: secret, info: "occulta-pairing-bind-v1").
    /// Applied to every slot's wrapping key, so a slot opens only for the pairing that sealed it.
    public static func bind(_ key: SymmetricKey, secret: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: key, salt: secret, info: Self.bindDomain, outputByteCount: Self.size
        )
    }

    // MARK: - Internals

    static let routingTagDomain   = Data("occulta-pairing-routing-tag-v1".utf8)
    static let deriveDomain       = Data("Occulta-v1-pairing-secret-2026".utf8)
    static let proofDomain   = Data("occulta-pairing-proof-v1".utf8)
    static let bindDomain    = Data("occulta-pairing-bind-v1".utf8)

    private static func domainInput(_ domain: Data, _ message: Data) -> Data { domain + message }

    private static func mac(_ secret: Data, domain: Data, _ message: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Self.domainInput(domain, message), using: SymmetricKey(data: secret)))
    }

    /// Random bytes, from the system source only.
    static func random(_ count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
            throw SecretError.entropyUnavailable
        }
        return Data(bytes)
    }
}

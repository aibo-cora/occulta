//
//  RoutingKey.swift
//  Occulta
//
//  A 32-byte routing key per pairing: each slot's routing tag, mixed into the slot's key, and the key to the
//  slot's sender proof (`bugs.md` Bug 196). Held only in the contact's sealed record; the functions here are
//  the wire half, pinned by the interop vectors.
//

import Foundation
import CryptoKit

/// The wire constants and pure functions of a routing key.
public enum RoutingKey {

    public static let size = 32

    public enum Failure: Error, Equatable {
        /// `SecRandomCopyBytes` failed. Nothing is generated from a predictable source.
        case entropyUnavailable
    }

    // MARK: - Routing

    /// HMAC(routing key, "occulta-pairing-routing-tag-v1" ‖ nonce) — 32 bytes. The routing tag a slot carries, readable before
    /// decryption. `nonce` is the bundle's `fingerprintNonce`, so every file's routing tag is new.
    public static func routingTag(routingKey: Data, nonce: Data) -> Data {
        Self.mac(routingKey, domain: Self.routingTagDomain, nonce)
    }

    /// A routing tag-sized value that matches no routing key: the filler in a slot that carries no real routing tag.
    public static func fillerTag() throws -> Data { try Self.random(Self.size) }

    // MARK: - Sender proof

    /// HMAC(routing key, "occulta-pairing-proof-v1" ‖ routing tag ‖ senderPublicKey). Sits in the slot, so it covers the
    /// slot's routing tag: a routing tag swapped in the clear no longer verifies. Keyed by the routing key, not the
    /// session key, which every member of a group holds.
    public static func slotProof(routingKey: Data, routingTag: Data, senderPublicKey: Data) -> Data {
        Self.mac(routingKey, domain: Self.proofDomain, routingTag + senderPublicKey)
    }

    /// Whether `proof` is the slot proof for this routing key, routing tag and sender key. Constant time.
    public static func isValidSlotProof(_ proof: Data, routingKey: Data, routingTag: Data, senderPublicKey: Data) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(
            proof, authenticating: Self.domainInput(Self.proofDomain, routingTag + senderPublicKey),
            using: SymmetricKey(data: routingKey)
        )
    }

    // MARK: - Key binding

    /// `key` with the routing key mixed in: HKDF-SHA256(ikm: key, salt: routing key, info: "occulta-pairing-bind-v1").
    /// Applied to every slot's wrapping key, so a slot opens only for the pairing that sealed it.
    public static func bind(_ key: SymmetricKey, routingKey: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: key, salt: routingKey, info: Self.bindDomain, outputByteCount: Self.size
        )
    }

    // MARK: - Internals

    static let routingTagDomain   = Data("occulta-pairing-routing-tag-v1".utf8)
    static let proofDomain   = Data("occulta-pairing-proof-v1".utf8)
    static let bindDomain    = Data("occulta-pairing-bind-v1".utf8)

    private static func domainInput(_ domain: Data, _ message: Data) -> Data { domain + message }

    private static func mac(_ routingKey: Data, domain: Data, _ message: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Self.domainInput(domain, message), using: SymmetricKey(data: routingKey)))
    }

    /// Random bytes, from the system source only.
    static func random(_ count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
            throw Failure.entropyUnavailable
        }
        return Data(bytes)
    }
}

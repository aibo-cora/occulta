//
//  PairingSecret.swift
//  Occulta
//
//  A 32-byte secret per pairing: each slot's routing label, mixed into the slot's key, and the key to the
//  slot's sender proof (`bugs.md` Bug 196). Held only in the contact's sealed record; the functions here are
//  the wire half, pinned by the interop vectors.
//

import Foundation
import CryptoKit

/// The wire constants and pure functions of a pairing secret.
public enum PairingSecret {

    public static let size = 32

    public enum SecretError: Error, Equatable {
        /// A half or secret that isn't `size` bytes.
        case malformed
        /// Both halves are the same: the peer echoed ours back, or the entropy failed. No secret comes of it.
        case identicalHalves
        /// `SecRandomCopyBytes` failed. Nothing is generated from a predictable source.
        case entropyUnavailable
    }

    // MARK: - Routing

    /// HMAC(secret, "occulta-pairing-label-v1" ‖ nonce) — 32 bytes. The label a slot carries, readable before
    /// decryption. `nonce` is the bundle's `fingerprintNonce`, so every file's label is new.
    public static func label(secret: Data, nonce: Data) -> Data {
        Self.mac(secret, domain: Self.labelDomain, nonce)
    }

    /// A label-sized value that matches no secret: the filler in a slot that carries no real label.
    public static func fillerLabel() throws -> Data { try Self.random(Self.size) }

    // MARK: - Sender proof

    /// HMAC(secret, "occulta-pairing-proof-v1" ‖ label ‖ senderPublicKey). Sits in the slot, so it covers the
    /// slot's label: a label swapped in the clear no longer verifies. Keyed by the pairing secret, not the
    /// session key, which every member of a group holds.
    public static func slotProof(secret: Data, label: Data, senderPublicKey: Data) -> Data {
        Self.mac(secret, domain: Self.proofDomain, label + senderPublicKey)
    }

    /// Whether `proof` is the slot proof for this secret, label and sender key. Constant time.
    public static func isValidSlotProof(_ proof: Data, secret: Data, label: Data, senderPublicKey: Data) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(
            proof, authenticating: Self.domainInput(Self.proofDomain, label + senderPublicKey),
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

    // MARK: - The swap

    /// A fresh random half.
    public static func newHalf() throws -> Data { try Self.random(Self.size) }

    /// The secret two halves make: HKDF-SHA256 over the halves sorted bytewise, so crossing sends agree whichever
    /// side's half is "ours".
    public static func combine(_ one: Data, _ other: Data) throws -> Data {
        guard one.count == Self.size, other.count == Self.size else { throw SecretError.malformed }
        guard one != other else { throw SecretError.identicalHalves }
        let (low, high) = one.lexicographicallyPrecedes(other) ? (one, other) : (other, one)
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: low + high), salt: Data(), info: Self.swapDomain,
            outputByteCount: Self.size
        )
        return key.withUnsafeBytes { Data($0) }
    }

    /// HMAC(secret, "occulta-pairing-confirm-v1" ‖ the sender's own half). Proves its sender holds the secret.
    /// Over the sender's half, not both: a receiver who sends our own confirmation back to us confirms nothing.
    public static func confirmation(secret: Data, ownHalf: Data) -> Data {
        Self.mac(secret, domain: Self.confirmDomain, ownHalf)
    }

    /// Whether `confirmation` is the one `peerHalf`'s sender would make with `secret`.
    public static func isValidConfirmation(_ confirmation: Data, secret: Data, peerHalf: Data) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(
            confirmation, authenticating: Self.domainInput(Self.confirmDomain, peerHalf),
            using: SymmetricKey(data: secret)
        )
    }

    // MARK: - Internals

    static let labelDomain   = Data("occulta-pairing-label-v1".utf8)
    static let proofDomain   = Data("occulta-pairing-proof-v1".utf8)
    static let bindDomain    = Data("occulta-pairing-bind-v1".utf8)
    static let swapDomain    = Data("occulta-pairing-swap-v1".utf8)
    static let confirmDomain = Data("occulta-pairing-confirm-v1".utf8)

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

// MARK: - PairingSecretSwap

/// What a slot carries toward making a pairing's secret: a random half, and a confirmation once its sender holds
/// both halves. An optional field of `RecipientPayload`, in the sealed slot, never in `SealedPayload` (a group
/// file's sealed payload reaches every member).
///
/// Present in **every** slot of a send to a recipient on the pairing-secret tier, as `kind: .none` with random
/// bytes when nothing is being swapped: slot sizes are visible in a group envelope, so a slot that carried the
/// field would be told from one that didn't. The kind names are the same length for the same reason.
public struct PairingSecretSwap: Codable, Equatable, Sendable {

    public enum Kind: String, Codable, Sendable {
        /// `key` is the sender's random half.
        case half
        /// Filler: nothing is being swapped.
        case none
        /// A kind this build doesn't know. Ignored, like `ShardOperation.Kind.unsupported`.
        case unsupported

        public init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = Kind(rawValue: raw) ?? .unsupported
        }
    }

    public let kind: Kind
    /// 32 bytes: the sender's half, or random filler.
    public let key: Data
    /// 32 bytes: `PairingSecret.confirmation` once the sender holds both halves, or random filler.
    public let confirmation: Data

    public init(kind: Kind, key: Data, confirmation: Data) {
        self.kind         = kind
        self.key          = key
        self.confirmation = confirmation
    }

    /// The filler a slot carries when no swap rides in it.
    public static func filler() throws -> PairingSecretSwap {
        PairingSecretSwap(
            kind: .none, key: try PairingSecret.random(PairingSecret.size),
            confirmation: try PairingSecret.random(PairingSecret.size)
        )
    }
}

//
//  PairwiseDerivation.swift
//  Occulta
//
//  What two phones derive at an exchange that gave each pairing its own key pair (`bugs.md` Bug 196, stage 2): the
//  transcript of what both sent, the routing key, the verification words' key, and the long-term slot key. Pure
//  functions over the ECDH outputs, pinned by the interop vectors. The ECDH itself is the caller's: the identity ECDH
//  never leaves the key manager, and the pair-key ECDH is the Enclave's.
//
//  The identity ECDH (`ik`) is in both the routing key and the words, beside the pair-key ECDH (`pk`). Without it the
//  identity key would be a claim nothing proves: it is public, and the Multipeer session authenticates nobody, so a
//  phone that sent a contact's public key and its own pair keys would pass for that contact.
//

import Foundation
import CryptoKit

extension RoutingKey {

    // MARK: - The transcript

    /// What one phone sent in its `pairing` field: its two P-256 pair keys and, from a phone that could make one, an
    /// ML-DSA-87 public key.
    public struct PairBlock: Equatable, Sendable {

        public static let p256KeySize = 65
        /// An ML-DSA-87 public key, FIPS 204.
        public static let mldsaKeySize = 2592

        public let agreementKey: Data
        public let signingKey: Data
        public let mldsaKey: Data?

        /// `nil` for a P-256 key that isn't 65 bytes, an ML-DSA key that isn't 2,592, or two P-256 keys that are the same.
        public init?(agreementKey: Data, signingKey: Data, mldsaKey: Data? = nil) {
            guard agreementKey.count == Self.p256KeySize, signingKey.count == Self.p256KeySize, agreementKey != signingKey else {
                return nil
            }
            if let mldsaKey, mldsaKey.count != Self.mldsaKeySize { return nil }
            self.agreementKey = agreementKey
            self.signingKey   = signingKey
            self.mldsaKey     = mldsaKey
        }

        /// `0x01 ‖ agreement ‖ signing ‖ UInt16 big-endian length of the ML-DSA key ‖ the ML-DSA key`. The length is 0 when
        /// the phone sent none, so a missing key and a present one can't be mistaken for each other.
        var encoded: Data {
            var out = Data([0x01])
            out.append(self.agreementKey)
            out.append(self.signingKey)
            let length = UInt16(self.mldsaKey?.count ?? 0)
            out.append(contentsOf: [UInt8(length >> 8), UInt8(length & 0xFF)])
            if let mldsaKey { out.append(mldsaKey) }
            return out
        }
    }

    /// SHA-256("occulta-pairing-transcript-v1" ‖ the two blocks' encodings, sorted bytewise). Both phones see the same two
    /// blocks if the channel is honest, whichever is "ours", even when only one sent an ML-DSA key. A man in the middle
    /// who adds, removes or swaps a field makes the two phones' transcripts differ, so their words differ.
    public static func transcript(_ one: PairBlock, _ other: PairBlock) -> Data {
        let (low, high) = one.encoded.lexicographicallyPrecedes(other.encoded) ? (one, other) : (other, one)
        var input = Self.transcriptDomain
        input.append(low.encoded)
        input.append(high.encoded)
        return Data(SHA256.hash(data: input))
    }

    // MARK: - The routing key

    /// The routing key of a pair-key pairing: HKDF-SHA256 over `pk ‖ ik ‖` both ML-KEM secrets sorted (where the exchange
    /// had them), salted with the two agreement keys XORed, with both exchange nonces sorted and the transcript after
    /// `pairingDomain` as the info.
    ///
    /// - Parameters:
    ///   - pairwiseECDH: the ECDH output between the two agreement keys (X9.63 KDF applied, 32 bytes).
    ///   - identityECDH: the ECDH output between the two identity keys (X9.63 KDF applied, 32 bytes).
    /// - Returns: `nil` for any input of the wrong size, two equal nonces, or two equal agreement keys.
    public static func derive(
        pairwiseECDH: Data, identityECDH: Data, ourAgreementKey: Data, peerAgreementKey: Data,
        mlkemSecrets: (Data, Data)?, ourNonce: Data, peerNonce: Data, transcript: Data
    ) -> Data? {
        guard let ikm = Self.keyMaterial(pairwiseECDH, identityECDH, mlkemSecrets),
              let salt = Self.salt(ourAgreementKey, peerAgreementKey),
              let nonces = Self.sortedNonces(ourNonce, peerNonce), transcript.count == 32 else { return nil }
        return Self.expand(ikm, salt: salt, info: Self.pairingDomain + nonces + transcript)
    }

    // MARK: - The words

    /// The key the verification words come from, for an exchange that made pair keys: the same input as the routing key,
    /// salted with the two identity keys XORed (`identitySalt`) and under a domain of its own, so what a screen shows
    /// reveals nothing of the routing key.
    ///
    /// Covers the transcript, so a pair key, or an ML-DSA key, that a man in the middle added, removed or swapped
    /// changes the words.
    public static func wordsKey(
        pairwiseECDH: Data, identityECDH: Data, identitySalt: Data, mlkemSecrets: (Data, Data)?,
        ourNonce: Data, peerNonce: Data, transcript: Data
    ) -> Data? {
        guard let ikm = Self.keyMaterial(pairwiseECDH, identityECDH, mlkemSecrets), identitySalt.count == 65,
              let nonces = Self.sortedNonces(ourNonce, peerNonce), transcript.count == 32 else { return nil }
        return Self.expand(ikm, salt: identitySalt, info: Self.wordsDomain + nonces + transcript)
    }

    // MARK: - The long-term slot key

    /// The key a long-term slot is wrapped under, for a pair-key pairing: HKDF-SHA256 over `pk ‖` both ML-KEM secrets
    /// sorted (hybrid), salted with the two agreement keys XORed. Applied before `bind`, like every slot's key.
    ///
    /// The identity key is not in it: that is the point of a key per pairing, so holding the identity key's private half
    /// opens nothing of such a pairing.
    ///
    /// - Returns: `nil` for any input of the wrong size.
    public static func longTermKey(
        pairwiseECDH: Data, ourAgreementKey: Data, peerAgreementKey: Data, mlkemSecrets: (Data, Data)?
    ) -> SymmetricKey? {
        guard pairwiseECDH.count == Self.size, let salt = Self.salt(ourAgreementKey, peerAgreementKey) else { return nil }
        var ikm = pairwiseECDH
        if let mlkemSecrets {
            guard let sorted = Self.sortedSecrets(mlkemSecrets) else { return nil }
            ikm.append(sorted)
        }
        let info = mlkemSecrets == nil ? Self.longTermClassicalDomain : Self.longTermHybridDomain
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: info, outputByteCount: Self.size
        )
    }

    // MARK: - Internals

    static let transcriptDomain       = Data("occulta-pairing-transcript-v1".utf8)
    static let pairingDomain          = Data("Occulta-v2-routing-key-2026".utf8)
    static let wordsDomain            = Data("Occulta-v2-pairwise-diceware-2026".utf8)
    static let longTermClassicalDomain = Data("Occulta-v1-pairwise-transport-2026".utf8)
    static let longTermHybridDomain    = Data("Occulta-v2-pairwise-hybrid-transport-2026".utf8)

    /// `pk ‖ ik ‖ both ML-KEM secrets sorted`, or `nil` if any part is the wrong size.
    private static func keyMaterial(_ pairwise: Data, _ identity: Data, _ mlkemSecrets: (Data, Data)?) -> Data? {
        guard pairwise.count == Self.size, identity.count == Self.size else { return nil }
        var ikm = pairwise
        ikm.append(identity)
        if let mlkemSecrets {
            guard let sorted = Self.sortedSecrets(mlkemSecrets) else { return nil }
            ikm.append(sorted)
        }
        return ikm
    }

    private static func sortedSecrets(_ secrets: (Data, Data)) -> Data? {
        guard secrets.0.count == Self.size, secrets.1.count == Self.size else { return nil }
        let (low, high) = secrets.0.lexicographicallyPrecedes(secrets.1) ? (secrets.0, secrets.1) : (secrets.1, secrets.0)
        return low + high
    }

    /// The two agreement keys XORed: 65 bytes, the same whichever is "ours". `nil` for a key that isn't 65 bytes or two
    /// that are the same, which would XOR to nothing.
    private static func salt(_ ours: Data, _ theirs: Data) -> Data? {
        guard ours.count == PairBlock.p256KeySize, theirs.count == PairBlock.p256KeySize, ours != theirs else { return nil }
        return Data(zip(ours, theirs).map { $0 ^ $1 })
    }

    private static func sortedNonces(_ ours: Data, _ theirs: Data) -> Data? {
        guard ours.count == 16, theirs.count == 16, ours != theirs else { return nil }
        let (low, high) = ours.lexicographicallyPrecedes(theirs) ? (ours, theirs) : (theirs, ours)
        return low + high
    }

    private static func expand(_ ikm: Data, salt: Data, info: Data) -> Data {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: info, outputByteCount: Self.size
        ).withUnsafeBytes { Data($0) }
    }
}

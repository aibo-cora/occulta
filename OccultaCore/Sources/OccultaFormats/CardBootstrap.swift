//
//  CardBootstrap.swift
//  Occulta
//
//  The bootstrap layer of a card conversation's slots
//  (`Docs/Features/Introduction Cards/SPEC.md` §4.3).
//
//  A bootstrap slot's `wrappedPayload` is
//
//      AES-GCM(K_outer, layer, AAD: blind)
//      layer = mlkemCiphertext (1,568) ‖ AES-GCM(K_inner, payload, AAD: blind ‖ mlkemCiphertext)
//
//  Both seals are `AES.GCM.SealedBox.combined` (nonce ‖ ciphertext ‖ tag). The ML-KEM ciphertext
//  isn't secret, so it travels under the classical outer key; everything secret is in `inner`,
//  under a key that mixes in an ML-KEM secret. The outer layer keeps a card bundle from being
//  recognisable by an extra `Recipient` field.
//
//  Key derivation for `K_outer` and for Bob's `K_inner` is the app's existing
//  `forwardSecretSessionKey`; only Carol's `K_inner` is new, and lives here.
//

import Foundation
import CryptoKit

public enum CardBootstrap {

    public static let mlkemCiphertextCount = 1_568
    /// HKDF info for Carol's `K_inner`.
    public static let innerKeyInfo = Data("Occulta-v2-card-bootstrap-2026".utf8)

    private static let publicKeyByteCount = 65
    private static let sharedSecretByteCount = 32
    /// AES-GCM's nonce (12) and tag (16) around the plaintext.
    private static let gcmOverhead = 28

    public enum BootstrapError: Error, Equatable {
        /// The bytes are not a sealed box, or too short to hold the layers.
        case malformed
        /// The ML-KEM ciphertext is not `mlkemCiphertextCount` bytes.
        case wrongCiphertextLength
    }

    // MARK: - Key

    /// `K_inner` for Carol's bootstrap slots: `HKDF-SHA256(ikm: ecdh ‖ ss1, salt: peer XOR own, info: innerKeyInfo)`,
    /// 32 bytes. Both sides derive it; XOR is symmetric, so neither needs to know which is Carol.
    ///
    /// - Parameters:
    ///   - ecdhOutput: The slot's ECDH output.
    ///   - ownPublicKey: Our 65-byte public key for the slot.
    ///   - peerPublicKey: The peer's 65-byte public key for the slot.
    ///   - ss1: The ML-KEM shared secret from Carol's encapsulation to Bob's card key, 32 bytes.
    /// - Returns: Nil unless both public keys are 65 bytes and `ss1` is 32.
    public static func carolInnerKey(ecdhOutput: Data, ownPublicKey: Data, peerPublicKey: Data, ss1: Data) -> SymmetricKey? {
        guard ownPublicKey.count == self.publicKeyByteCount,
              peerPublicKey.count == self.publicKeyByteCount,
              ss1.count == self.sharedSecretByteCount
        else { return nil }

        var ikm = ecdhOutput
        ikm.append(ss1)
        let salt = Data(zip(peerPublicKey, ownPublicKey).map { $0 ^ $1 })

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: self.innerKeyInfo, outputByteCount: 32
        )
    }

    // MARK: - Seal

    /// Seals `payload` into a bootstrap slot's `wrappedPayload`.
    ///
    /// - Parameters:
    ///   - payload: What `inner` holds, typically the JSON of a `RecipientPayload`.
    ///   - mlkemCiphertext: `ct1` from Carol, `ct2` from Bob; `mlkemCiphertextCount` bytes.
    ///   - blind: The bundle's blind, the AAD of both layers.
    /// - Throws: `BootstrapError.wrongCiphertextLength`.
    public static func seal(payload: Data, mlkemCiphertext: Data, outerKey: SymmetricKey, innerKey: SymmetricKey, blind: Data) throws -> Data {
        try self.seal(
            payload: payload, mlkemCiphertext: mlkemCiphertext, outerKey: outerKey, innerKey: innerKey, blind: blind,
            outerNonce: nil, innerNonce: nil
        )
    }

    /// Same, with fixed nonces for interop vectors. Never call with a nonce outside tests.
    static func seal(
        payload: Data, mlkemCiphertext: Data, outerKey: SymmetricKey, innerKey: SymmetricKey, blind: Data,
        outerNonce: AES.GCM.Nonce?, innerNonce: AES.GCM.Nonce?
    ) throws -> Data {
        guard mlkemCiphertext.count == self.mlkemCiphertextCount else { throw BootstrapError.wrongCiphertextLength }

        var innerAAD = blind
        innerAAD.append(mlkemCiphertext)
        let inner = try AES.GCM.seal(payload, using: innerKey, nonce: innerNonce, authenticating: innerAAD)
        guard let innerBytes = inner.combined else { throw BootstrapError.malformed }

        var layer = mlkemCiphertext
        layer.append(innerBytes)
        let outer = try AES.GCM.seal(layer, using: outerKey, nonce: outerNonce, authenticating: blind)
        guard let outerBytes = outer.combined else { throw BootstrapError.malformed }
        return outerBytes
    }

    // MARK: - Open

    /// Opens the outer layer only. Returns the ML-KEM ciphertext, which the receiver decapsulates to get the
    /// secret that `K_inner` needs, and the still-sealed inner bytes.
    ///
    /// - Throws: `BootstrapError.malformed` when `wrapped` is too short to hold both layers; a CryptoKit
    ///   authentication error when `outerKey` or `blind` is wrong, which is the normal result for a slot
    ///   that isn't a bootstrap one.
    public static func openOuter(_ wrapped: Data, outerKey: SymmetricKey, blind: Data) throws -> (mlkemCiphertext: Data, inner: Data) {
        guard wrapped.count >= self.gcmOverhead + self.mlkemCiphertextCount + self.gcmOverhead,
              let box = try? AES.GCM.SealedBox(combined: wrapped)
        else { throw BootstrapError.malformed }

        let layer = Data(try AES.GCM.open(box, using: outerKey, authenticating: blind))
        guard layer.count >= self.mlkemCiphertextCount + self.gcmOverhead else { throw BootstrapError.malformed }

        let split = layer.startIndex + self.mlkemCiphertextCount
        return (Data(layer[layer.startIndex ..< split]), Data(layer[split...]))
    }

    /// Opens the inner layer, with AAD `blind ‖ mlkemCiphertext`.
    ///
    /// - Throws: `BootstrapError.wrongCiphertextLength`, `.malformed`, or a CryptoKit authentication error.
    public static func openInner(_ inner: Data, mlkemCiphertext: Data, innerKey: SymmetricKey, blind: Data) throws -> Data {
        guard mlkemCiphertext.count == self.mlkemCiphertextCount else { throw BootstrapError.wrongCiphertextLength }
        guard let box = try? AES.GCM.SealedBox(combined: inner) else { throw BootstrapError.malformed }

        var aad = blind
        aad.append(mlkemCiphertext)
        return Data(try AES.GCM.open(box, using: innerKey, authenticating: aad))
    }
}

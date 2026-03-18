//
//  Key+Manager+Ephemeral.swift
//  Occulta
//
//  Created by Yura on 3/14/26.
//  Updated for prekey forward secrecy on 3/17/26.
//

import Foundation
import CryptoKit

// MARK: - Ephemeral key operations

extension Manager.Key {

    // MARK: - Ephemeral key pair generation

    /// Generate a transient P-256 key pair in memory — no Secure Enclave, no persistence.
    ///
    /// `kSecAttrIsPermanent: false` means the key is never written to the keychain.
    /// The private key reference is valid only for the lifetime of the returned `SecKey`
    /// object. Once that reference is released, the key material is gone with no way
    /// to recover it. This property is what makes the forward secret path work.
    ///
    /// - Returns: `(privateKey, publicKeyData)` where `publicKeyData` is x963 (65 bytes),
    ///   or `nil` if key generation fails.
    func generateEphemeralKeyPair() -> (privateKey: SecKey, publicKeyData: Data)? {
        var error: Unmanaged<CFError>?

        let attributes: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: false  // Never written to keychain or SE.
            ]
        ]

        guard
            let privateKey     = SecKeyCreateRandomKey(attributes, &error),
            let publicKey      = SecKeyCopyPublicKey(privateKey),
            let publicKeyData  = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
        else {
            return nil
        }

        return (privateKey, publicKeyData)
    }

    // MARK: - Shared secret derivation (ephemeral sender or prekey recipient)

    /// Derive a session key using a given private key and a peer's public key material.
    ///
    /// Used on both sides of the FS exchange:
    ///
    /// **Encryption side** (ephemeral private key + recipient prekey public):
    /// ```
    /// sessionKey = HKDF(ECDH(ephemeralPriv, recipientPrekeyPub))
    /// ```
    ///
    /// **Decryption side** (our prekey private key + sender ephemeral public):
    /// ```
    /// sessionKey = HKDF(ECDH(ourPrekeyPriv, senderEphemeralPub))
    /// ```
    ///
    /// ECDH commutativity guarantees both sides arrive at the same raw shared secret.
    /// The XOR salt is also commutative, so HKDF output is identical on both sides.
    /// This means no new decrypt-side HKDF logic is needed — the same derivation
    /// function works for both roles.
    ///
    /// Uses identical HKDF parameters to the existing `createSharedSecret(using:)`:
    /// - Algorithm: `.ecdhKeyExchangeCofactorX963SHA256`
    /// - Salt: XOR(peerPublicKey, ourPublicKey) — 65 bytes
    /// - Info: `"Occulta-v1-encryption-key-2025"` (UTF-8)
    /// - Output: 32 bytes
    ///
    /// - Parameters:
    ///   - ephemeralPrivateKey: Any in-memory `SecKey` — throwaway or prekey private.
    ///   - recipientMaterial:   Peer's public key in x963 format.
    /// - Returns: 256-bit `SymmetricKey`, or `nil` on failure.
    func createSharedSecret(ephemeralPrivateKey: SecKey, recipientMaterial: Data) -> SymmetricKey? {
        guard
            let recipientPublicKey = self.convert(material: recipientMaterial)
        else { return nil }

        let algorithm: SecKeyAlgorithm = .ecdhKeyExchangeCofactorX963SHA256

        guard
            SecKeyIsAlgorithmSupported(ephemeralPrivateKey, .keyExchange, algorithm)
        else { return nil }

        var error: Unmanaged<CFError>?

        guard
            let rawSharedSecret = SecKeyCopyKeyExchangeResult(
                ephemeralPrivateKey,
                algorithm,
                recipientPublicKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        else { return nil }

        // Build XOR salt from both public keys.
        // XOR is commutative: XOR(A, B) == XOR(B, A).
        // Encryption: XOR(recipientPub, ephemeralPub)
        // Decryption: XOR(ephemeralPub,  recipientPub)
        // Both produce identical salt. ✓
        guard
            let ephemeralPublicKey     = SecKeyCopyPublicKey(ephemeralPrivateKey),
            let ephemeralPublicKeyData = self.convert(key: ephemeralPublicKey),
            let recipientPublicKeyData = self.convert(key: recipientPublicKey)
        else { return nil }

        let peerBuffer: [UInt8] = recipientPublicKeyData.map { $0 }
        let ourBuffer:  [UInt8] = ephemeralPublicKeyData.map { $0 }
        let salt = Data(zip(peerBuffer, ourBuffer).map { $0 ^ $1 })

        // Identical HKDF parameters to createSharedSecret(using:) — intentional.
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSharedSecret),
            salt: salt,
            info: "Occulta-v1-encryption-key-2025".data(using: .utf8)!,
            outputByteCount: 32
        )
    }
}

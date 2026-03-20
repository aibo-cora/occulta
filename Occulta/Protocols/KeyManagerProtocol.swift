//
//  KeyManagerProtocol.swift
//  Occulta
//
//  Created by Yura on 3/19/26.
//

import Foundation
import CryptoKit

// MARK: - KeyManagerProtocol

/// Abstracts Secure Enclave operations so Manager.Crypto can be tested
/// without a real SE. Production code uses Manager.Key; tests use TestKeyManager.
protocol KeyManagerProtocol {
    /// Retrieve our long-term identity public key in x963 format.
    func retrieveIdentity() throws -> Data
    /// Create a symmetric key for local database encryption.
    func createLocalEncryptionKey() throws -> SymmetricKey?
    /// Derive a shared symmetric key from a peer's public key material.
    func createSharedSecret(using material: Data?) -> SymmetricKey?
    /// Derive a shared symmetric key using a given private key (ephemeral or prekey).
    func createSharedSecret(ephemeralPrivateKey: SecKey, recipientMaterial: Data) -> SymmetricKey?
    /// Generate an in-memory throwaway P-256 key pair.
    func generateEphemeralKeyPair() -> (privateKey: SecKey, publicKeyData: Data)?
}

// MARK: - Manager.Key conformance

extension Manager.Key: KeyManagerProtocol { }

// MARK: - TestKeyManager

/// In-memory P-256 key manager for unit tests.
///
/// Generates a fresh key pair on init and holds the private key in memory only.
/// No Secure Enclave — safe to use in the test process.
///
/// All operations are deterministic within a single test run:
/// the same `TestKeyManager` instance always produces the same identity
/// and the same shared secrets.
nonisolated
final class TestKeyManager: KeyManagerProtocol {

    private let privateKey: SecKey
    private let publicKeyData: Data

    init() {
        let attributes: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
        ]
        var error: Unmanaged<CFError>?
        let priv = SecKeyCreateRandomKey(attributes, &error)!
        let pub  = SecKeyCopyPublicKey(priv)!
        let data = SecKeyCopyExternalRepresentation(pub, nil)! as Data

        self.privateKey    = priv
        self.publicKeyData = data
    }

    func retrieveIdentity() throws -> Data {
        publicKeyData
    }

    func createLocalEncryptionKey() throws -> SymmetricKey? {
        // Derive a fixed local key from a well-known point — same as production
        // but using the in-memory private key instead of SE.
        let fixedX963 = Data([
            0x04,
            0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
            0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
            0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
            0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
            0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
            0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
            0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
            0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
        ])
        return createSharedSecret(using: fixedX963)
    }

    func createSharedSecret(using material: Data?) -> SymmetricKey? {
        guard let material else { return nil }
        
        return deriveKey(privateKey: privateKey, ourPublicKeyData: publicKeyData, peerMaterial: material)
    }

    func createSharedSecret(
        ephemeralPrivateKey: SecKey,
        recipientMaterial: Data
    ) -> SymmetricKey? {
        guard
            let ephPub     = SecKeyCopyPublicKey(ephemeralPrivateKey),
            let ephPubData = SecKeyCopyExternalRepresentation(ephPub, nil) as Data?
        else { return nil }

        return deriveKey(
            privateKey:       ephemeralPrivateKey,
            ourPublicKeyData: ephPubData,
            peerMaterial:     recipientMaterial
        )
    }

    func generateEphemeralKeyPair() -> (privateKey: SecKey, publicKeyData: Data)? {
        let attributes: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
        ]
        var error: Unmanaged<CFError>?
        guard
            let priv     = SecKeyCreateRandomKey(attributes, &error),
            let pub      = SecKeyCopyPublicKey(priv),
            let pubData  = SecKeyCopyExternalRepresentation(pub, nil) as Data?
        else { return nil }
        return (priv, pubData)
    }

    // MARK: - Private

    private func deriveKey(
        privateKey:       SecKey,
        ourPublicKeyData: Data,
        peerMaterial:     Data
    ) -> SymmetricKey? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String:     kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:    kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard
            let peerKey = SecKeyCreateWithData(peerMaterial as CFData, attributes as CFDictionary, &error)
        else { return nil }

        let algorithm: SecKeyAlgorithm = .ecdhKeyExchangeCofactorX963SHA256
        guard
            let rawSecret = SecKeyCopyKeyExchangeResult(
                privateKey, algorithm, peerKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        else { return nil }

        let peerBuf: [UInt8] = peerMaterial.map { $0 }
        let ourBuf:  [UInt8] = ourPublicKeyData.map { $0 }
        let salt = Data(zip(peerBuf, ourBuf).map { $0 ^ $1 })

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: salt,
            info: "Occulta-v1-encryption-key-2025".data(using: .utf8)!,
            outputByteCount: 32
        )
    }
}

//
//  KeyManagerProtocol.swift
//  Occulta
//
//  Created by Yura on 3/19/26.
//

import Foundation
import CryptoKit

// MARK: - KeyManagerProtocol

protocol KeyManagerProtocol {
    func retrieveIdentity() throws -> Data
    func createLocalEncryptionKey() throws -> SymmetricKey?
    /// Transport path — uses `kTransportKeyInfo`.
    func createSharedSecret(using material: Data?) -> SymmetricKey?
    /// Transport path (ephemeral/prekey) — uses `kTransportKeyInfo`.
    func createSharedSecret(ephemeralPrivateKey: SecKey, recipientMaterial: Data) -> SymmetricKey?
    func generateEphemeralKeyPair() -> (privateKey: SecKey, publicKeyData: Data)?
}

// MARK: - Manager.Key conformance

extension Manager.Key: KeyManagerProtocol { }

// MARK: - TestKeyManager

/// In-memory P-256 key manager for unit tests.
/// No Secure Enclave — safe to run in the test process.
/// Uses the same HKDF info strings as production.
@MainActor
final class TestKeyManager: KeyManagerProtocol {
    private let privateKey:    SecKey
    private let publicKeyData: Data

    init() {
        let attrs: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
        ]
        var err: Unmanaged<CFError>?
        let priv = SecKeyCreateRandomKey(attrs, &err)!
        let pub  = SecKeyCopyPublicKey(priv)!
        
        self.privateKey    = priv
        self.publicKeyData = SecKeyCopyExternalRepresentation(pub, nil)! as Data
    }

    func retrieveIdentity() throws -> Data { self.publicKeyData }

    /// Local DB key — uses `kLocalDBKeyInfo` to match production Key+Manager.
    func createLocalEncryptionKey() throws -> SymmetricKey? {
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
        return self.deriveKey(privateKey: self.privateKey, ourPublicKeyData: self.publicKeyData, peerMaterial: fixedX963, info: SaltInfo.kLocalDBKeyInfo)
    }

    /// Transport — uses `kTransportKeyInfo`.
    func createSharedSecret(using material: Data?) -> SymmetricKey? {
        guard let material else { return nil }
        
        return self.deriveKey(privateKey: self.privateKey, ourPublicKeyData: self.publicKeyData, peerMaterial: material, info: SaltInfo.kTransportKeyInfo)
    }

    /// Transport (ephemeral/prekey) — uses `kTransportKeyInfo`.
    func createSharedSecret(ephemeralPrivateKey: SecKey, recipientMaterial: Data) -> SymmetricKey? {
        guard
            let pub  = SecKeyCopyPublicKey(ephemeralPrivateKey),
            let data = SecKeyCopyExternalRepresentation(pub, nil) as Data?
        else { return nil }
        
        return self.deriveKey(privateKey: ephemeralPrivateKey, ourPublicKeyData: data, peerMaterial: recipientMaterial, info: SaltInfo.kTransportKeyInfo)
    }

    func generateEphemeralKeyPair() -> (privateKey: SecKey, publicKeyData: Data)? {
        let attrs: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
        ]
        var err: Unmanaged<CFError>?
        guard
            let priv = SecKeyCreateRandomKey(attrs, &err),
            let pub  = SecKeyCopyPublicKey(priv),
            let data = SecKeyCopyExternalRepresentation(pub, nil) as Data?
        else { return nil }
        
        return (priv, data)
    }

    // MARK: - Private

    private func deriveKey(privateKey: SecKey, ourPublicKeyData: Data, peerMaterial: Data, info: Data) -> SymmetricKey? {
        guard peerMaterial.count == 65 else { return nil }

        let attrs: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:      kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var err: Unmanaged<CFError>?
        guard
            let peerKey = SecKeyCreateWithData(peerMaterial as CFData, attrs as CFDictionary, &err)
        else { return nil }

        guard
            let rawSecret = SecKeyCopyKeyExchangeResult(privateKey, .ecdhKeyExchangeCofactorX963SHA256, peerKey, [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary, &err) as? Data
        else { return nil }

        let salt = Data(zip(peerMaterial.map { $0 }, ourPublicKeyData.map { $0 }).map { $0 ^ $1 })

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: salt,
            info: info,
            outputByteCount: 32
        )
    }
}

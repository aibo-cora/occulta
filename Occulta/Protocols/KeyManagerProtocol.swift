//
//  KeyManagerProtocol.swift
//  Occulta
//
//

import Foundation
import CryptoKit

// MARK: - KeyManagerProtocol

protocol KeyManagerProtocol {
    func retrieveIdentity() throws -> Data
    /// v1 path — ECDH(identity_key, G) → HKDF. Retained for migration decrypt only.
    func createLocalEncryptionKey() throws -> SymmetricKey?
    /// v2 path — HKDF(ECDH(localDB_SE_key, G) || random_keychain). PQ-reinforced.
    func createHybridLocalEncryptionKey() throws -> SymmetricKey?
    /// Transport path — uses `kTransportKeyInfo`.
    func createSharedSecret(using material: Data?) -> SymmetricKey?
    /// Transport path (ephemeral/prekey) — uses `kTransportKeyInfo`.
    func createSharedSecret(ephemeralPrivateKey: SecKey, recipientMaterial: Data) -> SymmetricKey?
    func generateEphemeralKeyPair() -> (privateKey: SecKey, publicKeyData: Data)?
    
    // MARK: - Hybrid PQ (HKDF only — no ML-KEM types)
     
    func createHybridSharedSecret(peerP256Material: Data, quantumMaterial: QuantumKeyMaterial) -> SymmetricKey?
    func createHybridFSSharedSecret(ephemeralPrivateKey: SecKey, recipientMaterial: Data, quantumMaterial: QuantumKeyMaterial) -> SymmetricKey?
    
    func createDicewareKey(peerP256Material: Data, quantumMaterial: QuantumKeyMaterial, ourNonce: Data, peerNonce: Data) -> SymmetricKey?
    func generateExchangeNonce() -> Data?
}

// MARK: - TestKeyManager

/// In-memory P-256 key manager for unit tests.
/// No Secure Enclave — safe to run in the test process.
@MainActor
final class TestKeyManager: KeyManagerProtocol {
    private let identityPrivateKey: SecKey
    private let identityPublicKeyData: Data

    /// Separate key pair simulating the dedicated local DB SE key.
    private let localDBPrivateKey: SecKey
    private let localDBPublicKeyData: Data

    /// Simulates the random Keychain component (32 bytes).
    private let randomComponent: Data
    
    var privateKey: Data?
    var publicKeyData: Data?

    /// Fixed generator point G for ECDH derivation.
    private let fixedX963 = Data([
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

    init() {
        // Identity key pair
        let attrs: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
        ]
        var err: Unmanaged<CFError>?
        let identityPriv = SecKeyCreateRandomKey(attrs, &err)!
        let identityPub  = SecKeyCopyPublicKey(identityPriv)!

        self.identityPrivateKey    = identityPriv
        self.identityPublicKeyData = SecKeyCopyExternalRepresentation(identityPub, nil)! as Data

        // Separate local DB key pair (simulates dedicated SE key)
        let localDBPriv = SecKeyCreateRandomKey(attrs, &err)!
        let localDBPub  = SecKeyCopyPublicKey(localDBPriv)!

        self.localDBPrivateKey    = localDBPriv
        self.localDBPublicKeyData = SecKeyCopyExternalRepresentation(localDBPub, nil)! as Data

        // Random component (simulates Keychain-stored random bytes)
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
        self.randomComponent = Data(bytes)
    }

    func retrieveIdentity() throws -> Data { self.identityPublicKeyData }

    /// v1 — identity-derived local key. Used only for migration tests.
    func createLocalEncryptionKey() throws -> SymmetricKey? {
        self.deriveKey(
            privateKey: self.identityPrivateKey,
            ourPublicKeyData: self.identityPublicKeyData,
            peerMaterial: self.fixedX963,
            info: SaltInfo.kLocalDBKeyInfo
        )
    }

    /// v2 — hybrid PQ-reinforced local key.
    func createHybridLocalEncryptionKey() throws -> SymmetricKey? {
        // Step 1: SE-derived component via ECDH(localDB_key, G)
        guard
            let seComponent = self.deriveRawECDH(
                privateKey: self.localDBPrivateKey,
                peerMaterial: self.fixedX963
            )
        else { return nil }

        // Step 2: Combine SE component + random component via HKDF
        var ikm = Data(seComponent)
        ikm.append(self.randomComponent)

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: self.localDBPublicKeyData,
            info: SaltInfo.kLocalDBHybridKeyInfo,
            outputByteCount: 32
        )
    }

    func createSharedSecret(using material: Data?) -> SymmetricKey? {
        guard let material else { return nil }
        return self.deriveKey(
            privateKey: self.identityPrivateKey,
            ourPublicKeyData: self.identityPublicKeyData,
            peerMaterial: material,
            info: SaltInfo.kTransportKeyInfo
        )
    }

    func createSharedSecret(ephemeralPrivateKey: SecKey, recipientMaterial: Data) -> SymmetricKey? {
        guard
            let pub  = SecKeyCopyPublicKey(ephemeralPrivateKey),
            let data = SecKeyCopyExternalRepresentation(pub, nil) as Data?
        else { return nil }
        return self.deriveKey(
            privateKey: ephemeralPrivateKey,
            ourPublicKeyData: data,
            peerMaterial: recipientMaterial,
            info: SaltInfo.kTransportKeyInfo
        )
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

    /// Raw 32-byte ECDH output without HKDF.
    private func deriveRawECDH(privateKey: SecKey, peerMaterial: Data) -> Data? {
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
            let rawSecret = SecKeyCopyKeyExchangeResult(
                privateKey, .ecdhKeyExchangeCofactorX963SHA256, peerKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &err
            ) as? Data
        else { return nil }

        return rawSecret
    }

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
            let rawSecret = SecKeyCopyKeyExchangeResult(
                privateKey, .ecdhKeyExchangeCofactorX963SHA256, peerKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &err
            ) as? Data
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

extension TestKeyManager {
    func createHybridSharedSecret(
        peerP256Material: Data,
        quantumMaterial: QuantumKeyMaterial
    ) -> SymmetricKey? {
        guard let ecdh = self.rawECDHWithSalt(peerP256Material: peerP256Material) else { return nil }
        guard quantumMaterial.isValid else { return nil }
 
        let sorted = [quantumMaterial.encapsulatedSecret, quantumMaterial.decapsulatedSecret]
            .sorted { $0.lexicographicallyPrecedes($1) }
        var ikm = ecdh.rawECDH
        ikm.append(contentsOf: sorted[0])
        ikm.append(contentsOf: sorted[1])
 
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: ecdh.salt,
            info: SaltInfo.kHybridTransportKeyInfo,
            outputByteCount: 32
        )
    }
    
    func createHybridFSSharedSecret(
        ephemeralPrivateKey: SecKey,
        recipientMaterial: Data,
        quantumMaterial: QuantumKeyMaterial
    ) -> SymmetricKey? {
        guard recipientMaterial.count == 65 else { return nil }
        guard quantumMaterial.isValid else { return nil }

        guard
            let ephemeralPublicKey = SecKeyCopyPublicKey(ephemeralPrivateKey),
            let ephemeralPublicKeyData = SecKeyCopyExternalRepresentation(ephemeralPublicKey, nil) as Data?
        else { return nil }

        let attrs: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:      kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var err: Unmanaged<CFError>?
        guard
            let peerKey = SecKeyCreateWithData(recipientMaterial as CFData, attrs as CFDictionary, &err)
        else { return nil }

        guard
            let rawECDH = SecKeyCopyKeyExchangeResult(
                ephemeralPrivateKey, .ecdhKeyExchangeCofactorX963SHA256, peerKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary, &err
            ) as? Data
        else { return nil }

        let sorted = [quantumMaterial.encapsulatedSecret, quantumMaterial.decapsulatedSecret]
            .sorted { $0.lexicographicallyPrecedes($1) }

        var ikm = rawECDH
        ikm.append(contentsOf: sorted[0])
        ikm.append(contentsOf: sorted[1])

        let salt = Data(zip(recipientMaterial, ephemeralPublicKeyData).map { $0 ^ $1 })

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: salt,
            info: SaltInfo.kHybridFSTransportKeyInfo,
            outputByteCount: 32
        )
    }
    
    func createDicewareKey(
        peerP256Material: Data,
        quantumMaterial: QuantumKeyMaterial,
        ourNonce: Data,
        peerNonce: Data
    ) -> SymmetricKey? {
        guard let ecdh = self.rawECDHWithSalt(peerP256Material: peerP256Material) else { return nil }
        guard quantumMaterial.isValid else { return nil }
        guard ourNonce.count == 16, peerNonce.count == 16 else { return nil }
 
        let sortedSecrets = [quantumMaterial.encapsulatedSecret, quantumMaterial.decapsulatedSecret]
            .sorted { $0.lexicographicallyPrecedes($1) }
        var ikm = ecdh.rawECDH
        ikm.append(contentsOf: sortedSecrets[0])
        ikm.append(contentsOf: sortedSecrets[1])
 
        let sortedNonces = [ourNonce, peerNonce].sorted { $0.lexicographicallyPrecedes($1) }
        var info = SaltInfo.kDicewareKeyInfo
        info.append(contentsOf: sortedNonces[0])
        info.append(contentsOf: sortedNonces[1])
 
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: ecdh.salt,
            info: info,
            outputByteCount: 32
        )
    }
    
    func generateExchangeNonce() -> Data? {
        var bytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return nil }
        return Data(bytes)
    }
 
    // MARK: - Private
 
    /// Raw ECDH + XOR salt without HKDF. Hybrid derivation combines ECDH with
    /// ML-KEM secrets before a single HKDF pass — running HKDF twice would produce the wrong key.
    private func rawECDHWithSalt(peerP256Material: Data) -> (rawECDH: Data, salt: Data)? {
        guard peerP256Material.count == 65 else { return nil }
 
        let attrs: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:      kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        
        var err: Unmanaged<CFError>?
        guard
            let peerKey = SecKeyCreateWithData(peerP256Material as CFData, attrs as CFDictionary, &err),
            let privateKeyData = self.privateKey,
            let privateKey = SecKeyCreateWithData(privateKeyData as CFData, attrs as CFDictionary, nil)
        else { return nil }
 
        guard
            let publicKeyData = self.publicKeyData,
            let rawECDH = SecKeyCopyKeyExchangeResult(privateKey, .ecdhKeyExchangeCofactorX963SHA256, peerKey, [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary, &err) as? Data
        else { return nil }
 
        let salt = Data(zip(peerP256Material, publicKeyData).map { $0 ^ $1 })
        
        return (rawECDH, salt)
    }
}

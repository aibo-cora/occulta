//
//  PQTestKeyPair.swift
//  OccultaTests
//
//  Non-isolated P-256 key pair for PQ unit tests.
//  Avoids the @MainActor isolation on TestKeyManager that causes memory corruption
//  when XCTest lifecycle methods cross actor boundaries.
//
//  This type performs the same ECDH + HKDF operations as Manager.Key / TestKeyManager
//  but without actor isolation, Secure Enclave access, or lifecycle dependencies.
//

import Foundation
import CryptoKit

@testable import Occulta

/// A non-isolated, in-memory P-256 key pair for testing hybrid HKDF derivation.
///
/// Created inline as a stored property or local variable — never in setUp().
/// No @MainActor, no SE, no keychain. Safe to use from any thread.
struct PQTestKeyPair {
    let privateKey: SecKey
    let publicKeyData: Data

    init() {
        let attributes: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
        ]
        var error: Unmanaged<CFError>?
        let generatedPrivateKey = SecKeyCreateRandomKey(attributes, &error)!
        let generatedPublicKey = SecKeyCopyPublicKey(generatedPrivateKey)!

        self.privateKey = generatedPrivateKey
        self.publicKeyData = SecKeyCopyExternalRepresentation(generatedPublicKey, nil)! as Data
    }

    // MARK: - Classical ECDH (for comparison tests)

    func createClassicalSharedSecret(peerPublicKeyData: Data) -> SymmetricKey? {
        guard peerPublicKeyData.count == 65 else { return nil }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:      kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard
            let peerKey = SecKeyCreateWithData(peerPublicKeyData as CFData, attributes as CFDictionary, &error)
        else { return nil }

        guard
            let rawECDH = SecKeyCopyKeyExchangeResult(
                self.privateKey, .ecdhKeyExchangeCofactorX963SHA256, peerKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary, &error
            ) as? Data
        else { return nil }

        let salt = Data(zip(peerPublicKeyData, self.publicKeyData).map { $0 ^ $1 })

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawECDH),
            salt: salt,
            info: SaltInfo.kTransportKeyInfo,
            outputByteCount: 32
        )
    }

    // MARK: - Hybrid ECDH + ML-KEM (identity-level)

    func createHybridSharedSecret(peerPublicKeyData: Data, quantumMaterial: QuantumKeyMaterial) -> SymmetricKey? {
        guard let ecdhResult = self.rawECDHWithSalt(peerPublicKeyData: peerPublicKeyData) else { return nil }
        guard quantumMaterial.isValid else { return nil }

        let sorted = [quantumMaterial.encapsulatedSecret, quantumMaterial.decapsulatedSecret]
            .sorted { $0.lexicographicallyPrecedes($1) }

        var inputKeyMaterial = ecdhResult.rawECDH
        inputKeyMaterial.append(contentsOf: sorted[0])
        inputKeyMaterial.append(contentsOf: sorted[1])

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: inputKeyMaterial),
            salt: ecdhResult.salt,
            info: SaltInfo.kHybridTransportKeyInfo,
            outputByteCount: 32
        )
    }

    // MARK: - Hybrid Diceware

    func createDicewareKey(peerPublicKeyData: Data, quantumMaterial: QuantumKeyMaterial, ourNonce: Data, peerNonce: Data) -> SymmetricKey? {
        guard let ecdhResult = self.rawECDHWithSalt(peerPublicKeyData: peerPublicKeyData) else { return nil }
        guard quantumMaterial.isValid else { return nil }
        guard ourNonce.count == 16, peerNonce.count == 16 else { return nil }

        let sortedSecrets = [quantumMaterial.encapsulatedSecret, quantumMaterial.decapsulatedSecret]
            .sorted { $0.lexicographicallyPrecedes($1) }

        var inputKeyMaterial = ecdhResult.rawECDH
        inputKeyMaterial.append(contentsOf: sortedSecrets[0])
        inputKeyMaterial.append(contentsOf: sortedSecrets[1])

        let sortedNonces = [ourNonce, peerNonce].sorted { $0.lexicographicallyPrecedes($1) }
        var info = SaltInfo.kDicewareKeyInfo
        info.append(contentsOf: sortedNonces[0])
        info.append(contentsOf: sortedNonces[1])

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: inputKeyMaterial),
            salt: ecdhResult.salt,
            info: info,
            outputByteCount: 32
        )
    }

    // MARK: - Private

    private struct ECDHResult {
        let rawECDH: Data
        let salt: Data
    }

    private func rawECDHWithSalt(peerPublicKeyData: Data) -> ECDHResult? {
        guard peerPublicKeyData.count == 65 else { return nil }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:      kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard
            let peerKey = SecKeyCreateWithData(peerPublicKeyData as CFData, attributes as CFDictionary, &error)
        else { return nil }

        guard
            let rawECDH = SecKeyCopyKeyExchangeResult(
                self.privateKey, .ecdhKeyExchangeCofactorX963SHA256, peerKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary, &error
            ) as? Data
        else { return nil }

        let salt = Data(zip(peerPublicKeyData, self.publicKeyData).map { $0 ^ $1 })
        return ECDHResult(rawECDH: rawECDH, salt: salt)
    }
}

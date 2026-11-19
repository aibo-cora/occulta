//
//  PQTestKeyPair.swift
//  OccultaTests
//
//  Non-isolated P-256 key pair for PQ unit tests.
//  Avoids the @MainActor isolation on TestKeyManager that causes memory corruption
//  when XCTest lifecycle methods cross actor boundaries.
//
//  This type performs the same ECDH, then the same TransportKeyDerivation call, as Manager.Key / TestKeyManager
//  but without actor isolation, Secure Enclave access, or lifecycle dependencies.
//

import Foundation
import CryptoKit
import OccultaCore

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
        guard let rawECDH = self.rawECDH(peerPublicKeyData: peerPublicKeyData) else { return nil }
        return try? TransportKeyDerivation.sessionKey(
            ecdhOutput: rawECDH, ownPublicKey: self.publicKeyData, peerPublicKey: peerPublicKeyData,
            postQuantumSecrets: nil, info: SaltInfo.kTransportKeyInfo
        )
    }

    // MARK: - Hybrid ECDH + ML-KEM (identity-level)

    func createHybridSharedSecret(peerPublicKeyData: Data, quantumMaterial: QuantumKeyMaterial) -> SymmetricKey? {
        guard let rawECDH = self.rawECDH(peerPublicKeyData: peerPublicKeyData) else { return nil }
        return try? TransportKeyDerivation.sessionKey(
            ecdhOutput: rawECDH, ownPublicKey: self.publicKeyData, peerPublicKey: peerPublicKeyData,
            postQuantumSecrets: quantumMaterial.sharedSecrets, info: SaltInfo.kHybridTransportKeyInfo
        )
    }

    // MARK: - Hybrid Diceware

    func createDicewareKey(peerPublicKeyData: Data, quantumMaterial: QuantumKeyMaterial, ourNonce: Data, peerNonce: Data) -> SymmetricKey? {
        guard let rawECDH = self.rawECDH(peerPublicKeyData: peerPublicKeyData) else { return nil }
        guard ourNonce.count == 16, peerNonce.count == 16 else { return nil }

        let sortedNonces = [ourNonce, peerNonce].sorted { $0.lexicographicallyPrecedes($1) }
        var info = SaltInfo.kDicewareKeyInfo
        info.append(contentsOf: sortedNonces[0])
        info.append(contentsOf: sortedNonces[1])

        return try? TransportKeyDerivation.sessionKey(
            ecdhOutput: rawECDH, ownPublicKey: self.publicKeyData, peerPublicKey: peerPublicKeyData,
            postQuantumSecrets: quantumMaterial.sharedSecrets, info: info
        )
    }

    // MARK: - Private

    private func rawECDH(peerPublicKeyData: Data) -> Data? {
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

        return SecKeyCopyKeyExchangeResult(
            self.privateKey, .ecdhKeyExchangeCofactorX963SHA256, peerKey,
            [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary, &error
        ) as? Data
    }
}

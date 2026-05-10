//
//  KeyManagerProtocol.swift
//  Occulta
//
//

import Foundation
import CryptoKit
import LocalAuthentication

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

    // MARK: - Identity challenge

    /// ECDSA-sign `data` with the long-term SE identity key (or the in-memory
    /// equivalent, in tests).
    ///
    /// Algorithm: `.ecdsaSignatureMessageX962SHA256`. The algorithm hashes
    /// `data` internally with SHA-256 — callers MUST NOT pre-hash.
    /// Double-hashing produces a signature that no verifier will accept,
    /// silently breaking identity verification.
    ///
    /// - Returns: DER-encoded ECDSA signature, raw bytes from `SecKeyCreateSignature`.
    func signIdentityChallenge(_ data: Data) throws -> Data

    // MARK: - Vault

    /// Derive the vault session key: ECDH(vault_SE_priv, G) → HKDF-SHA256.
    ///
    /// The `context` must be a pre-evaluated LAContext. The SE uses it to satisfy
    /// the biometric access control on the vault key without prompting the user.
    ///
    /// The returned SymmetricKey is scope-bounded — callers must not store it.
    ///
    /// - Returns: 256-bit SymmetricKey, or nil if the SE is unavailable.
    func deriveVaultKey(context: LAContext) throws -> SymmetricKey?

    /// ECDSA-sign `data` with the SE identity key (used for vault shard signing).
    ///
    /// ⚠️ DO NOT pre-hash — `.ecdsaSignatureMessageX962SHA256` hashes internally.
    ///
    /// - Returns: DER-encoded ECDSA signature.
    func signData(_ data: Data) throws -> Data

    /// Derive the shard custody key: ECDH(shardCustody_SE_priv, G) → HKDF-SHA256.
    ///
    /// No LAContext needed — the shard custody SE key has device-unlock-level access
    /// (no biometric flag). Enables fully automatic shard operations on bundle receipt.
    ///
    /// - Returns: 256-bit SymmetricKey, or nil if the SE is unavailable.
    func deriveShardCustodyKey() throws -> SymmetricKey?
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

    /// Separate key pair simulating the dedicated vault SE key.
    private let vaultPrivateKey: SecKey
    private let vaultPublicKeyData: Data

    /// Separate key pair simulating the dedicated shard custody SE key.
    private let shardCustodyPrivateKey: SecKey
    private let shardCustodyPublicKeyData: Data

    /// Simulates the random Keychain component for the local DB hybrid key (32 bytes).
    private let randomComponent: Data

    /// Set to true to make deriveVaultKey(context:) throw — tests lock-on-failure behaviour.
    var simulateVaultKeyFailure = false

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
        let attrs: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
        ]
        var err: Unmanaged<CFError>?

        // Identity key pair
        let identityPriv = SecKeyCreateRandomKey(attrs, &err)!
        let identityPub  = SecKeyCopyPublicKey(identityPriv)!
        self.identityPrivateKey    = identityPriv
        self.identityPublicKeyData = SecKeyCopyExternalRepresentation(identityPub, nil)! as Data

        // Separate local DB key pair (simulates dedicated SE key)
        let localDBPriv = SecKeyCreateRandomKey(attrs, &err)!
        let localDBPub  = SecKeyCopyPublicKey(localDBPriv)!
        self.localDBPrivateKey    = localDBPriv
        self.localDBPublicKeyData = SecKeyCopyExternalRepresentation(localDBPub, nil)! as Data

        // Separate vault key pair (simulates dedicated vault SE key)
        let vaultPriv = SecKeyCreateRandomKey(attrs, &err)!
        let vaultPub  = SecKeyCopyPublicKey(vaultPriv)!
        self.vaultPrivateKey    = vaultPriv
        self.vaultPublicKeyData = SecKeyCopyExternalRepresentation(vaultPub, nil)! as Data

        // Separate shard custody key pair (simulates dedicated shard custody SE key)
        let shardCustodyPriv = SecKeyCreateRandomKey(attrs, &err)!
        let shardCustodyPub  = SecKeyCopyPublicKey(shardCustodyPriv)!
        self.shardCustodyPrivateKey    = shardCustodyPriv
        self.shardCustodyPublicKeyData = SecKeyCopyExternalRepresentation(shardCustodyPub, nil)! as Data

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
        guard
            let seComponent = self.deriveRawECDH(
                privateKey: self.localDBPrivateKey,
                peerMaterial: self.fixedX963
            )
        else { return nil }

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

    // MARK: - Vault (TestKeyManager)

    /// ECDH(vaultPrivateKey, G) → HKDF — mirrors Manager.Key.deriveVaultKey(context:).
    ///
    /// The `context` parameter is ignored in tests — no SE, no biometric evaluation.
    /// `simulateVaultKeyFailure = true` makes this throw to test lock-on-failure.
    func deriveVaultKey(context: LAContext) throws -> SymmetricKey? {
        if simulateVaultKeyFailure { throw SimulatedFailure() }

        guard let fixedPubKey = makePublicKey(from: fixedX963) else { return nil }

        var err: Unmanaged<CFError>?
        guard
            let rawSecret = SecKeyCopyKeyExchangeResult(
                vaultPrivateKey, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &err
            ) as? Data
        else { return nil }

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: vaultPublicKeyData,
            info: SaltInfo.kVaultKeyInfo,
            outputByteCount: 32
        )
    }

    // MARK: - Shard custody (TestKeyManager)

    /// ECDH(shardCustodyPrivateKey, G) → HKDF — mirrors Manager.Key.deriveShardCustodyKey().
    ///
    /// The context-free signature mirrors the real key (no biometric needed).
    func deriveShardCustodyKey() throws -> SymmetricKey? {
        guard let fixedPubKey = makePublicKey(from: fixedX963) else { return nil }

        var err: Unmanaged<CFError>?
        guard
            let rawSecret = SecKeyCopyKeyExchangeResult(
                shardCustodyPrivateKey, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &err
            ) as? Data
        else { return nil }

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: shardCustodyPublicKeyData,
            info: SaltInfo.kShardCustodyKeyInfo,
            outputByteCount: 32
        )
    }

    // MARK: - Identity challenge

    /// In-memory ECDSA-sign with the test identity private key.
    /// ⚠️ DO NOT PRE-HASH — `.ecdsaSignatureMessageX962SHA256` hashes internally.
    func signIdentityChallenge(_ data: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard
            let signature = SecKeyCreateSignature(
                self.identityPrivateKey,
                .ecdsaSignatureMessageX962SHA256,
                data as CFData,
                &error
            ) as Data?
        else { throw error!.takeRetainedValue() as Error }
        return signature
    }

    /// In-memory ECDSA-sign — mirrors Manager.Key.signData(_:).
    /// ⚠️ DO NOT pre-hash — `.ecdsaSignatureMessageX962SHA256` hashes internally.
    func signData(_ data: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard
            let sig = SecKeyCreateSignature(
                identityPrivateKey,
                .ecdsaSignatureMessageX962SHA256,
                data as CFData,
                &error
            ) as Data?
        else { throw error!.takeRetainedValue() as Error }
        return sig
    }

    // MARK: - Private

    struct SimulatedFailure: Error {}

    private func makePublicKey(from data: Data) -> SecKey? {
        guard data.count == 65 else { return nil }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:      kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var err: Unmanaged<CFError>?
        return SecKeyCreateWithData(data as CFData, attrs as CFDictionary, &err)
    }

    /// Raw 32-byte ECDH output without HKDF.
    private func deriveRawECDH(privateKey: SecKey, peerMaterial: Data) -> Data? {
        guard let peerKey = makePublicKey(from: peerMaterial) else { return nil }
        var err: Unmanaged<CFError>?
        return SecKeyCopyKeyExchangeResult(
            privateKey, .ecdhKeyExchangeCofactorX963SHA256, peerKey,
            [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
            &err
        ) as? Data
    }

    private func deriveKey(privateKey: SecKey, ourPublicKeyData: Data, peerMaterial: Data, info: Data) -> SymmetricKey? {
        guard let rawSecret = deriveRawECDH(privateKey: privateKey, peerMaterial: peerMaterial) else { return nil }
        let salt = Data(zip(peerMaterial, ourPublicKeyData).map { $0 ^ $1 })
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: salt,
            info: info,
            outputByteCount: 32
        )
    }

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
            let privateKey = self.privateKey,
            let privKeyRef = SecKeyCreateWithData(privateKey as CFData, [
                kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass as String:      kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits as String: 256
            ] as CFDictionary, &err)
        else { return nil }

        guard
            let publicKeyData = self.publicKeyData,
            let rawECDH = SecKeyCopyKeyExchangeResult(
                privKeyRef, .ecdhKeyExchangeCofactorX963SHA256, peerKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &err
            ) as? Data
        else { return nil }

        let salt = Data(zip(peerP256Material, publicKeyData).map { $0 ^ $1 })
        return (rawECDH, salt)
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
        guard let peerKey = SecKeyCreateWithData(recipientMaterial as CFData, attrs as CFDictionary, &err) else {
            return nil
        }

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
}

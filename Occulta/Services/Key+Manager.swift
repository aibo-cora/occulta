//
//  Key+Manager.swift
//  Occulta
//
//  Created by Yura on 11/12/25.
//

import Foundation
import CryptoKit
import LocalAuthentication

// MARK: - HKDF info strings

struct SaltInfo {
    static let kTransportKeyInfo = "Occulta-v1-transport-2025".data(using: .utf8)!
    static let kLocalDBKeyInfo   = "Occulta-v1-encryption-key-2025".data(using: .utf8)!
    /// Domain separator for the hybrid local DB key. Distinct from kLocalDBKeyInfo
    /// to ensure the old (identity-derived) and new (hybrid) keys are never equivalent,
    /// even if the same SE key is used during migration.
    static let kLocalDBHybridKeyInfo = "Occulta-v2-local-db-pq-2026".data(using: .utf8)!
    /// Hybrid transport key: ECDH + ML-KEM combined input keying material.
    /// Used for long-term fallback encryption between PQ-capable contacts.
    static let kHybridTransportKeyInfo = "Occulta-v2-hybrid-pq-transport-2026".data(using: .utf8)!
    /// Hybrid forward-secret transport key: ECDH(ephemeral, prekey) + ML-KEM combined IKM.
    /// Domain-separated from the fallback hybrid path to prevent key collision.
    static let kHybridFSTransportKeyInfo = "Occulta-v2-hybrid-pq-fs-transport-2026".data(using: .utf8)!
    /// Diceware verification key: same hybrid IKM, but with exchange nonces
    /// appended to the info field for per-session uniqueness.
    /// The nonces are appended at call time — this is the static prefix only.
    static let kDicewareKeyInfo = "Occulta-v2-diceware-2026".data(using: .utf8)!
    /// Vault key: ECDH(vault_SE_priv, G) → HKDF. The vault SE key is a dedicated
    /// SE key protected by .biometryCurrentSet — separate from the identity key.
    /// The derived SymmetricKey lives only as a local per-operation value; never stored.
    /// Domain-separated from all transport and local-DB paths.
    static let kVaultKeyInfo = "Occulta-v1-vault-2026".data(using: .utf8)!
    /// Shard custody key: ECDH(shard_custody_SE_priv, G) → HKDF. Dedicated SE key
    /// with device-unlock-level access (no biometric). Used to seal CustodyShard
    /// records locally — fully automatic, no user friction.
    static let kShardCustodyKeyInfo = "Occulta-v1-shard-custody-2026".data(using: .utf8)!
    /// Secure Mode PIN key: ECDH(secureModePin_SE_priv, G) → HKDF. Dedicated SE key
    /// with device-unlock-level access (no biometric). Used to wrap PIN sentinels in
    /// AppLayerConfig. Domain-separated from all other key paths.
    static let kSecureModeKeyInfo = "Occulta-v1-secure-mode-pin-2026".data(using: .utf8)!
    /// Recovery buffer key: same SE key as shard custody, distinct HKDF info →
    /// dedicated symmetric key. Used to encrypt ReconstructShard rows — the
    /// transient buffer of returned shards Alice's device collects during
    /// reconstruction. Domain-separated from kShardCustodyKeyInfo so a custody
    /// blob and a reconstruct blob are never decryptable with the same key.
    static let kRecoveryBufferKeyInfo = "Occulta-v1-recovery-buffer-2026".data(using: .utf8)!
}

// MARK: - SE Key Inventory
//
// Manager.Key manages five distinct Secure Enclave P-256 key objects:
//
//  Tag                                      │ Biometric gate │ Purpose
//  ─────────────────────────────────────────┼────────────────┼──────────────────────────────────────
//  "master.key.privacy.turtles.are.cute"    │ No             │ Identity — ECDSA signing, ECDH transport
//  "local.db.se.key.occulta"                │ No             │ Local DB hybrid key ECDH component
//  "vault.key.occulta.v1"                   │ Yes (.biometryCurrentSet + .devicePasscode) │ Vault PEK derivation
//  "shard.custody.occulta"                  │ No             │ Shard custody records + recovery buffer
//  "app.layer.key.occulta.v1"               │ No             │ Secure Mode PIN sentinel encryption
//
// All four keys carry `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — never backed up,
// never synced to iCloud Keychain.
//
// The vault SE key requires a pre-evaluated `LAContext`; the other three operate
// automatically while the device is unlocked.
//
// The shard custody key is reused as the base for the recovery buffer key — the two
// derived symmetric keys are domain-separated by `kShardCustodyKeyInfo` vs
// `kRecoveryBufferKeyInfo` in HKDF.

extension Manager {
    class Key {
        let tag: String

        init() { self.tag = Tags.identity.rawValue }
        init(testingTag tag: String) { self.tag = tag }

        private enum Tags: String, CaseIterable {
            case identity      = "master.key.privacy.turtles.are.cute"
            case localDB       = "local.db.se.key.occulta"
            case vault         = "vault.key.occulta.v1"
            case shardCustody  = "shard.custody.occulta"
            case secureModePin = "app.layer.key.occulta.v1"
        }

        // MARK: - SE key creation

        private func create() throws -> Bool {
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage],
                &error
            ) else { throw error!.takeRetainedValue() as Error }

            let attributes: NSDictionary = [
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits: 256,
                kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs: [
                    kSecAttrIsPermanent: true,
                    kSecAttrApplicationTag: self.tag.data(using: .utf8)!,
                    kSecAttrAccessControl: access
                ]
            ]
            guard let _ = SecKeyCreateRandomKey(attributes, &error) else {
                throw error!.takeRetainedValue() as Error
            }
            return true
        }

        // P-256 generator base point G — fixed peer for local DB key derivation.
        let fixedX963: Data = Data([
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

        // MARK: - Local DB encryption key (kLocalDBKeyInfo)

        func createLocalEncryptionKey() throws -> SymmetricKey? {
            guard let ourPrivateKey = try? self.retrievePrivateKey() else { return nil }
            guard let fixedPubKey = self.convert(material: self.fixedX963) else { return nil }

            var error: Unmanaged<CFError>?
            guard
                let rawSecret = SecKeyCopyKeyExchangeResult(
                    ourPrivateKey, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey,
                    [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                    &error
                ) as? Data
            else { return nil }

            guard let ourPubData = self.convert(key: self.retrivePublicKey(using: ourPrivateKey))
            else { return nil }

            let salt = Data(zip(self.fixedX963.map { $0 }, ourPubData.map { $0 }).map { $0 ^ $1 })
            
            return HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: rawSecret),
                salt: salt, info: SaltInfo.kLocalDBKeyInfo, outputByteCount: 32
            )
        }

        // MARK: - SE retrieval

        /// Retrieve the SE identity private key by tag, creating it if absent.
        ///
        /// **SE operations:** `SecItemCopyMatching` + conditionally `SecKeyCreateRandomKey`.
        ///
        /// - Returns: The private key reference, or `nil` if the SE is unavailable.
        func retrievePrivateKey() throws -> SecKey? {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: self.tag.data(using: .utf8)!,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecReturnRef as String: true,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
            ]
            var item: CFTypeRef?
            
            switch SecItemCopyMatching(query as CFDictionary, &item) {
            case errSecItemNotFound:
                item = nil
                _ = try self.create()
                
                return SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess ? (item as! SecKey) : nil
            case errSecSuccess:
                return (item as! SecKey)
            default:
                return nil
            }
        }

        /// Copy the public key from a private key reference via `SecKeyCopyPublicKey`.
        ///
        /// - Returns: Public key reference, or `nil` if `key` is nil or the copy fails.
        ///
        /// Note: the method name contains a typo ("retrive"). Call sites use this name;
        /// rename only when all references can be updated atomically.
        func retrivePublicKey(using key: SecKey?) -> SecKey? {
            key.flatMap { SecKeyCopyPublicKey($0) }
        }

        /// Delete the SE key with the given application tag.
        ///
        /// - Returns: `true` if the key was deleted or did not exist; `false` on unexpected error.
        @discardableResult
        func delete(using tag: String) -> Bool {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
            ]
            let status = SecItemDelete(query as CFDictionary)
            
            return status == errSecSuccess || status == errSecItemNotFound
        }


        // MARK: - Transport session key — long-term identity path (kTransportKeyInfo)

        /// Derive a session key using our SE long-term identity key and a peer's public key.
        ///
        /// Returns nil — never crashes — on: nil/wrong-length material, SE unavailable, ECDH failure.
        func createSharedSecret(using material: Data?) -> SymmetricKey? {
            guard let peerKey = self.convert(material: material) else { return nil }
            guard let ourPriv = try? self.retrievePrivateKey()   else { return nil }

            var error: Unmanaged<CFError>?
            guard
                let rawSecret = SecKeyCopyKeyExchangeResult(
                    ourPriv, .ecdhKeyExchangeCofactorX963SHA256, peerKey,
                    [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                    &error
                ) as? Data
            else { return nil }

            guard
                let peerData = self.convert(key: peerKey),
                let ourData  = self.convert(key: self.retrivePublicKey(using: ourPriv))
            else { return nil }

            let salt = Data(zip(peerData.map { $0 }, ourData.map { $0 }).map { $0 ^ $1 })
            return HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: rawSecret),
                salt: salt, info: SaltInfo.kTransportKeyInfo, outputByteCount: 32
            )
        }

        // MARK: - Shared secret derivation (ephemeral or prekey private key)

        /// Derive a session key using any in-memory private key and a peer's public key.
        ///
        /// Used on both sides of the forward-secret exchange:
        ///
        /// **Encryption (sender):**
        /// ```
        /// sessionKey = HKDF(ECDH(ephemeralPriv, recipientPrekeyPub))
        /// ```
        ///
        /// **Decryption (recipient):**
        /// ```
        /// sessionKey = HKDF(ECDH(ourPrekeyPriv, senderEphemeralPub))
        /// ```
        ///
        /// ECDH commutativity guarantees both sides arrive at the same raw shared secret.
        /// The XOR salt is also commutative, so HKDF output is identical on both sides.
        ///
        /// Uses identical parameters to the existing `createSharedSecret(using:)`:
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
            guard recipientMaterial.count == 65 else { return nil }

            guard
                let ephPub     = SecKeyCopyPublicKey(ephemeralPrivateKey),
                let ephPubData = SecKeyCopyExternalRepresentation(ephPub, nil) as Data?
            else { return nil }

            guard let peerKey = self.convert(material: recipientMaterial) else { return nil }

            var error: Unmanaged<CFError>?
            guard
                let rawSecret = SecKeyCopyKeyExchangeResult(
                    ephemeralPrivateKey, .ecdhKeyExchangeCofactorX963SHA256, peerKey,
                    [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                    &error
                ) as? Data
            else { return nil }

            let salt = Data(zip(
                recipientMaterial.map { $0 },
                ephPubData.map        { $0 }
            ).map { $0 ^ $1 })

            return HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: rawSecret),
                salt: salt, info: SaltInfo.kTransportKeyInfo, outputByteCount: 32
            )
        }

        // MARK: - SE signing (general purpose)

        /// ECDSA-sign `data` with the SE identity key.
        ///
        /// **SE operations performed:**
        /// 1. `retrievePrivateKey` — reads the identity private key by tag.
        /// 2. `SecKeyCreateSignature` — signs; SE applies SHA-256 internally.
        ///
        /// ⚠️ DO NOT pre-hash `data`. `.ecdsaSignatureMessageX962SHA256` hashes
        /// internally. Pre-hashing produces a signature no verifier will accept,
        /// and the failure is silent — identical to a key mismatch.
        ///
        /// - Returns: DER-encoded ECDSA signature.
        func signData(_ data: Data) throws -> Data {
            guard let key = try self.retrievePrivateKey() else { throw Errors.noIdentityAvailable }
            var error: Unmanaged<CFError>?
            guard
                let sig = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, data as CFData, &error) as Data?
            else { throw error!.takeRetainedValue() as Error }
            return sig
        }

        /// Generate a throwaway in-memory P-256 key pair for a single FS message.
        ///
        /// `kSecAttrIsPermanent: false` — key is never written to any keychain.
        /// The private key exists only in memory for the duration of ECDH, then ARC releases it.
        func generateEphemeralKeyPair() -> (privateKey: SecKey, publicKeyData: Data)? {
            let attributes: NSDictionary = [
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits: 256,
                kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
            ]
            var error: Unmanaged<CFError>?
            guard
                let priv    = SecKeyCreateRandomKey(attributes, &error),
                let pub     = SecKeyCopyPublicKey(priv),
                let pubData = SecKeyCopyExternalRepresentation(pub, nil) as Data?
            else { return nil }
            
            return (priv, pubData)
        }
    }
}

// MARK: - Helpers

extension Manager.Key {
    /// Export a `SecKey` to its x963 external representation.
    ///
    /// For P-256 public keys the result is 65 bytes (`0x04 ∥ x ∥ y`).
    /// - Returns: Raw key bytes, or `nil` if `key` is nil or the export fails.
    func convert(key: SecKey?) -> Data? {
        key.flatMap { SecKeyCopyExternalRepresentation($0, nil) as Data? }
    }

    /// Validates `data` is exactly 65 bytes before creating a SecKey.
    /// Prevents ECDH from receiving malformed input (Finding 6).
    func convert(material data: Data?) -> SecKey? {
        guard let data, data.count == 65 else { return nil }
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:      kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        
        return SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error)
    }

    /// Retrieve and export the identity public key as x963 `Data` (65 bytes).
    ///
    /// **SE operations:** `retrievePrivateKey` (read), `SecKeyCopyPublicKey` (derive public),
    /// `SecKeyCopyExternalRepresentation` (export).
    ///
    /// - Throws: `.noIdentityAvailable` if the SE key is absent or cannot be exported.
    func retrieveIdentity() throws -> Data {
        guard
            let priv = try self.retrievePrivateKey(),
            let pub  = self.retrivePublicKey(using: priv),
            let data = self.convert(key: pub)
        else { throw Errors.noIdentityAvailable }
        
        return data
    }
}

extension Manager.Key {
    enum Errors: Error { case noIdentityAvailable }

    enum StagedKeyError: Error {
        case stagedKeyNotFound      // staged artefacts missing when commit was called
        case randomGenerationFailed // SecRandomCopyBytes or SecItemAdd failed
        case derivationFailed       // ECDH or HKDF failed on the staged key
    }
}

//  Phase 1: Hybrid PQ-reinforced local database encryption key.
//
//  Derivation: HKDF(ikm: ECDH(SE_priv, G) || randomKey,
//                    salt: SE_pub_x963,
//                    info: "Occulta-v1-local-db-pq-2025")
//
//  The SE component provides hardware binding — the key cannot be derived
//  without access to this specific Secure Enclave.
//  The random component provides PQ resistance — a quantum adversary who
//  recovers the SE private key via Shor's algorithm still faces ~2^128
//  (Grover's) on the 256-bit random half.
//  An attacker needs BOTH components to derive the hybrid key.
extension Manager.Key: KeyManagerProtocol {

    // MARK: - Tags and identifiers


    /// Keychain account identifier for the random symmetric component.
    private static let localDBRandomKeychainAccount = "local.db.random.key.occulta"

    // MARK: - Hybrid key derivation

    /// Derive the hybrid local DB encryption key.
    ///
    /// **SE operations performed:**
    /// 1. Retrieve (or create) the local DB SE private key by tag.
    /// 2. Copy the public key from the private key reference.
    /// 3. ECDH key exchange with the fixed generator point G.
    ///
    /// **Keychain operations performed:**
    /// 1. Retrieve (or generate and store) the 256-bit random component.
    ///
    /// - Returns: 256-bit `SymmetricKey`, or `nil` if SE or Keychain is unavailable.
    func createHybridLocalEncryptionKey() throws -> SymmetricKey? {
        // Step 1: SE-derived component — ECDH(localDB_SE_privkey, G)
        guard let seComponent = try self.deriveLocalDBSEComponent() else { return nil }

        // Step 2: Random Keychain component
        guard let randomComponent = try self.retrieveOrCreateRandomComponent() else { return nil }

        // Step 3: Combine via HKDF
        //   IKM  = SE_derived (32 bytes) || random (32 bytes)
        //   Salt = SE public key x963 (65 bytes) — binds to this specific SE key
        //   Info = domain separator
        guard
            let localDBPrivateKey = try self.retrieveLocalDBPrivateKey(),
            let localDBPubKey = self.retrivePublicKey(using: localDBPrivateKey),
            let pubKeyData = self.convert(key: localDBPubKey)
        else { return nil }

        var ikm = Data(seComponent)
        ikm.append(randomComponent)

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: pubKeyData,
            info: SaltInfo.kLocalDBHybridKeyInfo,
            outputByteCount: 32
        )
    }

    // MARK: - SE key for local DB

    /// Retrieve the dedicated local DB SE private key, creating it if absent.
    ///
    /// **SE operations:** SecItemCopyMatching, conditionally SecKeyCreateRandomKey.
    private func retrieveLocalDBPrivateKey() throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Tags.localDB.rawValue.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
        ]
        var item: CFTypeRef?

        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            return (item as! SecKey)

        case errSecItemNotFound:
            item = nil
            try self.createLocalDBSEKey()
            guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else {
                return nil
            }
            return (item as! SecKey)

        default:
            return nil
        }
    }

    /// Create the dedicated local DB P-256 key in the Secure Enclave.
    ///
    /// **SE operations:** SecKeyCreateRandomKey (single write, no ECDH).
    private func createLocalDBSEKey() throws {
        try self.createLocalDBSEKey(tag: Tags.localDB.rawValue)
    }

    /// Create a local-DB-style P-256 SE key with an explicit application tag.
    ///
    /// Used for both the canonical key and the staged key during key rotation.
    /// Access policy is identical to the canonical key: `.privateKeyUsage` only,
    /// device-unlock level, no biometric.
    private func createLocalDBSEKey(tag: String) throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &error
        ) else { throw error!.takeRetainedValue() as Error }

        let attributes: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: tag.data(using: .utf8)!,
                kSecAttrAccessControl: access
            ]
        ]

        guard let _ = SecKeyCreateRandomKey(attributes, &error) else {
            throw error!.takeRetainedValue() as Error
        }
    }

    // MARK: - SE component derivation

    /// ECDH with the fixed generator point G, using the local DB SE key.
    /// Returns 32 raw bytes of shared secret.
    ///
    /// **SE operations:** ECDH key exchange (single call).
    private func deriveLocalDBSEComponent() throws -> Data? {
        guard let privateKey = try self.retrieveLocalDBPrivateKey() else { return nil }
        guard let fixedPubKey = self.convert(material: fixedX963) else { return nil }

        var error: Unmanaged<CFError>?
        guard
            let rawSecret = SecKeyCopyKeyExchangeResult(
                privateKey,
                .ecdhKeyExchangeCofactorX963SHA256,
                fixedPubKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        else { return nil }

        return rawSecret
    }

    // MARK: - Random Keychain component

    /// Retrieve the 256-bit random component from Keychain, or generate and store it.
    ///
    /// **Keychain operations:** SecItemCopyMatching, conditionally SecItemAdd.
    private func retrieveOrCreateRandomComponent() throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: Self.localDBRandomKeychainAccount,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecReturnData as String: true
        ]

        var item: CFTypeRef?

        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            guard let data = item as? Data, data.count == 32 else { return nil }
            return data

        case errSecItemNotFound:
            return try self.generateAndStoreRandomComponent()

        default:
            return nil
        }
    }

    /// Generate 32 cryptographically random bytes and store in Keychain.
    ///
    /// The key is stored with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`:
    /// - Not included in unencrypted backups
    /// - Not synced to iCloud Keychain
    /// - Encrypted at rest by the device's hardware key
    ///
    /// ⚠️ If this Keychain entry is lost (device restore without Keychain migration),
    /// all locally encrypted data becomes permanently irrecoverable. This is the
    /// intended security posture — no recovery path exists by design.
    private func generateAndStoreRandomComponent() throws -> Data? {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
        guard status == errSecSuccess else { return nil }

        let randomData = Data(bytes)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: Self.localDBRandomKeychainAccount,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: randomData
        ]

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else { return nil }

        return randomData
    }

    // MARK: - Vault SE key

    /// Dedicated SE key tag for vault derivation — separate from identity and local DB keys.

    // CRYPTO_REVIEW_CHECKLIST — Vault Key Derivation Path (v2)
    // ══════════════════════════════════════════════════════════
    // 1. Key ownership map
    //    - Vault SE key: dedicated P-256 key in SE (tag: Tags.vault). Single owner.
    //    - Private half: hardware-bound, never extractable.
    //    - Public half: never stored, never exported — no harvest surface for QC.
    //    - Static peer: P-256 generator G — a universal constant, not a secret.
    //    - Shared between contacts: No. Vault key is derived entirely locally.
    //
    // 2. Consumption events
    //    - No one-time consumption. Re-derivable on demand via ECDH(vault_SE_priv, G).
    //    - Key lives only as a local SymmetricKey for the duration of each vault op.
    //    - No zeroing needed — scope-bounded by the calling function's stack frame.
    //
    // 3. Multi-party trace
    //    - Single owner only. No contact ever receives this key or material from it.
    //    - SSS shards split the vault entry key (separate per-entry concern).
    //
    // 4. Security property verification
    //    - Harvest-now-decrypt-later: vault public key never stored → no harvest surface.
    //    - QC: no classical public key on disk to recover the private key from.
    //    - Biometric gate: .biometryCurrentSet — key unusable if biometrics change.
    //    - Device binding: kSecAttrAccessibleWhenUnlockedThisDeviceOnly.
    //    - LAContext: pre-evaluated once per session; passed to SE to avoid per-op prompts.
    //    - Not achieved: forward secrecy (same key re-derived on each unlock).
    //    - No prekey public keys involved. Checklist item 4.6: N/A.
    //
    // 5. Layer boundary check
    //    - Input: LAContext. Output: SymmetricKey. No SwiftData, no UI.
    //    - SE operations: key retrieval (biometric-gated via context), ECDH (compute).

    /// Create the vault SE key with biometric access control.
    ///
    /// Access control: (`.biometryCurrentSet` OR `.devicePasscode`) + `.privateKeyUsage`.
    /// `.biometryCurrentSet` invalidates the key if the enrolled biometric set changes.
    private func createVaultSEKey() throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode],
            &error
        ) else { throw error!.takeRetainedValue() as Error }

        let attributes: NSDictionary = [
            kSecAttrKeyType:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID:       kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent:    true,
                kSecAttrApplicationTag: Tags.vault.rawValue.data(using: .utf8)!,
                kSecAttrAccessControl:  access
            ]
        ]
        var createError: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes, &createError) != nil else {
            throw createError!.takeRetainedValue() as Error
        }
    }

    /// Retrieve the vault SE private key, creating it on first use.
    ///
    /// Passes the pre-evaluated `context` to the Keychain query so the SE uses
    /// the already-verified biometric instead of prompting the user again.
    ///
    /// - Throws: Keychain/SE error if retrieval fails (e.g. biometric mismatch,
    ///           context invalidated). VaultManager.currentKey() converts these to .locked.
    private func retrieveVaultPrivateKey(context: LAContext) throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String:                    kSecClassKey,
            kSecAttrApplicationTag as String:       Tags.vault.rawValue.data(using: .utf8)!,
            kSecAttrKeyType as String:              kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String:                true,
            kSecAttrTokenID as String:              kSecAttrTokenIDSecureEnclave,
            kSecUseAuthenticationContext as String: context
        ]
        var item: CFTypeRef?

        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            return (item as! SecKey)
        case errSecItemNotFound:
            try self.createVaultSEKey()
            guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else {
                return nil
            }
            return (item as! SecKey)
        case let status:
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    /// Derive the vault session key: ECDH(vault_SE_priv, G) → HKDF-SHA256.
    ///
    /// **SE operations:**
    /// 1. `retrieveVaultPrivateKey(context:)` — retrieves vault SE key via pre-evaluated LAContext.
    /// 2. `SecKeyCopyKeyExchangeResult` — ECDH with the P-256 generator point G.
    ///
    /// The returned SymmetricKey is scope-bounded — callers must not store it.
    ///
    /// - Returns: 256-bit SymmetricKey, or nil if the SE is unavailable.
    func deriveVaultKey(context: LAContext) throws -> SymmetricKey? {
        guard let vaultPriv   = try self.retrieveVaultPrivateKey(context: context) else { return nil }
        guard let fixedPubKey = self.convert(material: fixedX963)                  else { return nil }

        var error: Unmanaged<CFError>?
        guard
            let rawSecret = SecKeyCopyKeyExchangeResult(
                vaultPriv, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        else { return nil }

        // Salt = vault public key x963 — binds derivation to this specific SE key.
        guard
            let vaultPub     = self.retrivePublicKey(using: vaultPriv),
            let vaultPubData = self.convert(key: vaultPub)
        else { return nil }

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: vaultPubData,
            info: SaltInfo.kVaultKeyInfo,
            outputByteCount: 32
        )
    }

    // MARK: - Shard custody SE key

    /// Dedicated SE key tag for shard custody — no biometric, device-unlock level.

    /// Create the shard custody P-256 key in the Secure Enclave.
    ///
    /// Access control: `.privateKeyUsage` only — no biometric flag.
    /// This allows fully automatic shard operations while the device is unlocked,
    /// without requiring the user to approve each SE access.
    private func createShardCustodySEKey() throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &error
        ) else { throw error!.takeRetainedValue() as Error }

        let attributes: NSDictionary = [
            kSecAttrKeyType:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID:       kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent:    true,
                kSecAttrApplicationTag: Tags.shardCustody.rawValue.data(using: .utf8)!,
                kSecAttrAccessControl:  access
            ]
        ]
        var createError: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes, &createError) != nil else {
            throw createError!.takeRetainedValue() as Error
        }
    }

    /// Retrieve the shard custody SE private key, creating it on first use.
    ///
    /// **SE operations:** `SecItemCopyMatching` + conditionally `SecKeyCreateRandomKey`.
    ///
    /// No `LAContext` is passed — access control is device-unlock level, so no biometric
    /// prompt is required. Throws an `NSError` (NSOSStatusErrorDomain) on unexpected
    /// Keychain failure.
    private func retrieveShardCustodyPrivateKey() throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecAttrApplicationTag as String: Tags.shardCustody.rawValue.data(using: .utf8)!,
            kSecAttrKeyType as String:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String:          true,
            kSecAttrTokenID as String:        kSecAttrTokenIDSecureEnclave
        ]
        var item: CFTypeRef?

        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            return (item as! SecKey)
        case errSecItemNotFound:
            try self.createShardCustodySEKey()
            guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else {
                return nil
            }
            return (item as! SecKey)
        case let status:
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    /// Derive the shard custody key: ECDH(shardCustody_SE_priv, G) → HKDF-SHA256.
    ///
    /// No LAContext needed — access control is device-unlock level (no biometric).
    /// This enables fully automatic shard operations triggered by bundle receipt.
    ///
    /// The returned SymmetricKey is scope-bounded — callers must not store it.
    ///
    /// - Returns: 256-bit SymmetricKey, or nil if the SE is unavailable.
    func deriveShardCustodyKey() throws -> SymmetricKey? {
        guard let custodyPriv  = try self.retrieveShardCustodyPrivateKey() else { return nil }
        guard let fixedPubKey  = self.convert(material: fixedX963)         else { return nil }

        var error: Unmanaged<CFError>?
        guard
            let rawSecret = SecKeyCopyKeyExchangeResult(
                custodyPriv, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        else { return nil }

        guard
            let custodyPub     = self.retrivePublicKey(using: custodyPriv),
            let custodyPubData = self.convert(key: custodyPub)
        else { return nil }

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: custodyPubData,
            info: SaltInfo.kShardCustodyKeyInfo,
            outputByteCount: 32
        )
    }

    // MARK: - Recovery buffer key

    /// Derive the recovery buffer key: ECDH(shardCustody_SE_priv, G) → HKDF-SHA256
    /// with `kRecoveryBufferKeyInfo`. Reuses the shard custody SE key (same access
    /// policy: device-unlock, no biometric) but produces a distinct symmetric key
    /// via HKDF domain separation.
    ///
    /// Used to seal ReconstructShard rows — the transient buffer of returned
    /// shards collected during reconstruction.
    ///
    /// The returned SymmetricKey is scope-bounded — callers must not store it.
    ///
    /// - Returns: 256-bit SymmetricKey, or nil if the SE is unavailable.
    func deriveRecoveryBufferKey() throws -> SymmetricKey? {
        guard let custodyPriv  = try self.retrieveShardCustodyPrivateKey() else { return nil }
        guard let fixedPubKey  = self.convert(material: fixedX963)         else { return nil }

        var error: Unmanaged<CFError>?
        guard
            let rawSecret = SecKeyCopyKeyExchangeResult(
                custodyPriv, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        else { return nil }

        guard
            let custodyPub     = self.retrivePublicKey(using: custodyPriv),
            let custodyPubData = self.convert(key: custodyPub)
        else { return nil }

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: custodyPubData,
            info: SaltInfo.kRecoveryBufferKeyInfo,
            outputByteCount: 32
        )
    }

    // MARK: - Secure Mode PIN SE key

    /// Derive the Secure Mode PIN key: ECDH(secureModePin_SE_priv, G) → HKDF-SHA256.
    ///
    /// No LAContext needed — device-unlock level access, no biometric.
    /// Used by PINManager to wrap/unwrap PIN sentinels stored in AppLayerConfig.
    ///
    /// The returned SymmetricKey is scope-bounded — callers must not store it.
    func deriveSecureModeKey() throws -> SymmetricKey? {
        guard let priv        = try self.retrieveSecureModePINPrivateKey() else { return nil }
        guard let fixedPubKey = self.convert(material: fixedX963)          else { return nil }

        var error: Unmanaged<CFError>?
        guard
            let rawSecret = SecKeyCopyKeyExchangeResult(
                priv, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        else { return nil }

        guard
            let pub     = self.retrivePublicKey(using: priv),
            let pubData = self.convert(key: pub)
        else { return nil }

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: pubData,
            info: SaltInfo.kSecureModeKeyInfo,
            outputByteCount: 32
        )
    }

    private func retrieveSecureModePINPrivateKey() throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecAttrApplicationTag as String: Tags.secureModePin.rawValue.data(using: .utf8)!,
            kSecAttrKeyType as String:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String:          true,
            kSecAttrTokenID as String:        kSecAttrTokenIDSecureEnclave
        ]
        var item: CFTypeRef?

        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            return (item as! SecKey)
        case errSecItemNotFound:
            try self.createSecureModePINKey()
            guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
            return (item as! SecKey)
        case let status:
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    private func createSecureModePINKey() throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &error
        ) else { throw error!.takeRetainedValue() as Error }

        let attributes: NSDictionary = [
            kSecAttrKeyType:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID:       kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent:    true,
                kSecAttrApplicationTag: Tags.secureModePin.rawValue.data(using: .utf8)!,
                kSecAttrAccessControl:  access
            ]
        ]
        var createError: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes, &createError) != nil else {
            throw createError!.takeRetainedValue() as Error
        }
    }

    // MARK: - Staged DB key (activation / deactivation key rotation)
    //
    // Key rotation uses a staged approach: a new SE key + random are created at
    // temporary tags ("staged"), contacts are re-encrypted under the derived key,
    // and only then the staged key is promoted to canonical. The old canonical key
    // is renamed to a "superseded" tag and deleted last (step 11 of activation) —
    // never before the staged key is confirmed canonical.
    //
    // Tags/accounts used:
    //   SE key, canonical:    Tags.localDB.rawValue         ("local.db.se.key.occulta")
    //   SE key, staged:       stagedLocalDBSETag            ("local.db.se.key.occulta.staged")
    //   SE key, superseded:   supersededLocalDBSETag        ("local.db.se.key.occulta.superseded")
    //   Keychain, canonical:  localDBRandomKeychainAccount  ("local.db.random.key.occulta")
    //   Keychain, staged:     stagedLocalDBRandomAccount    ("local.db.random.key.occulta.staged")

    private static let stagedLocalDBSETag           = "local.db.se.key.occulta.staged"
    private static let supersededLocalDBSETag       = "local.db.se.key.occulta.superseded"
    private static let stagedLocalDBRandomAccount   = "local.db.random.key.occulta.staged"

    /// Create a staged local DB key for use in the activation/deactivation sequence.
    ///
    /// Creates a new SE key at `stagedLocalDBSETag` and a new 32-byte random at
    /// `stagedLocalDBRandomAccount`. Any leftover staged artefacts from a prior
    /// aborted attempt are cleaned up first (idempotent).
    ///
    /// Returns the hybrid key derived from the staged components — use this key
    /// to re-encrypt contacts in step 8 of activation. It is NOT the canonical
    /// key until `commitStagedLocalDBKey()` is called.
    ///
    /// **Call `rollbackStagedLocalDBKey()` on any failure before commit.**
    func createStagedLocalDBKey() throws -> SymmetricKey {
        // Clean up any leftover staged artefacts from a prior aborted attempt.
        self.rollbackStagedLocalDBKey()

        // 1. New SE key at staged tag.
        try self.createLocalDBSEKey(tag: Self.stagedLocalDBSETag)

        // 2. New random component stored at staged Keychain account.
        guard
            let stagedRandom = try self.generateAndStoreRandomComponent(account: Self.stagedLocalDBRandomAccount)
        else {
            self.rollbackStagedLocalDBKey()
            
            throw StagedKeyError.randomGenerationFailed
        }

        // 3. Derive the hybrid key from staged components.
        guard
            let key = try self.deriveHybridKey(seTag: Self.stagedLocalDBSETag, randomData: stagedRandom)
        else {
            self.rollbackStagedLocalDBKey()
            
            throw StagedKeyError.derivationFailed
        }
        
        return key
    }

    /// Promote the staged key to canonical. ⚠️ Point of no return.
    ///
    /// After this call:
    /// - `Tags.localDB` SE key = new key (renamed from staged)
    /// - `localDBRandomKeychainAccount` value = staged random value
    /// - Old canonical SE key exists at `supersededLocalDBSETag` (delete in step 11)
    /// - Staged random entry exists at `stagedLocalDBRandomAccount` (delete in step 11)
    ///
    /// Call `deleteSupersededLocalDBArtefacts()` in step 11, after AppLayerConfig
    /// is written and state has transitioned to `.active`.
    ///
    /// If sub-step B (rename staged → canonical) fails, attempts to restore the
    /// old canonical tag before throwing.
    func commitStagedLocalDBKey() throws {
        // Read staged random before touching SE keys.
        guard let stagedRandom = self.retrieveRandomComponent(
            account: Self.stagedLocalDBRandomAccount
        ) else {
            throw StagedKeyError.stagedKeyNotFound
        }

        // A. Rename canonical SE key → superseded tag (frees the canonical slot).
        //    errSecItemNotFound is acceptable — crash-recovery path where canonical
        //    was already renamed in a prior partial commit attempt.
        //
        //    kSecAttrTokenID and kSecAttrKeyType are omitted from the search dict:
        //    SecItemUpdate rejects them as invalid search criteria on some iOS versions
        //    (errSecNoSuchAttr). kSecAttrApplicationTag alone identifies the key uniquely.
        let renameCanonical: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecAttrApplicationTag as String: Tags.localDB.rawValue.data(using: .utf8)!
        ]
        let markSuperseded: [String: Any] = [
            kSecAttrApplicationTag as String: Self.supersededLocalDBSETag.data(using: .utf8)!
        ]
        let renameStatus = SecItemUpdate(renameCanonical as CFDictionary, markSuperseded as CFDictionary)
        guard renameStatus == errSecSuccess || renameStatus == errSecItemNotFound else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(renameStatus))
        }

        // B. Rename staged SE key → canonical tag.
        let findStaged: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecAttrApplicationTag as String: Self.stagedLocalDBSETag.data(using: .utf8)!
        ]
        let makeCanonical: [String: Any] = [
            kSecAttrApplicationTag as String: Tags.localDB.rawValue.data(using: .utf8)!
        ]
        let promoteStatus = SecItemUpdate(findStaged as CFDictionary, makeCanonical as CFDictionary)
        
        guard promoteStatus == errSecSuccess else {
            // Promotion failed — attempt to restore the canonical tag on the old key.
            let findSuperseded: [String: Any] = [
                kSecClass as String:              kSecClassKey,
                kSecAttrApplicationTag as String: Self.supersededLocalDBSETag.data(using: .utf8)!
            ]
            let restoreCanonical: [String: Any] = [
                kSecAttrApplicationTag as String: Tags.localDB.rawValue.data(using: .utf8)!
            ]
            _ = SecItemUpdate(findSuperseded as CFDictionary, restoreCanonical as CFDictionary)
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(promoteStatus))
        }

        // C. Update canonical Keychain random → staged value.
        //    The entry already exists; we update its data in-place.
        let findRandom: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrAccount as String: Self.localDBRandomKeychainAccount
        ]
        let newRandomValue: [String: Any] = [kSecValueData as String: stagedRandom]
        var randomStatus = SecItemUpdate(findRandom as CFDictionary, newRandomValue as CFDictionary)
        if randomStatus == errSecItemNotFound {
            // Should not happen in normal operation; add defensively.
            let addRandom: [String: Any] = [
                kSecClass as String:          kSecClassGenericPassword,
                kSecAttrAccount as String:    Self.localDBRandomKeychainAccount,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                kSecValueData as String:      stagedRandom
            ]
            randomStatus = SecItemAdd(addRandom as CFDictionary, nil)
        }
        guard randomStatus == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(randomStatus))
        }
    }

    /// Delete leftover artefacts after `commitStagedLocalDBKey()` completes.
    ///
    /// Removes the old canonical SE key (at `supersededLocalDBSETag`) and the
    /// staged Keychain random entry. Both deletions are no-ops if the items are
    /// already absent. Call from step 11 of activation, after AppLayerConfig is
    /// written and the state machine has transitioned to `.active`.
    func deleteSupersededLocalDBArtefacts() {
        self.delete(using: Self.supersededLocalDBSETag)
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrAccount as String: Self.stagedLocalDBRandomAccount
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// Delete staged artefacts without touching the canonical key.
    ///
    /// No-op if items do not exist. Call on any error before `commitStagedLocalDBKey()`,
    /// or during crash recovery to guarantee a clean baseline before retrying.
    func rollbackStagedLocalDBKey() {
        self.delete(using: Self.stagedLocalDBSETag)
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrAccount as String: Self.stagedLocalDBRandomAccount
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Staged key private helpers

    /// Retrieve an SE private key by explicit tag without auto-creating.
    /// Returns `nil` if not found; throws on unexpected Keychain errors.
    private func retrieveExistingLocalDBPrivateKey(tag: String) throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
            kSecAttrKeyType as String:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String:          true,
            kSecAttrTokenID as String:        kSecAttrTokenIDSecureEnclave
        ]
        var item: CFTypeRef?
        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:     return (item as! SecKey)
        case errSecItemNotFound: return nil
        case let status:        throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    /// Generate 32 random bytes and store in the Keychain under the given account.
    /// Access policy matches the canonical random: `.whenUnlockedThisDeviceOnly`.
    private func generateAndStoreRandomComponent(account: String) throws -> Data? {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, 32, &bytes) == errSecSuccess else { return nil }
        let randomData = Data(bytes)
        let addQuery: [String: Any] = [
            kSecClass as String:          kSecClassGenericPassword,
            kSecAttrAccount as String:    account,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String:      randomData
        ]
        guard SecItemAdd(addQuery as CFDictionary, nil) == errSecSuccess else { return nil }
        return randomData
    }

    /// Retrieve a stored random component from Keychain. Returns `nil` if absent or wrong size.
    private func retrieveRandomComponent(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String:          kSecClassGenericPassword,
            kSecAttrAccount as String:    account,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecReturnData as String:     true
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data, data.count == 32 else { return nil }
        return data
    }

    /// Derive the hybrid local DB key from an explicit SE tag and random data.
    ///
    /// Replicates the derivation in `createHybridLocalEncryptionKey()` but with
    /// caller-supplied components — used to derive the key from staged artefacts
    /// before they are promoted to canonical.
    ///
    /// IKM = ECDH(seKey, G) || randomData · Salt = seKey public x963 · Info = kLocalDBHybridKeyInfo
    private func deriveHybridKey(seTag: String, randomData: Data) throws -> SymmetricKey? {
        guard let privateKey = try self.retrieveExistingLocalDBPrivateKey(tag: seTag) else { return nil }
        guard let fixedPubKey = self.convert(material: self.fixedX963) else { return nil }

        var error: Unmanaged<CFError>?
        guard let rawSecret = SecKeyCopyKeyExchangeResult(
            privateKey, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey,
            [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
            &error
        ) as? Data else { return nil }

        guard let pub = self.retrivePublicKey(using: privateKey),
              let pubData = self.convert(key: pub) else { return nil }

        var ikm = rawSecret
        ikm.append(randomData)

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: pubData,
            info: SaltInfo.kLocalDBHybridKeyInfo,
            outputByteCount: 32
        )
    }

    // MARK: - Cleanup

    /// Deletes all SE keys enumerated in Tags and the local DB random Keychain component.
    /// Adding a new case to Tags automatically includes it here — no manual update needed.
    /// After this call every encrypted blob in Occulta is permanently unreadable.
    @discardableResult
    func deleteAllKeys() -> Bool {
        let seDeleted = Tags.allCases.allSatisfy { delete(using: $0.rawValue) }
        // Also sweep transient staged/superseded artefacts in case a wipe fires mid-rotation.
        self.deleteSupersededLocalDBArtefacts()
        self.rollbackStagedLocalDBKey()
        let keychainQuery: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrAccount as String: Self.localDBRandomKeychainAccount
        ]
        let keychainStatus = SecItemDelete(keychainQuery as CFDictionary)
        return seDeleted && (keychainStatus == errSecSuccess || keychainStatus == errSecItemNotFound)
    }
}

extension Manager.Key {
 
    // MARK: - Hybrid shared secret (ECDH + ML-KEM)
 
    /// Derive a hybrid transport key combining ECDH and ML-KEM shared secrets.
    ///
    /// Option A — mutual encapsulation: both sides encapsulate and decapsulate,
    /// producing two independent ML-KEM shared secrets. Both are included in the IKM.
    ///
    /// The two ML-KEM secrets are sorted lexicographically before concatenation
    /// so both sides produce identical IKM regardless of who encapsulated first.
    ///
    /// ```
    /// IKM  = ECDH_secret || sorted(ML-KEM_secret_A, ML-KEM_secret_B)
    /// Salt = XOR(peerP256Pub, ourP256Pub)
    /// Info = kHybridTransportKeyInfo
    /// ```
    ///
    /// SE operations: one ECDH via SE identity key.
    ///
    /// - Parameters:
    ///   - peerP256Material: Peer's P-256 public key, x963 format (65 bytes).
    ///   - quantumMaterial: ML-KEM shared secrets from the exchange.
    /// - Returns: 256-bit hybrid SymmetricKey, or nil on failure.
    func createHybridSharedSecret(
        peerP256Material: Data,
        quantumMaterial: QuantumKeyMaterial
    ) -> SymmetricKey? {
        guard let ecdhAndSalt = self.ecdhWithSalt(peerP256Material: peerP256Material) else { return nil }
        guard quantumMaterial.isValid else { return nil }
 
        let sorted = [quantumMaterial.encapsulatedSecret, quantumMaterial.decapsulatedSecret]
            .sorted { $0.lexicographicallyPrecedes($1) }
 
        var ikm = ecdhAndSalt.rawECDH
        ikm.append(contentsOf: sorted[0])
        ikm.append(contentsOf: sorted[1])
 
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: ecdhAndSalt.salt,
            info: SaltInfo.kHybridTransportKeyInfo,
            outputByteCount: 32
        )
    }
    
    /// Derive a hybrid forward-secret session key combining ephemeral ECDH and ML-KEM shared secrets.
    ///
    /// Same hybrid pattern as `createHybridSharedSecret`, but uses an ephemeral/prekey
    /// ECDH instead of the identity-level ECDH. Each FS message becomes independently
    /// quantum-resistant rather than relying on transitive chain protection.
    ///
    /// ```
    /// IKM  = ECDH(ephemeralPriv, prekeyPub) || sorted(ML-KEM_secret_1, ML-KEM_secret_2)
    /// Salt = XOR(prekeyPub, ephemeralPub)
    /// Info = kHybridFSTransportKeyInfo
    /// ```
    ///
    /// SE operations: none (ephemeral key is in-memory, passed in by caller).
    ///
    /// - Parameters:
    ///   - ephemeralPrivateKey: Sender's throwaway in-memory P-256 private key.
    ///   - recipientMaterial: Contact's prekey public key, x963 format (65 bytes).
    ///   - quantumMaterial: ML-KEM shared secrets from the contact's exchange.
    /// - Returns: 256-bit hybrid SymmetricKey, or nil on failure.
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

        guard let peerKey = self.convert(material: recipientMaterial) else { return nil }

        var error: Unmanaged<CFError>?
        guard
            let rawECDH = SecKeyCopyKeyExchangeResult(
                ephemeralPrivateKey, .ecdhKeyExchangeCofactorX963SHA256, peerKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
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
 
    /// Derive a Diceware verification key from hybrid material with per-session nonces.
    ///
    /// Same IKM and salt as `createHybridSharedSecret`, but the HKDF info field
    /// includes both exchange nonces (sorted) for per-session uniqueness.
    /// This ensures Diceware words differ on every exchange, even between the same key pairs.
    ///
    /// SE operations: one ECDH via SE identity key.
    func createDicewareKey(
        peerP256Material: Data,
        quantumMaterial: QuantumKeyMaterial,
        ourNonce: Data,
        peerNonce: Data
    ) -> SymmetricKey? {
        guard let ecdhAndSalt = self.ecdhWithSalt(peerP256Material: peerP256Material) else { return nil }
        guard quantumMaterial.isValid else { return nil }
        guard ourNonce.count == 16, peerNonce.count == 16 else { return nil }
 
        let sortedSecrets = [quantumMaterial.encapsulatedSecret, quantumMaterial.decapsulatedSecret]
            .sorted { $0.lexicographicallyPrecedes($1) }
 
        var ikm = ecdhAndSalt.rawECDH
        ikm.append(contentsOf: sortedSecrets[0])
        ikm.append(contentsOf: sortedSecrets[1])
 
        let sortedNonces = [ourNonce, peerNonce].sorted { $0.lexicographicallyPrecedes($1) }
        var info = SaltInfo.kDicewareKeyInfo
        info.append(contentsOf: sortedNonces[0])
        info.append(contentsOf: sortedNonces[1])
 
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: ecdhAndSalt.salt,
            info: info,
            outputByteCount: 32
        )
    }
 
    // MARK: - 16-byte exchange nonce
 
    /// Generate a 16-byte cryptographic nonce for an exchange session.
    ///
    /// Committed in the discovery message before proximity is confirmed,
    /// preventing a MITM from choosing nonces after seeing identity keys.
    func generateExchangeNonce() -> Data? {
        var bytes = [UInt8](repeating: 0, count: 16)
 
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            return nil
        }
 
        return Data(bytes)
    }
 
    // MARK: - Private
 
    private struct ECDHResult {
        let rawECDH: Data
        let salt: Data
    }
 
    /// Perform ECDH with our SE identity key and compute the XOR salt.
    ///
    /// Factored out to avoid duplicating SE access between hybrid transport and Diceware derivation.
    ///
    /// SE operations: retrievePrivateKey (read), ECDH (compute).
    private func ecdhWithSalt(peerP256Material: Data) -> ECDHResult? {
        guard peerP256Material.count == 65 else { return nil }
        
        guard let peerKey = self.convert(material: peerP256Material) else { return nil }
        guard let ourPriv = try? self.retrievePrivateKey() else { return nil }
 
        var error: Unmanaged<CFError>?
        guard
            let rawECDH = SecKeyCopyKeyExchangeResult(ourPriv, .ecdhKeyExchangeCofactorX963SHA256, peerKey, [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary, &error) as? Data
        else { return nil }
 
        guard let ourPubData = self.convert(key: self.retrivePublicKey(using: ourPriv)) else { return nil }
 
        let salt = Data(zip(peerP256Material, ourPubData).map { $0 ^ $1 })
 
        return ECDHResult(rawECDH: rawECDH, salt: salt)
    }
}

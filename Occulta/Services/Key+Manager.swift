//
//  Key+Manager.swift
//  Occulta
//
//  Created by Yura on 11/12/25.
//

import Foundation
import CryptoKit

// MARK: - HKDF info strings

struct SaltInfo {
    static let kTransportKeyInfo = "Occulta-v1-transport-2025".data(using: .utf8)!
    static let kLocalDBKeyInfo   = "Occulta-v1-encryption-key-2025".data(using: .utf8)!
    /// Domain separator for the hybrid local DB key. Distinct from kLocalDBKeyInfo
    /// to ensure the old (identity-derived) and new (hybrid) keys are never equivalent,
    /// even if the same SE key is used during migration.
    static let kLocalDBHybridKeyInfo = "Occulta-v2-local-db-pq-2026".data(using: .utf8)!
}

extension Manager {
    class Key {
        let tag: String

        init() { self.tag = "master.key.privacy.turtles.are.cute" }
        init(testingTag tag: String) { self.tag = tag }

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
            guard let fixedPubKey = self.convert(material: fixedX963) else { return nil }

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

            let salt = Data(zip(fixedX963.map { $0 }, ourPubData.map { $0 }).map { $0 ^ $1 })
            return HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: rawSecret),
                salt: salt, info: SaltInfo.kLocalDBKeyInfo, outputByteCount: 32
            )
        }

        // MARK: - SE retrieval

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

        func retrivePublicKey(using key: SecKey?) -> SecKey? {
            key.flatMap { SecKeyCopyPublicKey($0) }
        }

        @discardableResult
        func delete(using tag: String) -> Bool {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tag.data(using: .utf8)!
            ]
            let status = SecItemDelete(query as CFDictionary)
            return status == errSecSuccess || status == errSecItemNotFound
        }

        @discardableResult
        func deleteIdentity() -> Bool { self.delete(using: self.tag) }

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

    /// SE key tag — dedicated to local DB encryption, separate from identity key.
    private static let localDBSEKeyTag = "local.db.se.key.occulta"

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
            kSecAttrApplicationTag as String: Self.localDBSEKeyTag.data(using: .utf8)!,
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
                kSecAttrApplicationTag: Self.localDBSEKeyTag.data(using: .utf8)!,
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

    // MARK: - Cleanup

    /// Delete both components of the hybrid local DB key.
    /// Call only during full identity reset.
    @discardableResult
    func deleteLocalDBKey() -> Bool {
        let seDeleted = self.delete(using: Self.localDBSEKeyTag)

        let keychainQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: Self.localDBRandomKeychainAccount
        ]
        let keychainStatus = SecItemDelete(keychainQuery as CFDictionary)
        let keychainDeleted = keychainStatus == errSecSuccess || keychainStatus == errSecItemNotFound

        return seDeleted && keychainDeleted
    }
}

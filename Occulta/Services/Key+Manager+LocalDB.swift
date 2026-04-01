//
//  Key+Manager+LocalDB.swift
//  Occulta
//
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

import Foundation
import CryptoKit

// MARK: - Constants

extension SaltInfo {
    /// Domain separator for the hybrid local DB key. Distinct from kLocalDBKeyInfo
    /// to ensure the old (identity-derived) and new (hybrid) keys are never equivalent,
    /// even if the same SE key is used during migration.
    static let kLocalDBHybridKeyInfo = "Occulta-v1-local-db-pq-2025".data(using: .utf8)!
}

extension Manager.Key {

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
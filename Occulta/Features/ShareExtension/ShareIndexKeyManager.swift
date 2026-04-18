//
//  ShareIndexKeyManager.swift
//  Occulta
//
//  SE key in shared access group + HKDF derivation + AES-GCM for the share index.
//  Linked by both the main app and the share extension.
//
//  This is the ONLY crypto code the extension links. It never touches the identity key,
//  the local DB key, prekeys, or ML-KEM material.
//

import Foundation
import CryptoKit

final class ShareIndexKeyManager {

    // MARK: - Constants

    /// Unique SE key tag — never shared with any other key in the app.
    private static let tag = "share.index.se.key.occulta"

    /// App Group that both the main app and extension belong to.
    /// The SE key is created IN this group — not migrated.
    private static let accessGroup = "group.com.occulta.shared"

    /// Domain separator for HKDF. Unique to the share index — never reuses
    /// an existing info string (kLocalDBKeyInfo, kTransportKeyInfo, etc.).
    private static let hkdfInfo = "Occulta-v1-share-index-2026".data(using: .utf8)!

    /// P-256 generator base point G (uncompressed x9.63, 65 bytes).
    /// Same constant used by Key+Manager for local DB key derivation.
    /// ECDH(privKey, G) produces a deterministic secret tied to the private key.
    private static let generatorG = Data([
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

    // MARK: - SE Key Retrieval

    /// Retrieve the SE private key, creating it on first access.
    ///
    /// The access group in the query ensures we only find keys
    /// that belong to the shared group — never the identity key.
    private func retrievePrivateKey() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Self.tag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrAccessGroup as String: Self.accessGroup
        ]
        var item: CFTypeRef?

        switch SecItemCopyMatching(query as CFDictionary, &item) {
        case errSecSuccess:
            return item as! SecKey

        case errSecItemNotFound:
            item = nil
            try self.createKey()
            guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else {
                throw KeyError.creationFailed
            }
            return item as! SecKey

        default:
            throw KeyError.retrievalFailed
        }
    }

    /// Create a new P-256 key in the Secure Enclave with the shared access group.
    ///
    /// - `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`: not backed up, not synced
    /// - `.privateKeyUsage`: allows ECDH without additional authentication
    /// - `kSecAttrAccessGroup` in `kSecPrivateKeyAttrs`: places the key in the shared
    ///   group so both the main app and extension can derive the same symmetric key
    private func createKey() throws {
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
                kSecAttrApplicationTag: Self.tag.data(using: .utf8)!,
                kSecAttrAccessControl: access,
                kSecAttrAccessGroup: Self.accessGroup
            ]
        ]

        guard let _ = SecKeyCreateRandomKey(attributes, &error) else {
            throw error!.takeRetainedValue() as Error
        }
    }

    // MARK: - Symmetric Key Derivation

    /// Derive the symmetric key for encrypting the contact index.
    ///
    /// Both the main app and the extension call this and get the same key because
    /// they share access to the same SE private key via the access group.
    ///
    /// ```
    /// ECDH(shareIndexSEKey, G) → 32 bytes raw shared secret
    /// HKDF<SHA256>(
    ///   IKM:  raw ECDH secret (32 bytes)
    ///   Salt: shareIndexSEKey public key x963 (65 bytes)
    ///   Info: "Occulta-v1-share-index-2026"
    /// ) → 32 bytes → SymmetricKey (AES-256)
    /// ```
    ///
    /// Salt is the public key (not XOR) — differs from Key+Manager's local DB pattern
    /// because this key has no peer; the public key alone provides per-key uniqueness.
    func deriveSymmetricKey() throws -> SymmetricKey {
        let privateKey = try self.retrievePrivateKey()

        guard let fixedPubKey = Self.convertToSecKey(Self.generatorG) else {
            throw KeyError.ecdhFailed
        }

        var error: Unmanaged<CFError>?
        guard
            let rawSecret = SecKeyCopyKeyExchangeResult(
                privateKey, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        else { throw KeyError.ecdhFailed }

        guard
            let pubKey = SecKeyCopyPublicKey(privateKey),
            let pubData = SecKeyCopyExternalRepresentation(pubKey, nil) as Data?
        else { throw KeyError.publicKeyExportFailed }

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: pubData,
            info: Self.hkdfInfo,
            outputByteCount: 32
        )
    }

    // MARK: - AES-GCM Encrypt / Decrypt

    /// AES-256-GCM encrypt. Random 96-bit nonce per call.
    /// Output format: nonce ∥ ciphertext ∥ tag (CryptoKit `.combined`).
    func encrypt(data: Data) throws -> Data {
        let key = try self.deriveSymmetricKey()
        let sealed = try AES.GCM.seal(data, using: key, nonce: AES.GCM.Nonce())
        guard let combined = sealed.combined else { throw KeyError.encryptionFailed }
        return combined
    }

    /// AES-256-GCM decrypt. Authenticates tag before returning plaintext.
    func decrypt(data: Data) throws -> Data {
        let key = try self.deriveSymmetricKey()
        let box = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(box, using: key)
    }

    // MARK: - Helpers

    /// Convert 65-byte x9.63 public key data to a SecKey reference.
    /// Rejects any input that isn't exactly 65 bytes (uncompressed P-256).
    private static func convertToSecKey(_ data: Data) -> SecKey? {
        guard data.count == 65 else { return nil }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        return SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error)
    }

    enum KeyError: Error {
        case creationFailed
        case retrievalFailed
        case ecdhFailed
        case publicKeyExportFailed
        case encryptionFailed
    }
}

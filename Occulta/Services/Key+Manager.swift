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
    static let kLocalDBKeyInfo   = "Occulta-v1-local-db-2025".data(using: .utf8)!
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
                _ = try self.create()
                return SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess
                    ? (item as! SecKey) : nil
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

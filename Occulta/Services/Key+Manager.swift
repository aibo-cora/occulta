//
//  Key+MAnager.swift
//  Occulta
//
//  Created by Yura on 11/12/25.
//

import Foundation
import CryptoKit

extension Manager {
    class Key {
        /// Identifier of our private key in the `Secure Enclave`.
        let tag: String
        
        /// /// Create a manager with a master key tag.
        init() {
            self.tag = "master.key.privacy.turtles.are.cute"
        }
        
        /// Create a manager with a custom tag.
        /// - Parameter tag: Tag of the master key.
        ///
        /// This is for testing purposes only.
        init(testingTag tag: String) {
            self.tag = tag
        }
        
        /// Create master key in the `Secure Enclave`.
        /// - Returns: Result of the operation.
        private func create() throws -> Bool {
            var error: Unmanaged<CFError>?
            
            // TODO: Should we add more flags to ensure user authenticity? - .userPresence
            
            if let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &error) {
                let attributes: NSDictionary = [
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits: 256,
                kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs: [
                    kSecAttrIsPermanent: true,
                    kSecAttrApplicationTag: self.tag.data(using: .utf8)!,
                    kSecAttrAccessControl: access]
                ]
                
                guard
                    let _ = SecKeyCreateRandomKey(attributes, &error)
                else {
                    throw error!.takeRetainedValue() as Error
                }
                
                return true
            } else {
                throw error!.takeRetainedValue() as Error
            }
        }
        
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
        
        /// Use a fixed public key in x963 format and our private key to create an AES encryption key for local crypto operations.
        /// - Returns: AES key to use in the local database.
        func createLocalEncryptionKey() throws -> SymmetricKey? {
            let fixedPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: self.fixedX963)
            
            let encryptionKey = self.createSharedSecret(using: fixedPublicKey.x963Representation)
            
            return encryptionKey
        }
        
        /// Retrieve private key from the `Secure Enclave`.
        /// - Returns: Private key in `SecKey` format.
        func retrievePrivateKey() throws -> SecKey? {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: self.tag.data(using: .utf8)!,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecReturnRef as String: true,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
            ]
            
            var item: CFTypeRef?
            
            let status = SecItemCopyMatching(query as CFDictionary, &item)
            
            switch status {
            case errSecItemNotFound:
                _ = try self.create()
                
                let status = SecItemCopyMatching(query as CFDictionary, &item)
                
                if status == errSecSuccess {
                    return (item as! SecKey)
                }
            case errSecSuccess:
                return (item as! SecKey)
            default:
                break
            }
            
            return nil
        }
        
        /// Get the public key part from a private key.
        /// - Parameter key: Private key.
        /// - Returns: Public key counterpart.
        func retrivePublicKey(using key: SecKey?) -> SecKey? {
            if let key {
                return SecKeyCopyPublicKey(key)
            }
            
            return nil
        }
        
        func replace(using tag: String) -> Bool {
            /// 1. Delete old key
            /// 2. Replace `tag`
            /// 3. Create new key
            false
        }
        
        @discardableResult
        func delete(using tag: String) -> Bool {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tag.data(using: .utf8)!
            ]
            
            let status = SecItemDelete(query as CFDictionary)
            
            if status == errSecSuccess || status == errSecItemNotFound {
                return true
            } else {
                return false
            }
        }
        
        /// Removes our private key from the Secure Enclave.
        ///
        /// This means that we no longer will be able to encrypt or decrypt using this key.
        /// - Returns: Result of deletion.
        @discardableResult
        func deleteIdentity() -> Bool {
            self.delete(using: self.tag)
        }
        
        /// Create a shared secret using peer's public key and our private key.
        /// - Parameter material: Keying material of a public key of the other party.
        /// - Returns: Shared symmetric key.
        func createSharedSecret(using material: Data?) -> SymmetricKey? {
            // TODO: - This needs to be changed into a throwing function.
            
            let peerPublicKey: SecKey? = self.convert(material: material)
            let ourPrivateKey = try? self.retrievePrivateKey()
            
            let algorithm: SecKeyAlgorithm = .ecdhKeyExchangeCofactorX963SHA256
            var error: Unmanaged<CFError>?
            
            guard
                let peerPublicKey
            else {
                fatalError("Peer public key is missing")
            }
            
            guard
                let ourPrivateKey
            else {
                fatalError("Our private key is missing")
            }
            
            guard
                let rawSharedSecret = SecKeyCopyKeyExchangeResult(ourPrivateKey, algorithm, peerPublicKey, [SecKeyKeyExchangeParameter.requestedSize.rawValue : 32] as CFDictionary, &error) as? Data
            else {
                fatalError("ECDH failed: \(error!.takeRetainedValue())")
            }
            
            guard
                let peerPublicKeyData = self.convert(key: peerPublicKey),
                let ourPublicKeyData = self.convert(key: self.retrivePublicKey(using: ourPrivateKey))
            else {
                return nil
            }
            
            /// Data buffer of peer's public key.
            let peerBuffer: [UInt8] = peerPublicKeyData.map { $0 }
            /// Data buffer of our public key.
            let ourBuffer:[UInt8] = ourPublicKeyData.map { $0 }
            /// XORing each element from one array with the corresponding element in the other.
            let addition = zip(peerBuffer, ourBuffer).map { $0 ^ $1 }
            let salt = Data(addition)
            
            let sessionKey = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: rawSharedSecret),
                salt: salt,
                info: "Occulta-v1-encryption-key-2025".data(using: .utf8)!,
                outputByteCount: 32
            )
            
            return sessionKey
        }
    }
}

extension Manager.Key {
    /// Convert public key, ours or peer's into a data buffer.
    /// - Parameter key: Public key.
    /// - Returns: Public keying material.
    func convert(key: SecKey?) -> Data? {
        if let key, let publicKeyData = SecKeyCopyExternalRepresentation(key, nil) as Data? {
            return publicKeyData
        }
        
        return nil
    }
    
    /// Convert public key material into a sec key.
    /// - Parameter data: Keying material.
    /// - Returns: Sec key.
    func convert(material data: Data?) -> SecKey? {
        guard
            let data
        else {
            return nil
        }
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        
        var error: Unmanaged<CFError>?
        
        let publicKey = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error)
        
        return publicKey
    }
    
    /// Retrieve public keying material of our master key.
    /// - Returns: Buffer with our public keying material.
    func retrieveIdentity() throws -> Data {
        let master = try self.retrievePrivateKey()
        let identityKey = self.retrivePublicKey(using: master)
        let representation = self.convert(key: identityKey)
        
        guard
            let representation
        else {
            throw Errors.noIdentityAvailable
        }
        
        return representation
    }
}

extension Manager.Key {
    enum Errors: Error {
        case noIdentityAvailable
    }
}

//
//  Key+MAnager.swift
//  Maverick
//
//  Created by Yura on 11/12/25.
//

import Foundation
import CryptoKit

class KeyManager {
    /// Identifier of our private key in the `Secure Enclave`.
    let tag: String
    
    init(using tag: String) {
        self.tag = tag
    }
    
    /// Create a key in the `Secure Enclave`.
    /// - Returns: Result of the operation.
    func create() throws -> Bool {
        var error: Unmanaged<CFError>?
        
        if let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error) {
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
    
    /// <#Description#>
    /// - Parameter rawData: <#rawData description#>
    /// - Returns: <#description#>
    func createPublicKeyFrom(_ rawData: Data) -> SecKey? {
        // rawData must be 65-byte uncompressed P-256 public key (starts with 0x04)
        guard
            rawData.count == 65,
                rawData[0] == 0x04
        else {
            print("Invalid public key format – must be 65-byte uncompressed P-256")
            return nil
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256,
            // No access control or tag needed for public keys
        ]

        var error: Unmanaged<CFError>?
        let key = SecKeyCreateWithData(rawData as CFData,
                                       attributes as CFDictionary,
                                       &error)

        if let error = error {
            print("Failed to recreate SecKey: \(error.takeRetainedValue())")
            return nil
        }

        return key
    }
    
    /// Retrieve private key from the `Secure Enclave`.
    /// - Returns: Private key in `SecKey` format.
    func retrievePrivateKey() -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: self.tag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
        ]
        
        var item: CFTypeRef?
        
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status == errSecSuccess {
            return (item as! SecKey)
        }
        
        return nil
    }
    
    /// <#Description#>
    /// - Parameter key: <#key description#>
    /// - Returns: <#description#>
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
    
    /// <#Description#>
    /// - Parameter material: <#material description#>
    /// - Returns: <#description#>
    func createSharedSecret(using material: Data?) -> Data? {
        let peerPublicKey: SecKey? = self.convert(material: material)
        let ourPrivateKey = self.retrievePrivateKey()
        
        return nil
        
    }
}

extension KeyManager {
    /// <#Description#>
    /// - Parameter key: <#key description#>
    /// - Returns: <#description#>
    func convert(key: SecKey?) -> Data? {
        if let key, let publicKeyData = SecKeyCopyExternalRepresentation(key, nil) as Data? {
            return publicKeyData
        }
        
        return nil
    }
    
    /// <#Description#>
    /// - Parameter data: <#data description#>
    /// - Returns: <#description#>
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
}

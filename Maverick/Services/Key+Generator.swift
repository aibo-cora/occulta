//
//  Key+Generator.swift
//  Maverick
//
//  Created by Yura on 11/12/25.
//

import Foundation
import CryptoKit

class KeyGenerator {
    /// Create a key in the `Secure Enclave`.
    /// - Parameter tag: Reference tag.
    func create(using tag: String) throws {
        var error: Unmanaged<CFError>?
        
        if let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error) {
            let attributes: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: tag.data(using: .utf8)!,
                kSecAttrAccessControl: access]
            ]
            
            guard
                let _ = SecKeyCreateRandomKey(attributes, &error)
            else {
                throw error!.takeRetainedValue() as Error
            }
        } else {
            throw error!.takeRetainedValue() as Error
        }
    }
    
    /// Retrieve public key from the `Secure Enclave`.
    /// - Parameter tag: Reference tag.
    /// - Returns: Base64 encoded public key in string format.
    func retrieve(using tag: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
        ]
        
        var item: CFTypeRef?
        
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status == errSecSuccess {
            if let publicKey = SecKeyCopyPublicKey(item as! SecKey), let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? {
                return publicKeyData.base64EncodedString()
            }
        }
        
        return nil
    }
    
    func replace(using tag: String) -> Bool {
        false
    }
    
    func delete(using tag: String) {
        
    }
}

//
//  Key+Generator.swift
//  Maverick
//
//  Created by Yura on 11/12/25.
//

import Foundation
import CryptoKit

class KeyGenerator {
    func generatePrivateKey(tag: String) throws {
        var error: Unmanaged<CFError>?
        
        if let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error) {
            let attributes: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: tag,
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
    
    func retrievePublicKey(using tag: String) -> Data? {
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
            if let publicKeyData = SecKeyCopyExternalRepresentation(item as! SecKey, nil) as Data? {
                return publicKeyData
            }
        }
        
        return nil
    }
}

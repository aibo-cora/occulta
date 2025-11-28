//
//  Crypto+Manager.swift
//  Maverick
//
//  Created by Yura on 11/21/25.
//

import Foundation
import CryptoKit
import Crypto

enum Manager { }

extension Manager {
    
    // TODO: Separate local and transport versions into their own classes for clarity
    
    class Crypto: CryptoProtocol {
        let keyManager = KeyManager()
        
        // MARK: Local encryption
        
        /// Encrypt data using our local encryption key.
        /// - Parameter data: Payload.
        /// - Returns: Encrypted data.
        func encrypt(data: Data?) throws -> Data? {
            guard
                let data = data,
                let key = try self.keyManager.createLocalEncryptionKey()
            else {
                return nil
            }
            
            let sealed = try AES.GCM.seal(data, using: key, nonce: AES.GCM.Nonce())
            
            return sealed.combined
        }
        
        /// Decrypt data using our local encryption key.
        /// - Parameter data: Encrypted payload.
        /// - Returns: Decrypted data.
        func decrypt(data: Data?) throws -> Data? {
            guard
                let data = data,
                let key = try self.keyManager.createLocalEncryptionKey()
            else {
                return nil
            }
            
            let box = try AES.GCM.SealedBox(combined: data)
            let payload = try AES.GCM.open(box, using: key)
            
            return payload
        }
        
        // MARK: Encrypting data for transport
        
        /// Encrypt a message for a contact using associated key to derived a shared crypto key.
        /// - Parameters:
        ///   - message: Message to encrypt.
        ///   - material: Public keying material of contact.
        /// - Returns: Encrypted data, combined.
        func encrypt(message: String, using material: Data?) throws -> Data? {
            /// Crypto key derived from our private key and contact's public key. It is a shared secret.
            guard
                let key = self.keyManager.createSharedSecret(using: material),
                let encoded = message.data(using: .utf8)
            else {
                return nil
            }
            
            let sealed = try AES.GCM.seal(encoded, using: key, nonce: AES.GCM.Nonce())
            
            return sealed.combined
        }
        
        /// Decrypt a sealed box in Base64 format.
        /// - Parameters:
        ///   - message: Encrypted message in Base64 format.
        ///   - material: Public keying material of our contact.
        /// - Returns: Decrypted message in encoded form.
        func decrypt(message: String, using material: Data?) throws -> Data? {
            guard
                let encrypted = Data(base64Encoded: message),
                let key = self.keyManager.createSharedSecret(using: material)
            else {
                return nil
            }
            
            let sealed = try AES.GCM.SealedBox(combined: encrypted)
            let payload = try AES.GCM.open(sealed, using: key)
            
            return payload
        }
    }
}

protocol CryptoProtocol {
    func encrypt(data: Data?) throws -> Data?
    func decrypt(data: Data?) throws -> Data?
    /// Encrypt a message for a contact using associated key to derived a shared crypto key.
    /// - Parameters:
    ///   - message: Message to encrypt.
    ///   - material: Public keying material of contact.
    /// - Returns: Encrypted data, combined.
    func encrypt(message: String, using material: Data?) throws -> Data?
    /// Decrypt a sealed box in Base64 format.
    /// - Parameters:
    ///   - message: Encrypted message in Base64 format.
    ///   - material: Public keying material of our contact.
    /// - Returns: Decrypted message in encoded form.
    func decrypt(message: String, using material: Data?) throws -> Data?
}

extension String {
    func decrypt() -> String {
        let data = Data(base64Encoded: self)
        let cryptoOps: CryptoProtocol = Manager.Crypto()
        
        do {
            if let decrypted = try cryptoOps.decrypt(data: data) {
                let decoded = String(data: decrypted, encoding: .utf8) ?? ""
                
                return decoded
            } else {
                return ""
            }
        } catch {
            return ""
        }
    }
}

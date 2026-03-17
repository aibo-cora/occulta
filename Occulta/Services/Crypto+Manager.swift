//
//  Crypto+Manager.swift
//  Occulta
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
        let keyManager = Manager.Key()
        
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
        func encrypt(message: Data, using material: Data?) throws -> Data? {
            /// Crypto key derived from our private key and contact's public key. It is a shared secret.
            guard
                let key = self.keyManager.createSharedSecret(using: material)
            else {
                return nil
            }
            
            let sealed = try AES.GCM.seal(message, using: key, nonce: AES.GCM.Nonce())
            
            return sealed.combined
        }
        
        /// Decrypt a sealed box using publoic keying material to derive the decryption key.
        /// - Parameters:
        ///   - message: Encrypted message.
        ///   - material: Public keying material of our contact.
        /// - Returns: Decrypted message in encoded form.
        func decrypt(message: Data, using material: Data?) throws -> Data? {
            guard
                let key = self.keyManager.createSharedSecret(using: material)
            else {
                return nil
            }
            
            let sealed = try AES.GCM.SealedBox(combined: message)
            let payload = try AES.GCM.open(sealed, using: key)
            
            return payload
        }
        
        /// Decrypt a message using a session key.
        /// - Parameters:
        ///   - message: Encrypted message.
        ///   - sessionKey: Session key. Used in a multi recipient message format.
        /// - Returns: Decrypted payload.
        func decrypt(message: Data?, sessionKey: Data) throws -> Data {
            let key = SymmetricKey(data: sessionKey)
            
            let sealed = try AES.GCM.SealedBox(combined: message ?? Data())
            let payload = try AES.GCM.open(sealed, using: key)
            
            return payload
        }
        
        func encrypt(contacts: Data, using passphrase: String) throws -> Data? {
            guard
                let material = passphrase.data(using: .utf8)
            else {
                return nil
            }
            
            let hash = Data(SHA256.hash(data: material))
            let key = SymmetricKey(data: hash)
            
            let sealed = try AES.GCM.seal(contacts, using: key, nonce: AES.GCM.Nonce())
            
            return sealed.combined
        }
        
        func decrypt(contacts: Data, using passphrase: String) throws -> Data? {
            guard
                contacts.isEmpty == false,
                let material = passphrase.data(using: .utf8)
            else {
                return nil
            }
            
            let hash = Data(SHA256.hash(data: material))
            let key = SymmetricKey(data: hash)
            
            let box = try AES.GCM.SealedBox(combined: contacts)
            let decrypted = try AES.GCM.open(box, using: key)
            
            return decrypted
        }
        
        func sign(data: Data?) -> String {
            do {
                let key = try self.keyManager.retrievePrivateKey()
                let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
                
                var error: Unmanaged<CFError>?
                
                guard
                    let key,
                    let data
                else {
                    return "Key or data is missing"
                }
                
                guard
                    SecKeyIsAlgorithmSupported(key, .sign, algorithm)
                else {
                    return "Algorithm is not supported"
                }
                
                guard
                    let signature = SecKeyCreateSignature(key, algorithm, data as CFData, &error) as Data?
                else {
                    return "Error creating signature: \(error!.takeRetainedValue() as Error)"
                }
                
                debugPrint("Signature size = \(signature.count)")
                
                return signature.hexEncodedString()
            } catch {
                return "Signature could not be created, try again."
            }
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
    func encrypt(message: Data, using material: Data?) throws -> Data?
    /// Decrypt a sealed box in Base64 format.
    /// - Parameters:
    ///   - message: Encrypted message in Base64 format.
    ///   - material: Public keying material of our contact.
    /// - Returns: Decrypted message in encoded form.
    func decrypt(message: Data, using material: Data?) throws -> Data?
    
    func encrypt(contacts: Data, using passphrase: String) throws -> Data?
    func decrypt(contacts: Data, using passphrase: String) throws -> Data?
    
    func sign(data: Data?) -> String
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

extension Data {
    func hexEncodedString() -> String {
        return self.map { String(format: "%02x", $0) }.joined()
    }
    
    func decrypt() -> Data? {
        let cryptoOps: CryptoProtocol = Manager.Crypto()
        
        return try? cryptoOps.decrypt(data: self)
    }
}

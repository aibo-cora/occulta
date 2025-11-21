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
    class Crypto: CryptoProtocol {
        let keyManager = KeyManager()
        
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
    }
}

protocol CryptoProtocol {
    func encrypt(data: Data?) throws -> Data?
    func decrypt(data: Data?) throws -> Data?
}

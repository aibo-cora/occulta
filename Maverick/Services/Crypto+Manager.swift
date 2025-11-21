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
        
        func encrypt(data: Data?) -> Data? {
            guard
                let data = data
            else {
                return nil
            }
            
            let nonce = AES.GCM.Nonce()
            
            return nil
        }
        
        func decrypt(data: Data?) -> Data? {
            guard
                let data = data
            else {
                return nil
            }
            
            return nil
        }
    }
}

protocol CryptoProtocol {
    func encrypt(data: Data?) -> Data?
    func decrypt(data: Data?) -> Data?
}

//
//  Key+Manipulation.swift
//  MaverickTests
//
//  Created by Yura on 11/13/25.
//

import Testing
@testable import Maverick
import Foundation

struct KeyManipulation {
    @Test("Generates private key in Secure Enclave")
    func generatePrivateKey() throws {
        let tag = UUID().uuidString
        let manager = KeyManager(using: tag)
        
        let result = try manager.create()

        let deletion = manager.delete(using: tag)
        
        #expect(result == true)
        #expect(deletion == true)
    }
    
    @Test("Retrieve public key material from Secure Enclave")
    func retrievePublicKey() throws {
        let tag = UUID().uuidString
        let manager = KeyManager(using: tag)
        
        let _ = try manager.create()
        let privateKey = manager.retrievePrivateKey()
        let publicKey = manager.retrivePublicKey(using: privateKey)
        
        manager.delete(using: tag)
        
        let material = manager.convert(key: publicKey)
        
        #expect(publicKey != nil)
        #expect((material ?? Data()).isEmpty == false, "Material is empty")
        #expect((material ?? Data()).count == 65, "Invalid material length")
        #expect(publicKey == manager.convert(material: manager.convert(key: publicKey)), "Keys are not equal")
    }
}

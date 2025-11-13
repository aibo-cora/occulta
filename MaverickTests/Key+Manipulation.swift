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
    let manager = KeyManager(using: UUID().uuidString)
    
    @Test("Generates private key in Secure Enclave")
    func generatePrivateKey() throws {
        let tag = UUID().uuidString
        let result = try self.manager.create()

        let deletion = self.manager.delete(using: tag)
        
        #expect(result == true)
        #expect(deletion == true)
    }
    
    @Test("Retrieve public key material from Secure Enclave")
    func retrievePublicKey() throws {
        let tag = UUID().uuidString
        
        let _ = try self.manager.create()
        let privateKey = self.manager.retrievePrivateKey()
        let publicKey = self.manager.retrivePublicKey(using: privateKey)
        
        self.manager.delete(using: tag)
        
        let material = self.manager.convert(key: publicKey)
        
        #expect(publicKey != nil)
        #expect((material ?? Data()).isEmpty == false, "Material is empty")
        #expect((material ?? Data()).count == 65, "Invalid material length")
        #expect(publicKey == self.manager.convert(material: self.manager.convert(key: publicKey)), "Keys are not equal")
    }
}

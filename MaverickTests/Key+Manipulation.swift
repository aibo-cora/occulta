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
    
    @Test("Create shared secret that is identical for 2 parties")
    func createSharedSecret() throws {
        let tagBob = UUID().uuidString
        let tagAlice = UUID().uuidString
        
        let managerBob = KeyManager(using: tagBob)
        let managerAlice = KeyManager(using: tagAlice)
        
        let _ = try managerBob.create()
        let _ = try managerAlice.create()
        
        let privateKeyBob = managerBob.retrievePrivateKey()
        let privateKeyAlice = managerAlice.retrievePrivateKey()
        
        let publicKeyBob = managerBob.retrivePublicKey(using: privateKeyBob)
        let publicKeyAlice = managerAlice.retrivePublicKey(using: privateKeyAlice)
        
        let publicKeyingMaterialBob = managerBob.convert(key: publicKeyBob)
        let publicKeyingMaterialAlice = managerAlice.convert(key: publicKeyAlice)
        
        let sharedSecretAliceToBob = managerAlice.createSharedSecret(using: publicKeyingMaterialBob)
        let sharedSecretBobToAlice = managerBob.createSharedSecret(using: publicKeyingMaterialAlice)
        
        #expect(publicKeyingMaterialBob != nil && publicKeyingMaterialAlice != nil)
        #expect(publicKeyingMaterialBob != publicKeyingMaterialAlice)
        
        #expect(sharedSecretAliceToBob != nil, "Shared secret - Bob - is nil")
        #expect(sharedSecretBobToAlice != nil, "Shared secret - Alice - is nil")
        #expect(sharedSecretBobToAlice == sharedSecretAliceToBob)
        
        managerBob.delete(using: tagBob)
        managerAlice.delete(using: tagAlice)
    }
}

//
//  Key+Manipulation.swift
//  OccultaTests
//
//  Created by Yura on 11/13/25.
//

import Testing
@testable import Occulta

/// True when this host can derive the real hybrid local DB key. False on GitHub-hosted CI
/// runners, which are VMs with no Secure Enclave. Tests gated on this report as *skipped*
/// rather than silently passing, so the size of the untested surface stays visible.
private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

import Foundation
import CryptoKit

struct KeyManipulation {
    @Test("Generates private key in Secure Enclave", .enabled(if: secureEnclaveAvailable()))
    func generatePrivateKey() throws {
        let tag = UUID().uuidString
        let manager = Manager.Key(testingTag: tag)
        
        let result = try manager.retrievePrivateKey()

        let deletion = manager.delete(using: tag)
        
        #expect(result != nil)
        #expect(deletion == true)
    }
    
    @Test("Retrieve public key material from Secure Enclave", .enabled(if: secureEnclaveAvailable()))
    func retrievePublicKey() throws {
        let tag = UUID().uuidString
        let manager = Manager.Key(testingTag: tag)
        
        let privateKey = try manager.retrievePrivateKey()
        let publicKey = manager.retrivePublicKey(using: privateKey)
        
        manager.delete(using: tag)
        
        let material = manager.convert(key: publicKey)
        
        #expect(publicKey != nil)
        #expect((material ?? Data()).isEmpty == false, "Material is empty")
        #expect((material ?? Data()).count == 65, "Invalid material length")
        #expect(publicKey == manager.convert(material: manager.convert(key: publicKey)), "Keys are not equal")
    }
    
    @Test("Create shared secret that is identical for 2 parties", .enabled(if: secureEnclaveAvailable()))
    func createSharedSecret() throws {
        let tagBob = UUID().uuidString
        let tagAlice = UUID().uuidString
        
        let managerBob = Manager.Key(testingTag: tagBob)
        let managerAlice = Manager.Key(testingTag: tagAlice)
        
        let privateKeyBob = try managerBob.retrievePrivateKey()
        let privateKeyAlice = try managerAlice.retrievePrivateKey()
        
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
    
    @Test("Create local encryption key", .enabled(if: secureEnclaveAvailable()))
    func createLocalEncryptionKey() throws {
        let tag = UUID().uuidString
        let manager = Manager.Key(testingTag: tag)
        
        let localEncryptionKey = try manager.createLocalEncryptionKey()
        
        #expect(localEncryptionKey != nil)
        #expect(localEncryptionKey?.bitCount == 256)
        
        manager.delete(using: tag)
    }
}

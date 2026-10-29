//
//  PostQuantumPersistenceTests.swift
//  OccultaTests
//
//  `PostQuantumProvider.generatePersistentKeyPair` and `decapsulate(ciphertext:keyBlob:)`: a card's ML-KEM key has to
//  outlive the call that made it (`Docs/Features/Introduction Cards/SPEC.md` §1, §13).
//
//  The in-memory provider runs anywhere. The Enclave test needs a Secure Enclave and iOS 26, and reports as skipped
//  without them.
//
//  ⚠️  Never run the Enclave test on a phone that holds real Occulta data: the suite is hosted in Occulta.app.
//

import Testing
import CryptoKit
import Foundation

import OccultaCore
@testable import Occulta

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

/// The Enclave ML-KEM provider exists on iOS 26 and later, and needs an Enclave to create a key.
private func enclaveMLKEMAvailable() -> Bool {
    guard #available(iOS 26, *) else { return false }
    return secureEnclaveAvailable()
}

@Suite("PostQuantumProvider — persistent ML-KEM keys (SPEC §1)")
struct PostQuantumPersistenceTests {

    // MARK: - In-memory provider

    @available(iOS 26, *)
    @Test("Encapsulate to the public key, then decapsulate from the blob: the same secret")
    func blobDecapsulatesToTheEncapsulatedSecret() throws {
        let provider = try #require(PostQuantumProviderFactory.createForTesting())
        let pair     = try #require(provider.generatePersistentKeyPair())
        #expect(pair.publicKeyData.count == 1_568)
        #expect(!pair.keyBlob.isEmpty)

        let sent = try #require(provider.encapsulate(peerPublicKeyData: pair.publicKeyData))
        #expect(sent.ciphertext.count == 1_568)
        #expect(sent.sharedSecret.count == 32)

        let received = try #require(provider.decapsulate(ciphertext: sent.ciphertext, keyBlob: pair.keyBlob))
        #expect(received == sent.sharedSecret)
    }

    @available(iOS 26, *)
    @Test("The blob alone is enough: a different provider instance, standing for a later launch, decapsulates")
    func blobWorksOnAFreshProvider() throws {
        let first  = try #require(PostQuantumProviderFactory.createForTesting())
        let pair   = try #require(first.generatePersistentKeyPair())
        let sent   = try #require(first.encapsulate(peerPublicKeyData: pair.publicKeyData))

        let second = try #require(PostQuantumProviderFactory.createForTesting())
        #expect(second.decapsulate(ciphertext: sent.ciphertext, keyBlob: pair.keyBlob) == sent.sharedSecret)
        #expect(second.decapsulate(ciphertext: sent.ciphertext, keyBlob: pair.keyBlob) == sent.sharedSecret, "and again: the blob is not consumed")
    }

    @available(iOS 26, *)
    @Test("Each call makes a new key")
    func keysAreDistinct() throws {
        let provider = try #require(PostQuantumProviderFactory.createForTesting())
        let a = try #require(provider.generatePersistentKeyPair())
        let b = try #require(provider.generatePersistentKeyPair())

        #expect(a.publicKeyData != b.publicKeyData)
        #expect(a.keyBlob != b.keyBlob)
    }

    @available(iOS 26, *)
    @Test("Another key's blob does not give the sender's secret")
    func anotherKeysBlob() throws {
        let provider = try #require(PostQuantumProviderFactory.createForTesting())
        let mine     = try #require(provider.generatePersistentKeyPair())
        let other    = try #require(provider.generatePersistentKeyPair())
        let sent     = try #require(provider.encapsulate(peerPublicKeyData: mine.publicKeyData))

        // ML-KEM rejects implicitly: decapsulating under the wrong key returns an unrelated secret, not an error.
        // What matters is that it is not the sender's secret.
        #expect(provider.decapsulate(ciphertext: sent.ciphertext, keyBlob: other.keyBlob) != sent.sharedSecret)
    }

    @available(iOS 26, *)
    @Test("A ciphertext of the wrong length gives nil")
    func wrongCiphertext() throws {
        let provider = try #require(PostQuantumProviderFactory.createForTesting())
        let pair     = try #require(provider.generatePersistentKeyPair())
        let sent     = try #require(provider.encapsulate(peerPublicKeyData: pair.publicKeyData))

        #expect(provider.decapsulate(ciphertext: Data(sent.ciphertext.dropLast()), keyBlob: pair.keyBlob) == nil)
        #expect(provider.decapsulate(ciphertext: sent.ciphertext + Data([0]), keyBlob: pair.keyBlob) == nil)
        #expect(provider.decapsulate(ciphertext: Data(), keyBlob: pair.keyBlob) == nil)
    }

    @available(iOS 26, *)
    @Test("A flipped ciphertext byte yields a different secret, not the sender's")
    func tamperedCiphertext() throws {
        let provider = try #require(PostQuantumProviderFactory.createForTesting())
        let pair     = try #require(provider.generatePersistentKeyPair())
        let sent     = try #require(provider.encapsulate(peerPublicKeyData: pair.publicKeyData))
        var tampered = [UInt8](sent.ciphertext)
        tampered[100] ^= 0x01

        #expect(provider.decapsulate(ciphertext: Data(tampered), keyBlob: pair.keyBlob) != sent.sharedSecret)
    }

    @available(iOS 26, *)
    @Test("The existing handle-based API still works alongside")
    func handleAPIIsUnchanged() throws {
        let provider = try #require(PostQuantumProviderFactory.createForTesting())
        let pair     = try #require(provider.generateKeyPair())
        let sent     = try #require(provider.encapsulate(peerPublicKeyData: pair.publicKeyData))
        #expect(provider.decapsulate(ciphertext: sent.ciphertext, privateKeyHandle: pair.privateKeyHandle) == sent.sharedSecret)
    }

    // MARK: - Secure Enclave

    @available(iOS 26, *)
    @Test("The Enclave provider's blob decapsulates after the key object is gone",
          .enabled(if: enclaveMLKEMAvailable()))
    func enclaveBlobDecapsulates() throws {
        let provider = try #require(PostQuantumProviderFactory.create())
        let pair     = try #require(provider.generatePersistentKeyPair())
        #expect(pair.publicKeyData.count == 1_568)

        // Carol's side: only the public key.
        let sent = try #require(PostQuantumProviderFactory.createForTesting()?.encapsulate(peerPublicKeyData: pair.publicKeyData))

        // Bob's side, later: only the blob, from a provider that never made the key.
        let later = try #require(PostQuantumProviderFactory.create())
        #expect(later.decapsulate(ciphertext: sent.ciphertext, keyBlob: pair.keyBlob) == sent.sharedSecret)
        #expect(later.decapsulate(ciphertext: Data(sent.ciphertext.dropLast()), keyBlob: pair.keyBlob) == nil, "wrong ciphertext length")
    }

    @available(iOS 26, *)
    @Test("The Enclave provider: an empty blob gives nil", .enabled(if: enclaveMLKEMAvailable()))
    func enclaveEmptyBlobGivesNil() throws {
        let provider = try #require(PostQuantumProviderFactory.create())
        let pair     = try #require(provider.generatePersistentKeyPair())
        let sent     = try #require(PostQuantumProviderFactory.createForTesting()?.encapsulate(peerPublicKeyData: pair.publicKeyData))
        #expect(provider.decapsulate(ciphertext: sent.ciphertext, keyBlob: Data()) == nil)
    }

    @available(iOS 26, *)
    @Test("The Enclave provider: a blob the Enclave never made gives nil", .enabled(if: enclaveMLKEMAvailable()))
    func enclaveForeignBlobGivesNil() throws {
        let provider = try #require(PostQuantumProviderFactory.create())
        let pair     = try #require(provider.generatePersistentKeyPair())
        let sent     = try #require(PostQuantumProviderFactory.createForTesting()?.encapsulate(peerPublicKeyData: pair.publicKeyData))
        #expect(provider.decapsulate(ciphertext: sent.ciphertext, keyBlob: randomBytes(143)) == nil)
    }

    // MARK: - Malformed blobs

    @available(iOS 26, *)
    @Test("A blob of the wrong size gives nil rather than trapping")
    func malformedBlobGivesNil() throws {
        let provider = try #require(PostQuantumProviderFactory.createForTesting())
        let pair     = try #require(provider.generatePersistentKeyPair())
        let sent     = try #require(provider.encapsulate(peerPublicKeyData: pair.publicKeyData))

        #expect(provider.decapsulate(ciphertext: sent.ciphertext, keyBlob: Data()) == nil, "empty")
        #expect(provider.decapsulate(ciphertext: sent.ciphertext, keyBlob: Data(pair.keyBlob.dropLast())) == nil, "truncated")
        #expect(provider.decapsulate(ciphertext: sent.ciphertext, keyBlob: pair.keyBlob + Data([0])) == nil, "extended")
    }
}

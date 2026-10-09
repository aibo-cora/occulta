//
//  ForwardSecretDerivationEquivalenceTests.swift
//  OccultaTests
//
//  Prekey Continuity stage 1, commit 1. Prekeys are moving from keychain `SecKey`s to CryptoKit Enclave
//  keys held as blobs in the contact's record (D9). Both must derive the same forward-secret session key,
//  or a message sealed by a sender to a record-held prekey wouldn't open.
//
//  The two paths differ in one step: a `SecKey` uses `.ecdhKeyExchangeCofactorX963SHA256` (ECDH then the
//  X9.63 KDF), a CryptoKit `SharedSecret` is the raw ECDH output. These tests hold one software P-256 key
//  in both forms and compare, so they need no Enclave and run on CI. The last one, Enclave-gated, opens a
//  real bundle with a real CryptoKit Enclave key.
//

import Testing
import Foundation
import CryptoKit
import Security
@testable import Occulta
@testable import OccultaCore

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

/// The same private key as a CryptoKit key and as a `SecKey`.
private func keyInBothForms() throws -> (cryptoKit: P256.KeyAgreement.PrivateKey, secKey: SecKey) {
    let key   = P256.KeyAgreement.PrivateKey()
    let attrs: [String: Any] = [
        kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String:      kSecAttrKeyClassPrivate,
        kSecAttrKeySizeInBits as String: 256
    ]
    let secKey = try #require(SecKeyCreateWithData(key.x963Representation as CFData, attrs as CFDictionary, nil))
    return (key, secKey)
}

private func quantumMaterial() -> QuantumKeyMaterial {
    QuantumKeyMaterial(
        encapsulatedSecret: Data((0..<32).map { _ in .random(in: .min ... .max) }),
        decapsulatedSecret: Data((0..<32).map { _ in .random(in: .min ... .max) }),
        ourCiphertext: Data(count: 32), peerCiphertext: Data(count: 32)
    )
}

private func bytes(_ key: SymmetricKey?) -> Data? {
    key?.withUnsafeBytes { Data($0) }
}

@Suite("Forward-secret derivation — CryptoKit and SecKey paths agree")
@MainActor struct ForwardSecretDerivationEquivalenceTests {

    let crypto = Manager.Crypto(keyManager: TestKeyManager())

    @Test("Same prekey, same peer, classical: identical session keys")
    func classicalSameKey() throws {
        let prekey  = try keyInBothForms()
        let peerPub = P256.KeyAgreement.PrivateKey().publicKey

        let viaSecKey = Manager.Key().createSharedSecret(
            ephemeralPrivateKey: prekey.secKey, recipientMaterial: peerPub.x963Representation
        )
        let viaCryptoKit = self.crypto.deriveSessionKey(
            sharedSecret: try prekey.cryptoKit.sharedSecretFromKeyAgreement(with: peerPub),
            ownPublicKey: prekey.cryptoKit.publicKey.x963Representation,
            recipientMaterial: peerPub.x963Representation
        )

        #expect(bytes(viaSecKey) != nil)
        #expect(bytes(viaSecKey) == bytes(viaCryptoKit))
    }

    @Test("Same prekey, same peer, hybrid: identical session keys")
    func hybridSameKey() throws {
        let prekey  = try keyInBothForms()
        let peerPub = P256.KeyAgreement.PrivateKey().publicKey
        let qm      = quantumMaterial()

        let viaSecKey = Manager.Key().createHybridFSSharedSecret(
            ephemeralPrivateKey: prekey.secKey, recipientMaterial: peerPub.x963Representation, quantumMaterial: qm
        )
        let viaCryptoKit = self.crypto.deriveSessionKey(
            sharedSecret: try prekey.cryptoKit.sharedSecretFromKeyAgreement(with: peerPub),
            ownPublicKey: prekey.cryptoKit.publicKey.x963Representation,
            recipientMaterial: peerPub.x963Representation,
            quantumMaterial: qm
        )

        #expect(bytes(viaSecKey) != nil)
        #expect(bytes(viaSecKey) == bytes(viaCryptoKit))
    }

    /// The pairing production will use: the sender's throwaway `SecKey` against our prekey's public key,
    /// and our CryptoKit prekey against the sender's ephemeral public key.
    @Test("Sender with a SecKey ephemeral, recipient with a CryptoKit prekey: same key, both modes",
          arguments: [false, true])
    func senderAndRecipientAgree(hybrid: Bool) throws {
        let ephemeral = try keyInBothForms()
        let prekey    = P256.KeyAgreement.PrivateKey()
        let qm        = hybrid ? quantumMaterial() : nil

        let senderKey: SymmetricKey?
        if let qm {
            senderKey = Manager.Key().createHybridFSSharedSecret(
                ephemeralPrivateKey: ephemeral.secKey, recipientMaterial: prekey.publicKey.x963Representation,
                quantumMaterial: qm)
        } else {
            senderKey = Manager.Key().createSharedSecret(
                ephemeralPrivateKey: ephemeral.secKey, recipientMaterial: prekey.publicKey.x963Representation)
        }
        let recipientKey = self.crypto.deriveSessionKey(
            sharedSecret: try prekey.sharedSecretFromKeyAgreement(with: ephemeral.cryptoKit.publicKey),
            ownPublicKey: prekey.publicKey.x963Representation,
            recipientMaterial: ephemeral.cryptoKit.publicKey.x963Representation,
            quantumMaterial: qm
        )

        #expect(bytes(senderKey) != nil)
        #expect(bytes(senderKey) == bytes(recipientKey))
    }

    /// End to end with a real Enclave key, rebuilt from its blob as a record-held prekey will be.
    @Test("A bundle sealed by today's sender code opens with a CryptoKit Enclave prekey rebuilt from its blob",
          .enabled(if: secureEnclaveAvailable()))
    func enclaveBlobOpensBundle() throws {
        var error: Unmanaged<CFError>?
        let access = try #require(SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &error
        ))
        let blob = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access).dataRepresentation
        let prekeyKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
        let prekeyPub = prekeyKey.publicKey.x963Representation

        let message = Data("record-held prekey".utf8)
        let bundle  = try Manager.Crypto().seal(
            message: message,
            contactPrekey: Prekey(id: UUID().uuidString, contactID: "equivalence", publicKey: prekeyPub),
            recipientMaterial: try Manager.Key().retrieveIdentity(),
            quantumMaterial: nil,
            version: .v4
        )
        #expect(bundle.secrecy.mode == .forwardSecretNoPQ)

        let senderEphemeral = try P256.KeyAgreement.PublicKey(x963Representation: bundle.secrecy.ephemeralPublicKey)
        let sessionKey = try #require(self.crypto.deriveSessionKey(
            sharedSecret: try prekeyKey.sharedSecretFromKeyAgreement(with: senderEphemeral),
            ownPublicKey: prekeyPub,
            recipientMaterial: bundle.secrecy.ephemeralPublicKey
        ))

        #expect(try self.crypto.open(bundle, using: sessionKey) == message)
    }
}

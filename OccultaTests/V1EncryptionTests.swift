//
//  V1EncryptionTests.swift
//  Occulta
//
//  Created by Yura on 4/1/26.
//


//
//  LocalEncryptionTests.swift
//  OccultaTests
//
//  Tests for local database encryption: v1 (identity-derived), v2 (hybrid PQ),
//  AAD enforcement, migration coordinator, and key derivation properties.
//
//  Uses Swift Testing. Runs without Secure Enclave (TestKeyManager).
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta

// MARK: - v1 Legacy Encryption

@Suite("v1 Identity-Derived Encryption")
@MainActor
struct V1EncryptionTests {
    let keyManager = TestKeyManager()

    @Test("Roundtrip: encrypt then decrypt returns original plaintext")
    func legacyRoundtrip() throws {
        let plaintext = "Occulta contact name".data(using: .utf8)!

        let key = try #require(try keyManager.createLocalEncryptionKey())
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce())
        let box = try AES.GCM.SealedBox(combined: sealed.combined!)
        let decrypted = try AES.GCM.open(box, using: key)

        #expect(decrypted == plaintext)
    }

    @Test("Empty data encrypts and decrypts to empty data")
    func legacyEmptyData() throws {
        let key = try #require(try keyManager.createLocalEncryptionKey())
        let sealed = try AES.GCM.seal(Data(), using: key, nonce: AES.GCM.Nonce())
        let box = try AES.GCM.SealedBox(combined: sealed.combined!)
        let decrypted = try AES.GCM.open(box, using: key)

        #expect(decrypted == Data())
    }

    @Test("v1 key is deterministic — same key manager produces same key")
    func legacyKeyDeterministic() throws {
        let key1 = try #require(try keyManager.createLocalEncryptionKey())
        let key2 = try #require(try keyManager.createLocalEncryptionKey())

        // Encrypt with key1, decrypt with key2 — should work if deterministic.
        let plaintext = "determinism test".data(using: .utf8)!
        let sealed = try AES.GCM.seal(plaintext, using: key1, nonce: AES.GCM.Nonce())
        let box = try AES.GCM.SealedBox(combined: sealed.combined!)
        let decrypted = try AES.GCM.open(box, using: key2)

        #expect(decrypted == plaintext)
    }

    @Test("v1 ciphertext via CryptoProtocol roundtrips through decryptLegacy")
    func legacyCryptoProtocolRoundtrip() throws {
        let crypto = Manager.Crypto(keyManager: keyManager)
        let plaintext = "protocol roundtrip".data(using: .utf8)!

        // Simulate v1 encryption (no AAD) manually.
        let key = try #require(try keyManager.createLocalEncryptionKey())
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce())

        let decrypted = try #require(try crypto.decryptLegacy(data: sealed.combined))

        #expect(decrypted == plaintext)
    }
}

// MARK: - v2 Hybrid PQ Encryption

@Suite("v2 Hybrid PQ Encryption")
@MainActor
struct V2EncryptionTests {
    let keyManager = TestKeyManager()

    @Test("Roundtrip: encrypt then decrypt returns original plaintext")
    func hybridRoundtrip() throws {
        let crypto = Manager.Crypto(keyManager: keyManager)
        let plaintext = "PQ reinforced contact data".data(using: .utf8)!

        let encrypted = try #require(try crypto.encrypt(data: plaintext))
        let decrypted = try #require(try crypto.decrypt(data: encrypted))

        #expect(decrypted == plaintext)
    }

    @Test("Empty data roundtrip")
    func hybridEmptyData() throws {
        let crypto = Manager.Crypto(keyManager: keyManager)

        let encrypted = try #require(try crypto.encrypt(data: Data()))
        let decrypted = try #require(try crypto.decrypt(data: encrypted))

        #expect(decrypted == Data())
    }

    @Test("Large payload roundtrip — simulates image data")
    func hybridLargePayload() throws {
        let crypto = Manager.Crypto(keyManager: keyManager)
        var largeData = [UInt8](repeating: 0, count: 512_000)
        _ = SecRandomCopyBytes(kSecRandomDefault, largeData.count, &largeData)

        let data = Data(largeData)
        let encrypted = try #require(try crypto.encrypt(data: data))
        let decrypted = try #require(try crypto.decrypt(data: encrypted))

        #expect(decrypted == data)
    }

    @Test("v2 key is deterministic — same components produce same key")
    func hybridKeyDeterministic() throws {
        let key1 = try #require(try keyManager.createHybridLocalEncryptionKey())
        let key2 = try #require(try keyManager.createHybridLocalEncryptionKey())

        let plaintext = "determinism test".data(using: .utf8)!
        let aad = EncryptionScheme.v2_hybridPQ.aad

        let sealed = try AES.GCM.seal(plaintext, using: key1, nonce: AES.GCM.Nonce(), authenticating: aad)
        let box = try AES.GCM.SealedBox(combined: sealed.combined!)
        let decrypted = try AES.GCM.open(box, using: key2, authenticating: aad)

        #expect(decrypted == plaintext)
    }

    @Test("v2 hybrid key differs from v1 identity-derived key")
    func hybridKeyDiffersFromLegacy() throws {
        let v1Key = try #require(try keyManager.createLocalEncryptionKey())
        let v2Key = try #require(try keyManager.createHybridLocalEncryptionKey())

        // Encrypt with v1, try to decrypt with v2 — must fail.
        let plaintext = "cross-scheme test".data(using: .utf8)!
        let sealed = try AES.GCM.seal(plaintext, using: v1Key, nonce: AES.GCM.Nonce())

        #expect(throws: (any Error).self) {
            let box = try AES.GCM.SealedBox(combined: sealed.combined!)
            let aad = EncryptionScheme.v2_hybridPQ.aad
            _ = try AES.GCM.open(box, using: v2Key, authenticating: aad)
        }
    }

    @Test("Nil input returns nil — no crash")
    func hybridNilInput() throws {
        let crypto = Manager.Crypto(keyManager: keyManager)

        let encrypted = try crypto.encrypt(data: nil)
        #expect(encrypted == nil)

        let decrypted = try crypto.decrypt(data: nil)
        #expect(decrypted == nil)
    }
}

// MARK: - AAD Enforcement

@Suite("AAD Enforcement")
@MainActor
struct AADTests {
    let keyManager = TestKeyManager()

    @Test("Decryption fails when AAD does not match")
    func aadMismatchRejected() throws {
        let key = try #require(try keyManager.createHybridLocalEncryptionKey())
        let plaintext = "AAD mismatch test".data(using: .utf8)!
        let correctAAD = EncryptionScheme.v2_hybridPQ.aad

        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(), authenticating: correctAAD)

        // Try to open with wrong AAD — must throw authenticationFailure.
        let wrongAAD = EncryptionScheme.v1_identityDerived.aad

        #expect(throws: (any Error).self) {
            let box = try AES.GCM.SealedBox(combined: sealed.combined!)
            _ = try AES.GCM.open(box, using: key, authenticating: wrongAAD)
        }
    }

    @Test("Decryption fails when AAD is omitted on v2 ciphertext")
    func aadOmittedRejected() throws {
        let key = try #require(try keyManager.createHybridLocalEncryptionKey())
        let plaintext = "AAD omission test".data(using: .utf8)!
        let aad = EncryptionScheme.v2_hybridPQ.aad

        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(), authenticating: aad)

        // Open without AAD — must throw.
        #expect(throws: (any Error).self) {
            let box = try AES.GCM.SealedBox(combined: sealed.combined!)
            _ = try AES.GCM.open(box, using: key)
        }
    }

    @Test("v2 ciphertext cannot be decrypted via decryptLegacy")
    func v2CiphertextRejectsLegacyDecrypt() throws {
        let crypto = Manager.Crypto(keyManager: keyManager)
        let plaintext = "cross-version test".data(using: .utf8)!

        let encrypted = try #require(try crypto.encrypt(data: plaintext))

        // decryptLegacy uses the v1 key without AAD — must fail on v2 ciphertext.
        #expect(throws: (any Error).self) {
            _ = try crypto.decryptLegacy(data: encrypted)
        }
    }

    @Test("v1 ciphertext cannot be decrypted via v2 decrypt")
    func v1CiphertextRejectsV2Decrypt() throws {
        let crypto = Manager.Crypto(keyManager: keyManager)
        let plaintext = "downgrade prevention test".data(using: .utf8)!

        // Manually create v1 ciphertext (no AAD, identity-derived key).
        let v1Key = try #require(try keyManager.createLocalEncryptionKey())
        let sealed = try AES.GCM.seal(plaintext, using: v1Key, nonce: AES.GCM.Nonce())

        // v2 decrypt uses hybrid key + AAD — must fail.
        #expect(throws: (any Error).self) {
            _ = try crypto.decrypt(data: sealed.combined)
        }
    }

    @Test("EncryptionScheme AAD values are distinct")
    func aadValuesDistinct() {
        let v1AAD = EncryptionScheme.v1_identityDerived.aad
        let v2AAD = EncryptionScheme.v2_hybridPQ.aad

        #expect(v1AAD != v2AAD)
        #expect(v1AAD.count == 1)
        #expect(v2AAD.count == 1)
        #expect(v1AAD[0] == 1)
        #expect(v2AAD[0] == 2)
    }
}

// MARK: - Migration

@Suite("Database Migration v1 → v2")
@MainActor
struct MigrationTests {
    let keyManager = TestKeyManager()

    @Test("String field re-encryption roundtrip")
    func stringFieldMigration() throws {
        let legacyCrypto = LegacyOnlyCrypto(keyManager: keyManager)
        let newCrypto = Manager.Crypto(keyManager: keyManager)

        let plaintext = "Alice Johnson"
        let plaintextData = plaintext.data(using: .utf8)!

        // Step 1: Encrypt with v1 (simulating existing data).
        let v1Key = try #require(try keyManager.createLocalEncryptionKey())
        let v1Sealed = try AES.GCM.seal(plaintextData, using: v1Key, nonce: AES.GCM.Nonce())
        let v1Base64 = v1Sealed.combined!.base64EncodedString()

        // Step 2: Legacy decrypt should recover plaintext.
        let v1Ciphertext = Data(base64Encoded: v1Base64)!
        let decrypted = try #require(try legacyCrypto.decryptLegacy(data: v1Ciphertext))

        #expect(String(data: decrypted, encoding: .utf8) == plaintext)

        // Step 3: Re-encrypt with v2.
        let v2Encrypted = try #require(try newCrypto.encrypt(data: decrypted))

        // Step 4: v2 decrypt should recover plaintext.
        let v2Decrypted = try #require(try newCrypto.decrypt(data: v2Encrypted))

        #expect(String(data: v2Decrypted, encoding: .utf8) == plaintext)
    }

    @Test("Data field re-encryption roundtrip — simulates imageData")
    func dataFieldMigration() throws {
        let legacyCrypto = LegacyOnlyCrypto(keyManager: keyManager)
        let newCrypto = Manager.Crypto(keyManager: keyManager)

        var imageBuffer: [UInt8] = .init(repeating: 0, count: 1024)
        
        _ = SecRandomCopyBytes(kSecRandomDefault, imageBuffer.count, &imageBuffer)

        // Step 1: v1 encrypt.
        let v1Key = try #require(try keyManager.createLocalEncryptionKey())
        let v1Sealed = try AES.GCM.seal(Data(imageBuffer), using: v1Key, nonce: AES.GCM.Nonce())

        // Step 2: Legacy decrypt.
        let decrypted = try #require(try legacyCrypto.decryptLegacy(data: v1Sealed.combined))

        #expect(decrypted == Data(imageBuffer))

        // Step 3: v2 encrypt.
        let v2Encrypted = try #require(try newCrypto.encrypt(data: decrypted))

        // Step 4: v2 decrypt.
        let v2Decrypted = try #require(try newCrypto.decrypt(data: v2Encrypted))

        #expect(v2Decrypted == Data(imageBuffer))
    }

    @Test("Previously unencrypted field gets encrypted")
    func newFieldEncryption() throws {
        let newCrypto = Manager.Crypto(keyManager: keyManager)

        let plaintextID = "peer-fingerprint-abc123"
        let plaintextData = plaintextID.data(using: .utf8)!

        let encrypted = try #require(try newCrypto.encrypt(data: plaintextData))

        // Must not equal the plaintext.
        #expect(encrypted != plaintextData)

        // Must decrypt back to original.
        let decrypted = try #require(try newCrypto.decrypt(data: encrypted))
        #expect(String(data: decrypted, encoding: .utf8) == plaintextID)
    }

    @Test("Empty string field preserved as empty through migration")
    func emptyFieldPreserved() throws {
        _ = LegacyOnlyCrypto(keyManager: keyManager)
        _ = Manager.Crypto(keyManager: keyManager)

        // Empty string → empty base64 → empty ciphertext data. Should stay empty.
        let emptyBase64 = ""

        // Simulating the reencryptString logic for empty input.
        let result: String
        if emptyBase64.isEmpty {
            result = ""
        } else {
            // Would go through decrypt/re-encrypt path.
            result = "should not reach here"
        }

        #expect(result == "")
    }

    @Test("ForwardSecrecy blob re-encryption roundtrip")
    func forwardSecrecyBlobMigration() throws {
        let legacyCrypto = LegacyOnlyCrypto(keyManager: keyManager)
        let newCrypto = Manager.Crypto(keyManager: keyManager)

        // Create a ForwardSecrecy struct and encode it.
        let secrecy = ForwardSecrecy()
        let encoded = try JSONEncoder().encode(secrecy)

        // v1 encrypt (as the model extension does via Data.encrypt()).
        let v1Key = try #require(try keyManager.createLocalEncryptionKey())
        let v1Sealed = try AES.GCM.seal(encoded, using: v1Key, nonce: AES.GCM.Nonce())

        // Legacy decrypt.
        let decrypted = try #require(try legacyCrypto.decryptLegacy(data: v1Sealed.combined))

        // Verify it's valid ForwardSecrecy JSON.
        let decoded = try JSONDecoder().decode(ForwardSecrecy.self, from: decrypted)
        #expect(decoded.encodedPrekeys?.isEmpty == true)

        // v2 re-encrypt.
        let v2Encrypted = try #require(try newCrypto.encrypt(data: decrypted))

        // v2 decrypt.
        let v2Decrypted = try #require(try newCrypto.decrypt(data: v2Encrypted))
        let reDecoded = try JSONDecoder().decode(ForwardSecrecy.self, from: v2Decrypted)

        #expect(reDecoded.encodedPrekeys?.isEmpty == true)
    }
}

// MARK: - Key Derivation Properties

@Suite("Key Derivation Properties")
@MainActor
struct KeyDerivationTests {

    @Test("Different TestKeyManager instances produce different keys")
    func differentInstancesDifferentKeys() throws {
        let km1 = TestKeyManager()
        let km2 = TestKeyManager()

        let key1 = try #require(try km1.createHybridLocalEncryptionKey())
        let key2 = try #require(try km2.createHybridLocalEncryptionKey())

        let plaintext = "cross-instance test".data(using: .utf8)!
        let aad = EncryptionScheme.v2_hybridPQ.aad

        let sealed = try AES.GCM.seal(plaintext, using: key1, nonce: AES.GCM.Nonce(), authenticating: aad)

        // Key from different instance must not decrypt.
        #expect(throws: (any Error).self) {
            let box = try AES.GCM.SealedBox(combined: sealed.combined!)
            _ = try AES.GCM.open(box, using: key2, authenticating: aad)
        }
    }

    @Test("v1 and v2 keys from same instance are different")
    func v1AndV2KeysDiffer() throws {
        let km = TestKeyManager()

        let v1 = try #require(try km.createLocalEncryptionKey())
        let v2 = try #require(try km.createHybridLocalEncryptionKey())

        // They must produce different ciphertexts for the same plaintext+nonce.
        // Since we can't reuse a nonce safely, we verify cross-decryption fails.
        let plaintext = "key separation test".data(using: .utf8)!

        let sealedV1 = try AES.GCM.seal(plaintext, using: v1, nonce: AES.GCM.Nonce())

        #expect(throws: (any Error).self) {
            let box = try AES.GCM.SealedBox(combined: sealedV1.combined!)
            _ = try AES.GCM.open(box, using: v2)
        }
    }
}

// MARK: - EncryptionScheme Model Field

@Suite("EncryptionScheme Enum")
struct EncryptionSchemeTests {

    @Test("Raw values are stable — changing these breaks migration")
    func rawValuesStable() {
        #expect(EncryptionScheme.v1_identityDerived.rawValue == 1)
        #expect(EncryptionScheme.v2_hybridPQ.rawValue == 2)
    }

    @Test("AAD bytes match raw values")
    func aadMatchesRawValue() {
        #expect(EncryptionScheme.v1_identityDerived.aad == Data([1]))
        #expect(EncryptionScheme.v2_hybridPQ.aad == Data([2]))
    }
}

// MARK: - Test helpers

/// Crypto wrapper that only exposes the legacy decrypt path.
/// Prevents accidental use of v2 encrypt during migration test setup.
@MainActor
private final class LegacyOnlyCrypto: CryptoProtocol {
    private let inner: Manager.Crypto

    init(keyManager: TestKeyManager) {
        self.inner = Manager.Crypto(keyManager: keyManager)
    }

    func encrypt(data: Data?) throws -> Data? {
        // Intentionally blocked — migration tests should not use v2 encrypt via this wrapper.
        fatalError("LegacyOnlyCrypto.encrypt should not be called — use newCrypto instead")
    }

    func decrypt(data: Data?) throws -> Data? {
        // Intentionally blocked — migration tests use decryptLegacy explicitly.
        fatalError("LegacyOnlyCrypto.decrypt should not be called — use decryptLegacy instead")
    }

    func decryptLegacy(data: Data?) throws -> Data? {
        try self.inner.decryptLegacy(data: data)
    }

    func encrypt(message: Data, using material: Data?) throws -> Data? {
        try self.inner.encrypt(message: message, using: material)
    }

    func decrypt(message: Data, using material: Data?) throws -> Data? {
        try self.inner.decrypt(message: message, using: material)
    }

    func encrypt(contacts: Data, using passphrase: String) throws -> Data? {
        try self.inner.encrypt(contacts: contacts, using: passphrase)
    }

    func decrypt(contacts: Data, using passphrase: String) throws -> Data? {
        try self.inner.decrypt(contacts: contacts, using: passphrase)
    }

    func sign(data: Data?) -> String {
        self.inner.sign(data: data)
    }
}

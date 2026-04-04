//
//  PostQuantumTests.swift
//  OccultaTests
//
//  Tests for the hybrid PQ key exchange implementation.
//  All tests use in-memory ML-KEM and PQTestKeyPair (no SE, no @MainActor).
//  Requires iOS 26+ for ML-KEM tests — skipped on earlier versions.
//

import XCTest
import CryptoKit
@testable import Occulta

// MARK: - 1. PQProvider Tests

@available(iOS 26, *)
final class PQProviderTests: XCTestCase {

    let provider: PQProvider = PQProviderFactory.createForTesting()!

    // MARK: 1.1 Key generation

    func testKeyPairGeneration() {
        let keyPair = self.provider.generateKeyPair()

        XCTAssertNotNil(keyPair)
        XCTAssertEqual(keyPair?.publicKeyData.count, 1568, "ML-KEM-1024 public key should be 1568 bytes")
        XCTAssertNotNil(keyPair?.privateKeyHandle)
    }

    func testTwoKeyPairsAreDistinct() {
        let keyPair1 = self.provider.generateKeyPair()
        let keyPair2 = self.provider.generateKeyPair()

        XCTAssertNotNil(keyPair1)
        XCTAssertNotNil(keyPair2)
        XCTAssertNotEqual(keyPair1?.publicKeyData, keyPair2?.publicKeyData)
    }

    // MARK: 1.2 Encapsulation

    func testEncapsulationProducesValidOutput() {
        guard let keyPair = self.provider.generateKeyPair() else {
            return XCTFail("Key pair generation failed")
        }
        let result = self.provider.encapsulate(peerPublicKeyData: keyPair.publicKeyData)

        XCTAssertNotNil(result)
        XCTAssertEqual(result?.sharedSecret.count, 32, "ML-KEM shared secret should be 32 bytes")
        XCTAssertEqual(result?.ciphertext.count, 1568, "ML-KEM-1024 ciphertext should be 1568 bytes")
    }

    func testEncapsulationWithMalformedKeyReturnsNil() {
        let malformedKey = Data(repeating: 0xFF, count: 100)

        XCTAssertNil(self.provider.encapsulate(peerPublicKeyData: malformedKey))
    }

    func testEncapsulationWithEmptyKeyReturnsNil() {
        XCTAssertNil(self.provider.encapsulate(peerPublicKeyData: Data()))
    }

    func testTwoEncapsulationsProduceDifferentSecrets() {
        guard let keyPair = self.provider.generateKeyPair() else {
            return XCTFail("Key pair generation failed")
        }

        let result1 = self.provider.encapsulate(peerPublicKeyData: keyPair.publicKeyData)
        let result2 = self.provider.encapsulate(peerPublicKeyData: keyPair.publicKeyData)

        XCTAssertNotNil(result1)
        XCTAssertNotNil(result2)
        XCTAssertNotEqual(result1?.sharedSecret, result2?.sharedSecret, "Each encapsulation uses fresh randomness")
        XCTAssertNotEqual(result1?.ciphertext, result2?.ciphertext)
    }

    // MARK: 1.3 Decapsulation

    func testDecapsulationRecoversSharedSecret() {
        guard let keyPair = self.provider.generateKeyPair() else {
            return XCTFail("Key pair generation failed")
        }
        guard let encapsulationResult = self.provider.encapsulate(peerPublicKeyData: keyPair.publicKeyData) else {
            return XCTFail("Encapsulation failed")
        }

        let recoveredSecret = self.provider.decapsulate(
            ciphertext: encapsulationResult.ciphertext,
            privateKeyHandle: keyPair.privateKeyHandle
        )

        XCTAssertEqual(recoveredSecret, encapsulationResult.sharedSecret)
    }

    func testDecapsulationWithWrongKeyProducesDifferentSecret() {
        guard let keyPairA = self.provider.generateKeyPair(),
              let keyPairB = self.provider.generateKeyPair() else {
            return XCTFail("Key pair generation failed")
        }
        guard let encapsulationResult = self.provider.encapsulate(peerPublicKeyData: keyPairA.publicKeyData) else {
            return XCTFail("Encapsulation failed")
        }

        // ML-KEM decapsulation with the wrong key produces a synthetic secret (IND-CCA2),
        // not nil. The synthetic secret will differ from the real one.
        let wrongSecret = self.provider.decapsulate(
            ciphertext: encapsulationResult.ciphertext,
            privateKeyHandle: keyPairB.privateKeyHandle
        )

        XCTAssertNotEqual(wrongSecret, encapsulationResult.sharedSecret)
    }

    func testDecapsulationWithWrongHandleTypeReturnsNil() {
        guard let keyPair = self.provider.generateKeyPair() else {
            return XCTFail("Key pair generation failed")
        }
        guard let encapsulationResult = self.provider.encapsulate(peerPublicKeyData: keyPair.publicKeyData) else {
            return XCTFail("Encapsulation failed")
        }

        let result = self.provider.decapsulate(
            ciphertext: encapsulationResult.ciphertext,
            privateKeyHandle: "not a key" as Any
        )

        XCTAssertNil(result)
    }

    func testDecapsulationIsDeterministic() {
        guard let keyPair = self.provider.generateKeyPair() else {
            return XCTFail("Key pair generation failed")
        }
        guard let encapsulationResult = self.provider.encapsulate(peerPublicKeyData: keyPair.publicKeyData) else {
            return XCTFail("Encapsulation failed")
        }

        let secret1 = self.provider.decapsulate(ciphertext: encapsulationResult.ciphertext, privateKeyHandle: keyPair.privateKeyHandle)
        let secret2 = self.provider.decapsulate(ciphertext: encapsulationResult.ciphertext, privateKeyHandle: keyPair.privateKeyHandle)

        XCTAssertEqual(secret1, secret2, "Same ciphertext + same key = same shared secret")
    }

    // MARK: 1.4 Mutual encapsulation roundtrip (Option A)

    func testMutualEncapsulationRoundtrip() {
        guard let aliceKeyPair = self.provider.generateKeyPair(),
              let bobKeyPair = self.provider.generateKeyPair() else {
            return XCTFail("Key pair generation failed")
        }

        guard let aliceEncapsulation = self.provider.encapsulate(peerPublicKeyData: bobKeyPair.publicKeyData),
              let bobEncapsulation = self.provider.encapsulate(peerPublicKeyData: aliceKeyPair.publicKeyData) else {
            return XCTFail("Encapsulation failed")
        }

        let bobRecoveredSecret = self.provider.decapsulate(
            ciphertext: aliceEncapsulation.ciphertext,
            privateKeyHandle: bobKeyPair.privateKeyHandle
        )
        let aliceRecoveredSecret = self.provider.decapsulate(
            ciphertext: bobEncapsulation.ciphertext,
            privateKeyHandle: aliceKeyPair.privateKeyHandle
        )

        XCTAssertEqual(aliceEncapsulation.sharedSecret, bobRecoveredSecret)
        XCTAssertEqual(bobEncapsulation.sharedSecret, aliceRecoveredSecret)
    }
}

// MARK: - 2. PQProviderFactory Tests



// MARK: - 3. QuantumKeyMaterial Tests

final class QuantumKeyMaterialTests: XCTestCase {

    func testIsValidWithCorrectSizes() {
        let material = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 32),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(repeating: 0xCC, count: 1568),
            peerCiphertext: Data(repeating: 0xDD, count: 1568)
        )

        XCTAssertTrue(material.isValid)
    }

    func testIsValidWithWrongSecretSize() {
        let material = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 16),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(repeating: 0xCC, count: 1568),
            peerCiphertext: Data(repeating: 0xDD, count: 1568)
        )

        XCTAssertFalse(material.isValid)
    }

    func testCodableRoundtrip() throws {
        let original = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 32),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(repeating: 0xCC, count: 1568),
            peerCiphertext: Data(repeating: 0xDD, count: 1568)
        )

        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(QuantumKeyMaterial.self, from: encoded)

        XCTAssertEqual(decoded.encapsulatedSecret, original.encapsulatedSecret)
        XCTAssertEqual(decoded.decapsulatedSecret, original.decapsulatedSecret)
        XCTAssertEqual(decoded.ourCiphertext, original.ourCiphertext)
        XCTAssertEqual(decoded.peerCiphertext, original.peerCiphertext)
    }
}

// MARK: - 4. Hybrid Key Derivation Tests

@available(iOS 26, *)
final class HybridKeyDerivationTests: XCTestCase {

    let alice = PQTestKeyPair()
    let bob = PQTestKeyPair()
    let provider: PQProvider = PQProviderFactory.createForTesting()!

    // MARK: 4.1 Both sides derive identical hybrid shared secret

    func testBothSidesDeriveIdenticalHybridSharedSecret() {
        guard let aliceKeyPair = self.provider.generateKeyPair(),
              let bobKeyPair = self.provider.generateKeyPair() else {
            return XCTFail("ML-KEM key pair generation failed")
        }

        guard let aliceEncapsulation = self.provider.encapsulate(peerPublicKeyData: bobKeyPair.publicKeyData),
              let bobEncapsulation = self.provider.encapsulate(peerPublicKeyData: aliceKeyPair.publicKeyData) else {
            return XCTFail("ML-KEM encapsulation failed")
        }

        guard let bobDecapsulatedSecret = self.provider.decapsulate(ciphertext: aliceEncapsulation.ciphertext, privateKeyHandle: bobKeyPair.privateKeyHandle),
              let aliceDecapsulatedSecret = self.provider.decapsulate(ciphertext: bobEncapsulation.ciphertext, privateKeyHandle: aliceKeyPair.privateKeyHandle) else {
            return XCTFail("ML-KEM decapsulation failed")
        }

        let aliceQuantum = QuantumKeyMaterial(
            encapsulatedSecret: aliceEncapsulation.sharedSecret,
            decapsulatedSecret: aliceDecapsulatedSecret,
            ourCiphertext: aliceEncapsulation.ciphertext,
            peerCiphertext: bobEncapsulation.ciphertext
        )

        let bobQuantum = QuantumKeyMaterial(
            encapsulatedSecret: bobEncapsulation.sharedSecret,
            decapsulatedSecret: bobDecapsulatedSecret,
            ourCiphertext: bobEncapsulation.ciphertext,
            peerCiphertext: aliceEncapsulation.ciphertext
        )

        let aliceSessionKey = self.alice.createHybridSharedSecret(
            peerPublicKeyData: self.bob.publicKeyData,
            quantumMaterial: aliceQuantum
        )

        let bobSessionKey = self.bob.createHybridSharedSecret(
            peerPublicKeyData: self.alice.publicKeyData,
            quantumMaterial: bobQuantum
        )

        XCTAssertNotNil(aliceSessionKey, "Alice's hybrid derivation should not return nil")
        XCTAssertNotNil(bobSessionKey, "Bob's hybrid derivation should not return nil")

        guard let aliceKeyData = aliceSessionKey?.withUnsafeBytes({ Data($0) }),
              let bobKeyData = bobSessionKey?.withUnsafeBytes({ Data($0) }) else {
            return XCTFail("Session key extraction failed")
        }

        XCTAssertEqual(aliceKeyData, bobKeyData, "Both sides must derive the same hybrid shared secret")
    }

    // MARK: 4.2 Hybrid key differs from classical key

    func testHybridKeyDiffersFromClassicalKey() {
        let classicalKey = self.alice.createClassicalSharedSecret(peerPublicKeyData: self.bob.publicKeyData)

        let quantumMaterial = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 32),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(),
            peerCiphertext: Data()
        )

        let hybridKey = self.alice.createHybridSharedSecret(
            peerPublicKeyData: self.bob.publicKeyData,
            quantumMaterial: quantumMaterial
        )

        XCTAssertNotNil(classicalKey)
        XCTAssertNotNil(hybridKey)

        guard let classicalData = classicalKey?.withUnsafeBytes({ Data($0) }),
              let hybridData = hybridKey?.withUnsafeBytes({ Data($0) }) else {
            return XCTFail("Key extraction failed")
        }

        XCTAssertNotEqual(classicalData, hybridData, "Hybrid derivation must produce a different key than classical")
    }

    // MARK: 4.3 Invalid quantum material

    func testHybridWithWrongSizeSecretReturnsNil() {
        let invalidMaterial = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 16),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(),
            peerCiphertext: Data()
        )

        let key = self.alice.createHybridSharedSecret(
            peerPublicKeyData: self.bob.publicKeyData,
            quantumMaterial: invalidMaterial
        )

        XCTAssertNil(key)
    }

    func testHybridWithWrongP256LengthReturnsNil() {
        let quantumMaterial = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 32),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(),
            peerCiphertext: Data()
        )

        let key = self.alice.createHybridSharedSecret(
            peerPublicKeyData: Data(repeating: 0x04, count: 33),
            quantumMaterial: quantumMaterial
        )

        XCTAssertNil(key)
    }

    // MARK: 4.4 Secret ordering is commutative

    func testSecretOrderDoesNotAffectOutput() {
        let secretA = Data(repeating: 0xAA, count: 32)
        let secretB = Data(repeating: 0xBB, count: 32)

        let material1 = QuantumKeyMaterial(
            encapsulatedSecret: secretA, decapsulatedSecret: secretB,
            ourCiphertext: Data(), peerCiphertext: Data()
        )
        let material2 = QuantumKeyMaterial(
            encapsulatedSecret: secretB, decapsulatedSecret: secretA,
            ourCiphertext: Data(), peerCiphertext: Data()
        )

        let key1 = self.alice.createHybridSharedSecret(peerPublicKeyData: self.bob.publicKeyData, quantumMaterial: material1)
        let key2 = self.alice.createHybridSharedSecret(peerPublicKeyData: self.bob.publicKeyData, quantumMaterial: material2)

        guard let data1 = key1?.withUnsafeBytes({ Data($0) }),
              let data2 = key2?.withUnsafeBytes({ Data($0) }) else {
            return XCTFail("Key extraction failed")
        }

        XCTAssertEqual(data1, data2, "Lexicographic sorting of secrets must make order irrelevant")
    }
}

// MARK: - 5. Diceware Key Derivation Tests

@available(iOS 26, *)
final class DicewareKeyDerivationTests: XCTestCase {

    let alice = PQTestKeyPair()
    let bob = PQTestKeyPair()
    let provider: PQProvider = PQProviderFactory.createForTesting()!

    func testBothSidesDeriveIdenticalDicewareKey() {
        guard let aliceKeyPair = self.provider.generateKeyPair(),
              let bobKeyPair = self.provider.generateKeyPair() else {
            return XCTFail("ML-KEM key pair generation failed")
        }

        guard let aliceEncapsulation = self.provider.encapsulate(peerPublicKeyData: bobKeyPair.publicKeyData),
              let bobEncapsulation = self.provider.encapsulate(peerPublicKeyData: aliceKeyPair.publicKeyData) else {
            return XCTFail("ML-KEM encapsulation failed")
        }

        guard let bobDecapsulatedSecret = self.provider.decapsulate(ciphertext: aliceEncapsulation.ciphertext, privateKeyHandle: bobKeyPair.privateKeyHandle),
              let aliceDecapsulatedSecret = self.provider.decapsulate(ciphertext: bobEncapsulation.ciphertext, privateKeyHandle: aliceKeyPair.privateKeyHandle) else {
            return XCTFail("ML-KEM decapsulation failed")
        }

        let aliceNonce = Data(repeating: 0x01, count: 16)
        let bobNonce = Data(repeating: 0x02, count: 16)

        let aliceQuantum = QuantumKeyMaterial(
            encapsulatedSecret: aliceEncapsulation.sharedSecret,
            decapsulatedSecret: aliceDecapsulatedSecret,
            ourCiphertext: aliceEncapsulation.ciphertext,
            peerCiphertext: bobEncapsulation.ciphertext
        )

        let bobQuantum = QuantumKeyMaterial(
            encapsulatedSecret: bobEncapsulation.sharedSecret,
            decapsulatedSecret: bobDecapsulatedSecret,
            ourCiphertext: bobEncapsulation.ciphertext,
            peerCiphertext: aliceEncapsulation.ciphertext
        )

        let aliceDicewareKey = self.alice.createDicewareKey(
            peerPublicKeyData: self.bob.publicKeyData,
            quantumMaterial: aliceQuantum,
            ourNonce: aliceNonce,
            peerNonce: bobNonce
        )

        let bobDicewareKey = self.bob.createDicewareKey(
            peerPublicKeyData: self.alice.publicKeyData,
            quantumMaterial: bobQuantum,
            ourNonce: bobNonce,
            peerNonce: aliceNonce
        )

        XCTAssertNotNil(aliceDicewareKey)
        XCTAssertNotNil(bobDicewareKey)

        guard let aliceData = aliceDicewareKey?.withUnsafeBytes({ Data($0) }),
              let bobData = bobDicewareKey?.withUnsafeBytes({ Data($0) }) else {
            return XCTFail("Diceware key extraction failed")
        }

        XCTAssertEqual(aliceData, bobData, "Both sides must derive the same Diceware words")
    }

    func testDicewareKeyDiffersFromTransportKey() {
        let quantumMaterial = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 32),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(), peerCiphertext: Data()
        )

        let transportKey = self.alice.createHybridSharedSecret(
            peerPublicKeyData: self.bob.publicKeyData,
            quantumMaterial: quantumMaterial
        )

        let dicewareKey = self.alice.createDicewareKey(
            peerPublicKeyData: self.bob.publicKeyData,
            quantumMaterial: quantumMaterial,
            ourNonce: Data(repeating: 0x01, count: 16),
            peerNonce: Data(repeating: 0x02, count: 16)
        )

        guard let transportData = transportKey?.withUnsafeBytes({ Data($0) }),
              let dicewareData = dicewareKey?.withUnsafeBytes({ Data($0) }) else {
            return XCTFail("Key extraction failed")
        }

        XCTAssertNotEqual(transportData, dicewareData, "Different HKDF info must produce different keys")
    }

    func testDifferentNoncesProduceDifferentDicewareKeys() {
        let quantumMaterial = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 32),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(), peerCiphertext: Data()
        )

        let key1 = self.alice.createDicewareKey(
            peerPublicKeyData: self.bob.publicKeyData,
            quantumMaterial: quantumMaterial,
            ourNonce: Data(repeating: 0x01, count: 16),
            peerNonce: Data(repeating: 0x02, count: 16)
        )

        let key2 = self.alice.createDicewareKey(
            peerPublicKeyData: self.bob.publicKeyData,
            quantumMaterial: quantumMaterial,
            ourNonce: Data(repeating: 0x03, count: 16),
            peerNonce: Data(repeating: 0x04, count: 16)
        )

        guard let data1 = key1?.withUnsafeBytes({ Data($0) }),
              let data2 = key2?.withUnsafeBytes({ Data($0) }) else {
            return XCTFail("Key extraction failed")
        }

        XCTAssertNotEqual(data1, data2, "Different nonces must produce different Diceware words")
    }

    func testNonceOrderDoesNotAffectDicewareKey() {
        let quantumMaterial = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 32),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(), peerCiphertext: Data()
        )

        let nonceA = Data(repeating: 0x01, count: 16)
        let nonceB = Data(repeating: 0x02, count: 16)

        let key1 = self.alice.createDicewareKey(
            peerPublicKeyData: self.bob.publicKeyData,
            quantumMaterial: quantumMaterial,
            ourNonce: nonceA, peerNonce: nonceB
        )

        let key2 = self.alice.createDicewareKey(
            peerPublicKeyData: self.bob.publicKeyData,
            quantumMaterial: quantumMaterial,
            ourNonce: nonceB, peerNonce: nonceA
        )

        guard let data1 = key1?.withUnsafeBytes({ Data($0) }),
              let data2 = key2?.withUnsafeBytes({ Data($0) }) else {
            return XCTFail("Key extraction failed")
        }

        XCTAssertEqual(data1, data2, "Nonce sorting must make our/peer order irrelevant")
    }

    func testWrongSizeNonceReturnsNil() {
        let quantumMaterial = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 32),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(), peerCiphertext: Data()
        )

        let key = self.alice.createDicewareKey(
            peerPublicKeyData: self.bob.publicKeyData,
            quantumMaterial: quantumMaterial,
            ourNonce: Data(repeating: 0x01, count: 8),
            peerNonce: Data(repeating: 0x02, count: 16)
        )

        XCTAssertNil(key)
    }
}

// MARK: - 6. Backward Compatibility Tests

@available(iOS 26, *)
final class BackwardCompatibilityTests: XCTestCase {

    func testV1PeerDecodesExchangeWithNewFields() throws {
        let exchange = Exchange(
            id: UUID().uuidString,
            token: Data([0x01, 0x02, 0x03]),
            version: .v1,
            identity: Data(repeating: 0x04, count: 65),
            nonce: Data(repeating: 0xAA, count: 16),
            encapsulationKey: Data(repeating: 0xBB, count: 1568)
        )

        let encoded = try JSONEncoder().encode(exchange)

        // Simulate v1 decoder — only has id, token, version, identity
        struct V1Exchange: Codable {
            let id: String
            let token: Data
            let version: Int8
            let identity: Data?
        }

        let v1Decoded = try JSONDecoder().decode(V1Exchange.self, from: encoded)

        XCTAssertEqual(v1Decoded.version, 1)
        XCTAssertEqual(v1Decoded.identity?.count, 65)
    }

    func testExchangePhaseDetection() {
        let discovery = Exchange(id: "1", token: Data(), nonce: Data(repeating: 0, count: 16))
        XCTAssertTrue(discovery.isDiscovery)
        XCTAssertFalse(discovery.isIdentity)
        XCTAssertFalse(discovery.isCiphertext)

        let identity = Exchange(id: "2", token: Data(), identity: Data(repeating: 0x04, count: 65), encapsulationKey: Data(repeating: 0, count: 1568))
        XCTAssertFalse(identity.isDiscovery)
        XCTAssertTrue(identity.isIdentity)
        XCTAssertFalse(identity.isCiphertext)
        XCTAssertTrue(identity.supportsPQ)

        let classicalIdentity = Exchange(id: "3", token: Data(), identity: Data(repeating: 0x04, count: 65))
        XCTAssertTrue(classicalIdentity.isIdentity)
        XCTAssertFalse(classicalIdentity.supportsPQ)

        let ciphertext = Exchange(id: "4", token: Data(), ciphertext: Data(repeating: 0, count: 1568))
        XCTAssertFalse(ciphertext.isDiscovery)
        XCTAssertFalse(ciphertext.isIdentity)
        XCTAssertTrue(ciphertext.isCiphertext)
    }
}

// MARK: - 7. Encrypt/Decrypt Roundtrip with Hybrid Session Key

@available(iOS 26, *)
final class HybridEncryptDecryptTests: XCTestCase {

    let alice = PQTestKeyPair()
    let bob = PQTestKeyPair()
    let provider: PQProvider = PQProviderFactory.createForTesting()!

    func testEncryptWithHybridKeyDecryptWithSameKey() throws {
        guard let aliceKeyPair = self.provider.generateKeyPair(),
              let bobKeyPair = self.provider.generateKeyPair() else {
            return XCTFail("ML-KEM key pair generation failed")
        }

        guard let aliceEncapsulation = self.provider.encapsulate(peerPublicKeyData: bobKeyPair.publicKeyData),
              let bobEncapsulation = self.provider.encapsulate(peerPublicKeyData: aliceKeyPair.publicKeyData) else {
            return XCTFail("ML-KEM encapsulation failed")
        }

        guard let bobDecapsulatedSecret = self.provider.decapsulate(ciphertext: aliceEncapsulation.ciphertext, privateKeyHandle: bobKeyPair.privateKeyHandle),
              let aliceDecapsulatedSecret = self.provider.decapsulate(ciphertext: bobEncapsulation.ciphertext, privateKeyHandle: aliceKeyPair.privateKeyHandle) else {
            return XCTFail("ML-KEM decapsulation failed")
        }

        let aliceQuantum = QuantumKeyMaterial(
            encapsulatedSecret: aliceEncapsulation.sharedSecret,
            decapsulatedSecret: aliceDecapsulatedSecret,
            ourCiphertext: aliceEncapsulation.ciphertext,
            peerCiphertext: bobEncapsulation.ciphertext
        )

        let bobQuantum = QuantumKeyMaterial(
            encapsulatedSecret: bobEncapsulation.sharedSecret,
            decapsulatedSecret: bobDecapsulatedSecret,
            ourCiphertext: bobEncapsulation.ciphertext,
            peerCiphertext: aliceEncapsulation.ciphertext
        )

        guard let aliceSessionKey = self.alice.createHybridSharedSecret(
            peerPublicKeyData: self.bob.publicKeyData,
            quantumMaterial: aliceQuantum
        ) else {
            return XCTFail("Alice hybrid derivation returned nil")
        }

        guard let bobSessionKey = self.bob.createHybridSharedSecret(
            peerPublicKeyData: self.alice.publicKeyData,
            quantumMaterial: bobQuantum
        ) else {
            return XCTFail("Bob hybrid derivation returned nil")
        }

        let plaintext = "Quantum-resistant message from Alice".data(using: .utf8)!
        let sealed = try AES.GCM.seal(plaintext, using: aliceSessionKey, nonce: AES.GCM.Nonce())

        let box = try AES.GCM.SealedBox(combined: sealed.combined!)
        let decrypted = try AES.GCM.open(box, using: bobSessionKey)

        XCTAssertEqual(decrypted, plaintext)
    }

    func testClassicalKeyCannotDecryptHybridEncryptedData() throws {
        let quantumMaterial = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 32),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(), peerCiphertext: Data()
        )

        guard let hybridKey = self.alice.createHybridSharedSecret(
            peerPublicKeyData: self.bob.publicKeyData,
            quantumMaterial: quantumMaterial
        ) else {
            return XCTFail("Hybrid derivation returned nil")
        }

        let plaintext = "Secret message".data(using: .utf8)!
        let sealed = try AES.GCM.seal(plaintext, using: hybridKey, nonce: AES.GCM.Nonce())

        guard let classicalKey = self.bob.createClassicalSharedSecret(peerPublicKeyData: self.alice.publicKeyData) else {
            return XCTFail("Classical derivation returned nil")
        }

        let box = try AES.GCM.SealedBox(combined: sealed.combined!)

        XCTAssertThrowsError(try AES.GCM.open(box, using: classicalKey))
    }
}

// MARK: - 8. Exchange Nonce Tests

final class ExchangeNonceTests: XCTestCase {

    let keyManager = Manager.Key(testingTag: "test.nonce.\(UUID().uuidString)")

    func testNonceIsCorrectLength() {
        let nonce = self.keyManager.generateExchangeNonce()

        XCTAssertNotNil(nonce)
        XCTAssertEqual(nonce?.count, 16)
    }

    func testTwoNoncesAreDistinct() {
        guard let nonce1 = self.keyManager.generateExchangeNonce(),
              let nonce2 = self.keyManager.generateExchangeNonce() else {
            return XCTFail("Nonce generation failed")
        }

        XCTAssertNotEqual(nonce1, nonce2)
    }
}

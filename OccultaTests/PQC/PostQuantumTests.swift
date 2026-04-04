//
//  PostQuantumTests.swift
//  OccultaTests
//
//  Tests for the hybrid PQ key exchange implementation.
//  All tests use in-memory ML-KEM (no Secure Enclave required).
//  Requires iOS 26+ — skipped on earlier versions.
//

import XCTest
import CryptoKit
@testable import Occulta

// MARK: - 1. PQProvider Tests

@available(iOS 26, *) @MainActor
final class PQProviderTests: XCTestCase {

    private var provider: PQProvider!

    override func setUp() {
        super.setUp()
        self.provider = PQProviderFactory.createForTesting()!
    }

    // MARK: 1.1 Key generation

    func testKeyPairGeneration() {
        let keyPair = self.provider.generateKeyPair()

        XCTAssertNotNil(keyPair)
        XCTAssertEqual(keyPair!.publicKeyData.count, 1568, "ML-KEM-1024 public key should be 1568 bytes")
        XCTAssertNotNil(keyPair!.privateKeyHandle)
    }

    func testTwoKeyPairsAreDistinct() {
        let keyPair1 = self.provider.generateKeyPair()!
        let keyPair2 = self.provider.generateKeyPair()!

        XCTAssertNotEqual(keyPair1.publicKeyData, keyPair2.publicKeyData)
    }

    // MARK: 1.2 Encapsulation

    func testEncapsulationProducesValidOutput() {
        let keyPair = self.provider.generateKeyPair()!
        let result = self.provider.encapsulate(peerPublicKeyData: keyPair.publicKeyData)

        XCTAssertNotNil(result)
        XCTAssertEqual(result!.sharedSecret.count, 32, "ML-KEM shared secret should be 32 bytes")
        XCTAssertEqual(result!.ciphertext.count, 1568, "ML-KEM-1024 ciphertext should be 1568 bytes")
    }

    func testEncapsulationWithMalformedKeyReturnsNil() {
        let malformedKey = Data(repeating: 0xFF, count: 100)
        let result = self.provider.encapsulate(peerPublicKeyData: malformedKey)

        XCTAssertNil(result)
    }

    func testEncapsulationWithEmptyKeyReturnsNil() {
        let result = self.provider.encapsulate(peerPublicKeyData: Data())

        XCTAssertNil(result)
    }

    func testTwoEncapsulationsProduceDifferentSecrets() {
        let keyPair = self.provider.generateKeyPair()!
        let result1 = self.provider.encapsulate(peerPublicKeyData: keyPair.publicKeyData)!
        let result2 = self.provider.encapsulate(peerPublicKeyData: keyPair.publicKeyData)!

        XCTAssertNotEqual(result1.sharedSecret, result2.sharedSecret, "Each encapsulation uses fresh randomness")
        XCTAssertNotEqual(result1.ciphertext, result2.ciphertext)
    }

    // MARK: 1.3 Decapsulation

    func testDecapsulationRecoversSharedSecret() {
        let keyPair = self.provider.generateKeyPair()!
        let encapsulationResult = self.provider.encapsulate(peerPublicKeyData: keyPair.publicKeyData)!

        let recoveredSecret = self.provider.decapsulate(
            ciphertext: encapsulationResult.ciphertext,
            privateKeyHandle: keyPair.privateKeyHandle
        )

        XCTAssertNotNil(recoveredSecret)
        XCTAssertEqual(recoveredSecret, encapsulationResult.sharedSecret)
    }

    func testDecapsulationWithWrongKeyProducesDifferentSecret() {
        let keyPairA = self.provider.generateKeyPair()!
        let keyPairB = self.provider.generateKeyPair()!

        let encapsulationResult = self.provider.encapsulate(peerPublicKeyData: keyPairA.publicKeyData)!

        // ML-KEM decapsulation with the wrong key produces a synthetic secret (IND-CCA2 defense),
        // not nil. The synthetic secret will differ from the real one.
        let wrongSecret = self.provider.decapsulate(
            ciphertext: encapsulationResult.ciphertext,
            privateKeyHandle: keyPairB.privateKeyHandle
        )

        XCTAssertNotEqual(wrongSecret, encapsulationResult.sharedSecret)
    }

    func testDecapsulationWithWrongHandleTypeReturnsNil() {
        let keyPair = self.provider.generateKeyPair()!
        let encapsulationResult = self.provider.encapsulate(peerPublicKeyData: keyPair.publicKeyData)!

        let result = self.provider.decapsulate(
            ciphertext: encapsulationResult.ciphertext,
            privateKeyHandle: "not a key" as Any
        )

        XCTAssertNil(result)
    }

    func testDecapsulationIsDeterministic() {
        let keyPair = self.provider.generateKeyPair()!
        let encapsulationResult = self.provider.encapsulate(peerPublicKeyData: keyPair.publicKeyData)!

        let secret1 = self.provider.decapsulate(ciphertext: encapsulationResult.ciphertext, privateKeyHandle: keyPair.privateKeyHandle)
        let secret2 = self.provider.decapsulate(ciphertext: encapsulationResult.ciphertext, privateKeyHandle: keyPair.privateKeyHandle)

        XCTAssertEqual(secret1, secret2, "Same ciphertext + same key = same shared secret")
    }

    // MARK: 1.4 Full roundtrip (Option A — mutual encapsulation)

    func testMutualEncapsulationRoundtrip() {
        let aliceKeyPair = self.provider.generateKeyPair()!
        let bobKeyPair = self.provider.generateKeyPair()!

        // Alice encapsulates to Bob
        let aliceEncapsulation = self.provider.encapsulate(peerPublicKeyData: bobKeyPair.publicKeyData)!
        // Bob encapsulates to Alice
        let bobEncapsulation = self.provider.encapsulate(peerPublicKeyData: aliceKeyPair.publicKeyData)!

        // Bob decapsulates Alice's ciphertext
        let bobRecoveredSecret = self.provider.decapsulate(
            ciphertext: aliceEncapsulation.ciphertext,
            privateKeyHandle: bobKeyPair.privateKeyHandle
        )!
        // Alice decapsulates Bob's ciphertext
        let aliceRecoveredSecret = self.provider.decapsulate(
            ciphertext: bobEncapsulation.ciphertext,
            privateKeyHandle: aliceKeyPair.privateKeyHandle
        )!

        // Alice has: aliceEncapsulation.sharedSecret (from her encapsulation) + aliceRecoveredSecret (from Bob's)
        // Bob has: bobRecoveredSecret (from Alice's ciphertext) + bobEncapsulation.sharedSecret (from his encapsulation)

        // Alice's encapsulated secret == Bob's decapsulated secret
        XCTAssertEqual(aliceEncapsulation.sharedSecret, bobRecoveredSecret)
        // Bob's encapsulated secret == Alice's decapsulated secret
        XCTAssertEqual(bobEncapsulation.sharedSecret, aliceRecoveredSecret)
    }
}

// MARK: - 2. PQProviderFactory Tests

final class PQProviderFactoryTests: XCTestCase {

    func testFactoryReturnsNilBeforeiOS26() {
        // This test validates the contract — on iOS < 26, create() returns nil.
        // When run on iOS 26+, this test is informational (always passes).
        if #available(iOS 26, *) {
            XCTAssertNotNil(PQProviderFactory.create())
            XCTAssertNotNil(PQProviderFactory.createForTesting())
        } else {
            XCTAssertNil(PQProviderFactory.create())
            XCTAssertNil(PQProviderFactory.createForTesting())
        }
    }
}

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

    @available(iOS 26, *)
    func testInitFromHybridExchangeResult() {
        let result = ExchangeManager.HybridExchangeResult(
            peerP256PublicKey: Data(repeating: 0x04, count: 65),
            mlkemSecret1: Data(repeating: 0xAA, count: 32),
            mlkemSecret2: Data(repeating: 0xBB, count: 32),
            ourNonce: Data(repeating: 0x01, count: 16),
            peerNonce: Data(repeating: 0x02, count: 16),
            ourCiphertext: Data(repeating: 0xCC, count: 1568),
            peerCiphertext: Data(repeating: 0xDD, count: 1568)
        )

        let material = QuantumKeyMaterial(from: result)

        XCTAssertEqual(material.encapsulatedSecret, result.mlkemSecret1)
        XCTAssertEqual(material.decapsulatedSecret, result.mlkemSecret2)
        XCTAssertEqual(material.ourCiphertext, result.ourCiphertext)
        XCTAssertEqual(material.peerCiphertext, result.peerCiphertext)
        XCTAssertTrue(material.isValid)
    }
}

// MARK: - 4. Hybrid Key Derivation Tests (TestKeyManager)

@available(iOS 26, *)
final class HybridKeyDerivationTests: XCTestCase {

    private var alice: TestKeyManager!
    private var bob: TestKeyManager!

    @MainActor
    override func setUp() {
        super.setUp()
        self.alice = TestKeyManager()
        self.bob = TestKeyManager()
    }

    // MARK: 4.1 Both sides derive the same hybrid shared secret
    
    let provider = PQProviderFactory.createForTesting()!

    @MainActor
    func testBothSidesDeriveIdenticalHybridSharedSecret() {
        

        // Simulate mutual encapsulation
        let aliceKeyPair = provider.generateKeyPair()!
        let bobKeyPair = provider.generateKeyPair()!

        let aliceEncapsulation = provider.encapsulate(peerPublicKeyData: bobKeyPair.publicKeyData)!
        let bobEncapsulation = provider.encapsulate(peerPublicKeyData: aliceKeyPair.publicKeyData)!

        let bobDecapsulatedSecret = provider.decapsulate(ciphertext: aliceEncapsulation.ciphertext, privateKeyHandle: bobKeyPair.privateKeyHandle)!
        let aliceDecapsulatedSecret = provider.decapsulate(ciphertext: bobEncapsulation.ciphertext, privateKeyHandle: aliceKeyPair.privateKeyHandle)!

        // Alice's quantum material
        let aliceQuantum = QuantumKeyMaterial(
            encapsulatedSecret: aliceEncapsulation.sharedSecret,
            decapsulatedSecret: aliceDecapsulatedSecret,
            ourCiphertext: aliceEncapsulation.ciphertext,
            peerCiphertext: bobEncapsulation.ciphertext
        )

        // Bob's quantum material — same secrets, but from opposite perspectives
        let bobQuantum = QuantumKeyMaterial(
            encapsulatedSecret: bobEncapsulation.sharedSecret,
            decapsulatedSecret: bobDecapsulatedSecret,
            ourCiphertext: bobEncapsulation.ciphertext,
            peerCiphertext: aliceEncapsulation.ciphertext
        )

        let alicePubKey = try! self.alice.retrieveIdentity()
        let bobPubKey = try! self.bob.retrieveIdentity()

        let aliceSessionKey = self.alice.createHybridSharedSecret(
            peerP256Material: bobPubKey,
            quantumMaterial: aliceQuantum
        )

        let bobSessionKey = self.bob.createHybridSharedSecret(
            peerP256Material: alicePubKey,
            quantumMaterial: bobQuantum
        )
        
        print("Alice quantum = \(aliceQuantum), key = \(alicePubKey)")

        XCTAssertNotNil(aliceSessionKey)
        XCTAssertNotNil(bobSessionKey)
        XCTAssertEqual(
            aliceSessionKey!.withUnsafeBytes { Data($0) },
            bobSessionKey!.withUnsafeBytes { Data($0) },
            "Both sides must derive the same hybrid shared secret"
        )
    }

    // MARK: 4.2 Hybrid key differs from classical key

    @MainActor
    func testHybridKeyDiffersFromClassicalKey() {
        let bobPubKey = try! self.bob.retrieveIdentity()

        let classicalKey = self.alice.createSharedSecret(using: bobPubKey)

        let quantumMaterial = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 32),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(),
            peerCiphertext: Data()
        )

        let hybridKey = self.alice.createHybridSharedSecret(
            peerP256Material: bobPubKey,
            quantumMaterial: quantumMaterial
        )

        XCTAssertNotNil(classicalKey)
        XCTAssertNotNil(hybridKey)
        XCTAssertNotEqual(
            classicalKey!.withUnsafeBytes { Data($0) },
            hybridKey!.withUnsafeBytes { Data($0) },
            "Hybrid derivation must produce a different key than classical ECDH-only"
        )
    }

    // MARK: 4.3 Invalid quantum material

    @MainActor
    func testHybridWithWrongSizeSecretReturnsNil() {
        let bobPubKey = try! self.bob.retrieveIdentity()

        let invalidMaterial = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 16),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(),
            peerCiphertext: Data()
        )

        let key = self.alice.createHybridSharedSecret(
            peerP256Material: bobPubKey,
            quantumMaterial: invalidMaterial
        )

        XCTAssertNil(key)
    }

    @MainActor
    func testHybridWithWrongP256LengthReturnsNil() {
        let quantumMaterial = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 32),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(),
            peerCiphertext: Data()
        )

        let key = self.alice.createHybridSharedSecret(
            peerP256Material: Data(repeating: 0x04, count: 33),
            quantumMaterial: quantumMaterial
        )

        XCTAssertNil(key)
    }

    // MARK: 4.4 Secret ordering is commutative

    @MainActor
    func testSecretOrderDoesNotAffectOutput() {
        let bobPubKey = try! self.bob.retrieveIdentity()

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

        let key1 = self.alice.createHybridSharedSecret(peerP256Material: bobPubKey, quantumMaterial: material1)
        let key2 = self.alice.createHybridSharedSecret(peerP256Material: bobPubKey, quantumMaterial: material2)

        XCTAssertEqual(
            key1!.withUnsafeBytes { Data($0) },
            key2!.withUnsafeBytes { Data($0) },
            "Lexicographic sorting of secrets must make order irrelevant"
        )
    }
}

// MARK: - 5. Diceware Key Derivation Tests

@available(iOS 26, *)
final class DicewareKeyDerivationTests: XCTestCase {

    private var alice: TestKeyManager!
    private var bob: TestKeyManager!

    @MainActor
    override func setUp() {
        super.setUp()
        self.alice = TestKeyManager()
        self.bob = TestKeyManager()
    }

    @MainActor
    func testBothSidesDeriveIdenticalDicewareKey() {
        let provider = PQProviderFactory.createForTesting()!

        let aliceKeyPair = provider.generateKeyPair()!
        let bobKeyPair = provider.generateKeyPair()!

        let aliceEncapsulation = provider.encapsulate(peerPublicKeyData: bobKeyPair.publicKeyData)!
        let bobEncapsulation = provider.encapsulate(peerPublicKeyData: aliceKeyPair.publicKeyData)!

        let bobDecapsulatedSecret = provider.decapsulate(ciphertext: aliceEncapsulation.ciphertext, privateKeyHandle: bobKeyPair.privateKeyHandle)!
        let aliceDecapsulatedSecret = provider.decapsulate(ciphertext: bobEncapsulation.ciphertext, privateKeyHandle: aliceKeyPair.privateKeyHandle)!

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

        let bobPubKey = try! self.bob.retrieveIdentity()
        let alicePubKey = try! self.alice.retrieveIdentity()

        let aliceDicewareKey = self.alice.createDicewareKey(
            peerP256Material: bobPubKey,
            quantumMaterial: aliceQuantum,
            ourNonce: aliceNonce,
            peerNonce: bobNonce
        )

        let bobDicewareKey = self.bob.createDicewareKey(
            peerP256Material: alicePubKey,
            quantumMaterial: bobQuantum,
            ourNonce: bobNonce,
            peerNonce: aliceNonce
        )

        XCTAssertNotNil(aliceDicewareKey)
        XCTAssertNotNil(bobDicewareKey)
        XCTAssertEqual(
            aliceDicewareKey!.withUnsafeBytes { Data($0) },
            bobDicewareKey!.withUnsafeBytes { Data($0) },
            "Both sides must see the same Diceware words"
        )
    }

    @MainActor
    func testDicewareKeyDiffersFromTransportKey() {
        let bobPubKey = try! self.bob.retrieveIdentity()

        let quantumMaterial = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 32),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(), peerCiphertext: Data()
        )
        let nonce = Data(repeating: 0x01, count: 16)

        let transportKey = self.alice.createHybridSharedSecret(
            peerP256Material: bobPubKey,
            quantumMaterial: quantumMaterial
        )

        let dicewareKey = self.alice.createDicewareKey(
            peerP256Material: bobPubKey,
            quantumMaterial: quantumMaterial,
            ourNonce: nonce,
            peerNonce: Data(repeating: 0x02, count: 16)
        )

        XCTAssertNotEqual(
            transportKey!.withUnsafeBytes { Data($0) },
            dicewareKey!.withUnsafeBytes { Data($0) },
            "Diceware key must differ from transport key due to different HKDF info"
        )
    }

    @MainActor
    func testDifferentNoncesProduceDifferentDicewareKeys() {
        let bobPubKey = try! self.bob.retrieveIdentity()

        let quantumMaterial = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 32),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(), peerCiphertext: Data()
        )

        let key1 = self.alice.createDicewareKey(
            peerP256Material: bobPubKey,
            quantumMaterial: quantumMaterial,
            ourNonce: Data(repeating: 0x01, count: 16),
            peerNonce: Data(repeating: 0x02, count: 16)
        )

        let key2 = self.alice.createDicewareKey(
            peerP256Material: bobPubKey,
            quantumMaterial: quantumMaterial,
            ourNonce: Data(repeating: 0x03, count: 16),
            peerNonce: Data(repeating: 0x04, count: 16)
        )

        XCTAssertNotEqual(
            key1!.withUnsafeBytes { Data($0) },
            key2!.withUnsafeBytes { Data($0) },
            "Different nonces must produce different Diceware words (freshness guarantee)"
        )
    }

    @MainActor
    func testNonceOrderDoesNotAffectDicewareKey() {
        let bobPubKey = try! self.bob.retrieveIdentity()

        let quantumMaterial = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 32),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(), peerCiphertext: Data()
        )

        let nonceA = Data(repeating: 0x01, count: 16)
        let nonceB = Data(repeating: 0x02, count: 16)

        let key1 = self.alice.createDicewareKey(
            peerP256Material: bobPubKey,
            quantumMaterial: quantumMaterial,
            ourNonce: nonceA,
            peerNonce: nonceB
        )

        let key2 = self.alice.createDicewareKey(
            peerP256Material: bobPubKey,
            quantumMaterial: quantumMaterial,
            ourNonce: nonceB,
            peerNonce: nonceA
        )

        XCTAssertEqual(
            key1!.withUnsafeBytes { Data($0) },
            key2!.withUnsafeBytes { Data($0) },
            "Nonce sorting must make our/peer order irrelevant"
        )
    }

    @MainActor
    func testWrongSizeNonceReturnsNil() {
        let bobPubKey = try! self.bob.retrieveIdentity()

        let quantumMaterial = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 32),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(), peerCiphertext: Data()
        )

        let key = self.alice.createDicewareKey(
            peerP256Material: bobPubKey,
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

    private var alice: TestKeyManager!
    private var bob: TestKeyManager!

    @MainActor
    override func setUp() {
        super.setUp()
        self.alice = TestKeyManager()
        self.bob = TestKeyManager()
    }

    // MARK: 6.1 deriveSessionKey fallback

    @MainActor
    func testDeriveSessionKeyWithNilQuantumMaterialUsesClassical() {
        let bobPubKey = try! self.bob.retrieveIdentity()
        let cryptoOps = Manager.Crypto(keyManager: self.alice)

        let classicalKey = self.alice.createSharedSecret(using: bobPubKey)
        let derivedKey = cryptoOps.deriveSessionKey(using: bobPubKey, quantumMaterial: nil)

        XCTAssertNotNil(classicalKey)
        XCTAssertNotNil(derivedKey)
        XCTAssertEqual(
            classicalKey!.withUnsafeBytes { Data($0) },
            derivedKey!.withUnsafeBytes { Data($0) },
            "Nil quantum material must produce the same key as classical derivation"
        )
    }

    @MainActor
    func testDeriveSessionKeyWithQuantumMaterialUsesHybrid() {
        let bobPubKey = try! self.bob.retrieveIdentity()
        let cryptoOps = Manager.Crypto(keyManager: self.alice)

        let quantumMaterial = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 32),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(), peerCiphertext: Data()
        )

        let classicalKey = cryptoOps.deriveSessionKey(using: bobPubKey, quantumMaterial: nil)
        let hybridKey = cryptoOps.deriveSessionKey(using: bobPubKey, quantumMaterial: quantumMaterial)

        XCTAssertNotNil(classicalKey)
        XCTAssertNotNil(hybridKey)
        XCTAssertNotEqual(
            classicalKey!.withUnsafeBytes { Data($0) },
            hybridKey!.withUnsafeBytes { Data($0) },
            "Quantum material must change the derivation path"
        )
    }

    // MARK: 6.2 Exchange model encoding

    func testV1PeerDecodesExchangeWithNewFields() throws {
        // Simulate a PQ peer sending an exchange with new fields
        let exchange = Exchange(
            id: UUID().uuidString,
            token: Data([0x01, 0x02, 0x03]),
            version: .v1,
            identity: Data(repeating: 0x04, count: 65),
            nonce: Data(repeating: 0xAA, count: 16),
            encapsulationKey: Data(repeating: 0xBB, count: 1568),
            ciphertext: nil
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
        // nonce, encapsulationKey, ciphertext are silently ignored by v1 decoder
    }

    func testExchangePhasesDetection() {
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

    private var alice: TestKeyManager!
    private var bob: TestKeyManager!

    @MainActor
    override func setUp() {
        super.setUp()
        self.alice = TestKeyManager()
        self.bob = TestKeyManager()
    }

    @MainActor
    func testEncryptWithHybridKeyDecryptWithSameKey() throws {
        let provider = PQProviderFactory.createForTesting()!
        let bobPubKey = try self.bob.retrieveIdentity()
        let alicePubKey = try self.alice.retrieveIdentity()

        // Full mutual encapsulation
        let aliceKeyPair = provider.generateKeyPair()!
        let bobKeyPair = provider.generateKeyPair()!

        let aliceEncapsulation = provider.encapsulate(peerPublicKeyData: bobKeyPair.publicKeyData)!
        let bobEncapsulation = provider.encapsulate(peerPublicKeyData: aliceKeyPair.publicKeyData)!

        let bobDecapsulatedSecret = provider.decapsulate(ciphertext: aliceEncapsulation.ciphertext, privateKeyHandle: bobKeyPair.privateKeyHandle)!
        let aliceDecapsulatedSecret = provider.decapsulate(ciphertext: bobEncapsulation.ciphertext, privateKeyHandle: aliceKeyPair.privateKeyHandle)!

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

        // Alice encrypts
        let aliceSessionKey = self.alice.createHybridSharedSecret(peerP256Material: bobPubKey, quantumMaterial: aliceQuantum)!
        let plaintext = "Quantum-resistant message from Alice".data(using: .utf8)!
        let sealed = try AES.GCM.seal(plaintext, using: aliceSessionKey, nonce: AES.GCM.Nonce())

        // Bob decrypts
        let bobSessionKey = self.bob.createHybridSharedSecret(peerP256Material: alicePubKey, quantumMaterial: bobQuantum)!
        let box = try AES.GCM.SealedBox(combined: sealed.combined!)
        let decrypted = try AES.GCM.open(box, using: bobSessionKey)

        XCTAssertEqual(decrypted, plaintext)
    }

    @MainActor
    func testClassicalKeyCannotDecryptHybridEncryptedData() throws {
        let bobPubKey = try self.bob.retrieveIdentity()

        let quantumMaterial = QuantumKeyMaterial(
            encapsulatedSecret: Data(repeating: 0xAA, count: 32),
            decapsulatedSecret: Data(repeating: 0xBB, count: 32),
            ourCiphertext: Data(), peerCiphertext: Data()
        )

        // Alice encrypts with hybrid key
        let hybridKey = self.alice.createHybridSharedSecret(peerP256Material: bobPubKey, quantumMaterial: quantumMaterial)!
        let plaintext = "Secret message".data(using: .utf8)!
        let sealed = try AES.GCM.seal(plaintext, using: hybridKey, nonce: AES.GCM.Nonce())

        // Bob tries to decrypt with classical key
        let classicalKey = self.bob.createSharedSecret(using: try self.alice.retrieveIdentity())!
        let box = try AES.GCM.SealedBox(combined: sealed.combined!)

        XCTAssertThrowsError(try AES.GCM.open(box, using: classicalKey)) { error in
            // GCM authentication failure — wrong key
            XCTAssertTrue(error is CryptoKit.CryptoKitError)
        }
    }
}

// MARK: - 8. Exchange Nonce Tests

final class ExchangeNonceTests: XCTestCase {
    let keyManager: Manager.Key = Manager.Key(testingTag: "test.nonce.\(UUID().uuidString)")
    
    func testNonceIsCorrectLength() {
        let nonce = keyManager.generateExchangeNonce()

        XCTAssertNotNil(nonce)
        XCTAssertEqual(nonce!.count, 16)
    }

    func testTwoNoncesAreDistinct() {
        let nonce1 = keyManager.generateExchangeNonce()!
        let nonce2 = keyManager.generateExchangeNonce()!

        XCTAssertNotEqual(nonce1, nonce2)
    }
}

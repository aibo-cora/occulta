//
//  PairwiseDerivationTests.swift
//  OccultaTests
//
//  Bug 196, stage 2: what two phones derive at an exchange that gave each pairing its own key pair. The transcript of what
//  both sent, the routing key, the verification words' key and the long-term slot key; and that the identity key stays in
//  the first two, so a phone that presents a contact's public key proves nothing.
//
//  No Enclave: pair keys here are software CryptoKit keys, which derive the same ECDH output (`cardECDHOutput`).
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta
@testable import OccultaFormats

// MARK: - Fixture

private func nonce(_ byte: UInt8) -> Data { Data(repeating: byte, count: 16) }

/// One phone: an identity key manager, a pair agreement key, and a pair block as it would send it.
@MainActor
private struct Phone {
    let identity = TestKeyManager()
    let agreement = P256.KeyAgreement.PrivateKey()
    let signing = P256.Signing.PrivateKey()
    var mldsaKey: Data?

    var agreementPublic: Data { self.agreement.publicKey.x963Representation }
    var block: RoutingKey.PairBlock {
        RoutingKey.PairBlock(
            agreementKey: self.agreementPublic, signingKey: self.signing.publicKey.x963Representation, mldsaKey: self.mldsaKey
        )!
    }

    /// The pair-key ECDH output with `peer`'s agreement key, as the Enclave's raw secret through the X9.63 KDF.
    func pairwiseECDH(with peer: Data) throws -> Data {
        let raw = try self.agreement.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: peer))
        return Manager.Crypto.cardECDHOutput(raw.withUnsafeBytes { Data($0) })
    }
}

private func quantum() -> (alice: QuantumKeyMaterial, bob: QuantumKeyMaterial) {
    let s1 = Data(repeating: 0x31, count: 32), s2 = Data(repeating: 0x32, count: 32)
    let c1 = Data(repeating: 0x41, count: 16), c2 = Data(repeating: 0x42, count: 16)
    return (
        QuantumKeyMaterial(encapsulatedSecret: s1, decapsulatedSecret: s2, ourCiphertext: c1, peerCiphertext: c2),
        QuantumKeyMaterial(encapsulatedSecret: s2, decapsulatedSecret: s1, ourCiphertext: c2, peerCiphertext: c1)
    )
}

private func mldsaKeyBytes(_ byte: UInt8) -> Data { Data(repeating: byte, count: RoutingKey.PairBlock.mldsaKeySize) }

/// What `me` derives for a pairing with `peer`, the way the exchange would: `theirBlock` is what `me` received.
private struct Derived {
    let routingKey: Data
    let words: Data
}

@MainActor
private func derive(
    me: Phone, peerIdentity: Data, peerAgreement: Data, theirBlock: RoutingKey.PairBlock, quantum: QuantumKeyMaterial?,
    ourNonce: Data, peerNonce: Data
) throws -> Derived? {
    let transcript = RoutingKey.transcript(me.block, theirBlock)
    let pk = try me.pairwiseECDH(with: peerAgreement)
    guard
        let routing = me.identity.createRoutingKey(
            peerP256Material: peerIdentity, pairwiseECDH: pk, ourAgreementKey: me.agreementPublic, peerAgreementKey: peerAgreement,
            transcript: transcript, quantumMaterial: quantum, ourNonce: ourNonce, peerNonce: peerNonce
        ),
        let words = me.identity.createPairwiseDicewareKey(
            peerP256Material: peerIdentity, pairwiseECDH: pk, transcript: transcript, quantumMaterial: quantum,
            ourNonce: ourNonce, peerNonce: peerNonce
        )
    else { return nil }
    return Derived(routingKey: routing, words: words.withUnsafeBytes { Data($0) })
}

// MARK: - Suite

@MainActor
@Suite("Bug 196 — what a pair-key exchange derives")
struct PairwiseDerivationTests {

    private let alice = Phone()
    private let bob   = Phone()

    private func both(
        aliceQuantum: QuantumKeyMaterial? = nil, bobQuantum: QuantumKeyMaterial? = nil
    ) throws -> (alice: Derived, bob: Derived) {
        let a = try #require(try derive(
            me: self.alice, peerIdentity: try self.bob.identity.retrieveIdentity(), peerAgreement: self.bob.agreementPublic,
            theirBlock: self.bob.block, quantum: aliceQuantum, ourNonce: nonce(1), peerNonce: nonce(2)))
        let b = try #require(try derive(
            me: self.bob, peerIdentity: try self.alice.identity.retrieveIdentity(), peerAgreement: self.alice.agreementPublic,
            theirBlock: self.alice.block, quantum: bobQuantum, ourNonce: nonce(2), peerNonce: nonce(1)))
        return (a, b)
    }

    // MARK: Agreement

    @Test("Both phones derive the same routing key and the same words key, classical")
    func classicalAgrees() throws {
        let (a, b) = try self.both()
        #expect(a.routingKey == b.routingKey && a.routingKey.count == 32)
        #expect(a.words == b.words && a.words.count == 32)
    }

    @Test("Both phones derive the same routing key and words key, hybrid")
    func hybridAgrees() throws {
        let q = quantum()
        let (a, b) = try self.both(aliceQuantum: q.alice, bobQuantum: q.bob)
        #expect(a.routingKey == b.routingKey)
        #expect(a.words == b.words)
    }

    @Test("They agree when only one phone sent an ML-DSA key, and differ from the pairing where neither did")
    func oneSidedMLDSAAgrees() throws {
        var alice = self.alice
        alice.mldsaKey = mldsaKeyBytes(0xA1)
        let a = try #require(try derive(
            me: alice, peerIdentity: try self.bob.identity.retrieveIdentity(), peerAgreement: self.bob.agreementPublic,
            theirBlock: self.bob.block, quantum: nil, ourNonce: nonce(1), peerNonce: nonce(2)))
        let b = try #require(try derive(
            me: self.bob, peerIdentity: try alice.identity.retrieveIdentity(), peerAgreement: alice.agreementPublic,
            theirBlock: alice.block, quantum: nil, ourNonce: nonce(2), peerNonce: nonce(1)))
        #expect(a.routingKey == b.routingKey && a.words == b.words)
        #expect(a.words != (try self.both()).alice.words)
    }

    // MARK: A man in the middle

    @Test("A pair key a man in the middle swapped changes the words and the routing key")
    func swappedPairKeyChangesBoth() throws {
        let mallory = Phone()
        let honest = try self.both()
        // Alice receives Mallory's pair keys in place of Bob's; the identity key is Bob's, passed through.
        let a = try #require(try derive(
            me: self.alice, peerIdentity: try self.bob.identity.retrieveIdentity(), peerAgreement: mallory.agreementPublic,
            theirBlock: mallory.block, quantum: nil, ourNonce: nonce(1), peerNonce: nonce(2)))
        #expect(a.words != honest.bob.words)
        #expect(a.routingKey != honest.bob.routingKey)
    }

    @Test("Bob's words differ from Alice's when Alice's ML-DSA key is added, removed or swapped on the way")
    func mldsaTamperingChangesTheWords() throws {
        var alice = self.alice
        alice.mldsaKey = mldsaKeyBytes(0xA1)
        let aliceIdentity = try alice.identity.retrieveIdentity()
        let bobIdentity = try self.bob.identity.retrieveIdentity()
        let bobsWords = try #require(try derive(
            me: self.bob, peerIdentity: aliceIdentity, peerAgreement: alice.agreementPublic, theirBlock: alice.block,
            quantum: nil, ourNonce: nonce(2), peerNonce: nonce(1))).words

        func aliceWords(whatBobSaw: RoutingKey.PairBlock) throws -> Data {
            // Alice's own view of the transcript is her own block and Bob's; what differs is what Bob was shown of hers.
            try #require(try derive(
                me: alice, peerIdentity: bobIdentity, peerAgreement: self.bob.agreementPublic, theirBlock: self.bob.block,
                quantum: nil, ourNonce: nonce(1), peerNonce: nonce(2))).words
        }
        #expect(try aliceWords(whatBobSaw: alice.block) == bobsWords, "untouched: the words match")

        var removed = alice; removed.mldsaKey = nil
        var swapped = alice; swapped.mldsaKey = mldsaKeyBytes(0xB2)
        for tampered in [removed, swapped] {
            let seenByBob = try #require(try derive(
                me: self.bob, peerIdentity: aliceIdentity, peerAgreement: alice.agreementPublic, theirBlock: tampered.block,
                quantum: nil, ourNonce: nonce(2), peerNonce: nonce(1))).words
            #expect(seenByBob != (try aliceWords(whatBobSaw: alice.block)), "a tampered ML-DSA key changes Bob's words")
        }

        var added = self.alice  // Alice sent none; the man in the middle added one for Bob.
        let honestWords = try self.both().alice.words
        added.mldsaKey = mldsaKeyBytes(0xC3)
        let seenByBob = try #require(try derive(
            me: self.bob, peerIdentity: aliceIdentity, peerAgreement: added.agreementPublic, theirBlock: added.block,
            quantum: nil, ourNonce: nonce(2), peerNonce: nonce(1))).words
        #expect(seenByBob != honestWords)
    }

    @Test("A phone that presents a contact's public identity key without its private half derives something else")
    func publicIdentityKeyProvesNothing() throws {
        // Mallory meets Alice and presents Bob's public identity key beside her own pair keys.
        let mallory = Phone()
        let bobPublic = try self.bob.identity.retrieveIdentity()
        let alicePublic = try self.alice.identity.retrieveIdentity()
        let aliceSees = try #require(try derive(
            me: self.alice, peerIdentity: bobPublic, peerAgreement: mallory.agreementPublic, theirBlock: mallory.block,
            quantum: nil, ourNonce: nonce(1), peerNonce: nonce(2)))
        // Mallory can compute the pair-key ECDH, but the identity ECDH needs a private key she doesn't have: hers is another.
        let malloryComputes = try #require(try derive(
            me: mallory, peerIdentity: alicePublic, peerAgreement: self.alice.agreementPublic, theirBlock: self.alice.block,
            quantum: nil, ourNonce: nonce(2), peerNonce: nonce(1)))
        #expect(aliceSees.routingKey != malloryComputes.routingKey)
        #expect(aliceSees.words != malloryComputes.words, "the words would not match on the two screens")
    }

    // MARK: Separation

    @Test("Two pairings of the same two phones differ, and ML-KEM secrets change the keys")
    func differsPerPairingAndPerQuantum() throws {
        let one = try self.both()
        let two = try #require(try derive(
            me: self.alice, peerIdentity: try self.bob.identity.retrieveIdentity(), peerAgreement: self.bob.agreementPublic,
            theirBlock: self.bob.block, quantum: nil, ourNonce: nonce(1), peerNonce: nonce(3)))
        #expect(one.alice.routingKey != two.routingKey)

        let hybrid = try self.both(aliceQuantum: quantum().alice, bobQuantum: quantum().bob)
        #expect(hybrid.alice.routingKey != one.alice.routingKey)
        #expect(hybrid.alice.words != one.alice.words)
    }

    @Test("The words' key is not the routing key, and a routing key of this domain is not one of the identity-only domain")
    func domainsAreSeparate() throws {
        let a = try self.both().alice
        #expect(a.words != a.routingKey)

        let old = self.alice.identity.createRoutingKey(
            peerP256Material: try self.bob.identity.retrieveIdentity(), quantumMaterial: nil, ourNonce: nonce(1), peerNonce: nonce(2)
        )
        #expect(old != nil && old != a.routingKey)
    }

    // MARK: Refusals

    @Test("A bad size, equal nonces or equal agreement keys derive nothing")
    func refusesBadInput() throws {
        let identity = try self.bob.identity.retrieveIdentity()
        let pk = try self.alice.pairwiseECDH(with: self.bob.agreementPublic)
        let transcript = RoutingKey.transcript(self.alice.block, self.bob.block)

        func routing(
            pk: Data? = nil, ourAgreement: Data? = nil, peerAgreement: Data? = nil, transcript t: Data? = nil,
            ourNonce: Data = nonce(1), peerNonce: Data = nonce(2)
        ) -> Data? {
            self.alice.identity.createRoutingKey(
                peerP256Material: identity, pairwiseECDH: pk ?? pk_, ourAgreementKey: ourAgreement ?? self.alice.agreementPublic,
                peerAgreementKey: peerAgreement ?? self.bob.agreementPublic, transcript: t ?? transcript,
                quantumMaterial: nil, ourNonce: ourNonce, peerNonce: peerNonce
            )
        }
        let pk_ = pk
        #expect(routing() != nil)
        #expect(routing(pk: Data(count: 31)) == nil)
        #expect(routing(transcript: Data(count: 31)) == nil)
        #expect(routing(ourNonce: nonce(1), peerNonce: nonce(1)) == nil)
        #expect(routing(ourNonce: Data(count: 15)) == nil)
        #expect(routing(ourAgreement: self.bob.agreementPublic) == nil, "two equal agreement keys XOR to nothing")
        #expect(routing(peerAgreement: Data(count: 64)) == nil)
    }

    // MARK: The block and the transcript

    @Test("A pair block refuses a key of the wrong size or two equal P-256 keys")
    func blockValidates() {
        let key = self.alice.agreementPublic, other = self.alice.signing.publicKey.x963Representation
        #expect(RoutingKey.PairBlock(agreementKey: key, signingKey: other) != nil)
        #expect(RoutingKey.PairBlock(agreementKey: key, signingKey: key) == nil)
        #expect(RoutingKey.PairBlock(agreementKey: Data(count: 64), signingKey: other) == nil)
        #expect(RoutingKey.PairBlock(agreementKey: key, signingKey: other, mldsaKey: Data(count: 100)) == nil)
        #expect(RoutingKey.PairBlock(agreementKey: key, signingKey: other, mldsaKey: mldsaKeyBytes(1)) != nil)
    }

    @Test("The transcript is the same whichever block is first, and tells a missing ML-DSA key from a present one")
    func transcriptIsSymmetricAndSensitive() {
        let a = self.alice.block, b = self.bob.block
        #expect(RoutingKey.transcript(a, b) == RoutingKey.transcript(b, a))
        #expect(RoutingKey.transcript(a, b).count == 32)

        var withKey = self.alice; withKey.mldsaKey = mldsaKeyBytes(7)
        var otherKey = self.alice; otherKey.mldsaKey = mldsaKeyBytes(8)
        #expect(RoutingKey.transcript(a, b) != RoutingKey.transcript(withKey.block, b))
        #expect(RoutingKey.transcript(withKey.block, b) != RoutingKey.transcript(otherKey.block, b))
    }

    // MARK: The long-term key

    @Test("Both phones derive the same long-term slot key, which the identity key is not part of")
    func longTermKeyAgrees() throws {
        func bytes(_ key: SymmetricKey?) -> Data? { key.map { $0.withUnsafeBytes { Data($0) } } }
        let a = RoutingKey.longTermKey(
            pairwiseECDH: try self.alice.pairwiseECDH(with: self.bob.agreementPublic),
            ourAgreementKey: self.alice.agreementPublic, peerAgreementKey: self.bob.agreementPublic, mlkemSecrets: nil)
        let b = RoutingKey.longTermKey(
            pairwiseECDH: try self.bob.pairwiseECDH(with: self.alice.agreementPublic),
            ourAgreementKey: self.bob.agreementPublic, peerAgreementKey: self.alice.agreementPublic, mlkemSecrets: nil)
        #expect(bytes(a) != nil && bytes(a) == bytes(b))

        let secrets = (Data(repeating: 0x31, count: 32), Data(repeating: 0x32, count: 32))
        let hybrid = RoutingKey.longTermKey(
            pairwiseECDH: try self.alice.pairwiseECDH(with: self.bob.agreementPublic),
            ourAgreementKey: self.alice.agreementPublic, peerAgreementKey: self.bob.agreementPublic, mlkemSecrets: secrets)
        let hybridFlipped = RoutingKey.longTermKey(
            pairwiseECDH: try self.bob.pairwiseECDH(with: self.alice.agreementPublic),
            ourAgreementKey: self.bob.agreementPublic, peerAgreementKey: self.alice.agreementPublic,
            mlkemSecrets: (secrets.1, secrets.0))
        #expect(bytes(hybrid) == bytes(hybridFlipped))
        #expect(bytes(hybrid) != bytes(a), "ML-KEM secrets change it, under a domain of their own")
    }

    @Test("A long-term key needs a 32-byte ECDH, two distinct 65-byte agreement keys and 32-byte ML-KEM secrets")
    func longTermKeyRefuses() throws {
        let pk = try self.alice.pairwiseECDH(with: self.bob.agreementPublic)
        let a = self.alice.agreementPublic, b = self.bob.agreementPublic
        #expect(RoutingKey.longTermKey(pairwiseECDH: pk, ourAgreementKey: a, peerAgreementKey: b, mlkemSecrets: nil) != nil)
        #expect(RoutingKey.longTermKey(pairwiseECDH: Data(count: 31), ourAgreementKey: a, peerAgreementKey: b, mlkemSecrets: nil) == nil)
        #expect(RoutingKey.longTermKey(pairwiseECDH: pk, ourAgreementKey: a, peerAgreementKey: a, mlkemSecrets: nil) == nil)
        #expect(RoutingKey.longTermKey(pairwiseECDH: pk, ourAgreementKey: a, peerAgreementKey: Data(count: 64), mlkemSecrets: nil) == nil)
        #expect(RoutingKey.longTermKey(
            pairwiseECDH: pk, ourAgreementKey: a, peerAgreementKey: b, mlkemSecrets: (Data(count: 32), Data(count: 31))) == nil)
    }

    // MARK: ML-DSA

    @Test("A software ML-DSA-87 key's stored blob imports and signs, and its signature verifies")
    @available(iOS 26, *)
    func mldsaBlobRoundTrips() throws {
        let keys = SoftwareCardKeys()
        let made = try keys.makeMLDSAKey()
        #expect(made.publicKey.count == RoutingKey.PairBlock.mldsaKeySize)
        #expect(try keys.mldsaPublicKey(blob: made.blob) == made.publicKey)

        let payload = Data("a payload".utf8)
        let signature = try keys.mldsaSign(payload, blob: made.blob)
        let publicKey = try MLDSA87.PublicKey(rawRepresentation: made.publicKey)
        #expect(publicKey.isValidSignature(signature, for: payload))
        #expect(!publicKey.isValidSignature(signature, for: Data("another".utf8)))
    }

    @Test("A phone that can't make an ML-DSA key throws, which the exchange reads as sending none")
    func mldsaUnavailableThrows() {
        let keys = SoftwareCardKeys()
        keys.mldsaAvailable = false
        #expect(throws: (any Error).self) { try keys.makeMLDSAKey() }
    }
}

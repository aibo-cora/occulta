//
//  ExchangeCommitmentTests.swift
//  OccultaTests
//
//  Bugs 198 and 199: commit, then reveal. The nonce commitment, the transcript hash of every message of the exchange, and
//  the words and routing key derived over both. What these pin: a man in the middle who has fixed everything he sends
//  before either nonce is revealed cannot steer the words; an ML-KEM key removed from a message in transit changes the
//  transcript and so the words; and a classical exchange's words are no longer the transport key's output.
//
//  No Enclave: identity keys are `TestKeyManager`'s software keys, pair keys are CryptoKit software keys.
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta
@testable import OccultaFormats

private func nonce(_ byte: UInt8) -> Data { Data(repeating: byte, count: 16) }

private func message(_ role: ExchangeCommitment.Role, _ step: ExchangeCommitment.Step, _ text: String) -> ExchangeCommitment.Message {
    ExchangeCommitment.Message(role: role, step: step, bytes: Data(text.utf8))
}

/// The six messages of a hybrid exchange, in whatever order the caller likes.
private func hybridMessages(initiatorIdentity: String = "I-identity", responderIdentity: String = "R-identity") -> [ExchangeCommitment.Message] {
    [
        message(.initiator, .discovery, "I-discovery"), message(.responder, .discovery, "R-discovery"),
        message(.initiator, .identity, initiatorIdentity), message(.responder, .identity, responderIdentity),
        message(.initiator, .ciphertext, "I-ciphertext"), message(.responder, .ciphertext, "R-ciphertext"),
    ]
}

private func classicalMessages() -> [ExchangeCommitment.Message] {
    hybridMessages().filter { $0.step != .ciphertext }
}

// MARK: - The commitment

@Suite("Bug 198 — the nonce commitment")
struct NonceCommitmentTests {

    @Test("A commitment is 32 bytes, repeatable, and different for every nonce")
    func shape() throws {
        let one = try #require(ExchangeCommitment.commitment(to: nonce(1)))
        #expect(one.count == 32)
        #expect(one == ExchangeCommitment.commitment(to: nonce(1)))
        #expect(one != ExchangeCommitment.commitment(to: nonce(2)))
    }

    @Test("A nonce that is not 16 bytes has no commitment")
    func wrongSize() {
        #expect(ExchangeCommitment.commitment(to: Data(count: 15)) == nil)
        #expect(ExchangeCommitment.commitment(to: Data(count: 17)) == nil)
        #expect(ExchangeCommitment.commitment(to: Data()) == nil)
    }

    @Test("A commitment opens with its own nonce and with no other")
    func opens() throws {
        let commitment = try #require(ExchangeCommitment.commitment(to: nonce(7)))
        #expect(ExchangeCommitment.opens(commitment, with: nonce(7)))
        #expect(!ExchangeCommitment.opens(commitment, with: nonce(8)))
        var flipped = nonce(7)
        flipped[15] ^= 1
        #expect(!ExchangeCommitment.opens(commitment, with: flipped), "one bit of the nonce")
    }

    @Test("A commitment of the wrong size opens nothing")
    func malformedCommitment() throws {
        let commitment = try #require(ExchangeCommitment.commitment(to: nonce(7)))
        #expect(!ExchangeCommitment.opens(commitment.prefix(31), with: nonce(7)))
        #expect(!ExchangeCommitment.opens(Data(), with: nonce(7)))
        #expect(!ExchangeCommitment.opens(commitment, with: Data(count: 15)))
    }
}

// MARK: - The transcript

@Suite("Bug 198 — the transcript of every message of the exchange")
struct ExchangeTranscriptTests {

    @Test("The order the caller lists the messages in does not matter")
    func orderFree() throws {
        let messages = hybridMessages()
        let transcript = try #require(ExchangeCommitment.transcript(messages))
        #expect(transcript.count == 32)
        #expect(transcript == ExchangeCommitment.transcript(messages.reversed()))
        #expect(transcript == ExchangeCommitment.transcript(messages.shuffled()))
    }

    @Test("A change to any byte of any message changes it", arguments: 0..<6)
    func everyMessageIsCovered(_ index: Int) throws {
        let original = hybridMessages()
        let base = try #require(ExchangeCommitment.transcript(original))
        var changed = original
        var bytes = changed[index].bytes
        bytes[bytes.startIndex] ^= 1
        changed[index] = ExchangeCommitment.Message(role: changed[index].role, step: changed[index].step, bytes: bytes)
        #expect(ExchangeCommitment.transcript(changed) != base)
    }

    @Test("The same bytes in the other phone's place give a different transcript")
    func rolesAreCovered() throws {
        let one = ExchangeCommitment.transcript(hybridMessages(initiatorIdentity: "A", responderIdentity: "B"))
        let swapped = ExchangeCommitment.transcript(hybridMessages(initiatorIdentity: "B", responderIdentity: "A"))
        #expect(one != nil && one != swapped)
    }

    @Test("A classical exchange and a hybrid one over the same messages differ: the ciphertexts are in it")
    func ciphertextsAreCovered() throws {
        #expect(try #require(ExchangeCommitment.transcript(classicalMessages())) != ExchangeCommitment.transcript(hybridMessages()))
    }

    @Test("Bug 199: an identity message with its ML-KEM key removed is a different message, so a different transcript")
    func strippedMLKEMKeyIsCovered() throws {
        let key = Data(repeating: 0x5A, count: 1568)
        func identity(withKey: Bool) throws -> Data {
            try JSONEncoder().encode(Exchange(
                id: "fixed", token: Data([1]), version: .v1, identity: Data(repeating: 4, count: 65),
                encapsulationKey: withKey ? key : nil
            ))
        }
        func transcript(_ identity: Data) -> Data? {
            ExchangeCommitment.transcript([
                message(.initiator, .discovery, "I"), message(.responder, .discovery, "R"),
                ExchangeCommitment.Message(role: .initiator, step: .identity, bytes: identity), message(.responder, .identity, "R"),
            ])
        }
        // What the sender sent and what a relay that removed the key passed on.
        #expect(try transcript(identity(withKey: true)) != transcript(identity(withKey: false)))
    }

    @Test("Incomplete or doubled sets are refused")
    func malformedSets() {
        #expect(ExchangeCommitment.transcript([]) == nil)
        #expect(ExchangeCommitment.transcript(classicalMessages().dropLast()) == nil, "no responder identity")
        #expect(ExchangeCommitment.transcript(classicalMessages().filter { $0.step != .discovery }) == nil, "no discovery")
        #expect(ExchangeCommitment.transcript(hybridMessages().dropLast()) == nil, "one ciphertext")
        #expect(ExchangeCommitment.transcript(classicalMessages() + [message(.initiator, .identity, "again")]) == nil, "two identities from one phone")
    }

    @Test("Each element is length-prefixed, so a boundary cannot move")
    func lengthPrefixed() {
        func transcript(_ identityA: String, _ identityB: String) -> Data? {
            ExchangeCommitment.transcript([
                message(.initiator, .discovery, "D"), message(.responder, .discovery, "E"),
                message(.initiator, .identity, identityA), message(.responder, .identity, identityB),
            ])
        }
        #expect(transcript("ab", "c") != transcript("a", "bc"))
    }
}

// MARK: - What is derived over it

/// One phone: an identity key manager, and a pair agreement key.
@MainActor
private struct Phone {
    let identity = TestKeyManager()
    let agreement = P256.KeyAgreement.PrivateKey()
    var agreementPublic: Data { self.agreement.publicKey.x963Representation }

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

@MainActor
@Suite("Bug 198 — the words and the routing key over a committed exchange")
struct CommittedDerivationTests {

    private let alice = Phone()
    private let bob = Phone()
    private let transcript = Data(repeating: 0x77, count: 32)

    /// The words key each phone derives, with `ourNonce`/`peerNonce` mirrored.
    private func words(
        pairKeys: Bool = false, hybrid: Bool = false, transcript: Data? = nil, aliceNonce: Data = nonce(1), bobNonce: Data = nonce(2)
    ) throws -> (alice: Data, bob: Data) {
        let q = quantum()
        let transcript = transcript ?? self.transcript
        let a = try #require(self.alice.identity.createCommittedDicewareKey(
            peerP256Material: try self.bob.identity.retrieveIdentity(),
            pairwiseECDH: pairKeys ? try self.alice.pairwiseECDH(with: self.bob.agreementPublic) : nil,
            quantumMaterial: hybrid ? q.alice : nil, ourNonce: aliceNonce, peerNonce: bobNonce, exchangeTranscript: transcript))
        let b = try #require(self.bob.identity.createCommittedDicewareKey(
            peerP256Material: try self.alice.identity.retrieveIdentity(),
            pairwiseECDH: pairKeys ? try self.bob.pairwiseECDH(with: self.alice.agreementPublic) : nil,
            quantumMaterial: hybrid ? q.bob : nil, ourNonce: bobNonce, peerNonce: aliceNonce, exchangeTranscript: transcript))
        return (a.withUnsafeBytes { Data($0) }, b.withUnsafeBytes { Data($0) })
    }

    @Test("Both phones derive the same words key in every shape of exchange", arguments: [(false, false), (false, true), (true, false), (true, true)])
    func agrees(_ shape: (pairKeys: Bool, hybrid: Bool)) throws {
        let (a, b) = try self.words(pairKeys: shape.pairKeys, hybrid: shape.hybrid)
        #expect(a == b && a.count == 32)
    }

    @Test("The shapes do not derive each other's words")
    func shapesDiffer() throws {
        let keys = try [(false, false), (false, true), (true, false), (true, true)].map { try self.words(pairKeys: $0.0, hybrid: $0.1).alice }
        #expect(Set(keys).count == 4)
    }

    @Test("Another transcript, another nonce on either side, or the nonces swapped, all change the words")
    func everyInputMatters() throws {
        let base = try self.words().alice
        #expect(try self.words(transcript: Data(repeating: 0x78, count: 32)).alice != base, "a message changed in transit")
        #expect(try self.words(aliceNonce: nonce(9)).alice != base)
        #expect(try self.words(bobNonce: nonce(9)).alice != base)
        // The same two nonces attributed the other way round are the same exchange to both phones: sorted.
        #expect(try self.words(aliceNonce: nonce(2), bobNonce: nonce(1)).alice == base)
    }

    @Test("A classical exchange's words are not the transport key's output, and differ at every exchange")
    func classicalIsNoLongerTheTransportKey() throws {
        let committed = try self.words().alice
        let transport = try #require(self.alice.identity.createSharedSecret(using: self.bob.identity.retrieveIdentity()))
        #expect(committed != transport.withUnsafeBytes { Data($0) })
        #expect(try self.words(aliceNonce: nonce(5), bobNonce: nonce(6)).alice != committed, "the same two phones, another exchange")
    }

    @Test("Both phones derive the same routing key, which is not the words key and not the old routing key")
    func routingKey() throws {
        let q = quantum()
        let alicePK = try self.alice.pairwiseECDH(with: self.bob.agreementPublic)
        let bobPK = try self.bob.pairwiseECDH(with: self.alice.agreementPublic)
        let a = try #require(self.alice.identity.createCommittedRoutingKey(
            peerP256Material: try self.bob.identity.retrieveIdentity(), pairwiseECDH: alicePK, ourAgreementKey: self.alice.agreementPublic,
            peerAgreementKey: self.bob.agreementPublic, quantumMaterial: q.alice, ourNonce: nonce(1), peerNonce: nonce(2),
            exchangeTranscript: self.transcript))
        let b = try #require(self.bob.identity.createCommittedRoutingKey(
            peerP256Material: try self.alice.identity.retrieveIdentity(), pairwiseECDH: bobPK, ourAgreementKey: self.bob.agreementPublic,
            peerAgreementKey: self.alice.agreementPublic, quantumMaterial: q.bob, ourNonce: nonce(2), peerNonce: nonce(1),
            exchangeTranscript: self.transcript))
        #expect(a == b && a.count == 32)
        #expect(a != (try self.words(pairKeys: true, hybrid: true).alice))

        let identityECDH = try #require(self.alice.identity.rawECDHWithSalt(peerP256Material: try self.bob.identity.retrieveIdentity())).rawECDH
        let old = try #require(RoutingKey.derive(
            pairwiseECDH: alicePK, identityECDH: identityECDH, ourAgreementKey: self.alice.agreementPublic,
            peerAgreementKey: self.bob.agreementPublic, mlkemSecrets: (q.alice.encapsulatedSecret, q.alice.decapsulatedSecret),
            ourNonce: nonce(1), peerNonce: nonce(2), transcript: self.transcript))
        #expect(a != old, "the committed derivation has a domain of its own")

        let other = try #require(self.alice.identity.createCommittedRoutingKey(
            peerP256Material: try self.bob.identity.retrieveIdentity(), pairwiseECDH: alicePK, ourAgreementKey: self.alice.agreementPublic,
            peerAgreementKey: self.bob.agreementPublic, quantumMaterial: q.alice, ourNonce: nonce(1), peerNonce: nonce(2),
            exchangeTranscript: Data(repeating: 0x78, count: 32)))
        #expect(other != a, "the routing key covers the transcript")
    }

    @Test("Inputs of the wrong size derive nothing")
    func wrongSizes() {
        let key = Data(repeating: 1, count: 32), salt = Data(repeating: 2, count: 65)
        #expect(RoutingKey.wordsKeyCommitted(pairwiseECDH: nil, identityECDH: key, identitySalt: salt, mlkemSecrets: nil, ourNonce: nonce(1), peerNonce: nonce(2), exchangeTranscript: self.transcript) != nil)
        #expect(RoutingKey.wordsKeyCommitted(pairwiseECDH: nil, identityECDH: key, identitySalt: salt, mlkemSecrets: nil, ourNonce: nonce(1), peerNonce: nonce(2), exchangeTranscript: Data(count: 31)) == nil)
        #expect(RoutingKey.wordsKeyCommitted(pairwiseECDH: Data(count: 31), identityECDH: key, identitySalt: salt, mlkemSecrets: nil, ourNonce: nonce(1), peerNonce: nonce(2), exchangeTranscript: self.transcript) == nil)
        #expect(RoutingKey.wordsKeyCommitted(pairwiseECDH: nil, identityECDH: key, identitySalt: salt, mlkemSecrets: nil, ourNonce: nonce(1), peerNonce: nonce(1), exchangeTranscript: self.transcript) == nil, "equal nonces")
        #expect(RoutingKey.wordsKeyCommitted(pairwiseECDH: nil, identityECDH: key, identitySalt: Data(count: 64), mlkemSecrets: nil, ourNonce: nonce(1), peerNonce: nonce(2), exchangeTranscript: self.transcript) == nil)
    }
}

// MARK: - The words the screen shows

@MainActor
@Suite("Bugs 198 and 199 — the words for each shape of payload")
struct ExchangeWordsTests {

    private let alice = TestKeyManager()
    private let bob = TestKeyManager()

    private func payload(
        peer: TestKeyManager, committed: ExchangeManager.ExchangePhase.Payload.Committed, hybrid: ExchangeManager.HybridExchangeResult? = nil
    ) throws -> ExchangeManager.ExchangePhase.Payload {
        .init(
            fingerprint: Data(count: 32), classicalKey: try peer.retrieveIdentity(), hybridResult: hybrid, committed: committed
        )
    }

    private func committed(_ ours: UInt8, _ theirs: UInt8, transcript: UInt8 = 0x11) -> ExchangeManager.ExchangePhase.Payload.Committed {
        .init(ourNonce: nonce(ours), peerNonce: nonce(theirs), transcript: Data(repeating: transcript, count: 32))
    }

    @Test("A committed classical exchange: both phones show the same words, and they are not the transport key's")
    func committedClassical() throws {
        let a = KeyExchange.words(for: try self.payload(peer: self.bob, committed: self.committed(1, 2)), using: self.alice)
        let b = KeyExchange.words(for: try self.payload(peer: self.alice, committed: self.committed(2, 1)), using: self.bob)
        #expect(a == b && a.count == 5)

        let transport = try #require(self.alice.createSharedSecret(using: self.bob.retrieveIdentity()))
        let transportWords = Manager.PassphraseGenerator().generate(separator: "-", sharedKey: transport.withUnsafeBytes { Data($0) })
        #expect(a != transportWords.components(separatedBy: "-"), "no path derives the words an older build shows")
    }

    @Test("Bug 199: a payload that holds an ML-KEM result and one that holds none show different words, other inputs equal")
    func quantumResultIsCovered() throws {
        let result = ExchangeManager.HybridExchangeResult(
            peerP256PublicKey: try self.bob.retrieveIdentity(), mlkemSecret1: Data(repeating: 0x31, count: 32),
            mlkemSecret2: Data(repeating: 0x32, count: 32), committed: self.committed(1, 2),
            ourCiphertext: Data(repeating: 0x41, count: 16), peerCiphertext: Data(repeating: 0x42, count: 16)
        )
        let withKey = KeyExchange.words(for: try self.payload(peer: self.bob, committed: self.committed(1, 2), hybrid: result), using: self.alice)
        let without = KeyExchange.words(for: try self.payload(peer: self.bob, committed: self.committed(1, 2)), using: self.alice)
        #expect(withKey != without)
    }

    @Test("Two committed exchanges that differ only in a message of the transcript show different words")
    func transcriptIsCovered() throws {
        let one = KeyExchange.words(for: try self.payload(peer: self.bob, committed: self.committed(1, 2, transcript: 0x11)), using: self.alice)
        let two = KeyExchange.words(for: try self.payload(peer: self.bob, committed: self.committed(1, 2, transcript: 0x12)), using: self.alice)
        #expect(one != two)
    }
}

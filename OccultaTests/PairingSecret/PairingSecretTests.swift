//
//  PairingSecretTests.swift
//  OccultaTests
//
//  Bug 196 — a secret per pairing. The wire half: routing tags, the sender proof, key binding, and the fields that
//  carry them.
//

import Testing
import Foundation
import CryptoKit
@testable import OccultaFormats

@Suite("Bug 196 — pairing secret: wire functions")
struct PairingSecretTests {

    private func secret(_ byte: UInt8) -> Data { Data(repeating: byte, count: PairingSecret.size) }

    // MARK: Routing tags

    @Test("A routing tag is 32 bytes and follows the secret and the nonce")
    func tagDependsOnSecretAndNonce() {
        let nonce = Data(repeating: 0x11, count: 16)
        let tag = PairingSecret.routingTag(secret: self.secret(1), nonce: nonce)
        #expect(tag.count == 32)
        #expect(tag == PairingSecret.routingTag(secret: self.secret(1), nonce: nonce))
        #expect(tag != PairingSecret.routingTag(secret: self.secret(2), nonce: nonce))
        #expect(tag != PairingSecret.routingTag(secret: self.secret(1), nonce: Data(repeating: 0x12, count: 16)))
    }

    @Test("A routing tag is not the identity fingerprint of anything it was made from")
    func tagIsNotTheFingerprint() {
        let nonce = Data(repeating: 0x11, count: 16)
        let key = self.secret(1)
        #expect(PairingSecret.routingTag(secret: key, nonce: nonce)
                != OccultaBundle.SecrecyContext.fingerprint(for: key, nonce: nonce))
    }

    @Test("A filler routing tag is 32 random bytes")
    func fillerTag() throws {
        let one = try PairingSecret.fillerTag(), two = try PairingSecret.fillerTag()
        #expect(one.count == 32)
        #expect(one != two)
    }

    // MARK: Sender proof

    @Test("The slot proof fails when the routing tag or the sender key is swapped, or the secret is another's")
    func slotProofCoversTagAndSender() {
        let tag = Data(repeating: 0xAA, count: 32), sender = Data(repeating: 0x04, count: 65)
        let proof = PairingSecret.slotProof(secret: self.secret(1), routingTag: tag, senderPublicKey: sender)
        #expect(proof == PairingSecret.slotProof(secret: self.secret(1), routingTag: tag, senderPublicKey: sender))
        #expect(proof != PairingSecret.slotProof(secret: self.secret(1), routingTag: Data(repeating: 0xAB, count: 32), senderPublicKey: sender))
        #expect(proof != PairingSecret.slotProof(secret: self.secret(1), routingTag: tag, senderPublicKey: Data(repeating: 0x05, count: 65)))
        #expect(proof != PairingSecret.slotProof(secret: self.secret(2), routingTag: tag, senderPublicKey: sender))
    }

    // MARK: Key binding

    @Test("Binding changes the key, deterministically, and differs per secret")
    func bindingChangesTheKey() {
        let key = SymmetricKey(data: Data(repeating: 0x42, count: 32))
        let bound = PairingSecret.bind(key, secret: self.secret(1))
        func bytes(_ k: SymmetricKey) -> Data { k.withUnsafeBytes { Data($0) } }
        #expect(bytes(bound) != bytes(key))
        #expect(bytes(bound) == bytes(PairingSecret.bind(key, secret: self.secret(1))))
        #expect(bytes(bound) != bytes(PairingSecret.bind(key, secret: self.secret(2))))
    }

    // MARK: Fields

    @Test("A slot without the new fields still decodes, and a new slot carries them")
    func slotsDecodeBothWays() throws {
        let old = #"{"secrecyContext":{"mode":"longTermNoPQ","ephemeralPublicKey":"","prekeyID":null},"wrappedPayload":"AA=="}"#
        #expect(try JSONDecoder().decode(OccultaBundle.Recipient.self, from: Data(old.utf8)).routingTag == nil)
        let payload = #"{"sessionKey":"AA=="}"#
        let decoded = try JSONDecoder().decode(OccultaBundle.RecipientPayload.self, from: Data(payload.utf8))
        #expect(decoded.slotProof == nil)

        let tag = try PairingSecret.fillerTag()
        let slot = OccultaBundle.Recipient(
            secrecyContext: .init(mode: .longTermNoPQ, ephemeralPublicKey: Data(), prekeyID: nil),
            wrappedPayload: Data([1]), routingTag: tag
        )
        #expect(try JSONDecoder().decode(OccultaBundle.Recipient.self, from: JSONEncoder().encode(slot)).routingTag == tag)
    }

    // MARK: The tier

    @Test("The tier is 2.0.1, its marker byte is 0x0B, and it is the most capable")
    func tier() {
        #expect(OccultaBundle.Version.max(forAppVersion: "2.0.1") == .pairingSecretCapable)
        #expect(OccultaBundle.Version.max(forAppVersion: "2.0.0") == .streamedBodyCapable)
        #expect(OccultaBundle.Version.pairingSecretCapable.wireByte == 0x0B)
        #expect(WireHandle.byteToVersion(0x0B) == .pairingSecretCapable)
        #expect(OccultaBundle.Version.mostCapable == .pairingSecretCapable)
        #expect(OccultaBundle.Version.pairingSecretCapable.isAtLeast(.streamedBodyCapable))
        #expect(!OccultaBundle.Version.streamedBodyCapable.isAtLeast(.pairingSecretCapable))
    }
}

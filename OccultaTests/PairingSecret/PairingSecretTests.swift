//
//  PairingSecretTests.swift
//  OccultaTests
//
//  Bug 196 — a secret per pairing. The wire half: routing tags, the sender proof, key binding, the swap's combining
//  and confirmation, and the fields that carry them.
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

    // MARK: The swap

    @Test("Crossing halves agree whichever side's half is first")
    func combineIsSymmetric() throws {
        let a = try PairingSecret.newHalf(), b = try PairingSecret.newHalf()
        #expect(try PairingSecret.combine(a, b) == (try PairingSecret.combine(b, a)))
        #expect(try PairingSecret.combine(a, b).count == 32)
    }

    @Test("Different halves make a different secret")
    func combineDiffers() throws {
        let a = try PairingSecret.newHalf(), b = try PairingSecret.newHalf(), c = try PairingSecret.newHalf()
        #expect(try PairingSecret.combine(a, b) != (try PairingSecret.combine(a, c)))
    }

    @Test("The same half twice, or a half of the wrong size, makes no secret")
    func combineRefusesBadHalves() throws {
        let a = try PairingSecret.newHalf()
        #expect(throws: PairingSecret.SecretError.identicalHalves) { try PairingSecret.combine(a, a) }
        #expect(throws: PairingSecret.SecretError.malformed) { try PairingSecret.combine(a, Data(count: 31)) }
    }

    @Test("A confirmation verifies for the half it was made over and for no other")
    func confirmationBindsTheSendersHalf() throws {
        let mine = try PairingSecret.newHalf(), theirs = try PairingSecret.newHalf()
        let secret = try PairingSecret.combine(mine, theirs)
        let confirmation = PairingSecret.confirmation(secret: secret, ownHalf: theirs)
        #expect(PairingSecret.isValidConfirmation(confirmation, secret: secret, peerHalf: theirs))
        // Reflected back at its sender, over the wrong half: confirms nothing.
        #expect(!PairingSecret.isValidConfirmation(confirmation, secret: secret, peerHalf: mine))
        #expect(!PairingSecret.isValidConfirmation(confirmation, secret: self.secret(9), peerHalf: theirs))
        #expect(!PairingSecret.isValidConfirmation(Data(count: 32), secret: secret, peerHalf: theirs))
    }

    // MARK: Fields

    @Test("A swap round-trips through JSON, and an unknown kind decodes to .unsupported")
    func swapCodable() throws {
        let swap = PairingSecretSwap(kind: .half, key: self.secret(3), confirmation: self.secret(4))
        #expect(try JSONDecoder().decode(PairingSecretSwap.self, from: JSONEncoder().encode(swap)) == swap)
        let future = #"{"kind":"rekey","key":"AA==","confirmation":"AA=="}"#
        #expect(try JSONDecoder().decode(PairingSecretSwap.self, from: Data(future.utf8)).kind == .unsupported)
    }

    /// Foundation writes `/` in base64 as `\/`, so two random values differ in length by the slashes they happen to
    /// hold. Real halves and filler are both random, so that spread is the same for both; with the escape off the
    /// lengths are equal exactly.
    @Test("Filler and a real swap encode to the same length")
    func swapSizesMatch() throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let real = PairingSecretSwap(kind: .half, key: try PairingSecret.newHalf(), confirmation: try PairingSecret.newHalf())
        let filler = try PairingSecretSwap.filler()
        #expect(filler.kind == .none)
        #expect(try encoder.encode(real).count == encoder.encode(filler).count)
    }

    @Test("A slot without the new fields still decodes, and a new slot carries them")
    func slotsDecodeBothWays() throws {
        let old = #"{"secrecyContext":{"mode":"longTermNoPQ","ephemeralPublicKey":"","prekeyID":null},"wrappedPayload":"AA=="}"#
        #expect(try JSONDecoder().decode(OccultaBundle.Recipient.self, from: Data(old.utf8)).routingTag == nil)
        let payload = #"{"sessionKey":"AA=="}"#
        let decoded = try JSONDecoder().decode(OccultaBundle.RecipientPayload.self, from: Data(payload.utf8))
        #expect(decoded.pairingSwap == nil && decoded.slotProof == nil)

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

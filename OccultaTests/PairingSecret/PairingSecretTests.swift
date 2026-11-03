//
//  PairingSecretTests.swift
//  OccultaTests
//
//  Bug 196 — a secret per pairing. The wire half: labels, the sender proof, key binding, the swap's combining
//  and confirmation, and the fields that carry them.
//

import Testing
import Foundation
import CryptoKit
@testable import OccultaFormats

@Suite("Bug 196 — pairing secret: wire functions")
struct PairingSecretTests {

    private func secret(_ byte: UInt8) -> Data { Data(repeating: byte, count: PairingSecret.size) }

    // MARK: Labels

    @Test("A label is 32 bytes and follows the secret and the nonce")
    func labelDependsOnSecretAndNonce() {
        let nonce = Data(repeating: 0x11, count: 16)
        let label = PairingSecret.label(secret: self.secret(1), nonce: nonce)
        #expect(label.count == 32)
        #expect(label == PairingSecret.label(secret: self.secret(1), nonce: nonce))
        #expect(label != PairingSecret.label(secret: self.secret(2), nonce: nonce))
        #expect(label != PairingSecret.label(secret: self.secret(1), nonce: Data(repeating: 0x12, count: 16)))
    }

    @Test("A label is not the identity fingerprint of anything it was made from")
    func labelIsNotTheFingerprint() {
        let nonce = Data(repeating: 0x11, count: 16)
        let key = self.secret(1)
        #expect(PairingSecret.label(secret: key, nonce: nonce)
                != OccultaBundle.SecrecyContext.fingerprint(for: key, nonce: nonce))
    }

    @Test("A filler label is 32 random bytes")
    func fillerLabel() throws {
        let one = try PairingSecret.fillerLabel(), two = try PairingSecret.fillerLabel()
        #expect(one.count == 32)
        #expect(one != two)
    }

    // MARK: Sender proof

    @Test("The slot proof fails when the label or the sender key is swapped, or the secret is another's")
    func slotProofCoversLabelAndSender() {
        let label = Data(repeating: 0xAA, count: 32), sender = Data(repeating: 0x04, count: 65)
        let proof = PairingSecret.slotProof(secret: self.secret(1), label: label, senderPublicKey: sender)
        #expect(proof == PairingSecret.slotProof(secret: self.secret(1), label: label, senderPublicKey: sender))
        #expect(proof != PairingSecret.slotProof(secret: self.secret(1), label: Data(repeating: 0xAB, count: 32), senderPublicKey: sender))
        #expect(proof != PairingSecret.slotProof(secret: self.secret(1), label: label, senderPublicKey: Data(repeating: 0x05, count: 65)))
        #expect(proof != PairingSecret.slotProof(secret: self.secret(2), label: label, senderPublicKey: sender))
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

    @Test("Filler and a real swap encode to the same length")
    func swapSizesMatch() throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = .sortedKeys
        let real = PairingSecretSwap(kind: .half, key: self.secret(3), confirmation: self.secret(4))
        let filler = try PairingSecretSwap.filler()
        #expect(filler.kind == .none)
        #expect(try encoder.encode(real).count == encoder.encode(filler).count)
    }

    @Test("A slot without the new fields still decodes, and a new slot carries them")
    func slotsDecodeBothWays() throws {
        let old = #"{"secrecyContext":{"mode":"longTermNoPQ","ephemeralPublicKey":"","prekeyID":null},"wrappedPayload":"AA=="}"#
        #expect(try JSONDecoder().decode(OccultaBundle.Recipient.self, from: Data(old.utf8)).label == nil)
        let payload = #"{"sessionKey":"AA=="}"#
        let decoded = try JSONDecoder().decode(OccultaBundle.RecipientPayload.self, from: Data(payload.utf8))
        #expect(decoded.pairingSwap == nil && decoded.slotProof == nil)

        let label = try PairingSecret.fillerLabel()
        let slot = OccultaBundle.Recipient(
            secrecyContext: .init(mode: .longTermNoPQ, ephemeralPublicKey: Data(), prekeyID: nil),
            wrappedPayload: Data([1]), label: label
        )
        #expect(try JSONDecoder().decode(OccultaBundle.Recipient.self, from: JSONEncoder().encode(slot)).label == label)
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

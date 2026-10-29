//
//  CardBootstrapTests.swift
//  OccultaTests
//
//  The bootstrap layer of a card conversation's slots and Carol's inner key
//  (`Docs/Features/Introduction Cards/SPEC.md` §4.3). Software keys only.
//
//  Main actor: the comparison with the ordinary derivation calls `Manager.Key`.
//

import Testing
import CryptoKit
import Foundation

@testable import Occulta
@testable import OccultaFormats

@MainActor
@Suite("Card bootstrap — layers and Carol's inner key (SPEC §4.3)")
struct CardBootstrapTests {

    private struct Slot {
        let payload         = randomBytes(300)
        let mlkemCiphertext = randomBytes(1_568)
        let outerKey        = SymmetricKey(size: .bits256)
        let innerKey        = SymmetricKey(size: .bits256)
        let blind           = randomBytes(32)

        func sealed() throws -> Data {
            try CardBootstrap.seal(
                payload: self.payload, mlkemCiphertext: self.mlkemCiphertext,
                outerKey: self.outerKey, innerKey: self.innerKey, blind: self.blind
            )
        }
    }

    private func bytes(_ key: SymmetricKey) -> Data { key.withUnsafeBytes { Data($0) } }

    // MARK: - Layers

    @Test("seal, openOuter and openInner round-trip")
    func roundTrip() throws {
        let slot    = Slot()
        let wrapped = try slot.sealed()

        let outer = try CardBootstrap.openOuter(wrapped, outerKey: slot.outerKey, blind: slot.blind)
        #expect(outer.mlkemCiphertext == slot.mlkemCiphertext)

        let payload = try CardBootstrap.openInner(
            outer.inner, mlkemCiphertext: outer.mlkemCiphertext, innerKey: slot.innerKey, blind: slot.blind
        )
        #expect(payload == slot.payload)
    }

    @Test("The sealed size is nonce and tag around ct ‖ (nonce and tag around the payload)")
    func sealedSize() throws {
        let slot = Slot()
        #expect(try slot.sealed().count == 12 + 1_568 + (12 + slot.payload.count + 16) + 16)
        #expect(CardBootstrap.mlkemCiphertextCount == 1_568)
    }

    @Test("An empty payload round-trips")
    func emptyPayload() throws {
        let slot = Slot()
        let wrapped = try CardBootstrap.seal(
            payload: Data(), mlkemCiphertext: slot.mlkemCiphertext, outerKey: slot.outerKey, innerKey: slot.innerKey, blind: slot.blind
        )
        let outer = try CardBootstrap.openOuter(wrapped, outerKey: slot.outerKey, blind: slot.blind)
        #expect(try CardBootstrap.openInner(outer.inner, mlkemCiphertext: outer.mlkemCiphertext, innerKey: slot.innerKey, blind: slot.blind).isEmpty)
    }

    @Test("Two seals of the same input differ: the nonces are random")
    func sealsAreRandomised() throws {
        let slot = Slot()
        #expect(try slot.sealed() != slot.sealed())
    }

    @Test("A wrong blind fails both layers")
    func wrongBlindFails() throws {
        let slot    = Slot()
        let wrapped = try slot.sealed()
        let other   = randomBytes(32)

        #expect(throws: (any Error).self) { try CardBootstrap.openOuter(wrapped, outerKey: slot.outerKey, blind: other) }

        let outer = try CardBootstrap.openOuter(wrapped, outerKey: slot.outerKey, blind: slot.blind)
        #expect(throws: (any Error).self) {
            try CardBootstrap.openInner(outer.inner, mlkemCiphertext: outer.mlkemCiphertext, innerKey: slot.innerKey, blind: other)
        }
    }

    @Test("A wrong outer key fails the outer layer; the inner key can't stand in for it")
    func wrongOuterKeyFails() throws {
        let slot    = Slot()
        let wrapped = try slot.sealed()

        #expect(throws: (any Error).self) { try CardBootstrap.openOuter(wrapped, outerKey: SymmetricKey(size: .bits256), blind: slot.blind) }
        #expect(throws: (any Error).self) { try CardBootstrap.openOuter(wrapped, outerKey: slot.innerKey, blind: slot.blind) }
    }

    @Test("A wrong inner key opens the outer layer and fails the inner one")
    func wrongInnerKeyFails() throws {
        let slot    = Slot()
        let wrapped = try slot.sealed()
        let outer   = try CardBootstrap.openOuter(wrapped, outerKey: slot.outerKey, blind: slot.blind)

        #expect(throws: (any Error).self) {
            try CardBootstrap.openInner(outer.inner, mlkemCiphertext: outer.mlkemCiphertext, innerKey: SymmetricKey(size: .bits256), blind: slot.blind)
        }
        #expect(throws: (any Error).self) {
            try CardBootstrap.openInner(outer.inner, mlkemCiphertext: outer.mlkemCiphertext, innerKey: slot.outerKey, blind: slot.blind)
        }
    }

    @Test("Swapping the ML-KEM ciphertext inside the layer fails the inner open: the AAD binds it")
    func swappedCiphertextFailsInner() throws {
        let slot    = Slot()
        let wrapped = try slot.sealed()

        // The attacker holds the outer key (it derives from the public ECDH) and rebuilds a valid outer layer
        // around a different ciphertext, leaving the inner box as it was.
        let layer = try AES.GCM.open(try AES.GCM.SealedBox(combined: wrapped), using: slot.outerKey, authenticating: slot.blind)
        let innerBytes = Data(layer.dropFirst(1_568))
        let otherCiphertext = randomBytes(1_568)
        let rewrapped = try #require(
            try AES.GCM.seal(otherCiphertext + innerBytes, using: slot.outerKey, authenticating: slot.blind).combined
        )

        let outer = try CardBootstrap.openOuter(rewrapped, outerKey: slot.outerKey, blind: slot.blind)
        #expect(outer.mlkemCiphertext == otherCiphertext, "control: the outer layer opens and returns the swapped ciphertext")
        #expect(throws: (any Error).self) {
            try CardBootstrap.openInner(outer.inner, mlkemCiphertext: outer.mlkemCiphertext, innerKey: slot.innerKey, blind: slot.blind)
        }

        // And directly: the true inner box under a different ciphertext.
        let original = try CardBootstrap.openOuter(wrapped, outerKey: slot.outerKey, blind: slot.blind)
        #expect(throws: (any Error).self) {
            try CardBootstrap.openInner(original.inner, mlkemCiphertext: otherCiphertext, innerKey: slot.innerKey, blind: slot.blind)
        }
    }

    @Test("A ciphertext that is not 1,568 bytes throws wrongCiphertextLength, on seal and on openInner")
    func wrongCiphertextLengthThrows() throws {
        let slot = Slot()
        for count in [0, 1, 1_567, 1_569, 3_136] {
            #expect(throws: CardBootstrap.BootstrapError.wrongCiphertextLength, "seal with \(count) bytes") {
                try CardBootstrap.seal(
                    payload: slot.payload, mlkemCiphertext: randomBytes(count),
                    outerKey: slot.outerKey, innerKey: slot.innerKey, blind: slot.blind
                )
            }
        }

        let outer = try CardBootstrap.openOuter(try slot.sealed(), outerKey: slot.outerKey, blind: slot.blind)
        for count in [0, 1_567, 1_569] {
            #expect(throws: CardBootstrap.BootstrapError.wrongCiphertextLength, "openInner with \(count) bytes") {
                try CardBootstrap.openInner(outer.inner, mlkemCiphertext: randomBytes(count), innerKey: slot.innerKey, blind: slot.blind)
            }
        }
    }

    @Test("Truncated or too-short input throws malformed from openOuter, and openInner on junk throws malformed")
    func truncatedInputIsMalformed() throws {
        let slot    = Slot()
        let wrapped = try slot.sealed()

        // Shorter than the two layers' overhead plus the ciphertext: refused before any key is tried.
        for count in [0, 1, 12, 28, 100, 1_623] {
            #expect(throws: CardBootstrap.BootstrapError.malformed, "\(count) bytes") {
                try CardBootstrap.openOuter(wrapped.prefix(count), outerKey: slot.outerKey, blind: slot.blind)
            }
        }
        // Long enough but cut: the tag no longer matches.
        #expect(throws: (any Error).self) { try CardBootstrap.openOuter(Data(wrapped.dropLast()), outerKey: slot.outerKey, blind: slot.blind) }
        #expect(throws: (any Error).self) { try CardBootstrap.openOuter(Data(wrapped.dropFirst()), outerKey: slot.outerKey, blind: slot.blind) }

        #expect(throws: CardBootstrap.BootstrapError.malformed) {
            try CardBootstrap.openInner(Data(count: 10), mlkemCiphertext: slot.mlkemCiphertext, innerKey: slot.innerKey, blind: slot.blind)
        }
        #expect(throws: CardBootstrap.BootstrapError.malformed) {
            try CardBootstrap.openInner(Data(), mlkemCiphertext: slot.mlkemCiphertext, innerKey: slot.innerKey, blind: slot.blind)
        }
    }

    @Test("Flipping any byte of the wrapped payload fails the outer open")
    func flippedByteFailsOuter() throws {
        let slot    = Slot()
        let wrapped = try slot.sealed()
        var accepted: [Int] = []
        for offset in stride(from: 0, to: wrapped.count, by: 7) + [wrapped.count - 1] {
            var edited = [UInt8](wrapped)
            edited[offset] ^= 0x01
            if (try? CardBootstrap.openOuter(Data(edited), outerKey: slot.outerKey, blind: slot.blind)) != nil { accepted.append(offset) }
        }
        #expect(accepted.isEmpty)
    }

    @Test("Slices open, whatever their start index")
    func slicesOpen() throws {
        let slot    = Slot()
        let wrapped = try slot.sealed()
        let framed  = Data(repeating: 0xAA, count: 9) + wrapped + Data(repeating: 0xBB, count: 4)
        let slice   = framed[9 ..< 9 + wrapped.count]

        let outer = try CardBootstrap.openOuter(slice, outerKey: slot.outerKey, blind: slot.blind)
        #expect(outer.mlkemCiphertext == slot.mlkemCiphertext)

        let innerFramed = Data(repeating: 0xCC, count: 3) + outer.inner
        let payload = try CardBootstrap.openInner(
            innerFramed.dropFirst(3), mlkemCiphertext: outer.mlkemCiphertext, innerKey: slot.innerKey, blind: slot.blind
        )
        #expect(payload == slot.payload)
    }

    // MARK: - Carol's inner key

    @Test("carolInnerKey gives the same key with own and peer swapped, so neither side needs to know which is Carol")
    func innerKeyIsSymmetric() throws {
        let ecdh = randomBytes(32), ss1 = randomBytes(32)
        let a = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        let b = P256.KeyAgreement.PrivateKey().publicKey.x963Representation

        let carolSide = try #require(CardBootstrap.carolInnerKey(ecdhOutput: ecdh, ownPublicKey: a, peerPublicKey: b, ss1: ss1))
        let bobSide   = try #require(CardBootstrap.carolInnerKey(ecdhOutput: ecdh, ownPublicKey: b, peerPublicKey: a, ss1: ss1))

        #expect(self.bytes(carolSide) == self.bytes(bobSide))
        #expect(self.bytes(carolSide).count == 32)
    }

    @Test("carolInnerKey depends on the ECDH output, ss1 and both public keys")
    func innerKeyDependsOnEveryInput() throws {
        let ecdh = randomBytes(32), ss1 = randomBytes(32)
        let a = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        let b = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        let c = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        let base = try #require(CardBootstrap.carolInnerKey(ecdhOutput: ecdh, ownPublicKey: a, peerPublicKey: b, ss1: ss1))

        #expect(self.bytes(base) == self.bytes(try #require(CardBootstrap.carolInnerKey(ecdhOutput: ecdh, ownPublicKey: a, peerPublicKey: b, ss1: ss1))), "deterministic")
        #expect(self.bytes(base) != self.bytes(try #require(CardBootstrap.carolInnerKey(ecdhOutput: randomBytes(32), ownPublicKey: a, peerPublicKey: b, ss1: ss1))))
        #expect(self.bytes(base) != self.bytes(try #require(CardBootstrap.carolInnerKey(ecdhOutput: ecdh, ownPublicKey: a, peerPublicKey: b, ss1: randomBytes(32)))))
        #expect(self.bytes(base) != self.bytes(try #require(CardBootstrap.carolInnerKey(ecdhOutput: ecdh, ownPublicKey: c, peerPublicKey: b, ss1: ss1))))
        #expect(self.bytes(base) != self.bytes(try #require(CardBootstrap.carolInnerKey(ecdhOutput: ecdh, ownPublicKey: a, peerPublicKey: c, ss1: ss1))))
    }

    @Test("carolInnerKey is nil for wrong sizes")
    func innerKeyRejectsWrongSizes() {
        let ecdh = randomBytes(32), ss1 = randomBytes(32), a = randomBytes(65), b = randomBytes(65)

        #expect(CardBootstrap.carolInnerKey(ecdhOutput: ecdh, ownPublicKey: a, peerPublicKey: b, ss1: ss1) != nil, "control")
        #expect(CardBootstrap.carolInnerKey(ecdhOutput: ecdh, ownPublicKey: randomBytes(64), peerPublicKey: b, ss1: ss1) == nil)
        #expect(CardBootstrap.carolInnerKey(ecdhOutput: ecdh, ownPublicKey: randomBytes(66), peerPublicKey: b, ss1: ss1) == nil)
        #expect(CardBootstrap.carolInnerKey(ecdhOutput: ecdh, ownPublicKey: a, peerPublicKey: randomBytes(64), ss1: ss1) == nil)
        #expect(CardBootstrap.carolInnerKey(ecdhOutput: ecdh, ownPublicKey: a, peerPublicKey: randomBytes(66), ss1: ss1) == nil)
        #expect(CardBootstrap.carolInnerKey(ecdhOutput: ecdh, ownPublicKey: a, peerPublicKey: b, ss1: randomBytes(31)) == nil)
        #expect(CardBootstrap.carolInnerKey(ecdhOutput: ecdh, ownPublicKey: a, peerPublicKey: b, ss1: randomBytes(33)) == nil)
        #expect(CardBootstrap.carolInnerKey(ecdhOutput: ecdh, ownPublicKey: Data(), peerPublicKey: Data(), ss1: Data()) == nil)
    }

    @Test("Carol's inner key differs from the ordinary derivation for the same ECDH, classical and hybrid (SPEC §11)")
    func innerKeyDiffersFromOrdinaryKeys() throws {
        let ecdh = randomBytes(32), ss1 = randomBytes(32), ss2 = randomBytes(32)
        let own  = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        let peer = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        let inner = self.bytes(try #require(CardBootstrap.carolInnerKey(ecdhOutput: ecdh, ownPublicKey: own, peerPublicKey: peer, ss1: ss1)))

        // K_outer: the classical derivation.
        let outer = self.bytes(try #require(
            Manager.Key.forwardSecretSessionKey(ecdhOutput: ecdh, ownPublicKey: own, peerMaterial: peer, quantumMaterial: nil)
        ))
        #expect(inner != outer)

        // The ordinary hybrid key, with ss1 among its inputs.
        let material = QuantumKeyMaterial(
            encapsulatedSecret: ss1, decapsulatedSecret: ss2, ourCiphertext: randomBytes(1_568), peerCiphertext: randomBytes(1_568)
        )
        let hybrid = self.bytes(try #require(
            Manager.Key.forwardSecretSessionKey(ecdhOutput: ecdh, ownPublicKey: own, peerMaterial: peer, quantumMaterial: material)
        ))
        #expect(inner != hybrid)
        #expect(outer != hybrid, "control: the two ordinary derivations differ from each other")

        // Even when the hybrid material is built from ss1 on both sides.
        let doubled = QuantumKeyMaterial(encapsulatedSecret: ss1, decapsulatedSecret: ss1, ourCiphertext: Data(), peerCiphertext: Data())
        let hybridSame = self.bytes(try #require(
            Manager.Key.forwardSecretSessionKey(ecdhOutput: ecdh, ownPublicKey: own, peerMaterial: peer, quantumMaterial: doubled)
        ))
        #expect(inner != hybridSame)
    }
}

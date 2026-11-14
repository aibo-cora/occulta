//
//  TransportKeyDerivationTests.swift
//  OccultaCoreAPITests
//
//  TransportKeyDerivation through the public API only. The bytes themselves are pinned by the app's
//  interop vectors (fsKey, ltKey, diceware, card.v1.longTermKey), which need Occulta's own labels.
//

import Testing
import Foundation
import CryptoKit
import OccultaCore

@Suite("OccultaCore public API — transport key derivation")
struct TransportKeyDerivationPublicAPITests {

    // The function checks lengths, not curve points, so fixed bytes of the right length stand in for the keys.
    private static let ecdhOutput = Data(repeating: 0x9a, count: 32)
    private static let alice      = Data([0x04] + [UInt8](repeating: 0x11, count: 64))
    private static let bob        = Data([0x04] + [UInt8](repeating: 0x33, count: 64))
    private static let secrets    = (Data(repeating: 0xa5, count: 32), Data(repeating: 0x5a, count: 32))
    private static let info       = Data("host-app-transport-v1".utf8)

    private func key(
        ecdh: Data = Self.ecdhOutput, own: Data = Self.alice, peer: Data = Self.bob,
        secrets: (Data, Data)? = Self.secrets, info: Data = Self.info
    ) throws(TransportKeyDerivation.Error) -> Data {
        try TransportKeyDerivation.sessionKey(
            ecdhOutput: ecdh, ownPublicKey: own, peerPublicKey: peer, postQuantumSecrets: secrets, info: info
        ).withUnsafeBytes { Data($0) }
    }

    @Test("The key is 32 bytes and deterministic")
    func deterministic() throws {
        let first = try self.key()
        #expect(first.count == 32)
        #expect(try self.key() == first)
    }

    @Test("A different info gives a different key")
    func infoSeparates() throws {
        let key = try self.key()
        #expect(try self.key(info: Data("host-app-transport-v2".utf8)) != key)
        #expect(try self.key(info: Data()) != key)
    }

    @Test("The classical and hybrid forms differ for the same inputs")
    func classicalIsNotHybrid() throws {
        let hybrid = try self.key()
        let classical = try self.key(secrets: nil)
        #expect(classical != hybrid)
    }

    @Test("Swapping the two ML-KEM secrets gives the same key")
    func secretOrderDoesNotMatter() throws {
        let key = try self.key()
        #expect(try self.key(secrets: (Self.secrets.1, Self.secrets.0)) == key)
    }

    @Test("Both sides derive the same key, each passing its own public key as own")
    func bothSidesAgree() throws {
        let aliceSide = try self.key(own: Self.alice, peer: Self.bob)
        let bobSide = try self.key(own: Self.bob, peer: Self.alice, secrets: (Self.secrets.1, Self.secrets.0))
        #expect(aliceSide == bobSide)
    }

    @Test("A public key that is not 65 bytes is rejected, naming which", arguments: [0, 33, 64, 66])
    func wrongLengthPublicKey(length: Int) {
        let wrong = Data(repeating: 0x04, count: length)
        #expect(throws: TransportKeyDerivation.Error.invalidOwnPublicKeyLength) { try self.key(own: wrong) }
        #expect(throws: TransportKeyDerivation.Error.invalidPeerPublicKeyLength) { try self.key(peer: wrong) }
        #expect(throws: TransportKeyDerivation.Error.invalidOwnPublicKeyLength) { try self.key(own: wrong, secrets: nil) }
        #expect(throws: TransportKeyDerivation.Error.invalidPeerPublicKeyLength) { try self.key(peer: wrong, secrets: nil) }
    }

    @Test("An ECDH output that is not 32 bytes is rejected, in both forms", arguments: [0, 16, 31, 33, 64])
    func wrongLengthECDHOutput(length: Int) {
        let wrong = Data(repeating: 0x9a, count: length)
        #expect(throws: TransportKeyDerivation.Error.invalidECDHOutputLength) { try self.key(ecdh: wrong, secrets: nil) }
        #expect(throws: TransportKeyDerivation.Error.invalidECDHOutputLength) { try self.key(ecdh: wrong) }
    }

    @Test("An ML-KEM secret that is not 32 bytes is rejected", arguments: [0, 16, 31, 33, 64])
    func wrongLengthSecret(length: Int) {
        let wrong = Data(repeating: 0xa5, count: length)
        #expect(throws: TransportKeyDerivation.Error.invalidPostQuantumSecretLength) {
            try self.key(secrets: (wrong, Self.secrets.1))
        }
        #expect(throws: TransportKeyDerivation.Error.invalidPostQuantumSecretLength) {
            try self.key(secrets: (Self.secrets.0, wrong))
        }
    }

    @Test("With every input wrong, the checks fire in order: own key, peer key, ECDH output, secrets")
    func checkOrder() {
        let bad = Data()
        #expect(throws: TransportKeyDerivation.Error.invalidOwnPublicKeyLength) {
            try self.key(ecdh: bad, own: bad, peer: bad, secrets: (bad, bad))
        }
        #expect(throws: TransportKeyDerivation.Error.invalidPeerPublicKeyLength) {
            try self.key(ecdh: bad, peer: bad, secrets: (bad, bad))
        }
        #expect(throws: TransportKeyDerivation.Error.invalidECDHOutputLength) {
            try self.key(ecdh: bad, secrets: (bad, bad))
        }
        #expect(throws: TransportKeyDerivation.Error.invalidPostQuantumSecretLength) {
            try self.key(secrets: (bad, bad))
        }
    }
}

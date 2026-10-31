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
        own: Data = Self.alice, peer: Data = Self.bob, secrets: (Data, Data)? = Self.secrets, info: Data = Self.info
    ) -> Data? {
        TransportKeyDerivation.sessionKey(
            ecdhOutput: Self.ecdhOutput, ownPublicKey: own, peerPublicKey: peer, postQuantumSecrets: secrets, info: info
        )?.withUnsafeBytes { Data($0) }
    }

    @Test("The key is 32 bytes and deterministic")
    func deterministic() throws {
        let first = try #require(self.key())
        #expect(first.count == 32)
        #expect(self.key() == first)
    }

    @Test("A different info gives a different key")
    func infoSeparates() throws {
        let key = try #require(self.key())
        #expect(self.key(info: Data("host-app-transport-v2".utf8)) != key)
        #expect(self.key(info: Data()) != key)
    }

    @Test("The classical and hybrid forms differ for the same inputs")
    func classicalIsNotHybrid() throws {
        let hybrid = try #require(self.key())
        let classical = try #require(self.key(secrets: nil))
        #expect(classical != hybrid)
    }

    @Test("Swapping the two ML-KEM secrets gives the same key")
    func secretOrderDoesNotMatter() throws {
        let key = try #require(self.key())
        #expect(self.key(secrets: (Self.secrets.1, Self.secrets.0)) == key)
    }

    @Test("Both sides derive the same key, each passing its own public key as own")
    func bothSidesAgree() throws {
        let aliceSide = try #require(self.key(own: Self.alice, peer: Self.bob))
        let bobSide = try #require(self.key(own: Self.bob, peer: Self.alice, secrets: (Self.secrets.1, Self.secrets.0)))
        #expect(aliceSide == bobSide)
    }

    @Test("A public key that is not 65 bytes is rejected", arguments: [0, 33, 64, 66])
    func wrongLengthPublicKey(length: Int) {
        let wrong = Data(repeating: 0x04, count: length)
        #expect(self.key(own: wrong) == nil)
        #expect(self.key(peer: wrong) == nil)
        #expect(self.key(own: wrong, secrets: nil) == nil)
        #expect(self.key(peer: wrong, secrets: nil) == nil)
    }

    @Test("An ML-KEM secret that is not 32 bytes is rejected", arguments: [0, 16, 31, 33, 64])
    func wrongLengthSecret(length: Int) {
        let wrong = Data(repeating: 0xa5, count: length)
        #expect(self.key(secrets: (wrong, Self.secrets.1)) == nil)
        #expect(self.key(secrets: (Self.secrets.0, wrong)) == nil)
    }
}

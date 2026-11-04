//
//  PairingSaveTests.swift
//  OccultaTests
//
//  Bug 196, stage 4: what a pairing derives and installs when both phones sent a prekey batch. The secret both phones
//  derive, the first batch installed as the pending one with the peer's accepted, what a re-pair retires, and the save
//  that does it all in one go. The Multipeer flow that produces the offer cannot run in a unit test.
//
//  No Enclave: the keys here carry public keys, not blobs, which is how a pending batch is kept until it is delivered.
//

import Testing
import Foundation
import SwiftData
import CryptoKit
@testable import Occulta
@testable import OccultaFormats

// MARK: - Helpers

private func nonce(_ byte: UInt8) -> Data { Data(repeating: byte, count: 16) }

private func uuidBytes(_ uuid: UUID = UUID()) -> Data { withUnsafeBytes(of: uuid.uuid) { Data($0) } }

private func ownBatch(id: UInt8, keys: Int = 15) -> PrekeyRecord.OwnBatch {
    PrekeyRecord.OwnBatch(
        id: Data(repeating: id, count: 16), createdAt: Date(timeIntervalSinceReferenceDate: 800_000_000), retiredAt: nil,
        isPending: true,
        keys: (0..<keys).map { PrekeyRecord.OwnKey(id: uuidBytes(), blob: nil, publicKey: Data(repeating: UInt8($0 + 1), count: 65)) },
        lastResort: PrekeyRecord.OwnKey(id: uuidBytes(), blob: nil, publicKey: Data(repeating: 0xEE, count: 65))
    )
}

private func peerBatch(keys: Int = 15) -> PairingOffer.Batch {
    PairingOffer.Batch(OccultaBundle.SealedPayload.PrekeySyncBatch(
        generatedAt: Date(timeIntervalSinceReferenceDate: 800_000_100),
        prekeys: (0..<keys).map { OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: Data(repeating: UInt8($0 + 1), count: 65)) },
        id: Data(repeating: 0xBB, count: 16),
        lastResort: OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: Data(repeating: 0xDD, count: 65))
    ))
}

private func offer(own: PrekeyRecord.OwnBatch? = nil, peer: PairingOffer.Batch? = nil) -> PairingOffer {
    var record = PrekeyRecord.empty
    record.ownBatches = [own ?? ownBatch(id: 0xAA)]
    return PairingOffer(ourNonce: nonce(1), peerNonce: nonce(2), ownPrekeys: record, peerBatch: peer ?? peerBatch())
}

@MainActor
private func makeContactManager() throws -> ContactManager {
    let schema = Schema([
        Group.self, Contact.Profile.self, Contact.Profile.PhoneNumber.self, Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self, Contact.Profile.Key.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    let security  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
    return ContactManager(modelContainer: container, security: security)
}

@MainActor
private func contact(in cm: ContactManager) throws -> Contact.Profile {
    try cm.save(contact: Contact.Draft(identifier: UUID().uuidString, givenName: "A", familyName: "B"))
    return try #require(try cm.fetchAllContacts().first)
}

private func draftKey(secret: Data?, date: String = "1") throws -> Contact.Draft.Key {
    try #require(Contact.Draft.Key(
        material: Data(repeating: 0x04, count: 65), owner: Data(repeating: 0x01, count: 65), date: date, routingKey: secret
    ))
}

// MARK: - The secret both phones derive

@MainActor
@Suite("Bug 196 — the routing key both phones derive")
struct RoutingKeyDerivationTests {

    private let alice = TestKeyManager()
    private let bob   = TestKeyManager()

    private func quantum() -> (alice: QuantumKeyMaterial, bob: QuantumKeyMaterial) {
        let s1 = Data(repeating: 0x31, count: 32), s2 = Data(repeating: 0x32, count: 32)
        let c1 = Data(repeating: 0x41, count: 16), c2 = Data(repeating: 0x42, count: 16)
        return (
            QuantumKeyMaterial(encapsulatedSecret: s1, decapsulatedSecret: s2, ourCiphertext: c1, peerCiphertext: c2),
            QuantumKeyMaterial(encapsulatedSecret: s2, decapsulatedSecret: s1, ourCiphertext: c2, peerCiphertext: c1)
        )
    }

    @Test("Both phones derive the same classical secret, whichever nonce each calls its own")
    func classicalAgrees() throws {
        let a = try #require(self.alice.createRoutingKey(
            peerP256Material: try self.bob.retrieveIdentity(), quantumMaterial: nil, ourNonce: nonce(1), peerNonce: nonce(2)))
        let b = try #require(self.bob.createRoutingKey(
            peerP256Material: try self.alice.retrieveIdentity(), quantumMaterial: nil, ourNonce: nonce(2), peerNonce: nonce(1)))
        #expect(a == b)
        #expect(a.count == 32)
    }

    @Test("Both phones derive the same hybrid secret")
    func hybridAgrees() throws {
        let q = self.quantum()
        let a = try #require(self.alice.createRoutingKey(
            peerP256Material: try self.bob.retrieveIdentity(), quantumMaterial: q.alice, ourNonce: nonce(1), peerNonce: nonce(2)))
        let b = try #require(self.bob.createRoutingKey(
            peerP256Material: try self.alice.retrieveIdentity(), quantumMaterial: q.bob, ourNonce: nonce(2), peerNonce: nonce(1)))
        #expect(a == b)
    }

    @Test("Two pairings of the same two identities differ, which is the point")
    func differsPerPairing() throws {
        let bobKey = try self.bob.retrieveIdentity()
        let first = self.alice.createRoutingKey(peerP256Material: bobKey, quantumMaterial: nil, ourNonce: nonce(1), peerNonce: nonce(2))
        let second = self.alice.createRoutingKey(peerP256Material: bobKey, quantumMaterial: nil, ourNonce: nonce(1), peerNonce: nonce(3))
        #expect(first != nil && second != nil && first != second)
    }

    @Test("ML-KEM secrets change the secret")
    func quantumChangesIt() throws {
        let bobKey = try self.bob.retrieveIdentity()
        let classical = self.alice.createRoutingKey(peerP256Material: bobKey, quantumMaterial: nil, ourNonce: nonce(1), peerNonce: nonce(2))
        let hybrid = self.alice.createRoutingKey(peerP256Material: bobKey, quantumMaterial: self.quantum().alice, ourNonce: nonce(1), peerNonce: nonce(2))
        #expect(classical != hybrid)
    }

    @Test("It is not the verification words' key: the screen shows those, and they reveal nothing of the secret")
    func notTheDicewareKey() throws {
        let bobKey = try self.bob.retrieveIdentity()
        let q = self.quantum().alice
        let secret = try #require(self.alice.createRoutingKey(
            peerP256Material: bobKey, quantumMaterial: q, ourNonce: nonce(1), peerNonce: nonce(2)))
        let words = try #require(self.alice.createDicewareKey(
            peerP256Material: bobKey, quantumMaterial: q, ourNonce: nonce(1), peerNonce: nonce(2)))
        #expect(words.withUnsafeBytes { Data($0) } != secret)
    }

    @Test("A bad nonce, an equal pair of nonces, or a bad peer key derives nothing")
    func refusesBadInput() throws {
        let bobKey = try self.bob.retrieveIdentity()
        #expect(self.alice.createRoutingKey(peerP256Material: bobKey, quantumMaterial: nil, ourNonce: nonce(1), peerNonce: nonce(1)) == nil)
        #expect(self.alice.createRoutingKey(peerP256Material: bobKey, quantumMaterial: nil, ourNonce: Data(count: 15), peerNonce: nonce(2)) == nil)
        #expect(self.alice.createRoutingKey(peerP256Material: Data(count: 64), quantumMaterial: nil, ourNonce: nonce(1), peerNonce: nonce(2)) == nil)
    }

    @Test("The offer derives through the key manager with its own nonces")
    func offerDerives() throws {
        let bobKey = try self.bob.retrieveIdentity()
        let direct = self.alice.createRoutingKey(peerP256Material: bobKey, quantumMaterial: nil, ourNonce: nonce(1), peerNonce: nonce(2))
        #expect(offer().secret(withPeer: bobKey, quantum: nil, using: self.alice) == direct)
    }
}

// MARK: - startPairing

@Suite("Bug 196 — a pairing's first batch in the record")
struct StartPairingTests {

    private let now = Date(timeIntervalSinceReferenceDate: 800_001_000)

    @Test("On an empty record the batch goes in pending and unretired")
    func onEmpty() {
        var record = PrekeyRecord.empty
        let batch = ownBatch(id: 0xAA)
        PrekeyBookkeeper().startPairing(with: batch, in: &record, now: self.now)

        #expect(record.ownBatches == [batch])
        #expect(PrekeyBookkeeper().hasPendingBatch(record))
    }

    @Test("A re-pair retires the old phone's batches and drops the keys it gave us")
    func rePair() {
        var record = PrekeyRecord.empty
        var delivered = ownBatch(id: 0x01); delivered.isPending = false; delivered.id = nil
        let undelivered = ownBatch(id: 0x02)
        record.ownBatches = [delivered, undelivered]
        record.inboundBatches = [PrekeyRecord.InboundBatch(id: nil, keys: [PrekeyRecord.InboundKey(id: UUID().uuidString, publicKey: Data(count: 65))])]
        record.inboundLastResort = PrekeyRecord.InboundKey(id: UUID().uuidString, publicKey: Data(count: 65))
        record.acceptedBatchIDs = [Data(repeating: 9, count: 16)]
        record.latestInboundGeneratedAt = Date()

        let fresh = ownBatch(id: 0xAA)
        PrekeyBookkeeper().startPairing(with: fresh, in: &record, now: self.now)

        #expect(record.ownBatches.count == 3)
        #expect(record.ownBatches[0].retiredAt == self.now)
        #expect(record.ownBatches[1].retiredAt == self.now)
        #expect(!record.ownBatches[1].isPending, "the old pending batch can no longer be delivered")
        #expect(record.ownBatches[1].id == nil)
        #expect(record.ownBatches[1].keys.allSatisfy { $0.publicKey == nil })
        #expect(record.ownBatches[2] == fresh)
        #expect(record.inboundBatches.isEmpty && record.inboundLastResort == nil)
        #expect(record.acceptedBatchIDs.isEmpty && record.latestInboundGeneratedAt == nil)
    }

    @Test("A retired batch that was already retired keeps its date")
    func keepsEarlierRetirement() {
        var record = PrekeyRecord.empty
        var old = ownBatch(id: 0x01); old.isPending = false; old.retiredAt = Date(timeIntervalSinceReferenceDate: 5)
        record.ownBatches = [old]
        PrekeyBookkeeper().startPairing(with: ownBatch(id: 0xAA), in: &record, now: self.now)
        #expect(record.ownBatches[0].retiredAt == Date(timeIntervalSinceReferenceDate: 5))
    }

    @Test("The record is held to the limit by evicting retired keys, never the new batch")
    func holdsLimit() {
        var record = PrekeyRecord.empty
        for n in 1...4 {
            var old = ownBatch(id: UInt8(n)); old.isPending = false; old.retiredAt = Date(timeIntervalSinceReferenceDate: Double(n))
            record.ownBatches.append(old)
        }
        let fresh = ownBatch(id: 0xAA)
        PrekeyBookkeeper().startPairing(with: fresh, in: &record, now: self.now)

        let total = record.ownBatches.reduce(0) { $0 + PrekeyBookkeeper.keyCount($1) }
        #expect(total <= PrekeyBookkeeper.maxOwnKeys)
        #expect(record.ownBatches.last == fresh)
    }

    @Test("The sweep deletes the retired batches once the grace period is up, and keeps the new one")
    func sweepAfterGrace() {
        var record = PrekeyRecord.empty
        record.ownBatches = [ownBatch(id: 0x01)]
        PrekeyBookkeeper().startPairing(with: ownBatch(id: 0xAA), in: &record, now: self.now)

        _ = PrekeyBookkeeper().sweep(&record, now: self.now.addingTimeInterval(PrekeyBookkeeper.gracePeriod + 1))
        #expect(record.ownBatches.count == 1)
        #expect(record.ownBatches[0].id == Data(repeating: 0xAA, count: 16))
    }
}

// MARK: - The save

@MainActor
@Suite("Bug 196 — the exchange's save installs the pairing in one go", .serialized)
struct PairingSaveTests {

    @Test("Both batches land, the secret is on the key row, the peer is at the tier", .ambientTestKeyManager)
    func fullPairing() throws {
        let cm = try makeContactManager()
        let paired = try contact(in: cm)
        let theirs = peerBatch()

        try cm.update(key: draftKey(secret: Data(repeating: 0x77, count: 32)), for: paired.identifier, pairing: offer(peer: theirs))

        let record = try cm.prekeyRecord(for: paired)
        #expect(record.ownBatches.count == 1)
        #expect(record.ownBatches[0].isPending)
        #expect(record.ownBatches[0].id == Data(repeating: 0xAA, count: 16), "the batch the peer was sent, as it was sent")
        #expect(record.inboundBatches.count == 1)
        #expect(record.inboundBatches[0].keys.count == 15)
        #expect(record.inboundBatches[0].keys.map(\.publicKey) == theirs.prekeys.map(\.publicKey))
        #expect(record.inboundLastResort?.publicKey == theirs.lastResort?.publicKey)

        let state = cm.pairingState(for: paired)
        #expect(state == .derived(secret: Data(repeating: 0x77, count: 32)))

        #expect(ContactManager.resolveTargetVersion(for: paired, using: Manager.Crypto()) == .pairingCapable)
    }

    @Test("The first message to the new contact is forward-secret, not long-term", .ambientTestKeyManager)
    func firstSendIsForwardSecret() throws {
        let cm = try makeContactManager()
        let paired = try contact(in: cm)

        #expect(cm.nextSendSecrecy(for: paired) == .longTerm, "before the pairing: the bootstrap")
        try cm.update(key: draftKey(secret: Data(repeating: 0x77, count: 32)), for: paired.identifier, pairing: offer())
        #expect(cm.nextSendSecrecy(for: paired) == .forwardSecret)
    }

    @Test("A peer batch outside the limits is dropped; our batch and the secret still go in", .ambientTestKeyManager)
    func malformedPeerBatch() throws {
        let cm = try makeContactManager()
        let paired = try contact(in: cm)

        try cm.update(key: draftKey(secret: Data(repeating: 0x77, count: 32)), for: paired.identifier, pairing: offer(peer: peerBatch(keys: 16)))

        let record = try cm.prekeyRecord(for: paired)
        #expect(record.ownBatches.count == 1 && record.ownBatches[0].isPending)
        #expect(record.inboundBatches.isEmpty && record.inboundLastResort == nil)
        #expect(cm.pairingState(for: paired).secret != nil)
    }

    @Test("A re-pair replaces what the old phone gave us and retires our old batches", .ambientTestKeyManager)
    func rePairResets() throws {
        let cm = try makeContactManager()
        let paired = try contact(in: cm)
        try cm.update(key: draftKey(secret: Data(repeating: 0x01, count: 32)), for: paired.identifier,
                      pairing: offer(own: ownBatch(id: 0x11), peer: peerBatch()))
        let oldInbound = try cm.prekeyRecord(for: paired).inboundBatches

        let newPeer = peerBatch(keys: 5)
        try cm.update(key: draftKey(secret: Data(repeating: 0x02, count: 32), date: "2"), for: paired.identifier,
                      pairing: offer(own: ownBatch(id: 0x22), peer: newPeer))

        let record = try cm.prekeyRecord(for: paired)
        #expect(record.inboundBatches.count == 1 && record.inboundBatches[0].keys.count == 5)
        #expect(record.inboundBatches != oldInbound)
        #expect(record.ownBatches.count == 2)
        #expect(record.ownBatches[0].retiredAt != nil && !record.ownBatches[0].isPending)
        #expect(record.ownBatches[1].isPending && record.ownBatches[1].retiredAt == nil)
        // Each pairing's secret is on its own key row. Not read through `.last`: a to-many relationship has no order of
        // its own, and which row is the current key is not what this test is about.
        let secrets = Set((paired.contactPublicKeys ?? []).compactMap { cm.pairingState(of: $0).secret })
        #expect(secrets == [Data(repeating: 0x01, count: 32), Data(repeating: 0x02, count: 32)])
    }

    @Test("A peer that sent no batch leaves the record and the tier as they were", .ambientTestKeyManager)
    func noOffer() throws {
        let cm = try makeContactManager()
        let paired = try contact(in: cm)
        let before = try cm.prekeyRecord(for: paired)
        let tier = paired.maxBundleVersion

        try cm.update(key: draftKey(secret: nil), for: paired.identifier)

        #expect(try cm.prekeyRecord(for: paired) == before)
        #expect(paired.maxBundleVersion == tier)
        #expect(cm.pairingState(for: paired) == .empty)
    }
}

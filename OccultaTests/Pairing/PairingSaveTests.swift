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
        keys: (0..<keys).map { PrekeyRecord.OwnKey(id: uuidBytes(), blob: nil, publicKey: Data(repeating: UInt8(truncatingIfNeeded: $0 + 1), count: 65)) },
        lastResort: PrekeyRecord.OwnKey(id: uuidBytes(), blob: nil, publicKey: Data(repeating: 0xEE, count: 65))
    )
}

private func peerBatch(keys: Int = 15) -> PairingOffer.Batch {
    PairingOffer.Batch(OccultaBundle.SealedPayload.PrekeySyncBatch(
        generatedAt: Date(timeIntervalSinceReferenceDate: 800_000_100),
        prekeys: (0..<keys).map { OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: Data(repeating: UInt8(truncatingIfNeeded: $0 + 1), count: 65)) },
        id: Data(repeating: 0xBB, count: 16),
        lastResort: OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: Data(repeating: 0xDD, count: 65))
    ))
}

/// The digest of the batch `record` would send, as the exchange takes it once when it makes the field.
private func sentDigest(of record: PrekeyRecord) -> Data {
    PairingOffer.Batch(PairingOffer.wireBatch(of: record)!).digest
}

private func offer(own: PrekeyRecord.OwnBatch? = nil, peer: PairingOffer.Batch? = nil) -> PairingOffer {
    var record = PrekeyRecord.empty
    record.ownBatches = [own ?? ownBatch(id: 0xAA)]
    return PairingOffer(
        ourNonce: nonce(1), peerNonce: nonce(2), ownPrekeys: record, ownBatchDigest: sentDigest(of: record), peerBatch: peer ?? peerBatch(),
        ours: ownPairKeys(), theirs: peerPairKeys(), pairwiseECDH: Data(repeating: 0x33, count: 32)
    )
}

private func ownPairKeys() -> PairingOffer.OwnPairKeys {
    PairingOffer.OwnPairKeys(
        agreementBlob: Data(repeating: 0xA1, count: 143), agreementKey: Data(repeating: 0xA2, count: 65),
        signingBlob: Data(repeating: 0xA3, count: 143), signingKey: Data(repeating: 0xA4, count: 65),
        mldsaBlob: nil, mldsaKey: nil
    )
}

private func peerPairKeys() -> PairingOffer.PeerPairKeys {
    PairingOffer.PeerPairKeys(agreementKey: Data(repeating: 0xB1, count: 65), signingKey: Data(repeating: 0xB2, count: 65), mldsaKey: nil)
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

private func draftKey(routingKey: Data?, date: String = "1") throws -> Contact.Draft.Key {
    try #require(Contact.Draft.Key(
        material: Data(repeating: 0x04, count: 65), owner: Data(repeating: 0x01, count: 65), date: date,
        pairing: routingKey.map { .paired(routingKey: $0, keys: samplePairKeys()) } ?? .empty
    ))
}

// MARK: - What the offer derives

@MainActor
@Suite("Bug 196 — what an offer derives through the key manager")
struct PairingOfferDerivationTests {

    private let alice = TestKeyManager()
    private let bob   = TestKeyManager()
    private let provider = SoftwareCardKeys()

    private func quantum() -> (alice: QuantumKeyMaterial, bob: QuantumKeyMaterial) {
        let s1 = Data(repeating: 0x31, count: 32), s2 = Data(repeating: 0x32, count: 32)
        let c1 = Data(repeating: 0x41, count: 16), c2 = Data(repeating: 0x42, count: 16)
        return (
            QuantumKeyMaterial(encapsulatedSecret: s1, decapsulatedSecret: s2, ourCiphertext: c1, peerCiphertext: c2),
            QuantumKeyMaterial(encapsulatedSecret: s2, decapsulatedSecret: s1, ourCiphertext: c2, peerCiphertext: c1)
        )
    }

    /// The two phones' offers for one exchange: each holds its own keys and the other's public ones.
    private func offers(mldsa: Bool = false) throws -> (alice: PairingOffer, bob: PairingOffer) {
        func make(mldsaAvailable: Bool) throws -> PairingOffer.OwnPairKeys {
            let keys = SoftwareCardKeys()
            keys.mldsaAvailable = mldsaAvailable
            return try PairingOffer.makeOwnPairKeys(using: keys)
        }
        let a = try make(mldsaAvailable: mldsa), b = try make(mldsaAvailable: false)
        // Each phone's own batch is the other's peer batch, as it is on the wire.
        var recordA = PrekeyRecord.empty, recordB = PrekeyRecord.empty
        recordA.ownBatches = [ownBatch(id: 0xAA)]
        recordB.ownBatches = [ownBatch(id: 0xBB)]
        let batchA = PairingOffer.Batch(try #require(PairingOffer.wireBatch(of: recordA)))
        let batchB = PairingOffer.Batch(try #require(PairingOffer.wireBatch(of: recordB)))
        func offer(
            record: PrekeyRecord, peerBatch: PairingOffer.Batch, ours: PairingOffer.OwnPairKeys, theirs: PairingOffer.OwnPairKeys,
            ourNonce: Data, peerNonce: Data
        ) throws -> PairingOffer {
            PairingOffer(
                ourNonce: ourNonce, peerNonce: peerNonce, ownPrekeys: record, ownBatchDigest: sentDigest(of: record), peerBatch: peerBatch,
                ours: ours,
                theirs: PairingOffer.PeerPairKeys(agreementKey: theirs.agreementKey, signingKey: theirs.signingKey, mldsaKey: theirs.mldsaKey),
                pairwiseECDH: try PairingOffer.pairwiseECDH(ours: ours, peerAgreementKey: theirs.agreementKey, using: self.provider)
            )
        }
        return (
            try offer(record: recordA, peerBatch: batchB, ours: a, theirs: b, ourNonce: nonce(1), peerNonce: nonce(2)),
            try offer(record: recordB, peerBatch: batchA, ours: b, theirs: a, ourNonce: nonce(2), peerNonce: nonce(1))
        )
    }

    @Test("Both phones' offers derive the same pair-key ECDH, routing key and words key")
    func bothAgree() throws {
        let (a, b) = try self.offers()
        #expect(a.pairwiseECDH == b.pairwiseECDH)

        let aliceKey = try self.alice.retrieveIdentity(), bobKey = try self.bob.retrieveIdentity()
        let routingA = try #require(a.routingKey(withPeer: bobKey, quantum: nil, using: self.alice))
        let routingB = try #require(b.routingKey(withPeer: aliceKey, quantum: nil, using: self.bob))
        #expect(routingA == routingB && routingA.count == 32)
        #expect(a.wordsKey(withPeer: bobKey, quantum: nil, using: self.alice) == b.wordsKey(withPeer: aliceKey, quantum: nil, using: self.bob))
        #expect(a.transcript == b.transcript)
    }

    @Test("They agree with ML-KEM secrets and with an ML-DSA key on one side, and differ from the exchange without")
    @available(iOS 26, *)
    func hybridAndMLDSA() throws {
        let aliceKey = try self.alice.retrieveIdentity(), bobKey = try self.bob.retrieveIdentity()
        let q = self.quantum()
        let plain = try self.offers()
        let withKey = try self.offers(mldsa: true)

        let a = try #require(withKey.alice.routingKey(withPeer: bobKey, quantum: q.alice, using: self.alice))
        let b = try #require(withKey.bob.routingKey(withPeer: aliceKey, quantum: q.bob, using: self.bob))
        #expect(a == b)
        #expect(withKey.alice.ours.mldsaKey != nil && withKey.bob.theirs.mldsaKey == withKey.alice.ours.mldsaKey)
        #expect(a != plain.alice.routingKey(withPeer: bobKey, quantum: q.alice, using: self.alice), "other keys, other pairing")
    }

    @Test("A prekey batch swapped on the way makes the two phones' words and routing keys differ")
    func swappedBatchIsSeen() throws {
        let (a, b) = try self.offers()
        let aliceKey = try self.alice.retrieveIdentity(), bobKey = try self.bob.retrieveIdentity()
        // Bob is shown Alice's keys with another batch beside them; everything else is honest.
        let other = PairingOffer.Batch(OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Date(timeIntervalSinceReferenceDate: 800_000_999), prekeys: [OccultaBundle.WirePrekey(id: "x", publicKey: Data(repeating: 9, count: 65))],
            id: Data(repeating: 0x99, count: 16), lastResort: nil
        ))
        let tampered = PairingOffer(
            ourNonce: b.ourNonce, peerNonce: b.peerNonce, ownPrekeys: b.ownPrekeys, ownBatchDigest: b.ownBatchDigest, peerBatch: other, ours: b.ours, theirs: b.theirs,
            pairwiseECDH: b.pairwiseECDH
        )

        #expect(a.wordsKey(withPeer: bobKey, quantum: nil, using: self.alice) != tampered.wordsKey(withPeer: aliceKey, quantum: nil, using: self.bob))
        #expect(a.routingKey(withPeer: bobKey, quantum: nil, using: self.alice) != tampered.routingKey(withPeer: aliceKey, quantum: nil, using: self.bob))
    }

    @Test("A routing key we can't derive is nil, never a weaker one")
    func derivationFailureIsNil() throws {
        let (a, _) = try self.offers()
        #expect(a.routingKey(withPeer: Data(count: 64), quantum: nil, using: self.alice) == nil)
        #expect(a.wordsKey(withPeer: Data(count: 64), quantum: nil, using: self.alice) == nil)
    }

    @Test("What save seals is what the offer holds")
    func pairKeysAreTheOffers() throws {
        let (a, _) = try self.offers()
        let keys = a.pairKeys
        #expect(keys.ourAgreementBlob == a.ours.agreementBlob && keys.ourAgreementKey == a.ours.agreementKey)
        #expect(keys.peerSigningKey == a.theirs.signingKey && keys.ourMLDSABlob == a.ours.mldsaBlob)
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

        try cm.update(key: draftKey(routingKey: Data(repeating: 0x77, count: 32)), for: paired.identifier, pairing: offer(peer: theirs))

        let record = try cm.prekeyRecord(for: paired)
        #expect(record.ownBatches.count == 1)
        #expect(record.ownBatches[0].isPending)
        #expect(record.ownBatches[0].id == Data(repeating: 0xAA, count: 16), "the batch the peer was sent, as it was sent")
        #expect(record.inboundBatches.count == 1)
        #expect(record.inboundBatches[0].keys.count == 15)
        #expect(record.inboundBatches[0].keys.map(\.publicKey) == theirs.prekeys.map(\.publicKey))
        #expect(record.inboundLastResort?.publicKey == theirs.lastResort?.publicKey)

        let state = cm.pairingState(for: paired)
        #expect(state == .paired(routingKey: Data(repeating: 0x77, count: 32), keys: samplePairKeys()))

        #expect(ContactManager.resolveTargetVersion(for: paired, using: Manager.Crypto()) == .pairingCapable)
    }

    @Test("The first message to the new contact is forward-secret, not long-term", .ambientTestKeyManager)
    func firstSendIsForwardSecret() throws {
        let cm = try makeContactManager()
        let paired = try contact(in: cm)

        #expect(cm.nextSendSecrecy(for: paired.identifier) == .longTerm, "before the pairing: the bootstrap")
        try cm.update(key: draftKey(routingKey: Data(repeating: 0x77, count: 32)), for: paired.identifier, pairing: offer())
        #expect(cm.nextSendSecrecy(for: paired.identifier) == .forwardSecret)
    }

    @Test("A peer batch outside the limits is dropped; our batch and the secret still go in", .ambientTestKeyManager)
    func malformedPeerBatch() throws {
        let cm = try makeContactManager()
        let paired = try contact(in: cm)

        try cm.update(key: draftKey(routingKey: Data(repeating: 0x77, count: 32)), for: paired.identifier, pairing: offer(peer: peerBatch(keys: 16)))

        let record = try cm.prekeyRecord(for: paired)
        #expect(record.ownBatches.count == 1 && record.ownBatches[0].isPending)
        #expect(record.inboundBatches.isEmpty && record.inboundLastResort == nil)
        #expect(cm.pairingState(for: paired).routingKey != nil)
    }

    @Test("A save with pair keys seals them with the routing key on the new row, and the pairing reads back as paired", .ambientTestKeyManager)
    func saveSealsThePairKeys() throws {
        let cm = try makeContactManager()
        let paired = try contact(in: cm)
        let pairing = offer()
        let key = try #require(Contact.Draft.Key(
            material: Data(repeating: 0x04, count: 65), owner: Data(repeating: 0x01, count: 65), date: "1",
            pairing: .paired(routingKey: Data(repeating: 0x77, count: 32), keys: pairing.pairKeys)
        ))
        try cm.update(key: key, for: paired.identifier, pairing: pairing)

        #expect(cm.pairingState(for: paired) == .paired(routingKey: Data(repeating: 0x77, count: 32), keys: pairing.pairKeys))
        #expect(cm.pairingSlotKeys(for: paired)?.routingKey == Data(repeating: 0x77, count: 32))
    }

    @Test("A save that fails after it has begun changing the contact leaves nothing for the next save to commit", .ambientTestKeyManager)
    func failureAfterChangesIsRolledBack() throws {
        let cm = try makeContactManager()
        let paired = try contact(in: cm)
        try cm.update(key: draftKey(routingKey: Data(repeating: 0x01, count: 32)), for: paired.identifier, pairing: offer())
        let current = try #require(paired.currentKey)
        let card = paired.introductionCardEncrypted
        let record = paired.prekeyRecordEncrypted
        let tier = paired.maxBundleVersion
        let sealedPairing = current.pairingEncrypted
        try cm.modelContext.save()
        #expect(!cm.modelContext.hasChanges)

        // 400 keys do not fit the 16 KiB prekey record, so `installPairingPrekeys` throws, after the card state has been
        // rewritten and before the retired rows and the new row are touched.
        let tooMany = offer(own: ownBatch(id: 0xCC, keys: 400))
        #expect(throws: PrekeyRecordCodec.CodecError.overCapacity) {
            try cm.update(key: draftKey(routingKey: Data(repeating: 0x02, count: 32), date: "2"), for: paired.identifier, pairing: tooMany)
        }

        // Nothing the failed save changed is waiting in the context, so an unrelated save elsewhere commits nothing of it.
        #expect(!cm.modelContext.hasChanges)
        #expect(paired.introductionCardEncrypted == card, "the card state")
        #expect(paired.prekeyRecordEncrypted == record, "the prekey record")
        #expect(paired.maxBundleVersion == tier, "the tier")
        #expect(paired.contactPublicKeys?.count == 1 && paired.currentKey === current && current.expiredOn == nil)
        #expect(current.pairingEncrypted == sealedPairing)
        #expect(cm.pairingState(for: paired) == .paired(routingKey: Data(repeating: 0x01, count: 32), keys: samplePairKeys()))
    }

    @Test("A re-pair replaces what the old phone gave us and retires our old batches", .ambientTestKeyManager)
    func rePairResets() throws {
        let cm = try makeContactManager()
        let paired = try contact(in: cm)
        try cm.update(key: draftKey(routingKey: Data(repeating: 0x01, count: 32)), for: paired.identifier,
                      pairing: offer(own: ownBatch(id: 0x11), peer: peerBatch()))
        let oldInbound = try cm.prekeyRecord(for: paired).inboundBatches

        let newPeer = peerBatch(keys: 5)
        try cm.update(key: draftKey(routingKey: Data(repeating: 0x02, count: 32), date: "2"), for: paired.identifier,
                      pairing: offer(own: ownBatch(id: 0x22), peer: newPeer))

        let record = try cm.prekeyRecord(for: paired)
        #expect(record.inboundBatches.count == 1 && record.inboundBatches[0].keys.count == 5)
        #expect(record.inboundBatches != oldInbound)
        #expect(record.ownBatches.count == 2)
        #expect(record.ownBatches[0].retiredAt != nil && !record.ownBatches[0].isPending)
        #expect(record.ownBatches[1].isPending && record.ownBatches[1].retiredAt == nil)
        // The new pairing's routing key is on the current key row; the retired row's was overwritten with the sealed
        // empty state, because a retired pairing's keys go with it.
        let routingKeys = (paired.contactPublicKeys ?? []).compactMap { cm.pairingState(of: $0).routingKey }
        #expect(routingKeys == [Data(repeating: 0x02, count: 32)])
        #expect(cm.pairingState(for: paired).routingKey == Data(repeating: 0x02, count: 32))
    }

    @Test("A peer that sent no batch leaves the record and the tier as they were", .ambientTestKeyManager)
    func noOffer() throws {
        let cm = try makeContactManager()
        let paired = try contact(in: cm)
        let before = try cm.prekeyRecord(for: paired)
        let tier = paired.maxBundleVersion

        try cm.update(key: draftKey(routingKey: nil), for: paired.identifier)

        #expect(try cm.prekeyRecord(for: paired) == before)
        #expect(paired.maxBundleVersion == tier)
        #expect(cm.pairingState(for: paired) == .empty)
    }
}

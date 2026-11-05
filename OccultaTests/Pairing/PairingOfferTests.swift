//
//  PairingOfferTests.swift
//  OccultaTests
//
//  Bug 196, stage 3: the `pairing` field an exchange carries (prekey batch, pair keys, an optional ML-DSA key), what the
//  peer's field is accepted as, and what the offer hands to `save()`. The exchange flow itself (MultipeerConnectivity and
//  NearbyInteraction between two phones) cannot run in a unit test; what is pinned here is the message, the validation,
//  the offer and the scratch record the flow is built from.
//

import Testing
import Foundation
import CryptoKit
import OccultaCore
@testable import Occulta
@testable import OccultaFormats

@Suite("Bug 196 — the exchange's pairing field")
struct PairingOfferTests {

    private func wirePrekey(_ n: UInt8) -> OccultaBundle.WirePrekey {
        OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: Data(repeating: n, count: 65))
    }

    private func batch(keys: Int = 3) -> OccultaBundle.SealedPayload.PrekeySyncBatch {
        OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Date(timeIntervalSinceReferenceDate: 800_000_000),
            prekeys: (0..<keys).map { self.wirePrekey(UInt8($0 + 1)) },
            id: Data(repeating: 0xAB, count: 16),
            lastResort: self.wirePrekey(0xEE)
        )
    }

    // MARK: The message

    private func field(
        agreement: Data? = nil, signing: Data? = nil, mldsa: Data? = nil
    ) -> Exchange.PairingField {
        Exchange.PairingField(
            prekeyBatch: self.batch(), agreementKey: agreement ?? Data(P256.KeyAgreement.PrivateKey().publicKey.x963Representation),
            signingKey: signing ?? Data(P256.Signing.PrivateKey().publicKey.x963Representation), mldsaKey: mldsa
        )
    }

    @Test("An identity message carries the pairing field and is still an identity message")
    func identityMessageCarriesTheField() throws {
        let sent = self.field(mldsa: Data(repeating: 7, count: RoutingKey.PairBlock.mldsaKeySize))
        let exchange = Exchange(
            id: "x", token: Data([1]), identity: Data(repeating: 4, count: 65), encapsulationKey: Data([9]), pairing: sent
        )
        let decoded = try JSONDecoder().decode(Exchange.self, from: JSONEncoder().encode(exchange))

        #expect(decoded.isIdentity)
        #expect(!decoded.isDiscovery)
        #expect(decoded.pairing?.prekeyBatch.prekeys == sent.prekeyBatch.prekeys)
        #expect(decoded.pairing?.prekeyBatch.lastResort == sent.prekeyBatch.lastResort)
        #expect(decoded.pairing?.agreementKey == sent.agreementKey && decoded.pairing?.signingKey == sent.signingKey)
        #expect(decoded.pairing?.mldsaKey == sent.mldsaKey)
    }

    @Test("A message from a build that sends no field decodes with none, and a 2.0.0-shaped decoder ignores ours")
    func olderMessagesDecode() throws {
        let old = #"{"id":"x","token":"AQ==","version":1,"identity":"BAQ=","nonce":null,"encapsulationKey":null}"#
        let decoded = try JSONDecoder().decode(Exchange.self, from: Data(old.utf8))
        #expect(decoded.pairing == nil)
        #expect(decoded.isIdentity)

        // The decoder of a build before this fix: the fields it knows, and nothing for a key it doesn't.
        struct Legacy: Decodable { let id: String; let token: Data; let identity: Data?; let encapsulationKey: Data? }
        let sent = Exchange(id: "x", token: Data([1]), identity: Data(repeating: 4, count: 65), pairing: self.field())
        let legacy = try JSONDecoder().decode(Legacy.self, from: JSONEncoder().encode(sent))
        #expect(legacy.id == "x" && legacy.identity?.count == 65)
    }

    @Test("Messages other than the identity message carry no pairing field")
    func otherMessagesCarryNone() {
        #expect(Exchange(id: "x", token: Data([1]), nonce: Data(count: 16)).pairing == nil)
        #expect(Exchange(id: "x", token: Data([1]), ciphertext: Data([1])).pairing == nil)
    }

    @Test("An identity message with the field and an ML-DSA key stays well under a megabyte, and about 10 KB")
    func messageSize() throws {
        var record = PrekeyRecord.empty
        record.ownBatches = [PrekeyRecord.OwnBatch(
            id: Data(repeating: 1, count: 16), createdAt: Date(timeIntervalSinceReferenceDate: 1), retiredAt: nil, isPending: true,
            keys: (0..<15).map { PrekeyRecord.OwnKey(id: Data(repeating: UInt8($0 + 1), count: 16), blob: nil, publicKey: Data(repeating: UInt8($0 + 1), count: 65)) },
            lastResort: PrekeyRecord.OwnKey(id: Data(repeating: 0xEE, count: 16), blob: nil, publicKey: Data(repeating: 0xEE, count: 65))
        )]
        let ours = PairingOffer.OwnPairKeys(
            agreementBlob: Data(count: 143), agreementKey: Data(P256.KeyAgreement.PrivateKey().publicKey.x963Representation),
            signingBlob: Data(count: 143), signingKey: Data(P256.Signing.PrivateKey().publicKey.x963Representation),
            mldsaBlob: nil, mldsaKey: Data((0..<RoutingKey.PairBlock.mldsaKeySize).map { UInt8($0 & 0xFF) })
        )
        let exchange = Exchange(
            id: UUID().uuidString, token: Data(count: 200), identity: Data(repeating: 4, count: 65),
            encapsulationKey: Data(count: 1568), pairing: PairingOffer.field(prekeys: record, keys: ours)
        )
        let size = try JSONEncoder().encode(exchange).count
        // Pinned so a regression in what the identity message carries shows here: roughly 3.6 KB of the pair keys and
        // the ML-DSA key on top of the 2.0.0 message.
        #expect((8_000...16_000).contains(size), "the identity message is \(size) bytes")
    }

    // MARK: What the peer's field is accepted as

    private func accept(
        _ field: Exchange.PairingField, ours: PairingOffer.OwnPairKeys? = nil, ourIdentity: Data? = Data(repeating: 0x11, count: 65),
        peerIdentity: Data = Data(repeating: 0x22, count: 65)
    ) throws -> (batch: PairingOffer.Batch, keys: PairingOffer.PeerPairKeys)? {
        let ours = try ours ?? PairingOffer.makeOwnPairKeys(using: SoftwareCardKeys())
        return PairingOffer.accepted(field, ours: ours, ourIdentity: ourIdentity, peerIdentity: peerIdentity)
    }

    @Test("A well-formed field is accepted as sent")
    func acceptsAGoodField() throws {
        let sent = self.field()
        let accepted = try #require(try self.accept(sent))
        #expect(accepted.keys.agreementKey == sent.agreementKey && accepted.keys.signingKey == sent.signingKey)
        #expect(accepted.keys.mldsaKey == nil)
        #expect(accepted.batch.prekeys == sent.prekeyBatch.prekeys)
    }

    @Test("A key that is the wrong size or not a point on the curve refuses the field")
    func refusesBadKeys() throws {
        #expect(try self.accept(self.field(agreement: Data(repeating: 4, count: 64))) == nil)
        #expect(try self.accept(self.field(signing: Data(repeating: 4, count: 66))) == nil)
        #expect(try self.accept(self.field(agreement: Data(repeating: 0x04, count: 65))) == nil, "65 bytes that are not a point")
        #expect(try self.accept(self.field(agreement: Data(count: 65))) == nil)
    }

    @Test("Two keys that are the same refuse the field")
    func refusesEqualKeys() throws {
        let key = Data(P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        #expect(try self.accept(self.field(agreement: key, signing: key)) == nil)
    }

    @Test("A key equal to either phone's identity key refuses the field")
    func refusesIdentityKeys() throws {
        let ours = Data(P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        let theirs = Data(P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        #expect(try self.accept(self.field(agreement: theirs), ourIdentity: ours, peerIdentity: theirs) == nil)
        #expect(try self.accept(self.field(signing: theirs), ourIdentity: ours, peerIdentity: theirs) == nil)
        #expect(try self.accept(self.field(agreement: ours), ourIdentity: ours, peerIdentity: theirs) == nil)
        #expect(try self.accept(self.field(), ourIdentity: nil, peerIdentity: theirs) != nil, "an identity we can't read is not a reason to refuse")
    }

    @Test("A reflection of one of our own pair keys refuses the field")
    func refusesReflection() throws {
        let ours = try PairingOffer.makeOwnPairKeys(using: SoftwareCardKeys())
        #expect(try self.accept(self.field(agreement: ours.agreementKey), ours: ours) == nil)
        #expect(try self.accept(self.field(signing: ours.signingKey), ours: ours) == nil)
        #expect(try self.accept(self.field(signing: ours.agreementKey), ours: ours) == nil)
    }

    @Test("A malformed ML-DSA key is dropped and the P-256 pair stays; a good one is kept")
    func malformedMLDSAIsDroppedAlone() throws {
        let bad = try #require(try self.accept(self.field(mldsa: Data(count: 100))))
        #expect(bad.keys.mldsaKey == nil)

        let good = Data(repeating: 9, count: RoutingKey.PairBlock.mldsaKeySize)
        #expect(try self.accept(self.field(mldsa: good))?.keys.mldsaKey == good)
    }

    @Test("Acceptance looks at no other contact's keys")
    func acceptanceIsPerExchange() throws {
        // `accepted` takes nothing but this exchange's keys: a hidden contact's pair keys can't change its answer.
        let sent = self.field()
        let ours = try PairingOffer.makeOwnPairKeys(using: SoftwareCardKeys())
        let first = PairingOffer.accepted(sent, ours: ours, ourIdentity: nil, peerIdentity: Data(repeating: 1, count: 65))
        let second = PairingOffer.accepted(sent, ours: ours, ourIdentity: nil, peerIdentity: Data(repeating: 1, count: 65))
        #expect(first?.keys == second?.keys)
    }

    // MARK: Our keys

    @Test("Our pair keys are two distinct P-256 keys, and an ML-DSA key where the phone could make one")
    func ownPairKeys() throws {
        let plain = SoftwareCardKeys(); plain.mldsaAvailable = false
        let without = try PairingOffer.makeOwnPairKeys(using: plain)
        #expect(without.agreementKey.count == 65 && without.signingKey.count == 65 && without.agreementKey != without.signingKey)
        #expect(without.mldsaKey == nil && without.mldsaBlob == nil, "a phone that can't make one sends none")

        guard #available(iOS 26, *) else { return }
        let with = try PairingOffer.makeOwnPairKeys(using: SoftwareCardKeys())
        #expect(with.mldsaKey?.count == RoutingKey.PairBlock.mldsaKeySize && with.mldsaBlob != nil)
    }

    @Test("A phone that can't make a P-256 key sends none of the field")
    func failureSendsNothing() {
        let keys = SoftwareCardKeys()
        keys.failing = true
        #expect(throws: (any Error).self) { try PairingOffer.makeOwnPairKeys(using: keys) }
        #expect(PairingOffer.field(prekeys: nil, keys: nil) == nil)
    }

    @Test("A phone that can make an ML-DSA key can make an ML-KEM one: an exchange with ML-DSA on both sides is hybrid")
    func mldsaImpliesMLKEM() {
        // Both are iOS 26 and later. The decision to keep ML-DSA out of the slot relies on this: wherever the key exists the
        // routing key has the ML-KEM secrets in it.
        let mldsa: Bool = { if #available(iOS 26, *) { return true } else { return false } }()
        #expect(mldsa == (PostQuantumProviderFactory.create() != nil))
    }

    // MARK: The offer

    @Test("The peer's batch is kept as received")
    func peerBatchKeepsFields() {
        let wire = batch(keys: 4)
        let kept = PairingOffer.Batch(wire)
        #expect(kept.id == wire.id)
        #expect(kept.generatedAt == wire.generatedAt)
        #expect(kept.prekeys == wire.prekeys)
        #expect(kept.lastResort == wire.lastResort)
    }

    @Test("Our pending batch is read back in wire form from a record")
    func wireBatchOfRecord() throws {
        let keys = (1...3).map { PrekeyRecord.OwnKey(id: Data(repeating: UInt8($0), count: 16), blob: nil, publicKey: Data(repeating: UInt8($0), count: 65)) }
        let lastResort = PrekeyRecord.OwnKey(id: Data(repeating: 0xEE, count: 16), blob: nil, publicKey: Data(repeating: 0xEE, count: 65))
        var record = PrekeyRecord.empty
        record.ownBatches = [PrekeyRecord.OwnBatch(
            id: Data(repeating: 0xCD, count: 16), createdAt: Date(timeIntervalSinceReferenceDate: 1), retiredAt: nil,
            isPending: true, keys: keys, lastResort: lastResort
        )]

        let wire = try #require(PairingOffer.wireBatch(of: record))
        #expect(wire.prekeys.count == 3)
        #expect(wire.prekeys.allSatisfy { $0.publicKey.count == 65 })
        #expect(wire.lastResort?.publicKey == Data(repeating: 0xEE, count: 65))
        #expect(wire.id == Data(repeating: 0xCD, count: 16))
    }

    @Test("A record with no pending batch gives none")
    func noBatchWhenNothingPending() {
        #expect(PairingOffer.wireBatch(of: .empty) == nil)
    }

    // MARK: The scratch record (Enclave)

    @MainActor
    @Test("Our first prekeys are one pending batch of the batch size plus a last-resort key, blobs only",
          .enabled(if: TestSupport.secureEnclaveAvailable()))
    func ownPrekeysAreOnePendingBatch() throws {
        let record = try PairingOffer.makeOwnPrekeys()

        let batch = try #require(record.ownBatches.first)
        #expect(record.ownBatches.count == 1)
        #expect(batch.isPending)
        #expect(batch.keys.count == Manager.PrekeySecretsManager.defaultBatchSize)
        #expect(batch.keys.allSatisfy { $0.blob != nil && $0.publicKey == nil })
        #expect(batch.lastResort?.blob != nil)
        #expect(record.inboundBatches.isEmpty && record.inboundLastResort == nil)

        let wire = try #require(PairingOffer.wireBatch(of: record))
        #expect(wire.prekeys.count == Manager.PrekeySecretsManager.defaultBatchSize)
        #expect(wire.prekeys.allSatisfy { $0.publicKey.count == 65 })
        #expect(Set(wire.prekeys.map(\.publicKey)).count == wire.prekeys.count, "every key is distinct")
        #expect(wire.lastResort?.publicKey.count == 65)
        #expect(wire.lastResort.map { last in !wire.prekeys.contains { $0.publicKey == last.publicKey } } == true)
    }

    @MainActor
    @Test("Two scratch records share no key", .enabled(if: TestSupport.secureEnclaveAvailable()))
    func scratchRecordsAreIndependent() throws {
        let first = try #require(PairingOffer.wireBatch(of: try PairingOffer.makeOwnPrekeys()))
        let second = try #require(PairingOffer.wireBatch(of: try PairingOffer.makeOwnPrekeys()))
        #expect(Set(first.prekeys.map(\.publicKey)).isDisjoint(with: second.prekeys.map(\.publicKey)))
        #expect(first.id != second.id)
    }
}

// MARK: - A blob that does not fit

/// Software keys whose agreement blob is larger than its room in the sealed column.
private struct OversizedBlobKeys: CardKeyProviding {
    let inner = SoftwareCardKeys()
    func makeAgreementKey() throws -> (publicKey: Data, blob: Data) {
        let key = try self.inner.makeAgreementKey()
        return (key.publicKey, key.blob + Data(count: PairingCodec.p256BlobRoom))
    }
    func makeSigningKey() throws -> (publicKey: Data, blob: Data) { try self.inner.makeSigningKey() }
    func signRaw(_ payload: Data, signingBlob: Data) throws -> Data { try self.inner.signRaw(payload, signingBlob: signingBlob) }
    func signDER(_ payload: Data, signingBlob: Data) throws -> Data { try self.inner.signDER(payload, signingBlob: signingBlob) }
    func sharedSecret(agreementBlob: Data, peerPublicKey: Data) throws -> Data {
        try self.inner.sharedSecret(agreementBlob: agreementBlob, peerPublicKey: peerPublicKey)
    }
    func agreementPublicKey(blob: Data) throws -> Data { try self.inner.agreementPublicKey(blob: blob) }
    func signingPublicKey(blob: Data) throws -> Data { try self.inner.signingPublicKey(blob: blob) }
    func makeMLDSAKey() throws -> (publicKey: Data, blob: Data) { try self.inner.makeMLDSAKey() }
    func mldsaSign(_ payload: Data, blob: Data) throws -> Data { try self.inner.mldsaSign(payload, blob: blob) }
    func mldsaPublicKey(blob: Data) throws -> Data { try self.inner.mldsaPublicKey(blob: blob) }
}

@Suite("Bug 196 — pair keys that would not fit the sealed column")
struct OversizedPairKeyTests {

    @Test("A P-256 blob larger than its room makes the phone send no pairing field, instead of failing at Save")
    func oversizedP256BlobSendsNothing() {
        #expect(throws: PairingCodec.CodecError.wrongSize) { try PairingOffer.makeOwnPairKeys(using: OversizedBlobKeys()) }
    }

    @Test("An ML-DSA blob larger than its room is left out and the P-256 pair stands")
    @available(iOS 26, *)
    func oversizedMLDSABlobIsLeftOut() throws {
        struct BigMLDSA: CardKeyProviding {
            let inner = SoftwareCardKeys()
            func makeAgreementKey() throws -> (publicKey: Data, blob: Data) { try self.inner.makeAgreementKey() }
            func makeSigningKey() throws -> (publicKey: Data, blob: Data) { try self.inner.makeSigningKey() }
            func signRaw(_ payload: Data, signingBlob: Data) throws -> Data { try self.inner.signRaw(payload, signingBlob: signingBlob) }
            func signDER(_ payload: Data, signingBlob: Data) throws -> Data { try self.inner.signDER(payload, signingBlob: signingBlob) }
            func sharedSecret(agreementBlob: Data, peerPublicKey: Data) throws -> Data {
                try self.inner.sharedSecret(agreementBlob: agreementBlob, peerPublicKey: peerPublicKey)
            }
            func agreementPublicKey(blob: Data) throws -> Data { try self.inner.agreementPublicKey(blob: blob) }
            func signingPublicKey(blob: Data) throws -> Data { try self.inner.signingPublicKey(blob: blob) }
            func makeMLDSAKey() throws -> (publicKey: Data, blob: Data) {
                let key = try self.inner.makeMLDSAKey()
                return (key.publicKey, key.blob + Data(count: PairingCodec.mldsaBlobRoom))
            }
            func mldsaSign(_ payload: Data, blob: Data) throws -> Data { try self.inner.mldsaSign(payload, blob: blob) }
            func mldsaPublicKey(blob: Data) throws -> Data { try self.inner.mldsaPublicKey(blob: blob) }
        }
        let keys = try PairingOffer.makeOwnPairKeys(using: BigMLDSA())
        #expect(keys.mldsaKey == nil && keys.mldsaBlob == nil)
        #expect(keys.agreementKey.count == 65 && keys.signingKey.count == 65)
    }
}

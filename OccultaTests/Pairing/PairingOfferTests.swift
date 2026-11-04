//
//  PairingOfferTests.swift
//  OccultaTests
//
//  Bug 196, stage 3: the prekey batch an exchange carries, and what it hands to `save()`. The exchange flow itself
//  (MultipeerConnectivity and NearbyInteraction between two phones) cannot run in a unit test; what is pinned here is
//  the message, the offer and the scratch record the flow is built from.
//

import Testing
import Foundation
@testable import Occulta
@testable import OccultaFormats

@Suite("Bug 196 — the exchange's prekey batch")
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

    @Test("An identity message carries the batch and is still an identity message")
    func identityMessageCarriesBatch() throws {
        let sent = batch()
        let exchange = Exchange(
            id: "x", token: Data([1]), identity: Data(repeating: 4, count: 65), encapsulationKey: Data([9]),
            prekeyBatch: sent
        )
        let decoded = try JSONDecoder().decode(Exchange.self, from: JSONEncoder().encode(exchange))

        #expect(decoded.isIdentity)
        #expect(!decoded.isDiscovery)
        #expect(decoded.prekeyBatch?.prekeys == sent.prekeys)
        #expect(decoded.prekeyBatch?.lastResort == sent.lastResort)
        #expect(decoded.prekeyBatch?.id == sent.id)
    }

    @Test("A message from a build that sends no batch decodes with none")
    func olderMessageDecodes() throws {
        let old = #"{"id":"x","token":"AQ==","version":1,"identity":"BAQ=","nonce":null,"encapsulationKey":null}"#
        let decoded = try JSONDecoder().decode(Exchange.self, from: Data(old.utf8))
        #expect(decoded.prekeyBatch == nil)
        #expect(decoded.isIdentity)
    }

    @Test("Messages other than the identity message carry no batch")
    func otherMessagesCarryNone() {
        #expect(Exchange(id: "x", token: Data([1]), nonce: Data(count: 16)).prekeyBatch == nil)
        #expect(Exchange(id: "x", token: Data([1]), ciphertext: Data([1])).prekeyBatch == nil)
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

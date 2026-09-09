//
//  LayerStoreReadPayloadTests.swift
//  OccultaTests
//
//  readPayload's new validation (SecureMode+LayerStore.swift), added alongside Design B's
//  step 5 (plan.md's "What Design B requires" item 5, `bugs.md` Bug 108). readPayload was
//  promoted from diagnostics-only to a production path because Design B's own unlock step
//  needs a repeatable, non-destructive read — but promoting it without validation would
//  have silently accepted a stale blob, exactly what pop()'s existing sequenceNumber and
//  slotIndex checks already exist to catch. These tests pin that readPayload now carries
//  the same checks, minus the erasure.
//

import Testing
import CryptoKit
@testable import Occulta

@Suite("LayerStore — readPayload validation")
struct LayerStoreReadPayloadTests {

    private func makePayload(sequenceNumber: Int, slotIndex: Int) -> LayerPayload {
        LayerPayload(sequenceNumber: sequenceNumber, slotIndex: slotIndex, contacts: [])
    }

    @Test("Reading back what was pushed succeeds with the matching sequence number")
    func roundTripWithCorrectSequenceNumber() throws {
        let store   = Manager.LayerStore(backend: InMemoryLayerStoreBackend())
        let key     = SymmetricKey(size: .bits256)
        let payload = makePayload(sequenceNumber: 42, slotIndex: 5)

        try store.push(payload, key: key, slotIndex: 5)
        let read = try store.readPayload(key: key, slotIndex: 5, expectedSequenceNumber: 42)

        #expect(read.sequenceNumber == 42)
        #expect(read.slotIndex == 5)
    }

    @Test("A stale sequence number is rejected, not silently accepted")
    func staleSequenceNumberThrows() throws {
        let store   = Manager.LayerStore(backend: InMemoryLayerStoreBackend())
        let key     = SymmetricKey(size: .bits256)
        let payload = makePayload(sequenceNumber: 42, slotIndex: 5)

        try store.push(payload, key: key, slotIndex: 5)

        #expect(throws: Manager.LayerStore.Error.self) {
            try store.readPayload(key: key, slotIndex: 5, expectedSequenceNumber: 99)
        }
    }

    @Test("A slot-index mismatch is rejected — the payload's own slotIndex field disagrees with where it's stored")
    func slotIndexMismatchThrows() throws {
        let store = Manager.LayerStore(backend: InMemoryLayerStoreBackend())
        let key   = SymmetricKey(size: .bits256)
        // Stored at slot 6, but the payload's own slotIndex field still says 5 — a real,
        // validly-decodable payload with a mismatched field, not garbage filler (which
        // would fail to JSON-decode at all and throw a different, unrelated error).
        let payload = makePayload(sequenceNumber: 1, slotIndex: 5)

        try store.push(payload, key: key, slotIndex: 6)

        #expect(throws: Manager.LayerStore.Error.self) {
            try store.readPayload(key: key, slotIndex: 6, expectedSequenceNumber: 1)
        }
    }

    @Test("readPayload does not modify the file — repeatable across multiple calls")
    func nonDestructiveAcrossRepeatedReads() throws {
        let store   = Manager.LayerStore(backend: InMemoryLayerStoreBackend())
        let key     = SymmetricKey(size: .bits256)
        let payload = makePayload(sequenceNumber: 7, slotIndex: 3)

        try store.push(payload, key: key, slotIndex: 3)

        let first  = try store.readPayload(key: key, slotIndex: 3, expectedSequenceNumber: 7)
        let second = try store.readPayload(key: key, slotIndex: 3, expectedSequenceNumber: 7)

        #expect(first.sequenceNumber == second.sequenceNumber)
        #expect(first.slotIndex == second.slotIndex)
    }
}

//
//  PrekeyManagerTests.swift
//  OccultaTests
//
//  ⚠️  DEVICE ONLY — requires Secure Enclave.
//  Tests: SE key generation, retrieval, consumption, deletion, stock tracking.
//

import Testing
import Foundation
import Security

@testable import Occulta

// MARK: - Helpers

private extension String {
    /// Unique contact ID scoped to a test function, cleaned up in defer blocks.
    static func testContactID(function: String = #function) -> String {
        "test.\(function).\(UUID().uuidString)"
    }
}

// MARK: - Generation

@Suite("PrekeyManager — Generation")
struct PrekeyManagerGenerationTests {

    let pm = Manager.PrekeyManager()

    @Test func generateBatch_returnsDefaultCount() throws {
        let cid = String.testContactID()
        defer { pm.deleteAllKeys(for: cid) }

        let prekeys = try pm.generateBatch(contactID: cid)
        #expect(prekeys.count == Manager.PrekeyManager.defaultBatchSize)
    }

    @Test func generateBatch_customCount() throws {
        let cid = String.testContactID()
        defer { pm.deleteAllKeys(for: cid) }

        let prekeys = try pm.generateBatch(contactID: cid, count: 3)
        #expect(prekeys.count == 3)
    }

    @Test func generateBatch_allPublicKeysAre65Bytes() throws {
        let cid = String.testContactID()
        defer { pm.deleteAllKeys(for: cid) }

        let prekeys = try pm.generateBatch(contactID: cid, count: 3)
        for prekey in prekeys {
            #expect(prekey.publicKey.count == 65, "publicKey must be 65-byte x963 uncompressed point")
        }
    }

    @Test func generateBatch_allIDsAreUnique() throws {
        let cid = String.testContactID()
        defer { pm.deleteAllKeys(for: cid) }

        let prekeys = try pm.generateBatch(contactID: cid)
        let ids     = Set(prekeys.map(\.id))
        #expect(ids.count == prekeys.count)
    }

    @Test func generateBatch_allContactIDsMatchInput() throws {
        let cid = String.testContactID()
        defer { pm.deleteAllKeys(for: cid) }

        let prekeys = try pm.generateBatch(contactID: cid, count: 3)
        #expect(prekeys.allSatisfy { $0.contactID == cid })
    }

    @Test func generateBatch_keysImmediatelyRetrievable() throws {
        let cid = String.testContactID()
        defer { pm.deleteAllKeys(for: cid) }

        let prekeys = try pm.generateBatch(contactID: cid, count: 3)
        for prekey in prekeys {
            let key = pm.retrievePrivateKey(for: prekey)
            #expect(key != nil, "Every generated key must be immediately retrievable from SE")
        }
    }

    @Test func generateBatch_twoBatches_allKeysRetrievable() throws {
        let cid = String.testContactID()
        defer { pm.deleteAllKeys(for: cid) }

        let batch1 = try pm.generateBatch(contactID: cid, count: 3)
        let batch2 = try pm.generateBatch(contactID: cid, count: 3)

        for prekey in batch1 + batch2 {
            #expect(pm.retrievePrivateKey(for: prekey) != nil)
        }
    }
}

// MARK: - Retrieval

@Suite("PrekeyManager — Retrieval")
struct PrekeyManagerRetrievalTests {

    let pm = Manager.PrekeyManager()

    @Test func retrievePrivateKey_nilForPhantomID() {
        let phantom = Prekey(id: UUID().uuidString, contactID: "nonexistent", publicKey: Data(count: 65))
        #expect(pm.retrievePrivateKey(for: phantom) == nil)
    }

    @Test func retrievePrivateKey_nilAfterConsume() throws {
        let cid = String.testContactID()
        defer { pm.deleteAllKeys(for: cid) }

        let prekeys = try pm.generateBatch(contactID: cid, count: 1)
        let prekey  = prekeys[0]
        pm.consume(prekey: prekey)
        #expect(pm.retrievePrivateKey(for: prekey) == nil)
    }

    @Test func retrievePrivateKey_tempPrekeyPattern_works() throws {
        // Verifies the contactID + id → SE tag reconstruction used in decrypt.
        let cid = String.testContactID()
        defer { pm.deleteAllKeys(for: cid) }

        let prekeys = try pm.generateBatch(contactID: cid, count: 1)
        let original = prekeys[0]

        // Construct a temp Prekey with empty publicKey — only id + contactID matter for the tag.
        let temp = Prekey(id: original.id, contactID: cid, publicKey: Data())
        #expect(pm.retrievePrivateKey(for: temp) != nil, "Temp prekey must reconstruct the correct SE tag")
    }
}

// MARK: - Consumption

@Suite("PrekeyManager — Consumption")
struct PrekeyManagerConsumptionTests {

    let pm = Manager.PrekeyManager()

    @Test func consume_deletesKeyFromSE() throws {
        let cid = String.testContactID()
        defer { pm.deleteAllKeys(for: cid) }

        let prekeys = try pm.generateBatch(contactID: cid, count: 1)
        #expect(pm.retrievePrivateKey(for: prekeys[0]) != nil)

        pm.consume(prekey: prekeys[0])
        #expect(pm.retrievePrivateKey(for: prekeys[0]) == nil)
    }

    @Test func consume_isIdempotent() throws {
        let cid = String.testContactID()
        defer { pm.deleteAllKeys(for: cid) }

        let prekeys = try pm.generateBatch(contactID: cid, count: 1)
        pm.consume(prekey: prekeys[0])
        // Second call must return true (errSecItemNotFound is treated as success)
        #expect(pm.consume(prekey: prekeys[0]) == true)
    }

    @Test func consume_onlyDeletesTargetKey() throws {
        let cid = String.testContactID()
        defer { pm.deleteAllKeys(for: cid) }

        let prekeys = try pm.generateBatch(contactID: cid, count: 3)
        pm.consume(prekey: prekeys[0])

        #expect(pm.retrievePrivateKey(for: prekeys[1]) != nil, "Sibling key must survive")
        #expect(pm.retrievePrivateKey(for: prekeys[2]) != nil, "Sibling key must survive")
    }

    @Test func secKeyLifetime_closurePattern_nocrash() throws {
        // Verifies the double-temp-Prekey pattern from ContactManager.decrypt.
        // SecKey released inside closure before consume() fires.
        let cid = String.testContactID()
        defer { pm.deleteAllKeys(for: cid) }

        let prekeys = try pm.generateBatch(contactID: cid, count: 1)
        let prekeyID = prekeys[0].id

        // First temp — SecKey retrieved and released inside closure
        let didRetrieve: Bool = {
            let temp   = Prekey(id: prekeyID, contactID: cid, publicKey: Data())
            let secKey = pm.retrievePrivateKey(for: temp)
            return secKey != nil
            // secKey released here
        }()

        #expect(didRetrieve)

        // Second temp — consume fires after SecKey is gone
        let temp2 = Prekey(id: prekeyID, contactID: cid, publicKey: Data())
        pm.consume(prekey: temp2)   // SecItemDelete — no live SecKey reference
        #expect(pm.retrievePrivateKey(for: prekeys[0]) == nil)
    }
}

// MARK: - Pool deletion

@Suite("PrekeyManager — Pool deletion")
struct PrekeyManagerDeletionTests {

    let pm = Manager.PrekeyManager()

    @Test func deleteAllKeys_removesEntirePool() throws {
        let cid = String.testContactID()
        defer { pm.deleteAllKeys(for: cid) }   // safety net if assertions throw
        let prekeys = try pm.generateBatch(contactID: cid, count: 3)

        pm.deleteAllKeys(for: cid)

        for prekey in prekeys {
            #expect(pm.retrievePrivateKey(for: prekey) == nil)
        }
        #expect(pm.remainingCount(for: cid) == 0)
    }

    @Test func deleteAllKeys_isContactScoped() throws {
        let cid1 = String.testContactID() + ".one"
        let cid2 = String.testContactID() + ".two"
        defer { pm.deleteAllKeys(for: cid2) }

        let keys1 = try pm.generateBatch(contactID: cid1, count: 2)
        let keys2 = try pm.generateBatch(contactID: cid2, count: 2)

        pm.deleteAllKeys(for: cid1)

        for key in keys1 { #expect(pm.retrievePrivateKey(for: key) == nil) }
        for key in keys2 { #expect(pm.retrievePrivateKey(for: key) != nil, "Other contact untouched") }
    }
}

// MARK: - Stock tracking

@Suite("PrekeyManager — Stock")
struct PrekeyManagerStockTests {

    let pm = Manager.PrekeyManager()

    @Test func remainingCount_accurateAfterGeneration() throws {
        let cid = String.testContactID()
        defer { pm.deleteAllKeys(for: cid) }

        #expect(pm.remainingCount(for: cid) == 0)

        _ = try pm.generateBatch(contactID: cid, count: 5)
        #expect(pm.remainingCount(for: cid) == 5)
    }

    @Test func remainingCount_decrementsAfterConsume() throws {
        let cid = String.testContactID()
        defer { pm.deleteAllKeys(for: cid) }

        let prekeys = try pm.generateBatch(contactID: cid, count: 3)
        pm.consume(prekey: prekeys[0])
        #expect(pm.remainingCount(for: cid) == 2)
    }

    @Test func needsReplenishment_falseAtOrAboveThreshold() throws {
        let cid = String.testContactID()
        defer { pm.deleteAllKeys(for: cid) }

        _ = try pm.generateBatch(contactID: cid, count: Manager.PrekeyManager.replenishThreshold)
        #expect(pm.needsReplenishment(for: cid) == false)
    }

    @Test func needsReplenishment_trueBelowThreshold() throws {
        let cid = String.testContactID()
        defer { pm.deleteAllKeys(for: cid) }

        _ = try pm.generateBatch(contactID: cid, count: Manager.PrekeyManager.replenishThreshold - 1)
        #expect(pm.needsReplenishment(for: cid) == true)
    }

    @Test func needsReplenishment_trueForNewContact() {
        let cid = "never-used-\(UUID().uuidString)"
        #expect(pm.needsReplenishment(for: cid) == true)
    }
}

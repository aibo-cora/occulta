//
//  PrekeyManagerSETests.swift
//  OccultaTests
//
//  Tests for Manager.PrekeyManager — all operations that touch the Secure Enclave.
//
//  ⚠️  THESE TESTS WRITE TO THE SECURE ENCLAVE.
//  Every test that generates keys MUST clean them up via defer.
//  Failure to clean up leaks SE entries that persist across test runs.
//
//  Run on device only — SE not available in simulator.
//

import XCTest
@testable import Occulta

final class PrekeyManagerSETests: XCTestCase {

    var manager: Manager.PrekeyManager!

    override func setUp() {
        super.setUp()
        manager = Manager.PrekeyManager()
    }

    override func tearDown() {
        manager = nil
        super.tearDown()
    }

    // MARK: - Helpers

    /// Unique contact ID per test — prevents cross-test SE pollution.
    private func contactID(function: String = #function) -> String {
        "test.\(function).\(UUID().uuidString)"
    }

    // MARK: - Generation

    func test_generateBatch_returnsRequestedCount() throws {
        let cid = contactID()
        defer { manager.deleteAllKeys(for: cid) }

        let (keys, _) = try manager.generateBatch(contactID: cid, currentSequence: 0, count: 5)

        XCTAssertEqual(keys.count, 5)
    }

    func test_generateBatch_allKeysHaveCorrectContactIDAndSequence() throws {
        let cid = contactID()
        defer { manager.deleteAllKeys(for: cid) }

        let (keys, _) = try manager.generateBatch(contactID: cid, currentSequence: 3, count: 4)

        for key in keys {
            XCTAssertEqual(key.contactID, cid,   "contactID must match")
            XCTAssertEqual(key.sequence,  3,     "sequence must match currentSequence")
            XCTAssertFalse(key.id.isEmpty,       "id must not be empty")
            XCTAssertEqual(key.publicKey.count, 65, "x963 public key must be 65 bytes")
        }
    }

    func test_generateBatch_returnsIncrementedNextSequence() throws {
        let cid = contactID()
        defer { manager.deleteAllKeys(for: cid) }

        let (_, next) = try manager.generateBatch(contactID: cid, currentSequence: 7, count: 1)

        XCTAssertEqual(next, 8)
    }

    func test_generateBatch_privateKeysStoredInSE() throws {
        let cid = contactID()
        defer { manager.deleteAllKeys(for: cid) }

        let (keys, _) = try manager.generateBatch(contactID: cid, currentSequence: 0, count: 3)

        for key in keys {
            XCTAssertNotNil(
                manager.retrievePrivateKey(for: key),
                "Private key for \(key.id) must be retrievable from SE after generation"
            )
        }
    }

    // MARK: - Retrieval

    func test_retrievePrivateKey_returnsNilForUnknownID() throws {
        let cid    = contactID()
        let phantom = Prekey(id: UUID().uuidString, contactID: cid, sequence: 0, publicKey: Data(count: 65))

        XCTAssertNil(manager.retrievePrivateKey(for: phantom),
                     "Unknown prekey must return nil, not throw")
    }

    // MARK: - Consumption

    /// ⚠️ CRASH CANDIDATE
    /// SecItemDelete (inside consume) invalidates the SE item backing the SecKey.
    /// If the SecKey is still retained by ARC when the item is deleted, ARC's
    /// CFRelease call on teardown will reference freed memory.
    ///
    /// Safety: this test does NOT hold a SecKey reference across consume().
    /// It calls retrievePrivateKey only to assert existence — the reference
    /// is discarded before consume is called.
    func test_consume_deletesPrivateKeyFromSE() throws {
        let cid = contactID()
        defer { manager.deleteAllKeys(for: cid) }

        let (keys, _) = try manager.generateBatch(contactID: cid, currentSequence: 0, count: 1)
        let key       = keys[0]

        // Assert key exists — reference intentionally discarded immediately.
        XCTAssertNotNil(manager.retrievePrivateKey(for: key))

        // consume() calls SecItemDelete. No SecKey reference is live at this point.
        manager.consume(prekey: key)

        XCTAssertNil(manager.retrievePrivateKey(for: key),
                     "Private key must be gone from SE after consume")
    }

    func test_consume_idempotent_secondCallReturnsTrue() throws {
        let cid = contactID()
        defer { manager.deleteAllKeys(for: cid) }

        let (keys, _) = try manager.generateBatch(contactID: cid, currentSequence: 0, count: 1)
        let key       = keys[0]

        manager.consume(prekey: key)
        let result = manager.consume(prekey: key) // second consume on absent item

        // deleteKey returns true for both errSecSuccess and errSecItemNotFound.
        // Idempotent success — the item is absent, which is the desired state.
        XCTAssertTrue(result, "Second consume must return true (errSecItemNotFound = success)")
    }

    // MARK: - Stock tracking

    func test_remainingCount_accurateAfterGenerationAndConsumption() throws {
        let cid = contactID()
        defer { manager.deleteAllKeys(for: cid) }

        let (keys, _) = try manager.generateBatch(contactID: cid, currentSequence: 0, count: 4)

        XCTAssertEqual(manager.remainingCount(for: cid), 4)

        manager.consume(prekey: keys[0])
        XCTAssertEqual(manager.remainingCount(for: cid), 3)

        manager.consume(prekey: keys[1])
        manager.consume(prekey: keys[2])
        XCTAssertEqual(manager.remainingCount(for: cid), 1)

        manager.consume(prekey: keys[3])
        XCTAssertEqual(manager.remainingCount(for: cid), 0)
    }

    func test_needsReplenishment_falseWhenAtThreshold() throws {
        let cid = contactID()
        defer { manager.deleteAllKeys(for: cid) }

        let (_, _) = try manager.generateBatch(
            contactID: cid,
            currentSequence: 0,
            count: Manager.PrekeyManager.replenishThreshold
        )

        XCTAssertFalse(manager.needsReplenishment(for: cid),
                       "Stock at threshold must not need replenishment")
    }

    func test_needsReplenishment_trueWhenBelowThreshold() throws {
        let cid = contactID()
        defer { manager.deleteAllKeys(for: cid) }

        let (keys, _) = try manager.generateBatch(
            contactID: cid,
            currentSequence: 0,
            count: Manager.PrekeyManager.replenishThreshold
        )

        manager.consume(prekey: keys[0]) // drop below threshold

        XCTAssertTrue(manager.needsReplenishment(for: cid),
                      "Stock below threshold must need replenishment")
    }

    // MARK: - Pruning

    func test_pruneSequences_deletesOldKeysKeepsCurrentAndBuffer() throws {
        let cid = contactID()
        defer { manager.deleteAllKeys(for: cid) }

        let (seq1Keys, _) = try manager.generateBatch(contactID: cid, currentSequence: 1, count: 2)
        let (seq2Keys, _) = try manager.generateBatch(contactID: cid, currentSequence: 2, count: 2)
        let (seq3Keys, _) = try manager.generateBatch(contactID: cid, currentSequence: 3, count: 2)

        // After seq 3 generation, generateBatch auto-prunes seq < 2.
        // Seq 1 must be gone. Seq 2 (buffer) and seq 3 (current) must survive.

        for key in seq1Keys {
            XCTAssertNil(
                manager.retrievePrivateKey(for: key),
                "Seq 1 key \(key.id) must be pruned after seq 3 is generated"
            )
        }
        for key in seq2Keys {
            XCTAssertNotNil(
                manager.retrievePrivateKey(for: key),
                "Seq 2 key \(key.id) must survive as safety buffer"
            )
        }
        for key in seq3Keys {
            XCTAssertNotNil(
                manager.retrievePrivateKey(for: key),
                "Seq 3 key \(key.id) must survive as current batch"
            )
        }
    }

    func test_pruneSequences_scopedToContactID_doesNotAffectOtherContacts() throws {
        let cid1 = contactID() + ".alpha"
        let cid2 = contactID() + ".beta"
        defer {
            manager.deleteAllKeys(for: cid1)
            manager.deleteAllKeys(for: cid2)
        }

        let (keys1, _) = try manager.generateBatch(contactID: cid1, currentSequence: 1, count: 2)
        let (keys2, _) = try manager.generateBatch(contactID: cid2, currentSequence: 1, count: 2)

        // Prune cid1 seq 0 (no-op) and up to seq 1 — should not touch cid2
        manager.pruneSequences(olderThan: 2, contactID: cid1)

        for key in keys1 {
            XCTAssertNil(
                manager.retrievePrivateKey(for: key),
                "cid1 seq 1 must be pruned"
            )
        }
        for key in keys2 {
            XCTAssertNotNil(
                manager.retrievePrivateKey(for: key),
                "cid2 keys must be completely unaffected by pruning cid1"
            )
        }
    }

    // MARK: - Full pool deletion

    func test_deleteAllKeys_removesEntireContactPool() throws {
        let cid = contactID()

        let (seq0Keys, _) = try manager.generateBatch(contactID: cid, currentSequence: 0, count: 3)
        let (seq1Keys, _) = try manager.generateBatch(contactID: cid, currentSequence: 1, count: 3)

        manager.deleteAllKeys(for: cid)

        XCTAssertEqual(manager.remainingCount(for: cid), 0)

        for key in seq0Keys + seq1Keys {
            XCTAssertNil(manager.retrievePrivateKey(for: key))
        }
    }

    func test_deleteAllKeys_doesNotAffectOtherContacts() throws {
        let cid1 = contactID() + ".one"
        let cid2 = contactID() + ".two"
        defer { manager.deleteAllKeys(for: cid2) }

        let (_, _) = try manager.generateBatch(contactID: cid1, currentSequence: 0, count: 3)
        let (keys2, _) = try manager.generateBatch(contactID: cid2, currentSequence: 0, count: 3)

        manager.deleteAllKeys(for: cid1)

        for key in keys2 {
            XCTAssertNotNil(
                manager.retrievePrivateKey(for: key),
                "cid2 keys must survive deletion of cid1's pool"
            )
        }
    }

    // MARK: - SE tag correctness

    func test_prekeySeTag_format() {
        let key = Prekey(id: "abc-123", contactID: "contact-456", sequence: 7, publicKey: Data())
        XCTAssertEqual(key.seTag, "prekey.contact-456.7.abc-123")
    }

    func test_prekeySeTagPrefix_contactAndSequence() {
        XCTAssertEqual(Prekey.seTagPrefix(contactID: "bob", sequence: 3), "prekey.bob.3.")
    }

    func test_prekeySeTagPrefix_contactOnly() {
        XCTAssertEqual(Prekey.seTagPrefix(contactID: "bob"), "prekey.bob.")
    }
}

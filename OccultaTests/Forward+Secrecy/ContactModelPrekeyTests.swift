//
//  ContactModelPrekeyTests.swift
//  OccultaTests
//
//  Tests for Contact.Profile prekey extension methods.
//  No SE. No Manager.Crypto. No SwiftData container.
//  Safe to run in the simulator.
//

import XCTest
import CryptoKit
@testable import Occulta

final class ContactModelPrekeyTests: XCTestCase {

    // MARK: - Fixed test encryption (no SE)

    private static let blobKey = SymmetricKey(size: .bits256)

    private func encrypt(_ prekey: Prekey) throws -> Data {
        let encoded = try JSONEncoder().encode(prekey)
        return try AES.GCM.seal(encoded, using: Self.blobKey, nonce: AES.GCM.Nonce()).combined!
    }

    private func decrypt(_ data: Data) throws -> Data {
        try AES.GCM.open(try AES.GCM.SealedBox(combined: data), using: Self.blobKey)
    }

    private func decryptPrekey(_ data: Data) throws -> Prekey {
        try JSONDecoder().decode(Prekey.self, from: try decrypt(data))
    }

    // MARK: - Helpers

    private func makeContact() -> Contact.Profile {
        Contact.Profile(
            identifier: UUID().uuidString, givenName: "Test", familyName: "Contact",
            middleName: "", nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
    }

    private func prekey(id: String, sequence: Int = 0) -> Prekey {
        Prekey(id: id, contactID: "c", sequence: sequence, publicKey: Data(count: 65))
    }

    // MARK: - syncInboundPrekeys

    func test_syncInbound_replacesStore_whenSequenceIsHigher() throws {
        let c = makeContact()
        c.syncInboundPrekeys(try [encrypt(prekey(id: "A")), encrypt(prekey(id: "B"))], sequence: 3)
        XCTAssertEqual(c.contactPrekeys?.count, 2)
        XCTAssertEqual(c.contactPrekeySequence, 3)
    }

    func test_syncInbound_ignores_whenSequenceIsEqual() throws {
        let c = makeContact()
        c.syncInboundPrekeys(try [encrypt(prekey(id: "A"))], sequence: 5)
        c.syncInboundPrekeys(try [encrypt(prekey(id: "B")), encrypt(prekey(id: "C"))], sequence: 5)
        XCTAssertEqual(c.contactPrekeys?.count, 1, "Equal sequence must be ignored")
    }

    func test_syncInbound_ignores_whenSequenceIsLower() throws {
        let c = makeContact()
        c.syncInboundPrekeys(try [encrypt(prekey(id: "A"))], sequence: 10)
        c.syncInboundPrekeys(try [encrypt(prekey(id: "B"))], sequence: 7)
        XCTAssertEqual(c.contactPrekeySequence, 10, "Sequence must not regress")
        XCTAssertEqual(c.contactPrekeys?.count, 1)
    }

    func test_syncInbound_replacesAll_notAppends() throws {
        let c = makeContact()
        c.syncInboundPrekeys(try [encrypt(prekey(id: "A")), encrypt(prekey(id: "B")), encrypt(prekey(id: "C"))], sequence: 1)
        c.syncInboundPrekeys(try [encrypt(prekey(id: "D"))], sequence: 2)
        XCTAssertEqual(c.contactPrekeys?.count, 1, "Replace, not append")
        XCTAssertEqual(try decryptPrekey(c.contactPrekeys![0]).id, "D")
    }

    // MARK: - popOldestPrekeyData

    func test_pop_isFIFO() throws {
        let c     = makeContact()
        let blobA = try encrypt(prekey(id: "A"))
        let blobB = try encrypt(prekey(id: "B"))
        let blobC = try encrypt(prekey(id: "C"))
        c.syncInboundPrekeys([blobA, blobB, blobC], sequence: 1)

        XCTAssertEqual(c.popOldestPrekeyData(), blobA)
        XCTAssertEqual(c.popOldestPrekeyData(), blobB)
        XCTAssertEqual(c.popOldestPrekeyData(), blobC)
        XCTAssertNil(c.popOldestPrekeyData())
    }

    func test_pop_reducesCount() throws {
        let c = makeContact()
        c.syncInboundPrekeys(try [encrypt(prekey(id: "A")), encrypt(prekey(id: "B"))], sequence: 1)
        _ = c.popOldestPrekeyData(); XCTAssertEqual(c.availableInboundPrekeyCount, 1)
        _ = c.popOldestPrekeyData(); XCTAssertEqual(c.availableInboundPrekeyCount, 0)
    }

    func test_pop_nilWhenEmpty()       { XCTAssertNil(makeContact().popOldestPrekeyData()) }
    func test_pop_nilWhenNeverSynced() { XCTAssertNil(makeContact().popOldestPrekeyData()) }

    // MARK: - hasPrekeyAvailable

    func test_hasPrekeyAvailable_true() throws {
        let c = makeContact()
        c.syncInboundPrekeys(try [encrypt(prekey(id: "A"))], sequence: 1)
        XCTAssertTrue(c.hasPrekeyAvailable)
    }

    func test_hasPrekeyAvailable_falseWhenEmpty()      { XCTAssertFalse(makeContact().hasPrekeyAvailable) }
    func test_hasPrekeyAvailable_falseAfterAllPopped() throws {
        let c = makeContact()
        c.syncInboundPrekeys(try [encrypt(prekey(id: "A"))], sequence: 1)
        _ = c.popOldestPrekeyData()
        XCTAssertFalse(c.hasPrekeyAvailable)
    }

    // MARK: - appendOwnPrekeys / findOwnPrekeyData

    func test_appendOwnPrekeys_appendsNotReplaces() throws {
        let c = makeContact()
        c.appendOwnPrekeys(try [encrypt(prekey(id: "A"))])
        c.appendOwnPrekeys(try [encrypt(prekey(id: "B")), encrypt(prekey(id: "C"))])
        XCTAssertEqual(c.ownPrekeysCount, 3, "Append must accumulate, not replace")
    }

    func test_findOwn_returnsCorrectBlobById() throws {
        let c     = makeContact()
        let blobA = try encrypt(prekey(id: "A"))
        let blobB = try encrypt(prekey(id: "B"))
        let blobC = try encrypt(prekey(id: "C"))
        c.appendOwnPrekeys([blobA, blobB, blobC])

        let found = c.findOwnPrekeyData(id: "B") { try self.decrypt($0) }
        XCTAssertEqual(found, blobB)
    }

    func test_findOwn_nilWhenIdNotPresent() throws {
        let c = makeContact()
        c.appendOwnPrekeys(try [encrypt(prekey(id: "A"))])
        XCTAssertNil(c.findOwnPrekeyData(id: "NONEXISTENT") { try self.decrypt($0) })
    }

    func test_findOwn_nilWhenStoreEmpty() {
        XCTAssertNil(makeContact().findOwnPrekeyData(id: "A") { try self.decrypt($0) })
    }

    func test_findOwn_doesNotRemoveFromStore() throws {
        let c = makeContact()
        c.appendOwnPrekeys(try [encrypt(prekey(id: "A"))])
        _ = c.findOwnPrekeyData(id: "A") { try self.decrypt($0) }
        XCTAssertEqual(c.ownPrekeysCount, 1, "find must not modify the store")
    }

    func test_findOwn_corruptEntrySkippedNoThrow() throws {
        let c = makeContact()
        c.ownPrekeys = [Data(repeating: 0xDE, count: 40)]   // corrupt blob
        let found = c.findOwnPrekeyData(id: "any") { try self.decrypt($0) }
        XCTAssertNil(found, "Corrupt entry must be skipped, not throw")
    }

    // MARK: - removeOwnPrekeyData

    func test_removeOwn_deletesCorrectBlobOnly() throws {
        let c     = makeContact()
        let blobA = try encrypt(prekey(id: "A"))
        let blobB = try encrypt(prekey(id: "B"))
        let blobC = try encrypt(prekey(id: "C"))
        c.appendOwnPrekeys([blobA, blobB, blobC])
        c.removeOwnPrekeyData(blobB)

        XCTAssertEqual(c.ownPrekeysCount, 2)
        XCTAssertFalse(c.ownPrekeys!.contains(blobB), "B must be removed")
        XCTAssertTrue(c.ownPrekeys!.contains(blobA),  "A must remain")
        XCTAssertTrue(c.ownPrekeys!.contains(blobC),  "C must remain")
    }

    func test_removeOwn_noOpWhenNotPresent() throws {
        let c = makeContact()
        c.appendOwnPrekeys(try [encrypt(prekey(id: "A"))])
        c.removeOwnPrekeyData(try encrypt(prekey(id: "PHANTOM")))
        XCTAssertEqual(c.ownPrekeysCount, 1)
    }

    func test_removeOwn_noOpOnEmptyStore() throws {
        let c = makeContact()
        c.removeOwnPrekeyData(try encrypt(prekey(id: "A")))  // no crash
        XCTAssertEqual(c.ownPrekeysCount, 0)
    }

    // MARK: - pruneOwnPrekeys

    func test_pruneOwn_removesOldSequenceBlobs() throws {
        let c = makeContact()
        let seq0A = try encrypt(prekey(id: "A", sequence: 0))
        let seq0B = try encrypt(prekey(id: "B", sequence: 0))
        let seq1A = try encrypt(prekey(id: "C", sequence: 1))
        let seq2A = try encrypt(prekey(id: "D", sequence: 2))
        c.appendOwnPrekeys([seq0A, seq0B, seq1A, seq2A])

        // Prune sequences < 1 (matches SE pruning when currentSequence = 2)
        c.pruneOwnPrekeys(olderThan: 1) { try self.decrypt($0) }

        XCTAssertEqual(c.ownPrekeysCount, 2, "seq=0 blobs must be pruned")
        XCTAssertFalse(c.ownPrekeys!.contains(seq0A))
        XCTAssertFalse(c.ownPrekeys!.contains(seq0B))
        XCTAssertTrue(c.ownPrekeys!.contains(seq1A))
        XCTAssertTrue(c.ownPrekeys!.contains(seq2A))
    }

    func test_pruneOwn_threshold0_noOp() throws {
        let c = makeContact()
        c.appendOwnPrekeys(try [encrypt(prekey(id: "A", sequence: 0))])
        c.pruneOwnPrekeys(olderThan: 0) { try self.decrypt($0) }
        XCTAssertEqual(c.ownPrekeysCount, 1, "threshold=0 must be a no-op")
    }

    func test_pruneOwn_corruptBlobKept() throws {
        let c = makeContact()
        let corrupt = Data(repeating: 0xDE, count: 40)
        let good    = try encrypt(prekey(id: "A", sequence: 0))
        c.appendOwnPrekeys([corrupt, good])
        c.pruneOwnPrekeys(olderThan: 1) { try self.decrypt($0) }
        // corrupt blob: can't decode → kept defensively
        // good blob: seq=0 < 1 → pruned
        XCTAssertEqual(c.ownPrekeysCount, 1, "corrupt blob kept, valid old blob pruned")
        XCTAssertTrue(c.ownPrekeys!.contains(corrupt))
    }

    func test_pruneOwn_noOpOnEmptyStore() {
        let c = makeContact()
        c.pruneOwnPrekeys(olderThan: 5) { try self.decrypt($0) }   // no crash
        XCTAssertEqual(c.ownPrekeysCount, 0)
    }

    // MARK: - isLikelySender

    func test_isLikelySender_trueForMatchingKeyAndNonce() throws {
        let c         = makeContact()
        let publicKey = Data(repeating: 0x42, count: 65)
        let nonce     = try OccultaBundle.SecrecyContext.generateNonce()
        let fp        = OccultaBundle.SecrecyContext.fingerprint(for: publicKey, nonce: nonce)
        XCTAssertTrue(c.isLikelySender(of: makeBundleWith(nonce: nonce, fingerprint: fp), contactPublicKey: publicKey))
    }

    func test_isLikelySender_falseForDifferentPublicKey() throws {
        let c    = makeContact()
        let key1 = Data(repeating: 0x42, count: 65)
        let key2 = Data(repeating: 0x43, count: 65)
        let nonce = try OccultaBundle.SecrecyContext.generateNonce()
        let fp    = OccultaBundle.SecrecyContext.fingerprint(for: key1, nonce: nonce)
        XCTAssertFalse(c.isLikelySender(of: makeBundleWith(nonce: nonce, fingerprint: fp), contactPublicKey: key2))
    }

    func test_isLikelySender_falseForDifferentNonce() throws {
        let c         = makeContact()
        let publicKey = Data(repeating: 0x42, count: 65)
        let nonce1    = Data(repeating: 0x01, count: 16)
        let nonce2    = Data(repeating: 0x02, count: 16)
        let fp        = OccultaBundle.SecrecyContext.fingerprint(for: publicKey, nonce: nonce1)
        XCTAssertFalse(c.isLikelySender(of: makeBundleWith(nonce: nonce2, fingerprint: fp), contactPublicKey: publicKey))
    }

    func test_isLikelySender_falseForZeroKey() throws {
        let c         = makeContact()
        let realKey   = Data(repeating: 0x42, count: 65)
        let nonce     = try OccultaBundle.SecrecyContext.generateNonce()
        let fp        = OccultaBundle.SecrecyContext.fingerprint(for: realKey, nonce: nonce)
        XCTAssertFalse(c.isLikelySender(of: makeBundleWith(nonce: nonce, fingerprint: fp), contactPublicKey: Data(count: 65)))
    }

    // MARK: - Two-array isolation

    /// Verifying the core Finding 1 fix: writing to ownPrekeys never contaminates contactPrekeys.
    func test_twoArrays_areIsolated() throws {
        let c = makeContact()

        // Simulate encryptBundle: sync their inbound keys into contactPrekeys
        c.syncInboundPrekeys(try [encrypt(prekey(id: "THEIRS-1"))], sequence: 1)

        // Simulate decrypt: append our outbound keys to ownPrekeys
        c.appendOwnPrekeys(try [encrypt(prekey(id: "OURS-1"))])

        // Assert complete isolation
        XCTAssertEqual(c.availableInboundPrekeyCount, 1)
        XCTAssertEqual(c.ownPrekeysCount, 1)

        let inboundId  = try decryptPrekey(c.contactPrekeys![0]).id
        let outboundId = try decryptPrekey(c.ownPrekeys![0]).id

        XCTAssertEqual(inboundId,  "THEIRS-1")
        XCTAssertEqual(outboundId, "OURS-1")
        XCTAssertNotEqual(inboundId, outboundId)
    }

    /// Writing a higher-sequence inbound batch does not affect ownPrekeys.
    func test_syncInbound_doesNotAffectOwnPrekeys() throws {
        let c = makeContact()
        c.appendOwnPrekeys(try [encrypt(prekey(id: "OURS-A")), encrypt(prekey(id: "OURS-B"))])
        c.syncInboundPrekeys(try [encrypt(prekey(id: "THEIRS-1"))], sequence: 5)

        XCTAssertEqual(c.ownPrekeysCount, 2, "syncInboundPrekeys must not touch ownPrekeys")
    }

    // MARK: - Helpers

    private func makeBundleWith(nonce: Data, fingerprint: Data) -> OccultaBundle {
        OccultaBundle(
            version:           .v3fs,
            secrecy:           OccultaBundle.SecrecyContext(
                mode: .longTermFallback, ephemeralPublicKey: Data(count: 65),
                prekeyID: nil, prekeySequence: nil, prekeyBatch: nil
            ),
            ciphertext:        Data(count: 28),
            fingerprintNonce:  nonce,
            senderFingerprint: fingerprint
        )
    }
}

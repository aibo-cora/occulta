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

    /// Non-throwing — matches the `(Data) -> Data?` signature required by
    /// `syncInboundPrekeys` and `pruneOwnPrekeys`.
    private func decryptBlob(_ data: Data) -> Data? {
        try? AES.GCM.open(try AES.GCM.SealedBox(combined: data), using: Self.blobKey)
    }

    /// Throwing — used where `findOwnPrekeyData` expects `(Data) throws -> Data?`.
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

    // MARK: - syncInboundPrekeys — sequence guard

    func test_syncInbound_acceptsHigherSequence() throws {
        let c = makeContact()
        c.syncInboundPrekeys(
            try [encrypt(prekey(id: "A")), encrypt(prekey(id: "B"))],
            sequence: 3,
            decryptor: decryptBlob
        )
        XCTAssertEqual(c.contactPrekeys?.count, 2)
        XCTAssertEqual(c.contactPrekeySequence, 3)
    }

    func test_syncInbound_ignores_equalSequence() throws {
        let c = makeContact()
        c.syncInboundPrekeys(try [encrypt(prekey(id: "A"))], sequence: 5, decryptor: decryptBlob)
        c.syncInboundPrekeys(try [encrypt(prekey(id: "B")), encrypt(prekey(id: "C"))], sequence: 5, decryptor: decryptBlob)
        XCTAssertEqual(c.contactPrekeys?.count, 1, "Equal sequence must be ignored")
    }

    func test_syncInbound_ignores_lowerSequence() throws {
        let c = makeContact()
        c.syncInboundPrekeys(try [encrypt(prekey(id: "A"))], sequence: 10, decryptor: decryptBlob)
        c.syncInboundPrekeys(try [encrypt(prekey(id: "B"))], sequence: 7, decryptor: decryptBlob)
        XCTAssertEqual(c.contactPrekeySequence, 10, "Sequence must not regress")
        XCTAssertEqual(c.contactPrekeys?.count, 1)
    }

    // MARK: - syncInboundPrekeys — prune-then-append semantics

    /// Dead keys (seq < incoming - 1) are pruned; the new batch is appended.
    /// seq=0 keys are dead when seq=2 arrives (threshold = 2-1 = 1, 0 < 1 → pruned).
    func test_syncInbound_prunesDeadKeys_appendsNew() throws {
        let c = makeContact()
        // First batch: seq=0 prekeys (A, B, C)
        c.syncInboundPrekeys(
            try [encrypt(prekey(id: "A", sequence: 0)),
                 encrypt(prekey(id: "B", sequence: 0)),
                 encrypt(prekey(id: "C", sequence: 0))],
            sequence: 1,
            decryptor: decryptBlob
        )
        // Second batch: seq=1 prekeys (D)
        // threshold = 2 - 1 = 1; existing seq=0 keys have sequence < 1 → pruned
        c.syncInboundPrekeys(
            try [encrypt(prekey(id: "D", sequence: 1))],
            sequence: 2,
            decryptor: decryptBlob
        )
        XCTAssertEqual(c.contactPrekeys?.count, 1, "Dead seq=0 keys pruned, only D remains")
        XCTAssertEqual(try decryptPrekey(c.contactPrekeys![0]).id, "D")
    }

    /// Valid unconsumed keys (seq >= incoming - 1) are preserved and new batch appended.
    /// seq=1 keys survive when seq=2 arrives (threshold = 2-1 = 1, 1 >= 1 → kept).
    func test_syncInbound_keepsValidUnconsumedKeys_appendsNew() throws {
        let c = makeContact()
        // First batch: seq=1 prekeys (A, B) — still valid when seq=2 arrives
        c.syncInboundPrekeys(
            try [encrypt(prekey(id: "A", sequence: 1)),
                 encrypt(prekey(id: "B", sequence: 1))],
            sequence: 1,
            decryptor: decryptBlob
        )
        // Second batch: seq=2 prekeys (C, D)
        // threshold = 3 - 1 = 2; existing seq=1 keys have sequence >= 1 → kept
        // Wait, incoming sequence IS 2 here, so threshold = 2 - 1 = 1. seq=1 >= 1 → kept.
        c.syncInboundPrekeys(
            try [encrypt(prekey(id: "C", sequence: 2)),
                 encrypt(prekey(id: "D", sequence: 2))],
            sequence: 2,
            decryptor: decryptBlob
        )
        // seq=1 A and B survive (still valid); C and D appended
        XCTAssertEqual(c.contactPrekeys?.count, 4,
            "seq=1 keys are still valid and must be kept; new batch appended")
        let ids = try c.contactPrekeys!.map { try decryptPrekey($0).id }
        XCTAssertTrue(ids.contains("A") && ids.contains("B"), "Valid seq=1 keys must survive")
        XCTAssertTrue(ids.contains("C") && ids.contains("D"), "New seq=2 keys must be appended")
    }

    /// Corrupt blobs that cannot be decrypted are kept defensively.
    func test_syncInbound_corruptBlobKept_onPrune() throws {
        let c = makeContact()
        let corrupt = Data(repeating: 0xDE, count: 40)
        c.contactPrekeys = [corrupt]
        c.contactPrekeySequence = 0
        // New batch at seq=2 — would prune seq < 1, but corrupt blob can't be decoded → kept
        c.syncInboundPrekeys(
            try [encrypt(prekey(id: "A", sequence: 2))],
            sequence: 2,
            decryptor: decryptBlob
        )
        XCTAssertTrue(c.contactPrekeys!.contains(corrupt), "Corrupt blob kept defensively")
    }

    // MARK: - popOldestPrekeyData

    func test_pop_isFIFO() throws {
        let c     = makeContact()
        let blobA = try encrypt(prekey(id: "A"))
        let blobB = try encrypt(prekey(id: "B"))
        let blobC = try encrypt(prekey(id: "C"))
        c.syncInboundPrekeys([blobA, blobB, blobC], sequence: 1, decryptor: decryptBlob)

        XCTAssertEqual(c.popOldestPrekeyData(), blobA)
        XCTAssertEqual(c.popOldestPrekeyData(), blobB)
        XCTAssertEqual(c.popOldestPrekeyData(), blobC)
        XCTAssertNil(c.popOldestPrekeyData())
    }

    func test_pop_reducesCount() throws {
        let c = makeContact()
        c.syncInboundPrekeys(
            try [encrypt(prekey(id: "A")), encrypt(prekey(id: "B"))],
            sequence: 1,
            decryptor: decryptBlob
        )
        _ = c.popOldestPrekeyData(); XCTAssertEqual(c.availableInboundPrekeyCount, 1)
        _ = c.popOldestPrekeyData(); XCTAssertEqual(c.availableInboundPrekeyCount, 0)
    }

    func test_pop_nilWhenEmpty()       { XCTAssertNil(makeContact().popOldestPrekeyData()) }
    func test_pop_nilWhenNeverSynced() { XCTAssertNil(makeContact().popOldestPrekeyData()) }

    // MARK: - hasPrekeyAvailable

    func test_hasPrekeyAvailable_true() throws {
        let c = makeContact()
        c.syncInboundPrekeys(try [encrypt(prekey(id: "A"))], sequence: 1, decryptor: decryptBlob)
        XCTAssertTrue(c.hasPrekeyAvailable)
    }

    func test_hasPrekeyAvailable_falseWhenEmpty() { XCTAssertFalse(makeContact().hasPrekeyAvailable) }

    func test_hasPrekeyAvailable_falseAfterAllPopped() throws {
        let c = makeContact()
        c.syncInboundPrekeys(try [encrypt(prekey(id: "A"))], sequence: 1, decryptor: decryptBlob)
        _ = c.popOldestPrekeyData()
        XCTAssertFalse(c.hasPrekeyAvailable)
    }

    // MARK: - appendOwnPrekeys / findOwnPrekeyData

    func test_appendOwnPrekeys_appendsNotReplaces() throws {
        let c = makeContact()
        c.appendOwnPrekeys(try [encrypt(prekey(id: "A"))])
        c.appendOwnPrekeys(try [encrypt(prekey(id: "B")), encrypt(prekey(id: "C"))])
        XCTAssertEqual(c.ownPrekeysCount, 3)
    }

    func test_findOwn_returnsCorrectBlobById() throws {
        let c     = makeContact()
        let blobA = try encrypt(prekey(id: "A"))
        let blobB = try encrypt(prekey(id: "B"))
        let blobC = try encrypt(prekey(id: "C"))
        c.appendOwnPrekeys([blobA, blobB, blobC])
        XCTAssertEqual(c.findOwnPrekeyData(id: "B") { try self.decrypt($0) }, blobB)
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
        XCTAssertEqual(c.ownPrekeysCount, 1)
    }

    func test_findOwn_corruptEntrySkippedNoThrow() {
        let c = makeContact()
        c.ownPrekeys = [Data(repeating: 0xDE, count: 40)]
        XCTAssertNil(c.findOwnPrekeyData(id: "any") { try self.decrypt($0) })
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
        XCTAssertFalse(c.ownPrekeys!.contains(blobB))
        XCTAssertTrue(c.ownPrekeys!.contains(blobA))
        XCTAssertTrue(c.ownPrekeys!.contains(blobC))
    }

    func test_removeOwn_noOpWhenNotPresent() throws {
        let c = makeContact()
        c.appendOwnPrekeys(try [encrypt(prekey(id: "A"))])
        c.removeOwnPrekeyData(try encrypt(prekey(id: "PHANTOM")))
        XCTAssertEqual(c.ownPrekeysCount, 1)
    }

    func test_removeOwn_noOpOnEmptyStore() throws {
        let c = makeContact()
        c.removeOwnPrekeyData(try encrypt(prekey(id: "A")))
        XCTAssertEqual(c.ownPrekeysCount, 0)
    }

    // MARK: - pruneOwnPrekeys
    //
    // NOTE: decryptor must be non-throwing — (Data) -> Data?
    // Use decryptBlob (non-throwing helper), not decrypt (throwing helper).

    func test_pruneOwn_removesOldSequenceBlobs() throws {
        let c     = makeContact()
        let seq0A = try encrypt(prekey(id: "A", sequence: 0))
        let seq0B = try encrypt(prekey(id: "B", sequence: 0))
        let seq1A = try encrypt(prekey(id: "C", sequence: 1))
        let seq2A = try encrypt(prekey(id: "D", sequence: 2))
        c.appendOwnPrekeys([seq0A, seq0B, seq1A, seq2A])

        c.pruneOwnPrekeys(olderThan: 1, decryptor: decryptBlob)

        XCTAssertEqual(c.ownPrekeysCount, 2, "seq=0 must be pruned")
        XCTAssertFalse(c.ownPrekeys!.contains(seq0A))
        XCTAssertFalse(c.ownPrekeys!.contains(seq0B))
        XCTAssertTrue(c.ownPrekeys!.contains(seq1A))
        XCTAssertTrue(c.ownPrekeys!.contains(seq2A))
    }

    func test_pruneOwn_threshold0_noOp() throws {
        let c = makeContact()
        c.appendOwnPrekeys(try [encrypt(prekey(id: "A", sequence: 0))])
        c.pruneOwnPrekeys(olderThan: 0, decryptor: decryptBlob)
        XCTAssertEqual(c.ownPrekeysCount, 1)
    }

    func test_pruneOwn_corruptBlobKept() throws {
        let c       = makeContact()
        let corrupt = Data(repeating: 0xDE, count: 40)
        let good    = try encrypt(prekey(id: "A", sequence: 0))
        c.appendOwnPrekeys([corrupt, good])
        c.pruneOwnPrekeys(olderThan: 1, decryptor: decryptBlob)
        XCTAssertEqual(c.ownPrekeysCount, 1, "corrupt kept, seq=0 good blob pruned")
        XCTAssertTrue(c.ownPrekeys!.contains(corrupt))
    }

    func test_pruneOwn_noOpOnEmptyStore() {
        let c = makeContact()
        c.pruneOwnPrekeys(olderThan: 5, decryptor: decryptBlob)
        XCTAssertEqual(c.ownPrekeysCount, 0)
    }

    // MARK: - Pending outbound batch

    func test_pendingBatch_nilOnNewContact() {
        XCTAssertNil(makeContact().loadPendingBatch())
        XCTAssertFalse(makeContact().hasPendingBatch)
    }

    func test_pendingBatch_storeAndLoad() throws {
        let c     = makeContact()
        let batch = OccultaBundle.PrekeySyncBatch(
            sequence: 3,
            prekeys:  [Prekey(id: "X", contactID: "c", sequence: 3, publicKey: Data(count: 65))]
        )
        try c.storePendingBatch(batch)
        let loaded = c.loadPendingBatch()
        XCTAssertNotNil(loaded)
        XCTAssertEqual(loaded?.sequence, 3)
        XCTAssertEqual(loaded?.prekeys.count, 1)
        XCTAssertEqual(loaded?.prekeys.first?.id, "X")
    }

    func test_pendingBatch_hasPendingBatch_trueAfterStore() throws {
        let c     = makeContact()
        let batch = OccultaBundle.PrekeySyncBatch(sequence: 1, prekeys: [])
        try c.storePendingBatch(batch)
        XCTAssertTrue(c.hasPendingBatch)
    }

    func test_pendingBatch_clearSetsNil() throws {
        let c     = makeContact()
        let batch = OccultaBundle.PrekeySyncBatch(sequence: 1, prekeys: [])
        try c.storePendingBatch(batch)
        c.clearPendingBatch()
        XCTAssertNil(c.loadPendingBatch())
        XCTAssertFalse(c.hasPendingBatch)
    }

    func test_pendingBatch_storeReplacesExisting() throws {
        let c      = makeContact()
        let batch1 = OccultaBundle.PrekeySyncBatch(sequence: 1, prekeys: [])
        let batch2 = OccultaBundle.PrekeySyncBatch(sequence: 2, prekeys: [])
        try c.storePendingBatch(batch1)
        try c.storePendingBatch(batch2)
        XCTAssertEqual(c.loadPendingBatch()?.sequence, 2,
                       "Second store must overwrite first")
    }

    func test_pendingBatch_survivesClearAndStore() throws {
        let c = makeContact()
        let b1 = OccultaBundle.PrekeySyncBatch(sequence: 5, prekeys: [])
        try c.storePendingBatch(b1)
        c.clearPendingBatch()
        XCTAssertFalse(c.hasPendingBatch)
        let b2 = OccultaBundle.PrekeySyncBatch(sequence: 6, prekeys: [])
        try c.storePendingBatch(b2)
        XCTAssertEqual(c.loadPendingBatch()?.sequence, 6)
    }

    // MARK: - Two-array isolation

    func test_twoArrays_areIsolated() throws {
        let c = makeContact()
        c.syncInboundPrekeys(try [encrypt(prekey(id: "THEIRS-1"))], sequence: 1, decryptor: decryptBlob)
        c.appendOwnPrekeys(try [encrypt(prekey(id: "OURS-1"))])

        XCTAssertEqual(c.availableInboundPrekeyCount, 1)
        XCTAssertEqual(c.ownPrekeysCount, 1)

        let inboundId  = try decryptPrekey(c.contactPrekeys![0]).id
        let outboundId = try decryptPrekey(c.ownPrekeys![0]).id

        XCTAssertEqual(inboundId,  "THEIRS-1")
        XCTAssertEqual(outboundId, "OURS-1")
        XCTAssertNotEqual(inboundId, outboundId)
    }

    func test_syncInbound_doesNotAffectOwnPrekeys() throws {
        let c = makeContact()
        c.appendOwnPrekeys(try [encrypt(prekey(id: "OURS-A")), encrypt(prekey(id: "OURS-B"))])
        c.syncInboundPrekeys(try [encrypt(prekey(id: "THEIRS-1"))], sequence: 5, decryptor: decryptBlob)
        XCTAssertEqual(c.ownPrekeysCount, 2)
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
        let c     = makeContact()
        let key1  = Data(repeating: 0x42, count: 65)
        let key2  = Data(repeating: 0x43, count: 65)
        let nonce = try OccultaBundle.SecrecyContext.generateNonce()
        let fp    = OccultaBundle.SecrecyContext.fingerprint(for: key1, nonce: nonce)
        XCTAssertFalse(c.isLikelySender(of: makeBundleWith(nonce: nonce, fingerprint: fp), contactPublicKey: key2))
    }

    func test_isLikelySender_falseForDifferentNonce() throws {
        let c         = makeContact()
        let publicKey = Data(repeating: 0x42, count: 65)
        let fp        = OccultaBundle.SecrecyContext.fingerprint(
            for: publicKey, nonce: Data(repeating: 0x01, count: 16)
        )
        XCTAssertFalse(c.isLikelySender(
            of: makeBundleWith(nonce: Data(repeating: 0x02, count: 16), fingerprint: fp),
            contactPublicKey: publicKey
        ))
    }

    func test_isLikelySender_falseForZeroKey() throws {
        let c         = makeContact()
        let realKey   = Data(repeating: 0x42, count: 65)
        let nonce     = try OccultaBundle.SecrecyContext.generateNonce()
        let fp        = OccultaBundle.SecrecyContext.fingerprint(for: realKey, nonce: nonce)
        XCTAssertFalse(c.isLikelySender(of: makeBundleWith(nonce: nonce, fingerprint: fp), contactPublicKey: Data(count: 65)))
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

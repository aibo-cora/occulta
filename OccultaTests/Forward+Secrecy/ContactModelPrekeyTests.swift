//
//  ContactModelPrekeyTests.swift
//  OccultaTests
//
//  Tests for Contact.Profile prekey extension methods.
//  No SE. No Manager.Crypto. No SwiftData container.
//
//  Blobs are encrypted with a fixed in-memory SymmetricKey so tests
//  can verify store/retrieve semantics without any SE dependency.
//  These tests are safe to run in the simulator.
//

import XCTest
internal import CryptoKit
@testable import Occulta

final class ContactModelPrekeyTests: XCTestCase {

    // MARK: - Fixed test encryption (no SE)

    /// Single key shared across all tests in this class.
    /// Static so all tests share the same key — blobs encrypted in one test
    /// can be decrypted in helpers called by any other test in the class.
    private static let blobKey = SymmetricKey(size: .bits256)

    private func encrypt(_ prekey: Prekey) throws -> Data {
        let encoded = try JSONEncoder().encode(prekey)
        let sealed  = try AES.GCM.seal(encoded, using: Self.blobKey, nonce: AES.GCM.Nonce())
        return sealed.combined!
    }

    private func decrypt(_ data: Data) throws -> Data {
        let box = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(box, using: Self.blobKey)
    }

    private func decryptPrekey(_ data: Data) throws -> Prekey {
        let raw = try decrypt(data)
        return try JSONDecoder().decode(Prekey.self, from: raw)
    }

    // MARK: - Helpers

    private func makeContact() -> Contact.Profile {
        Contact.Profile(
            identifier:       UUID().uuidString,
            givenName:        "Test",
            familyName:       "Contact",
            middleName:       "",
            nickname:         "",
            organizationName: "",
            departmentName:   "",
            jobTitle:         ""
        )
    }

    private func prekey(id: String, sequence: Int = 0) -> Prekey {
        Prekey(id: id, contactID: "c", sequence: sequence, publicKey: Data(count: 65))
    }

    // MARK: - syncPrekeyData

    func test_sync_replacesStore_whenSequenceIsHigher() throws {
        let contact = makeContact()
        let blobA   = try encrypt(prekey(id: "A", sequence: 3))
        let blobB   = try encrypt(prekey(id: "B", sequence: 3))

        contact.syncPrekeyData([blobA, blobB], sequence: 3)

        XCTAssertEqual(contact.contactPrekeys?.count, 2)
        XCTAssertEqual(contact.contactPrekeySequence, 3)
    }

    func test_sync_ignores_whenSequenceIsEqual() throws {
        let contact = makeContact()
        let original = try [encrypt(prekey(id: "A"))]
        contact.syncPrekeyData(original, sequence: 5)

        let duplicate = try [encrypt(prekey(id: "B")), encrypt(prekey(id: "C"))]
        contact.syncPrekeyData(duplicate, sequence: 5) // same sequence — must be ignored

        XCTAssertEqual(contact.contactPrekeys?.count, 1,
                       "Equal sequence must be ignored — store must not change")
        XCTAssertEqual(contact.contactPrekeySequence, 5)
    }

    func test_sync_ignores_whenSequenceIsLower() throws {
        let contact = makeContact()
        contact.syncPrekeyData(try [encrypt(prekey(id: "A"))], sequence: 10)

        contact.syncPrekeyData(try [encrypt(prekey(id: "B"))], sequence: 7) // stale

        XCTAssertEqual(contact.contactPrekeySequence, 10,
                       "Sequence must not regress")
        XCTAssertEqual(contact.contactPrekeys?.count, 1,
                       "Store must not change on stale batch")
    }

    func test_sync_replacesAllExistingKeys() throws {
        let contact = makeContact()
        contact.syncPrekeyData(
            try [encrypt(prekey(id: "A")), encrypt(prekey(id: "B")), encrypt(prekey(id: "C"))],
            sequence: 1
        )
        XCTAssertEqual(contact.contactPrekeys?.count, 3)

        contact.syncPrekeyData(try [encrypt(prekey(id: "D"))], sequence: 2)

        XCTAssertEqual(contact.contactPrekeys?.count, 1,
                       "New batch must fully replace old keys, not append")
        let stored = try decryptPrekey(contact.contactPrekeys![0])
        XCTAssertEqual(stored.id, "D")
    }

    // MARK: - popOldestPrekeyData (FIFO)

    func test_pop_isFIFO() throws {
        let contact = makeContact()
        let blobA   = try encrypt(prekey(id: "A"))
        let blobB   = try encrypt(prekey(id: "B"))
        let blobC   = try encrypt(prekey(id: "C"))
        contact.syncPrekeyData([blobA, blobB, blobC], sequence: 1)

        let first  = contact.popOldestPrekeyData()
        let second = contact.popOldestPrekeyData()
        let third  = contact.popOldestPrekeyData()
        let fourth = contact.popOldestPrekeyData()

        XCTAssertEqual(first,  blobA, "First pop must return oldest (A)")
        XCTAssertEqual(second, blobB, "Second pop must return next (B)")
        XCTAssertEqual(third,  blobC, "Third pop must return last (C)")
        XCTAssertNil(fourth,          "Fourth pop on empty store must return nil")
    }

    func test_pop_reducesCount() throws {
        let contact = makeContact()
        contact.syncPrekeyData(
            try [encrypt(prekey(id: "A")), encrypt(prekey(id: "B"))],
            sequence: 1
        )

        _ = contact.popOldestPrekeyData()
        XCTAssertEqual(contact.storedPrekeyCount, 1)

        _ = contact.popOldestPrekeyData()
        XCTAssertEqual(contact.storedPrekeyCount, 0)
    }

    func test_pop_nilWhenStoreEmpty() {
        let contact = makeContact()
        XCTAssertNil(contact.popOldestPrekeyData())
    }

    func test_pop_nilWhenNeverSynced() {
        let contact = makeContact()
        XCTAssertNil(contact.popOldestPrekeyData())
    }

    // MARK: - hasPrekeyAvailable

    func test_hasPrekeyAvailable_trueWhenStoreHasEntries() throws {
        let contact = makeContact()
        contact.syncPrekeyData(try [encrypt(prekey(id: "A"))], sequence: 1)
        XCTAssertTrue(contact.hasPrekeyAvailable)
    }

    func test_hasPrekeyAvailable_falseWhenEmpty() {
        XCTAssertFalse(makeContact().hasPrekeyAvailable)
    }

    func test_hasPrekeyAvailable_falseAfterAllPopped() throws {
        let contact = makeContact()
        contact.syncPrekeyData(try [encrypt(prekey(id: "A"))], sequence: 1)
        _ = contact.popOldestPrekeyData()
        XCTAssertFalse(contact.hasPrekeyAvailable)
    }

    // MARK: - findPrekeyData

    func test_find_returnsCorrectBlobById() throws {
        let contact = makeContact()
        let blobA   = try encrypt(prekey(id: "A"))
        let blobB   = try encrypt(prekey(id: "B"))
        let blobC   = try encrypt(prekey(id: "C"))
        contact.syncPrekeyData([blobA, blobB, blobC], sequence: 1)

        let found = contact.findPrekeyData(id: "B") { try self.decrypt($0) }

        XCTAssertEqual(found, blobB, "Must return the blob for id B")
    }

    func test_find_nilWhenIdNotPresent() throws {
        let contact = makeContact()
        contact.syncPrekeyData(try [encrypt(prekey(id: "A"))], sequence: 1)

        let found = contact.findPrekeyData(id: "NONEXISTENT") { try self.decrypt($0) }

        XCTAssertNil(found)
    }

    func test_find_nilWhenStoreEmpty() {
        let contact = makeContact()
        let found   = contact.findPrekeyData(id: "A") { try self.decrypt($0) }
        XCTAssertNil(found)
    }

    func test_find_doesNotRemoveBlobFromStore() throws {
        let contact = makeContact()
        contact.syncPrekeyData(try [encrypt(prekey(id: "A"))], sequence: 1)

        _ = contact.findPrekeyData(id: "A") { try self.decrypt($0) }

        XCTAssertEqual(contact.storedPrekeyCount, 1,
                       "findPrekeyData must not modify the store")
    }

    func test_find_decryptErrorSkipsEntry_returnsNilNotThrow() throws {
        let contact = makeContact()
        // Store a blob that is valid JSON but cannot be decrypted by our test key
        // Simulate a corrupted entry by storing raw bytes that will fail GCM open
        let corruptBlob = Data(repeating: 0xDE, count: 40)
        contact.contactPrekeys = [corruptBlob]

        // Should not throw — decrypt errors are swallowed per-entry
        let found = contact.findPrekeyData(id: "any") { try self.decrypt($0) }
        XCTAssertNil(found)
    }

    // MARK: - removePrekeyData

    func test_remove_deletesCorrectBlobOnly() throws {
        let contact = makeContact()
        let blobA   = try encrypt(prekey(id: "A"))
        let blobB   = try encrypt(prekey(id: "B"))
        let blobC   = try encrypt(prekey(id: "C"))
        contact.syncPrekeyData([blobA, blobB, blobC], sequence: 1)

        contact.removePrekeyData(blobB)

        XCTAssertEqual(contact.storedPrekeyCount, 2)
        XCTAssertFalse(contact.contactPrekeys!.contains(blobB), "B must be removed")
        XCTAssertTrue(contact.contactPrekeys!.contains(blobA),  "A must remain")
        XCTAssertTrue(contact.contactPrekeys!.contains(blobC),  "C must remain")
    }

    func test_remove_noOpWhenBlobNotPresent() throws {
        let contact  = makeContact()
        let blobA    = try encrypt(prekey(id: "A"))
        let phantom  = try encrypt(prekey(id: "PHANTOM"))
        contact.syncPrekeyData([blobA], sequence: 1)

        contact.removePrekeyData(phantom) // not in store

        XCTAssertEqual(contact.storedPrekeyCount, 1, "Store must be unchanged")
    }

    func test_remove_noOpOnEmptyStore() throws {
        let contact = makeContact()
        let blob    = try encrypt(prekey(id: "A"))
        contact.removePrekeyData(blob) // no crash expected
        XCTAssertEqual(contact.storedPrekeyCount, 0)
    }

    // MARK: - isLikelySender

    func test_isLikelySender_trueForMatchingKeyAndNonce() {
        let contact   = makeContact()
        let publicKey = Data(repeating: 0x42, count: 65)
        let nonce     = OccultaBundle.SecrecyContext.generateNonce()
        let fp        = OccultaBundle.SecrecyContext.fingerprint(for: publicKey, nonce: nonce)
        let bundle    = makeBundleWith(nonce: nonce, fingerprint: fp)

        XCTAssertTrue(contact.isLikelySender(of: bundle, contactPublicKey: publicKey))
    }

    func test_isLikelySender_falseForDifferentPublicKey() {
        let contact  = makeContact()
        let key1     = Data(repeating: 0x42, count: 65)
        let key2     = Data(repeating: 0x43, count: 65)
        let nonce    = OccultaBundle.SecrecyContext.generateNonce()
        let fp       = OccultaBundle.SecrecyContext.fingerprint(for: key1, nonce: nonce)
        let bundle   = makeBundleWith(nonce: nonce, fingerprint: fp)

        XCTAssertFalse(contact.isLikelySender(of: bundle, contactPublicKey: key2),
                       "Different public key must not match fingerprint")
    }

    func test_isLikelySender_falseForDifferentNonce() {
        let contact   = makeContact()
        let publicKey = Data(repeating: 0x42, count: 65)
        let nonce1    = Data(repeating: 0x01, count: 16)
        let nonce2    = Data(repeating: 0x02, count: 16)
        let fp        = OccultaBundle.SecrecyContext.fingerprint(for: publicKey, nonce: nonce1)
        // Bundle carries nonce2 but fingerprint was computed with nonce1
        let bundle    = makeBundleWith(nonce: nonce2, fingerprint: fp)

        XCTAssertFalse(contact.isLikelySender(of: bundle, contactPublicKey: publicKey),
                       "Fingerprint computed with different nonce must not match")
    }

    func test_isLikelySender_falseForZeroKey() {
        let contact   = makeContact()
        let realKey   = Data(repeating: 0x42, count: 65)
        let zeroKey   = Data(count: 65)
        let nonce     = OccultaBundle.SecrecyContext.generateNonce()
        let fp        = OccultaBundle.SecrecyContext.fingerprint(for: realKey, nonce: nonce)
        let bundle    = makeBundleWith(nonce: nonce, fingerprint: fp)

        XCTAssertFalse(contact.isLikelySender(of: bundle, contactPublicKey: zeroKey))
    }

    // MARK: - Helpers

    private func makeBundleWith(nonce: Data, fingerprint: Data) -> OccultaBundle {
        let secrecy = OccultaBundle.SecrecyContext(
            mode:               .longTermFallback,
            ephemeralPublicKey: Data(count: 65),
            prekeyID:           nil,
            prekeySequence:     nil,
            fingerprintNonce:   nonce,
            senderFingerprint:  fingerprint,
            prekeyBatch:        nil
        )
        return OccultaBundle(
            version:    .v3fs,
            secrecy:    secrecy,
            ciphertext: Data(count: 28)
        )
    }
}

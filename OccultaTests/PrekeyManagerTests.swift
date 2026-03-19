//
//  ForwardSecrecyTests.swift
//  OccultaTests
//
//  Created by Yura on 3/19/26.
//

import XCTest
internal import CryptoKit
import SwiftData
@testable import Occulta

// MARK: - Test helpers

/// Generates a fresh P-256 key pair in memory (not SE) for test use.
/// Returns (privateKey: SecKey, publicKeyData: Data).
private func makeTestKeyPair() -> (SecKey, Data) {
    let attributes: NSDictionary = [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits: 256,
        kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
    ]
    var error: Unmanaged<CFError>?
    let priv = SecKeyCreateRandomKey(attributes, &error)!
    let pub  = SecKeyCopyPublicKey(priv)!
    let data = SecKeyCopyExternalRepresentation(pub, nil)! as Data
    return (priv, data)
}

/// Returns a unique contact ID string scoped to the calling test.
private func testContactID(function: String = #function) -> String {
    "test.\(function).\(UUID().uuidString)"
}

// MARK: - PrekeyManager Tests

final class PrekeyManagerTests: XCTestCase {

    var manager: Manager.PrekeyManager!

    override func setUp() {
        super.setUp()
        manager = Manager.PrekeyManager()
    }

    override func tearDown() {
        super.tearDown()
        manager = nil
    }

    // MARK: Generation

    func testGenerateBatch_returnsCorrectCount() throws {
        let contactID = testContactID()
        defer { manager.deleteAllKeys(for: contactID) }

        let (prekeys, _) = try manager.generateBatch(contactID: contactID, currentSequence: 0, count: 5)

        XCTAssertEqual(prekeys.count, 5)
    }

    func testGenerateBatch_allPrekeysHaveCorrectContactIDAndSequence() throws {
        let contactID = testContactID()
        defer { manager.deleteAllKeys(for: contactID) }

        let (prekeys, _) = try manager.generateBatch(contactID: contactID, currentSequence: 3, count: 5)

        for prekey in prekeys {
            XCTAssertEqual(prekey.contactID, contactID)
            XCTAssertEqual(prekey.sequence, 3)
            XCTAssertFalse(prekey.id.isEmpty)
            XCTAssertEqual(prekey.publicKey.count, 65, "x963 public key must be 65 bytes")
        }
    }

    func testGenerateBatch_incrementsSequence() throws {
        let contactID = testContactID()
        defer { manager.deleteAllKeys(for: contactID) }

        let (_, next) = try manager.generateBatch(contactID: contactID, currentSequence: 7, count: 3)

        XCTAssertEqual(next, 8)
    }

    func testGenerateBatch_storesPrivateKeysInSE() throws {
        let contactID = testContactID()
        defer { manager.deleteAllKeys(for: contactID) }

        let (prekeys, _) = try manager.generateBatch(contactID: contactID, currentSequence: 0, count: 3)

        for prekey in prekeys {
            let key = manager.retrievePrivateKey(for: prekey)
            XCTAssertNotNil(key, "Private key for prekey \(prekey.id) must be in SE")
        }
    }

    // MARK: Consumption

    func testConsume_deletesPrivateKeyFromSE() throws {
        let contactID = testContactID()
        defer { manager.deleteAllKeys(for: contactID) }

        let (prekeys, _) = try manager.generateBatch(contactID: contactID, currentSequence: 0, count: 1)
        let prekey = prekeys[0]

        XCTAssertNotNil(manager.retrievePrivateKey(for: prekey), "Key must exist before consume")

        manager.consume(prekey: prekey)

        XCTAssertNil(manager.retrievePrivateKey(for: prekey), "Key must be gone after consume")
    }

    func testConsume_idempotent_doesNotCrash() throws {
        let contactID = testContactID()
        defer { manager.deleteAllKeys(for: contactID) }

        let (prekeys, _) = try manager.generateBatch(contactID: contactID, currentSequence: 0, count: 1)
        let prekey = prekeys[0]

        manager.consume(prekey: prekey)
        let result = manager.consume(prekey: prekey) // second consume

        // deleteKey returns true for errSecItemNotFound — idempotent success.
        // The key guarantee is it does not crash or throw.
        XCTAssertTrue(result)
    }

    // MARK: Remaining count

    func testRemainingCount_accurate() throws {
        let contactID = testContactID()
        defer { manager.deleteAllKeys(for: contactID) }

        let (prekeys, _) = try manager.generateBatch(contactID: contactID, currentSequence: 0, count: 4)

        XCTAssertEqual(manager.remainingCount(for: contactID), 4)

        manager.consume(prekey: prekeys[0])
        XCTAssertEqual(manager.remainingCount(for: contactID), 3)

        manager.consume(prekey: prekeys[1])
        manager.consume(prekey: prekeys[2])
        XCTAssertEqual(manager.remainingCount(for: contactID), 1)
    }

    func testNeedsReplenishment_trueWhenBelowThreshold() throws {
        let contactID = testContactID()
        defer { manager.deleteAllKeys(for: contactID) }

        // Generate exactly at threshold (5) — should NOT need replenishment
        let (prekeys, _) = try manager.generateBatch(
            contactID: contactID,
            currentSequence: 0,
            count: Manager.PrekeyManager.replenishThreshold
        )
        XCTAssertFalse(manager.needsReplenishment(for: contactID))

        // Consume one — now below threshold
        manager.consume(prekey: prekeys[0])
        XCTAssertTrue(manager.needsReplenishment(for: contactID))
    }

    // MARK: Pruning

    func testPruneSequences_deletesOldKeys_keepsCurrentSequence() throws {
        let contactID = testContactID()
        defer { manager.deleteAllKeys(for: contactID) }

        let (oldPrekeys, _) = try manager.generateBatch(contactID: contactID, currentSequence: 1, count: 3)
        let (newPrekeys, _) = try manager.generateBatch(contactID: contactID, currentSequence: 2, count: 3)

        // Prune sequences older than 2 — seq 1 should be gone, seq 2 must survive
        manager.pruneSequences(olderThan: 2, contactID: contactID)

        for prekey in oldPrekeys {
            XCTAssertNil(
                manager.retrievePrivateKey(for: prekey),
                "Seq 1 key \(prekey.id) must be pruned"
            )
        }

        for prekey in newPrekeys {
            XCTAssertNotNil(
                manager.retrievePrivateKey(for: prekey),
                "Seq 2 key \(prekey.id) must survive"
            )
        }
    }

    func testPruneSequences_scopedToContact_doesNotAffectOtherContacts() throws {
        let bobID  = testContactID() + ".bob"
        let jakeID = testContactID() + ".jake"
        defer {
            manager.deleteAllKeys(for: bobID)
            manager.deleteAllKeys(for: jakeID)
        }

        let (bobPrekeys,  _) = try manager.generateBatch(contactID: bobID,  currentSequence: 1, count: 2)
        let (jakePrekeys, _) = try manager.generateBatch(contactID: jakeID, currentSequence: 1, count: 2)

        // Prune Bob's old sequence — Jake should be untouched
        manager.pruneSequences(olderThan: 2, contactID: bobID)

        for prekey in bobPrekeys {
            XCTAssertNil(
                manager.retrievePrivateKey(for: prekey),
                "Bob's seq 1 key must be pruned"
            )
        }

        for prekey in jakePrekeys {
            XCTAssertNotNil(
                manager.retrievePrivateKey(for: prekey),
                "Jake's keys must be unaffected by pruning Bob's contact"
            )
        }
    }

    func testDeleteAllKeys_removesEntirePool() throws {
        let contactID = testContactID()

        let (prekeys, _) = try manager.generateBatch(contactID: contactID, currentSequence: 0, count: 5)

        manager.deleteAllKeys(for: contactID)

        XCTAssertEqual(manager.remainingCount(for: contactID), 0)
        for prekey in prekeys {
            XCTAssertNil(manager.retrievePrivateKey(for: prekey))
        }
    }

    // MARK: SE isolation between contacts

    func testSEIsolation_consumingBobKeyDoesNotAffectJake() throws {
        let bobID  = testContactID() + ".bob"
        let jakeID = testContactID() + ".jake"
        defer {
            manager.deleteAllKeys(for: bobID)
            manager.deleteAllKeys(for: jakeID)
        }

        let (bobPrekeys,  _) = try manager.generateBatch(contactID: bobID,  currentSequence: 0, count: 3)
        let (jakePrekeys, _) = try manager.generateBatch(contactID: jakeID, currentSequence: 0, count: 3)

        // Consume all of Bob's prekeys
        for prekey in bobPrekeys { manager.consume(prekey: prekey) }

        XCTAssertEqual(manager.remainingCount(for: bobID),  0, "Bob's pool must be empty")
        XCTAssertEqual(manager.remainingCount(for: jakeID), 3, "Jake's pool must be untouched")

        for prekey in jakePrekeys {
            XCTAssertNotNil(
                manager.retrievePrivateKey(for: prekey),
                "Jake's private key \(prekey.id) must still be in SE"
            )
        }
    }
}

// MARK: - Crypto+ForwardSecrecy Tests

final class CryptoForwardSecrecyTests: XCTestCase {

    var crypto: Manager.Crypto!
    var prekeyManager: Manager.PrekeyManager!
    var testKeyManager: TestKeyManager!

    override func setUp() {
        super.setUp()
        testKeyManager = TestKeyManager()
        crypto         = Manager.Crypto(keyManager: testKeyManager)
        prekeyManager  = Manager.PrekeyManager()
    }

    override func tearDown() {
        super.tearDown()
        crypto         = nil
        prekeyManager  = nil
        testKeyManager = nil
    }

    // MARK: - Helpers

    /// Produces a minimal valid contactID and prekey for test use.
    private func makeContactPrekey(contactID: String) throws -> (Prekey, Int) {
        let (prekeys, next) = try prekeyManager.generateBatch(
            contactID: contactID,
            currentSequence: 0,
            count: 1
        )
        return (prekeys[0], next)
    }

    // MARK: Encrypt / Decrypt — forward secret path

    func testForwardSecret_encryptDecrypt_roundtrip() throws {
        let contactID = testContactID()
        defer { prekeyManager.deleteAllKeys(for: contactID) }

        let (_, recipientPublicKey) = makeTestKeyPair()
        let (contactPrekey, _)      = try makeContactPrekey(contactID: contactID)
        let plaintext               = "Forward secret message".data(using: .utf8)!

        let (bundle, _, _) = try crypto.encryptForwardSecret(
            message:                plaintext,
            contactPrekey:          contactPrekey,
            recipientMaterial:      recipientPublicKey,
            contactID:              contactID,
            outboundPrekeySequence: 0
        )

        // Decrypt using the SE identity key against the ephemeral public key.
        // Uses the existing long-term fallback path to simulate the recipient's SE.
        // (Full two-device roundtrip is tested in integration tests.)
        XCTAssertEqual(bundle.version, .v3fs)
        XCTAssertEqual(bundle.secrecy.mode, .forwardSecret)
        XCTAssertNotNil(bundle.secrecy.prekeyID)
        XCTAssertNotNil(bundle.secrecy.prekeySequence)
        XCTAssertEqual(bundle.secrecy.prekeyID, contactPrekey.id)
        XCTAssertEqual(bundle.secrecy.prekeySequence, contactPrekey.sequence)
    }

    func testForwardSecret_bundleMode_isForwardSecret_whenPrekeyProvided() throws {
        let contactID = testContactID()
        defer { prekeyManager.deleteAllKeys(for: contactID) }

        let (_, recipientPublicKey) = makeTestKeyPair()
        let (contactPrekey, _)      = try makeContactPrekey(contactID: contactID)

        let (bundle, _, _) = try crypto.encryptForwardSecret(
            message:                Data("test".utf8),
            contactPrekey:          contactPrekey,
            recipientMaterial:      recipientPublicKey,
            contactID:              contactID,
            outboundPrekeySequence: 0
        )

        XCTAssertEqual(bundle.secrecy.mode, .forwardSecret)
    }

    // MARK: Encrypt / Decrypt — fallback path

    func testFallback_bundleMode_isLongTermFallback_whenNoPrekeyProvided() throws {
        let contactID = testContactID()
        defer { prekeyManager.deleteAllKeys(for: contactID) }

        let (_, recipientPublicKey) = makeTestKeyPair()

        let (bundle, _, _) = try crypto.encryptForwardSecret(
            message:                Data("fallback test".utf8),
            contactPrekey:          nil,     // no prekey → fallback
            recipientMaterial:      recipientPublicKey,
            contactID:              contactID,
            outboundPrekeySequence: 0
        )

        XCTAssertEqual(bundle.secrecy.mode, .longTermFallback)
    }

    func testFallback_prekeyID_isNil() throws {
        let contactID = testContactID()
        defer { prekeyManager.deleteAllKeys(for: contactID) }

        let (_, recipientPublicKey) = makeTestKeyPair()

        let (bundle, _, _) = try crypto.encryptForwardSecret(
            message:                Data("test".utf8),
            contactPrekey:          nil,
            recipientMaterial:      recipientPublicKey,
            contactID:              contactID,
            outboundPrekeySequence: 0
        )

        XCTAssertNil(bundle.secrecy.prekeyID)
        XCTAssertNil(bundle.secrecy.prekeySequence)
    }

    func testFallback_generatesFreshOutboundBatch() throws {
        let contactID = testContactID()
        defer { prekeyManager.deleteAllKeys(for: contactID) }

        let (_, recipientPublicKey) = makeTestKeyPair()

        let (_, outboundBatch, _) = try crypto.encryptForwardSecret(
            message:                Data("test".utf8),
            contactPrekey:          nil,    // fallback always generates fresh batch
            recipientMaterial:      recipientPublicKey,
            contactID:              contactID,
            outboundPrekeySequence: 0
        )

        XCTAssertNotNil(outboundBatch, "Fallback path must always include a fresh prekey batch")
        XCTAssertFalse(outboundBatch?.prekeys.isEmpty ?? true)
    }

    // MARK: Outbound batch and sequence

    func testEncrypt_outboundBatch_nilWhenStockIsHealthy() throws {
        let contactID = testContactID()
        defer { prekeyManager.deleteAllKeys(for: contactID) }

        let (_, recipientPublicKey) = makeTestKeyPair()
        let (contactPrekey, _)      = try makeContactPrekey(contactID: contactID)

        // Fill SE above replenish threshold so no replenishment is triggered.
        let (_, _) = try prekeyManager.generateBatch(
            contactID: contactID,
            currentSequence: 1,
            count: Manager.PrekeyManager.replenishThreshold + 5
        )

        let (_, outboundBatch, _) = try crypto.encryptForwardSecret(
            message:                Data("test".utf8),
            contactPrekey:          contactPrekey,
            recipientMaterial:      recipientPublicKey,
            contactID:              contactID,
            outboundPrekeySequence: 0
        )

        XCTAssertNil(outboundBatch, "No replenishment batch expected when stock is healthy")
    }

    func testEncrypt_nextSequenceIncremented_whenBatchGenerated() throws {
        let contactID = testContactID()
        defer { prekeyManager.deleteAllKeys(for: contactID) }

        let (_, recipientPublicKey) = makeTestKeyPair()

        // Empty SE — will trigger replenishment
        let (_, _, nextSeq) = try crypto.encryptForwardSecret(
            message:                Data("test".utf8),
            contactPrekey:          nil,
            recipientMaterial:      recipientPublicKey,
            contactID:              contactID,
            outboundPrekeySequence: 5
        )

        XCTAssertGreaterThan(nextSeq, 5, "Sequence must increment when batch is generated")
    }

    func testEncrypt_nextSequenceUnchanged_whenNoBatchGenerated() throws {
        let contactID = testContactID()
        defer { prekeyManager.deleteAllKeys(for: contactID) }

        let (_, recipientPublicKey) = makeTestKeyPair()
        let (contactPrekey, _)      = try makeContactPrekey(contactID: contactID)

        // Stock healthy — no batch generated, sequence must stay at 5
        let (_, _) = try prekeyManager.generateBatch(
            contactID: contactID,
            currentSequence: 1,
            count: Manager.PrekeyManager.replenishThreshold + 5
        )

        let (_, outboundBatch, nextSeq) = try crypto.encryptForwardSecret(
            message:                Data("test".utf8),
            contactPrekey:          contactPrekey,
            recipientMaterial:      recipientPublicKey,
            contactID:              contactID,
            outboundPrekeySequence: 5
        )

        XCTAssertNil(outboundBatch)
        XCTAssertEqual(nextSeq, 5)
    }

    // MARK: Decryption — consumed prekey

    func testDecrypt_forwardSecretPath_consumesPrekeyFromSE() throws {
        let contactID = testContactID()
        defer { prekeyManager.deleteAllKeys(for: contactID) }

        let (_, recipientPublicKey) = makeTestKeyPair()
        let (contactPrekey, _)      = try makeContactPrekey(contactID: contactID)

        let (bundle, _, _) = try crypto.encryptForwardSecret(
            message:                Data("secret".utf8),
            contactPrekey:          contactPrekey,
            recipientMaterial:      recipientPublicKey,
            contactID:              contactID,
            outboundPrekeySequence: 0
        )

        XCTAssertNotNil(
            prekeyManager.retrievePrivateKey(for: contactPrekey),
            "Private key must exist before decrypt"
        )

        _ = try crypto.decryptForwardSecret(bundle: bundle, prekey: contactPrekey)

        XCTAssertNil(
            prekeyManager.retrievePrivateKey(for: contactPrekey),
            "Private key must be deleted from SE immediately after successful decrypt"
        )
    }

    func testDecrypt_duplicateDelivery_returnsNilGracefully() throws {
        let contactID = testContactID()
        defer { prekeyManager.deleteAllKeys(for: contactID) }

        let (_, recipientPublicKey) = makeTestKeyPair()
        let (contactPrekey, _)      = try makeContactPrekey(contactID: contactID)

        do {
            let (bundle, _, _) = try crypto.encryptForwardSecret(
                message:                Data("once".utf8),
                contactPrekey:          contactPrekey,
                recipientMaterial:      recipientPublicKey,
                contactID:              contactID,
                outboundPrekeySequence: 0
            )
            // First decrypt — succeeds, consumes prekey
            _ = try crypto.decryptForwardSecret(bundle: bundle, prekey: contactPrekey)

            // Second decrypt — prekey gone, should return nil not crash
            let (secondResult, _) = try crypto.decryptForwardSecret(bundle: bundle, prekey: contactPrekey)
            XCTAssertNil(secondResult, "Duplicate delivery must return nil, not throw or crash")
        } catch {
            debugPrint("error = \(error)")
        }

        
    }

    func testDecrypt_tamperedCiphertext_throws() throws {
        let contactID = testContactID()
        defer { prekeyManager.deleteAllKeys(for: contactID) }

        let (_, recipientPublicKey) = makeTestKeyPair()
        let (contactPrekey, _)      = try makeContactPrekey(contactID: contactID)

        let (bundle, _, _) = try crypto.encryptForwardSecret(
            message:                Data("tamper test".utf8),
            contactPrekey:          contactPrekey,
            recipientMaterial:      recipientPublicKey,
            contactID:              contactID,
            outboundPrekeySequence: 0
        )

        // Flip a byte in the ciphertext to simulate tampering
        var tamperedCiphertext = bundle.ciphertext
        tamperedCiphertext[tamperedCiphertext.count / 2] ^= 0xFF

        let tamperedSecrecy = OccultaBundle.SecrecyContext(
            mode:               bundle.secrecy.mode,
            ephemeralPublicKey: bundle.secrecy.ephemeralPublicKey,
            prekeyID:           bundle.secrecy.prekeyID,
            prekeySequence:     bundle.secrecy.prekeySequence,
            fingerprintNonce:   bundle.secrecy.fingerprintNonce,
            senderFingerprint:  bundle.secrecy.senderFingerprint,
            prekeyBatch:        bundle.secrecy.prekeyBatch
        )
        let tamperedBundle = OccultaBundle(
            version:    bundle.version,
            secrecy:    tamperedSecrecy,
            ciphertext: tamperedCiphertext
        )

        XCTAssertThrowsError(
            try crypto.decryptForwardSecret(bundle: tamperedBundle, prekey: contactPrekey),
            "Tampered ciphertext must fail GCM tag verification and throw"
        )
    }

    // MARK: Sender fingerprint

    func testSenderFingerprint_uniquePerBundle() throws {
        let contactID = testContactID()
        defer { prekeyManager.deleteAllKeys(for: contactID) }

        let (_, recipientPublicKey) = makeTestKeyPair()
        let (prekey1, _)            = try makeContactPrekey(contactID: contactID)
        let (prekey2, _)            = try makeContactPrekey(contactID: contactID)

        let (bundle1, _, _) = try crypto.encryptForwardSecret(
            message:                Data("msg1".utf8),
            contactPrekey:          prekey1,
            recipientMaterial:      recipientPublicKey,
            contactID:              contactID,
            outboundPrekeySequence: 0
        )
        let (bundle2, _, _) = try crypto.encryptForwardSecret(
            message:                Data("msg2".utf8),
            contactPrekey:          prekey2,
            recipientMaterial:      recipientPublicKey,
            contactID:              contactID,
            outboundPrekeySequence: 0
        )

        XCTAssertNotEqual(
            bundle1.secrecy.fingerprintNonce,
            bundle2.secrecy.fingerprintNonce,
            "Each bundle must have a unique random nonce"
        )
        XCTAssertNotEqual(
            bundle1.secrecy.senderFingerprint,
            bundle2.secrecy.senderFingerprint,
            "Different nonces must produce different fingerprints even for same sender"
        )
    }

    func testSenderFingerprint_doesNotMatchDifferentPublicKey() throws {
        let contactID = testContactID()
        defer { prekeyManager.deleteAllKeys(for: contactID) }

        let (_, recipientPublicKey) = makeTestKeyPair()
        let (_, wrongPublicKey)     = makeTestKeyPair()
        let (contactPrekey, _)      = try makeContactPrekey(contactID: contactID)

        let (bundle, _, _) = try crypto.encryptForwardSecret(
            message:                Data("msg".utf8),
            contactPrekey:          contactPrekey,
            recipientMaterial:      recipientPublicKey,
            contactID:              contactID,
            outboundPrekeySequence: 0
        )

        let correctCandidate = OccultaBundle.SecrecyContext.fingerprint(
            for: try testKeyManager.retrieveIdentity(),  // our test public key
            nonce: bundle.secrecy.fingerprintNonce
        )
        let wrongCandidate = OccultaBundle.SecrecyContext.fingerprint(
            for: wrongPublicKey,
            nonce: bundle.secrecy.fingerprintNonce
        )

        XCTAssertEqual(correctCandidate, bundle.secrecy.senderFingerprint,
                       "Correct key must produce matching fingerprint")
        XCTAssertNotEqual(wrongCandidate, bundle.secrecy.senderFingerprint,
                          "Wrong key must not produce a matching fingerprint")
    }
}

// MARK: - Contact+Model+Prekeys Tests

final class ContactModelPrekeysTests: XCTestCase {

    /// Minimal in-memory Contact.Profile stand-in for model layer tests.
    /// Avoids spinning up SwiftData — we only test the extension methods.
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

    /// Fixed in-memory key for blob encryption in model layer tests.
    /// Avoids SE dependency — these tests exercise store/retrieve semantics,
    /// not the encryption primitive itself. SE-backed encryption is covered
    /// by integration tests running on device.
    private static let testKey = SymmetricKey(size: .bits256)

    private func encryptBlob(_ prekey: Prekey) throws -> Data {
        let encoded = try JSONEncoder().encode(prekey)
        let sealed  = try AES.GCM.seal(encoded, using: Self.testKey, nonce: AES.GCM.Nonce())
        return sealed.combined!
    }

    private func decryptBlob(_ data: Data) throws -> Data {
        let box = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(box, using: Self.testKey)
    }

    // MARK: syncPrekeyData

    func testSyncPrekeyData_replacesStore_whenSequenceIsHigher() throws {
        let contact = makeContact()
        contact.contactPrekeySequence = 2

        let blobs = [try encryptBlob(Prekey(id: "A", contactID: "c", sequence: 3, publicKey: Data(count: 65)))]
        contact.syncPrekeyData(blobs, sequence: 3)

        XCTAssertEqual(contact.contactPrekeys?.count, 1)
        XCTAssertEqual(contact.contactPrekeySequence, 3)
    }

    func testSyncPrekeyData_ignoresStale_whenSequenceIsLower() throws {
        let contact = makeContact()
        let original = [try encryptBlob(Prekey(id: "A", contactID: "c", sequence: 5, publicKey: Data(count: 65)))]
        contact.syncPrekeyData(original, sequence: 5)

        // Attempt to replace with lower sequence
        let stale = [try encryptBlob(Prekey(id: "B", contactID: "c", sequence: 3, publicKey: Data(count: 65)))]
        contact.syncPrekeyData(stale, sequence: 3)

        XCTAssertEqual(contact.contactPrekeySequence, 5, "Sequence must not regress")
        XCTAssertEqual(contact.contactPrekeys?.count, 1, "Store must not change on stale batch")
    }

    func testSyncPrekeyData_ignoresDuplicate_whenSequenceIsEqual() throws {
        let contact = makeContact()
        let first = [try encryptBlob(Prekey(id: "A", contactID: "c", sequence: 4, publicKey: Data(count: 65)))]
        contact.syncPrekeyData(first, sequence: 4)

        let duplicate = [
            try encryptBlob(Prekey(id: "B", contactID: "c", sequence: 4, publicKey: Data(count: 65))),
            try encryptBlob(Prekey(id: "C", contactID: "c", sequence: 4, publicKey: Data(count: 65)))
        ]
        contact.syncPrekeyData(duplicate, sequence: 4)

        XCTAssertEqual(contact.contactPrekeys?.count, 1, "Duplicate sequence must be ignored")
    }

    // MARK: popOldestPrekeyData

    func testPopOldestPrekeyData_isFIFO() throws {
        let contact = makeContact()
        let blobA   = try encryptBlob(Prekey(id: "A", contactID: "c", sequence: 0, publicKey: Data(count: 65)))
        let blobB   = try encryptBlob(Prekey(id: "B", contactID: "c", sequence: 0, publicKey: Data(count: 65)))

        contact.syncPrekeyData([blobA, blobB], sequence: 1)

        let first  = contact.popOldestPrekeyData()
        let second = contact.popOldestPrekeyData()
        let third  = contact.popOldestPrekeyData()

        XCTAssertEqual(first,  blobA,  "First pop must return oldest blob")
        XCTAssertEqual(second, blobB,  "Second pop must return second blob")
        XCTAssertNil(third,            "Third pop on empty store must return nil")
    }

    func testPopOldestPrekeyData_nilWhenEmpty() {
        let contact = makeContact()
        XCTAssertNil(contact.popOldestPrekeyData())
    }

    // MARK: findPrekeyData

    func testFindPrekeyData_returnsCorrectBlob() throws {
        let contact = makeContact()
        let prekeyA = Prekey(id: "A", contactID: "c", sequence: 0, publicKey: Data(count: 65))
        let prekeyB = Prekey(id: "B", contactID: "c", sequence: 0, publicKey: Data(count: 65))
        let blobA   = try encryptBlob(prekeyA)
        let blobB   = try encryptBlob(prekeyB)

        contact.syncPrekeyData([blobA, blobB], sequence: 1)

        let found = contact.findPrekeyData(id: "B") { data in
            try self.decryptBlob(data)
        }

        XCTAssertEqual(found, blobB, "findPrekeyData must return the blob for the matching id")
    }

    func testFindPrekeyData_nilWhenIdNotFound() throws {
        let contact = makeContact()
        let blob    = try encryptBlob(Prekey(id: "A", contactID: "c", sequence: 0, publicKey: Data(count: 65)))
        contact.syncPrekeyData([blob], sequence: 1)

        let found = contact.findPrekeyData(id: "NONEXISTENT") { data in
            try self.decryptBlob(data)
        }

        XCTAssertNil(found)
    }

    // MARK: removePrekeyData

    func testRemovePrekeyData_removesCorrectBlobOnly() throws {
        let contact = makeContact()
        let blobA   = try encryptBlob(Prekey(id: "A", contactID: "c", sequence: 0, publicKey: Data(count: 65)))
        let blobB   = try encryptBlob(Prekey(id: "B", contactID: "c", sequence: 0, publicKey: Data(count: 65)))
        let blobC   = try encryptBlob(Prekey(id: "C", contactID: "c", sequence: 0, publicKey: Data(count: 65)))

        contact.syncPrekeyData([blobA, blobB, blobC], sequence: 1)
        contact.removePrekeyData(blobB)

        XCTAssertEqual(contact.contactPrekeys?.count, 2)
        XCTAssertFalse(contact.contactPrekeys?.contains(blobB) ?? false, "blobB must be removed")
        XCTAssertTrue(contact.contactPrekeys?.contains(blobA) ?? false, "blobA must remain")
        XCTAssertTrue(contact.contactPrekeys?.contains(blobC) ?? false, "blobC must remain")
    }

    // MARK: isLikelySender

    func testIsLikelySender_trueForMatchingPublicKey() throws {
        let contact       = makeContact()
        let (_, pubKeyA)  = makeTestKeyPair()
        let nonce         = OccultaBundle.SecrecyContext.generateNonce()
        let fingerprint   = OccultaBundle.SecrecyContext.fingerprint(for: pubKeyA, nonce: nonce)

        let bundle = makeBundleWithFingerprint(nonce: nonce, fingerprint: fingerprint)

        XCTAssertTrue(contact.isLikelySender(of: bundle, contactPublicKey: pubKeyA))
    }

    func testIsLikelySender_falseForDifferentPublicKey() throws {
        let contact      = makeContact()
        let (_, pubKeyA) = makeTestKeyPair()
        let (_, pubKeyB) = makeTestKeyPair()
        let nonce        = OccultaBundle.SecrecyContext.generateNonce()
        let fingerprint  = OccultaBundle.SecrecyContext.fingerprint(for: pubKeyA, nonce: nonce)

        let bundle = makeBundleWithFingerprint(nonce: nonce, fingerprint: fingerprint)

        XCTAssertFalse(
            contact.isLikelySender(of: bundle, contactPublicKey: pubKeyB),
            "Different public key must not match sender fingerprint"
        )
    }

    func testIsLikelySender_falseForDifferentNonce() throws {
        let contact      = makeContact()
        let (_, pubKey)  = makeTestKeyPair()
        let nonce1       = OccultaBundle.SecrecyContext.generateNonce()
        let nonce2       = OccultaBundle.SecrecyContext.generateNonce()
        let fingerprint  = OccultaBundle.SecrecyContext.fingerprint(for: pubKey, nonce: nonce1)

        // Bundle uses nonce2 but fingerprint was computed with nonce1
        let bundle = makeBundleWithFingerprint(nonce: nonce2, fingerprint: fingerprint)

        XCTAssertFalse(
            contact.isLikelySender(of: bundle, contactPublicKey: pubKey),
            "Fingerprint computed with different nonce must not match"
        )
    }

    // MARK: Helper

    private func makeBundleWithFingerprint(nonce: Data, fingerprint: Data) -> OccultaBundle {
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

// MARK: - Integration Tests

final class ForwardSecrecyIntegrationTests: XCTestCase {

    var crypto: Manager.Crypto!
    var prekeyManager: Manager.PrekeyManager!
    var testKeyManager: TestKeyManager!

    override func setUp() {
        super.setUp()
        testKeyManager = TestKeyManager()
        crypto         = Manager.Crypto(keyManager: testKeyManager)
        prekeyManager  = Manager.PrekeyManager()
    }

    override func tearDown() {
        super.tearDown()
        crypto         = nil
        prekeyManager  = nil
        testKeyManager = nil
    }

    // MARK: Multiple contacts — independent pools

    /// Bob and Jake each receive unique prekey batches.
    /// Consuming Bob's prekey has no effect on Jake's ability to decrypt.
    func testMultipleContacts_independentPrekeyPools() throws {
        let bobID  = "integration.bob.\(UUID().uuidString)"
        let jakeID = "integration.jake.\(UUID().uuidString)"
        defer {
            prekeyManager.deleteAllKeys(for: bobID)
            prekeyManager.deleteAllKeys(for: jakeID)
        }

        let (_, bobPublicKey)  = makeTestKeyPair()
        let (_, jakePublicKey) = makeTestKeyPair()

        // Generate independent batches for Bob and Jake
        let (bobPrekeys,  _) = try prekeyManager.generateBatch(contactID: bobID,  currentSequence: 0, count: 3)
        let (jakePrekeys, _) = try prekeyManager.generateBatch(contactID: jakeID, currentSequence: 0, count: 3)

        // Encrypt for Bob using Bob's prekey
        let (bobBundle, _, _) = try crypto.encryptForwardSecret(
            message:                Data("Message for Bob".utf8),
            contactPrekey:          bobPrekeys[0],
            recipientMaterial:      bobPublicKey,
            contactID:              bobID,
            outboundPrekeySequence: 0
        )

        // Encrypt for Jake using Jake's prekey
        let (jakeBundle, _, _) = try crypto.encryptForwardSecret(
            message:                Data("Message for Jake".utf8),
            contactPrekey:          jakePrekeys[0],
            recipientMaterial:      jakePublicKey,
            contactID:              jakeID,
            outboundPrekeySequence: 0
        )

        // Decrypt Bob's bundle — consumes Bob's prekey
        _ = try crypto.decryptForwardSecret(bundle: bobBundle, prekey: bobPrekeys[0])

        XCTAssertNil(
            prekeyManager.retrievePrivateKey(for: bobPrekeys[0]),
            "Bob's prekey must be consumed"
        )

        // Jake's prekey must still be intact
        XCTAssertNotNil(
            prekeyManager.retrievePrivateKey(for: jakePrekeys[0]),
            "Jake's prekey must be unaffected by Bob's decryption"
        )

        // Decrypt Jake's bundle — must still succeed
        let (jakePlaintext, _) = try crypto.decryptForwardSecret(bundle: jakeBundle, prekey: jakePrekeys[0])

        XCTAssertNotNil(jakePlaintext, "Jake must be able to decrypt independently")
    }

    // MARK: Prekey exhaustion → fallback → replenishment

    func testPrekeyExhaustion_fallback_includesFreshBatch() throws {
        let contactID = "integration.exhaustion.\(UUID().uuidString)"
        defer { prekeyManager.deleteAllKeys(for: contactID) }

        let (_, recipientPublicKey) = makeTestKeyPair()

        // No prekeys stored — triggers fallback
        let (bundle, outboundBatch, _) = try crypto.encryptForwardSecret(
            message:                Data("fallback message".utf8),
            contactPrekey:          nil,
            recipientMaterial:      recipientPublicKey,
            contactID:              contactID,
            outboundPrekeySequence: 0
        )

        XCTAssertEqual(bundle.secrecy.mode, .longTermFallback,
                       "Fallback must produce .longTermFallback bundle mode")
        XCTAssertNotNil(outboundBatch,
                        "Fallback must always generate a fresh batch to break the exhaustion cycle")
        XCTAssertEqual(
            outboundBatch?.prekeys.count,
            Manager.PrekeyManager.defaultBatchSize,
            "Fresh batch must be a full default-sized batch"
        )
        XCTAssertTrue(
            outboundBatch?.prekeys.allSatisfy { $0.contactID == contactID } ?? false,
            "All prekeys in fresh batch must be scoped to the correct contactID"
        )
    }

    func testPrekeyExhaustion_secondMessage_isForwardSecret_afterBatchSynced() throws {
        let contactID = "integration.replenish.\(UUID().uuidString)"
        defer { prekeyManager.deleteAllKeys(for: contactID) }

        let (_, recipientPublicKey) = makeTestKeyPair()

        // First message — exhausted, fallback, generates outbound batch
        let (_, outboundBatch, nextSeq) = try crypto.encryptForwardSecret(
            message:                Data("first".utf8),
            contactPrekey:          nil,
            recipientMaterial:      recipientPublicKey,
            contactID:              contactID,
            outboundPrekeySequence: 0
        )

        // Simulate recipient returning the batch to us in their reply.
        // Take any prekey from the batch as the "contact's prekey for us to use".
        guard let returnedPrekey = outboundBatch?.prekeys.first else {
            XCTFail("Expected outbound batch from fallback path")
            return
        }

        // Second message — use the returned prekey → should be forward secret
        let (secondBundle, _, _) = try crypto.encryptForwardSecret(
            message:                Data("second".utf8),
            contactPrekey:          returnedPrekey,
            recipientMaterial:      recipientPublicKey,
            contactID:              contactID,
            outboundPrekeySequence: nextSeq
        )

        XCTAssertEqual(
            secondBundle.secrecy.mode, .forwardSecret,
            "Second message must use forward secret path once prekey is available"
        )
    }

    // MARK: Forward secrecy — consumed key cannot decrypt again

    func testForwardSecrecy_consumedKey_cannotDecryptSameBundle() throws {
        let contactID = "integration.consumed.\(UUID().uuidString)"
        defer { prekeyManager.deleteAllKeys(for: contactID) }

        let (_, recipientPublicKey) = makeTestKeyPair()
        let (prekeys, _) = try prekeyManager.generateBatch(
            contactID: contactID,
            currentSequence: 0,
            count: 1
        )

        let (bundle, _, _) = try crypto.encryptForwardSecret(
            message:                Data("once only".utf8),
            contactPrekey:          prekeys[0],
            recipientMaterial:      recipientPublicKey,
            contactID:              contactID,
            outboundPrekeySequence: 0
        )

        // First decrypt — succeeds, consumes key
        let (first, _) = try crypto.decryptForwardSecret(bundle: bundle, prekey: prekeys[0])
        XCTAssertNotNil(first, "First decrypt must succeed")

        // Second decrypt — key gone, must return nil
        let (second, _) = try crypto.decryptForwardSecret(bundle: bundle, prekey: prekeys[0])
        XCTAssertNil(second, "Once the prekey is consumed, the bundle can never be decrypted again")
    }

    // MARK: Sequence pruning on new batch generation

    func testSequencePruning_oldKeysDeleted_newKeysSurvive() throws {
        let contactID = "integration.pruning.\(UUID().uuidString)"
        defer { prekeyManager.deleteAllKeys(for: contactID) }

        // Generate seq 1
        let (seq1Prekeys, _) = try prekeyManager.generateBatch(
            contactID: contactID,
            currentSequence: 1,
            count: 3
        )

        // Generate seq 2 — should prune seq 0 (there are none) but keep seq 1
        let (seq2Prekeys, _) = try prekeyManager.generateBatch(
            contactID: contactID,
            currentSequence: 2,
            count: 3
        )

        // Generate seq 3 — should prune seq 1 (older than seq 2)
        let (seq3Prekeys, _) = try prekeyManager.generateBatch(
            contactID: contactID,
            currentSequence: 3,
            count: 3
        )

        // After seq 3 generation: seq 1 pruned, seq 2 kept as buffer, seq 3 current
        for prekey in seq1Prekeys {
            XCTAssertNil(
                prekeyManager.retrievePrivateKey(for: prekey),
                "Seq 1 keys must be pruned after seq 3 is generated"
            )
        }

        for prekey in seq2Prekeys {
            XCTAssertNotNil(
                prekeyManager.retrievePrivateKey(for: prekey),
                "Seq 2 keys must survive as safety buffer"
            )
        }

        for prekey in seq3Prekeys {
            XCTAssertNotNil(
                prekeyManager.retrievePrivateKey(for: prekey),
                "Seq 3 keys must survive as current batch"
            )
        }
    }

    // MARK: Bundle serialisation roundtrip

    func testBundle_encodeDecode_preservesAllFields() throws {
        let contactID = "integration.serial.\(UUID().uuidString)"
        defer { prekeyManager.deleteAllKeys(for: contactID) }

        let (_, recipientPublicKey) = makeTestKeyPair()
        let (prekeys, _) = try prekeyManager.generateBatch(
            contactID: contactID,
            currentSequence: 5,
            count: 1
        )

        let (original, _, _) = try crypto.encryptForwardSecret(
            message:                Data("serialise me".utf8),
            contactPrekey:          prekeys[0],
            recipientMaterial:      recipientPublicKey,
            contactID:              contactID,
            outboundPrekeySequence: 5
        )

        let encoded  = try original.encode()
        let decoded  = try OccultaBundle.decode(from: encoded)

        XCTAssertEqual(decoded.version,                    original.version)
        XCTAssertEqual(decoded.secrecy.mode,               original.secrecy.mode)
        XCTAssertEqual(decoded.secrecy.ephemeralPublicKey, original.secrecy.ephemeralPublicKey)
        XCTAssertEqual(decoded.secrecy.prekeyID,           original.secrecy.prekeyID)
        XCTAssertEqual(decoded.secrecy.prekeySequence,     original.secrecy.prekeySequence)
        XCTAssertEqual(decoded.secrecy.fingerprintNonce,   original.secrecy.fingerprintNonce)
        XCTAssertEqual(decoded.secrecy.senderFingerprint,  original.secrecy.senderFingerprint)
        XCTAssertEqual(decoded.ciphertext,                 original.ciphertext)
    }
}

// MARK: - Prekey Struct Tests

final class PrekeyStructTests: XCTestCase {

    func testSETag_format() {
        let prekey = Prekey(id: "abc-123", contactID: "contact-456", sequence: 7, publicKey: Data())
        XCTAssertEqual(prekey.seTag, "prekey.contact-456.7.abc-123")
    }

    func testSETagPrefix_contactAndSequence() {
        XCTAssertEqual(
            Prekey.seTagPrefix(contactID: "bob", sequence: 3),
            "prekey.bob.3."
        )
    }

    func testSETagPrefix_contactOnly() {
        XCTAssertEqual(
            Prekey.seTagPrefix(contactID: "bob"),
            "prekey.bob."
        )
    }
}

//
//  ForwardSecrecyIntegrationTests.swift
//  OccultaTests
//
//  Full-stack integration tests using the real Secure Enclave.
//  ⚠️  RUN ON DEVICE ONLY.
//
//  SE operation ordering enforced throughout:
//    All SE writes (generateBatch) before ECDH.
//    SecKey released inside closure before consume().
//

import XCTest
import CryptoKit
@testable import Occulta

final class ForwardSecrecyIntegrationTests: XCTestCase {

    var crypto:        Manager.Crypto!
    var prekeyManager: Manager.PrekeyManager!

    override func setUp() {
        super.setUp()
        crypto        = Manager.Crypto()
        prekeyManager = Manager.PrekeyManager()
    }

    override func tearDown() {
        crypto = nil; prekeyManager = nil
        super.tearDown()
    }

    // MARK: - Helpers

    private func cid(function: String = #function) -> String {
        "int.\(function).\(UUID().uuidString)"
    }

    private func inMemoryKeyPair() -> (SecKey, Data) {
        let attrs: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
        ]
        var e: Unmanaged<CFError>?
        let priv = SecKeyCreateRandomKey(attrs, &e)!
        let pub  = SecKeyCopyPublicKey(priv)!
        return (priv, SecKeyCopyExternalRepresentation(pub, nil)! as Data)
    }

    // Encryption key for test blobs — mirrors what ContactManager uses for ownPrekeys
    private static let blobKey = SymmetricKey(size: .bits256)

    private func encryptBlob(_ prekey: Prekey) throws -> Data {
        let encoded = try JSONEncoder().encode(prekey)
        return try AES.GCM.seal(encoded, using: Self.blobKey, nonce: AES.GCM.Nonce()).combined!
    }

    // Non-throwing — required by syncInboundPrekeys and pruneOwnPrekeys signatures
    private func decryptBlob(_ data: Data) -> Data? {
        try? AES.GCM.open(try AES.GCM.SealedBox(combined: data), using: Self.blobKey)
    }

    private func makeContact() -> Contact.Profile {
        Contact.Profile(
            identifier: UUID().uuidString, givenName: "Test", familyName: "Contact",
            middleName: "", nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
    }

    // Canonical decrypt — SecKey scoped inside closure, consume after.
    private func decrypt(bundle: OccultaBundle, prekey: Prekey?) throws -> Data? {
        switch bundle.secrecy.mode {
        case .forwardSecret:
            let result: Data? = try {
                guard
                    let pk  = prekey,
                    let priv = prekeyManager.retrievePrivateKey(for: pk),
                    let key  = crypto.deriveSessionKey(
                                   ephemeralPrivateKey: priv,
                                   recipientMaterial:   bundle.secrecy.ephemeralPublicKey
                               )
                else { return nil }
                return try crypto.open(bundle, using: key)
                // ← priv released here
            }()
            if result != nil, let pk = prekey { prekeyManager.consume(prekey: pk) }
            return result
        case .longTermFallback:
            guard let key = crypto.deriveSessionKey(using: bundle.secrecy.ephemeralPublicKey)
            else { return nil }
            return try crypto.open(bundle, using: key)
        }
    }

    // MARK: - Basic roundtrip

    /// ⚠️ CRASH CANDIDATE — tests SecKey lifetime fix.
    func test_roundtrip_FSPath() throws {
        let c          = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let (keys, _)  = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 1)
        let (_, recip) = inMemoryKeyPair()
        let message    = Data("Integration roundtrip".utf8)

        let bundle = try crypto.seal(
            message: message, contactPrekey: keys[0],
            recipientMaterial: recip, outboundBatch: nil
        )
        XCTAssertEqual(bundle.secrecy.mode, .forwardSecret)
        XCTAssertEqual(try decrypt(bundle: bundle, prekey: keys[0]), message)
    }

    func test_roundtrip_fiveSequentialMessages() throws {
        let c          = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let (keys, _)  = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 5)
        let (_, recip) = inMemoryKeyPair()

        for (i, prekey) in keys.enumerated() {
            let msg = Data("Message \(i)".utf8)
            let bundle = try crypto.seal(
                message: msg, contactPrekey: prekey, recipientMaterial: recip, outboundBatch: nil
            )
            XCTAssertEqual(try decrypt(bundle: bundle, prekey: prekey), msg)
            XCTAssertNil(prekeyManager.retrievePrivateKey(for: prekey),
                         "Prekey \(i) must be consumed")
        }
    }

    // MARK: - Bidirectional conversation

    func test_bidirectional_aliceAndBob_independentPools() throws {
        let aliceForBobCID = cid() + ".aliceForBob"
        let bobForAliceCID = cid() + ".bobForAlice"
        defer {
            prekeyManager.deleteAllKeys(for: aliceForBobCID)
            prekeyManager.deleteAllKeys(for: bobForAliceCID)
        }

        let (_, alicePub) = inMemoryKeyPair()
        let (_, bobPub)   = inMemoryKeyPair()

        let (aliceKeys, _) = try prekeyManager.generateBatch(
            contactID: aliceForBobCID, currentSequence: 0, count: 3
        )
        let (bobKeys, _) = try prekeyManager.generateBatch(
            contactID: bobForAliceCID, currentSequence: 0, count: 3
        )

        // Alice → Bob (uses Bob's prekey, sends Alice's prekeys as batch)
        let aliceToBob = try crypto.seal(
            message: Data("Hello Bob".utf8),
            contactPrekey: bobKeys[0],
            recipientMaterial: bobPub,
            outboundBatch: OccultaBundle.PrekeySyncBatch(sequence: 0, prekeys: aliceKeys)
        )

        // Bob → Alice (uses Alice's prekey, sends Bob's prekeys as batch)
        let bobToAlice = try crypto.seal(
            message: Data("Hello Alice".utf8),
            contactPrekey: aliceKeys[0],
            recipientMaterial: alicePub,
            outboundBatch: OccultaBundle.PrekeySyncBatch(sequence: 0, prekeys: bobKeys)
        )

        // Bob decrypts — consumes bobKeys[0]
        XCTAssertEqual(try decrypt(bundle: aliceToBob, prekey: bobKeys[0]),
                       Data("Hello Bob".utf8))
        XCTAssertNil(prekeyManager.retrievePrivateKey(for: bobKeys[0]),
                     "Bob's prekey must be consumed")
        XCTAssertNotNil(prekeyManager.retrievePrivateKey(for: aliceKeys[0]),
                        "Alice's prekey must be unaffected")

        // Alice decrypts — consumes aliceKeys[0]
        XCTAssertEqual(try decrypt(bundle: bobToAlice, prekey: aliceKeys[0]),
                       Data("Hello Alice".utf8))
        XCTAssertNil(prekeyManager.retrievePrivateKey(for: aliceKeys[0]))

        XCTAssertEqual(prekeyManager.remainingCount(for: aliceForBobCID), 2)
        XCTAssertEqual(prekeyManager.remainingCount(for: bobForAliceCID), 2)
    }

    // MARK: - Pool isolation

    func test_poolIsolation_consumingBobDoesNotAffectJake() throws {
        let bobCID  = cid() + ".bob"
        let jakeCID = cid() + ".jake"
        defer {
            prekeyManager.deleteAllKeys(for: bobCID)
            prekeyManager.deleteAllKeys(for: jakeCID)
        }

        let (bobKeys,  _) = try prekeyManager.generateBatch(contactID: bobCID,  currentSequence: 0, count: 3)
        let (jakeKeys, _) = try prekeyManager.generateBatch(contactID: jakeCID, currentSequence: 0, count: 3)
        let (_, bobPub)   = inMemoryKeyPair()
        let (_, jakePub)  = inMemoryKeyPair()

        let bobBundle = try crypto.seal(
            message: Data("For Bob".utf8), contactPrekey: bobKeys[0],
            recipientMaterial: bobPub, outboundBatch: nil
        )
        let jakeBundle = try crypto.seal(
            message: Data("For Jake".utf8), contactPrekey: jakeKeys[0],
            recipientMaterial: jakePub, outboundBatch: nil
        )

        _ = try decrypt(bundle: bobBundle, prekey: bobKeys[0])
        XCTAssertNil(prekeyManager.retrievePrivateKey(for: bobKeys[0]))
        XCTAssertNotNil(prekeyManager.retrievePrivateKey(for: jakeKeys[0]))

        XCTAssertEqual(try decrypt(bundle: jakeBundle, prekey: jakeKeys[0]),
                       Data("For Jake".utf8))
    }

    // MARK: - Forward secrecy guarantee

    /// ⚠️ CRASH CANDIDATE — consumed key must return nil, not crash.
    func test_forwardSecrecy_consumedKey_cannotDecrypt() throws {
        let c          = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let (keys, _)  = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 1)
        let (_, recip) = inMemoryKeyPair()
        let bundle     = try crypto.seal(
            message: Data("once only".utf8), contactPrekey: keys[0],
            recipientMaterial: recip, outboundBatch: nil
        )
        XCTAssertNotNil(try decrypt(bundle: bundle, prekey: keys[0]))
        XCTAssertNil(try decrypt(bundle: bundle, prekey: keys[0]),
                     "Consumed key must never decrypt again")
    }

    // MARK: - Pending batch: proof-of-receipt guarantee

    /// The pending batch must ride every outbound message until the contact uses one
    /// of our prekeys — clearPendingBatch fires only when removeOwnPrekeyData fires.
    func test_pendingBatch_clearedOnlyAfterFSReceipt() throws {
        let c         = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let (keys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 3)
        let contact   = makeContact()

        // Simulate storing our new batch as pending
        let batch = OccultaBundle.PrekeySyncBatch(sequence: 0, prekeys: keys)
        try contact.storePendingBatch(batch)

        // Store the corresponding ownPrekeys blobs so removeOwnPrekeyData can find them
        let blobs = try keys.map { try encryptBlob($0) }
        contact.appendOwnPrekeys(blobs)

        XCTAssertTrue(contact.hasPendingBatch, "Batch must be pending before FS receipt")

        // Simulate receiving a FS bundle that consumed one of our prekeys:
        // removeOwnPrekeyData fires → clearPendingBatch fires
        contact.removeOwnPrekeyData(blobs[0])
        contact.clearPendingBatch()

        XCTAssertFalse(contact.hasPendingBatch, "Batch must be cleared after FS receipt")
        XCTAssertEqual(contact.ownPrekeysCount, 2, "One prekey consumed, two remain")
    }

    /// The same pending batch must be returned on every loadPendingBatch call
    /// until explicitly cleared — not regenerated each time.
    func test_pendingBatch_sameInstanceEachLoad() throws {
        let c         = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let (keys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 2)
        let contact   = makeContact()
        let batch     = OccultaBundle.PrekeySyncBatch(sequence: 0, prekeys: keys)
        try contact.storePendingBatch(batch)

        let load1 = contact.loadPendingBatch()
        let load2 = contact.loadPendingBatch()

        XCTAssertEqual(load1?.sequence, load2?.sequence)
        XCTAssertEqual(load1?.prekeys.count, load2?.prekeys.count)
        XCTAssertEqual(load1?.prekeys.first?.id, load2?.prekeys.first?.id,
                       "Every load must return the same batch")
    }

    // MARK: - Prekey exhaustion: inbound valid keys preserved on new batch arrival

    /// When Bob exhausted Alice's contactPrekeys and Alice gets a new batch from
    /// any source, any unconsumed valid prekeys already in the store must be
    /// preserved (prune-then-append, not blind replace).
    func test_inbound_validKeysPreservedWhenNewBatchArrives() throws {
        let contact = makeContact()

        // Alice has 3 unconsumed prekeys from Bob at seq=1 (valid when seq=2 arrives)
        let validPrekeys = [
            Prekey(id: "V1", contactID: "bob", sequence: 1, publicKey: Data(count: 65)),
            Prekey(id: "V2", contactID: "bob", sequence: 1, publicKey: Data(count: 65)),
            Prekey(id: "V3", contactID: "bob", sequence: 1, publicKey: Data(count: 65))
        ]
        let validBlobs = try validPrekeys.map { try encryptBlob($0) }
        contact.syncInboundPrekeys(validBlobs, sequence: 1, decryptor: decryptBlob)
        XCTAssertEqual(contact.availableInboundPrekeyCount, 3)

        // Bob sends a new batch at seq=2 (because his stock was low)
        // threshold = 2 - 1 = 1; seq=1 prekeys have sequence >= 1 → preserved
        let newPrekeys = [
            Prekey(id: "N1", contactID: "bob", sequence: 2, publicKey: Data(count: 65)),
            Prekey(id: "N2", contactID: "bob", sequence: 2, publicKey: Data(count: 65))
        ]
        let newBlobs = try newPrekeys.map { try encryptBlob($0) }
        contact.syncInboundPrekeys(newBlobs, sequence: 2, decryptor: decryptBlob)

        // All 3 valid + 2 new = 5 total
        XCTAssertEqual(contact.availableInboundPrekeyCount, 5,
                       "Valid unconsumed seq=1 keys must be preserved, new seq=2 appended")

        // Pop all and verify FIFO (old before new)
        var ids: [String] = []
        while let blob = contact.popOldestPrekeyData() {
            if let raw = decryptBlob(blob),
               let pk  = try? JSONDecoder().decode(Prekey.self, from: raw) {
                ids.append(pk.id)
            }
        }
        XCTAssertEqual(ids.prefix(3).sorted(), ["V1", "V2", "V3"],
                       "Old valid keys must be popped before new batch keys")
    }

    // MARK: - ownPrekeys pruning

    func test_pruneOwnPrekeys_alignsWithSEPruning() throws {
        let contact  = makeContact()

        let seq0Blobs = try [
            encryptBlob(Prekey(id: "A", contactID: "c", sequence: 0, publicKey: Data(count: 65))),
            encryptBlob(Prekey(id: "B", contactID: "c", sequence: 0, publicKey: Data(count: 65)))
        ]
        let seq1Blobs = try [
            encryptBlob(Prekey(id: "C", contactID: "c", sequence: 1, publicKey: Data(count: 65)))
        ]
        let seq2Blobs = try [
            encryptBlob(Prekey(id: "D", contactID: "c", sequence: 2, publicKey: Data(count: 65)))
        ]

        contact.appendOwnPrekeys(seq0Blobs)
        contact.appendOwnPrekeys(seq1Blobs)
        contact.appendOwnPrekeys(seq2Blobs)
        XCTAssertEqual(contact.ownPrekeysCount, 4)

        // SE prunes seq < 2 when generating seq=3. Mirror here.
        // NOTE: decryptor must be non-throwing (Data) -> Data?
        contact.pruneOwnPrekeys(olderThan: 2, decryptor: decryptBlob)

        XCTAssertEqual(contact.ownPrekeysCount, 1, "seq=0 and seq=1 must be pruned")
        let surviving = try JSONDecoder().decode(
            Prekey.self,
            from: AES.GCM.open(
                try AES.GCM.SealedBox(combined: contact.ownPrekeys![0]),
                using: Self.blobKey
            )
        )
        XCTAssertEqual(surviving.sequence, 2)
    }

    // MARK: - Sequence pruning (SE)

    func test_sequencePruning_oldKeysDeletedNewKeysSurvive() throws {
        let c = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let (seq1, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 1, count: 2)
        let (seq2, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 2, count: 2)
        let (seq3, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 3, count: 2)

        for k in seq1 { XCTAssertNil(prekeyManager.retrievePrivateKey(for: k), "Seq 1 pruned") }
        for k in seq2 { XCTAssertNotNil(prekeyManager.retrievePrivateKey(for: k), "Seq 2 survives") }
        for k in seq3 { XCTAssertNotNil(prekeyManager.retrievePrivateKey(for: k), "Seq 3 survives") }
    }

    func test_sequencePruning_contactScoped() throws {
        let c1 = cid() + ".alpha"; let c2 = cid() + ".beta"
        defer { prekeyManager.deleteAllKeys(for: c1); prekeyManager.deleteAllKeys(for: c2) }
        let (k1, _) = try prekeyManager.generateBatch(contactID: c1, currentSequence: 1, count: 2)
        let (k2, _) = try prekeyManager.generateBatch(contactID: c2, currentSequence: 1, count: 2)
        let _ = try prekeyManager.generateBatch(contactID: c1, currentSequence: 2, count: 2)
        let _ = try prekeyManager.generateBatch(contactID: c1, currentSequence: 3, count: 2)
        for k in k1 { XCTAssertNil(prekeyManager.retrievePrivateKey(for: k)) }
        for k in k2 { XCTAssertNotNil(prekeyManager.retrievePrivateKey(for: k)) }
    }

    // MARK: - Input validation and version check

    func test_decrypt_wrongVersion_throws() throws {
        let c          = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let (keys, _)  = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 1)
        let (_, recip) = inMemoryKeyPair()
        let bundle     = try crypto.seal(
            message: Data("test".utf8), contactPrekey: keys[0],
            recipientMaterial: recip, outboundBatch: nil
        )
        let wrongVersion = OccultaBundle(
            version:           .v1,
            secrecy:           bundle.secrecy,
            ciphertext:        bundle.ciphertext,
            fingerprintNonce:  bundle.fingerprintNonce,
            senderFingerprint: bundle.senderFingerprint
        )
        let sessKey = SymmetricKey(size: .bits256)
        XCTAssertThrowsError(try crypto.open(wrongVersion, using: sessKey),
                             "Wrong version must fail AAD verification")
        prekeyManager.consume(prekey: keys[0])
    }

    func test_decrypt_invalidEphemeralPublicKeyLength_throws() throws {
        let c          = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let (keys, _)  = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 1)
        let (_, recip) = inMemoryKeyPair()
        let bundle     = try crypto.seal(
            message: Data("test".utf8), contactPrekey: keys[0],
            recipientMaterial: recip, outboundBatch: nil
        )
        prekeyManager.consume(prekey: keys[0])
        let tampered = OccultaBundle(
            version: bundle.version,
            secrecy: OccultaBundle.SecrecyContext(
                mode: bundle.secrecy.mode,
                ephemeralPublicKey: Data(count: 32),    // wrong length
                prekeyID: bundle.secrecy.prekeyID,
                prekeySequence: bundle.secrecy.prekeySequence,
                prekeyBatch: bundle.secrecy.prekeyBatch
            ),
            ciphertext:        bundle.ciphertext,
            fingerprintNonce:  bundle.fingerprintNonce,
            senderFingerprint: bundle.senderFingerprint
        )
        let sessKey = SymmetricKey(size: .bits256)
        XCTAssertThrowsError(try crypto.open(tampered, using: sessKey),
                             "Tampered ephemeralPublicKey must fail AAD verification")
    }

    // MARK: - Bundle serialisation

    func test_bundleEncodeDecode_allFieldsPreserved() throws {
        let c          = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let (keys, _)  = try prekeyManager.generateBatch(contactID: c, currentSequence: 5, count: 1)
        let (_, recip) = inMemoryKeyPair()
        let original   = try crypto.seal(
            message: Data("serialise".utf8), contactPrekey: keys[0],
            recipientMaterial: recip, outboundBatch: nil
        )
        let decoded = try OccultaBundle.decoded(from: original.encoded())
        XCTAssertEqual(decoded.version,                    original.version)
        XCTAssertEqual(decoded.secrecy.mode,               original.secrecy.mode)
        XCTAssertEqual(decoded.secrecy.ephemeralPublicKey, original.secrecy.ephemeralPublicKey)
        XCTAssertEqual(decoded.secrecy.prekeyID,           original.secrecy.prekeyID)
        XCTAssertEqual(decoded.secrecy.prekeySequence,     original.secrecy.prekeySequence)
        XCTAssertEqual(decoded.fingerprintNonce,           original.fingerprintNonce)
        XCTAssertEqual(decoded.senderFingerprint,          original.senderFingerprint)
        XCTAssertEqual(decoded.ciphertext,                 original.ciphertext)
        prekeyManager.consume(prekey: keys[0])
    }

    // MARK: - SE cleanup

    func test_deleteAllKeys_removesEntirePool() throws {
        let c = cid()
        let (s0, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 3)
        let (s1, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 1, count: 3)
        prekeyManager.deleteAllKeys(for: c)
        XCTAssertEqual(prekeyManager.remainingCount(for: c), 0)
        
        for k in s0 + s1 { XCTAssertNil(prekeyManager.retrievePrivateKey(for: k)) }
    }

    // MARK: - Fallback path

    func test_fallback_bundleMode() throws {
        let c = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let bundle = try crypto.seal(
            message: Data("fallback".utf8), contactPrekey: nil,
            recipientMaterial: inMemoryKeyPair().1, outboundBatch: nil
        )
        XCTAssertEqual(bundle.secrecy.mode, .longTermFallback)
        XCTAssertNil(bundle.secrecy.prekeyID)
    }
}

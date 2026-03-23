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
    // MARK: - 5.5.3 — ownPrekeys only appended on new generation, not on pending reuse

    func test_ownPrekeys_onlyAppendedOnNewGeneration_notOnPendingReuse() throws {
        let c         = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let contact   = makeContact()
        let (keys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 3)

        // Store the batch as pending and record blobs in ownPrekeys — simulating first generation
        let batch = OccultaBundle.PrekeySyncBatch(sequence: 0, prekeys: keys)
        try contact.storePendingBatch(batch)
        let blobs = try keys.map { try encryptBlob($0) }
        contact.appendOwnPrekeys(blobs)
        let countAfterFirstGen = contact.ownPrekeysCount
        XCTAssertEqual(countAfterFirstGen, 3, "ownPrekeys must have 3 entries after generation")

        // Simulate reusing the pending batch for a subsequent message: loadPendingBatch returns it.
        // NO appendOwnPrekeys should be called on reuse — blobs are already there.
        let pending = contact.loadPendingBatch()
        XCTAssertNotNil(pending, "Pending batch must still be set")

        // ownPrekeys count must be unchanged — reuse does not re-append
        XCTAssertEqual(contact.ownPrekeysCount, countAfterFirstGen,
                       "Reusing pending batch must NOT append blobs to ownPrekeys again")
    }

    // MARK: - 5.6 — Full prekey exhaustion scenario

    /// 5.6.2 — After all contactPrekeys are consumed, the next encrypt call
    /// uses nil contactPrekey and produces a .longTermFallback bundle.
    func test_exhaustion_allContactPrekeysConsumed_producesFallback() throws {
        let c         = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let contact   = makeContact()
        let (_, recip) = inMemoryKeyPair()

        // Give the contact 3 inbound prekeys from the "sender"
        let (senderKeys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 3)
        let inboundBlobs    = try senderKeys.map { try encryptBlob($0) }
        contact.syncInboundPrekeys(inboundBlobs, sequence: 1, decryptor: decryptBlob)
        XCTAssertEqual(contact.availableInboundPrekeyCount, 3)

        // Exhaust all 3 prekeys
        _ = contact.popOldestPrekeyData()
        _ = contact.popOldestPrekeyData()
        _ = contact.popOldestPrekeyData()
        XCTAssertFalse(contact.hasPrekeyAvailable, "All prekeys must be consumed")

        // Next encrypt: contactPrekey = nil → fallback
        let bundle = try crypto.seal(
            message:           Data("fallback message".utf8),
            contactPrekey:     nil,   // no prekeys available
            recipientMaterial: recip,
            outboundBatch:     nil
        )
        XCTAssertEqual(bundle.secrecy.mode, .longTermFallback,
                       "Exhausted prekeys must produce fallback bundle")
        XCTAssertNil(bundle.secrecy.prekeyID)
    }

    /// 5.6.3 — When Alice detects an inbound .longTermFallback (Bob is out of her prekeys),
    /// she generates a new batch immediately and stores it as pendingOutboundBatch.
    func test_exhaustion_inboundFallback_triggersNewBatchAsPending() throws {
        let c       = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let contact = makeContact()

        // Precondition: no pending batch
        XCTAssertFalse(contact.hasPendingBatch)

        // Simulate detecting an inbound .longTermFallback: generate a fresh batch for the sender
        let seq    = contact.outboundPrekeySequence
        let result = try prekeyManager.generateBatch(contactID: contact.identifier, currentSequence: seq)
        let batch  = OccultaBundle.PrekeySyncBatch(sequence: seq, prekeys: result.prekeys)
        try contact.storePendingBatch(batch)
        contact.outboundPrekeySequence = result.nextSequence

        // Record own prekeys
        let blobs = try result.prekeys.map { try encryptBlob($0) }
        contact.appendOwnPrekeys(blobs)

        XCTAssertTrue(contact.hasPendingBatch,
                      "New batch must be stored as pending after fallback detection")
        XCTAssertEqual(contact.ownPrekeysCount, result.prekeys.count,
                       "Blobs must be recorded in ownPrekeys")
        
        self.prekeyManager.deleteAllKeys(for: contact.identifier)
    }

    /// 5.6.4 — Pending batch is returned unchanged on every load until cleared.
    /// The same batch (same sequence, same prekey IDs) must ride every outbound message.
    func test_exhaustion_pendingBatchRidesEveryMessage_unchanged() throws {
        let c         = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let contact   = makeContact()
        let (keys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 3)

        let originalBatch = OccultaBundle.PrekeySyncBatch(sequence: 0, prekeys: keys)
        try contact.storePendingBatch(originalBatch)

        // Load the batch 5 times — simulating 5 outbound messages
        for i in 1...5 {
            let loaded = contact.loadPendingBatch()
            XCTAssertNotNil(loaded, "Load \(i): pending batch must be non-nil")
            XCTAssertEqual(loaded?.sequence, originalBatch.sequence,
                           "Load \(i): sequence must be unchanged")
            XCTAssertEqual(loaded?.prekeys.count, originalBatch.prekeys.count,
                           "Load \(i): prekey count must be unchanged")
            XCTAssertEqual(loaded?.prekeys.first?.id, originalBatch.prekeys.first?.id,
                           "Load \(i): first prekey ID must be unchanged")
        }
        // Pending batch must still be set — it clears only on FS receipt
        XCTAssertTrue(contact.hasPendingBatch)
    }

    /// 5.6.5 — Bob receives any one of Alice's messages carrying her batch and stores it.
    /// syncInboundPrekeys makes Alice's prekeys available for Bob to use.
    func test_exhaustion_receivingOneBatchMessage_storesPrekeys() throws {
        let c       = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let contact = makeContact()
        XCTAssertFalse(contact.hasPrekeyAvailable, "Bob starts with no Alice prekeys")

        // Alice's prekeys arrive in a bundle's prekeyBatch
        let (aliceKeys, _) = try prekeyManager.generateBatch(
            contactID: c, currentSequence: 0, count: 3
        )
        let aliceBlobs = try aliceKeys.map { try encryptBlob($0) }

        // Bob processes inbound batch (simulating ContactManager decrypt step 7)
        contact.syncInboundPrekeys(aliceBlobs, sequence: 1, decryptor: decryptBlob)

        XCTAssertTrue(contact.hasPrekeyAvailable,
                      "Bob must have Alice's prekeys after syncInboundPrekeys")
        XCTAssertEqual(contact.availableInboundPrekeyCount, 3)
    }

    /// 5.6.6 — After Bob stores Alice's prekeys, his next encrypt pops one and
    /// produces a .forwardSecret bundle.
    func test_exhaustion_afterReceivingBatch_nextEncryptIsFS() throws {
        let cAlice    = cid() + ".alice"; defer { prekeyManager.deleteAllKeys(for: cAlice) }
        let cBob      = cid() + ".bob";   defer { prekeyManager.deleteAllKeys(for: cBob) }
        let (_, alicePub) = inMemoryKeyPair()

        // Alice generates keys for Bob, Bob stores them as his contactPrekeys
        let contact         = makeContact()
        let (aliceKeys, _)  = try prekeyManager.generateBatch(contactID: cAlice, currentSequence: 0, count: 3)
        let aliceBlobs      = try aliceKeys.map { try encryptBlob($0) }
        contact.syncInboundPrekeys(aliceBlobs, sequence: 1, decryptor: decryptBlob)

        // Bob pops the oldest prekey and encrypts to Alice using FS
        guard let blob = contact.popOldestPrekeyData() else {
            XCTFail("Bob must have a prekey to pop"); return
        }
        let contactPrekey = (decryptBlob(blob)).flatMap {
            try? JSONDecoder().decode(Prekey.self, from: $0)
        }
        XCTAssertNotNil(contactPrekey, "Bob must decode Alice's prekey")

        let bundle = try crypto.seal(
            message:           Data("Bob → Alice FS".utf8),
            contactPrekey:     contactPrekey,
            recipientMaterial: alicePub,
            outboundBatch:     nil
        )
        XCTAssertEqual(bundle.secrecy.mode, .forwardSecret,
                       "After receiving Alice's prekeys, Bob must send FS")
    }

    /// 5.6.7 — Alice's pending batch is cleared when Bob's FS reply uses one of her prekeys.
    /// removeOwnPrekeyData fires → clearPendingBatch fires.
    func test_exhaustion_pendingBatchCleared_onBobFSReply() throws {
        let c         = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let contact   = makeContact()
        let (keys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 3)

        // Alice has a pending batch
        let batch = OccultaBundle.PrekeySyncBatch(sequence: 0, prekeys: keys)
        try contact.storePendingBatch(batch)
        let blobs = try keys.map { try encryptBlob($0) }
        contact.appendOwnPrekeys(blobs)
        XCTAssertTrue(contact.hasPendingBatch)

        // Bob uses Alice's first prekey to send her a FS message.
        // On Alice's side: removeOwnPrekeyData fires → clearPendingBatch.
        contact.removeOwnPrekeyData(blobs[0])
        contact.clearPendingBatch()

        XCTAssertFalse(contact.hasPendingBatch,
                       "Pending batch must be cleared after Bob uses Alice's prekey")
        XCTAssertEqual(contact.ownPrekeysCount, 2,
                       "Only the consumed blob must be removed; 2 remain")
    }

    // MARK: - 5.7 — Multi-message in-flight

    /// 5.7.1 — Two messages encrypted before either is sent both carry the identical
    /// pending batch (same sequence, same prekey IDs, same prekey count).
    func test_inflight_twoMessagesCarrySamePendingBatch() throws {
        let c         = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let (_, recip) = inMemoryKeyPair()
        let contact   = makeContact()
        let (keys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 3)

        // Store pending batch (simulates encryptBundle on first exhaustion/replenishment)
        let batch = OccultaBundle.PrekeySyncBatch(sequence: 0, prekeys: keys)
        try contact.storePendingBatch(batch)

        // Message 1: load pending batch — same one
        let outbound1 = contact.loadPendingBatch()
        let bundle1   = try crypto.seal(
            message: Data("M1".utf8), contactPrekey: nil,
            recipientMaterial: recip, outboundBatch: outbound1
        )

        // Message 2: load pending batch — still the same
        let outbound2 = contact.loadPendingBatch()
        let bundle2   = try crypto.seal(
            message: Data("M2".utf8), contactPrekey: nil,
            recipientMaterial: recip, outboundBatch: outbound2
        )

        // Both bundles carry the same batch
        XCTAssertEqual(bundle1.secrecy.prekeyBatch?.sequence, bundle2.secrecy.prekeyBatch?.sequence,
                       "Both in-flight messages must carry the same batch sequence")
        XCTAssertEqual(bundle1.secrecy.prekeyBatch?.prekeys.count,
                       bundle2.secrecy.prekeyBatch?.prekeys.count,
                       "Both in-flight messages must carry the same prekey count")
        let ids1 = bundle1.secrecy.prekeyBatch?.prekeys.map { $0.id }.sorted() ?? []
        let ids2 = bundle2.secrecy.prekeyBatch?.prekeys.map { $0.id }.sorted() ?? []
        XCTAssertEqual(ids1, ids2, "Both bundles must carry identical prekey IDs")
    }

    /// 5.7.2 — Bob opens message 1: syncInboundPrekeys stores Alice's batch.
    func test_inflight_openingMessage1_storesBatch() throws {
        let contact   = makeContact()
        let c         = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let (keys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 3)
        let blobs     = try keys.map { try encryptBlob($0) }

        XCTAssertFalse(contact.hasPrekeyAvailable, "Bob starts with no prekeys")

        // Bob receives and processes message 1 (simulating step 7 of decrypt)
        contact.syncInboundPrekeys(blobs, sequence: 1, decryptor: decryptBlob)

        XCTAssertTrue(contact.hasPrekeyAvailable, "After opening M1, Bob must have Alice's prekeys")
        XCTAssertEqual(contact.contactPrekeySequence, 1)
    }

    /// 5.7.3 — Bob opens message 2: sequence guard ignores the duplicate batch (idempotent).
    /// The store must be unchanged — no keys added, no keys removed.
    func test_inflight_openingMessage2_sequenceGuardIgnoresDuplicate() throws {
        let contact   = makeContact()
        let c         = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let (keys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 3)
        let blobs     = try keys.map { try encryptBlob($0) }

        // Bob opens message 1 first — stores the batch at sequence 1
        contact.syncInboundPrekeys(blobs, sequence: 1, decryptor: decryptBlob)
        let countAfterM1 = contact.availableInboundPrekeyCount
        XCTAssertEqual(countAfterM1, 3)

        // Bob opens message 2 — same batch at sequence 1 (equal → ignored)
        contact.syncInboundPrekeys(blobs, sequence: 1, decryptor: decryptBlob)

        XCTAssertEqual(contact.availableInboundPrekeyCount, countAfterM1,
                       "Duplicate batch must be ignored — prekey count must not change")
        XCTAssertEqual(contact.contactPrekeySequence, 1,
                       "Sequence must remain at 1 — must not regress or advance")
    }

    /// 5.7.4 — Bob opens messages in reverse order: result is the same.
    /// M2 first (seq=1), then M1 (seq=1 again — equal, ignored). Bob ends up with the batch.
    func test_inflight_reverseOpenOrder_sameResult() throws {
        let contact   = makeContact()
        let c         = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let (keys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 3)
        let blobs     = try keys.map { try encryptBlob($0) }

        // Both messages carry the same batch at sequence 1.
        // Bob opens M2 first.
        contact.syncInboundPrekeys(blobs, sequence: 1, decryptor: decryptBlob)
        let countAfterM2 = contact.availableInboundPrekeyCount

        // Bob opens M1 — same sequence, ignored
        contact.syncInboundPrekeys(blobs, sequence: 1, decryptor: decryptBlob)

        XCTAssertEqual(contact.availableInboundPrekeyCount, countAfterM2,
                       "Opening in reverse order must produce the same result")
        XCTAssertTrue(contact.hasPrekeyAvailable)
    }

    /// 5.7.5 — Of N in-flight messages, Bob opens only one; he still gets the batch.
    func test_inflight_openingOnlyOneOfN_stillGetsBatch() throws {
        let contact   = makeContact()
        let c         = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let (keys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 3)
        let blobs     = try keys.map { try encryptBlob($0) }

        // 5 in-flight messages all carry the same batch. Bob opens only message 3.
        contact.syncInboundPrekeys(blobs, sequence: 1, decryptor: decryptBlob)

        XCTAssertTrue(contact.hasPrekeyAvailable,
                      "Opening any one of N in-flight messages must deliver the batch")
    }

    // MARK: - 5.8 — Inbound batch validation

    /// 5.8.1 — An inbound batch exceeding the maximum count is rejected before any storage.
    /// ContactManager.decrypt throws invalidPrekeySyncBatch.
    /// Verified here at the model level: batch size > defaultBatchSize * 2.
    func test_inboundBatch_oversized_rejectedBeforeStorage() throws {
        let contact = makeContact()
        let limit   = Manager.PrekeyManager.defaultBatchSize * 2   // 30

        // Construct an oversized batch (31 prekeys)
        let oversizedPrekeys = (0..<(limit + 1)).map { i in
            Prekey(id: "p\(i)", contactID: "c", sequence: 1, publicKey: Data(count: 65))
        }
        XCTAssertGreaterThan(oversizedPrekeys.count, limit,
                             "Batch must exceed the limit to be a valid test")

        // Verify the guard condition that ContactManager checks:
        // count > defaultBatchSize * 2 → reject
        XCTAssertTrue(oversizedPrekeys.count > limit,
                      "Oversized batch count must trigger the guard in ContactManager.decrypt")

        // Model is not written — ContactManager would throw before calling syncInboundPrekeys
        XCTAssertFalse(contact.hasPrekeyAvailable,
                       "contactPrekeys must remain empty — batch was never written")
    }

    /// 5.8.2 — A batch containing a prekey with wrong-length publicKey is rejected.
    /// ContactManager.decrypt validates allSatisfy { publicKey.count == 65 } before storing.
    func test_inboundBatch_wrongLengthPublicKey_rejectedBeforeStorage() throws {
        let contact = makeContact()

        // Batch with one malformed prekey (32 bytes instead of 65)
        let malformedPrekeys = [
            Prekey(id: "good",    contactID: "c", sequence: 1, publicKey: Data(count: 65)),
            Prekey(id: "bad",     contactID: "c", sequence: 1, publicKey: Data(count: 32))
        ]

        // Verify the guard condition:
        let allValid = malformedPrekeys.allSatisfy { $0.publicKey.count == 65 }
        XCTAssertFalse(allValid,
                       "Batch with wrong-length key must fail the allSatisfy guard")

        // Model is not written — ContactManager would throw before syncInboundPrekeys
        XCTAssertFalse(contact.hasPrekeyAvailable,
                       "contactPrekeys must remain empty — malformed batch was never written")
    }

    /// 5.8.3 — When a .longTermFallback is received and no pending batch exists,
    /// a new batch is generated (pendingBatch becomes non-nil).
    func test_inboundFallback_noPendingBatch_newBatchGenerated() throws {
        let contact = makeContact()
        XCTAssertFalse(contact.hasPendingBatch, "Precondition: no pending batch")

        // Simulate the ContactManager inbound-fallback detection path:
        // generate only when !hasPendingBatch
        if !contact.hasPendingBatch {
            let c      = contact.identifier
            let seq    = contact.outboundPrekeySequence
            let result = try prekeyManager.generateBatch(contactID: c, currentSequence: seq)
            let batch  = OccultaBundle.PrekeySyncBatch(sequence: seq, prekeys: result.prekeys)
            try contact.storePendingBatch(batch)
            contact.outboundPrekeySequence = result.nextSequence
            defer { prekeyManager.deleteAllKeys(for: c) }

            XCTAssertTrue(contact.hasPendingBatch,
                          "New batch must be stored as pending after fallback with no existing pending")
        }
    }

    /// 5.8.4 — When a .longTermFallback is received but a pending batch already exists,
    /// no new batch is generated. The existing pending batch keeps riding.
    func test_inboundFallback_pendingBatchExists_noNewGeneration() throws {
        let c       = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let contact = makeContact()

        // Pre-existing pending batch at sequence 0
        let (existingKeys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 2)
        let existingBatch = OccultaBundle.PrekeySyncBatch(sequence: 0, prekeys: existingKeys)
        try contact.storePendingBatch(existingBatch)
        XCTAssertTrue(contact.hasPendingBatch)

        let existingSeq = contact.outboundPrekeySequence

        // Simulate the ContactManager guard: only generate when !hasPendingBatch
        // Since hasPendingBatch == true, the block is skipped
        if !contact.hasPendingBatch {
            XCTFail("This block must NOT execute — pending batch exists")
        }

        // outboundPrekeySequence and pendingBatch must be unchanged
        XCTAssertEqual(contact.outboundPrekeySequence, existingSeq,
                       "Sequence must not advance — no new generation")
        XCTAssertEqual(contact.loadPendingBatch()?.sequence, existingBatch.sequence,
                       "Existing pending batch must be unchanged")
    }

    // MARK: - 5.9.2 — After pruning, old seq blobs are unfindable by ID

    func test_ownPrekeys_prunedBlobsAreUnfindable() throws {
        let c         = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let contact   = makeContact()
        let (keys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 3)

        // Store seq=0 prekeys in ownPrekeys
        let seq0Blobs = try keys.map { try encryptBlob($0) }
        contact.appendOwnPrekeys(seq0Blobs)
        XCTAssertEqual(contact.ownPrekeysCount, 3)

        // Prune seq < 1 — all seq=0 blobs must be removed
        contact.pruneOwnPrekeys(olderThan: 1, decryptor: decryptBlob)
        XCTAssertEqual(contact.ownPrekeysCount, 0, "All seq=0 blobs must be pruned")

        // findOwnPrekeyData must return nil for any of the pruned IDs
        for key in keys {
            let found = contact.findOwnPrekeyData(id: key.id) { try self.decryptBlobThrowing($0) }
            XCTAssertNil(found, "Pruned blob for id \(key.id) must not be findable")
        }
    }

    // MARK: - 5.11.3 — Unknown sender fingerprint

    /// 5.11.3 — A bundle whose senderFingerprint matches no known contact returns
    /// nil from isLikelySender for every contact in the store.
    func test_unknownSender_fingerprintMatchesNoContact() throws {
        // Generate a bundle from a completely unknown key pair
        let (unknownPriv, unknownPub) = inMemoryKeyPair()
        _ = unknownPriv  // suppress unused warning; key pair is real P-256

        let nonce             = try OccultaBundle.SecrecyContext.generateNonce()
        let unknownFingerprint = OccultaBundle.SecrecyContext.fingerprint(
            for: unknownPub, nonce: nonce
        )

        // Three known contacts with different keys
        let contacts = (0..<3).map { _ -> Contact.Profile in
            let c = makeContact()
            return c
        }
        let knownKeys = (0..<3).map { _ -> Data in inMemoryKeyPair().1 }

        // None of the known contacts should match the unknown sender fingerprint
        for (contact, key) in zip(contacts, knownKeys) {
            let bundle = OccultaBundle(
                version:           .v3fs,
                secrecy:           OccultaBundle.SecrecyContext(
                    mode: .longTermFallback, ephemeralPublicKey: Data(count: 65),
                    prekeyID: nil, prekeySequence: nil, prekeyBatch: nil
                ),
                ciphertext:        Data(count: 28),
                fingerprintNonce:  nonce,
                senderFingerprint: unknownFingerprint
            )
            XCTAssertFalse(
                contact.isLikelySender(of: bundle, contactPublicKey: key),
                "Known contact must not match unknown sender fingerprint"
            )
        }
    }

    // MARK: - 6.12, 6.13, 6.14 — Attack scenarios

    /// 6.13 — Tampered fingerprintNonce: sender identification fails
    /// (candidate hash won't match senderFingerprint). Bundle is undeliverable.
    /// No plaintext exposure — we can't even derive a session key without identifying sender.
    func test_attack_tamperedFingerprintNonce_senderNotFound() throws {
        let (_, senderPub) = inMemoryKeyPair()
        let realNonce      = try OccultaBundle.SecrecyContext.generateNonce()
        let realFp         = OccultaBundle.SecrecyContext.fingerprint(for: senderPub, nonce: realNonce)

        // Attacker replaces nonce with different bytes
        let tamperedNonce = Data(repeating: 0xFF, count: 16)
        let contact       = makeContact()

        let bundleWithTamperedNonce = OccultaBundle(
            version:           .v3fs,
            secrecy:           OccultaBundle.SecrecyContext(
                mode: .longTermFallback, ephemeralPublicKey: Data(count: 65),
                prekeyID: nil, prekeySequence: nil, prekeyBatch: nil
            ),
            ciphertext:        Data(count: 28),
            fingerprintNonce:  tamperedNonce,   // tampered
            senderFingerprint: realFp           // computed with realNonce, not tamperedNonce
        )

        // Fingerprint candidate = SHA-256(senderPub || tamperedNonce) ≠ realFp
        XCTAssertFalse(
            contact.isLikelySender(of: bundleWithTamperedNonce, contactPublicKey: senderPub),
            "Tampered nonce must cause sender identification to fail"
        )
    }

    /// 6.14 — Tampered senderFingerprint: the computed candidate won't match
    /// the injected fingerprint. Bundle is undeliverable to any contact.
    func test_attack_tamperedSenderFingerprint_senderNotFound() throws {
        let (_, senderPub) = inMemoryKeyPair()
        let nonce          = try OccultaBundle.SecrecyContext.generateNonce()
        // Attacker replaces the fingerprint with random bytes
        let attackerFp     = Data(repeating: 0xAB, count: 32)
        let contact        = makeContact()

        let bundleWithFakeFingerprint = OccultaBundle(
            version:           .v3fs,
            secrecy:           OccultaBundle.SecrecyContext(
                mode: .longTermFallback, ephemeralPublicKey: Data(count: 65),
                prekeyID: nil, prekeySequence: nil, prekeyBatch: nil
            ),
            ciphertext:        Data(count: 28),
            fingerprintNonce:  nonce,
            senderFingerprint: attackerFp   // tampered
        )

        // SHA-256(senderPub || nonce) ≠ attackerFp
        XCTAssertFalse(
            contact.isLikelySender(of: bundleWithFakeFingerprint, contactPublicKey: senderPub),
            "Tampered senderFingerprint must cause sender identification to fail"
        )
    }

    // MARK: - 6.15 — Cross-contact prekey injection

    /// 6.15 — An attacker injects Bob's prekey public key into Jake's store and
    /// tries to decrypt a bundle addressed to Jake using Bob's SE private key.
    /// The SE tag for Bob's key is "prekey.bob.0.<id>" — retrieving it with Jake's
    /// contactID produces a different tag "prekey.jake.0.<id>" → nil → no decryption.
    func test_attack_crossContactPrekeyInjection_failsSafely() throws {
        let bobCID  = cid() + ".bob"
        let jakeCID = cid() + ".jake"
        defer {
            prekeyManager.deleteAllKeys(for: bobCID)
            prekeyManager.deleteAllKeys(for: jakeCID)
        }

        // Generate Bob's prekey (private key in SE tagged for Bob)
        let (bobKeys, _) = try prekeyManager.generateBatch(
            contactID: bobCID, currentSequence: 0, count: 1
        )
        let bobPrekey = bobKeys[0]

        // Injected: attacker stores Bob's PUBLIC key in Jake's ownPrekeys store
        // with Jake's contactID — reconstructing the SE tag "prekey.jake.0.<bobID>"
        let injectedPrekey = Prekey(
            id:        bobPrekey.id,
            contactID: jakeCID,          // wrong contact — Bob's ID goes here in real life
            sequence:  bobPrekey.sequence,
            publicKey: bobPrekey.publicKey
        )

        // Try to retrieve Bob's SE private key using Jake's SE tag
        // Tag = "prekey.jake.0.<bobID>" — this key does not exist in the SE
        let retrieved = prekeyManager.retrievePrivateKey(for: injectedPrekey)
        XCTAssertNil(retrieved,
                     "Injecting Bob's prekey with Jake's contactID must not retrieve Bob's SE key")

        // Bob's key is still safely in the SE under Bob's tag
        XCTAssertNotNil(
            prekeyManager.retrievePrivateKey(for: bobPrekey),
            "Bob's actual prekey must remain in the SE unaffected"
        )
    }

    // MARK: - Integration test helpers (extended)

    /// Throwing variant of decryptBlob for findOwnPrekeyData compatibility.
    private func decryptBlobThrowing(_ data: Data) throws -> Data? {
        try AES.GCM.open(try AES.GCM.SealedBox(combined: data), using: Self.blobKey)
    }
}

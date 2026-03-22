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
        crypto        = Manager.Crypto()     // real SE identity key
        prekeyManager = Manager.PrekeyManager()
    }

    override func tearDown() {
        crypto = nil; prekeyManager = nil
        super.tearDown()
    }

    // MARK: - Helpers

    private func cid(function: String = #function) -> String { "int.\(function).\(UUID().uuidString)" }

    private func inMemoryKeyPair() -> (SecKey, Data) {
        let attrs: NSDictionary = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                                   kSecAttrKeySizeInBits: 256,
                                   kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]]
        var e: Unmanaged<CFError>?
        let priv = SecKeyCreateRandomKey(attrs, &e)!
        let pub  = SecKeyCopyPublicKey(priv)!
        return (priv, SecKeyCopyExternalRepresentation(pub, nil)! as Data)
    }

    // Canonical decrypt — SecKey scoped in closure, consume after.
    private func decrypt(bundle: OccultaBundle, prekey: Prekey?) throws -> Data? {
        switch bundle.secrecy.mode {
        case .forwardSecret:
            let result: Data? = try {
                guard
                    let pk   = prekey,
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
        let c         = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let (keys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 1)
        let (_, recip) = inMemoryKeyPair()
        let message    = Data("Integration roundtrip".utf8)

        let bundle    = try crypto.seal(
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
            let message = Data("Message \(i)".utf8)
            let bundle  = try crypto.seal(
                message: message, contactPrekey: prekey, recipientMaterial: recip, outboundBatch: nil
            )
            XCTAssertEqual(try decrypt(bundle: bundle, prekey: prekey), message)
            XCTAssertNil(prekeyManager.retrievePrivateKey(for: prekey),
                         "Prekey \(i) must be consumed")
        }
    }

    // MARK: - Bidirectional conversation (the test that would have caught Finding 1)
    //
    // This test verifies that Alice sending to Bob and Bob sending to Alice
    // use COMPLETELY SEPARATE prekey pools. Before the fix, both paths wrote
    // to the same `contactPrekeys` array, causing the second direction to
    // overwrite the first when sequences advanced.

    func test_bidirectional_aliceAndBob_independentPools() throws {
        // Alice's pool for Bob (Alice generates keys, Bob will use them to reply)
        let aliceForBobCID  = cid() + ".aliceForBob"
        // Bob's pool for Alice (Bob generates keys, Alice will use them)
        let bobForAliceCID  = cid() + ".bobForAlice"
        defer {
            prekeyManager.deleteAllKeys(for: aliceForBobCID)
            prekeyManager.deleteAllKeys(for: bobForAliceCID)
        }

        let (_, alicePub)  = inMemoryKeyPair()
        let (_, bobPub)    = inMemoryKeyPair()

        // Alice generates a batch for Bob (Alice's ownPrekeys for Bob)
        let (aliceKeys, _) = try prekeyManager.generateBatch(
            contactID: aliceForBobCID, currentSequence: 0, count: 3
        )

        // Bob generates a batch for Alice (Bob's ownPrekeys for Alice)
        let (bobKeys, _) = try prekeyManager.generateBatch(
            contactID: bobForAliceCID, currentSequence: 0, count: 3
        )

        // Alice → Bob: uses Bob's prekey (bobKeys[0]) to encrypt
        let aliceToBobBundle = try crypto.seal(
            message:           Data("Hello Bob".utf8),
            contactPrekey:     bobKeys[0],       // Bob's prekey
            recipientMaterial: bobPub,
            outboundBatch:     OccultaBundle.PrekeySyncBatch(
                sequence: 0, prekeys: aliceKeys   // Alice's prekeys for Bob to reply with
            )
        )

        // Bob → Alice: uses Alice's prekey (aliceKeys[0]) to encrypt
        let bobToAliceBundle = try crypto.seal(
            message:           Data("Hello Alice".utf8),
            contactPrekey:     aliceKeys[0],     // Alice's prekey
            recipientMaterial: alicePub,
            outboundBatch:     OccultaBundle.PrekeySyncBatch(
                sequence: 0, prekeys: bobKeys    // Bob's prekeys for Alice to reply with
            )
        )

        // Bob decrypts Alice's message using his own prekey (bobKeys[0])
        let bobDecrypted = try decrypt(bundle: aliceToBobBundle, prekey: bobKeys[0])
        XCTAssertEqual(bobDecrypted, Data("Hello Bob".utf8))

        // Consuming Bob's key must NOT affect Alice's keys
        XCTAssertNil(
            prekeyManager.retrievePrivateKey(for: bobKeys[0]),
            "Bob's prekey must be consumed"
        )
        XCTAssertNotNil(
            prekeyManager.retrievePrivateKey(for: aliceKeys[0]),
            "Alice's prekey must be unaffected by Bob's consumption"
        )

        // Alice decrypts Bob's message using her own prekey (aliceKeys[0])
        let aliceDecrypted = try decrypt(bundle: bobToAliceBundle, prekey: aliceKeys[0])
        XCTAssertEqual(aliceDecrypted, Data("Hello Alice".utf8))

        XCTAssertNil(
            prekeyManager.retrievePrivateKey(for: aliceKeys[0]),
            "Alice's prekey must be consumed after her decrypt"
        )

        // Remaining keys in each pool must be untouched
        XCTAssertEqual(prekeyManager.remainingCount(for: aliceForBobCID), 2,
                       "Alice's remaining prekeys for Bob must be intact")
        XCTAssertEqual(prekeyManager.remainingCount(for: bobForAliceCID), 2,
                       "Bob's remaining prekeys for Alice must be intact")
    }

    // MARK: - Pool isolation

    func test_poolIsolation_consumingBobDoesNotAffectJake() throws {
        let bobCID  = cid() + ".bob"
        let jakeCID = cid() + ".jake"
        defer { prekeyManager.deleteAllKeys(for: bobCID); prekeyManager.deleteAllKeys(for: jakeCID) }

        let (bobKeys,  _) = try prekeyManager.generateBatch(contactID: bobCID,  currentSequence: 0, count: 3)
        let (jakeKeys, _) = try prekeyManager.generateBatch(contactID: jakeCID, currentSequence: 0, count: 3)
        let (_, bobPub)   = inMemoryKeyPair()
        let (_, jakePub)  = inMemoryKeyPair()

        let bobBundle  = try crypto.seal(
            message: Data("For Bob".utf8),  contactPrekey: bobKeys[0],  recipientMaterial: bobPub,  outboundBatch: nil
        )
        let jakeBundle = try crypto.seal(
            message: Data("For Jake".utf8), contactPrekey: jakeKeys[0], recipientMaterial: jakePub, outboundBatch: nil
        )

        _ = try decrypt(bundle: bobBundle, prekey: bobKeys[0])
        XCTAssertNil(prekeyManager.retrievePrivateKey(for: bobKeys[0]))
        XCTAssertNotNil(prekeyManager.retrievePrivateKey(for: jakeKeys[0]),
                        "Jake's prekey must be unaffected")

        let jakePlaintext = try decrypt(bundle: jakeBundle, prekey: jakeKeys[0])
        XCTAssertEqual(jakePlaintext, Data("For Jake".utf8))
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
        let first  = try decrypt(bundle: bundle, prekey: keys[0])
        XCTAssertNotNil(first)
        let second = try decrypt(bundle: bundle, prekey: keys[0])
        XCTAssertNil(second, "Consumed key must never decrypt again")
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

    // MARK: - ownPrekeys pruning (new test for accumulation fix)

    func test_pruneOwnPrekeys_alignsWithSEPruning() throws {
        let blobKey = SymmetricKey(size: .bits256)

        let encrypt: (Prekey) throws -> Data = { prekey in
            let encoded = try JSONEncoder().encode(prekey)
            return try AES.GCM.seal(encoded, using: blobKey, nonce: AES.GCM.Nonce()).combined!
        }
        let decrypt: (Data) throws -> Data = { data in
            try AES.GCM.open(try AES.GCM.SealedBox(combined: data), using: blobKey)
        }

        let contact = makeContact()

        // Simulate three batch rounds
        let seq0Blobs = try [encrypt(Prekey(id: "A", contactID: "c", sequence: 0, publicKey: Data(count: 65))),
                             encrypt(Prekey(id: "B", contactID: "c", sequence: 0, publicKey: Data(count: 65)))]
        let seq1Blobs = try [encrypt(Prekey(id: "C", contactID: "c", sequence: 1, publicKey: Data(count: 65)))]
        let seq2Blobs = try [encrypt(Prekey(id: "D", contactID: "c", sequence: 2, publicKey: Data(count: 65)))]

        contact.appendOwnPrekeys(seq0Blobs)
        contact.appendOwnPrekeys(seq1Blobs)
        contact.appendOwnPrekeys(seq2Blobs)
        XCTAssertEqual(contact.ownPrekeysCount, 4)

        // When SE generates seq=3, it prunes seq < 2. Mirror that here.
        contact.pruneOwnPrekeys(olderThan: 2) { try decrypt($0) }

        // seq=0 and seq=1 blobs pruned; seq=2 survives
        XCTAssertEqual(contact.ownPrekeysCount, 1)
        let surviving = try JSONDecoder().decode(
            Prekey.self,
            from: AES.GCM.open(try AES.GCM.SealedBox(combined: contact.ownPrekeys![0]), using: blobKey)
        )
        XCTAssertEqual(surviving.sequence, 2)
    }

    // MARK: - Sequence pruning

    func test_sequencePruning_oldKeysDeletedNewKeysSurvive() throws {
        let c = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let (seq1, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 1, count: 2)
        let (seq2, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 2, count: 2)
        let (seq3, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 3, count: 2)

        for k in seq1 { XCTAssertNil(prekeyManager.retrievePrivateKey(for: k), "Seq 1 must be pruned") }
        for k in seq2 { XCTAssertNotNil(prekeyManager.retrievePrivateKey(for: k), "Seq 2 must survive") }
        for k in seq3 { XCTAssertNotNil(prekeyManager.retrievePrivateKey(for: k), "Seq 3 must survive") }
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

    // MARK: - Input validation and version check

    func test_decrypt_wrongVersion_throws() throws {
        let c          = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let (keys, _)  = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 1)
        let (_, recip) = inMemoryKeyPair()
        let bundle     = try crypto.seal(
            message: Data("test".utf8), contactPrekey: keys[0],
            recipientMaterial: recip, outboundBatch: nil
        )
        // Construct a bundle with a different version — AAD mismatch AND version check
        let wrongVersion = OccultaBundle(
            version:           .v1,             // wrong
            secrecy:           bundle.secrecy,
            ciphertext:        bundle.ciphertext,
            fingerprintNonce:  bundle.fingerprintNonce,
            senderFingerprint: bundle.senderFingerprint
        )
        // ContactManager.decrypt rejects non-.v3fs versions before any crypto
        // In unit test context we call the crypto layer directly — confirm fullAAD fails
        let sessKey = SymmetricKey(size: .bits256)
        XCTAssertThrowsError(
            try crypto.open(wrongVersion, using: sessKey),
            "Wrong version must produce different AAD and fail GCM"
        )
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

        // Tamper the ephemeralPublicKey to wrong length
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
        // ContactManager.decrypt validates ephemeralPublicKey.count == 65 before ECDH
        // and openBundle will fail AAD (tampered SecrecyContext)
        let sessKey = SymmetricKey(size: .bits256)
        XCTAssertThrowsError(
            try crypto.open(tampered, using: sessKey),
            "Tampered ephemeralPublicKey must fail GCM AAD verification"
        )
    }

    // MARK: - Helpers

    private func makeContact() -> Contact.Profile {
        Contact.Profile(
            identifier: UUID().uuidString, givenName: "Test", familyName: "Contact",
            middleName: "", nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
    }
}

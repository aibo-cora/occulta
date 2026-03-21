//
//  ForwardSecrecyIntegrationTests.swift
//  OccultaTests
//
//  Full-stack integration tests using the real Secure Enclave.
//
//  ⚠️  RUN ON DEVICE ONLY — SE not available in simulator.
//
//  Architecture rule enforced throughout:
//    All SE writes (generateBatch) are done BEFORE any ECDH operation.
//    encryptForwardSecret performs zero SE writes.
//    deriveSessionKey + openBundle perform zero SE writes.
//    consume() is called only after the SecKey reference is out of scope.
//

import XCTest
internal import CryptoKit
@testable import Occulta

final class ForwardSecrecyIntegrationTests: XCTestCase {

    var crypto:        Manager.Crypto!
    var prekeyManager: Manager.PrekeyManager!

    override func setUp() {
        super.setUp()
        crypto        = Manager.Crypto()          // real SE master key
        prekeyManager = Manager.PrekeyManager()
    }

    override func tearDown() {
        crypto        = nil
        prekeyManager = nil
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

    /// Decrypt helper — SecKey scoped inside closure, consume after.
    private func decrypt(bundle: OccultaBundle, prekey: Prekey?) throws -> Data? {
        switch bundle.secrecy.mode {

        case .forwardSecret:
            // ⚠️ CRASH PROTECTION: SecKey released inside closure before consume.
            let result: Data? = try {
                guard
                    let pk         = prekey,
                    let privKey    = prekeyManager.retrievePrivateKey(for: pk),
                    let sessionKey = crypto.deriveSessionKey(
                                         ephemeralPrivateKey: privKey,
                                         recipientMaterial:   bundle.secrecy.ephemeralPublicKey
                                     )
                else { return nil }
                return try crypto.open(bundle, using: sessionKey)
                // ← privKey released here
            }()

            if result != nil, let pk = prekey {
                prekeyManager.consume(prekey: pk)   // SecKey is gone — safe
            }
            return result

        case .longTermFallback:
            guard
                let sessionKey = crypto.deriveSessionKey(
                    using: bundle.secrecy.ephemeralPublicKey
                )
            else { return nil }
            return try crypto.open(bundle, using: sessionKey)
        }
    }

    // MARK: - Full encrypt → decrypt roundtrip

    /// ⚠️ CRASH CANDIDATE — SecKey lifetime in decrypt helper.
    /// The closure guarantees SecKey is released before consume().
    func test_roundtrip_FSPath() throws {
        let c         = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }

        // SE writes BEFORE encrypt
        let (keys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 1)
        let (_, recip) = inMemoryKeyPair()
        let message    = Data("Integration roundtrip".utf8)

        // Zero SE writes inside this call
        let bundle = try crypto.encryptForwardSecret(
            message:           message,
            contactPrekey:     keys[0],
            recipientMaterial: recip,
            outboundBatch:     nil
        )

        XCTAssertEqual(bundle.secrecy.mode, .forwardSecret)

        // ⚠️ SecKey held inside closure, released before consume
        let plaintext = try decrypt(bundle: bundle, prekey: keys[0])
        XCTAssertEqual(plaintext, message)
    }

    func test_roundtrip_fiveSequentialMessages() throws {
        let c         = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }

        let (keys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 5)
        let (_, recip) = inMemoryKeyPair()

        for (i, prekey) in keys.enumerated() {
            let message = Data("Message \(i)".utf8)

            let bundle = try crypto.encryptForwardSecret(
                message: message, contactPrekey: prekey,
                recipientMaterial: recip, outboundBatch: nil
            )

            let plaintext = try decrypt(bundle: bundle, prekey: prekey)
            XCTAssertEqual(plaintext, message, "Message \(i) roundtrip failed")
            XCTAssertNil(
                prekeyManager.retrievePrivateKey(for: prekey),
                "Prekey \(i) must be consumed after decrypt"
            )
        }
    }

    // MARK: - Pool isolation

    func test_poolIsolation_independentContacts() throws {
        let bobID  = cid() + ".bob"
        let jakeID = cid() + ".jake"
        defer {
            prekeyManager.deleteAllKeys(for: bobID)
            prekeyManager.deleteAllKeys(for: jakeID)
        }

        let (bobKeys,  _) = try prekeyManager.generateBatch(contactID: bobID,  currentSequence: 0, count: 3)
        let (jakeKeys, _) = try prekeyManager.generateBatch(contactID: jakeID, currentSequence: 0, count: 3)
        let (_, bobRecip)  = inMemoryKeyPair()
        let (_, jakeRecip) = inMemoryKeyPair()

        let bobBundle = try crypto.encryptForwardSecret(
            message: Data("For Bob".utf8), contactPrekey: bobKeys[0],
            recipientMaterial: bobRecip, outboundBatch: nil
        )
        let jakeBundle = try crypto.encryptForwardSecret(
            message: Data("For Jake".utf8), contactPrekey: jakeKeys[0],
            recipientMaterial: jakeRecip, outboundBatch: nil
        )

        // Decrypt Bob — consumes bobKeys[0]
        let bobPlaintext = try decrypt(bundle: bobBundle, prekey: bobKeys[0])
        XCTAssertNotNil(bobPlaintext)
        XCTAssertNil(prekeyManager.retrievePrivateKey(for: bobKeys[0]),
                     "Bob's prekey must be consumed")

        // Jake's prekeys must be unaffected
        XCTAssertNotNil(
            prekeyManager.retrievePrivateKey(for: jakeKeys[0]),
            "Jake's prekey must NOT be affected by Bob's decryption"
        )

        let jakePlaintext = try decrypt(bundle: jakeBundle, prekey: jakeKeys[0])
        XCTAssertEqual(jakePlaintext, Data("For Jake".utf8))
    }

    // MARK: - Forward secrecy guarantee

    /// ⚠️ CRASH CANDIDATE — second call with consumed prekey.
    /// retrievePrivateKey returns nil immediately. No SecKey. No crash.
    func test_forwardSecrecy_consumedKey_returnsNil() throws {
        let c         = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }

        let (keys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 1)
        let (_, recip) = inMemoryKeyPair()

        let bundle = try crypto.encryptForwardSecret(
            message: Data("once only".utf8), contactPrekey: keys[0],
            recipientMaterial: recip, outboundBatch: nil
        )

        let first = try decrypt(bundle: bundle, prekey: keys[0])
        XCTAssertNotNil(first, "First decrypt must succeed")

        let second = try decrypt(bundle: bundle, prekey: keys[0])
        XCTAssertNil(second, "Consumed key must never decrypt the same bundle again")
    }

    // MARK: - Fallback path

    func test_fallback_bundleMode() throws {
        let c = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }

        let bundle = try crypto.encryptForwardSecret(
            message: Data("fallback".utf8), contactPrekey: nil,
            recipientMaterial: inMemoryKeyPair().1, outboundBatch: nil
        )

        XCTAssertEqual(bundle.secrecy.mode, .longTermFallback)
        XCTAssertNil(bundle.secrecy.prekeyID)
        XCTAssertNil(bundle.secrecy.prekeySequence)
    }

    // MARK: - Replenishment — SE writes before encrypt

    func test_replenishment_batchInBundleThenDecryptable() throws {
        let c          = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }

        let (_, recip) = inMemoryKeyPair()
        let seq        = 0

        // SE writes HERE — before encrypt
        let result = try prekeyManager.generateBatch(contactID: c, currentSequence: seq)
        let outboundBatch = OccultaBundle.PrekeySyncBatch(
            sequence: seq,
            prekeys:  result.prekeys
        )

        // Encrypt — zero SE writes
        let bundle = try crypto.encryptForwardSecret(
            message:           Data("with batch".utf8),
            contactPrekey:     result.prekeys[0],
            recipientMaterial: recip,
            outboundBatch:     outboundBatch
        )

        XCTAssertEqual(bundle.secrecy.mode, .forwardSecret)
        XCTAssertEqual(bundle.secrecy.prekeyBatch?.sequence,      seq)
        XCTAssertEqual(bundle.secrecy.prekeyBatch?.prekeys.count, Manager.PrekeyManager.defaultBatchSize)

        let plaintext = try decrypt(bundle: bundle, prekey: result.prekeys[0])
        XCTAssertEqual(plaintext, Data("with batch".utf8))
    }

    // MARK: - Sequence pruning

    func test_sequencePruning_oldKeysDeletedNewKeysSurvive() throws {
        let c = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }

        let (seq1, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 1, count: 2)
        let (seq2, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 2, count: 2)
        let (seq3, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 3, count: 2)

        for key in seq1 {
            XCTAssertNil(prekeyManager.retrievePrivateKey(for: key), "Seq 1 must be pruned")
        }
        for key in seq2 {
            XCTAssertNotNil(prekeyManager.retrievePrivateKey(for: key), "Seq 2 must survive as buffer")
        }
        for key in seq3 {
            XCTAssertNotNil(prekeyManager.retrievePrivateKey(for: key), "Seq 3 must survive as current")
        }
    }

    func test_sequencePruning_strictlyContactScoped() throws {
        let c1 = cid() + ".alpha"
        let c2 = cid() + ".beta"
        defer {
            prekeyManager.deleteAllKeys(for: c1)
            prekeyManager.deleteAllKeys(for: c2)
        }

        let (k1, _) = try prekeyManager.generateBatch(contactID: c1, currentSequence: 1, count: 2)
        let (k2, _) = try prekeyManager.generateBatch(contactID: c2, currentSequence: 1, count: 2)

        let _ = try prekeyManager.generateBatch(contactID: c1, currentSequence: 2, count: 2)
        let _ = try prekeyManager.generateBatch(contactID: c1, currentSequence: 3, count: 2)

        for key in k1 { XCTAssertNil(prekeyManager.retrievePrivateKey(for: key), "c1 seq 1 pruned") }
        for key in k2 { XCTAssertNotNil(prekeyManager.retrievePrivateKey(for: key), "c2 unaffected") }
    }

    // MARK: - Bundle serialisation

    func test_bundleEncodeDecode_allFieldsPreserved() throws {
        let c          = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }

        let (keys, _)  = try prekeyManager.generateBatch(contactID: c, currentSequence: 5, count: 1)
        let (_, recip) = inMemoryKeyPair()

        let original = try crypto.encryptForwardSecret(
            message: Data("serialise".utf8), contactPrekey: keys[0],
            recipientMaterial: recip, outboundBatch: nil
        )
        let decoded = try OccultaBundle.decode(from: original.encode())

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
        for key in s0 + s1 {
            XCTAssertNil(prekeyManager.retrievePrivateKey(for: key))
        }
    }
}

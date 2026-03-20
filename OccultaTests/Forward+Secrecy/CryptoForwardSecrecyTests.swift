//
//  CryptoForwardSecrecyTests.swift
//  OccultaTests
//
//  Tests for Manager.Crypto forward-secret encryption and session key derivation.
//  Uses TestKeyManager — NO SE access during ECDH or AES-GCM operations.
//
//  PrekeyManager writes SE keys in test setup (generateBatch).
//  encryptForwardSecret itself performs ZERO SE writes.
//  deriveSessionKey + openBundle perform zero SE writes.
//
//  Crash candidates are annotated with ⚠️.
//

import XCTest
internal import CryptoKit
@testable import Occulta

final class CryptoForwardSecrecyTests: XCTestCase {

    var crypto:        Manager.Crypto!
    var prekeyManager: Manager.PrekeyManager!
    var testKeyMgr:    TestKeyManager!

    override func setUp() {
        super.setUp()
        testKeyMgr    = TestKeyManager()
        crypto        = Manager.Crypto(keyManager: testKeyMgr)
        prekeyManager = Manager.PrekeyManager()
    }

    override func tearDown() {
        crypto        = nil
        prekeyManager = nil
        testKeyMgr    = nil
        super.tearDown()
    }

    // MARK: - Helpers

    private func cid(function: String = #function) -> String {
        "crypto.\(function).\(UUID().uuidString)"
    }

    private func onePrekey(for cid: String) throws -> Prekey {
        let (keys, _) = try prekeyManager.generateBatch(contactID: cid, currentSequence: 0, count: 1)
        return keys[0]
    }

    /// Recipient public key — in-memory only, private key immediately discarded.
    private func recipientPub() -> Data {
        let attrs: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
        ]
        var e: Unmanaged<CFError>?
        let priv = SecKeyCreateRandomKey(attrs, &e)!
        return SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(priv)!, nil)! as Data
    }

    /// Decrypt a bundle using deriveSessionKey + openBundle.
    /// The SecKey (for FS) is scoped inside the closure — released before consume.
    private func decrypt(
        bundle: OccultaBundle,
        prekey: Prekey?
    ) throws -> Data? {
        switch bundle.secrecy.mode {

        case .forwardSecret:
            let result: Data? = try {
                guard
                    let pk        = prekey,
                    let privKey   = prekeyManager.retrievePrivateKey(for: pk),
                    let sessionKey = crypto.deriveSessionKey(
                        ephemeralPrivateKey: privKey,
                        recipientMaterial:   bundle.secrecy.ephemeralPublicKey
                    )
                else { return nil }
                return try crypto.open(bundle, using: sessionKey)
                // ← privKey released here
            }()

            if result != nil, let pk = prekey {
                prekeyManager.consume(prekey: pk)
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

    // MARK: - encryptForwardSecret — FS path

    func test_encrypt_FS_modeIsForwardSecret() throws {
        let c = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }

        let bundle = try crypto.encryptForwardSecret(
            message: Data("test".utf8), contactPrekey: try onePrekey(for: c),
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        XCTAssertEqual(bundle.secrecy.mode, .forwardSecret)
    }

    func test_encrypt_FS_versionIsV3fs() throws {
        let c = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }

        let bundle = try crypto.encryptForwardSecret(
            message: Data("test".utf8), contactPrekey: try onePrekey(for: c),
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        XCTAssertEqual(bundle.version, .v3fs)
    }

    func test_encrypt_FS_prekeyIDAndSequenceMatchInput() throws {
        let c      = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }
        let prekey = try onePrekey(for: c)

        let bundle = try crypto.encryptForwardSecret(
            message: Data("test".utf8), contactPrekey: prekey,
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        XCTAssertEqual(bundle.secrecy.prekeyID,       prekey.id)
        XCTAssertEqual(bundle.secrecy.prekeySequence, prekey.sequence)
    }

    func test_encrypt_FS_ciphertextNonEmpty() throws {
        let c = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }

        let bundle = try crypto.encryptForwardSecret(
            message: Data("hello".utf8), contactPrekey: try onePrekey(for: c),
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        XCTAssertFalse(bundle.ciphertext.isEmpty)
    }

    func test_encrypt_FS_fingerprintNonceIs16Bytes() throws {
        let c = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }

        let bundle = try crypto.encryptForwardSecret(
            message: Data("test".utf8), contactPrekey: try onePrekey(for: c),
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        XCTAssertEqual(bundle.secrecy.fingerprintNonce.count, 16)
    }

    func test_encrypt_FS_fingerprintMatchesOurKey() throws {
        let c = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }

        let bundle = try crypto.encryptForwardSecret(
            message: Data("test".utf8), contactPrekey: try onePrekey(for: c),
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        let expected = OccultaBundle.SecrecyContext.fingerprint(
            for:   try testKeyMgr.retrieveIdentity(),
            nonce: bundle.secrecy.fingerprintNonce
        )
        XCTAssertEqual(bundle.secrecy.senderFingerprint, expected)
    }

    func test_encrypt_FS_eachBundleUniqueNonce() throws {
        let c = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }
        let (keys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 2)
        let recip     = recipientPub()

        let b1 = try crypto.encryptForwardSecret(
            message: Data("a".utf8), contactPrekey: keys[0],
            recipientMaterial: recip, outboundBatch: nil
        )
        let b2 = try crypto.encryptForwardSecret(
            message: Data("b".utf8), contactPrekey: keys[1],
            recipientMaterial: recip, outboundBatch: nil
        )
        XCTAssertNotEqual(b1.secrecy.fingerprintNonce,  b2.secrecy.fingerprintNonce)
        XCTAssertNotEqual(b1.secrecy.senderFingerprint, b2.secrecy.senderFingerprint)
    }

    func test_encrypt_FS_outboundBatchEmbedded() throws {
        let c = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }
        let batch = OccultaBundle.PrekeySyncBatch(
            sequence: 1,
            prekeys: [Prekey(id: "P1", contactID: c, sequence: 1, publicKey: Data(count: 65))]
        )
        let bundle = try crypto.encryptForwardSecret(
            message: Data("test".utf8), contactPrekey: try onePrekey(for: c),
            recipientMaterial: recipientPub(), outboundBatch: batch
        )
        XCTAssertEqual(bundle.secrecy.prekeyBatch?.sequence,          1)
        XCTAssertEqual(bundle.secrecy.prekeyBatch?.prekeys.first?.id, "P1")
    }

    // MARK: - encryptForwardSecret — fallback path

    func test_encrypt_fallback_modeIsLongTermFallback() throws {
        let c = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }

        let bundle = try crypto.encryptForwardSecret(
            message: Data("fallback".utf8), contactPrekey: nil,
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        XCTAssertEqual(bundle.secrecy.mode, .longTermFallback)
    }

    func test_encrypt_fallback_prekeyFieldsNil() throws {
        let c = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }

        let bundle = try crypto.encryptForwardSecret(
            message: Data("fallback".utf8), contactPrekey: nil,
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        XCTAssertNil(bundle.secrecy.prekeyID)
        XCTAssertNil(bundle.secrecy.prekeySequence)
    }

    func test_encrypt_fallback_outboundBatchPassedThrough() throws {
        let c = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }
        let batch = OccultaBundle.PrekeySyncBatch(
            sequence: 5,
            prekeys: [Prekey(id: "P", contactID: c, sequence: 5, publicKey: Data(count: 65))]
        )
        let bundle = try crypto.encryptForwardSecret(
            message: Data("fallback".utf8), contactPrekey: nil,
            recipientMaterial: recipientPub(), outboundBatch: batch
        )
        XCTAssertEqual(bundle.secrecy.prekeyBatch?.sequence, 5)
    }

    func test_encrypt_fallback_nilBatchPassedThrough() throws {
        let c = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }

        let bundle = try crypto.encryptForwardSecret(
            message: Data("fallback".utf8), contactPrekey: nil,
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        XCTAssertNil(bundle.secrecy.prekeyBatch)
    }

    // MARK: - deriveSessionKey + openBundle — FS path

    /// ⚠️ CRASH CANDIDATE — SecKey lifetime
    /// retrievePrivateKey returns an SE-backed SecKey.
    /// The helper above scopes it inside a closure so ARC releases it
    /// before consume() calls SecItemDelete.
    func test_decrypt_FS_plaintextMatchesOriginal() throws {
        let c      = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }
        let prekey = try onePrekey(for: c)
        let recip  = recipientPub()

        let bundle = try crypto.encryptForwardSecret(
            message: Data("round trip".utf8), contactPrekey: prekey,
            recipientMaterial: recip, outboundBatch: nil
        )

        // TestKeyManager used the same in-memory key for encrypt and decrypt,
        // so the ECDH result is consistent and the roundtrip succeeds.
        let plaintext = try decrypt(bundle: bundle, prekey: prekey)

        XCTAssertEqual(plaintext, Data("round trip".utf8))
    }

    /// ⚠️ CRASH CANDIDATE — SecKey lifetime
    /// After first decrypt, prekey is consumed. Second call returns nil
    /// without touching the SE — retrievePrivateKey returns nil immediately.
    func test_decrypt_FS_consumesKeyAfterSuccessfulDecrypt() throws {
        let c      = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }
        let prekey = try onePrekey(for: c)

        let bundle = try crypto.encryptForwardSecret(
            message: Data("secret".utf8), contactPrekey: prekey,
            recipientMaterial: recipientPub(), outboundBatch: nil
        )

        XCTAssertNotNil(prekeyManager.retrievePrivateKey(for: prekey))
        _ = try decrypt(bundle: bundle, prekey: prekey)
        XCTAssertNil(prekeyManager.retrievePrivateKey(for: prekey),
                     "Key must be deleted after successful decrypt")
    }

    /// ⚠️ CRASH CANDIDATE — duplicate delivery
    /// Second call: retrievePrivateKey returns nil → no SecKey held → no crash.
    func test_decrypt_FS_duplicateDelivery_returnsNil() throws {
        let c      = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }
        let prekey = try onePrekey(for: c)

        let bundle = try crypto.encryptForwardSecret(
            message: Data("once".utf8), contactPrekey: prekey,
            recipientMaterial: recipientPub(), outboundBatch: nil
        )

        let first  = try decrypt(bundle: bundle, prekey: prekey)
        XCTAssertNotNil(first)

        let second = try decrypt(bundle: bundle, prekey: prekey)
        XCTAssertNil(second, "Consumed key must never decrypt again")
    }

    func test_decrypt_FS_nilPrekeyReturnsNil() throws {
        let c      = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }
        let prekey = try onePrekey(for: c)

        let bundle = try crypto.encryptForwardSecret(
            message: Data("test".utf8), contactPrekey: prekey,
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        let result = try decrypt(bundle: bundle, prekey: nil)
        XCTAssertNil(result)
    }

    // MARK: - deriveSessionKey + openBundle — fallback path

    func test_decrypt_fallback_batchEmbeddedInBundle() throws {
        let c     = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }
        let batch = OccultaBundle.PrekeySyncBatch(
            sequence: 3,
            prekeys: [Prekey(id: "R1", contactID: c, sequence: 3, publicKey: Data(count: 65))]
        )
        let bundle = try crypto.encryptForwardSecret(
            message: Data("fallback".utf8), contactPrekey: nil,
            recipientMaterial: recipientPub(), outboundBatch: batch
        )
        XCTAssertEqual(bundle.secrecy.prekeyBatch?.sequence,          3)
        XCTAssertEqual(bundle.secrecy.prekeyBatch?.prekeys.first?.id, "R1")
    }

    // MARK: - openBundle — tampered ciphertext

    func test_openBundle_tamperedCiphertext_throws() throws {
        let c      = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }
        let prekey = try onePrekey(for: c)

        let bundle = try crypto.encryptForwardSecret(
            message: Data("tamper".utf8), contactPrekey: prekey,
            recipientMaterial: recipientPub(), outboundBatch: nil
        )

        var tampered = bundle.ciphertext
        tampered[tampered.count / 2] ^= 0xFF

        let tamperedBundle = OccultaBundle(
            version:    bundle.version,
            secrecy:    bundle.secrecy,
            ciphertext: tampered
        )

        // Need a session key to call openBundle
        guard
            let privKey    = prekeyManager.retrievePrivateKey(for: prekey),
            let sessionKey = crypto.deriveSessionKey(
                ephemeralPrivateKey: privKey,
                recipientMaterial:   bundle.secrecy.ephemeralPublicKey
            )
        else {
            XCTFail("Could not derive session key for tamper test")
            return
        }
        prekeyManager.consume(prekey: prekey)   // privKey already out of guard scope

        XCTAssertThrowsError(
            try crypto.open(tamperedBundle, using: sessionKey),
            "Tampered ciphertext must fail GCM tag verification"
        )
    }

    // MARK: - Fingerprint

    func test_fingerprint_wrongKeyDoesNotMatch() throws {
        let c      = cid()
        defer { prekeyManager.deleteAllKeys(for: c) }
        let prekey = try onePrekey(for: c)

        let bundle = try crypto.encryptForwardSecret(
            message: Data("test".utf8), contactPrekey: prekey,
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        let candidate = OccultaBundle.SecrecyContext.fingerprint(
            for:   Data(repeating: 0x00, count: 65),
            nonce: bundle.secrecy.fingerprintNonce
        )
        XCTAssertNotEqual(candidate, bundle.secrecy.senderFingerprint)
    }
}

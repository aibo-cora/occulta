//
//  CryptoForwardSecrecyTests.swift
//  OccultaTests
//
//  Tests for Manager.Crypto forward-secret encryption and session key helpers.
//  Uses TestKeyManager — NO Secure Enclave during ECDH or AES-GCM.
//  PrekeyManager generates SE keys in test setup only.
//

import XCTest
import CryptoKit
@testable import Occulta

@MainActor
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
        crypto = nil; prekeyManager = nil; testKeyMgr = nil
        super.tearDown()
    }

    // MARK: - Helpers

    private func cid(function: String = #function) -> String { "crypto.\(function).\(UUID().uuidString)" }

    private func onePrekey(for cid: String) throws -> Prekey {
        try prekeyManager.generateBatch(contactID: cid, currentSequence: 0, count: 1).prekeys[0]
    }

    private func recipientPub() -> Data {
        let attrs: NSDictionary = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                                   kSecAttrKeySizeInBits: 256,
                                   kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]]
        var e: Unmanaged<CFError>?
        let priv = SecKeyCreateRandomKey(attrs, &e)!
        return SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(priv)!, nil)! as Data
    }

    // Decrypt helper — correct SecKey lifetime ordering
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
                return try crypto.openBundle(bundle, using: key)
            }()
            if result != nil, let pk = prekey { prekeyManager.consume(prekey: pk) }
            return result
        case .longTermFallback:
            guard let key = crypto.deriveSessionKey(using: bundle.secrecy.ephemeralPublicKey)
            else { return nil }
            return try crypto.openBundle(bundle, using: key)
        }
    }

    // MARK: - encryptForwardSecret — input validation (Finding 6)

    func test_encrypt_invalidRecipientMaterial_throws() throws {
        let c = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        XCTAssertThrowsError(
            try crypto.encryptForwardSecret(
                message: Data("test".utf8), contactPrekey: nil,
                recipientMaterial: Data(count: 32),   // wrong length: 32 not 65
                outboundBatch: nil
            ),
            "Wrong-length recipientMaterial must throw, not silently fall back"
        )
    }

    func test_encrypt_emptyRecipientMaterial_throws() throws {
        let c = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        XCTAssertThrowsError(
            try crypto.encryptForwardSecret(
                message: Data("test".utf8), contactPrekey: nil,
                recipientMaterial: Data(),
                outboundBatch: nil
            )
        )
    }

    func test_encrypt_invalidPrekeyPublicKeyLength_throws() throws {
        let c = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        // Construct a Prekey with a wrong-length public key (32 bytes instead of 65).
        // This simulates a malformed inbound batch entry.
        let badPrekey = Prekey(id: "bad", contactID: c, sequence: 0, publicKey: Data(count: 32))
        XCTAssertThrowsError(
            try crypto.encryptForwardSecret(
                message: Data("test".utf8), contactPrekey: badPrekey,
                recipientMaterial: recipientPub(), outboundBatch: nil
            ),
            "Wrong-length prekey publicKey must throw invalidPrekeyMaterial, not silently fall back"
        )
    }

    func test_encrypt_FS_doesNotSilentlyFallBack_onPrekeyECDHFailure() throws {
        // This test verifies the no-silent-degradation invariant:
        // if the caller provides a contactPrekey, any crypto failure throws
        // rather than silently producing a longTermFallback bundle.
        // We use a 65-byte all-zero key which is not a valid curve point
        // and will cause ECDH to fail.
        let c = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let invalidPrekey = Prekey(
            id: "invalid", contactID: c, sequence: 0,
            publicKey: Data(count: 65)   // all zeros — not a valid P-256 point
        )
        XCTAssertThrowsError(
            try crypto.encryptForwardSecret(
                message: Data("test".utf8), contactPrekey: invalidPrekey,
                recipientMaterial: recipientPub(), outboundBatch: nil
            ),
            "Invalid curve point must cause ECDH failure and throw, not fall back to longTermFallback"
        )
    }

    // MARK: - encryptForwardSecret — FS path

    func test_encrypt_FS_modeIsForwardSecret() throws {
        let c = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let bundle = try crypto.encryptForwardSecret(
            message: Data("test".utf8), contactPrekey: try onePrekey(for: c),
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        XCTAssertEqual(bundle.secrecy.mode, .forwardSecret)
    }

    func test_encrypt_FS_versionIsV3fs() throws {
        let c = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let bundle = try crypto.encryptForwardSecret(
            message: Data("test".utf8), contactPrekey: try onePrekey(for: c),
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        XCTAssertEqual(bundle.version, .v3fs)
    }

    func test_encrypt_FS_prekeyIDMatchesInput() throws {
        let c = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let prekey = try onePrekey(for: c)
        let bundle = try crypto.encryptForwardSecret(
            message: Data("test".utf8), contactPrekey: prekey,
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        XCTAssertEqual(bundle.secrecy.prekeyID,       prekey.id)
        XCTAssertEqual(bundle.secrecy.prekeySequence, prekey.sequence)
    }

    func test_encrypt_FS_ciphertextNonEmpty() throws {
        let c = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let bundle = try crypto.encryptForwardSecret(
            message: Data("hello".utf8), contactPrekey: try onePrekey(for: c),
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        XCTAssertFalse(bundle.ciphertext.isEmpty)
    }

    func test_encrypt_FS_fingerprintNonceIs16Bytes() throws {
        let c = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let bundle = try crypto.encryptForwardSecret(
            message: Data("test".utf8), contactPrekey: try onePrekey(for: c),
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        XCTAssertEqual(bundle.fingerprintNonce.count, 16)
    }

    func test_encrypt_FS_fingerprintMatchesOurKey() throws {
        let c = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let bundle = try crypto.encryptForwardSecret(
            message: Data("test".utf8), contactPrekey: try onePrekey(for: c),
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        let expected = OccultaBundle.SecrecyContext.fingerprint(
            for: try testKeyMgr.retrieveIdentity(), nonce: bundle.fingerprintNonce
        )
        XCTAssertEqual(bundle.senderFingerprint, expected)
    }

    func test_encrypt_FS_eachBundleUniqueNonce() throws {
        let c = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let (keys, _) = try prekeyManager.generateBatch(contactID: c, currentSequence: 0, count: 2)
        let recip     = recipientPub()
        let b1 = try crypto.encryptForwardSecret(
            message: Data("m1".utf8), contactPrekey: keys[0], recipientMaterial: recip, outboundBatch: nil
        )
        let b2 = try crypto.encryptForwardSecret(
            message: Data("m2".utf8), contactPrekey: keys[1], recipientMaterial: recip, outboundBatch: nil
        )
        XCTAssertNotEqual(b1.fingerprintNonce,  b2.fingerprintNonce)
        XCTAssertNotEqual(b1.senderFingerprint, b2.senderFingerprint)
    }

    // MARK: - encryptForwardSecret — fallback path

    func test_encrypt_fallback_modeIsLongTermFallback() throws {
        let c = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let bundle = try crypto.encryptForwardSecret(
            message: Data("fb".utf8), contactPrekey: nil,
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        XCTAssertEqual(bundle.secrecy.mode, .longTermFallback)
        XCTAssertNil(bundle.secrecy.prekeyID)
        XCTAssertNil(bundle.secrecy.prekeySequence)
    }

    func test_encrypt_fallback_outboundBatchPassedThrough() throws {
        let c = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let batch = OccultaBundle.PrekeySyncBatch(
            sequence: 5,
            prekeys: [Prekey(id: "P", contactID: c, sequence: 5, publicKey: Data(count: 65))]
        )
        let bundle = try crypto.encryptForwardSecret(
            message: Data("fb".utf8), contactPrekey: nil,
            recipientMaterial: recipientPub(), outboundBatch: batch
        )
        XCTAssertEqual(bundle.secrecy.prekeyBatch?.sequence, 5)
    }

    // MARK: - Decrypt + consume (⚠️ crash candidate)

    func test_decrypt_FS_roundtrip() throws {
        let c     = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let prekey = try onePrekey(for: c)
        let msg    = Data("round trip".utf8)
        let bundle = try crypto.encryptForwardSecret(
            message: msg, contactPrekey: prekey, recipientMaterial: recipientPub(), outboundBatch: nil
        )
        XCTAssertEqual(try decrypt(bundle: bundle, prekey: prekey), msg)
    }

    func test_decrypt_FS_consumesKeyAfterSuccessfulDecrypt() throws {
        let c     = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let prekey = try onePrekey(for: c)
        let bundle = try crypto.encryptForwardSecret(
            message: Data("secret".utf8), contactPrekey: prekey, recipientMaterial: recipientPub(), outboundBatch: nil
        )
        XCTAssertNotNil(prekeyManager.retrievePrivateKey(for: prekey))
        _ = try decrypt(bundle: bundle, prekey: prekey)
        XCTAssertNil(prekeyManager.retrievePrivateKey(for: prekey), "Key must be deleted after successful decrypt")
    }

    /// ⚠️ CRASH CANDIDATE — second call with consumed prekey must return nil, not crash.
    func test_decrypt_FS_duplicateDelivery_returnsNil() throws {
        let c     = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let prekey = try onePrekey(for: c)
        let bundle = try crypto.encryptForwardSecret(
            message: Data("once".utf8), contactPrekey: prekey, recipientMaterial: recipientPub(), outboundBatch: nil
        )
        let first  = try decrypt(bundle: bundle, prekey: prekey)
        XCTAssertNotNil(first)
        let second = try decrypt(bundle: bundle, prekey: prekey)
        XCTAssertNil(second, "Consumed key must never decrypt again")
    }

    func test_decrypt_FS_nilPrekeyReturnsNil() throws {
        let c     = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let prekey = try onePrekey(for: c)
        let bundle = try crypto.encryptForwardSecret(
            message: Data("test".utf8), contactPrekey: prekey, recipientMaterial: recipientPub(), outboundBatch: nil
        )
        XCTAssertNil(try decrypt(bundle: bundle, prekey: nil))
    }

    // MARK: - AAD tamper protection (Findings 2 & original prekey-batch attack)

    /// Finding 2: tampering version must fail GCM authentication.
    func test_openBundle_tamperedVersion_throws() throws {
        let c     = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let prekey = try onePrekey(for: c)
        let bundle = try crypto.encryptForwardSecret(
            message: Data("test".utf8), contactPrekey: prekey, recipientMaterial: recipientPub(), outboundBatch: nil
        )
        let tampered = OccultaBundle(
            version:           .v1,                     // flipped from v3fs
            secrecy:           bundle.secrecy,
            ciphertext:        bundle.ciphertext,
            fingerprintNonce:  bundle.fingerprintNonce,
            senderFingerprint: bundle.senderFingerprint
        )
        guard
            let priv = prekeyManager.retrievePrivateKey(for: prekey),
            let key  = crypto.deriveSessionKey(
                ephemeralPrivateKey: priv,
                recipientMaterial:   bundle.secrecy.ephemeralPublicKey
            )
        else { XCTFail("Key derivation failed"); return }
        prekeyManager.consume(prekey: prekey)
        XCTAssertThrowsError(try crypto.openBundle(tampered, using: key),
                             "Tampered version must fail GCM AAD verification")
    }

    /// The original prekey substitution attack: attacker replaces prekeyBatch with their own keys.
    func test_openBundle_tamperedPrekeyBatch_throws() throws {
        let c     = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let prekey = try onePrekey(for: c)
        let legitBatch = OccultaBundle.PrekeySyncBatch(
            sequence: 1,
            prekeys: [Prekey(id: "legit", contactID: c, sequence: 1, publicKey: Data(count: 65))]
        )
        let bundle = try crypto.encryptForwardSecret(
            message: Data("test".utf8), contactPrekey: prekey,
            recipientMaterial: recipientPub(), outboundBatch: legitBatch
        )
        let attackerBatch = OccultaBundle.PrekeySyncBatch(
            sequence: 1,
            prekeys: [Prekey(id: "attacker", contactID: c, sequence: 1, publicKey: Data(repeating: 0xAA, count: 65))]
        )
        let tampered = OccultaBundle(
            version: bundle.version,
            secrecy: OccultaBundle.SecrecyContext(
                mode: bundle.secrecy.mode,
                ephemeralPublicKey: bundle.secrecy.ephemeralPublicKey,
                prekeyID: bundle.secrecy.prekeyID,
                prekeySequence: bundle.secrecy.prekeySequence,
                prekeyBatch: attackerBatch          // substituted
            ),
            ciphertext:        bundle.ciphertext,
            fingerprintNonce:  bundle.fingerprintNonce,
            senderFingerprint: bundle.senderFingerprint
        )
        guard
            let priv = prekeyManager.retrievePrivateKey(for: prekey),
            let key  = crypto.deriveSessionKey(
                ephemeralPrivateKey: priv, recipientMaterial: bundle.secrecy.ephemeralPublicKey
            )
        else { XCTFail("Key derivation failed"); return }
        prekeyManager.consume(prekey: prekey)
        XCTAssertThrowsError(try crypto.openBundle(tampered, using: key),
                             "Substituted prekeyBatch must fail GCM AAD verification")
    }

    func test_openBundle_tamperedMode_throws() throws {
        let c     = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let prekey = try onePrekey(for: c)
        let bundle = try crypto.encryptForwardSecret(
            message: Data("test".utf8), contactPrekey: prekey,
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        let tampered = OccultaBundle(
            version: bundle.version,
            secrecy: OccultaBundle.SecrecyContext(
                mode: .longTermFallback,    // changed
                ephemeralPublicKey: bundle.secrecy.ephemeralPublicKey,
                prekeyID: bundle.secrecy.prekeyID, prekeySequence: bundle.secrecy.prekeySequence,
                prekeyBatch: bundle.secrecy.prekeyBatch
            ),
            ciphertext:        bundle.ciphertext,
            fingerprintNonce:  bundle.fingerprintNonce,
            senderFingerprint: bundle.senderFingerprint
        )
        guard
            let priv = prekeyManager.retrievePrivateKey(for: prekey),
            let key  = crypto.deriveSessionKey(
                ephemeralPrivateKey: priv, recipientMaterial: bundle.secrecy.ephemeralPublicKey
            )
        else { XCTFail("Key derivation failed"); return }
        prekeyManager.consume(prekey: prekey)
        XCTAssertThrowsError(try crypto.openBundle(tampered, using: key))
    }

    func test_openBundle_tamperedCiphertext_throws() throws {
        let c     = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let prekey = try onePrekey(for: c)
        let bundle = try crypto.encryptForwardSecret(
            message: Data("tamper".utf8), contactPrekey: prekey,
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        var tampered = bundle.ciphertext
        tampered[tampered.count / 2] ^= 0xFF
        let tamperedBundle = OccultaBundle(
            version: bundle.version, secrecy: bundle.secrecy,
            ciphertext: tampered, fingerprintNonce: bundle.fingerprintNonce,
            senderFingerprint: bundle.senderFingerprint
        )
        guard
            let priv = prekeyManager.retrievePrivateKey(for: prekey),
            let key  = crypto.deriveSessionKey(
                ephemeralPrivateKey: priv, recipientMaterial: bundle.secrecy.ephemeralPublicKey
            )
        else { XCTFail("Key derivation failed"); return }
        prekeyManager.consume(prekey: prekey)
        XCTAssertThrowsError(try crypto.openBundle(tamperedBundle, using: key))
    }

    // MARK: - Sender fingerprint

    func test_fingerprint_wrongKeyDoesNotMatch() throws {
        let c     = cid(); defer { prekeyManager.deleteAllKeys(for: c) }
        let prekey = try onePrekey(for: c)
        let bundle = try crypto.encryptForwardSecret(
            message: Data("test".utf8), contactPrekey: prekey,
            recipientMaterial: recipientPub(), outboundBatch: nil
        )
        prekeyManager.consume(prekey: prekey)
        let candidate = OccultaBundle.SecrecyContext.fingerprint(
            for: Data(repeating: 0x00, count: 65), nonce: bundle.fingerprintNonce
        )
        XCTAssertNotEqual(candidate, bundle.senderFingerprint)
    }
}

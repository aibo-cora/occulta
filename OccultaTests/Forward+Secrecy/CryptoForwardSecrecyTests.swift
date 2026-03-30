//
//  CryptoForwardSecrecyTests.swift
//  OccultaTests
//
//  Simulator safe — uses TestKeyManager (in-memory P-256, no SE).
//  Tests: seal, open, input validation, AAD tamper detection.
//

import Testing
import CryptoKit
import Security
import Foundation

@testable import Occulta

// MARK: - Helpers

/// Generate an in-memory P-256 key pair. Not stored anywhere.
private func ephemeralKeyPair() -> (privateKey: SecKey, publicKey: Data) {
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

// MARK: - seal — forward secret path

@Suite("Crypto — seal (forward secret)")
@MainActor struct CryptoSealFSTests {

    let senderKM   = TestKeyManager()
    let recipientKM = TestKeyManager()
    var crypto:      Manager.Crypto { .init(keyManager: senderKM) }
    var recipPub:    Data           { try! recipientKM.retrieveIdentity() }

    private func validPrekey() -> (prekey: Prekey, privateKey: SecKey) {
        let pair = ephemeralKeyPair()
        let pk   = Prekey(id: UUID().uuidString, contactID: "bob", publicKey: pair.publicKey)
        return (pk, pair.privateKey)
    }

    @Test func seal_FS_modeIsForwardSecret() throws {
        let (prekey, _) = validPrekey()
        let bundle = try crypto.seal(message: Data("test".utf8), contactPrekey: prekey, recipientMaterial: recipPub)
        #expect(bundle.secrecy.mode == .forwardSecret)
    }

    @Test func seal_FS_versionIsV3fs() throws {
        let (prekey, _) = validPrekey()
        let bundle = try crypto.seal(message: Data("test".utf8), contactPrekey: prekey, recipientMaterial: recipPub)
        #expect(bundle.version == .v3fs)
    }

    @Test func seal_FS_prekeyIDMatchesInput() throws {
        let (prekey, _) = validPrekey()
        let bundle = try crypto.seal(message: Data("test".utf8), contactPrekey: prekey, recipientMaterial: recipPub)
        #expect(bundle.secrecy.prekeyID == prekey.id)
    }

    @Test func seal_FS_ephemeralPublicKeyIs65Bytes() throws {
        let (prekey, _) = validPrekey()
        let bundle = try crypto.seal(message: Data("test".utf8), contactPrekey: prekey, recipientMaterial: recipPub)
        #expect(bundle.secrecy.ephemeralPublicKey.count == 65)
    }

    @Test func seal_FS_ciphertextNonEmpty() throws {
        let (prekey, _) = validPrekey()
        let bundle = try crypto.seal(message: Data("test".utf8), contactPrekey: prekey, recipientMaterial: recipPub)
        #expect(!bundle.ciphertext.isEmpty)
    }

    @Test func seal_FS_fingerprintNonceIs16Bytes() throws {
        let (prekey, _) = validPrekey()
        let bundle = try crypto.seal(message: Data("test".utf8), contactPrekey: prekey, recipientMaterial: recipPub)
        #expect(bundle.fingerprintNonce.count == 16)
    }

    @Test func seal_FS_senderFingerprintIs32Bytes() throws {
        let (prekey, _) = validPrekey()
        let bundle = try crypto.seal(message: Data("test".utf8), contactPrekey: prekey, recipientMaterial: recipPub)
        #expect(bundle.senderFingerprint.count == 32)
    }

    @Test func seal_FS_twoMessages_differentNonces() throws {
        let (prekey, _) = validPrekey()
        let b1 = try crypto.seal(message: Data("m1".utf8), contactPrekey: prekey, recipientMaterial: recipPub)
        let (prekey2, _) = validPrekey()
        let b2 = try crypto.seal(message: Data("m2".utf8), contactPrekey: prekey2, recipientMaterial: recipPub)
        #expect(b1.fingerprintNonce != b2.fingerprintNonce)
    }
}

// MARK: - seal — fallback path

@Suite("Crypto — seal (fallback)")
@MainActor struct CryptoSealFallbackTests {

    let senderKM    = TestKeyManager()
    let recipientKM = TestKeyManager()
    var crypto:      Manager.Crypto { .init(keyManager: senderKM) }
    var recipPub:    Data           { try! recipientKM.retrieveIdentity() }

    @Test func seal_fallback_modeIsLongTermFallback() throws {
        let bundle = try crypto.seal(message: Data("test".utf8), contactPrekey: nil, recipientMaterial: recipPub)
        #expect(bundle.secrecy.mode == .longTermFallback)
    }

    @Test func seal_fallback_prekeyIDIsNil() throws {
        let bundle = try crypto.seal(message: Data("test".utf8), contactPrekey: nil, recipientMaterial: recipPub)
        #expect(bundle.secrecy.prekeyID == nil)
    }

    @Test func seal_fallback_ephemeralPublicKeyIsEmpty() throws {
        // Recipient uses the stored sender identity key, not this field.
        let bundle = try crypto.seal(message: Data("test".utf8), contactPrekey: nil, recipientMaterial: recipPub)
        #expect(bundle.secrecy.ephemeralPublicKey.isEmpty)
    }
}

// MARK: - seal — input validation

@Suite("Crypto — seal (input validation)")
@MainActor struct CryptoSealValidationTests {

    let crypto: Manager.Crypto = .init(keyManager: TestKeyManager())
    let recipPub = ephemeralKeyPair().publicKey

    @Test func seal_shortRecipientMaterial_throwsInvalidRecipientMaterial() {
        #expect(throws: Manager.Crypto.EncryptionError.invalidRecipientMaterial) {
            try crypto.seal(message: Data("test".utf8), contactPrekey: nil, recipientMaterial: Data(count: 32))
        }
    }

    @Test func seal_emptyRecipientMaterial_throws() {
        #expect(throws: (any Error).self) {
            try crypto.seal(message: Data("test".utf8), contactPrekey: nil, recipientMaterial: Data())
        }
    }

    @Test func seal_shortPrekeyPublicKey_throwsInvalidPrekeyMaterial() {
        let badPrekey = Prekey(id: "x", contactID: "c", publicKey: Data(count: 32))
        #expect(throws: Manager.Crypto.EncryptionError.invalidPrekeyMaterial) {
            try crypto.seal(message: Data("test".utf8), contactPrekey: badPrekey, recipientMaterial: recipPub)
        }
    }

    @Test func seal_noSilentDegradation_invalidCurvePoint_throws() {
        // All-zero 65-byte key is not a valid P-256 curve point.
        // seal must throw, not silently produce a longTermFallback bundle.
        let badPrekey = Prekey(id: "x", contactID: "c", publicKey: Data(count: 65))
        #expect(throws: (any Error).self) {
            try crypto.seal(message: Data("test".utf8), contactPrekey: badPrekey, recipientMaterial: recipPub)
        }
    }
}

// MARK: - open — roundtrip

@Suite("Crypto — open (roundtrip)")
@MainActor struct CryptoOpenRoundtripTests {

    // Session key derivation for the FS roundtrip:
    //   seal:  ECDH(senderEphemeralPriv, prekeyPub)
    //   open:  ECDH(prekeyPriv, senderEphemeralPub)  → same result by commutativity
    //
    // We control the "prekey" key pair so we can reproduce the recipient's session key.

    @Test func open_FS_roundtrip() throws {
        let senderKM    = TestKeyManager()
        let recipientKM = TestKeyManager()
        let recipPub    = try recipientKM.retrieveIdentity()

        // Create a prekey where we control both sides
        let (prekeyPriv, prekeyPub) = ephemeralKeyPair()
        let prekey  = Prekey(id: "k1", contactID: "alice", publicKey: prekeyPub)

        // Sender seals: ECDH(senderEphemeral, prekeyPub)
        let message = Data("forward secret roundtrip".utf8)
        let payload = OccultaBundle.SealedPayload(message: message, prekeyBatch: nil)
        let encoded = try JSONEncoder().encode(payload)
        let bundle  = try Manager.Crypto(keyManager: senderKM).seal(
            message: encoded, contactPrekey: prekey, recipientMaterial: recipPub
        )
        #expect(bundle.secrecy.mode == .forwardSecret)

        // Recipient derives session key: ECDH(prekeyPriv, senderEphemeralPub)
        let sessKey = Manager.Crypto(keyManager: recipientKM).deriveSessionKey(
            ephemeralPrivateKey: prekeyPriv,
            recipientMaterial:   bundle.secrecy.ephemeralPublicKey
        )
        let raw     = try Manager.Crypto(keyManager: recipientKM).open(bundle, using: sessKey!)
        let decoded = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: raw)
        #expect(decoded.message == message)
    }

    @Test func open_fallback_roundtrip() throws {
        // Session key derivation for the fallback roundtrip:
        //   seal:  ECDH(senderPriv, recipientPub)
        //   open:  ECDH(recipientPriv, senderPub)  → same result by commutativity
        //
        // Both keys are in TestKeyManager instances, so we can access both public keys.

        let senderKM    = TestKeyManager()
        let recipientKM = TestKeyManager()
        let senderPub   = try senderKM.retrieveIdentity()
        let recipPub    = try recipientKM.retrieveIdentity()

        let message = Data("fallback roundtrip".utf8)
        let payload = OccultaBundle.SealedPayload(message: message, prekeyBatch: nil)
        let encoded = try JSONEncoder().encode(payload)
        let bundle  = try Manager.Crypto(keyManager: senderKM).seal(
            message: encoded, contactPrekey: nil, recipientMaterial: recipPub
        )
        #expect(bundle.secrecy.mode == .longTermFallback)

        // Recipient: ECDH(recipientPriv, senderPub) — matches ECDH(senderPriv, recipientPub)
        let sessKey = recipientKM.createSharedSecret(using: senderPub)!
        let raw     = try Manager.Crypto(keyManager: recipientKM).open(bundle, using: sessKey)
        let decoded = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: raw)
        #expect(decoded.message == message)
    }

    @Test func open_sealedPayload_batchPreserved() throws {
        let senderKM    = TestKeyManager()
        let recipientKM = TestKeyManager()
        let recipPub    = try recipientKM.retrieveIdentity()

        let (prekeyPriv, prekeyPub) = ephemeralKeyPair()
        let prekey = Prekey(id: "k1", contactID: "alice", publicKey: prekeyPub)

        let batch = OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Date(timeIntervalSince1970: 1_700_000_000),
            prekeys:     [OccultaBundle.WirePrekey(id: "pk1", publicKey: Data(repeating: 0x04, count: 65))]
        )
        let payload = OccultaBundle.SealedPayload(message: Data("msg".utf8), prekeyBatch: batch)
        let encoded = try JSONEncoder().encode(payload)
        let bundle  = try Manager.Crypto(keyManager: senderKM).seal(
            message: encoded, contactPrekey: prekey, recipientMaterial: recipPub
        )

        let sessKey = Manager.Crypto(keyManager: recipientKM).deriveSessionKey(
            ephemeralPrivateKey: prekeyPriv,
            recipientMaterial:   bundle.secrecy.ephemeralPublicKey
        )!
        let raw     = try Manager.Crypto(keyManager: recipientKM).open(bundle, using: sessKey)
        let decoded = try JSONDecoder().decode(OccultaBundle.SealedPayload.self, from: raw)
        #expect(decoded.prekeyBatch?.prekeys.first?.id == "pk1")
    }
}

// MARK: - open — AAD tamper detection

@Suite("Crypto — open (tamper detection)")
@MainActor struct CryptoOpenTamperTests {

    /// Returns a valid FS bundle and the matching session key for the recipient.
    private func sealed() throws -> (bundle: OccultaBundle, sessionKey: SymmetricKey) {
        let senderKM    = TestKeyManager()
        let recipientKM = TestKeyManager()
        let recipPub    = try recipientKM.retrieveIdentity()

        let (prekeyPriv, prekeyPub) = ephemeralKeyPair()
        let prekey  = Prekey(id: "k1", contactID: "c", publicKey: prekeyPub)
        let payload = OccultaBundle.SealedPayload(message: Data("test".utf8), prekeyBatch: nil)
        let encoded = try JSONEncoder().encode(payload)
        let bundle  = try Manager.Crypto(keyManager: senderKM).seal(
            message: encoded, contactPrekey: prekey, recipientMaterial: recipPub
        )
        let sessKey = Manager.Crypto(keyManager: recipientKM).deriveSessionKey(
            ephemeralPrivateKey: prekeyPriv,
            recipientMaterial:   bundle.secrecy.ephemeralPublicKey
        )!
        return (bundle, sessKey)
    }

    private let recipientCrypto = Manager.Crypto(keyManager: TestKeyManager())

    @Test func tamper_version_throwsAuthFailure() throws {
        let (bundle, key) = try sealed()
        let tampered = OccultaBundle(
            version:           .v1,
            secrecy:           bundle.secrecy,
            ciphertext:        bundle.ciphertext,
            fingerprintNonce:  bundle.fingerprintNonce,
            senderFingerprint: bundle.senderFingerprint
        )
        #expect(throws: (any Error).self) { try recipientCrypto.open(tampered, using: key) }
    }

    @Test func tamper_mode_throwsAuthFailure() throws {
        let (bundle, key) = try sealed()
        let tampered = OccultaBundle(
            version: bundle.version,
            secrecy: OccultaBundle.SecrecyContext(
                mode: .longTermFallback, ephemeralPublicKey: bundle.secrecy.ephemeralPublicKey, prekeyID: bundle.secrecy.prekeyID
            ),
            ciphertext:        bundle.ciphertext,
            fingerprintNonce:  bundle.fingerprintNonce,
            senderFingerprint: bundle.senderFingerprint
        )
        #expect(throws: (any Error).self) { try recipientCrypto.open(tampered, using: key) }
    }

    @Test func tamper_prekeyID_throwsAuthFailure() throws {
        let (bundle, key) = try sealed()
        let tampered = OccultaBundle(
            version: bundle.version,
            secrecy: OccultaBundle.SecrecyContext(
                mode: bundle.secrecy.mode, ephemeralPublicKey: bundle.secrecy.ephemeralPublicKey, prekeyID: "attacker-id"
            ),
            ciphertext:        bundle.ciphertext,
            fingerprintNonce:  bundle.fingerprintNonce,
            senderFingerprint: bundle.senderFingerprint
        )
        #expect(throws: (any Error).self) { try recipientCrypto.open(tampered, using: key) }
    }

    @Test func tamper_ciphertext_throwsAuthFailure() throws {
        let (bundle, key) = try sealed()
        var bad = bundle.ciphertext; bad[bad.count / 2] ^= 0xFF
        let tampered = OccultaBundle(
            version:           bundle.version,
            secrecy:           bundle.secrecy,
            ciphertext:        bad,
            fingerprintNonce:  bundle.fingerprintNonce,
            senderFingerprint: bundle.senderFingerprint
        )
        #expect(throws: (any Error).self) { try recipientCrypto.open(tampered, using: key) }
    }

    @Test func tamper_ephemeralPublicKey_throwsAuthFailure() throws {
        let (bundle, key) = try sealed()
        let tampered = OccultaBundle(
            version: bundle.version,
            secrecy: OccultaBundle.SecrecyContext(
                mode: bundle.secrecy.mode, ephemeralPublicKey: Data(repeating: 0xAB, count: 65), prekeyID: bundle.secrecy.prekeyID
            ),
            ciphertext:        bundle.ciphertext,
            fingerprintNonce:  bundle.fingerprintNonce,
            senderFingerprint: bundle.senderFingerprint
        )
        #expect(throws: (any Error).self) { try recipientCrypto.open(tampered, using: key) }
    }

    @Test func fingerprintNonce_notInAAD_tamperDoesNotAffectDecryption() throws {
        // fingerprintNonce is routing metadata — not in AAD. Tamper must not break open.
        let (bundle, key) = try sealed()
        let tampered = OccultaBundle(
            version:           bundle.version,
            secrecy:           bundle.secrecy,
            ciphertext:        bundle.ciphertext,
            fingerprintNonce:  Data(repeating: 0xFF, count: 16),
            senderFingerprint: bundle.senderFingerprint
        )
        #expect(throws: Never.self) { try recipientCrypto.open(tampered, using: key) }
    }
}

// MARK: - Sender fingerprint

@Suite("Crypto — Sender fingerprint")
@MainActor struct CryptoFingerprintTests {

    @Test func senderFingerprint_matchesExpectedValue() throws {
        let km     = TestKeyManager()
        let ourPub = try km.retrieveIdentity()
        let recip  = ephemeralKeyPair().publicKey
        let bundle = try Manager.Crypto(keyManager: km).seal(
            message: Data("x".utf8), contactPrekey: nil, recipientMaterial: recip
        )
        let expected = OccultaBundle.SecrecyContext.fingerprint(for: ourPub, nonce: bundle.fingerprintNonce)
        #expect(bundle.senderFingerprint == expected)
    }

    @Test func senderFingerprint_wrongKey_doesNotMatch() throws {
        let km     = TestKeyManager()
        let bundle = try Manager.Crypto(keyManager: km).seal(
            message: Data("x".utf8), contactPrekey: nil, recipientMaterial: ephemeralKeyPair().publicKey
        )
        let wrongFP = OccultaBundle.SecrecyContext.fingerprint(
            for: Data(repeating: 0x00, count: 65), nonce: bundle.fingerprintNonce
        )
        #expect(wrongFP != bundle.senderFingerprint)
    }
}

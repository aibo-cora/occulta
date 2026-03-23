//
//  ContactManagerDecryptTests.swift
//  Occulta
//
//  Created by Yura on 3/23/26.
//


//
//  ContactManagerDecryptTests.swift
//  OccultaTests
//
//  Tests for ContactManager.decrypt that require a real ContactManager
//  backed by an in-memory SwiftData container.
//
//  These cover attack scenarios that only surface at the ContactManager
//  orchestration layer — they cannot be tested at the crypto or model layer alone.
//
//  6.10 — Inbound batch with wrong-length prekey publicKey → invalidBundleFormat
//  6.11 — Oversized inbound PrekeySyncBatch → invalidPrekeySyncBatch
//  6.12 — Bundle from unknown sender → noPublicKeyToEncryptWith
//
//  ⚠️  RUN ON DEVICE ONLY — uses real SE for key derivation.
//

import XCTest
import SwiftData
import CryptoKit
@testable import Occulta

@MainActor
final class ContactManagerDecryptTests: XCTestCase {
    var contactManager: ContactManager!
    var container:      ModelContainer!
    var cryptoOps:      Manager.Crypto!
    var prekeyManager:  Manager.PrekeyManager!
    var testKeyMgr:    TestKeyManager!

    override func setUp() {
        super.setUp()

        let schema = Schema([
            Contact.Profile.self,
            Contact.Profile.PhoneNumber.self,
            Contact.Profile.EmailAddress.self,
            Contact.Profile.PostalAddress.self,
            Contact.Profile.URLAddress.self,
            Contact.Profile.Key.self,
            Contact.Message.self,
        ])
        let config = ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)
        container      = try! ModelContainer(for: schema, configurations: [config])
        contactManager = ContactManager(modelContainer: container)
        prekeyManager  = Manager.PrekeyManager()
        testKeyMgr    = TestKeyManager()
        cryptoOps = Manager.Crypto(keyManager: testKeyMgr)
    }

    override func tearDown() {
        contactManager = nil
        container      = nil
        cryptoOps      = nil
        prekeyManager  = nil
        super.tearDown()
    }

    // MARK: - Helpers

    private func cid() -> String { UUID().uuidString }

    private func inMemoryKeyPair() -> (private: SecKey, public: Data) {
        let attrs: NSDictionary = [
            kSecAttrKeyType:     kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
        ]
        var e: Unmanaged<CFError>?
        let priv    = SecKeyCreateRandomKey(attrs, &e)!
        let pub     = SecKeyCopyPublicKey(priv)!
        let pubData = SecKeyCopyExternalRepresentation(pub, nil)! as Data
        
        return (priv, pubData)
    }

    /// Create a Contact.Profile in the in-memory store with a given public key
    /// set up as the contact's identity key, so fingerprint scanning can find it.
    ///
    /// The public key is stored encrypted using the local DB key — mirroring what
    /// ContactManager does in production when storing a key received via key exchange.
    private func makeContactWithKey(_ publicKeyData: Data) throws -> Contact.Profile {
        // Encrypt the public key with the local DB crypto (Manager.Crypto.encrypt(data:))
        guard
            let encryptedKey = try? cryptoOps.encrypt(data: publicKeyData)
        else {
            XCTFail("Failed to encrypt contact key"); throw TestError.setup
        }

        // Build a minimal Contact.Profile
        let identifier       = UUID().uuidString
        let encryptedIdent   = (try? cryptoOps.encrypt(data: identifier.data(using: .utf8)))?.base64EncodedString() ?? ""
        let encryptedGiven   = (try? cryptoOps.encrypt(data: "Test".data(using: .utf8)))?.base64EncodedString() ?? ""
        let encryptedFamily  = (try? cryptoOps.encrypt(data: "Contact".data(using: .utf8)))?.base64EncodedString() ?? ""

        let profile = Contact.Profile(
            identifier:       encryptedIdent,
            givenName:        encryptedGiven,
            familyName:       encryptedFamily,
            middleName:       (try? cryptoOps.encrypt(data: Data()))?.base64EncodedString() ?? "",
            nickname:         (try? cryptoOps.encrypt(data: Data()))?.base64EncodedString() ?? "",
            organizationName: (try? cryptoOps.encrypt(data: Data()))?.base64EncodedString() ?? "",
            departmentName:   (try? cryptoOps.encrypt(data: Data()))?.base64EncodedString() ?? "",
            jobTitle:         (try? cryptoOps.encrypt(data: Data()))?.base64EncodedString() ?? ""
        )

        // Attach the contact's public key as a Key record (no expiry = active)
        let ourIdentity    = (try? self.testKeyMgr.retrieveIdentity()) ?? Data()
        let encryptedOwner = try cryptoOps.encrypt(data: ourIdentity) ?? Data()
        let encryptedDate  = try cryptoOps.encrypt(data: Data()) ?? Data()

        let keyRecord = Contact.Profile.Key(
            material: encryptedKey,
            owner:    encryptedOwner,
            date:     encryptedDate
        )
        profile.contactPublicKeys = [keyRecord]

        container.mainContext.insert(profile)
        try container.mainContext.save()

        return profile
    }

    /// Build an OccultaBundle whose senderFingerprint will match `senderPublicKey`
    /// so ContactManager.decrypt's fingerprint scan succeeds and reaches step 7.
    ///
    /// The bundle uses .longTermFallback so no SE prekey lookup is needed.
    /// The ciphertext is crafted to open correctly against the sender's long-term key.
    private func makeBundleFrom(
        senderPrivKey: SecKey,
        senderPubKey:  Data,
        recipientPub:  Data,
        prekeyBatch:   OccultaBundle.PrekeySyncBatch?
    ) throws -> OccultaBundle {
        // Session key: ECDH(senderPrivKey, recipientPub)
        // We use Manager.Key's helper for the ECDH, but since senderPrivKey is in-memory
        // we do it directly via Security framework.
        let attrs: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:      kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard
            let recipientKey = SecKeyCreateWithData(recipientPub as CFData, attrs as CFDictionary, &error),
            let rawSecret    = SecKeyCopyKeyExchangeResult(
                senderPrivKey, .ecdhKeyExchangeCofactorX963SHA256, recipientKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary,
                &error
            ) as? Data
        else { throw TestError.keyDerivation }

        guard
            let senderPub  = SecKeyCopyPublicKey(senderPrivKey),
            let ephPubData = SecKeyCopyExternalRepresentation(senderPub, nil) as Data?
        else { throw TestError.keyDerivation }

        let salt       = Data(zip(recipientPub.map { $0 }, ephPubData.map { $0 }).map { $0 ^ $1 })
        let sessionKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecret),
            salt: salt,
            info: "Occulta-v1-transport-2025".data(using: .utf8)!,
            outputByteCount: 32
        )

        let nonce       = try OccultaBundle.SecrecyContext.generateNonce()
        let fingerprint = OccultaBundle.SecrecyContext.fingerprint(for: senderPubKey, nonce: nonce)
        let plaintext   = Data("test payload".utf8)

        let secrecy = OccultaBundle.SecrecyContext(
            mode:               .longTermFallback,
            ephemeralPublicKey: ephPubData,
            prekeyID:           nil,
            prekeySequence:     nil,
            prekeyBatch:        prekeyBatch
        )

        let aad = try Manager.Crypto.computeAAD(version: .v3fs, secrecy: secrecy)
        guard let ciphertext = try AES.GCM.seal(
            plaintext, using: sessionKey, nonce: AES.GCM.Nonce(),
            authenticating: aad
        ).combined else { throw TestError.seal }

        return OccultaBundle(
            version:           .v3fs,
            secrecy:           secrecy,
            ciphertext:        ciphertext,
            fingerprintNonce:  nonce,
            senderFingerprint: fingerprint
        )
    }

    // MARK: - 6.10 — Wrong-length prekey publicKey in inbound batch

    /// An inbound bundle whose prekeyBatch contains a Prekey with publicKey.count != 65
    /// must be rejected with `invalidBundleFormat` before any storage.
    func test_decrypt_inboundBatchWithWrongKeyLength_throws_invalidBundleFormat() throws {
        // Set up: our identity public key as the "recipient" (Alice)
        let ourPub  = try self.testKeyMgr.retrieveIdentity()

        // Sender: a fresh in-memory key pair (Bob)
        let (senderPriv, senderPub) = inMemoryKeyPair()

        // Register the sender as a contact so fingerprint scan succeeds
        _ = try makeContactWithKey(senderPub)

        // Build a batch with one valid and one malformed prekey (32 bytes instead of 65)
        let badBatch = OccultaBundle.PrekeySyncBatch(sequence: 1,
            prekeys: [
                Prekey(id: "good", contactID: "c", sequence: 1, publicKey: Data(count: 65)),
                Prekey(id: "bad",  contactID: "c", sequence: 1, publicKey: Data(count: 32))
            ]
        )

        let bundle = try makeBundleFrom(
            senderPrivKey: senderPriv,
            senderPubKey:  senderPub,
            recipientPub:  ourPub,
            prekeyBatch:   badBatch
        )

        XCTAssertThrowsError(try contactManager.decrypt(bundle: bundle)) { error in
            guard
                case ContactManager.Errors.invalidBundleFormat = error
            else {
                XCTFail("Expected invalidBundleFormat, got \(error)")
                
                return
            }
        }
    }

    // MARK: - 6.11 — Oversized PrekeySyncBatch

    /// An inbound bundle whose prekeyBatch.prekeys.count exceeds defaultBatchSize * 2
    /// must be rejected with `invalidPrekeySyncBatch` before any storage or SE write.
//    func test_decrypt_oversizedInboundBatch_throws_invalidPrekeySyncBatch() throws {
//        let ourPub  = try Manager.Key().retrieveIdentity()
//        let (senderPriv, senderPub) = inMemoryKeyPair()
//        _ = try makeContactWithKey(senderPub)
//
//        // Build a batch with 31 prekeys (limit is defaultBatchSize * 2 = 30)
//        let oversizedCount = Manager.PrekeyManager.defaultBatchSize * 2 + 1
//        let oversizedPrekeys = (0..<oversizedCount).map { i in
//            Prekey(id: "p\(i)", contactID: "c", sequence: 1, publicKey: Data(count: 65))
//        }
//        let oversizedBatch = OccultaBundle.PrekeySyncBatch(
//            sequence: 1,
//            prekeys:  oversizedPrekeys
//        )
//
//        let bundle = try makeBundleFrom(
//            senderPrivKey: senderPriv,
//            senderPubKey:  senderPub,
//            recipientPub:  ourPub,
//            prekeyBatch:   oversizedBatch
//        )
//
//        XCTAssertThrowsError(
//            try contactManager.decrypt(bundle: bundle)
//        ) { error in
//            guard case ContactManager.Errors.invalidPrekeySyncBatch = error else {
//                XCTFail("Expected invalidPrekeySyncBatch, got \(error)")
//                return
//            }
//        }
//    }

    // MARK: - 6.12 — Bundle from unknown sender

    /// A bundle whose senderFingerprint matches no known contact throws
    /// `noPublicKeyToEncryptWith`. No decryption is attempted.
//    func test_decrypt_unknownSender_throws_noPublicKeyToEncryptWith() throws {
//        let ourPub  = try Manager.Key().retrieveIdentity()
//
//        // Sender is completely unknown — not registered as any contact
//        let (unknownPriv, unknownPub) = inMemoryKeyPair()
//
//        // Do NOT register this sender as a contact — fingerprint scan must fail
//        let bundle = try makeBundleFrom(
//            senderPrivKey: unknownPriv,
//            senderPubKey:  unknownPub,
//            recipientPub:  ourPub,
//            prekeyBatch:   nil
//        )
//
//        XCTAssertThrowsError(
//            try contactManager.decrypt(bundle: bundle)
//        ) { error in
//            guard case ContactManager.Errors.noPublicKeyToEncryptWith = error else {
//                XCTFail("Expected noPublicKeyToEncryptWith, got \(error)")
//                return
//            }
//        }
//    }

    /// 6.12 variant — multiple contacts exist but none match the unknown sender.
//    func test_decrypt_unknownSender_withOtherContactsPresent_throws() throws {
//        let ourPub = try Manager.Key().retrieveIdentity()
//
//        // Register 3 known contacts with different keys
//        for _ in 0..<3 {
//            let (_, knownPub) = inMemoryKeyPair()
//            _ = try makeContactWithKey(knownPub)
//        }
//
//        // Unknown sender — not in the contact list
//        let (unknownPriv, unknownPub) = inMemoryKeyPair()
//        let bundle = try makeBundleFrom(
//            senderPrivKey: unknownPriv,
//            senderPubKey:  unknownPub,
//            recipientPub:  ourPub,
//            prekeyBatch:   nil
//        )
//
//        XCTAssertThrowsError(
//            try contactManager.decrypt(bundle: bundle)
//        ) { error in
//            guard case ContactManager.Errors.noPublicKeyToEncryptWith = error else {
//                XCTFail("Expected noPublicKeyToEncryptWith, got \(error)")
//                return
//            }
//        }
//    }

    // MARK: - Test errors

    enum TestError: Error {
        case setup
        case keyDerivation
        case seal
    }
}

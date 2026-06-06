//
//  DuressModePrekeyTests.swift
//  OccultaTests
//
//  Regression guard for the duress-mode prekey consumption bug.
//
//  Before the fix, buildOwnedBasket called decryptSealed (which consumes the
//  prekey on successful decryption) before passSecurityControl. Opening a
//  bundle from a sensitive contact in duress mode popped the prekey and then
//  threw — leaving the bundle unopenable on the next attempt in normal mode.
//
//  The fix calls identifyOwner(of:) first — a pure fingerprint lookup that
//  never touches prekeys — and only reaches decryptSealed when the security
//  check passes. These tests verify both halves of that invariant.
//
//  Coverage:
//    - identifyOwner(of:) does not consume prekeys when no contact matches
//    - identifyOwner(of:) does not consume prekeys when the contact IS found (device only)
//    - isSafeContact returns false for a sensitive contact in duress mode
//

import Testing
import CryptoKit
import Foundation
import Security
import SwiftData
@testable import Occulta

// MARK: - Helpers

private func makeSenderKeyPair() -> (privateKey: SecKey, publicKey: Data) {
    let attrs: NSDictionary = [
        kSecAttrKeyType:       kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits: 256,
        kSecPrivateKeyAttrs:   [kSecAttrIsPermanent: false]
    ]
    var err: Unmanaged<CFError>?
    let priv = SecKeyCreateRandomKey(attrs, &err)!
    let pub  = SecKeyCopyPublicKey(priv)!
    return (priv, SecKeyCopyExternalRepresentation(pub, nil)! as Data)
}

/// Minimal schema for contact-only operations.
private func makeContactContainer() throws -> ModelContainer {
    let schema = Schema([Contact.Profile.self, Contact.Profile.Key.self])
    return try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
}

/// Full schema required by Manager.Security.
private func makeSecurityContainer() throws -> ModelContainer {
    let schema = Schema([
        AppLayerConfig.self,
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
        VaultEntry.self,
    ])
    return try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
}

// MARK: - Suite

@Suite("Secure Mode — duress prekey protection")
@MainActor struct DuressModePrekeyTests {

    let pm     = Manager.PrekeyManager()
    let crypto = Manager.Crypto(keyManager: TestKeyManager())

    // MARK: identifyOwner prekey safety

    /// identifyOwner(of:) must not consume prekeys when no contact matches the
    /// bundle fingerprint. If someone accidentally moves consume() into the
    /// identification path, the remaining count would drop and this test breaks.
    @Test func identifyOwner_isPrekeySafe_noMatch() throws {
        let contactID = "duress.noMatch.\(UUID().uuidString)"
        defer { pm.deleteAllKeys(for: contactID) }

        let prekeys       = try pm.generateBatch(contactID: contactID, count: 1)
        let prekey        = prekeys[0]
        let (_, recipPub) = makeSenderKeyPair()

        let payload = OccultaBundle.SealedPayload(message: Data("test".utf8), prekeyBatch: nil)
        let bundle  = try crypto.seal(
            message:           try JSONEncoder().encode(payload),
            contactPrekey:     prekey,
            recipientMaterial: recipPub
        )

        let contacts = ContactManager(modelContainer: try makeContactContainer())
        let before   = pm.remainingCount(for: contactID)

        _ = try? contacts.identifyOwner(of: bundle)   // throws — no contact matches

        #expect(pm.remainingCount(for: contactID) == before,
                "identifyOwner must not consume prekeys when no contact matches")
    }

    /// Same invariant when a contact IS fingerprint-matched. This is the
    /// critical path — consume() must only fire inside decryptSealed, never
    /// during identification alone. Device only: requires SE for field encryption.
    @Test func identifyOwner_isPrekeySafe_withMatchingContact() throws {
        let contactID = "duress.match.\(UUID().uuidString)"
        defer { pm.deleteAllKeys(for: contactID) }

        let (_, senderPub) = makeSenderKeyPair()

        // Encrypt the sender's public key for DB storage.
        // Returns nil on the simulator (no SE) — graceful skip.
        let realCrypto = Manager.Crypto()
        guard let encryptedPub = try realCrypto.encrypt(data: senderPub) else { return }

        // Insert a contact whose stored public key matches the bundle fingerprint.
        let container = try makeContactContainer()
        let ctx       = ModelContext(container)
        let profile   = Contact.Profile(
            identifier:       UUID().uuidString,
            givenName:        "",
            familyName:       "",
            middleName:       "",
            nickname:         "",
            organizationName: "",
            departmentName:   "",
            jobTitle:         ""
        )
        let keyRecord = Contact.Profile.Key(material: encryptedPub, owner: Data(), date: Data())
        profile.contactPublicKeys = [keyRecord]
        ctx.insert(profile)
        try ctx.save()

        // Build a bundle that fingerprint-matches the contact.
        // The ciphertext is garbage — decryptSealed will fail, but identification succeeds.
        let nonce       = try OccultaBundle.SecrecyContext.generateNonce()
        let fingerprint = OccultaBundle.SecrecyContext.fingerprint(for: senderPub, nonce: nonce)
        let prekeys     = try pm.generateBatch(contactID: contactID, count: 1)
        let prekey      = prekeys[0]

        let bundle = OccultaBundle(
            version: .v3fs,
            secrecy: OccultaBundle.SecrecyContext(
                mode:               .forwardSecret,
                ephemeralPublicKey: senderPub,
                prekeyID:           prekey.id
            ),
            ciphertext:        Data(repeating: 0, count: 32),
            fingerprintNonce:  nonce,
            senderFingerprint: fingerprint
        )

        let contacts = ContactManager(modelContainer: container)
        let before   = pm.remainingCount(for: contactID)

        _ = try? contacts.identifyOwner(of: bundle)   // succeeds, then returns ownerID

        #expect(pm.remainingCount(for: contactID) == before,
                "identifyOwner must not consume prekeys even when the contact fingerprint matches")
    }

    // MARK: isSafeContact blocks sensitive contacts in duress

    /// A contact with a non-decryptable visibleThroughDepth is treated as
    /// sensitive (isVisible returns false for the conservative exclusion path).
    /// In duress mode, isSafeContact must return false — this is what causes
    /// passSecurityControl to throw before decryptSealed is ever called.
    @Test func isSafeContact_sensitiveContact_blockedInDuress() throws {
        let container  = try makeSecurityContainer()
        let security   = Manager.Security(modelContainer: container, keyManager: TestKeyManager())

        let identifier = UUID().uuidString
        let ctx        = ModelContext(container)
        let profile    = Contact.Profile(
            identifier:       identifier,
            givenName:        "",
            familyName:       "",
            middleName:       "",
            nickname:         "",
            organizationName: "",
            departmentName:   "",
            jobTitle:         ""
        )
        // Non-nil, non-decryptable field: decrypt() returns nil → isVisible returns false.
        profile.visibleThroughDepth = Data([0xFF, 0xFE])
        ctx.insert(profile)
        try ctx.save()

        security.applyVerifyState(for: .duress)

        #expect(security.isRestricted,
                "applyVerifyState(.duress) must set isRestricted")
        #expect(
            security.isSafeContact(identifier) == false,
            "sensitive contact must not pass isSafeContact in duress mode"
        )
    }
}

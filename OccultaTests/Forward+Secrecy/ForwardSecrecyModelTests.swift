//
//  ForwardSecrecyModelTests.swift
//  OccultaTests
//
//  Tests Contact.Profile.isLikelySender in isolation. The prekey methods this file used to cover
//  moved off Contact.Profile in prekey continuity stage 1; their rules are PrekeyBookkeeper's
//  (PrekeyBookkeeperTests) and their wiring ContactManager's (PrekeyReplenishmentTriggerTests).
//

import Testing
import SwiftData
import Foundation

@testable import Occulta
@testable import OccultaFormats


// MARK: - Shared helpers

private func makeContainer() throws -> ModelContainer {
    let schema = Schema([
        Contact.Profile.self,
        Contact.Profile.Key.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
    ])
    return try ModelContainer(
        for: schema,
        configurations: ModelConfiguration(isStoredInMemoryOnly: true)
    )
}

private func makeContact(in context: ModelContext) throws -> Contact.Profile {
    let c = Contact.Profile(
        identifier:       UUID().uuidString,
        givenName:        "Test",
        familyName:       "Contact",
        middleName:       "",
        nickname:         "",
        organizationName: "",
        departmentName:   "",
        jobTitle:         ""
    )
    context.insert(c)
    try context.save()
    return c
}

// MARK: - isLikelySender

@Suite("ForwardSecrecyModel — isLikelySender")
struct IsLikelySenderTests {

    private func bundle(nonce: Data, fingerprint: Data) -> OccultaBundle {
        OccultaBundle(
            version:           .v3fs,
            secrecy:           OccultaBundle.SecrecyContext(
                mode: .longTermFallback, ephemeralPublicKey: Data(), prekeyID: nil
            ),
            ciphertext:        Data(count: 28),
            fingerprintNonce:  nonce,
            senderFingerprint: fingerprint
        )
    }

    @Test func isLikelySender_trueForMatchingKeyAndNonce() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)

        let pubKey = Data(repeating: 0x42, count: 65)
        let nonce  = try OccultaBundle.SecrecyContext.generateNonce()
        let fp     = OccultaBundle.SecrecyContext.fingerprint(for: pubKey, nonce: nonce)

        #expect(contact.isLikelySender(of: bundle(nonce: nonce, fingerprint: fp), contactPublicKey: pubKey))
    }

    @Test func isLikelySender_falseForWrongPublicKey() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)

        let key1  = Data(repeating: 0x42, count: 65)
        let key2  = Data(repeating: 0x43, count: 65)
        let nonce = try OccultaBundle.SecrecyContext.generateNonce()
        let fp    = OccultaBundle.SecrecyContext.fingerprint(for: key1, nonce: nonce)

        #expect(!contact.isLikelySender(of: bundle(nonce: nonce, fingerprint: fp), contactPublicKey: key2))
    }

    @Test func isLikelySender_falseForWrongNonce() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)

        let pubKey = Data(repeating: 0x42, count: 65)
        let fp     = OccultaBundle.SecrecyContext.fingerprint(
            for: pubKey, nonce: Data(repeating: 0x01, count: 16)
        )
        #expect(!contact.isLikelySender(
            of: bundle(nonce: Data(repeating: 0x02, count: 16), fingerprint: fp),
            contactPublicKey: pubKey
        ))
    }

    @Test func isLikelySender_falseForTamperedFingerprint() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)

        let pubKey = Data(repeating: 0x42, count: 65)
        let nonce  = try OccultaBundle.SecrecyContext.generateNonce()

        // Correct nonce but wrong fingerprint
        #expect(!contact.isLikelySender(
            of: bundle(nonce: nonce, fingerprint: Data(repeating: 0xAB, count: 32)),
            contactPublicKey: pubKey
        ))
    }
}

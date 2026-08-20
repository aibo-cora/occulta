//
//  MigrateToV2ResilienceTests.swift
//  OccultaTests
//
//  Bug 89 — one unmigratable contact must not block the rest, and a failed contact must
//  leave no field changed.
//
//  Needs no Secure Enclave: `migrateToV2` takes its legacy and new crypto as parameters,
//  so both can be stubbed.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta

// MARK: - Stubs

/// Legacy crypto that decrypts with a fixed key, and *throws* on anything it cannot
/// authenticate — which is the real behaviour: `authenticationFailure` comes out of
/// AES-GCM, it is not a nil return. That distinction is the whole of Bug 89's diagnostic.
private struct StubCrypto: CryptoProtocol {
    let key: SymmetricKey
    static let aad = EncryptionScheme.v2_hybridPQ.aad

    func seal(_ text: String) -> String {
        let sealed = try! AES.GCM.seal(Data(text.utf8), using: self.key, authenticating: Self.aad)
        return sealed.combined!.base64EncodedString()
    }

    func encrypt(data: Data?) throws -> Data? {
        guard let data else { return nil }
        return try AES.GCM.seal(data, using: self.key, authenticating: Self.aad).combined
    }

    func decrypt(data: Data?) throws -> Data? {
        guard let data else { return nil }
        return try AES.GCM.open(try AES.GCM.SealedBox(combined: data),
                                using: self.key, authenticating: Self.aad)
    }

    func decryptLegacy(data: Data?) throws -> Data? { try self.decrypt(data: data) }
    func encrypt(message: Data, using material: Data?) throws -> Data? { nil }
    func decrypt(message: Data, using material: Data?) throws -> Data? { nil }
    func sign(data: Data?) throws -> String { "" }
}

@MainActor
private func makeContainer() throws -> ModelContainer {
    let schema = Schema([
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
    ])
    return try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
}

@MainActor
@discardableResult
private func insertV1(identifier id: String, givenName: String, familyName: String,
                      in context: ModelContext) -> Contact.Profile {
    let profile = Contact.Profile(
        identifier: id, givenName: givenName, familyName: familyName, middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.encryptionScheme = EncryptionScheme.v1_identityDerived.rawValue
    context.insert(profile)
    return profile
}

@Suite("Bug 89 — v1 migration resilience", .serialized)
@MainActor
struct MigrateToV2ResilienceTests {

    /// The defect. The first row whose legacy ciphertext will not authenticate used to end
    /// the whole pass, so every row after it was never attempted — however recoverable those
    /// rows individually were.
    @Test("A contact that cannot be migrated does not block the ones after it")
    func failingContactDoesNotBlockTheRest() throws {
        let context = ModelContext(try makeContainer())
        let legacy  = StubCrypto(key: SymmetricKey(size: .bits256))
        let new     = StubCrypto(key: SymmetricKey(size: .bits256))

        // Row 1 is garbage under the legacy key. Row 2 is perfectly migratable.
        // Identifiers are sealed too: `migrateContact` re-encrypts `identifier` like any
        // other field, so a plain string there fails for the wrong reason.
        let bad  = insertV1(identifier: legacy.seal("bad"),
                            givenName: "!!not-base64-ciphertext!!", familyName: "", in: context)
        let good = insertV1(identifier: legacy.seal("good"),
                            givenName: legacy.seal("Alice"),
                            familyName: legacy.seal("Wonderland"), in: context)
        try context.save()

        try DatabaseMigration.migrateToV2(modelContext: context, legacyCrypto: legacy, newCrypto: new)

        // Asserted on the object references: `identifier` is itself re-encrypted by a
        // successful migration, so looking a row up by it afterwards would not find it.
        #expect(good.encryptionScheme == EncryptionScheme.v2_hybridPQ.rawValue, """
            The migratable contact after the failing one was never attempted. One \
            unrecoverable row must not strand the recoverable rows behind it.
            """)
        #expect(bad.encryptionScheme == EncryptionScheme.v1_identityDerived.rawValue, """
            A failed row must stay at v1 so it is retried. Marking it v2 collapses "not yet \
            migrated" into "migrated" and destroys the evidence that a retry is possible.
            """)
    }

    /// The second defect. `migrateContact` assigns field by field, so a throw partway leaves
    /// earlier fields already converted on the live object — and the next contact's `save()`
    /// would commit them, producing the half-converted row this fix exists to repair.
    @Test("A failed contact leaves no field changed, even after a later save")
    func failedContactLeavesNoFieldChanged() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let legacy  = StubCrypto(key: SymmetricKey(size: .bits256))
        let new     = StubCrypto(key: SymmetricKey(size: .bits256))

        // givenName is readable, familyName is not: migrateContact converts the first and
        // throws on the second, which is precisely the partial-mutation case.
        let readable  = legacy.seal("Alice")
        let partialID = legacy.seal("partial")
        insertV1(identifier: partialID, givenName: readable, familyName: "!!garbage!!", in: context)
        insertV1(identifier: legacy.seal("after"),
                 givenName: legacy.seal("Bob"), familyName: legacy.seal("Builder"), in: context)
        try context.save()

        try DatabaseMigration.migrateToV2(modelContext: context, legacyCrypto: legacy, newCrypto: new)

        // Asserted through a FRESH context, not the in-memory object. `rollback()` discards
        // the context's pending changes, but an already-materialised reference can still
        // hold the mutated value — and what matters here is only whether the partial
        // mutation reached disk, which is what a later save would have committed.
        let fresh   = ModelContext(container)
        let partial = try #require(
            try fresh.fetch(FetchDescriptor<Contact.Profile>()).first { $0.identifier == partialID }
        )

        #expect(partial.givenName == readable, """
            givenName was converted before the throw and then committed by a later save, \
            leaving a row with v2 ciphertext in one field and v1 in another and its marker \
            still reading v1 — unreadable by either key on the next launch.
            """)
        #expect(partial.encryptionScheme == EncryptionScheme.v1_identityDerived.rawValue)
    }

    /// Resume. A row already half-converted by an earlier partial run must be able to finish:
    /// its already-v2 fields are left alone rather than throwing, and the row completes.
    @Test("A half-converted row resumes and completes")
    func halfConvertedRowResumes() throws {
        let context = ModelContext(try makeContainer())
        let legacy  = StubCrypto(key: SymmetricKey(size: .bits256))
        let new     = StubCrypto(key: SymmetricKey(size: .bits256))

        // Exactly the device's state: givenName already sealed under the NEW key, the rest
        // still under the legacy one, and the row still marked v1.
        let alreadyV2 = new.seal("Alice")
        let mixed = insertV1(identifier: legacy.seal("mixed"),
                             givenName: alreadyV2,
                             familyName: legacy.seal("Wonderland"), in: context)
        try context.save()

        try DatabaseMigration.migrateToV2(modelContext: context, legacyCrypto: legacy, newCrypto: new)

        #expect(mixed.encryptionScheme == EncryptionScheme.v2_hybridPQ.rawValue, """
            A half-converted row must finish. Without resume it dies every launch on the \
            field it already converted, and stays stuck forever.
            """)
        #expect(mixed.givenName == alreadyV2,
                "the already-converted field must be left byte-identical, not re-encrypted")
        #expect(try new.decrypt(data: Data(base64Encoded: mixed.familyName)!)
                    .map { String(data: $0, encoding: .utf8) } == "Wonderland",
                "the remaining v1 field must have been converted")
    }
}

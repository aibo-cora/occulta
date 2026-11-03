//
//  PairingSecretStateTests.swift
//  OccultaTests
//
//  Bug 196, stage 2: the state a pairing holds on its secret, its fixed-size codec, the sealed column on the peer's
//  `Key` row from insertion to deletion, and the migration that fills it. The column is never nil and always the same
//  sealed length, so it says nothing about which pairings have a secret.
//
//  These run under `.ambientTestKeyManager`: the local DB key is the only key involved.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta
@testable import OccultaFormats

// MARK: - Helpers

@MainActor
private func makeContactManager() throws -> (ContactManager, ModelContainer) {
    let schema = Schema([
        Group.self,
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    let security  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
    return (ContactManager(modelContainer: container, security: security), container)
}

/// A contact with one key, saved the way a pairing saves it.
@MainActor
private func pairedContact(
    _ cm: ContactManager, secret: Data?
) throws -> (contact: Contact.Profile, key: Contact.Profile.Key) {
    try cm.save(contact: Contact.Draft(identifier: UUID().uuidString, givenName: "A", familyName: "B"))
    let contact = try #require(try cm.fetchAllContacts().first)
    let draft = try #require(Contact.Draft.Key(
        material: Data(repeating: 0x04, count: 65), owner: Data(repeating: 0x01, count: 65),
        date: "1", pairingSecret: secret
    ))
    try cm.update(key: draft, for: contact.identifier)
    return (contact, try #require(contact.contactPublicKeys?.last))
}

private func half(_ byte: UInt8) -> Data { Data(repeating: byte, count: 32) }

private let everyState: [(name: String, state: PairingSecretState)] = [
    ("none", .empty),
    ("none, refuses old form", PairingSecretState(phase: .none, refusesOldForm: true)),
    ("swapping", PairingSecretState(phase: .swapping(ourHalf: half(0x11)), refusesOldForm: false)),
    ("held, unconfirmed", PairingSecretState(phase: .held(secret: half(0x22), peerConfirmed: false), refusesOldForm: false)),
    ("held, confirmed", PairingSecretState(phase: .held(secret: half(0x33), peerConfirmed: true), refusesOldForm: false)),
    ("derived", .derived(secret: half(0x44))),
]

// MARK: - The state and its codec

@Suite("Bug 196 — pairing secret state and codec")
struct PairingSecretCodecTests {

    @Test("Every state round-trips and encodes to the capacity", arguments: everyState.indices)
    func roundTrips(_ index: Int) throws {
        let (name, state) = everyState[index]
        let plaintext = try PairingSecretCodec().encode(state)
        #expect(plaintext.count == PairingSecretCodec.capacity, "\(name)")
        #expect(try PairingSecretCodec().decode(plaintext) == state, "\(name)")
    }

    @Test("A held secret and a half in the same state land in separate fields")
    func fieldsAreSeparate() throws {
        let held = try PairingSecretCodec().encode(.derived(secret: half(0xAA)))
        let swapping = try PairingSecretCodec().encode(
            PairingSecretState(phase: .swapping(ourHalf: half(0xBB)), refusesOldForm: false)
        )
        #expect(held[3..<35] == half(0xAA))
        #expect(swapping[35..<67] == half(0xBB))
        #expect(held[35..<67] == Data(count: 32), "a held state keeps no half")
        #expect(swapping[3..<35] == Data(count: 32), "a swapping state keeps no secret")
    }

    @Test("A malformed plaintext is refused")
    func decodeRefuses() throws {
        let good = try PairingSecretCodec().encode(.derived(secret: half(1)))
        #expect(throws: PairingSecretCodec.CodecError.malformed) { try PairingSecretCodec().decode(good.dropLast()) }
        #expect(throws: PairingSecretCodec.CodecError.malformed) { try PairingSecretCodec().decode(Data()) }

        var wrongVersion = good; wrongVersion[0] = 0x02
        #expect(throws: PairingSecretCodec.CodecError.malformed) { try PairingSecretCodec().decode(wrongVersion) }

        var unknownPhase = good; unknownPhase[1] = 3
        #expect(throws: PairingSecretCodec.CodecError.malformed) { try PairingSecretCodec().decode(unknownPhase) }

        var unknownFlag = good; unknownFlag[2] |= 0x04
        #expect(throws: PairingSecretCodec.CodecError.malformed) { try PairingSecretCodec().decode(unknownFlag) }
    }

    @Test("A secret or half of the wrong size is refused, never padded or cut")
    func encodeRefuses() {
        #expect(throws: PairingSecretCodec.CodecError.wrongSize) {
            try PairingSecretCodec().encode(.derived(secret: Data(count: 31)))
        }
        #expect(throws: PairingSecretCodec.CodecError.wrongSize) {
            try PairingSecretCodec().encode(PairingSecretState(phase: .swapping(ourHalf: Data(count: 33)), refusesOldForm: false))
        }
    }

    @Test("A pairing that derived its secret holds it, confirmed, and refuses the old form")
    func derivedState() {
        let state = PairingSecretState.derived(secret: half(7))
        #expect(state.secret == half(7))
        #expect(state.sendsNewForm)
        #expect(state.refusesOldForm)
    }

    @Test("Only a held and confirmed secret sends the new form; a held one already routes labels")
    func rules() {
        #expect(!PairingSecretState.empty.sendsNewForm)
        #expect(PairingSecretState.empty.secret == nil)
        let swapping = PairingSecretState(phase: .swapping(ourHalf: half(1)), refusesOldForm: false)
        #expect(!swapping.sendsNewForm && swapping.secret == nil)
        let unconfirmed = PairingSecretState(phase: .held(secret: half(2), peerConfirmed: false), refusesOldForm: false)
        #expect(!unconfirmed.sendsNewForm && unconfirmed.secret == half(2))
    }
}

// MARK: - The column

@MainActor
@Suite("Bug 196 — the sealed column on the peer's key row", .serialized)
struct PairingSecretColumnTests {

    @Test("A key saved with a derived secret holds it, sealed", .ambientTestKeyManager)
    func savedWithSecret() throws {
        let (cm, _) = try makeContactManager()
        let (_, key) = try pairedContact(cm, secret: half(0x55))
        #expect(key.pairingSecretEncrypted != nil)
        #expect(cm.pairingSecretState(of: key) == .derived(secret: half(0x55)))
    }

    @Test("A key saved with no secret holds the sealed empty state, not nil", .ambientTestKeyManager)
    func savedWithoutSecret() throws {
        let (cm, _) = try makeContactManager()
        let (contact, key) = try pairedContact(cm, secret: nil)
        #expect(key.pairingSecretEncrypted != nil)
        #expect(cm.pairingSecretState(of: key) == .empty)
        #expect(cm.pairingSecretState(for: contact) == .empty)
    }

    @Test("A second pairing with the same contact has its own secret; the first stays on its row", .ambientTestKeyManager)
    func rePairKeepsOldRow() throws {
        let (cm, _) = try makeContactManager()
        let (contact, first) = try pairedContact(cm, secret: half(1))
        let draft = try #require(Contact.Draft.Key(
            material: Data(repeating: 0x04, count: 65), owner: Data(repeating: 0x01, count: 65),
            date: "2", pairingSecret: half(2)
        ))
        try cm.update(key: draft, for: contact.identifier)

        #expect(contact.contactPublicKeys?.count == 2)
        #expect(cm.pairingSecretState(of: first) == .derived(secret: half(1)))
        #expect(cm.pairingSecretState(for: contact) == .derived(secret: half(2)), "the current key's secret is the latest")
    }

    @Test("Every state seals to one length, and a created key's field is that length", .ambientTestKeyManager)
    func sealedLengthsMatch() throws {
        let (cm, _) = try makeContactManager()
        let (_, withSecret) = try pairedContact(cm, secret: half(9))
        let lengths = try everyState.map { entry -> Int in
            let key = Contact.Profile.Key(owner: Data(), date: Data())
            try cm.store(entry.state, in: key)
            return try #require(key.pairingSecretEncrypted).count
        }
        #expect(Set(lengths).count == 1, "lengths differ: \(lengths)")
        #expect(withSecret.pairingSecretEncrypted?.count == lengths.first)
    }

    @Test("Sealing the same state twice gives different bytes", .ambientTestKeyManager)
    func sealingIsRandomised() throws {
        let (cm, _) = try makeContactManager()
        let key = Contact.Profile.Key(owner: Data(), date: Data())
        try cm.store(.empty, in: key)
        let first = key.pairingSecretEncrypted
        try cm.store(.empty, in: key)
        #expect(first != key.pairingSecretEncrypted, "a fixed nonce would let equal fields be compared without the key")
    }

    @Test("An unreadable seal reads as empty", .ambientTestKeyManager)
    func unreadableReadsEmpty() throws {
        let (cm, _) = try makeContactManager()
        let key = Contact.Profile.Key(owner: Data(), date: Data(), pairingSecretEncrypted: Data(repeating: 1, count: 200))
        #expect(cm.pairingSecretState(of: key) == .empty)
        #expect(cm.pairingSecretState(of: Contact.Profile.Key(owner: Data(), date: Data())) == .empty)
    }

    @Test("Deleting a contact overwrites every key's state with the sealed empty state", .ambientTestKeyManager)
    func deletionOverwrites() throws {
        let (cm, _) = try makeContactManager()
        let (contact, key) = try pairedContact(cm, secret: half(0x66))
        let before = try #require(key.pairingSecretEncrypted).count

        try cm.deleteContact(identifier: contact.identifier)

        #expect(cm.pairingSecretState(of: key) == .empty)
        #expect(key.pairingSecretEncrypted?.count == before, "the field keeps its length")
    }
}

// MARK: - The migration

@MainActor
@Suite("Bug 196 — the launch migration that fills the column", .serialized)
struct PairingSecretMigrationTests {

    @discardableResult
    private func insert(
        keys: Int, field: Data? = nil, scheme: EncryptionScheme = .v2_hybridPQ,
        deletionToken: Data? = nil, in context: ModelContext
    ) -> Contact.Profile {
        let profile = Contact.Profile(
            identifier: UUID().uuidString, givenName: "", familyName: "", middleName: "", nickname: "",
            organizationName: "", departmentName: "", jobTitle: ""
        )
        profile.encryptionScheme = scheme.rawValue
        profile.deletionToken = deletionToken
        for _ in 0..<keys {
            profile.contactPublicKeys?.append(Contact.Profile.Key(
                material: Data([1]), owner: Data(), date: Data(), pairingSecretEncrypted: field
            ))
        }
        context.insert(profile)
        return profile
    }

    @Test("Every key row without the field gets the sealed empty state", .ambientTestKeyManager)
    func fillsNilRows() throws {
        let (cm, _) = try makeContactManager()
        let row = insert(keys: 3, in: cm.modelContext)

        try DatabaseMigration.migratePairingSecretFields(modelContext: cm.modelContext)

        for key in try #require(row.contactPublicKeys) {
            #expect(key.pairingSecretEncrypted != nil)
            #expect(cm.pairingSecretState(of: key) == .empty)
        }
    }

    @Test("A soft-deleted row is filled too", .ambientTestKeyManager)
    func fillsSoftDeleted() throws {
        let (cm, _) = try makeContactManager()
        let row = insert(keys: 1, deletionToken: Data([1]), in: cm.modelContext)

        try DatabaseMigration.migratePairingSecretFields(modelContext: cm.modelContext)

        #expect(row.contactPublicKeys?.first?.pairingSecretEncrypted != nil)
    }

    @Test("A row that has the field is left byte-identical", .ambientTestKeyManager)
    func leavesFilledRowsAlone() throws {
        let (cm, _) = try makeContactManager()
        let sealed = try cm.sealedPairingSecret(.derived(secret: half(0x77)))
        let row = insert(keys: 1, field: sealed, in: cm.modelContext)

        try DatabaseMigration.migratePairingSecretFields(modelContext: cm.modelContext)

        #expect(row.contactPublicKeys?.first?.pairingSecretEncrypted == sealed)
    }

    @Test("A row still at the v1 scheme is skipped until migrateToV2 has converted it", .ambientTestKeyManager)
    func skipsV1() throws {
        let (cm, _) = try makeContactManager()
        let row = insert(keys: 1, scheme: .v1_identityDerived, in: cm.modelContext)

        try DatabaseMigration.migratePairingSecretFields(modelContext: cm.modelContext)

        #expect(row.contactPublicKeys?.first?.pairingSecretEncrypted == nil)
    }

    @Test("Running it again changes nothing", .ambientTestKeyManager)
    func idempotent() throws {
        let (cm, _) = try makeContactManager()
        let row = insert(keys: 2, in: cm.modelContext)

        try DatabaseMigration.migratePairingSecretFields(modelContext: cm.modelContext)
        let first = try #require(row.contactPublicKeys).map(\.pairingSecretEncrypted)
        try DatabaseMigration.migratePairingSecretFields(modelContext: cm.modelContext)

        #expect(try #require(row.contactPublicKeys).map(\.pairingSecretEncrypted) == first)
    }

    @Test("It touches no other field of the key", .ambientTestKeyManager)
    func touchesNothingElse() throws {
        let (cm, _) = try makeContactManager()
        let row = insert(keys: 1, in: cm.modelContext)
        let key = try #require(row.contactPublicKeys?.first)
        let (material, owner, date, quantum) = (key.material, key.owner, key.acquiredAt, key.quantumKeyMaterialEncrypted)

        try DatabaseMigration.migratePairingSecretFields(modelContext: cm.modelContext)

        #expect(key.material == material && key.owner == owner && key.acquiredAt == date)
        #expect(key.quantumKeyMaterialEncrypted == quantum)
    }
}

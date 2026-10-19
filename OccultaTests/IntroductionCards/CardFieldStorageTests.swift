//
//  CardFieldStorageTests.swift
//  OccultaTests
//
//  Introduction cards, stage A: the card field on `Contact.Profile` from creation to deletion, the launch
//  migration that fills it, and the tier derived from it (`Docs/Features/Introduction Cards/SPEC.md` §5, §12;
//  `BUILD_PLAN.md` stage A). The field is never nil and always the same sealed length, so it says nothing about
//  whether a contact has a card or what kind.
//
//  These run under `.ambientTestKeyManager`: the local DB key is the only key involved, and nothing here touches
//  the Enclave. The states hold filler blobs of realistic size with distinct values everywhere, because a binary
//  plist stores a repeated value once and would make a state look smaller than any real one.
//

import Testing
import Foundation
import SwiftData
import Contacts
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
    let security  = try Manager.Security(modelContainer: container, keyManager: TestKeyManager())
    return (ContactManager(modelContainer: container, security: security), container)
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
    return try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
}

/// A row as an upgraded device holds it: on the v2 scheme, with a prekey record and a name, and no card field
/// unless given one.
@discardableResult
@MainActor
private func insertRow(
    card: Data? = nil,
    visibleThroughDepth: Int = Int.max,
    deletionToken: Data? = nil,
    scheme: EncryptionScheme = .v2_hybridPQ,
    in context: ModelContext
) throws -> Contact.Profile {
    let profile = Contact.Profile(
        identifier: UUID().uuidString, givenName: try #require(try Data("Ada".utf8).encrypt()).base64EncodedString(),
        familyName: "", middleName: "", nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.encryptionScheme    = scheme.rawValue
    profile.visibleThroughDepth = try DepthCodec.encode(visibleThroughDepth).encrypt()
    profile.prekeyRecordEncrypted = try PrekeyRecordCodec().encode(.empty).encrypt()
    profile.introductionCardEncrypted = card
    profile.deletionToken = deletionToken
    context.insert(profile)
    return profile
}

private func distinctQuantum() -> QuantumKeyMaterial {
    QuantumKeyMaterial(
        encapsulatedSecret: randomBytes(32), decapsulatedSecret: randomBytes(32),
        ourCiphertext: randomBytes(1_568), peerCiphertext: randomBytes(1_568)
    )
}

private func issuedState() -> CardState {
    .issued(
        card: randomBytes(1_768), agreementKey: randomBytes(143), signingKey: randomBytes(143),
        mlkemKey: randomBytes(4_788), expiresAt: Date(timeIntervalSinceReferenceDate: 800_000_000.25)
    )
}

private func importedState(sent: Bool) -> CardState {
    .imported(
        peerCard: randomBytes(1_768), agreementKey: randomBytes(143), signingKey: randomBytes(143),
        mlkemKey: randomBytes(4_788), ss1: randomBytes(32), ct1: randomBytes(1_568),
        expiresAt: Date(timeIntervalSinceReferenceDate: 800_086_400.5), sentFirstMessage: sent
    )
}

private func conversationState(isIssuer: Bool, bootstrapOpen: Bool) -> CardState {
    .conversation(
        agreementKey: randomBytes(143), signingKey: randomBytes(143),
        peerAgreementKey: randomBytes(65), peerSigningKey: randomBytes(65),
        quantum: distinctQuantum(), bootstrapOpen: bootstrapOpen, isIssuer: isIssuer
    )
}

/// Every shape the field can hold, the largest included.
private func everyState() -> [(name: String, state: CardState)] {
    [
        ("empty", .empty),
        ("issued", issuedState()),
        ("imported, not yet sent", importedState(sent: false)),
        ("imported, sent", importedState(sent: true)),
        ("conversation, Bob, bootstrap open", conversationState(isIssuer: true, bootstrapOpen: true)),
        ("conversation, Bob, settled", conversationState(isIssuer: true, bootstrapOpen: false)),
        ("conversation, Carol, settled", conversationState(isIssuer: false, bootstrapOpen: false)),
        ("conversation, Carol, bootstrap open", conversationState(isIssuer: false, bootstrapOpen: true)),
    ]
}

/// The sealed length of the field holding `state`.
@MainActor
private func sealedLength(of state: CardState, in cm: ContactManager) throws -> Int {
    let scratch = try insertRow(in: cm.modelContext)
    try cm.store(state, for: scratch)
    return try #require(scratch.introductionCardEncrypted).count
}

/// What the migration must not change: every other sealed field this test populates.
private struct OtherFields: Equatable {
    let prekeyRecord: Data?
    let givenName: String
    let visibleThroughDepth: Data?
    let deletionToken: Data?
    let encryptionScheme: Int

    @MainActor
    init(_ row: Contact.Profile) {
        self.prekeyRecord        = row.prekeyRecordEncrypted
        self.givenName           = row.givenName
        self.visibleThroughDepth = row.visibleThroughDepth
        self.deletionToken       = row.deletionToken
        self.encryptionScheme    = row.encryptionScheme
    }
}

// MARK: - Creation

@MainActor
@Suite("Card field — present at one sealed length from creation", .serialized)
struct CardFieldCreationTests {

    @Test("A contact saved from a draft starts with a sealed empty card field", .ambientTestKeyManager)
    func savedFromDraft() throws {
        let (cm, _) = try makeContactManager()
        try cm.save(contact: Contact.Draft(identifier: UUID().uuidString, givenName: "A", familyName: "B"))

        let contact = try #require(try cm.fetchAllContacts().first)
        #expect(contact.introductionCardEncrypted != nil)
        #expect(contact.cardState == .empty)
    }

    @Test("A contact saved through the injectable-crypto overload starts with it too", .ambientTestKeyManager)
    func savedWithInjectedCrypto() throws {
        let (cm, _) = try makeContactManager()
        try cm.save(contact: Contact.Draft(identifier: UUID().uuidString, givenName: "A", familyName: "B"),
                    currentDepth: 0, using: Manager.Crypto())

        let contact = try #require(try cm.fetchAllContacts().first)
        #expect(contact.introductionCardEncrypted != nil)
        #expect(contact.cardState == .empty)
    }

    @Test("A contact created at a duress depth starts with it too", .ambientTestKeyManager)
    func savedAtDuressDepth() throws {
        let (cm, _) = try makeContactManager()
        try cm.save(contact: Contact.Draft(identifier: UUID().uuidString, givenName: "A", familyName: "B"), currentDepth: 1)

        let contact = try #require(try cm.modelContext.fetch(FetchDescriptor<Contact.Profile>()).first)
        #expect(contact.introductionCardEncrypted != nil)
        #expect(contact.cardState == .empty)
    }

    @Test("A contact imported from the address book starts with it", .ambientTestKeyManager)
    func importedFromAddressBook() throws {
        let (cm, _) = try makeContactManager()
        let imported = CNMutableContact()
        imported.givenName = "A"
        try cm.createContacts(from: [imported])

        let contact = try #require(try cm.fetchAllContacts().first)
        #expect(contact.introductionCardEncrypted != nil)
        #expect(contact.cardState == .empty)
    }

    @Test("A contact imported from the address book at a duress depth starts with it too", .ambientTestKeyManager)
    func importedAtDuressDepth() throws {
        let (cm, _) = try makeContactManager()
        let imported = CNMutableContact()
        imported.givenName = "A"
        try cm.createContacts(from: [imported], currentDepth: 1)

        let contact = try #require(try cm.modelContext.fetch(FetchDescriptor<Contact.Profile>()).first)
        #expect(contact.introductionCardEncrypted != nil)
        #expect(contact.cardState == .empty)
    }

    /// The field's length must say nothing about the state: a created contact's empty field is the length of the
    /// fullest state there is.
    @Test("A created contact's field is the sealed length of every other state", .ambientTestKeyManager)
    func createdFieldMatchesEveryState() throws {
        let (cm, _) = try makeContactManager()
        let imported = CNMutableContact()
        imported.givenName = "A"
        try cm.createContacts(from: [imported])
        try cm.save(contact: Contact.Draft(identifier: UUID().uuidString, givenName: "B", familyName: "C"))

        let created = try cm.fetchAllContacts().map { try #require($0.introductionCardEncrypted).count }
        #expect(created.count == 2)

        for (name, state) in everyState() {
            let length = try sealedLength(of: state, in: cm)
            #expect(created.allSatisfy { $0 == length }, "\(name): a created contact's field differs in length")
        }
    }

    @Test("Every state seals to one length", .ambientTestKeyManager)
    func everyStateSealsToOneLength() throws {
        let (cm, _) = try makeContactManager()
        let states = everyState()
        let lengths = try states.map { try sealedLength(of: $0.state, in: cm) }
        #expect(lengths.count == states.count)
        #expect(Set(lengths).count == 1, "lengths differ: \(Dictionary(uniqueKeysWithValues: zip(states.map(\.name), lengths)))")
    }

    @Test("Sealing the same state twice gives different bytes", .ambientTestKeyManager)
    func sealingIsRandomised() throws {
        let (cm, _) = try makeContactManager()
        let row = try insertRow(in: cm.modelContext)
        try cm.store(CardState.empty, for: row)
        let first = row.introductionCardEncrypted
        try cm.store(CardState.empty, for: row)
        #expect(first != row.introductionCardEncrypted, "a fixed nonce would let equal fields be compared without the key")
    }
}

// MARK: - Read / write

@MainActor
@Suite("Card field — store and read", .serialized)
struct CardFieldRoundTripTests {

    @Test("Every state round-trips through store and cardState", .ambientTestKeyManager,
          arguments: [0, 1, 2, 3, 4, 5, 6, 7])
    func roundTrips(_ index: Int) throws {
        let (cm, _) = try makeContactManager()
        let row = try insertRow(in: cm.modelContext)
        let (name, state) = everyState()[index]

        try cm.store(state, for: row)

        #expect(row.cardState == state, "\(name)")
    }

    @Test("Storing overwrites the previous state", .ambientTestKeyManager)
    func storeOverwrites() throws {
        let (cm, _) = try makeContactManager()
        let row = try insertRow(in: cm.modelContext)
        let issued = issuedState()
        try cm.store(issued, for: row)
        #expect(row.cardState == issued)

        try cm.store(CardState.empty, for: row)
        #expect(row.cardState == .empty)
    }

    @Test("A nil field reads as empty", .ambientTestKeyManager)
    func nilReadsEmpty() throws {
        let (cm, _) = try makeContactManager()
        let row = try insertRow(in: cm.modelContext)
        #expect(row.introductionCardEncrypted == nil)
        #expect(row.cardState == .empty)
    }

    @Test("A field that won't decrypt, decode or has the wrong version reads as empty", .ambientTestKeyManager,
          arguments: ["undecryptable", "wrongVersion", "wrongLength", "garbagePayload", "lengthPastCapacity", "emptyData"])
    func unreadableReadsEmpty(_ kind: String) throws {
        let (cm, _) = try makeContactManager()
        let row = try insertRow(in: cm.modelContext)

        // A good plaintext to corrupt, so the damage is the only thing wrong with it.
        var plaintext = try CardStateCodec().encode(issuedState())
        switch kind {
        case "undecryptable":
            row.introductionCardEncrypted = randomBytes(300)
        case "wrongVersion":
            plaintext[0] = CardStateCodec.formatVersion &+ 1
            row.introductionCardEncrypted = try #require(try plaintext.encrypt())
        case "wrongLength":
            row.introductionCardEncrypted = try #require(try plaintext.dropLast().encrypt())
        case "garbagePayload":
            var junk = Data([CardStateCodec.formatVersion, 0, 0, 0, 8])
            junk.append(randomBytes(8))
            junk.append(Data(count: CardStateCodec.capacity - junk.count))
            row.introductionCardEncrypted = try #require(try junk.encrypt())
        case "lengthPastCapacity":
            plaintext.replaceSubrange(1...4, with: [0xFF, 0xFF, 0xFF, 0xFF])
            row.introductionCardEncrypted = try #require(try plaintext.encrypt())
        default:
            row.introductionCardEncrypted = Data()
        }

        #expect(row.cardState == .empty, "\(kind)")
    }

    /// A field sealed under another local DB key is what a restored or half-migrated row looks like.
    @Test("A field sealed with a different key reads as empty", .ambientTestKeyManager)
    func otherKeyReadsEmpty() throws {
        let (cm, _) = try makeContactManager()
        let row = try insertRow(in: cm.modelContext)
        let plaintext = try CardStateCodec().encode(issuedState())
        let foreign = try Manager.Crypto(keyManager: TestKeyManager()).encrypt(data: plaintext)
        row.introductionCardEncrypted = try #require(foreign)

        #expect(row.cardState == .empty)
    }
}

// MARK: - Deletion

@MainActor
@Suite("Card field — deletion", .serialized)
struct CardFieldDeletionTests {

    @Test("Deleting a contact overwrites the field with the sealed empty state, at the same length", .ambientTestKeyManager,
          arguments: [1, 3, 7])
    func deleteEmptiesField(_ index: Int) throws {
        let (cm, _) = try makeContactManager()
        let row = try insertRow(in: cm.modelContext)
        let (name, state) = everyState()[index]
        try cm.store(state, for: row)
        try cm.modelContext.save()
        let before = try #require(row.introductionCardEncrypted)
        #expect(row.cardState == state, "precondition: \(name) is held")

        try cm.deleteContact(identifier: row.identifier)

        let after = try #require(row.introductionCardEncrypted)
        #expect(row.deletionToken != nil, "precondition: the soft-delete path ran")
        #expect(after.count == before.count)
        #expect(after != before)
        #expect(row.cardState == .empty, "a deleted contact's field holds none of the Enclave blobs")
    }

    @Test("Deleting a contact that never had a card also leaves the field at the same length", .ambientTestKeyManager)
    func deleteWithoutCard() throws {
        let (cm, _) = try makeContactManager()
        try cm.save(contact: Contact.Draft(identifier: UUID().uuidString, givenName: "A", familyName: "B"))
        let contact = try #require(try cm.fetchAllContacts().first)
        let before = try #require(contact.introductionCardEncrypted).count

        try cm.deleteContact(identifier: contact.identifier)

        #expect(try #require(contact.introductionCardEncrypted).count == before)
        #expect(contact.cardState == .empty)
    }
}

// MARK: - Migration

@MainActor
@Suite("DatabaseMigration — card fields", .serialized)
struct CardFieldMigrationTests {

    private func emptyLength() throws -> Int {
        try #require(try CardStateCodec().encode(.empty).encrypt()).count
    }

    @Test("A live row with no field gets a sealed empty state", .ambientTestKeyManager)
    func liveRow() throws {
        let context = ModelContext(try makeContainer())
        let row = try insertRow(in: context)

        try DatabaseMigration.migrateCardFields(modelContext: context)

        #expect(try #require(row.introductionCardEncrypted).count == (try self.emptyLength()))
        #expect(row.cardState == .empty)
    }

    @Test("A row hidden at a duress depth gets one too", .ambientTestKeyManager)
    func hiddenRow() throws {
        let context = ModelContext(try makeContainer())
        let row = try insertRow(visibleThroughDepth: 0, in: context)

        try DatabaseMigration.migrateCardFields(modelContext: context)

        #expect(try #require(row.introductionCardEncrypted).count == (try self.emptyLength()))
        #expect(row.cardState == .empty)
    }

    @Test("A soft-deleted row gets the sealed empty state a deletion writes", .ambientTestKeyManager)
    func softDeletedRow() throws {
        let context = ModelContext(try makeContainer())
        let row = try insertRow(deletionToken: try Data([1]).encrypt(), in: context)

        try DatabaseMigration.migrateCardFields(modelContext: context)

        #expect(try #require(row.introductionCardEncrypted).count == (try self.emptyLength()))
        #expect(row.cardState == .empty)
    }

    /// A soft-deleted row whose token is unreadable is still filled: a NULL would single it out, and the sealed
    /// empty state is the same bytes-at-rest as any other row's.
    @Test("A soft-deleted row whose token doesn't decrypt is filled too", .ambientTestKeyManager)
    func strandedSoftDeletedRow() throws {
        let context = ModelContext(try makeContainer())
        let row = try insertRow(deletionToken: randomBytes(33), in: context)

        try DatabaseMigration.migrateCardFields(modelContext: context)

        #expect(try #require(row.introductionCardEncrypted).count == (try self.emptyLength()))
    }

    @Test("A row that already has a field is left byte for byte", .ambientTestKeyManager)
    func existingFieldUnchanged() throws {
        let (cm, _) = try makeContactManager()
        let held = try insertRow(in: cm.modelContext)
        try cm.store(importedState(sent: true), for: held)
        let sealedEmpty = try insertRow(in: cm.modelContext)
        try cm.store(CardState.empty, for: sealedEmpty)
        let heldBytes = held.introductionCardEncrypted
        let emptyBytes = sealedEmpty.introductionCardEncrypted
        let unreadable = try insertRow(card: randomBytes(300), in: cm.modelContext)
        let unreadableBytes = unreadable.introductionCardEncrypted

        try DatabaseMigration.migrateCardFields(modelContext: cm.modelContext)

        #expect(held.introductionCardEncrypted == heldBytes)
        #expect(sealedEmpty.introductionCardEncrypted == emptyBytes)
        #expect(unreadable.introductionCardEncrypted == unreadableBytes, "present but unreadable is not nil: the pass leaves it")
    }

    @Test("It changes no other field", .ambientTestKeyManager)
    func otherFieldsUntouched() throws {
        let context = ModelContext(try makeContainer())
        let rows = [
            try insertRow(in: context),
            try insertRow(visibleThroughDepth: 0, in: context),
            try insertRow(deletionToken: try Data([1]).encrypt(), in: context),
        ]
        try context.save()
        let before = rows.map { OtherFields($0) }

        try DatabaseMigration.migrateCardFields(modelContext: context)

        #expect(rows.map { OtherFields($0) } == before)
        #expect(rows.allSatisfy { $0.prekeyRecordEncrypted != nil }, "precondition: the prekey record is populated")
    }

    @Test("A row still on the v1 scheme is left for migrateToV2", .ambientTestKeyManager)
    func v1RowSkipped() throws {
        let context = ModelContext(try makeContainer())
        let row = try insertRow(scheme: .v1_identityDerived, in: context)

        try DatabaseMigration.migrateCardFields(modelContext: context)

        #expect(row.introductionCardEncrypted == nil)
    }

    @Test("A store with no rows does nothing", .ambientTestKeyManager)
    func noRows() throws {
        let context = ModelContext(try makeContainer())
        try DatabaseMigration.migrateCardFields(modelContext: context)
        #expect(try context.fetch(FetchDescriptor<Contact.Profile>()).isEmpty)
    }

    /// The whole population at once: every row saved with one length, and a second launch rewrites nothing.
    @Test("After the pass every row has one length, it is saved, and a second pass changes nothing", .ambientTestKeyManager)
    func everyRowUniformAndIdempotent() throws {
        let (cm, container) = try makeContactManager()
        let context = cm.modelContext
        try insertRow(in: context)
        try insertRow(visibleThroughDepth: 0, in: context)
        try insertRow(deletionToken: try Data([1]).encrypt(), in: context)
        try insertRow(deletionToken: randomBytes(33), in: context)
        let held = try insertRow(in: context)
        try cm.store(issuedState(), for: held)
        let heldState = held.cardState
        try context.save()

        try DatabaseMigration.migrateCardFields(modelContext: context)

        let rows = try ModelContext(container).fetch(FetchDescriptor<Contact.Profile>())
        #expect(rows.count == 5)
        #expect(Set(rows.map { $0.introductionCardEncrypted?.count }) == [try self.emptyLength()])

        let before = Dictionary(uniqueKeysWithValues: rows.map { ($0.identifier, $0.introductionCardEncrypted) })
        let otherBefore = Dictionary(uniqueKeysWithValues: rows.map { ($0.identifier, OtherFields($0)) })

        try DatabaseMigration.migrateCardFields(modelContext: context)

        let again = try ModelContext(container).fetch(FetchDescriptor<Contact.Profile>())
        #expect(Dictionary(uniqueKeysWithValues: again.map { ($0.identifier, $0.introductionCardEncrypted) }) == before,
                "a second launch must leave every field byte-identical")
        #expect(Dictionary(uniqueKeysWithValues: again.map { ($0.identifier, OtherFields($0)) }) == otherBefore)
        #expect(again.first { $0.identifier == held.identifier }?.cardState == heldState)
    }
}

// MARK: - Tier

@MainActor
@Suite("Card tier — in-person keys, and what the field says", .serialized)
struct CardTierTests {

    /// A contact holding a key whose owner hash is `ownerHash`, as an exchange on this device writes it.
    private func contact(ownerHash: Data?, expired: Bool = false, in cm: ContactManager) throws -> Contact.Profile {
        let row = try insertRow(in: cm.modelContext)
        if let ownerHash {
            let key = Contact.Profile.Key(
                material: try Data(count: 65).encrypt(),
                owner: try #require(try ownerHash.encrypt()),
                date: try #require(try Data("0".utf8).encrypt())
            )
            if expired { key.expiredOn = try Data("1".utf8).encrypt() }
            row.contactPublicKeys = [key]
        }
        try cm.modelContext.save()
        return row
    }

    private func ourHash() throws -> Data {
        try Manager.Ambient.keyManager.retrieveIdentity().sha256
    }

    @Test("In-person keys read as held", .ambientTestKeyManager)
    func hasKeys() throws {
        let (cm, _) = try makeContactManager()
        #expect(try self.contact(ownerHash: self.ourHash(), in: cm).hasInPersonKeys)
    }

    @Test("No keys, someone else's owner hash, or an expired key read as not held", .ambientTestKeyManager)
    func doesNotHaveKeys() throws {
        let (cm, _) = try makeContactManager()
        #expect(try self.contact(ownerHash: nil, in: cm).hasInPersonKeys == false)
        #expect(try self.contact(ownerHash: randomBytes(32), in: cm).hasInPersonKeys == false)
        #expect(try self.contact(ownerHash: self.ourHash(), expired: true, in: cm).hasInPersonKeys == false)
    }

    @Test("A contact with in-person keys is verified whatever the card state", .ambientTestKeyManager,
          arguments: [0, 1, 2, 3, 4, 5, 6, 7])
    func inPersonKeysAreVerified(_ index: Int) throws {
        let (cm, _) = try makeContactManager()
        let row = try self.contact(ownerHash: self.ourHash(), in: cm)
        let (name, state) = everyState()[index]
        try cm.store(state, for: row)

        #expect(cardTier(of: row) == .verified, "\(name)")
    }

    @Test("A contact without in-person keys: imported or in conversation is not verified", .ambientTestKeyManager,
          arguments: [2, 3, 4, 5, 6, 7])
    func cardWithoutKeysIsNotVerified(_ index: Int) throws {
        let (cm, _) = try makeContactManager()
        let row = try self.contact(ownerHash: nil, in: cm)
        let (name, state) = everyState()[index]
        try cm.store(state, for: row)

        #expect(cardTier(of: row) == .notVerified, "\(name)")
    }

    @Test("A pending contact with an imported card is not verified", .ambientTestKeyManager)
    func importedIsNotVerified() throws {
        let (cm, _) = try makeContactManager()
        let row = try self.contact(ownerHash: nil, in: cm)
        try cm.store(importedState(sent: false), for: row)
        #expect(cardTier(of: row) == .notVerified)
    }

    @Test("An issued card leaves the contact pending", .ambientTestKeyManager)
    func issuedIsPending() throws {
        let (cm, _) = try makeContactManager()
        let row = try self.contact(ownerHash: nil, in: cm)
        try cm.store(issuedState(), for: row)
        #expect(cardTier(of: row) == .pending)
    }

    @Test("No card and no keys is pending; a nil field is too", .ambientTestKeyManager)
    func emptyIsPending() throws {
        let (cm, _) = try makeContactManager()
        let row = try self.contact(ownerHash: nil, in: cm)
        #expect(row.introductionCardEncrypted == nil)
        #expect(cardTier(of: row) == .pending)
        try cm.store(CardState.empty, for: row)
        #expect(cardTier(of: row) == .pending)
    }

    @Test("An expired in-person key stops overriding the card", .ambientTestKeyManager)
    func expiredKeysDoNotOverride() throws {
        let (cm, _) = try makeContactManager()
        let row = try self.contact(ownerHash: self.ourHash(), expired: true, in: cm)
        try cm.store(importedState(sent: true), for: row)
        #expect(cardTier(of: row) == .notVerified)
    }
}

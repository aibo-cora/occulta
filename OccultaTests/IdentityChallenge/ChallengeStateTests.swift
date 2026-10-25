//
//  ChallengeStateTests.swift
//  OccultaTests
//
//  `bugs.md` Bug 180: identity-challenge state is a sealed, per-depth property of the contact. The codec and its
//  fixed shape, the column from creation to deletion, the launch pass that fills it, and the ledger that reads and
//  writes it, one depth at a time.
//
//  These run under `.ambientTestKeyManager`: the local DB key is the only key involved, and nothing here touches
//  the Enclave.
//

import Testing
import Foundation
import SwiftData
import Contacts
import CryptoKit
@testable import Occulta
@testable import OccultaFormats

// MARK: - Helpers

@MainActor
private func makeContactManager() throws -> ContactManager {
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
    return ContactManager(modelContainer: container, security: security)
}

/// A row as an upgraded device holds it: on the v2 scheme, with a name, and no challenge column unless given one.
@discardableResult
@MainActor
private func insertRow(
    challenge: Data? = nil,
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
    profile.challengeStateEncrypted = challenge
    profile.deletionToken = deletionToken
    context.insert(profile)
    return profile
}

/// A state with a live challenge and a verified-at in every slot, at the largest values.
private func fullState() -> ChallengeState {
    var slots: [ChallengeState.Slot] = []
    for index in 0..<ChallengeStateCodec.slotCount {
        let nonce = Data(repeating: UInt8(0xF0 | (index & 0x0F)), count: IdentityChallenge.nonceLength)
        let largest = UInt64.max - UInt64(index)
        slots.append(ChallengeState.Slot(
            challenge: IdentityChallenge.OutstandingChallenge(nonce: nonce, issuedAt: largest), verifiedAt: largest
        ))
    }
    return ChallengeState(slots: slots)
}

/// A state with something different in every slot, but not the largest values.
private func distinctState() -> ChallengeState {
    var slots: [ChallengeState.Slot] = []
    for index in 0..<ChallengeStateCodec.slotCount {
        var slot = ChallengeState.Slot.empty
        if index % 2 == 0 {
            let nonce = Data((0..<IdentityChallenge.nonceLength).map { UInt8(($0 + index) & 0xFF) })
            slot.challenge = IdentityChallenge.OutstandingChallenge(nonce: nonce, issuedAt: 1_700_000_000 + UInt64(index))
        }
        if index % 3 == 0 {
            slot.verifiedAt = 1_700_000_500 + UInt64(index)
        }
        slots.append(slot)
    }
    return ChallengeState(slots: slots)
}

@MainActor
private func emptySealedLength() throws -> Int {
    try #require(try ChallengeStateCodec().encode(.empty).encrypt()).count
}

// MARK: - Codec

@MainActor
@Suite("ChallengeStateCodec — one fixed shape", .serialized)
struct ChallengeStateCodecTests {

    @Test("The plaintext is 16 + 33 × 64 = 2128 bytes, and the slot count covers every reachable depth")
    func capacityAndSlots() {
        #expect(ChallengeStateCodec.capacity == 2_128)
        #expect(ChallengeStateCodec.slotCount >= AppLayerConfig.maxDepthCount + 1, "a depth of 0…maxDepthCount each has a slot")
    }

    @Test("Every state encodes to exactly `capacity` bytes")
    func everyStateIsCapacity() throws {
        let codec = ChallengeStateCodec()
        for state in [ChallengeState.empty, distinctState(), fullState()] {
            #expect(try codec.encode(state).count == ChallengeStateCodec.capacity)
        }
    }

    @Test("The empty state is the header and zeros")
    func emptyLayout() throws {
        let plaintext = try ChallengeStateCodec().encode(.empty)
        #expect(plaintext.prefix(2) == Data([0x01, 0x21]))
        #expect(plaintext.dropFirst(2).allSatisfy { $0 == 0 })
    }

    @Test("A slot's padding is zeros")
    func paddingIsZeros() throws {
        let plaintext = [UInt8](try ChallengeStateCodec().encode(fullState()))
        for index in 0..<ChallengeStateCodec.slotCount {
            let start = ChallengeStateCodec.headerSize + index * ChallengeStateCodec.slotSize
            #expect(plaintext[(start + 49) ..< (start + 64)].allSatisfy { $0 == 0 }, "slot \(index)")
        }
        #expect(plaintext[2 ..< 16].allSatisfy { $0 == 0 }, "the reserved header bytes")
    }

    @Test("Every slot round-trips on its own", arguments: Array(0..<33))
    func roundTripsEachSlot(_ index: Int) throws {
        var state = ChallengeState.empty
        state[depth: index] = .init(challenge: .init(nonce: Data(repeating: 7, count: 32), issuedAt: 42), verifiedAt: 43)

        let decoded = try ChallengeStateCodec().decode(try ChallengeStateCodec().encode(state))
        #expect(decoded == state)
        for other in 0..<ChallengeStateCodec.slotCount where other != index {
            #expect(decoded[depth: other] == .empty, "slot \(index) leaked into slot \(other)")
        }
    }

    @Test("Mixed and maximal states round-trip")
    func roundTripsWholeStates() throws {
        let codec = ChallengeStateCodec()
        for state in [ChallengeState.empty, distinctState(), fullState()] {
            #expect(try codec.decode(try codec.encode(state)) == state)
        }
    }

    @Test("A challenge without a verified-at, and the reverse, keep apart")
    func flagsAreIndependent() throws {
        var state = ChallengeState.empty
        state[depth: 0] = .init(challenge: .init(nonce: Data(repeating: 1, count: 32), issuedAt: 5), verifiedAt: nil)
        state[depth: 1] = .init(challenge: nil, verifiedAt: 9)
        let decoded = try ChallengeStateCodec().decode(try ChallengeStateCodec().encode(state))
        #expect(decoded[depth: 0].verifiedAt == nil && decoded[depth: 0].challenge?.issuedAt == 5)
        #expect(decoded[depth: 1].challenge == nil && decoded[depth: 1].verifiedAt == 9)
    }

    @Test("Garbage, a wrong version, a wrong slot count, a wrong length and an unknown flag are malformed")
    func malformed() throws {
        let codec = ChallengeStateCodec()
        let good = try codec.encode(distinctState())

        #expect(throws: ChallengeStateCodec.CodecError.malformed) { try codec.decode(randomBytes(ChallengeStateCodec.capacity)) }
        #expect(throws: ChallengeStateCodec.CodecError.malformed) { try codec.decode(Data()) }
        #expect(throws: ChallengeStateCodec.CodecError.malformed) { try codec.decode(good.dropLast()) }
        #expect(throws: ChallengeStateCodec.CodecError.malformed) { try codec.decode(good + Data([0])) }

        var version = good
        version[version.startIndex] = 0x02
        #expect(throws: ChallengeStateCodec.CodecError.malformed) { try codec.decode(version) }

        var count = good
        count[count.startIndex + 1] = 32
        #expect(throws: ChallengeStateCodec.CodecError.malformed) { try codec.decode(count) }

        var flag = good
        flag[flag.startIndex + ChallengeStateCodec.headerSize] |= 0b100
        #expect(throws: ChallengeStateCodec.CodecError.malformed) { try codec.decode(flag) }
    }

    @Test("A depth beyond the last slot clamps into it, and a negative one into the first")
    func clamping() {
        #expect(ChallengeStateCodec.slotIndex(forDepth: 0) == 0)
        #expect(ChallengeStateCodec.slotIndex(forDepth: 32) == 32)
        #expect(ChallengeStateCodec.slotIndex(forDepth: 33) == 32)
        #expect(ChallengeStateCodec.slotIndex(forDepth: 10_000) == 32)
        #expect(ChallengeStateCodec.slotIndex(forDepth: -5) == 0)
    }

    @Test("The empty and the fullest state seal to one length, and the same state twice to different bytes", .ambientTestKeyManager)
    func sealedLength() throws {
        let codec = ChallengeStateCodec()
        let lengths = try [ChallengeState.empty, distinctState(), fullState()].map { try #require(try codec.encode($0).encrypt()).count }
        #expect(Set(lengths) == [ChallengeStateCodec.capacity + 28], "2128 plus the nonce and the tag")

        let first = try #require(try codec.encode(.empty).encrypt())
        let second = try #require(try codec.encode(.empty).encrypt())
        #expect(first != second, "a fixed nonce would let equal columns be compared without the key")
    }

    @Test("The sealed empty state opens with the local DB key and decodes", .ambientTestKeyManager)
    func sealedRoundTrip() throws {
        let sealed = try #require(try ChallengeStateCodec().encode(distinctState()).encrypt())
        let opened = try #require(sealed.decrypt())
        #expect(try ChallengeStateCodec().decode(opened) == distinctState())
    }
}

// MARK: - Creation and deletion

@MainActor
@Suite("Challenge column — present at one sealed length from creation to deletion", .serialized)
struct ChallengeFieldCreationTests {

    @Test("A contact saved from a draft starts with a sealed empty column", .ambientTestKeyManager)
    func savedFromDraft() throws {
        let cm = try makeContactManager()
        try cm.save(contact: Contact.Draft(identifier: UUID().uuidString, givenName: "A", familyName: "B"))

        let contact = try #require(try cm.fetchAllContacts().first)
        #expect(try #require(contact.challengeStateEncrypted).count == (try emptySealedLength()))
        #expect(contact.challengeState == .empty)
    }

    @Test("A contact saved through the injectable-crypto overload starts with it too", .ambientTestKeyManager)
    func savedWithInjectedCrypto() throws {
        let cm = try makeContactManager()
        try cm.save(contact: Contact.Draft(identifier: UUID().uuidString, givenName: "A", familyName: "B"),
                    currentDepth: 0, using: Manager.Crypto())

        let contact = try #require(try cm.fetchAllContacts().first)
        #expect(try #require(contact.challengeStateEncrypted).count == (try emptySealedLength()))
    }

    @Test("A contact created at a duress depth starts with it too", .ambientTestKeyManager)
    func savedAtDuressDepth() throws {
        let cm = try makeContactManager()
        try cm.save(contact: Contact.Draft(identifier: UUID().uuidString, givenName: "A", familyName: "B"), currentDepth: 1)

        let contact = try #require(try cm.modelContext.fetch(FetchDescriptor<Contact.Profile>()).first)
        #expect(try #require(contact.challengeStateEncrypted).count == (try emptySealedLength()))
        #expect(contact.challengeState == .empty)
    }

    @Test("Contacts imported from the address book start with it, at depth 0 and at a duress depth", .ambientTestKeyManager)
    func importedFromAddressBook() throws {
        let cm = try makeContactManager()
        let first = CNMutableContact()
        first.givenName = "A"
        try cm.createContacts(from: [first])
        let second = CNMutableContact()
        second.givenName = "B"
        try cm.createContacts(from: [second], currentDepth: 1)

        let lengths = try cm.modelContext.fetch(FetchDescriptor<Contact.Profile>()).map { $0.challengeStateEncrypted?.count }
        #expect(lengths == [try emptySealedLength(), try emptySealedLength()])
    }

    @Test("A created contact's column is the sealed length of the fullest state", .ambientTestKeyManager)
    func createdColumnMatchesFullState() throws {
        let cm = try makeContactManager()
        try cm.save(contact: Contact.Draft(identifier: UUID().uuidString, givenName: "A", familyName: "B"))
        let row = try insertRow(in: cm.modelContext)
        try cm.store(fullState(), for: row)

        let created = try #require(try cm.fetchAllContacts().first { $0 !== row })
        #expect(created.challengeStateEncrypted?.count == row.challengeStateEncrypted?.count)
    }

    @Test("Deleting a contact overwrites the column at the same length, every depth's slot", .ambientTestKeyManager)
    func deletionEmptiesEveryDepth() throws {
        let cm = try makeContactManager()
        let row = try insertRow(in: cm.modelContext)
        try cm.store(fullState(), for: row)
        try cm.modelContext.save()
        let before = try #require(row.challengeStateEncrypted).count

        try cm.deleteContact(identifier: row.identifier)

        #expect(row.challengeState == .empty)
        #expect(row.challengeStateEncrypted?.count == before)
    }

    @Test("A column that is nil, unreadable or of another version reads as empty, and a write replaces it", .ambientTestKeyManager)
    func unreadableReadsEmpty() throws {
        let cm = try makeContactManager()
        var wrongVersion = try ChallengeStateCodec().encode(distinctState())
        wrongVersion[wrongVersion.startIndex] = 0x02
        let strangers: [(String, Data?)] = [
            ("nil", nil),
            ("random bytes", randomBytes(300)),
            ("sealed, wrong version", try wrongVersion.encrypt()),
            ("sealed, short", try Data(count: 64).encrypt()),
        ]
        for (name, held) in strangers {
            let row = try insertRow(challenge: held, in: cm.modelContext)
            #expect(row.challengeState == .empty, "\(name)")

            var state = ChallengeState.empty
            state[depth: 0].verifiedAt = 99
            try cm.store(state, for: row)
            #expect(row.challengeState == state, "\(name): the write replaces what could not be read")
        }
    }

    @Test("Sealing the same state twice gives different bytes", .ambientTestKeyManager)
    func sealingIsRandomised() throws {
        let cm = try makeContactManager()
        let row = try insertRow(in: cm.modelContext)
        try cm.store(ChallengeState.empty, for: row)
        let first = row.challengeStateEncrypted
        try cm.store(ChallengeState.empty, for: row)
        #expect(first != row.challengeStateEncrypted)
    }
}

// MARK: - Migration

@MainActor
@Suite("DatabaseMigration — challenge fields", .serialized)
struct ChallengeFieldMigrationTests {

    private struct OtherFields: Equatable {
        let name: String, prekeys: Data?, card: Data?, depth: Data?, token: Data?, scheme: Int
        @MainActor init(_ row: Contact.Profile) {
            self.name = row.givenName; self.prekeys = row.prekeyRecordEncrypted; self.card = row.introductionCardEncrypted
            self.depth = row.visibleThroughDepth; self.token = row.deletionToken; self.scheme = row.encryptionScheme
        }
    }

    private func container() throws -> ModelContainer {
        let schema = Schema([
            Contact.Profile.self, Contact.Profile.PhoneNumber.self, Contact.Profile.EmailAddress.self,
            Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self, Contact.Profile.Key.self,
        ])
        return try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    }

    @Test("A live row with no column gets a sealed empty state", .ambientTestKeyManager)
    func liveRow() throws {
        let context = ModelContext(try self.container())
        let row = try insertRow(in: context)

        try DatabaseMigration.migrateChallengeFields(modelContext: context)

        #expect(try #require(row.challengeStateEncrypted).count == (try emptySealedLength()))
        #expect(row.challengeState == .empty)
    }

    @Test("A row hidden at a duress depth gets one too", .ambientTestKeyManager)
    func hiddenRow() throws {
        let context = ModelContext(try self.container())
        let row = try insertRow(visibleThroughDepth: 0, in: context)

        try DatabaseMigration.migrateChallengeFields(modelContext: context)

        #expect(try #require(row.challengeStateEncrypted).count == (try emptySealedLength()))
    }

    @Test("A soft-deleted row gets the sealed empty state a deletion writes, even if its token won't decrypt", .ambientTestKeyManager)
    func softDeletedRows() throws {
        let context = ModelContext(try self.container())
        let readable = try insertRow(deletionToken: try Data([1]).encrypt(), in: context)
        let stranded = try insertRow(deletionToken: randomBytes(33), in: context)

        try DatabaseMigration.migrateChallengeFields(modelContext: context)

        #expect(try #require(readable.challengeStateEncrypted).count == (try emptySealedLength()))
        #expect(try #require(stranded.challengeStateEncrypted).count == (try emptySealedLength()))
    }

    @Test("A row that already has a column is left byte for byte, readable or not", .ambientTestKeyManager)
    func existingColumnUnchanged() throws {
        let cm = try makeContactManager()
        let held = try insertRow(in: cm.modelContext)
        try cm.store(distinctState(), for: held)
        let unreadable = try insertRow(challenge: randomBytes(300), in: cm.modelContext)
        let heldBytes = held.challengeStateEncrypted
        let unreadableBytes = unreadable.challengeStateEncrypted

        try DatabaseMigration.migrateChallengeFields(modelContext: cm.modelContext)

        #expect(held.challengeStateEncrypted == heldBytes)
        #expect(unreadable.challengeStateEncrypted == unreadableBytes, "present but unreadable is not nil: the pass leaves it")
    }

    @Test("It changes no other field", .ambientTestKeyManager)
    func otherFieldsUntouched() throws {
        let context = ModelContext(try self.container())
        let rows = [
            try insertRow(in: context),
            try insertRow(visibleThroughDepth: 0, in: context),
            try insertRow(deletionToken: try Data([1]).encrypt(), in: context),
        ]
        try context.save()
        let before = rows.map { OtherFields($0) }

        try DatabaseMigration.migrateChallengeFields(modelContext: context)

        #expect(rows.map { OtherFields($0) } == before)
    }

    @Test("A row still on the v1 scheme is left for migrateToV2", .ambientTestKeyManager)
    func v1RowSkipped() throws {
        let context = ModelContext(try self.container())
        let row = try insertRow(scheme: .v1_identityDerived, in: context)

        try DatabaseMigration.migrateChallengeFields(modelContext: context)

        #expect(row.challengeStateEncrypted == nil)
    }

    /// A stand-in for the legacy and the new crypto, as `MigrateToV2ResilienceTests` uses: `migrateToV2` takes both as
    /// parameters. Not the real keys, which only a device with an Enclave has.
    private struct StubCrypto: LegacyCryptoProtocol {
        let key: SymmetricKey
        func seal(_ text: String) -> String {
            try! AES.GCM.seal(Data(text.utf8), using: self.key, authenticating: EncryptionScheme.v2_hybridPQ.aad).combined!.base64EncodedString()
        }
        func encrypt(data: Data?) throws -> Data? {
            guard let data else { return nil }
            return try AES.GCM.seal(data, using: self.key, authenticating: EncryptionScheme.v2_hybridPQ.aad).combined
        }
        func decrypt(data: Data?) throws -> Data? {
            guard let data else { return nil }
            return try AES.GCM.open(try AES.GCM.SealedBox(combined: data), using: self.key, authenticating: EncryptionScheme.v2_hybridPQ.aad)
        }
        func decryptLegacy(data: Data?) throws -> Data? { try self.decrypt(data: data) }
        func encrypt(message: Data, using material: Data?) throws -> Data? { nil }
        func decrypt(message: Data, using material: Data?) throws -> Data? { nil }
        func sign(data: Data?) throws -> String { "" }
    }

    @Test("A v1 row converted by migrateToV2 is filled by the next pass, and not before", .ambientTestKeyManager)
    func filledAfterConversion() throws {
        let context = ModelContext(try self.container())
        let legacy = StubCrypto(key: SymmetricKey(size: .bits256))
        let new    = StubCrypto(key: SymmetricKey(size: .bits256))
        let row = Contact.Profile(
            identifier: legacy.seal("old"), givenName: legacy.seal("Alice"), familyName: legacy.seal("Wonderland"),
            middleName: "", nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        row.encryptionScheme = EncryptionScheme.v1_identityDerived.rawValue
        context.insert(row)
        try context.save()

        try DatabaseMigration.migrateChallengeFields(modelContext: context)
        #expect(row.challengeStateEncrypted == nil, "a v1 row waits for migrateToV2")

        try DatabaseMigration.migrateToV2(modelContext: context, legacyCrypto: legacy, newCrypto: new)
        #expect(row.encryptionScheme == EncryptionScheme.v2_hybridPQ.rawValue, "precondition: it was converted")
        #expect(row.challengeStateEncrypted == nil, "migrateToV2 doesn't write the column")

        try DatabaseMigration.migrateChallengeFields(modelContext: context)
        #expect(try #require(row.challengeStateEncrypted).count == (try emptySealedLength()))
        #expect(row.challengeState == .empty)
    }

    @Test("A store with no rows does nothing", .ambientTestKeyManager)
    func noRows() throws {
        let context = ModelContext(try self.container())
        try DatabaseMigration.migrateChallengeFields(modelContext: context)
        #expect(try context.fetch(FetchDescriptor<Contact.Profile>()).isEmpty)
    }

    @Test("After the pass every row has one length, it is saved, and a second pass changes nothing", .ambientTestKeyManager)
    func everyRowUniformAndIdempotent() throws {
        let schemaContainer = try self.container()
        let context = ModelContext(schemaContainer)
        try insertRow(in: context)
        try insertRow(visibleThroughDepth: 0, in: context)
        try insertRow(deletionToken: try Data([1]).encrypt(), in: context)
        try insertRow(deletionToken: randomBytes(33), in: context)
        try context.save()

        try DatabaseMigration.migrateChallengeFields(modelContext: context)

        let rows = try ModelContext(schemaContainer).fetch(FetchDescriptor<Contact.Profile>())
        #expect(rows.count == 4)
        #expect(Set(rows.map { $0.challengeStateEncrypted?.count }) == [try emptySealedLength()])

        let before = Dictionary(uniqueKeysWithValues: rows.map { ($0.identifier, $0.challengeStateEncrypted) })
        try DatabaseMigration.migrateChallengeFields(modelContext: context)

        let again = try ModelContext(schemaContainer).fetch(FetchDescriptor<Contact.Profile>())
        #expect(Dictionary(uniqueKeysWithValues: again.map { ($0.identifier, $0.challengeStateEncrypted) }) == before,
                "a second launch must leave every column byte-identical")
    }
}

// MARK: - The ledger over the column

@MainActor
@Suite("Challenge ledger — per-depth slots in the contact's sealed column", .serialized)
struct ChallengeLedgerPersistenceTests {

    private func column(_ contact: Contact.Profile?) throws -> Data {
        let row = try #require(contact)
        return try #require(row.challengeStateEncrypted)
    }

    private func slot(_ depth: Int, of contact: Contact.Profile?) throws -> ChallengeState.Slot {
        try #require(contact).challengeState[depth: depth]
    }

    @Test("A challenge lands in the slot of the depth that made it, and a write at another depth leaves it alone", .ambientTestKeyManager)
    func slotsAreIsolated() throws {
        let clock = ChallengeClock()
        let phone = try ChallengePhone(depth: 0, clock: clock)
        let alice = ChallengeAlice(clock: clock)
        let profile = try alice.profile(in: phone.contacts)

        try phone.coordinator.createChallenge(for: profile, contextNote: nil)
        let atZero = try self.slot(0, of: profile)
        #expect(atZero.challenge != nil)
        #expect(ChallengeState.empty.slots.indices.dropFirst().allSatisfy { profile.challengeState.slots[$0] == .empty })

        phone.endSession()
        try phone.unlock("999999")
        clock.seconds += 5
        try phone.coordinator.createChallenge(for: profile, contextNote: nil)

        let state = profile.challengeState
        #expect(state[depth: 0] == atZero, "slot 0 is unchanged after the depth-1 write")
        #expect(state[depth: 1].challenge != nil && state[depth: 1].challenge != atZero.challenge)
        #expect(state.slots.indices.dropFirst(2).allSatisfy { state.slots[$0] == .empty })

        // And the reverse: settling at depth 0 leaves slot 1 as it is.
        let slotOne = state[depth: 1]
        try phone.unlock("111111")
        let nonce = try #require(atZero.challenge).nonce
        phone.contacts.settle(nonce: nonce, for: "alice", passedAt: clock.date)
        #expect(profile.challengeState[depth: 1] == slotOne)
        #expect(profile.challengeState[depth: 0].challenge == nil)
    }

    @Test("The column stays one sealed length through create, settle and sweep", .ambientTestKeyManager)
    func lengthNeverChanges() throws {
        let clock = ChallengeClock()
        let phone = try ChallengePhone(depth: 0, clock: clock)
        let alice = ChallengeAlice(clock: clock)
        let profile = try alice.profile(in: phone.contacts)
        try phone.contacts.store(ChallengeState.empty, for: profile)
        let expected = try emptySealedLength()
        #expect(try self.column(profile).count == expected)

        try phone.coordinator.createChallenge(for: profile, contextNote: "a question")
        #expect(try self.column(profile).count == expected)

        let reply = try alice.answer(phone.coordinator)
        phone.coordinator.handleInboundChallenge(bundle: reply, envelope: alice.envelope, sender: profile)
        #expect(try self.column(profile).count == expected)

        clock.seconds += IdentityChallenge.timestampStaleThreshold
        phone.coordinator.sweepExpired()
        #expect(try self.column(profile).count == expected)
        #expect(profile.challengeState == .empty)
    }

    @Test("A genuine reply settles the slot and starts the badge; the question is not on disk", .ambientTestKeyManager)
    func settleAndNoteNotOnDisk() throws {
        let clock = ChallengeClock()
        let phone = try ChallengePhone(depth: 0, clock: clock)
        let alice = ChallengeAlice(clock: clock)
        let profile = try alice.profile(in: phone.contacts)

        let question = "Where did we meet in Lisbon?"
        try phone.coordinator.createChallenge(for: profile, contextNote: question)
        let plaintext = try #require(try self.column(profile).decrypt())
        #expect(plaintext.range(of: Data(question.utf8)) == nil, "the owner's own text stays in memory")

        let reply = try alice.answer(phone.coordinator)
        clock.seconds += 30
        phone.coordinator.handleInboundChallenge(bundle: reply, envelope: alice.envelope, sender: profile)

        #expect(phone.coordinator.verificationOutcome?.contextNote == question)
        let settled = try self.slot(0, of: profile)
        #expect(settled.challenge == nil)
        #expect(settled.verifiedAt == UInt64(clock.seconds))
    }

    @Test("A stray reply, and a replay of a settled one, write nothing", .ambientTestKeyManager)
    func strayRepliesLeaveNoTrace() throws {
        let clock = ChallengeClock()
        let phone = try ChallengePhone(depth: 0, clock: clock)
        let alice = ChallengeAlice(clock: clock)
        let profile = try alice.profile(in: phone.contacts)

        try phone.coordinator.createChallenge(for: profile, contextNote: nil)
        let waiting = try self.column(profile)

        phone.coordinator.handleInboundChallenge(bundle: try alice.strayAnswer(), envelope: alice.envelope, sender: profile)
        #expect(try self.column(profile) == waiting, "a reply to a challenge we never sent doesn't touch the column")
        #expect(phone.coordinator.verificationOutcome == nil)

        let reply = try alice.answer(phone.coordinator)
        phone.coordinator.handleInboundChallenge(bundle: reply, envelope: alice.envelope, sender: profile)
        let settled = try self.column(profile)
        phone.coordinator.verificationOutcome = nil
        phone.coordinator.handleInboundChallenge(bundle: reply, envelope: alice.envelope, sender: profile)
        #expect(try self.column(profile) == settled, "a replay finds nothing and writes nothing")
        #expect(phone.coordinator.verificationOutcome == nil)
    }

    @Test("Killed and restarted, a reply made at the real depth still passes, without the question", .ambientTestKeyManager)
    func killThenReplyAtCreatingDepth() throws {
        let clock = ChallengeClock()
        let phone = try ChallengePhone(depth: 0, clock: clock)
        let alice = ChallengeAlice(clock: clock)
        let profile = try alice.profile(in: phone.contacts)
        try phone.coordinator.createChallenge(for: profile, contextNote: "real-depth question")
        let reply = try alice.answer(phone.coordinator)

        let restarted = try phone.restarted(enteringPIN: "111111")
        #expect(restarted.contacts.hasOutstanding(for: "alice", now: clock.date), "the challenge survived the kill")
        let sender = try #require(try restarted.contacts.fetchContact(by: "alice"))
        restarted.coordinator.handleInboundChallenge(bundle: reply, envelope: alice.envelope, sender: sender)

        #expect(restarted.coordinator.verificationOutcome?.passed == true)
        #expect(restarted.coordinator.verificationOutcome?.contextNote == nil, "the question was memory only")
        #expect(restarted.coordinator.verifiedBadge(for: "alice", now: clock.date) != nil)
    }

    @Test("Killed and restarted, the same reply opened at a duress depth shows nothing, and the real depth still has it", .ambientTestKeyManager)
    func killThenReplyAtAnotherDepth() throws {
        let clock = ChallengeClock()
        let phone = try ChallengePhone(depth: 0, clock: clock)
        let alice = ChallengeAlice(clock: clock)
        let profile = try alice.profile(in: phone.contacts)
        try phone.coordinator.createChallenge(for: profile, contextNote: "real-depth question")
        let reply = try alice.answer(phone.coordinator)

        let duress = try phone.restarted(enteringPIN: "111111")
        try duress.unlock("999999")
        #expect(duress.security.currentDepth == 1)
        #expect(!duress.contacts.hasOutstanding(for: "alice", now: clock.date), "no sign of the owner's challenge")
        let sender = try #require(try duress.contacts.fetchContact(by: "alice"))
        duress.coordinator.handleInboundChallenge(bundle: reply, envelope: alice.envelope, sender: sender)
        #expect(duress.coordinator.verificationOutcome == nil)
        #expect(duress.coordinator.verifiedBadge(for: "alice", now: clock.date) == nil)

        try duress.unlock("111111")
        #expect(duress.contacts.hasOutstanding(for: "alice", now: clock.date), "the real depth still waits for its answer")
    }

    @Test("The sweep clears expired slots at every depth, leaves live ones, and writes nothing when none expired", .ambientTestKeyManager)
    func sweepAtEveryDepth() throws {
        let clock = ChallengeClock()
        let phone = try ChallengePhone(depth: 0, clock: clock)
        let alice = ChallengeAlice(clock: clock)
        let profile = try alice.profile(in: phone.contacts)

        try phone.coordinator.createChallenge(for: profile, contextNote: nil)              // depth 0, at t
        phone.endSession()
        try phone.unlock("999999")
        clock.seconds += 1_000
        try phone.coordinator.createChallenge(for: profile, contextNote: nil)              // depth 1, at t + 1000
        let live = try self.slot(1, of: profile)

        phone.coordinator.sweepExpired()
        let untouched = try self.column(profile)
        #expect(try self.slot(0, of: profile).challenge != nil, "nothing has expired yet")
        phone.coordinator.sweepExpired()
        #expect(try self.column(profile) == untouched, "a sweep that finds nothing expired writes nothing")

        clock.seconds += IdentityChallenge.timestampStaleThreshold - 1_000                  // depth 0's is an hour old
        phone.coordinator.sweepExpired()

        #expect(try self.slot(0, of: profile) == .empty, "cleared, though the session is at depth 1")
        #expect(try self.slot(1, of: profile) == live)
    }

    @Test("An unswept expired slot is free to overwrite, and a late reply to it fails", .ambientTestKeyManager)
    func expiredSlotIsFree() throws {
        let clock = ChallengeClock()
        let phone = try ChallengePhone(depth: 0, clock: clock)
        let alice = ChallengeAlice(clock: clock)
        let profile = try alice.profile(in: phone.contacts)

        try phone.coordinator.createChallenge(for: profile, contextNote: "old")
        let late = try alice.answer(phone.coordinator)
        clock.seconds += IdentityChallenge.timestampWindow + 1
        #expect(!phone.contacts.hasOutstanding(for: "alice", now: clock.date))

        phone.coordinator.handleInboundChallenge(bundle: late, envelope: alice.envelope, sender: profile)
        #expect(phone.coordinator.verificationOutcome?.passed == false)
        #expect(try self.slot(0, of: profile).challenge == nil)

        try phone.coordinator.createChallenge(for: profile, contextNote: nil)
        #expect(phone.contacts.hasOutstanding(for: "alice", now: clock.date))
    }

    @Test("A column that can't be read reads as empty, and a new challenge replaces it", .ambientTestKeyManager)
    func unreadableColumn() throws {
        let clock = ChallengeClock()
        let phone = try ChallengePhone(depth: 0, clock: clock)
        let alice = ChallengeAlice(clock: clock)
        let profile = try alice.profile(in: phone.contacts)
        profile.challengeStateEncrypted = randomBytes(300)

        #expect(!phone.contacts.hasOutstanding(for: "alice", now: clock.date))
        phone.coordinator.sweepExpired()
        #expect(profile.challengeStateEncrypted?.count == 300, "the sweep leaves what it can't read")

        try phone.coordinator.createChallenge(for: profile, contextNote: nil)
        #expect(phone.contacts.hasOutstanding(for: "alice", now: clock.date))
        #expect(try self.column(profile).count == (try emptySealedLength()))
    }

    @Test("A challenge to a contact with no row is refused, and nothing is visible for them", .ambientTestKeyManager)
    func unknownContact() throws {
        let clock = ChallengeClock()
        let phone = try ChallengePhone(depth: 0, clock: clock)
        let challenge = IdentityChallenge.OutstandingChallenge(nonce: Data(repeating: 1, count: 32), issuedAt: UInt64(clock.seconds))

        #expect(throws: IdentityChallenge.LedgerError.contactUnknown) {
            try phone.contacts.record(challenge, for: "nobody", now: clock.date)
        }
        #expect(!phone.contacts.hasOutstanding(for: "nobody", now: clock.date))
        #expect(phone.contacts.verifiedAt(for: "nobody") == nil)
    }

    @Test("Deleting the contact empties every depth's slot", .ambientTestKeyManager)
    func deletionEmptiesSlots() throws {
        let clock = ChallengeClock()
        let phone = try ChallengePhone(depth: 0, clock: clock)
        let alice = ChallengeAlice(clock: clock)
        let profile = try alice.profile(in: phone.contacts)

        try phone.coordinator.createChallenge(for: profile, contextNote: nil)
        phone.endSession()
        try phone.unlock("999999")
        try phone.coordinator.createChallenge(for: profile, contextNote: nil)
        #expect(profile.challengeState != .empty)

        try phone.contacts.deleteContact(identifier: "alice")

        #expect(profile.challengeState == .empty)
        #expect(try self.column(profile).count == (try emptySealedLength()))
    }
}

// MARK: - Who writes the column

@Suite("Challenge column — written only by the ledger, the creation and deletion paths, and the launch pass")
struct ChallengeColumnWritersTests {

    /// Mirrors the rule on the sibling columns ("read and written only by ContactManager"): a source-level check,
    /// since nothing else stops a new site from writing a depth's slot with the wrong depth.
    @Test("No source file outside the ledger and the launch pass assigns challengeStateEncrypted")
    func onlyTheLedgerWrites() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let sources = root.appendingPathComponent("Occulta")
        let files = try #require(FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil), "the source tree is readable")

        let allowed: Set<String> = ["ContactManager+ChallengeLedger.swift", "PQmigration.swift"]
        var seen = 0
        var offenders: [String] = []
        for case let url as URL in files where url.pathExtension == "swift" {
            seen += 1
            guard !allowed.contains(url.lastPathComponent) else { continue }
            let text = try String(contentsOf: url, encoding: .utf8)
            for line in text.split(separator: "\n") where line.contains("challengeStateEncrypted") {
                let code = line.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
                if code.range(of: #"challengeStateEncrypted\s*=[^=]"#, options: .regularExpression) != nil {
                    offenders.append("\(url.lastPathComponent): \(line.trimmingCharacters(in: .whitespaces))")
                }
            }
        }
        #expect(seen > 100, "the scan found the sources")
        #expect(offenders.isEmpty, "\(offenders)")
    }
}

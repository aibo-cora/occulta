//
//  PairingStateTests.swift
//  OccultaTests
//
//  Bug 196, stage 2: the state a pairing holds (a routing key with its pair keys, or neither), its fixed-size codec, the
//  sealed column on the peer's `Key` row from insertion to deletion, and the migration that fills it. The column is never
//  nil and always the same sealed length, so it says nothing about which pairings have pair keys.
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

/// A contact with one key, saved the way a pairing saves it: paired when `routingKey` is given (with `keys`, or sample ones),
/// else a pairing with neither.
@MainActor
private func pairedContact(
    _ cm: ContactManager, routingKey: Data?, keys: PairKeys? = nil
) throws -> (contact: Contact.Profile, key: Contact.Profile.Key) {
    try cm.save(contact: Contact.Draft(identifier: UUID().uuidString, givenName: "A", familyName: "B"))
    let contact = try #require(try cm.fetchAllContacts().first)
    let draft = try #require(Contact.Draft.Key(
        material: Data(repeating: 0x04, count: 65), owner: Data(repeating: 0x01, count: 65),
        date: "1", pairing: routingKey.map { .paired(routingKey: $0, keys: keys ?? samplePairKeys()) } ?? .empty
    ))
    try cm.update(key: draft, for: contact.identifier)
    return (contact, try #require(contact.contactPublicKeys?.last))
}

private func half(_ byte: UInt8) -> Data { Data(repeating: byte, count: 32) }

private let everyState: [(name: String, state: PairingState)] = [
    ("none", .empty),
    ("paired, P-256 only", .paired(routingKey: half(0x45), keys: samplePairKeys())),
    ("paired, our ML-DSA key", .paired(routingKey: half(0x46), keys: samplePairKeys(mldsa: true))),
    ("paired, the peer's ML-DSA key", .paired(routingKey: half(0x47), keys: samplePairKeys(peerMLDSA: true))),
    ("paired, both ML-DSA keys", .paired(routingKey: half(0x48), keys: samplePairKeys(mldsa: true, peerMLDSA: true))),
]

// MARK: - The state and its codec

@Suite("Bug 196 — routing key state and codec")
struct PairingCodecTests {

    @Test("Every state round-trips and encodes to the capacity", arguments: everyState.indices)
    func roundTrips(_ index: Int) throws {
        let (name, state) = everyState[index]
        let plaintext = try PairingCodec().encode(state)
        #expect(plaintext.count == PairingCodec.capacity, "\(name)")
        #expect(try PairingCodec().decode(plaintext) == state, "\(name)")
    }

    @Test("The capacity holds the whole layout, with room left for a field a later release adds")
    func capacityHoldsTheLayout() {
        // 2 + 32 routing key, two 258-byte P-256 blob rooms, four 65-byte keys, a 12,290-byte ML-DSA blob room, 1 + 2,592.
        #expect(2 + 32 + 258 * 2 + 65 * 4 + (2 + PairingCodec.mldsaBlobRoom) + (1 + PairingCodec.mldsaKeySize) == 15_693)
        #expect(PairingCodec.capacity >= 15_693)
    }

    @Test("A held routing key lands in its field, ahead of the pair keys; an empty state is zeros past the version")
    func fieldsAreSeparate() throws {
        let held = try PairingCodec().encode(.paired(routingKey: half(0xAA), keys: samplePairKeys()))
        let empty = try PairingCodec().encode(.empty)
        #expect(held[1] == 1)
        #expect(held[2..<34] == half(0xAA))
        #expect(empty[1...] == Data(count: PairingCodec.capacity - 1))
    }

    @Test("Each pair key lands at its own offset and a state's unused room stays zero")
    func pairKeysLandAtTheirOffsets() throws {
        let plaintext = [UInt8](try PairingCodec().encode(.paired(routingKey: half(0x45), keys: samplePairKeys())))
        #expect(plaintext[1] == 1)
        #expect(Array(plaintext[34..<36]) == [0, 143], "the agreement blob's length, big-endian")
        #expect(Set(plaintext[36..<(36 + 143)]) == [0xA1])
        #expect(Set(plaintext[(36 + 143)..<292]) == [0], "the rest of that blob's room is zero")
        #expect(Set(plaintext[550..<615]) == [0xA2] && Set(plaintext[615..<680]) == [0xA4])
        #expect(Set(plaintext[680..<745]) == [0xB1] && Set(plaintext[745..<810]) == [0xB2])
        #expect(Array(plaintext[810..<812]) == [0, 0], "no ML-DSA blob: length zero")
        #expect(plaintext[13_100] == 0, "no peer ML-DSA key")
        #expect(Set(plaintext[15_693...]) == [0])
    }

    @Test("A malformed plaintext is refused")
    func decodeRefuses() throws {
        let good = try PairingCodec().encode(.paired(routingKey: half(1), keys: samplePairKeys(mldsa: true, peerMLDSA: true)))
        #expect(throws: PairingCodec.CodecError.malformed) { try PairingCodec().decode(good.dropLast()) }
        #expect(throws: PairingCodec.CodecError.malformed) { try PairingCodec().decode(Data()) }

        var wrongVersion = good; wrongVersion[0] = 0x01
        #expect(throws: PairingCodec.CodecError.malformed) { try PairingCodec().decode(wrongVersion) }

        var unknownPresence = good; unknownPresence[1] = 2
        #expect(throws: PairingCodec.CodecError.malformed) { try PairingCodec().decode(unknownPresence) }

        var blobLongerThanItsRoom = good; blobLongerThanItsRoom[34] = 0x02; blobLongerThanItsRoom[35] = 0x00
        #expect(throws: PairingCodec.CodecError.malformed) { try PairingCodec().decode(blobLongerThanItsRoom) }

        var noAgreementBlob = good; noAgreementBlob[34] = 0; noAgreementBlob[35] = 0
        #expect(throws: PairingCodec.CodecError.malformed) { try PairingCodec().decode(noAgreementBlob) }

        var unknownPeerMLDSAFlag = good; unknownPeerMLDSAFlag[13_100] = 2
        #expect(throws: PairingCodec.CodecError.malformed) { try PairingCodec().decode(unknownPeerMLDSAFlag) }
    }

    @Test("A key or blob that doesn't fit is refused, never padded or cut")
    func encodeRefuses() {
        #expect(throws: PairingCodec.CodecError.wrongSize) {
            try PairingCodec().encode(.paired(routingKey: Data(count: 31), keys: samplePairKeys()))
        }
        #expect(throws: PairingCodec.CodecError.wrongSize) {
            try PairingCodec().encode(.paired(routingKey: Data(count: 33), keys: samplePairKeys()))
        }

        func paired(_ edit: (inout PairKeys) -> Void) -> PairingState {
            var keys = samplePairKeys(mldsa: true, peerMLDSA: true)
            edit(&keys)
            return .paired(routingKey: half(1), keys: keys)
        }
        let cases: [PairingState] = [
            paired { $0.ourAgreementBlob = Data(count: PairingCodec.p256BlobRoom + 1) },
            paired { $0.ourSigningBlob = Data() },
            paired { $0.ourAgreementKey = Data(count: 64) },
            paired { $0.peerSigningKey = Data(count: 66) },
            paired { $0.ourMLDSABlob = Data(count: PairingCodec.mldsaBlobRoom + 1) },
            paired { $0.peerMLDSAKey = Data(count: 2_591) },
        ]
        for state in cases {
            #expect(throws: PairingCodec.CodecError.wrongSize) { try PairingCodec().encode(state) }
        }
    }

    @Test("An ML-DSA blob exactly as large as its room fits")
    func fullRoomFits() throws {
        var keys = samplePairKeys(peerMLDSA: true)
        keys.ourMLDSABlob = Data(repeating: 0x5A, count: PairingCodec.mldsaBlobRoom)
        keys.ourAgreementBlob = Data(repeating: 0x5B, count: PairingCodec.p256BlobRoom)
        let state = PairingState.paired(routingKey: half(2), keys: keys)
        #expect(try PairingCodec().decode(try PairingCodec().encode(state)) == state)
    }

    @Test("A pairing with pair keys holds them with its routing key and refuses the old form; one without holds neither and accepts it")
    func rules() {
        let paired = PairingState.paired(routingKey: half(3), keys: samplePairKeys())
        #expect(paired.routingKey == half(3) && paired.keys != nil && paired.refusesOldForm)
        #expect(PairingState.empty.routingKey == nil && PairingState.empty.keys == nil && !PairingState.empty.refusesOldForm)
    }
}

// MARK: - The column

@MainActor
@Suite("Bug 196 — the sealed column on the peer's key row", .serialized)
struct PairingColumnTests {

    @Test("A key saved with a routing key and pair keys holds them, sealed", .ambientTestKeyManager)
    func savedWithPairing() throws {
        let (cm, _) = try makeContactManager()
        let (_, key) = try pairedContact(cm, routingKey: half(0x55))
        #expect(key.pairingEncrypted != nil)
        #expect(cm.pairingState(of: key) == .paired(routingKey: half(0x55), keys: samplePairKeys()))
    }

    @Test("A key saved with no pairing holds the sealed empty state, not nil", .ambientTestKeyManager)
    func savedWithoutPairing() throws {
        let (cm, _) = try makeContactManager()
        let (contact, key) = try pairedContact(cm, routingKey: nil)
        #expect(key.pairingEncrypted != nil)
        #expect(cm.pairingState(of: key) == .empty)
        #expect(cm.pairingState(for: contact) == .empty)
    }

    @Test("A second pairing with the same contact has its own routing key; the first row is retired and wiped", .ambientTestKeyManager)
    func rePairRetiresAndWipesTheOldRow() throws {
        let (cm, _) = try makeContactManager()
        let (contact, first) = try pairedContact(cm, routingKey: half(1))
        #expect(cm.pairingState(of: first) == .paired(routingKey: half(1), keys: samplePairKeys()))
        let draft = try #require(Contact.Draft.Key(
            material: Data(repeating: 0x04, count: 65), owner: Data(repeating: 0x01, count: 65),
            date: "2", pairing: .paired(routingKey: half(2), keys: samplePairKeys(mldsa: true))
        ))
        try cm.update(key: draft, for: contact.identifier)

        // Not read through `.last`: a to-many relationship has no order of its own. The current key is the one not retired.
        let keys = try #require(contact.contactPublicKeys)
        #expect(keys.count == 2)
        #expect(cm.pairingState(of: first) == .empty, "a retired pairing's Enclave blobs are overwritten with the sealed empty state")
        #expect(first.expiredOn != nil)
        let current = try #require(contact.currentKey)
        #expect(cm.pairingState(of: current) == .paired(routingKey: half(2), keys: samplePairKeys(mldsa: true)))
        #expect(first.pairingEncrypted?.count == current.pairingEncrypted?.count, "one sealed length for every row")
    }

    @Test("Every state seals to one length, and a created key's field is that length", .ambientTestKeyManager)
    func sealedLengthsMatch() throws {
        let (cm, _) = try makeContactManager()
        let (_, withSecret) = try pairedContact(cm, routingKey: half(9))
        let lengths = try everyState.map { entry -> Int in
            let key = Contact.Profile.Key(owner: Data(), date: Data())
            try cm.store(entry.state, in: key)
            return try #require(key.pairingEncrypted).count
        }
        #expect(Set(lengths).count == 1, "lengths differ: \(lengths)")
        #expect(withSecret.pairingEncrypted?.count == lengths.first)
    }

    @Test("Sealing the same state twice gives different bytes", .ambientTestKeyManager)
    func sealingIsRandomised() throws {
        let (cm, _) = try makeContactManager()
        let key = Contact.Profile.Key(owner: Data(), date: Data())
        try cm.store(.empty, in: key)
        let first = key.pairingEncrypted
        try cm.store(.empty, in: key)
        #expect(first != key.pairingEncrypted, "a fixed nonce would let equal fields be compared without the key")
    }

    @Test("An unreadable seal reads as empty", .ambientTestKeyManager)
    func unreadableReadsEmpty() throws {
        let (cm, _) = try makeContactManager()
        let key = Contact.Profile.Key(owner: Data(), date: Data(), pairingEncrypted: Data(repeating: 1, count: 200))
        #expect(cm.pairingState(of: key) == .empty)
        #expect(cm.pairingState(of: Contact.Profile.Key(owner: Data(), date: Data())) == .empty)
    }

    @Test("Deleting a contact overwrites every key's state with the sealed empty state", .ambientTestKeyManager)
    func deletionOverwrites() throws {
        let (cm, _) = try makeContactManager()
        let (contact, key) = try pairedContact(cm, routingKey: half(0x66), keys: samplePairKeys(mldsa: true, peerMLDSA: true))
        #expect(cm.pairingState(of: key).keys != nil, "a pair-key row is the case the overwrite exists for")
        let before = try #require(key.pairingEncrypted).count

        try cm.deleteContact(identifier: contact.identifier)

        #expect(cm.pairingState(of: key) == .empty)
        #expect(key.pairingEncrypted?.count == before, "the field keeps its length")
    }
}

// MARK: - The migration

@MainActor
@Suite("Bug 196 — the launch migration that fills the column", .serialized)
struct PairingMigrationTests {

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
                material: Data([1]), owner: Data(), date: Data(), pairingEncrypted: field
            ))
        }
        context.insert(profile)
        return profile
    }

    @Test("Every key row without the field gets the sealed empty state", .ambientTestKeyManager)
    func fillsNilRows() throws {
        let (cm, _) = try makeContactManager()
        let row = insert(keys: 3, in: cm.modelContext)

        try DatabaseMigration.migratePairingFields(modelContext: cm.modelContext)

        for key in try #require(row.contactPublicKeys) {
            #expect(key.pairingEncrypted != nil)
            #expect(cm.pairingState(of: key) == .empty)
        }
    }

    @Test("A soft-deleted row is filled too", .ambientTestKeyManager)
    func fillsSoftDeleted() throws {
        let (cm, _) = try makeContactManager()
        let row = insert(keys: 1, deletionToken: Data([1]), in: cm.modelContext)

        try DatabaseMigration.migratePairingFields(modelContext: cm.modelContext)

        #expect(row.contactPublicKeys?.first?.pairingEncrypted != nil)
    }

    @Test("A row that has the field is left byte-identical", .ambientTestKeyManager)
    func leavesFilledRowsAlone() throws {
        let (cm, _) = try makeContactManager()
        let sealed = try cm.sealedPairing(.paired(routingKey: half(0x77), keys: samplePairKeys()))
        let row = insert(keys: 1, field: sealed, in: cm.modelContext)

        try DatabaseMigration.migratePairingFields(modelContext: cm.modelContext)

        #expect(row.contactPublicKeys?.first?.pairingEncrypted == sealed)
    }

    @Test("A row still at the v1 scheme is skipped until migrateToV2 has converted it", .ambientTestKeyManager)
    func skipsV1() throws {
        let (cm, _) = try makeContactManager()
        let row = insert(keys: 1, scheme: .v1_identityDerived, in: cm.modelContext)

        try DatabaseMigration.migratePairingFields(modelContext: cm.modelContext)

        #expect(row.contactPublicKeys?.first?.pairingEncrypted == nil)
    }

    @Test("A row converted from v1 gets the field on the next pass, at the same sealed length as every other", .ambientTestKeyManager)
    func convertedRowIsFilledNextPass() throws {
        let (cm, _) = try makeContactManager()
        let converted = insert(keys: 1, scheme: .v1_identityDerived, in: cm.modelContext)
        let steady = insert(keys: 1, in: cm.modelContext)

        try DatabaseMigration.migratePairingFields(modelContext: cm.modelContext)
        #expect(converted.contactPublicKeys?.first?.pairingEncrypted == nil)

        converted.encryptionScheme = EncryptionScheme.v2_hybridPQ.rawValue
        try DatabaseMigration.migratePairingFields(modelContext: cm.modelContext)

        let sealed = try #require(converted.contactPublicKeys?.first?.pairingEncrypted)
        #expect(sealed.count == steady.contactPublicKeys?.first?.pairingEncrypted?.count)
        #expect(cm.pairingState(of: try #require(converted.contactPublicKeys?.first)) == .empty)
    }

    @Test("Running it again changes nothing", .ambientTestKeyManager)
    func idempotent() throws {
        let (cm, _) = try makeContactManager()
        let row = insert(keys: 2, in: cm.modelContext)

        try DatabaseMigration.migratePairingFields(modelContext: cm.modelContext)
        // As sets: a to-many relationship has no order of its own, and the order isn't what this test is about.
        let first = Set(try #require(row.contactPublicKeys).compactMap(\.pairingEncrypted))
        try DatabaseMigration.migratePairingFields(modelContext: cm.modelContext)

        #expect(first.count == 2)
        #expect(Set(try #require(row.contactPublicKeys).compactMap(\.pairingEncrypted)) == first)
    }

    @Test("It touches no other field of the key", .ambientTestKeyManager)
    func touchesNothingElse() throws {
        let (cm, _) = try makeContactManager()
        let row = insert(keys: 1, in: cm.modelContext)
        let key = try #require(row.contactPublicKeys?.first)
        let (material, owner, date, quantum) = (key.material, key.owner, key.acquiredAt, key.quantumKeyMaterialEncrypted)

        try DatabaseMigration.migratePairingFields(modelContext: cm.modelContext)

        #expect(key.material == material && key.owner == owner && key.acquiredAt == date)
        #expect(key.quantumKeyMaterialEncrypted == quantum)
    }
}

// MARK: - No data loss

@MainActor
@Suite("Bug 196 — the migration for an install from before the change", .serialized)
struct PairingMigrationNoDataLossTests {

    @Test("It leaves every other field of a pre-change contact byte-identical, and the contact's old-form files still open",
          .ambientTestKeyManager)
    func nothingElseChanges() throws {
        let (cm, _) = try makeContactManager()
        let me = try Manager.Ambient.keyManager.retrieveIdentity()
        let sender = TestKeyManager()
        let profile = Contact.Profile(
            identifier: UUID().uuidString, givenName: "", familyName: "", middleName: "", nickname: "",
            organizationName: "", departmentName: "", jobTitle: ""
        )
        profile.encryptionScheme = EncryptionScheme.v2_hybridPQ.rawValue
        profile.contactPublicKeys = [Contact.Profile.Key(
            material: try Manager.Crypto().encrypt(data: try sender.retrieveIdentity()), owner: Data(), date: Data()
        )]
        var record = PrekeyRecord.empty
        record.ownBatches = [PrekeyRecord.OwnBatch(
            id: Data(repeating: 7, count: 16), createdAt: Date(), retiredAt: nil, isPending: true,
            keys: [PrekeyRecord.OwnKey(id: Data(repeating: 9, count: 16), blob: nil, publicKey: Data(repeating: 4, count: 65))]
        )]
        profile.prekeyRecordEncrypted = try PrekeyRecordCodec().encode(record).encrypt()
        profile.maxBundleVersion = try Manager.Crypto().encrypt(data: Data([0x09]))
        try cm.insertProfile(profile)

        let (prekeys, tier, scheme) = (profile.prekeyRecordEncrypted, profile.maxBundleVersion, profile.encryptionScheme)

        try DatabaseMigration.migratePairingFields(modelContext: cm.modelContext)

        #expect(profile.prekeyRecordEncrypted == prekeys)
        #expect(profile.maxBundleVersion == tier)
        #expect(profile.encryptionScheme == scheme)
        #expect(cm.pairingState(for: profile) == .empty)

        // An old-form file from them still opens: nothing about the pairing changed.
        let bundle = try Manager.Crypto(keyManager: sender).seal(
            sealedPayload: OccultaBundle.SealedPayload(message: Data("hello".utf8), appVersion: "1.11.1"), groupID: UUID(),
            recipients: [GroupRecipient(publicKey: me, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)]
        )
        #expect(try cm.openGroup(bundle: bundle).ownerID == profile.identifier)
    }
}

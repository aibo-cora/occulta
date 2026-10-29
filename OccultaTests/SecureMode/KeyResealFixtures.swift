//
//  KeyResealFixtures.swift
//  OccultaTests
//
//  What the key reseal tests (Bug 171, Stage 2) are built on: a frozen key manager, a store sealed the way the
//  release before the fix sealed it, and the checks that say where each sealed value now stands.
//
//  Frozen. `TestKeyManager.frozen()` has fixed scalars, fixed tier secrets and a fixed ML-KEM record, and the keys it
//  derives are pinned below as hex. A fixture is sealed with the pinned bytes, not with `legacyKey(_:)`: a test sealed
//  through the code it checks would follow any edit to that code and still agree with itself. If the legacy
//  derivation ever changes, `FrozenKeyTests` fails on the pin, and the fixtures still stand for what real stores hold.
//
//  The store. `LegacyStore.seed(…)` writes one sealed value for every inventory entry that tier U owns: the local
//  key's `Data` and `String` fields (as base64 where the model stores a string), the five custody models and the
//  restore buffer, the retired rows a later pass still reads (`ReconstructShard`, `forwardSecrecyEncrypted`), and the
//  random filler of the containers that mix real and filler members. It also records what the pass must leave alone:
//  `Contact.Profile.identifier`, and the vault's and the PIN's fields, which later stages move.
//

import Testing
import CryptoKit
import Foundation
import SwiftData

@testable import Occulta
@testable import OccultaCore
@testable import OccultaFormats

// MARK: - The pinned keys

/// Whether the device is on iOS 26+ (hybrid) or below (classical). Everything that depends on it runs in both.
enum KeyForm: String, CaseIterable, Sendable {
    case hybrid
    case classical
}

/// Whose key seals a value.
enum KeyOwner: Sendable {
    case local
    case custody
    case restore
}

enum Frozen {

    /// Five private scalars, in the order `TestKeyManager.init(scalars:)` takes them: identity, local DB, vault, shard
    /// custody, PIN. Bytes in 1...120, so each is far below the curve order.
    static let scalars: [Data] = (0..<5).map { k in
        var data = Data()
        for i in 0..<32 {
            let value: Int = 1 + ((k * 37 + i * 11) % 120)
            data.append(UInt8(value))
        }
        return data
    }

    /// `r_U`: C0 C1 … DF.
    static let tierSecretU: Data = {
        var data = Data()
        for i in 0..<32 { data.append(UInt8(0xC0 + i)) }
        return data
    }()

    /// `r_B`: E0 E1 … FF.
    static let tierSecretB: Data = {
        var data = Data()
        for i in 0..<32 { data.append(UInt8(0xE0 + i)) }
        return data
    }()

    /// The hybrid record of tier U: the in-memory ML-KEM key from the 64-byte seed 00 … 3F and a ciphertext to it.
    static let recordU: TierPQRecord = {
        // swiftlint:disable:next force_try
        try! TierPQRecord.hybrid(keyBlob: katPQSeed, ciphertext: katPQCiphertext)
    }()

    // MARK: Pinned bytes (computed once by an independent script, from the scalars above)

    static let legacyLocal   = "bb66005d48c1543eac69eea04412129024d13820724b2a6868a882f4cd3b85ed"
    static let legacyCustody = "82c28a656f3f49a52584dd0106f6deaf673432561662b3568f4965205c172ee6"
    static let legacyRestore = "1eebdd02bb76127db54bf89840c212a5ac2be4fd8b3c327c530e6c23ee36b1fd"

    static let classicalLocal   = "20740f11cb3dd14f864182b3c47d91f8c9c762eb21da8321ce73fe29d569fbf9"
    static let classicalCustody = "2f3e82432b237e48cafcde9b51fa1afc9fe747a38ffa5aa744a1890fea078184"
    static let classicalRestore = "ce8aa413db1a68dd11c7ab8b9675e53708b75d44873367e04a7613e3deeeb1ff"

    static let hybridLocal   = "681181e0f7d41895eab933788f578dac52b3c5987baeb6cc0ab496ceccf097cd"
    static let hybridCustody = "a74d9a3f78d19a696234a8d662d9ef95d21a61b0d042572820ae57889b5863a3"
    static let hybridRestore = "dd95b4161cef6fd0e0823a4a03ac876d5831ed2cc4aa7c3e1718026ea1fd6ca9"

    static func legacyKey(_ owner: KeyOwner) -> SymmetricKey {
        switch owner {
        case .local:   return SymmetricKey(data: dataFromHex(Self.legacyLocal))
        case .custody: return SymmetricKey(data: dataFromHex(Self.legacyCustody))
        case .restore: return SymmetricKey(data: dataFromHex(Self.legacyRestore))
        }
    }

    static func newKey(_ owner: KeyOwner, form: KeyForm) -> SymmetricKey {
        switch (owner, form) {
        case (.local, .classical):   return SymmetricKey(data: dataFromHex(Self.classicalLocal))
        case (.custody, .classical): return SymmetricKey(data: dataFromHex(Self.classicalCustody))
        case (.restore, .classical): return SymmetricKey(data: dataFromHex(Self.classicalRestore))
        case (.local, .hybrid):      return SymmetricKey(data: dataFromHex(Self.hybridLocal))
        case (.custody, .hybrid):    return SymmetricKey(data: dataFromHex(Self.hybridCustody))
        case (.restore, .hybrid):    return SymmetricKey(data: dataFromHex(Self.hybridRestore))
        }
    }

    /// The epoch the pass writes for `form`.
    static func epoch(_ form: KeyForm) -> KeyReseal.Epoch {
        KeyReseal.Epoch(number: 1, form: form == .hybrid ? .hybrid : .classical)
    }
}

extension TestKeyManager {

    /// The frozen manager, in the form of an iOS 26+ device: hybrid record in tier U, classical in tier B.
    static func frozen() -> TestKeyManager {
        TestKeyManager(
            scalars: Frozen.scalars, tierSecretU: Frozen.tierSecretU, tierSecretB: Frozen.tierSecretB,
            tierPQRecordU: Frozen.recordU, tierPQRecordB: .classical
        )
    }

    /// The frozen manager as a device below iOS 26 has it: a classical record, and no ML-KEM.
    func becomeClassical() {
        self.tierPQRecordU = .classical
        self.simulatesNoPostQuantum = true
    }

    /// The frozen manager as an iOS 26+ device has it.
    func becomeHybrid() {
        self.tierPQRecordU = Frozen.recordU
        self.simulatesNoPostQuantum = false
    }

    func become(_ form: KeyForm) {
        switch form {
        case .hybrid:    self.becomeHybrid()
        case .classical: self.becomeClassical()
        }
    }
}

// MARK: - Sealing and opening, with explicit keys

enum Sealing {

    /// AES-GCM as every local value is sealed: the scheme's one-byte AAD, `[2]`.
    static let fixedAAD = Data([2])

    static func seal(_ plaintext: Data, key: SymmetricKey, aad: Data?) -> Data {
        let sealed: AES.GCM.SealedBox
        if let aad {
            sealed = try! AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(), authenticating: aad)
        } else {
            sealed = try! AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce())
        }
        return sealed.combined!
    }

    static func open(_ sealed: Data, key: SymmetricKey, aad: Data?) -> Data? {
        guard let box = try? AES.GCM.SealedBox(combined: sealed) else { return nil }

        if let aad { return try? AES.GCM.open(box, using: key, authenticating: aad) }
        return try? AES.GCM.open(box, using: key)
    }

    static func random(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }

    /// A key no one holds, for the value that opens under neither.
    static let stranger = SymmetricKey(data: Data(repeating: 0x5A, count: 32))
}

/// Where a sealed value stands.
enum SlotState: Equatable, CustomStringConvertible {
    case legacy
    case new
    case neither
    case absent

    var description: String {
        switch self {
        case .legacy:  return "legacy"
        case .new:     return "new"
        case .neither: return "neither"
        case .absent:  return "absent"
        }
    }
}

// MARK: - The store

@MainActor
final class LegacyStore {

    /// One sealed value of an inventory entry.
    struct Slot {
        /// `Model.attribute`, with `[i]` for an element of an array.
        let name: String
        /// `Model.attribute`.
        let entry: String
        let owner: KeyOwner
        let plaintext: Data
        let aad: Data?
        /// The stored bytes as seeded.
        let before: Data
        /// The stored bytes now, read from `context`; nil if the row or the value is gone.
        let load: (ModelContext) -> Data?
        /// Overwrites the stored bytes, for a test that plays the previous release writing after a downgrade. nil
        /// where the model doesn't let a test write: `Group`'s slot arrays are `private(set)`.
        let write: ((ModelContext, Data) -> Void)?
    }

    /// A stored value the pass must not change.
    struct Probe {
        let name: String
        let before: Data
        let load: (ModelContext) -> Data?
    }

    let container: ModelContainer
    let keys: TestKeyManager

    private(set) var slots: [Slot] = []
    /// `Contact.Profile.identifier`, byte for byte.
    private(set) var references: [Probe] = []
    /// The vault's and the PIN's sealed fields, which later stages move.
    private(set) var untouched: [Probe] = []
    /// Random filler in containers that also hold real values.
    private(set) var fillers: [Probe] = []

    /// The identifier of the live contact, as stored (base64 of a sealed value), and the three records that carry it
    /// as a value: a group slot, a draft's recipient and a custody payload.
    private(set) var identifier = ""

    /// The secret the restore buffer row holds a shard for, and that shard's `SignedAttribute.id`.
    private(set) var restoreDistributionID = UUID()
    private(set) var restoreAttributeID = UUID()

    /// The same for the retired `ReconstructShard` row, which `VaultManager.unlock` moves into the restore buffer.
    private(set) var reconstructDistributionID = UUID()
    private(set) var reconstructAttributeID = UUID()

    /// Entries a launch pass consumes or deletes by design, so their rows are not there afterwards.
    static let consumedByLaunchPasses: Set<String> = ["GlobalShardConfig.encryptedPayload", "Profile.forwardSecrecyEncrypted"]

    private struct Pending {
        let name: String
        let entry: String
        let kind: Kind
        let owner: KeyOwner
        let plaintext: Data
        let aad: Data?
        let before: Data
        let load: (ModelContext) -> Data?
        var write: ((ModelContext, Data) -> Void)? = nil

        enum Kind { case slot, reference, untouched, filler }
    }

    private var pending: [Pending] = []
    private let context: ModelContext

    init(keys: TestKeyManager) throws {
        let schema = OccultaApp.schema
        self.container = try ModelContainer(for: schema, configurations: ModelConfiguration(schema: schema, isStoredInMemoryOnly: true))
        self.context   = ModelContext(self.container)
        self.keys      = keys
        self.context.autosaveEnabled = false
    }

    // MARK: Reading

    func newContext() -> ModelContext {
        let context = ModelContext(self.container)
        context.autosaveEnabled = false
        return context
    }

    /// Where `slot` stands now. A value that opens under the new key to its plaintext is `.new`; under the legacy key
    /// to its plaintext, `.legacy`.
    func state(of slot: Slot, form: KeyForm, in context: ModelContext) -> SlotState {
        self.state(of: slot, newKey: Frozen.newKey(slot.owner, form: form), in: context)
    }

    /// `state(of:form:in:)` for a store whose new keys aren't the pinned ones, because the bootstrap created the
    /// record or the secret they come from: the new key is whatever `keys` derives now.
    func state(of slot: Slot, derivedBy keys: TestKeyManager, in context: ModelContext) -> SlotState {
        let key: EnclaveBoundKey
        switch slot.owner {
        case .local:   key = .localDB
        case .custody: key = .shardCustody
        case .restore: key = .restoreVault
        }
        return self.state(of: slot, newKey: try? keys.enclaveBoundKey(key), in: context)
    }

    private func state(of slot: Slot, newKey: SymmetricKey?, in context: ModelContext) -> SlotState {
        guard let current = slot.load(context) else { return .absent }

        if let newKey, let opened = Sealing.open(current, key: newKey, aad: slot.aad), opened == slot.plaintext {
            return .new
        }
        if let opened = Sealing.open(current, key: Frozen.legacyKey(slot.owner), aad: slot.aad), opened == slot.plaintext {
            return .legacy
        }
        return .neither
    }

    /// Slots grouped by entry: what the report's resealed count for an entry must equal.
    var seededCounts: [String: Int] {
        Dictionary(grouping: self.slots, by: \.entry).mapValues(\.count)
    }

    /// The row count of every model in the schema, by entity name.
    func rowCounts(in context: ModelContext) throws -> [String: Int] {
        var counts: [String: Int] = [:]
        counts["Profile"]                    = try context.fetchCount(FetchDescriptor<Contact.Profile>())
        counts["PhoneNumber"]                = try context.fetchCount(FetchDescriptor<Contact.Profile.PhoneNumber>())
        counts["EmailAddress"]               = try context.fetchCount(FetchDescriptor<Contact.Profile.EmailAddress>())
        counts["PostalAddress"]              = try context.fetchCount(FetchDescriptor<Contact.Profile.PostalAddress>())
        counts["URLAddress"]                 = try context.fetchCount(FetchDescriptor<Contact.Profile.URLAddress>())
        counts["Key"]                        = try context.fetchCount(FetchDescriptor<Contact.Profile.Key>())
        counts["Message"]                    = try context.fetchCount(FetchDescriptor<Contact.Message>())
        counts["Draft"]                      = try context.fetchCount(FetchDescriptor<Message.Draft>())
        counts["Group"]                      = try context.fetchCount(FetchDescriptor<Group>())
        counts["VaultEntry"]                 = try context.fetchCount(FetchDescriptor<VaultEntry>())
        counts["CustodyShard"]               = try context.fetchCount(FetchDescriptor<CustodyShard>())
        counts["PendingShardDistribute"]     = try context.fetchCount(FetchDescriptor<PendingShardDistribute>())
        counts["PendingShardStatusUpdate"]   = try context.fetchCount(FetchDescriptor<PendingShardStatusUpdate>())
        counts["PotentiallyLostShard"]       = try context.fetchCount(FetchDescriptor<PotentiallyLostShard>())
        counts["GlobalShardConfig"]          = try context.fetchCount(FetchDescriptor<GlobalShardConfig>())
        counts["ReconstructShard"]           = try context.fetchCount(FetchDescriptor<ReconstructShard>())
        counts["PendingShamirSecretRestore"] = try context.fetchCount(FetchDescriptor<PendingShamirSecretRestore>())
        counts["BackupEncryptionKey"]        = try context.fetchCount(FetchDescriptor<BackupEncryptionKey>())
        counts["AppLayerConfig"]             = try context.fetchCount(FetchDescriptor<AppLayerConfig>())
        counts["Vault"]                      = try context.fetchCount(FetchDescriptor<Vault>())
        return counts
    }

    // MARK: Playing the previous release

    /// What a downgrade looks like to the store: the older schema has no epoch columns, so both are gone, and the
    /// older release wrote some of the values it could write back under the legacy key (every `step`-th one that a
    /// test can write, and none of the two the launch passes consume). Returns the names it wrote.
    @discardableResult
    func downgrade(every step: Int = 3) throws -> [String] {
        let context = self.newContext()
        var written: [String] = []

        for (index, slot) in self.slots.enumerated() where index % step == 0 && !Self.consumedByLaunchPasses.contains(slot.entry) {
            guard let write = slot.write else { continue }
            write(context, Sealing.seal(slot.plaintext, key: Frozen.legacyKey(slot.owner), aad: slot.aad))
            written.append(slot.name)
        }

        if let config = try context.fetch(FetchDescriptor<AppLayerConfig>()).first {
            config.keyEpoch      = nil
            config.vaultKeyEpoch = nil
        }
        try context.save()
        return written
    }

    /// A contact the older release added after the downgrade: one field, sealed under the legacy key
    /// (`previousReleaseName`).
    func addContactWrittenByThePreviousRelease() throws -> PersistentIdentifier {
        let context = self.newContext()
        let profile = Contact.Profile(
            identifier: "", givenName: "", familyName: "", middleName: "", nickname: "",
            organizationName: "", departmentName: "", jobTitle: "",
            encryptionScheme: EncryptionScheme.v2_hybridPQ.rawValue
        )
        profile.givenName = Sealing.seal(Data(Self.previousReleaseName.utf8), key: Frozen.legacyKey(.local), aad: Sealing.fixedAAD).base64EncodedString()
        context.insert(profile)
        try context.save()
        return profile.persistentModelID
    }

    static let previousReleaseName = "Written by the previous release"

    /// A live contact whose prekey state is still in the retired `forwardSecrecyEncrypted` and which has no
    /// `prekeyRecordEncrypted`, sealed under the legacy key: the launch pass `migratePrekeyRecords` carries it over.
    /// `expected` is the record that carrying over produces when the value opens.
    func addPrekeyCarrier() throws -> (id: PersistentIdentifier, expected: PrekeyRecord) {
        var legacy = ForwardSecrecy()
        legacy.encodedPrekeys = try [UUID().uuidString].map {
            try JSONEncoder().encode(Prekey(id: $0, contactID: "", publicKey: Data(repeating: 0x04, count: 65)))
        }
        legacy.latestPrekeysGeneratedAt = Date(timeIntervalSince1970: 1_800_000_000)
        legacy.pendingOutboundBatch = try JSONEncoder().encode(OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Date(timeIntervalSince1970: 1_800_000_000),
            prekeys: [OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: Data(repeating: 0x04, count: 65))]
        ))
        let json     = try JSONEncoder().encode(legacy)
        let expected = try PrekeyRecordCodec().decode(json)

        let context = self.newContext()
        let profile = Contact.Profile(
            identifier: UUID().uuidString, givenName: "", familyName: "", middleName: "", nickname: "",
            organizationName: "", departmentName: "", jobTitle: "",
            encryptionScheme: EncryptionScheme.v2_hybridPQ.rawValue
        )
        profile.retiredForwardSecrecyEncrypted = Sealing.seal(json, key: Frozen.legacyKey(.local), aad: Sealing.fixedAAD)
        profile.prekeyRecordEncrypted = nil
        context.insert(profile)
        try context.save()
        return (profile.persistentModelID, expected)
    }

    /// The prekey record of `id`, opened with `key`; nil if it doesn't open or doesn't decode.
    func prekeyRecord(of id: PersistentIdentifier, openedWith key: SymmetricKey) -> PrekeyRecord? {
        guard
            let profile = Self.fetch(Contact.Profile.self, id, in: self.newContext()),
            let field   = profile.prekeyRecordEncrypted,
            let plain   = Sealing.open(field, key: key, aad: Sealing.fixedAAD)
        else { return nil }
        return try? PrekeyRecordCodec().decode(plain)
    }

    /// The first name field of `id`, opened with `key`.
    func givenName(of id: PersistentIdentifier, openedWith key: SymmetricKey) -> String? {
        guard
            let profile = Self.fetch(Contact.Profile.self, id, in: self.newContext()),
            let sealed  = Data(base64Encoded: profile.givenName),
            let plain   = Sealing.open(sealed, key: key, aad: Sealing.fixedAAD)
        else { return nil }
        return String(data: plain, encoding: .utf8)
    }

    // MARK: Tracking

    private static func fetch<M: PersistentModel>(_ type: M.Type, _ id: PersistentIdentifier, in context: ModelContext) -> M? {
        var descriptor = FetchDescriptor<M>(predicate: #Predicate<M> { $0.persistentModelID == id })
        descriptor.fetchLimit = 1
        return (try? context.fetch(descriptor))?.first
    }

    private func track<M: PersistentModel>(
        _ kind: Pending.Kind, _ model: M, entry: String, name: String? = nil, owner: KeyOwner = .local,
        plaintext: Data = Data(), aad: Data? = Sealing.fixedAAD, before: Data, read: @escaping (M) -> Data?,
        write: ((M, Data) -> Void)? = nil
    ) {
        self.pending.append(Pending(
            name: name ?? entry, entry: entry, kind: kind, owner: owner, plaintext: plaintext, aad: aad, before: before,
            load: { context in
                // The identifier is permanent once saved; read lazily, after the seeding context saved.
                guard let found = Self.fetch(M.self, model.persistentModelID, in: context) else { return nil }
                return read(found)
            },
            write: write.map { write in
                { context, bytes in
                    if let found = Self.fetch(M.self, model.persistentModelID, in: context) { write(found, bytes) }
                }
            }
        ))
    }

    private func sealed(_ plaintext: Data, _ owner: KeyOwner, aad: Data? = Sealing.fixedAAD) -> Data {
        Sealing.seal(plaintext, key: Frozen.legacyKey(owner), aad: aad)
    }

    /// Seals `plaintext` into an optional `Data` property and tracks it.
    @discardableResult
    private func data<M: PersistentModel>(
        _ model: M, _ entry: String, _ keyPath: ReferenceWritableKeyPath<M, Data?>, owner: KeyOwner = .local,
        plaintext: Data? = nil, aad: Data? = Sealing.fixedAAD, name: String? = nil
    ) -> Data {
        let plain  = plaintext ?? Data("fixture \(entry)".utf8)
        let bytes  = self.sealed(plain, owner, aad: aad)
        model[keyPath: keyPath] = bytes
        self.track(.slot, model, entry: entry, name: name, owner: owner, plaintext: plain, aad: aad, before: bytes,
                   read: { $0[keyPath: keyPath] }, write: { $0[keyPath: keyPath] = $1 })
        return bytes
    }

    /// Seals `plaintext` into a non-optional `Data` property and tracks it.
    @discardableResult
    private func data<M: PersistentModel>(
        _ model: M, _ entry: String, _ keyPath: ReferenceWritableKeyPath<M, Data>, owner: KeyOwner = .local,
        plaintext: Data? = nil, aad: Data? = Sealing.fixedAAD, name: String? = nil
    ) -> Data {
        let plain  = plaintext ?? Data("fixture \(entry)".utf8)
        let bytes  = self.sealed(plain, owner, aad: aad)
        model[keyPath: keyPath] = bytes
        self.track(.slot, model, entry: entry, name: name, owner: owner, plaintext: plain, aad: aad, before: bytes,
                   read: { $0[keyPath: keyPath] }, write: { $0[keyPath: keyPath] = $1 })
        return bytes
    }

    /// Seals into a `String` property as base64, which is how the contact models store their fields, and tracks it.
    private func string<M: PersistentModel>(_ model: M, _ entry: String, _ keyPath: ReferenceWritableKeyPath<M, String>, _ value: String) {
        let plain = Data(value.utf8)
        let bytes = self.sealed(plain, .local)
        model[keyPath: keyPath] = bytes.base64EncodedString()
        self.track(.slot, model, entry: entry, plaintext: plain, before: bytes, read: { Data(base64Encoded: $0[keyPath: keyPath]) },
                   write: { $0[keyPath: keyPath] = $1.base64EncodedString() })
    }

    private func string<M: PersistentModel>(_ model: M, _ entry: String, _ keyPath: ReferenceWritableKeyPath<M, String?>, _ value: String) {
        let plain = Data(value.utf8)
        let bytes = self.sealed(plain, .local)
        model[keyPath: keyPath] = bytes.base64EncodedString()
        self.track(.slot, model, entry: entry, plaintext: plain, before: bytes, read: { $0[keyPath: keyPath].flatMap { Data(base64Encoded: $0) } },
                   write: { $0[keyPath: keyPath] = $1.base64EncodedString() })
    }

    /// Seals each plaintext into an array property, tracking every element.
    private func array<M: PersistentModel>(
        _ model: M, _ entry: String, _ keyPath: ReferenceWritableKeyPath<M, [Data]>, _ plaintexts: [Data], owner: KeyOwner = .local
    ) {
        let sealedElements = plaintexts.map { self.sealed($0, owner) }
        model[keyPath: keyPath] = sealedElements
        for (index, plain) in plaintexts.enumerated() {
            self.track(.slot, model, entry: entry, name: "\(entry)[\(index)]", owner: owner, plaintext: plain, before: sealedElements[index],
                       read: { $0[keyPath: keyPath].indices.contains(index) ? $0[keyPath: keyPath][index] : nil },
                       write: { model, bytes in
                           var elements = model[keyPath: keyPath]
                           if elements.indices.contains(index) { elements[index] = bytes; model[keyPath: keyPath] = elements }
                       })
        }
    }

    // MARK: Seeding

    /// Seeds one sealed value for every inventory entry tier U owns, plus what must stay put.
    ///
    /// - Parameter gateDepth: The depth at which the PIN gate is lowered, as a user under coercion leaves it. The
    ///   persisted depth is that depth too. Both are what `Manager.Security.init` restores.
    func seed(gateDepth: Int = 2) throws {
        let ctx = self.context

        try self.seedContacts(into: ctx)
        try self.seedGroups(into: ctx)
        try self.seedDrafts(into: ctx)
        try self.seedVault(into: ctx)
        try self.seedCustodyAndRestore(into: ctx)
        try self.seedConfig(into: ctx, gateDepth: gateDepth)

        try ctx.save()
        self.finalize()
    }

    /// The contact whose fields cover the inventory: every string, every `Data`, the four child models and a key.
    private func seedContacts(into ctx: ModelContext) throws {
        let profile = Contact.Profile(
            identifier: "", givenName: "", familyName: "", middleName: "", nickname: "",
            organizationName: "", departmentName: "", jobTitle: "",
            encryptionScheme: EncryptionScheme.v2_hybridPQ.rawValue
        )
        ctx.insert(profile)

        // The identifier is sealed like any field, and is left exactly as it is.
        let identifierPlain = Data("fixture identifier".utf8)
        let identifierBytes = self.sealed(identifierPlain, .local)
        profile.identifier = identifierBytes.base64EncodedString()
        self.identifier    = profile.identifier
        self.pending.append(Pending(
            name: "Profile.identifier", entry: "Profile.identifier", kind: .reference, owner: .local, plaintext: identifierPlain,
            aad: Sealing.fixedAAD, before: identifierBytes,
            load: { context in Self.fetch(Contact.Profile.self, profile.persistentModelID, in: context).flatMap { Data(base64Encoded: $0.identifier) } }
        ))

        self.string(profile, "Profile.givenName", \.givenName, "Alice")
        self.string(profile, "Profile.familyName", \.familyName, "Wonderland")
        self.string(profile, "Profile.middleName", \.middleName, "Elizabeth")
        self.string(profile, "Profile.namePrefix", \.namePrefix, "Dr")
        self.string(profile, "Profile.nameSuffix", \.nameSuffix, "PhD")
        self.string(profile, "Profile.nickname", \.nickname, "AW")
        self.string(profile, "Profile.organizationName", \.organizationName, "Wonderland Enterprises")
        self.string(profile, "Profile.departmentName", \.departmentName, "Engineering")
        self.string(profile, "Profile.jobTitle", \.jobTitle, "Software Engineer")
        self.string(profile, "Profile.phoneticGivenName", \.phoneticGivenName, "AH-lis")
        self.string(profile, "Profile.phoneticMiddleName", \.phoneticMiddleName, "eh-LIZ")
        self.string(profile, "Profile.phoneticFamilyName", \.phoneticFamilyName, "WUN-der-land")
        self.string(profile, "Profile.birthday", \.birthday, "1/1/90")
        self.string(profile, "Profile.note", \.note, "Fell down a hole")

        self.data(profile, "Profile.thumbnailImageData", \.thumbnailImageData, plaintext: Sealing.random(2_000))
        self.data(profile, "Profile.imageData", \.imageData, plaintext: Sealing.random(9_000))
        self.data(profile, "Profile.prekeyRecordEncrypted", \.prekeyRecordEncrypted, plaintext: Sealing.random(PrekeyRecordCodec.capacity))
        self.data(profile, "Profile.introductionCardEncrypted", \.introductionCardEncrypted, plaintext: Sealing.random(CardStateCodec.capacity))
        self.data(profile, "Profile.challengeStateEncrypted", \.challengeStateEncrypted, plaintext: Sealing.random(ChallengeStateCodec.capacity))
        self.data(profile, "Profile.forwardSecrecyEncrypted", \.retiredForwardSecrecyEncrypted)
        self.data(profile, "Profile.signedAttributes", \.signedAttributes)
        self.data(profile, "Profile.globalTrusteeDepth", \.globalTrusteeDepth, plaintext: DepthCodec.encode(-1))
        self.data(profile, "Profile.maxBundleVersion", \.maxBundleVersion, plaintext: Data([3]))
        self.data(profile, "Profile.visibleThroughDepth", \.visibleThroughDepth, plaintext: DepthCodec.encode(Int.max))
        self.data(profile, "Profile.originDepth", \.originDepth, plaintext: DepthCodec.encode(0))

        let phone = Contact.Profile.PhoneNumber(label: "", value: "")
        phone.profile = profile
        ctx.insert(phone)
        self.string(phone, "PhoneNumber.label", \.label, "mobile")
        self.string(phone, "PhoneNumber.value", \.value, "+1 555 0100")

        let email = Contact.Profile.EmailAddress(label: "", value: "")
        email.profile = profile
        ctx.insert(email)
        self.string(email, "EmailAddress.label", \.label, "work")
        self.string(email, "EmailAddress.value", \.value, "alice@example.com")

        let postal = Contact.Profile.PostalAddress(label: "", street: "", city: "", state: "", postalCode: "", country: "", isoCountryCode: "")
        postal.profile = profile
        ctx.insert(postal)
        self.string(postal, "PostalAddress.label", \.label, "home")
        self.string(postal, "PostalAddress.street", \.street, "1 Rabbit Hole")
        self.string(postal, "PostalAddress.city", \.city, "Oxford")
        self.string(postal, "PostalAddress.state", \.state, "Oxon")
        self.string(postal, "PostalAddress.postalCode", \.postalCode, "OX1")
        self.string(postal, "PostalAddress.country", \.country, "United Kingdom")
        self.string(postal, "PostalAddress.isoCountryCode", \.isoCountryCode, "GB")

        let url = Contact.Profile.URLAddress(label: "", value: "")
        url.profile = profile
        ctx.insert(url)
        self.string(url, "URLAddress.label", \.label, "homepage")
        self.string(url, "URLAddress.value", \.value, "https://example.com")

        let key = Contact.Profile.Key(material: nil, owner: Data(), date: Data())
        key.profile = profile
        ctx.insert(key)
        self.data(key, "Key.material", \.material)
        self.data(key, "Key.acquiredAt", \.acquiredAt)
        self.data(key, "Key.owner", \.owner)
        self.data(key, "Key.expiredOn", \.expiredOn)
        self.data(key, "Key.quantumKeyMaterialEncrypted", \.quantumKeyMaterialEncrypted)

        // A soft-deleted contact: the one place `Profile.deletionToken` is set. Its stamps are left nil, so the scrub
        // pass that owns soft-deleted rows has nothing to rewrite.
        let deleted = Contact.Profile(
            identifier: "", givenName: "", familyName: "", middleName: "", nickname: "",
            organizationName: "", departmentName: "", jobTitle: "",
            encryptionScheme: EncryptionScheme.v2_hybridPQ.rawValue
        )
        ctx.insert(deleted)
        self.data(deleted, "Profile.deletionToken", \.deletionToken, plaintext: Data([1]))
        self.sealedRecordsOfADeletedContact(deleted)

        // The retired model nothing reads: still in the schema, still sealed if a row exists.
        let message = Contact.Message(origin: nil, recipients: nil, content: Data())
        ctx.insert(message)
        self.string(message, "Message.origin", \.origin, "fixture origin")
        self.array(message, "Message.recipients", \.recipientsOrEmpty, [Data("recipient one".utf8), Data("recipient two".utf8)])
        self.data(message, "Message.content", \.content)
    }

    /// A soft-deleted contact still carries the two fixed-size records, so the passes that fill nil ones leave it be.
    private func sealedRecordsOfADeletedContact(_ deleted: Contact.Profile) {
        self.data(deleted, "Profile.prekeyRecordEncrypted", \.prekeyRecordEncrypted, plaintext: Data(count: 64), name: "Profile.prekeyRecordEncrypted (soft-deleted)")
        self.data(deleted, "Profile.introductionCardEncrypted", \.introductionCardEncrypted, plaintext: Data(count: 64), name: "Profile.introductionCardEncrypted (soft-deleted)")
        self.data(deleted, "Profile.challengeStateEncrypted", \.challengeStateEncrypted, plaintext: Data(count: 64), name: "Profile.challengeStateEncrypted (soft-deleted)")
    }

    /// Group slots hold the live contact's identifier as a value: the three arrays below, a draft's recipient and a
    /// custody payload (`Profile.identifier` is a reference key).
    private func seedGroups(into ctx: ModelContext) throws {
        // Group's slot arrays are private(set): they are only written through its own API, which seals under whatever
        // key the ambient manager derives. A build from before the fix derived the legacy key; so does this manager.
        let wasLegacyOnly = self.keys.derivesLegacyKeysOnly
        self.keys.derivesLegacyKeysOnly = true
        defer { self.keys.derivesLegacyKeysOnly = wasLegacyOnly }

        let group = try Group(name: "Tea party")
        ctx.insert(group)

        let idPlain = Data(UUID().uuidString.utf8)
        group.encryptedID = self.sealed(idPlain, .local)
        self.track(.slot, group, entry: "Group.encryptedID", plaintext: idPlain, before: group.encryptedID!, read: { $0.encryptedID },
                   write: { $0.encryptedID = $1 })

        let namePlain = Data("Tea party".utf8)
        group.encryptedName = self.sealed(namePlain, .local)
        self.track(.slot, group, entry: "Group.encryptedName", plaintext: namePlain, before: group.encryptedName!, read: { $0.encryptedName },
                   write: { $0.encryptedName = $1 })

        let createdPlain = try JSONEncoder().encode(floor(Date().timeIntervalSince1970))
        group.encryptedCreatedAt = self.sealed(createdPlain, .local)
        self.track(.slot, group, entry: "Group.encryptedCreatedAt", plaintext: createdPlain, before: group.encryptedCreatedAt!, read: { $0.encryptedCreatedAt },
                   write: { $0.encryptedCreatedAt = $1 })

        // Members at depths 0, 1 and 3; every other slot stays random filler.
        try group.addMember(self.identifier, atDepth: 0)
        try group.addMember("member two", atDepth: 0)
        try group.addMember(self.identifier, atDepth: 1)
        try group.addMember("member three", atDepth: 3)

        let legacy = Frozen.legacyKey(.local)
        func classify(_ array: [Data], entry: String, label: String, read: @escaping (Group) -> [Data]) {
            for (index, element) in array.enumerated() {
                let name = "\(entry)\(label)[\(index)]"
                let load: (ModelContext) -> Data? = { context in
                    Self.fetch(Group.self, group.persistentModelID, in: context).flatMap {
                        let current = read($0)
                        return current.indices.contains(index) ? current[index] : nil
                    }
                }
                if let opened = Sealing.open(element, key: legacy, aad: Sealing.fixedAAD) {
                    self.pending.append(Pending(name: name, entry: entry, kind: .slot, owner: .local, plaintext: opened, aad: Sealing.fixedAAD, before: element, load: load))
                } else {
                    self.pending.append(Pending(name: name, entry: entry, kind: .filler, owner: .local, plaintext: Data(), aad: nil, before: element, load: load))
                }
            }
        }
        classify(group.realMemberSlots, entry: "Group.realMemberSlots", label: "") { $0.realMemberSlots }
        classify(group.duressMemberSlots, entry: "Group.duressMemberSlots", label: "") { $0.duressMemberSlots }
        for depthIndex in 0..<group.deeperMemberSlots.count {
            classify(group.deeperMemberSlots[depthIndex], entry: "Group.deeperMemberSlots", label: "[\(depthIndex)]") { $0.deeperMemberSlots[depthIndex] }
        }
    }

    private func seedDrafts(into ctx: ModelContext) throws {
        let id = UUID()
        let draft = Message.Draft(id: id, encryptedRecipientID: Data(), encryptedContent: Data())
        ctx.insert(draft)

        // The recipient is the live contact's identifier, a reference.
        self.data(draft, "Draft.encryptedRecipientID", \.encryptedRecipientID,
                  plaintext: Data(self.identifier.utf8), aad: Message.Draft.aad(id: id, field: .recipientID))
        self.data(draft, "Draft.encryptedContent", \.encryptedContent,
                  plaintext: Data("a draft".utf8), aad: Message.Draft.aad(id: id, field: .content))
    }

    private func seedVault(into ctx: ModelContext) throws {
        // The vault's tier is Stage 4: its fields must come through byte-identical.
        let entry = VaultEntry(encryptedLabel: Sealing.random(60), encryptedContent: Sealing.random(120))
        entry.encryptedEntryKey = Sealing.random(60)
        ctx.insert(entry)
        self.data(entry, "VaultEntry.visibleThroughDepth", \.visibleThroughDepth, plaintext: DepthCodec.encode(0))
        self.data(entry, "VaultEntry.deletionToken", \.deletionToken, plaintext: VaultEntry.liveToken)
        // Retired with per-entry splitting and not sealed under a key of tier U: `VaultManager.unlock` clears it.
        entry.shardDistributionEncrypted = Sealing.random(60)
        for (name, bytes) in [("encryptedLabel", entry.encryptedLabel), ("encryptedContent", entry.encryptedContent), ("encryptedEntryKey", entry.encryptedEntryKey), ("shardDistributionEncrypted", entry.shardDistributionEncrypted!)] {
            self.pending.append(Pending(
                name: "VaultEntry.\(name)", entry: "VaultEntry.\(name)", kind: .untouched, owner: .local, plaintext: Data(), aad: nil, before: bytes,
                load: { context in
                    Self.fetch(VaultEntry.self, entry.persistentModelID, in: context).flatMap { (row: VaultEntry) -> Data? in
                        switch name {
                        case "encryptedLabel":      return row.encryptedLabel
                        case "encryptedContent":    return row.encryptedContent
                        case "encryptedEntryKey":   return row.encryptedEntryKey
                        default:                    return row.shardDistributionEncrypted
                        }
                    }
                }
            ))
        }

        // One claimed backup-key row, and two filler rows (never claimed): random bytes in every field.
        let live = BackupEncryptionKey(depth: nil, deletionToken: nil, encryptedPayload: Sealing.random(200))
        ctx.insert(live)
        self.data(live, "BackupEncryptionKey.depth", \.depth, plaintext: DepthCodec.encode(0))
        self.data(live, "BackupEncryptionKey.deletionToken", \.deletionToken, plaintext: BackupEncryptionKey.liveToken)
        self.pending.append(Pending(
            name: "BackupEncryptionKey.encryptedPayload", entry: "BackupEncryptionKey.encryptedPayload", kind: .untouched, owner: .local,
            plaintext: Data(), aad: nil, before: live.encryptedPayload,
            load: { context in Self.fetch(BackupEncryptionKey.self, live.persistentModelID, in: context)?.encryptedPayload }
        ))

        for index in 0..<2 {
            let filler = BackupEncryptionKey(
                depth: Sealing.random(DepthCodec.sealedSize), deletionToken: Sealing.random(1 + 28), encryptedPayload: Sealing.random(200)
            )
            ctx.insert(filler)
            for (field, bytes, read) in [
                ("depth", filler.depth!, { (row: BackupEncryptionKey) in row.depth }),
                ("deletionToken", filler.deletionToken!, { (row: BackupEncryptionKey) in row.deletionToken }),
            ] {
                self.pending.append(Pending(
                    name: "BackupEncryptionKey.\(field) (filler \(index))", entry: "BackupEncryptionKey.\(field)", kind: .filler, owner: .local,
                    plaintext: Data(), aad: nil, before: bytes,
                    load: { context in Self.fetch(BackupEncryptionKey.self, filler.persistentModelID, in: context).flatMap(read) }
                ))
            }
            self.pending.append(Pending(
                name: "BackupEncryptionKey.encryptedPayload (filler \(index))", entry: "BackupEncryptionKey.encryptedPayload", kind: .untouched,
                owner: .local, plaintext: Data(), aad: nil, before: filler.encryptedPayload,
                load: { context in Self.fetch(BackupEncryptionKey.self, filler.persistentModelID, in: context)?.encryptedPayload }
            ))
        }
    }

    private func seedCustodyAndRestore(into ctx: ModelContext) throws {
        let identifierJSON = try JSONEncoder().encode(["ownerContactIdentifier": self.identifier])

        func row<M: PersistentModel>(_ make: (UUID, Data) -> M, _ entry: String, _ owner: KeyOwner, _ keyPath: ReferenceWritableKeyPath<M, Data>, plaintext: Data) {
            let id    = UUID()
            let aad   = id.uuidString.data(using: .utf8)!
            let bytes = self.sealed(plaintext, owner, aad: aad)
            let model = make(id, bytes)
            ctx.insert(model)
            self.track(.slot, model, entry: entry, owner: owner, plaintext: plaintext, aad: aad, before: bytes,
                       read: { $0[keyPath: keyPath] }, write: { $0[keyPath: keyPath] = $1 })
        }

        row({ CustodyShard(id: $0, encryptedPayload: $1) }, "CustodyShard.encryptedPayload", .custody, \.encryptedPayload, plaintext: identifierJSON)
        row({ PendingShardDistribute(id: $0, encryptedPayload: $1) }, "PendingShardDistribute.encryptedPayload", .custody, \.encryptedPayload, plaintext: Data("distribute".utf8))
        row({ PendingShardStatusUpdate(id: $0, encryptedPayload: $1) }, "PendingShardStatusUpdate.encryptedPayload", .custody, \.encryptedPayload, plaintext: Data("status".utf8))
        row({ PotentiallyLostShard(id: $0, encryptedPayload: $1) }, "PotentiallyLostShard.encryptedPayload", .custody, \.encryptedPayload, plaintext: Data("lost".utf8))
        row({ GlobalShardConfig(id: $0, encryptedPayload: $1) }, "GlobalShardConfig.encryptedPayload", .custody, \.encryptedPayload, plaintext: Data("global".utf8))

        // The retired mechanism's row, with a payload that decodes: `VaultManager.unlock` absorbs it into the restore
        // buffer, and deletes it if it doesn't open.
        self.reconstructDistributionID = UUID()
        let reconstructAttribute = try self.shardAttribute(entryID: self.reconstructDistributionID)
        self.reconstructAttributeID = reconstructAttribute.id
        let reconstructPayload = try JSONEncoder().encode(ReconstructShard.Payload(
            entryID: self.reconstructDistributionID, attrID: reconstructAttribute.id,
            signedAttribute: reconstructAttribute, senderIdentifier: "trustee-reconstruct"
        ))
        row({ ReconstructShard(id: $0, encryptedPayload: $1) }, "ReconstructShard.encryptedPayload", .restore, \.encryptedPayload, plaintext: reconstructPayload)

        let vault = Vault()
        ctx.insert(vault)
        let restoreID = UUID()
        let restore = PendingShamirSecretRestore(id: restoreID, vault: vault)
        ctx.insert(restore)

        // A banked piece, as `absorbShard` would have written it.
        self.restoreDistributionID = UUID()
        let restoreAttribute = try self.shardAttribute(entryID: self.restoreDistributionID)
        self.restoreAttributeID = restoreAttribute.id
        let slots = try PendingShamirSecretRestore.ShardsCodec.encode([
            PendingRestoreShardSlot(signedAttribute: restoreAttribute, sender: TrusteeTag(identifier: "trustee-restore"))
        ])
        self.data(restore, "PendingShamirSecretRestore.attributeID", \.attributeID,
                  plaintext: withUnsafeBytes(of: self.restoreDistributionID.uuid) { Data($0) })
        self.data(restore, "PendingShamirSecretRestore.deletionToken", \.deletionToken, plaintext: PendingShamirSecretRestore.liveToken)
        self.data(restore, "PendingShamirSecretRestore.shards", \.shards, owner: .restore,
                  plaintext: slots, aad: restoreID.uuidString.data(using: .utf8)!)
    }

    /// A shard attribute of the shape a trustee hands back: a 33-byte value and a real signature.
    private func shardAttribute(entryID: UUID) throws -> SignedAttribute {
        let id        = UUID()
        let value     = Data([UInt8(1)]) + Sealing.random(32)
        let createdAt = Date()
        let payload   = SignedAttribute.signingPayload(id: id, category: .shard, value: value, entryID: entryID, createdAt: createdAt)
        return SignedAttribute(
            id: id, label: "vault-shard", value: value, category: .shard,
            signature: try self.keys.signData(payload), createdAt: createdAt, entryID: entryID
        )
    }

    private func seedConfig(into ctx: ModelContext, gateDepth: Int) throws {
        let config = AppLayerConfig()
        ctx.insert(config)

        self.data(config, "AppLayerConfig.persistedDepth", \.persistedDepth, plaintext: DepthCodec.encode(gateDepth))
        self.data(config, "AppLayerConfig.pinEnabled", \.pinEnabled, plaintext: try JSONEncoder().encode(false))
        self.data(config, "AppLayerConfig.coercerBaseDepth", \.coercerBaseDepth, plaintext: DepthCodec.encode(0))
        self.data(config, "AppLayerConfig.lockoutCountEncrypted", \.lockoutCountEncrypted, plaintext: try JSONEncoder().encode(2))
        self.data(config, "AppLayerConfig.lockoutAnchorUptimeEncrypted", \.lockoutAnchorUptimeEncrypted, plaintext: try JSONEncoder().encode(1234.5))

        // 32 gate entries: enabled everywhere (`UInt8` 1), lowered at `gateDepth` (`UInt8` 0).
        var gates: [Data] = []
        for depth in 0..<32 { gates.append(try JSONEncoder().encode(UInt8(depth == gateDepth ? 0 : 1))) }
        self.array(config, "AppLayerConfig.pinEnabledPerDepth", \.pinEnabledPerDepth, gates)

        // The PIN's verifiers are Stage 3's. Random bytes of the right length stand in for them.
        config.sealedNormalVerifier  = Sealing.random(53)
        config.sealedDuressVerifier  = Sealing.random(53)
        config.sealedNormalVerifiers = (0..<32).map { _ in Sealing.random(53) }
        config.sealedDuressVerifiers = (0..<32).map { _ in Sealing.random(53) }
        let probe: (String, Data, @escaping (AppLayerConfig) -> Data?) -> Void = { name, before, read in
            self.pending.append(Pending(
                name: "AppLayerConfig.\(name)", entry: "AppLayerConfig.\(name)", kind: .untouched, owner: .local, plaintext: Data(), aad: nil, before: before,
                load: { context in Self.fetch(AppLayerConfig.self, config.persistentModelID, in: context).flatMap(read) }
            ))
        }
        probe("sealedNormalVerifier", config.sealedNormalVerifier!, { $0.sealedNormalVerifier })
        probe("sealedDuressVerifier", config.sealedDuressVerifier!, { $0.sealedDuressVerifier })
        for index in 0..<32 {
            probe("sealedNormalVerifiers[\(index)]", config.sealedNormalVerifiers[index], { $0.sealedNormalVerifiers.indices.contains(index) ? $0.sealedNormalVerifiers[index] : nil })
            probe("sealedDuressVerifiers[\(index)]", config.sealedDuressVerifiers[index], { $0.sealedDuressVerifiers.indices.contains(index) ? $0.sealedDuressVerifiers[index] : nil })
        }
    }

    private func finalize() {
        for item in self.pending {
            switch item.kind {
            case .slot:
                self.slots.append(Slot(name: item.name, entry: item.entry, owner: item.owner, plaintext: item.plaintext, aad: item.aad, before: item.before, load: item.load, write: item.write))
            case .reference:
                self.references.append(Probe(name: item.name, before: item.before, load: item.load))
            case .untouched:
                self.untouched.append(Probe(name: item.name, before: item.before, load: item.load))
            case .filler:
                self.fillers.append(Probe(name: item.name, before: item.before, load: item.load))
            }
        }
        self.pending = []
    }
}

private extension Contact.Message {
    /// `recipients` is `[Data]?`; the fixture seals elements of a non-optional view of it.
    var recipientsOrEmpty: [Data] {
        get { self.recipients ?? [] }
        set { self.recipients = newValue }
    }
}

// MARK: - The entries tier U owns

enum Stage2Inventory {

    /// Entries the pass moves: sealed under the local, custody or restore key, other than the reference key and the
    /// epochs it writes itself.
    static var ownedEntries: Set<String> {
        let epochs: Set<String> = ["keyEpoch", "vaultKeyEpoch"]

        return Set(KeyReseal.fields
            .filter { [.local, .custody, .restore].contains($0.key) }
            .filter { $0.treatment != .reference && !($0.model == "AppLayerConfig" && epochs.contains($0.attribute)) }
            .map { "\($0.model).\($0.attribute)" })
    }
}

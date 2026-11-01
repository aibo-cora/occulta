//
//  KeyResealLaunchTests.swift
//  OccultaTests
//
//  Bug 171, Stage 2: the reseal in the order the app runs it. The migration test matrix of the plan, rows 7 to 11:
//
//    - the launch order: the sequence first, then `Manager.Security`, so the gate and the persisted depth are read
//      under the key they are sealed under; then the unlock-time and launch-time passes that open tier U's values
//      and delete or empty what doesn't open (`VaultManager.unlock`, `migratePrekeyRecords`);
//    - a backup-key split whose custody and restore rows were made before the pass;
//    - a fresh install;
//    - an upgrade on a device that has no PQ record yet;
//    - upgrading again after a downgrade.
//
//  Written first, as `KeyResealTests` is: against the Stage 2a stubs the data was never moved, and the tests that
//  look for it under the new key failed there. What `OccultaApp.init()` does (the call order) can't be run from a test;
//  `LaunchSequence.run` followed by `Manager.Security(...)` is the order those tests pin, and `OccultaApp.init()` has
//  to match it.
//

import Testing
import CryptoKit
import Foundation
import LocalAuthentication
import SwiftData

@testable import Occulta
@testable import OccultaCore
@testable import OccultaFormats

// MARK: - Helpers

@MainActor
func makeStore() throws -> ModelContainer {
    let schema = OccultaApp.schema
    return try ModelContainer(for: schema, configurations: ModelConfiguration(schema: schema, isStoredInMemoryOnly: true))
}

/// A backup-key piece (33 bytes, a real signature), as `signer` hands it to a trustee.
@MainActor
func signedShard(signer: TestKeyManager, entryID: UUID) throws -> SignedAttribute {
    let id        = UUID()
    let value     = Data([UInt8(1)]) + Data.randomBytes(32)
    let createdAt = Date()
    let payload   = SignedAttribute.signingPayload(id: id, category: .shard, value: value, entryID: entryID, createdAt: createdAt)
    return SignedAttribute(
        id: id, label: SignedAttribute.backupKeyPieceLabel, value: value, category: .shard,
        signature: try signer.signData(payload), createdAt: createdAt, entryID: entryID
    )
}

/// The reseal's report from a launch, or a failure recorded against the test.
@MainActor
func resealReport(_ report: LaunchSequence.Report, sourceLocation: SourceLocation = #_sourceLocation) -> KeyReseal.Report? {
    switch report.reseal {
    case .success(let value):
        return value
    case .failure(let error):
        Issue.record("the reseal failed: \(error)", sourceLocation: sourceLocation)
        return nil
    }
}

// MARK: - Launch order

@Suite("Key reseal — launch order", .ambientFrozenTestKeyManager)
@MainActor
struct KeyResealLaunchOrderTests {

    @Test("The persisted depth and the lowered gate come through the sequence, and Manager.Security restores them as they were",
          arguments: KeyForm.allCases, [1, 3])
    func gateSurvivesTheSequence(form: KeyForm, depth: Int) throws {
        let (keys, store) = try prepare(form, gateDepth: depth)

        let gate = store.slots.filter { $0.name == "AppLayerConfig.persistedDepth" || $0.entry == "AppLayerConfig.pinEnabledPerDepth" }
        #expect(gate.count == 33)

        let report = LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        #expect(resealReport(report)?.outcome == .completed)

        // The values Security reads are under the key it reads them with.
        let context = store.newContext()
        let notNew  = gate.filter { store.state(of: $0, form: form, in: context) != .new }.map(\.name)
        #expect(notNew.isEmpty, "not under the new key when Manager.Security reads them: \(shown(notNew))")

        let before = snapshot(store)
        let security = Manager.Security(modelContainer: store.container, keyManager: keys)

        #expect(security.currentDepth == depth, "the routing depth restored at launch")
        #expect(security.pinEnabled == false, "the gate stays down")

        let config = try #require(appConfig(store))
        #expect(config.readPersistedDepth() == depth)
        #expect(config.readPinEnabled(at: depth) == false)
        #expect(config.readPinEnabled(at: 0) == true)

        // Security's init rewrote nothing it read.
        let after = snapshot(store)
        let changed = gate.filter { after[$0.name] != before[$0.name] }.map(\.name)
        #expect(changed.isEmpty, "Manager.Security changed: \(shown(changed))")

        // And the launch after this one restores the same.
        LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        let relaunched = Manager.Security(modelContainer: store.container, keyManager: keys)
        #expect(relaunched.currentDepth == depth && relaunched.pinEnabled == false)
    }

    @Test("VaultManager.unlock after the sequence loses nothing from the restore buffer or the retired ReconstructShard rows",
          arguments: KeyForm.allCases)
    func unlockLosesNoShards(form: KeyForm) throws {
        let (keys, store) = try prepare(form)

        LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        let notNew = slots(store, notIn: .new, form: form, afterLaunchPasses: true)
        #expect(notNew.isEmpty, "not under the new key when the vault unlocks: \(shown(notNew))")

        let vault = VaultManager(modelContainer: store.container, keyManager: keys)
        vault.unlock(context: LAContext())

        let banked = try vault.collectedShards(forAttributeID: store.restoreDistributionID)
        #expect(banked.map(\.attribute.id) == [store.restoreAttributeID], "the piece banked in the restore buffer")

        let moved = try vault.collectedShards(forAttributeID: store.reconstructDistributionID)
        #expect(moved.map(\.attribute.id) == [store.reconstructAttributeID], "the retired row's piece, absorbed by the unlock")
        #expect(try ModelContext(store.container).fetchCount(FetchDescriptor<ReconstructShard>()) == 0, "and its row gone")
    }

    @Test("A v1 row is left alone by the pass and reaches the new key through migrateToV2", arguments: KeyForm.allCases)
    func v1RowReachesTheNewKey(form: KeyForm) throws {
        let (keys, store) = try prepare(form)

        // Sealed as the first release sealed it: the v1 local key, no authenticated data.
        let v1Key = try #require(try keys.createLocalEncryptionKey())
        func v1(_ text: String) -> String { Sealing.seal(Data(text.utf8), key: v1Key, aad: nil).base64EncodedString() }

        let context = store.newContext()
        let profile = Contact.Profile(
            identifier: v1("v1 identifier"), givenName: v1("Alice"), familyName: v1("Wonderland"), middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: "",
            encryptionScheme: EncryptionScheme.v1_identityDerived.rawValue
        )
        context.insert(profile)
        try context.save()
        let id = profile.persistentModelID

        LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)

        let migrated = try #require(store.newContext().model(for: id) as? Contact.Profile)
        #expect(migrated.encryptionScheme == EncryptionScheme.v2_hybridPQ.rawValue)

        let newKey = Frozen.newKey(.local, form: form)
        func opened(_ field: String) -> String? {
            Data(base64Encoded: field)
                .flatMap { Sealing.open($0, key: newKey, aad: Sealing.fixedAAD) }
                .flatMap { String(data: $0, encoding: .utf8) }
        }
        #expect(opened(migrated.givenName) == "Alice", "written straight to the new key, not to the legacy one")
        #expect(opened(migrated.familyName) == "Wonderland")
        #expect(opened(migrated.identifier) == "v1 identifier")
    }

    @Test("migratePrekeyRecords carries a contact's prekey state over intact, because the reseal has moved it first",
          arguments: KeyForm.allCases)
    func prekeyStateSurvives(form: KeyForm) throws {
        let (keys, store) = try prepare(form)
        let carrier = try store.addPrekeyCarrier()

        LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)

        let record = store.prekeyRecord(of: carrier.id, openedWith: Frozen.newKey(.local, form: form))
        #expect(record != nil, "the carried-over record opens under the new key")
        #expect(record == carrier.expected, "the contact's keys and our pending batch, not an empty record with legacy keys in use")
        #expect(carrier.expected.legacyKeys == .inUse && carrier.expected.inboundBatches.count == 1 && carrier.expected.ownBatches.count == 1,
                "precondition: the fixture exercises both halves of the record")
    }
}

// MARK: - A backup-key split

@Suite("Key reseal — backup-key split", .ambientFrozenTestKeyManager)
@MainActor
struct KeyResealBackupKeySplitTests {

    @Test("A split made before the pass, with its custody rows and its restore rows, is recoverable after it",
          arguments: KeyForm.allCases)
    func splitSurvives(form: KeyForm) throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(form)
        keys.derivesLegacyKeysOnly = true   // the release before the fix, whatever the next one derives

        // `exportBackup` seals an export-metadata snapshot into Application Support, which the app always has and a
        // test host may not.
        let appSupport = Manager.Paths.applicationSupport
        try? FileManager.default.createDirectory(at: appSupport, withIntermediateDirectories: true)

        // The owner: a backup key split two ways, one entry, and a backup file. As a trustee it also holds two
        // pieces of other people's.
        let ownerStore = try makeStore()
        let owner      = VaultManager(modelContainer: ownerStore, keyManager: keys)
        owner.unlock(context: LAContext())

        try owner.setupBackup(currentDepth: 0)
        let recipients = (0..<2).map { _ in realFormatContactIdentifier() }
        let pieces     = try owner.prepareBackupShards(threshold: 2, recipients: recipients, currentDepth: 0)
        try owner.setBackupShardStatuses(Dictionary(uniqueKeysWithValues: pieces.map { ($0.id, ShardStatus.confirmed) }), currentDepth: 0)
        _ = try owner.addEntry(label: "note-label", content: Data("note-body".utf8), type: .note)
        let backup = try owner.exportBackup(currentDepth: 0)

        let custody = ShardCustodyManager(modelContainer: ownerStore, keyManager: keys)
        let friend  = TestKeyManager()
        for _ in 0..<2 {
            _ = custody.handleInbound(
                shardOperations:  [.init(kind: .distribute, attribute: try signedShard(signer: friend, entryID: UUID()))],
                custodyManifest:  nil,
                senderPublicKey:  try friend.retrieveIdentity(),
                senderIdentifier: realFormatContactIdentifier(),
                vaultManager:     owner
            )
        }
        let custodyRows = try ModelContext(ownerStore).fetch(FetchDescriptor<CustodyShard>())
        #expect(custodyRows.count == 2, "precondition: the trustee holds two pieces")

        // The new phone: banks the owner's two pieces in its restore buffer.
        let phoneStore = try makeStore()
        let phone      = VaultManager(modelContainer: phoneStore, keyManager: keys)
        phone.unlock(context: LAContext())
        var senders = Set<String>()
        for piece in pieces {
            let sender = realFormatContactIdentifier()
            try phone.absorbShard(piece, senderIdentifier: sender)
            senders.insert(sender)
        }

        // The next release launches over both, and derives the new keys from then on.
        LaunchSequence.run(context: ModelContext(ownerStore), keyManager: keys, batchSize: 7)
        LaunchSequence.run(context: ModelContext(phoneStore), keyManager: keys, batchSize: 7)
        keys.derivesLegacyKeysOnly = false

        // The rows are on the new keys.
        let custodyKey = Frozen.newKey(.custody, form: form)
        for row in try ModelContext(ownerStore).fetch(FetchDescriptor<CustodyShard>()) {
            let opened = Sealing.open(row.encryptedPayload, key: custodyKey, aad: row.aad())
            #expect(opened != nil, "a custody row has to open under the new custody key")
        }

        let restoreKey = Frozen.newKey(.restore, form: form)
        let localKey   = Frozen.newKey(.local, form: form)
        let banked     = try ModelContext(phoneStore).fetch(FetchDescriptor<PendingShamirSecretRestore>())
        #expect(banked.count == 1)
        for row in banked {
            #expect(row.shards.flatMap { Sealing.open($0, key: restoreKey, aad: row.aad()) } != nil, "the banked pieces open under the new restore key")
            #expect(row.attributeID.flatMap { Sealing.open($0, key: localKey, aad: Sealing.fixedAAD) }?.count == 16, "and the secret they belong to under the new local key")
        }

        // And the split does what it is for: the new phone restores the backup, and the owner can still export one.
        let imported = try phone.restoreBackup(from: backup, currentDepth: 0, visibleContactIdentifiers: senders)
        #expect(imported, "the restore has to succeed from the banked pieces")
        #expect(try ModelContext(phoneStore).fetchCount(FetchDescriptor<VaultEntry>()) == 1)

        _ = try owner.exportBackup(currentDepth: 0)
    }
}

// MARK: - Fresh install, and an upgrade with no record yet

@Suite("Key reseal — fresh install and first upgrade", .ambientFrozenTestKeyManager)
@MainActor
struct KeyResealInstallTests {

    @Test("A fresh install: the secret, the record and the config row are created, the epoch is set, the pass writes nothing, and the legacy derivation never runs",
          arguments: KeyForm.allCases)
    func freshInstall(form: KeyForm) throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(form)
        keys.tierSecretU   = nil
        keys.tierPQRecordU = nil

        let store    = try LegacyStore(keys: keys)
        let baseline = keys.legacyKeyCalls

        let launch = LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)

        guard case .success(let bootstrap) = launch.bootstrap else {
            Issue.record("the bootstrap failed: \(launch.bootstrap)")
            return
        }
        #expect(bootstrap.createdTierSecret && bootstrap.createdTierPQRecord, "r_U and the tier U record")
        #expect(bootstrap.createdConfig, "the config row, for the epochs to live in before Manager.Security runs")
        #expect(bootstrap.seededVaultKeyEpoch)
        #expect(bootstrap.refusals.isEmpty)
        #expect(keys.tierSecretU?.count == 32)
        #expect(keys.tierPQRecordU?.mode == (form == .hybrid ? .hybrid : .classical))

        let report = resealReport(launch)
        #expect(report?.outcome == .completed)
        // Nothing to move. The config row the bootstrap made is born under the new key, so the pass sees its values
        // and counts them as already done.
        #expect(report?.total.resealed == 0 && report?.total.left == 0 && report?.total.failed == 0 && report?.total.refreshed == 0,
                "there was nothing to move: \(String(describing: report?.total))")
        #expect(report?.entries.keys.allSatisfy { $0.hasPrefix("AppLayerConfig.") } == true, "and nothing but the config row to look at")
        #expect(report?.epochWritten == true)
        #expect(keys.legacyKeyCalls == baseline, "no legacy key is derived on a fresh install: there is nothing sealed under one")

        // The epochs open under the key this device derives, and say what they should.
        let localKey = try #require(try keys.enclaveBoundKey(.localDB))
        let config   = try #require(appConfig(store))
        #expect(KeyReseal.Epoch.opening(config.keyEpoch, using: localKey) == Frozen.epoch(form))
        #expect(KeyReseal.Epoch.opening(config.vaultKeyEpoch, using: localKey)?.number == 1)

        // Nothing else was written.
        let counts = try store.rowCounts(in: store.newContext())
        #expect(counts.filter { $0.value != 0 }.keys.sorted() == ["AppLayerConfig"], "only the config row exists: \(counts.filter { $0.value != 0 })")

        // A second launch and Manager.Security leave both epochs as they are.
        let before = snapshot(store)
        LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        _ = Manager.Security(modelContainer: store.container, keyManager: keys)
        #expect(snapshot(store) == before)
        #expect(try #require(appConfig(store)).readPersistedDepth() == 0)
    }

    @Test("An upgrade on a device with no PQ record yet: the record is created, kept, and the data ends up under the keys that include it",
          arguments: KeyForm.allCases)
    func upgradeCreatesTheRecord(form: KeyForm) throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(form)
        keys.tierPQRecordU = nil   // r_U is there: the release before the fix made it for the local key

        let store = try LegacyStore(keys: keys)
        try store.seed()
        let secret = keys.tierSecretU

        let launch = LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)

        guard case .success(let bootstrap) = launch.bootstrap else {
            Issue.record("the bootstrap failed: \(launch.bootstrap)")
            return
        }
        #expect(bootstrap.createdTierPQRecord && !bootstrap.createdTierSecret && !bootstrap.createdConfig)
        #expect(keys.tierSecretU == secret, "r_U is the one the local key already includes")

        let record = keys.tierPQRecordU
        #expect(record?.mode == (form == .hybrid ? .hybrid : .classical))
        #expect(resealReport(launch)?.outcome == .completed)

        let context = store.newContext()
        let notNew  = store.slots
            .filter { !LegacyStore.consumedByLaunchPasses.contains($0.entry) }
            .filter { store.state(of: $0, derivedBy: keys, in: context) != .new }
            .map(\.name)
        #expect(notNew.isEmpty, "not under the keys the created record yields: \(shown(notNew))")

        LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        #expect(keys.tierPQRecordU == record, "a later launch keeps the record it has")
    }
}

// MARK: - Upgrading again after a downgrade

@Suite("Key reseal — re-upgrade after a downgrade", .ambientFrozenTestKeyManager)
@MainActor
struct KeyResealReUpgradeTests {

    @Test("Upgrading again reseals what the previous release wrote, and nothing else changes and nothing is lost",
          arguments: KeyForm.allCases)
    func reUpgrade(form: KeyForm) throws {
        let (keys, store) = try prepare(form)

        // The first upgrade.
        LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        let afterFirst = slots(store, notIn: .new, form: form, afterLaunchPasses: true)
        #expect(afterFirst.isEmpty, "the first upgrade left: \(shown(afterFirst))")

        // The downgrade: the epoch columns go, and the previous release writes some values and a contact under
        // the legacy key. The rest stays under the new key, which it cannot read and leaves alone.
        let written    = try store.downgrade()
        let newContact = try store.addContactWrittenByThePreviousRelease()
        let rowsBefore = try store.rowCounts(in: store.newContext())
        let snapshotAfterDowngrade = snapshot(store)
        #expect(written.count > 10, "precondition: the previous release rewrote a good part of the store")
        #expect(appConfig(store)?.keyEpoch == nil && appConfig(store)?.vaultKeyEpoch == nil)
        #expect(slots(store, notIn: .new, form: form, afterLaunchPasses: true).count == written.count, "and only that part is legacy again")

        // The second upgrade.
        let launch = LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        let report = try #require(resealReport(launch))

        #expect(report.outcome == .completed)
        #expect(report.total.resealed == written.count + 1, "the rewritten values and the new contact's name, no more")
        #expect(report.total.failed == 0)
        #expect(keyEpoch(store, form: form) == Frozen.epoch(form), "the epoch is back")
        #expect(KeyReseal.Epoch.opening(appConfig(store)?.vaultKeyEpoch, using: Frozen.newKey(.local, form: form))?.number == 1, "and the vault's")

        // Everything is under the new key again, with its plaintext.
        let notNew = slots(store, notIn: .new, form: form, afterLaunchPasses: true)
        #expect(notNew.isEmpty, "after the second upgrade: \(shown(notNew))")
        #expect(store.givenName(of: newContact, openedWith: Frozen.newKey(.local, form: form)) == LegacyStore.previousReleaseName)

        // What the previous release did not write is byte for byte what it was, except the containers that change
        // whole (the uniform-change rule): a group's slot arrays and the backup-key table. A run that moved only the
        // members the previous release wrote would show, in a diff, which slots are real and at which depth.
        let after = snapshot(store)
        let writtenNames = Set(written)
        let whole: Set<String> = [
            "Group.realMemberSlots", "Group.duressMemberSlots", "Group.deeperMemberSlots",
            "BackupEncryptionKey.depth", "BackupEncryptionKey.deletionToken",
        ]
        let changed = store.slots
            .filter { !writtenNames.contains($0.name) && !LegacyStore.consumedByLaunchPasses.contains($0.entry) && !whole.contains($0.entry) }
            .filter { after[$0.name] != snapshotAfterDowngrade[$0.name] }
            .map(\.name)
        #expect(changed.isEmpty, "changed though the previous release did not write it: \(shown(changed))")

        let members = store.slots.filter { whole.contains($0.entry) }.map(\.name) + store.fillers.map(\.name)
        let same = members.filter { after[$0] == snapshotAfterDowngrade[$0] }
        #expect(!members.isEmpty && same.isEmpty, "a container that changes whole kept the bytes of: \(shown(same))")
        #expect((store.references + store.untouched).filter { after[$0.name] != snapshotAfterDowngrade[$0.name] }.isEmpty, "references and later stages' fields")

        // Nothing lost.
        #expect(try store.rowCounts(in: store.newContext()) == rowsBefore)
    }
}

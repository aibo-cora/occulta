//
//  KeyResealTests.swift
//  OccultaTests
//
//  Bug 171, Stage 2: the key reseal (`KeyReseal.run`, `KeyReseal.bootstrap`), as the migration test matrix of the plan
//  asks for it (rows 1 to 5 and 11 here; 7 to 10 in `KeyResealLaunchTests`, volume, cost and Erase All Data in
//  `KeyResealScaleTests`).
//
//  Written first (Stage 2a), and failing for the right reason: against the stubs, which did nothing, every test that
//  expects a value to have moved, an epoch to be set, or a failure to be reported failed on that assertion. The tests
//  that passed against the stubs were the ones that pin something that existed already (the frozen keys, the
//  fixtures' coverage of the inventory), and they say so in their names.
//
//  Everything runs without a Secure Enclave, on the frozen `TestKeyManager` (`TestKeyManager.frozen()`), in both
//  forms the device can be in: hybrid (iOS 26+) and classical (below).
//
//    - `FrozenKeyTests`:        the pins, and the fixtures' coverage of the inventory.
//    - `KeyResealRoundTripTests`: every entry opens under the new key, row counts, the report's counts, identifiers.
//    - `KeyResealCrashSafetyTests`: an interruption at each point, and the read-back.
//    - `KeyResealFailureTests`: a key, secret or record that can't be read, and a row that opens under neither key.
//

import Testing
import CryptoKit
import Foundation
import SwiftData

@testable import Occulta
@testable import OccultaFormats

// MARK: - Helpers

@MainActor
func prepare(_ form: KeyForm, gateDepth: Int = 2) throws -> (keys: TestKeyManager, store: LegacyStore) {
    let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
    keys.become(form)

    let store = try LegacyStore(keys: keys)
    try store.seed(gateDepth: gateDepth)
    return (keys, store)
}

/// Every stored value the tests watch, by name: sealed slots, fillers, the values that must not change, and the two
/// epoch columns. Equal snapshots mean no byte changed.
@MainActor
func snapshot(_ store: LegacyStore) -> [String: Data?] {
    let context = store.newContext()
    var out: [String: Data?] = [:]

    for slot in store.slots { out[slot.name] = slot.load(context) }
    for probe in store.references + store.untouched + store.fillers { out[probe.name] = probe.load(context) }

    let config = try? context.fetch(FetchDescriptor<AppLayerConfig>()).first
    out["AppLayerConfig.keyEpoch"]      = config?.keyEpoch
    out["AppLayerConfig.vaultKeyEpoch"] = config?.vaultKeyEpoch
    return out
}

/// Slots not in `expected`, as `name=state`, leaving out the entries the launch passes consume by design.
@MainActor
func slots(_ store: LegacyStore, notIn expected: SlotState, form: KeyForm, afterLaunchPasses: Bool = false) -> [String] {
    let context = store.newContext()

    return store.slots
        .filter { !(afterLaunchPasses && LegacyStore.consumedByLaunchPasses.contains($0.entry)) }
        .map { ($0.name, store.state(of: $0, form: form, in: context)) }
        .filter { $0.1 != expected }
        .map { "\($0.0)=\($0.1)" }
}

func shown(_ names: [String]) -> String {
    names.count <= 8 ? names.joined(separator: ", ") : names.prefix(8).joined(separator: ", ") + " … and \(names.count - 8) more"
}

@MainActor
func appConfig(_ store: LegacyStore) -> AppLayerConfig? {
    try? store.newContext().fetch(FetchDescriptor<AppLayerConfig>()).first
}

@MainActor
func keyEpoch(_ store: LegacyStore, form: KeyForm) -> KeyReseal.Epoch? {
    KeyReseal.Epoch.opening(appConfig(store)?.keyEpoch, using: Frozen.newKey(.local, form: form))
}

/// Writes the epoch the way the end of a finished pass does, for a test that needs "an epoch exists".
@MainActor
func writeEpoch(_ store: LegacyStore, form: KeyForm) throws {
    let context = store.newContext()
    let config  = try #require(try context.fetch(FetchDescriptor<AppLayerConfig>()).first)
    config.keyEpoch = try Frozen.epoch(form).sealed(using: Frozen.newKey(.local, form: form))
    try context.save()
}

// MARK: - The pins

@Suite("Key reseal — frozen fixtures", .ambientFrozenTestKeyManager)
@MainActor
struct FrozenKeyTests {

    @Test("Pin: the legacy local DB, shard custody and restore keys are the pinned bytes (passes today; fails if the legacy derivation is edited)")
    func legacyKeysArePinned() throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)

        for (owner, key) in [(KeyOwner.local, try keys.legacyKey(.localDB)), (.custody, try keys.legacyKey(.shardCustody)), (.restore, try keys.legacyKey(.restoreVault))] {
            #expect(keyBytes(try #require(key)) == keyBytes(Frozen.legacyKey(owner)), "\(owner)")
        }
    }

    @Test("Pin: the Enclave-bound keys are the pinned bytes in both forms (passes today)", arguments: KeyForm.allCases)
    func newKeysArePinned(form: KeyForm) throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(form)

        for (owner, key) in [(KeyOwner.local, try keys.enclaveBoundKey(.localDB)), (.custody, try keys.enclaveBoundKey(.shardCustody)), (.restore, try keys.enclaveBoundKey(.restoreVault))] {
            #expect(keyBytes(try #require(key)) == keyBytes(Frozen.newKey(owner, form: form)), "\(owner) \(form)")
        }
    }

    @Test("Fixture guard: the seeded store has a value for every inventory entry tier U owns, and for no other (passes today)")
    func fixturesCoverTheInventory() throws {
        let (_, store) = try prepare(.hybrid)

        let seeded = Set(store.slots.map(\.entry))
        #expect(seeded.subtracting(Stage2Inventory.ownedEntries).isEmpty, "seeded but not owned: \(shown(seeded.subtracting(Stage2Inventory.ownedEntries).sorted()))")
        #expect(Stage2Inventory.ownedEntries.subtracting(seeded).isEmpty, "owned but not seeded: \(shown(Stage2Inventory.ownedEntries.subtracting(seeded).sorted()))")
    }

    @Test("Fixture guard: every seeded value opens under the pinned legacy key and under no other (passes today)")
    func everyFixtureIsLegacy() throws {
        let (_, store) = try prepare(.hybrid)

        #expect(slots(store, notIn: .legacy, form: .hybrid).isEmpty)
        #expect(slots(store, notIn: .legacy, form: .classical).isEmpty)
        #expect(!store.slots.isEmpty && !store.fillers.isEmpty && !store.untouched.isEmpty && store.references.count == 1)
    }
}

// MARK: - Round trip

@Suite("Key reseal — round trip", .ambientFrozenTestKeyManager)
@MainActor
struct KeyResealRoundTripTests {

    @Test("Every entry opens under the new key afterwards, with the same plaintext and length, and none under the legacy key",
          arguments: KeyForm.allCases)
    func everyEntryOpensUnderTheNewKey(form: KeyForm) throws {
        let (keys, store) = try prepare(form)

        let report = try KeyReseal.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        #expect(report.outcome == .completed)

        let context = store.newContext()
        let notNew  = slots(store, notIn: .new, form: form)
        #expect(notNew.isEmpty, "not under the new key: \(shown(notNew))")

        let resized = store.slots.filter { $0.load(context)?.count != $0.before.count }.map(\.name)
        #expect(resized.isEmpty, "changed length: \(shown(resized))")

        #expect(keyEpoch(store, form: form) == Frozen.epoch(form), "the epoch records the form the data is under")
    }

    @Test("Row counts are the same before and after, and the report's resealed count equals the seeded count, entry by entry",
          arguments: KeyForm.allCases)
    func countsMatch(form: KeyForm) throws {
        let (keys, store) = try prepare(form)
        let rowsBefore = try store.rowCounts(in: store.newContext())

        let report = try KeyReseal.run(context: store.newContext(), keyManager: keys, batchSize: 7)

        #expect(try store.rowCounts(in: store.newContext()) == rowsBefore)
        #expect(rowsBefore["Profile"] == 2 && rowsBefore["Group"] == 1 && rowsBefore["BackupEncryptionKey"] == 3)

        for (entry, seeded) in store.seededCounts {
            #expect(report.entries[entry]?.resealed == seeded, "\(entry): seeded \(seeded), report \(String(describing: report.entries[entry]))")
        }
        #expect(report.total.resealed == store.slots.count)
        #expect(report.total.left == 0 && report.total.failed == 0)
        #expect(report.total.skipped == 0, "nothing was under the new key yet")
    }

    @Test("The vault's and the PIN's sealed fields, and the fields no key of tier U seals, come through byte for byte")
    func untouchedValuesStayPut() throws {
        let (keys, store) = try prepare(.hybrid)
        let before = snapshot(store).filter { name, _ in store.untouched.contains { $0.name == name } }
        #expect(before.count == store.untouched.count)

        let report = try KeyReseal.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        #expect(report.outcome == .completed, "the pass has to have run for \"unchanged\" to mean anything")

        let after = snapshot(store).filter { name, _ in store.untouched.contains { $0.name == name } }
        #expect(after == before)
    }

    @Test("Profile.identifier and every record that carries it as a value come through unchanged: the identifier is left byte-identical",
          arguments: KeyForm.allCases)
    func identifierIsLeftAlone(form: KeyForm) throws {
        let (keys, store) = try prepare(form)
        let identifier = store.identifier
        #expect(!identifier.isEmpty)

        let report = try KeyReseal.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        #expect(report.outcome == .completed, "the pass has to have run for \"unchanged\" to mean anything")

        // The column itself.
        let context = store.newContext()
        for reference in store.references {
            #expect(reference.load(context) == reference.before, "\(reference.name)")
        }
        #expect(report.entries["Profile.identifier"] == nil || report.entries["Profile.identifier"] == KeyReseal.Counts())

        // The records that store it: their plaintext still holds the same identifier, under the new key.
        let carriers = store.slots.filter { $0.plaintext.range(of: Data(identifier.utf8)) != nil }
        #expect(carriers.count >= 3, "a group slot, a draft's recipient and a custody payload carry it; found \(carriers.map(\.name))")
        for carrier in carriers {
            let current = try #require(carrier.load(context), "\(carrier.name)")
            let opened  = Sealing.open(current, key: Frozen.newKey(carrier.owner, form: form), aad: carrier.aad)
            #expect(opened?.range(of: Data(identifier.utf8)) != nil, "\(carrier.name) has to open under the new key and still hold the same identifier")
        }
    }

    @Test("Random filler in a container that also holds real values changes with them: every member changes, or none does",
          arguments: KeyForm.allCases)
    func uniformChange(form: KeyForm) throws {
        let (keys, store) = try prepare(form)
        #expect(!store.fillers.isEmpty)

        try KeyReseal.run(context: store.newContext(), keyManager: keys, batchSize: 7)

        let context = store.newContext()
        let unchanged = store.fillers.filter { $0.load(context) == $0.before }.map(\.name)
        #expect(unchanged.isEmpty, "filler that kept its bytes next to values that changed: \(shown(unchanged))")

        let resized = store.fillers.filter { $0.load(context)?.count != $0.before.count }.map(\.name)
        #expect(resized.isEmpty, "filler of another length: \(shown(resized))")
    }

    @Test("A run that finds the real members already under the new key still changes a container whole, and changes nothing else",
          arguments: KeyForm.allCases)
    func rerunChangesContainersWhole(form: KeyForm) throws {
        let (keys, store) = try prepare(form)
        try KeyReseal.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        let first = snapshot(store)

        // The epoch is gone and the previous release wrote nothing: every real member is current.
        let context = store.newContext()
        try #require(try context.fetch(FetchDescriptor<AppLayerConfig>()).first).keyEpoch = nil
        try context.save()
        let report = try KeyReseal.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        let second = snapshot(store)

        #expect(report.outcome == .completed)
        #expect(report.total.resealed == 0, "nothing was legacy")

        let whole: Set<String> = [
            "Group.realMemberSlots", "Group.duressMemberSlots", "Group.deeperMemberSlots",
            "BackupEncryptionKey.depth", "BackupEncryptionKey.deletionToken",
        ]
        let members = store.slots.filter { whole.contains($0.entry) }.map(\.name) + store.fillers.map(\.name)
        let kept = members.filter { first[$0] == second[$0] }
        #expect(!members.isEmpty && kept.isEmpty, "a container that changes whole kept the bytes of: \(shown(kept))")

        let others = store.slots.filter { !whole.contains($0.entry) }.map(\.name) + store.references.map(\.name) + store.untouched.map(\.name)
        let changed = others.filter { first[$0] != second[$0] }
        #expect(changed.isEmpty, "changed though already under the new key: \(shown(changed))")
    }
}


// MARK: - Crash safety

@Suite("Key reseal — crash safety", .ambientFrozenTestKeyManager)
@MainActor
struct KeyResealCrashSafetyTests {

    @Test("Interrupted at each point: nothing is unreadable, the relaunch finishes, and a third run changes no byte",
          arguments: KeyReseal.FaultPoint.allCases)
    func interruptionLosesNothing(point: KeyReseal.FaultPoint) throws {
        let (keys, store) = try prepare(.hybrid)

        // The launch sequence, with a kill at `point`.
        let faults = KeyReseal.Faults(interruptAt: point)
        let first  = KeyReseal.$faults.withValue(faults) {
            LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        }
        #expect(faults.reached.contains(point), "the pass never reached \(point)")
        if case .failure(let error) = first.reseal {
            #expect((error as? KeyReseal.InjectedFault)?.point == point)
        } else {
            Issue.record("the pass was to be interrupted at \(point) and was not")
        }

        // Whatever was committed, each value opens under the legacy key or the new one; none under neither.
        let stranded = slots(store, notIn: .legacy, form: .hybrid, afterLaunchPasses: true).filter { !$0.hasSuffix("=new") }
        #expect(stranded.isEmpty, "unreadable after an interruption at \(point): \(shown(stranded))")
        #expect(appConfig(store)?.keyEpoch == nil, "no epoch may be written at \(point): the pass has not finished")

        // Relaunch without the fault: the end state is an uninterrupted run's.
        let second = LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        guard case .success(let report) = second.reseal else {
            Issue.record("the relaunch failed: \(second.reseal)")
            return
        }
        #expect(report.outcome == .completed)
        #expect(keyEpoch(store, form: .hybrid) == Frozen.epoch(.hybrid))

        let notNew = slots(store, notIn: .new, form: .hybrid, afterLaunchPasses: true)
        #expect(notNew.isEmpty, "after the relaunch: \(shown(notNew))")

        // A third run: the epoch is there, so the pass is skipped and not a byte changes.
        let before = snapshot(store)
        let third  = LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        #expect(snapshot(store) == before)
        if case .success(let thirdReport) = third.reseal {
            #expect(thirdReport.outcome == .alreadyDone)
        } else {
            Issue.record("the third run failed: \(third.reseal)")
        }
    }

    @Test("A relaunch after an interruption mid-batch reports what the first run had already moved as skipped")
    func relaunchSkipsWhatIsDone() throws {
        let (keys, store) = try prepare(.hybrid)

        let faults = KeyReseal.Faults(interruptAt: .midBatch)
        _ = try? KeyReseal.$faults.withValue(faults) {
            try KeyReseal.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        }
        #expect(faults.reached.contains(.midBatch))

        let report = try KeyReseal.run(context: store.newContext(), keyManager: keys, batchSize: 7)

        #expect(report.outcome == .completed)
        #expect(report.total.skipped + report.total.resealed == store.slots.count)
        #expect(report.total.resealed > 0 && report.total.skipped > 0, "a mid-batch kill leaves some batches committed and the rest to do")
    }

    @Test("Each new ciphertext is opened and compared before it replaces the old: a corrupt sealer leaves every old byte, writes no epoch, and reports the failure")
    func readBackBeforeReplace() throws {
        let (keys, store) = try prepare(.hybrid)
        let before = snapshot(store)

        let faults = KeyReseal.Faults(corruptsNewCiphertext: true)
        let report = try KeyReseal.$faults.withValue(faults) {
            try KeyReseal.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        }

        #expect(snapshot(store) == before, "not one byte, filler included, may change when the new ciphertexts are bad")
        #expect(appConfig(store)?.keyEpoch == nil)
        #expect(report.epochWritten == false)
        #expect(report.outcome == .incomplete)
        #expect(report.total.failed == store.slots.count, "each value that couldn't be moved is reported: \(report.total)")
        #expect(report.total.resealed == 0)
    }
}

// MARK: - Failure leaves data intact

@Suite("Key reseal — failures leave data intact", .ambientFrozenTestKeyManager)
@MainActor
struct KeyResealFailureTests {

    /// A run that must write nothing: the report says why, and the bytes, the epoch and the keychain are as they were.
    private func expectAborted(
        _ reason: KeyReseal.AbortReason, store: LegacyStore, keys: TestKeyManager, secrets: (Data?, TierPQRecord?),
        sourceLocation: SourceLocation = #_sourceLocation
    ) throws {
        let before = snapshot(store)

        let report = try KeyReseal.run(context: store.newContext(), keyManager: keys, batchSize: 7)

        #expect(report.outcome == .aborted(reason), "\(report.outcome)", sourceLocation: sourceLocation)
        #expect(report.epochWritten == false, sourceLocation: sourceLocation)
        #expect(report.total == KeyReseal.Counts(), "nothing was touched: \(report.total)", sourceLocation: sourceLocation)
        #expect(snapshot(store) == before, "no byte may change", sourceLocation: sourceLocation)
        #expect(appConfig(store)?.keyEpoch == nil, sourceLocation: sourceLocation)
        #expect(keys.tierSecretU == secrets.0 && keys.tierPQRecordU == secrets.1, "the pass never creates a secret or a record", sourceLocation: sourceLocation)
    }

    @Test("r_U missing, no epoch yet: nothing is written and r_U is not created; once it is back, the next run finishes")
    func tierSecretMissing() throws {
        let (keys, store) = try prepare(.hybrid)
        keys.tierSecretU = nil

        try expectAborted(.tierSecretMissing, store: store, keys: keys, secrets: (nil, keys.tierPQRecordU))

        keys.tierSecretU = Frozen.tierSecretU
        #expect(try KeyReseal.run(context: store.newContext(), keyManager: keys, batchSize: 7).outcome == .completed)
    }

    @Test("The tier U PQ record missing, no epoch yet: nothing is written and the record is not created")
    func tierPQRecordMissing() throws {
        let (keys, store) = try prepare(.hybrid)
        keys.tierPQRecordU = nil

        try expectAborted(.tierPQRecordMissing, store: store, keys: keys, secrets: (keys.tierSecretU, nil))

        keys.tierPQRecordU = Frozen.recordU
        #expect(try KeyReseal.run(context: store.newContext(), keyManager: keys, batchSize: 7).outcome == .completed)
    }

    @Test("The local key unavailable (no Enclave): nothing is written, and the next run finishes")
    func localKeyUnavailable() throws {
        let (keys, store) = try prepare(.hybrid)
        keys.simulatesLocalKeyUnavailable = true

        try expectAborted(.localKeyUnavailable, store: store, keys: keys, secrets: (keys.tierSecretU, keys.tierPQRecordU))

        keys.simulatesLocalKeyUnavailable = false
        #expect(try KeyReseal.run(context: store.newContext(), keyManager: keys, batchSize: 7).outcome == .completed)
    }

    @Test("A locked device (the secret read throws) is not a missing secret: nothing is written, nothing is created, and the next run finishes")
    func deviceLocked() throws {
        let (keys, store) = try prepare(.hybrid)
        keys.simulatesLockedDevice = true

        try expectAborted(.tierSecretUnreadable, store: store, keys: keys, secrets: (Frozen.tierSecretU, Frozen.recordU))

        // The bootstrap does not create on a guess either.
        let bootstrap = try KeyReseal.bootstrap(context: store.newContext(), keyManager: keys)
        #expect(bootstrap.refusals.contains(.unreadable))
        #expect(bootstrap.createdTierSecret == false && bootstrap.createdTierPQRecord == false)

        keys.simulatesLockedDevice = false
        #expect(try KeyReseal.run(context: store.newContext(), keyManager: keys, batchSize: 7).outcome == .completed)
    }

    @Test("r_U missing after an epoch exists: the bootstrap does not recreate it, the run writes nothing, and the report says why")
    func tierSecretMissingAfterTheEpoch() throws {
        let (keys, store) = try prepare(.hybrid)
        try writeEpoch(store, form: .hybrid)
        keys.tierSecretU = nil
        let before = snapshot(store)

        let bootstrap = try KeyReseal.bootstrap(context: store.newContext(), keyManager: keys)
        let report    = try KeyReseal.run(context: store.newContext(), keyManager: keys, batchSize: 7)

        #expect(bootstrap.refusals.contains(.tierSecretMissingAfterEpoch))
        #expect(bootstrap.createdTierSecret == false)
        #expect(keys.tierSecretU == nil, "a new r_U would leave everything sealed under the old one unreadable")
        #expect(report.outcome == .alreadyDone)
        #expect(snapshot(store) == before)
    }

    @Test("The tier U PQ record missing after an epoch exists: the bootstrap does not recreate it, and nothing is written")
    func tierPQRecordMissingAfterTheEpoch() throws {
        let (keys, store) = try prepare(.hybrid)
        try writeEpoch(store, form: .hybrid)
        keys.tierPQRecordU = nil
        let before = snapshot(store)

        let bootstrap = try KeyReseal.bootstrap(context: store.newContext(), keyManager: keys)
        let report    = try KeyReseal.run(context: store.newContext(), keyManager: keys, batchSize: 7)

        #expect(bootstrap.refusals.contains(.tierPQRecordMissingAfterEpoch))
        #expect(bootstrap.createdTierPQRecord == false)
        #expect(keys.tierPQRecordU == nil, "a new record is a new key")
        #expect(report.outcome == .alreadyDone)
        #expect(snapshot(store) == before)
    }

    @Test("One row that opens under neither key is left as it is; the rest are resealed and the epoch is set",
          arguments: KeyForm.allCases)
    func oneRowOpensUnderNeither(form: KeyForm) throws {
        let (keys, store) = try prepare(form)

        // A contact whose name was sealed under a key this device never had.
        let context  = store.newContext()
        let stranger = Contact.Profile(
            identifier: "", givenName: "", familyName: "", middleName: "", nickname: "",
            organizationName: "", departmentName: "", jobTitle: "",
            encryptionScheme: EncryptionScheme.v2_hybridPQ.rawValue
        )
        let strangerBytes = Sealing.seal(Data("Stranger".utf8), key: Sealing.stranger, aad: Sealing.fixedAAD)
        let strangerString = strangerBytes.base64EncodedString()
        stranger.givenName = strangerString
        context.insert(stranger)
        try context.save()

        let report = try KeyReseal.run(context: store.newContext(), keyManager: keys, batchSize: 7)

        #expect(report.outcome == .completed)
        #expect(report.entries["Profile.givenName"]?.left == 1)
        #expect(report.entries["Profile.givenName"]?.resealed == 1)
        #expect(report.total.left == 1 && report.total.failed == 0)
        #expect(report.total.resealed == store.slots.count)
        #expect(keyEpoch(store, form: form) == Frozen.epoch(form), "a row nothing can open does not stop the epoch")

        let rows = try store.newContext().fetch(FetchDescriptor<Contact.Profile>(predicate: #Predicate { $0.givenName == strangerString }))
        #expect(rows.count == 1, "the stranger's bytes are untouched")

        #expect(slots(store, notIn: .new, form: form).isEmpty)
    }
}

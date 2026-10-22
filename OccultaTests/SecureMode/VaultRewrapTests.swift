//
//  VaultRewrapTests.swift
//  OccultaTests
//
//  Bug 171, Stage 4: the vault tier, rewrapped at the first vault unlock. `VaultManager.unlock(context:)`, when the sealed
//  `AppLayerConfig.vaultKeyEpoch` is 1, runs the existing legacy-storage migration under the legacy vault key, creates `r_B`
//  and the tier B record if absent, rewraps in one transaction every `VaultEntry.encryptedEntryKey`, every
//  `BackupEncryptionKey.encryptedPayload` (a container: the whole table, filler included, changes together) and
//  `backup-export-meta.dat` (written to a temp file, read back, renamed, before the commit), sets the epoch to 2, and only
//  then switches `deriveVaultKey(context:)` from the legacy derivation to the Enclave-bound one.
//
//  Written first (Stage 4a), against a stub that does nothing, and failing for the right reason: nothing moves, the epoch
//  stays 1, the vault key stays legacy.
//
//  Frozen: fixtures are sealed with pinned key bytes (`VaultPins`), not through the code under test. Everything runs without
//  a Secure Enclave on `TestKeyManager.frozen()`. The real vault access control is device-only (Bug 171, 0b): the Simulator
//  can't create the key, so `deriveVaultKey` on a real `Manager.Key` and `retrieveVaultPrivateKey` creating `r_B` with the
//  vault Enclave key are not covered here.
//
//    - `VaultRewrapFixtureTests`:  the pins, and that the fixture is what the previous release left.
//    - `VaultRewrapPassTests`:     `KeyReseal.rewrapVault` directly, on a temp directory of its own.
//    - `VaultRewrapUnlockTests`:   `VaultManager.unlock(context:)`: the trigger, the order, the switch, retries, backups.
//

import Testing
import CryptoKit
import Foundation
import LocalAuthentication
import SwiftData

@testable import Occulta
@testable import OccultaFormats

// MARK: - The pins

/// The vault key of the frozen manager, in the three forms it can be in: `legacyKey(.vault)`, and `enclaveBoundKey(.vault)`
/// with a classical tier B record and with a hybrid one (the frozen hybrid record).
enum VaultPins {
    static let legacy    = "0c54f124e4e003dbf9c2e47d272dba903669e9d339c76b03ece70d45ee1e3a67"
    static let classical = "c166bcb59a1efc93ca7c7490d5bb4b3cf9648597f768062b1bf52a586d982075"
    static let hybrid    = "8314ae51dc9b3ba106ac81ec94749c5e76ba8f9be69d6a833d9c4cdaacb4f760"

    static var legacyKey: SymmetricKey { SymmetricKey(data: dataFromHex(Self.legacy)) }

    static func newKey(_ form: KeyForm) -> SymmetricKey {
        SymmetricKey(data: dataFromHex(form == .hybrid ? Self.hybrid : Self.classical))
    }

    /// The tier B record of `form`.
    static func record(_ form: KeyForm) -> TierPQRecord {
        form == .hybrid ? Frozen.recordU : .classical
    }

    /// The constant `backup-export-meta.dat` is sealed with.
    static let exportMetaAAD = Data("occulta.backup-export-meta-v1".utf8)

    /// 32 depth slots of 28 bytes.
    static let exportMetaPlainSize = 32 * 28
}

/// What a sealed vault value stands at.
enum VaultState: Equatable, CustomStringConvertible {
    case legacy, new, neither, absent
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

/// A vault as the release before Stage 4 left it: entries with their per-entry keys wrapped under the legacy vault key, a
/// backup-key table (real rows, an orphaned one, 32 filler), and `backup-export-meta.dat` in a directory of its own, with
/// `vaultKeyEpoch` sealed at 1.
@MainActor
final class VaultStore {

    let container: ModelContainer
    let keys: TestKeyManager
    let directory: URL
    let form: KeyForm

    struct Entry {
        let id: PersistentIdentifier
        let uuid: UUID
        let pek: Data
        let label: String
        let content: Data
        let depth: Int
    }

    struct BackupRow {
        let id: PersistentIdentifier
        let uuid: UUID
        let depth: Int?
        let payload: Data?
        let orphaned: Bool
    }

    private(set) var entries: [Entry] = []
    private(set) var backupRows: [BackupRow] = []
    private(set) var exportMetaPlain = Data()

    // Identifiers are only permanent once saved, so the rows are kept until then.
    private var pendingEntries: [(model: VaultEntry, uuid: UUID, pek: Data, label: String, content: Data, depth: Int)] = []
    private var pendingBackupRows: [(model: BackupEncryptionKey, uuid: UUID, depth: Int?, payload: Data?, orphaned: Bool)] = []

    var exportMetaURL: URL { self.directory.appendingPathComponent("backup-export-meta.dat") }
    var exportMetaTemporaryURL: URL { KeyReseal.exportMetadataTemporaryURL(in: self.directory) }

    /// - Parameters:
    ///   - form: The tier B record: classical, or the frozen hybrid one.
    ///   - entries: How many vault entries; their depths cycle through `0...5`, and every 7th is orphaned.
    ///   - backupDepths: Depths that hold a real backup key. The rest of the table is filler, 32 rows in all.
    ///   - file: Whether `backup-export-meta.dat` exists.
    ///   - epoch: The vault epoch to seal, or nil to leave the column empty.
    init(keys: TestKeyManager, form: KeyForm, entries: Int = 12, backupDepths: [Int] = [0, 2, 5], file: Bool = true, epoch: UInt8? = 1) throws {
        let schema = OccultaApp.schema
        self.container = try ModelContainer(for: schema, configurations: ModelConfiguration(schema: schema, isStoredInMemoryOnly: true))
        self.keys      = keys
        self.form      = form
        self.directory = FileManager.default.temporaryDirectory.appendingPathComponent("vault-rewrap-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: self.directory, withIntermediateDirectories: true)

        keys.tierPQRecordB = VaultPins.record(form)

        let context = ModelContext(self.container)
        let config  = AppLayerConfig()
        context.insert(config)
        if let epoch {
            config.vaultKeyEpoch = try KeyReseal.Epoch(number: epoch, form: .classical).sealed(using: Frozen.newKey(.local, form: .hybrid))
        }

        try self.seedEntries(count: entries, into: context)
        try self.seedBackupTable(depths: backupDepths, into: context)
        try context.save()
        self.entries = self.pendingEntries.map {
            Entry(id: $0.model.persistentModelID, uuid: $0.uuid, pek: $0.pek, label: $0.label, content: $0.content, depth: $0.depth)
        }
        self.backupRows = self.pendingBackupRows.map {
            BackupRow(id: $0.model.persistentModelID, uuid: $0.uuid, depth: $0.depth, payload: $0.payload, orphaned: $0.orphaned)
        }
        self.pendingEntries = []
        self.pendingBackupRows = []
        if file { try self.seedExportMeta() }
    }

    deinit {
        try? FileManager.default.removeItem(at: self.directory)
    }

    private func seedEntries(count: Int, into context: ModelContext) throws {
        for index in 0..<count {
            let depth   = index % 6
            let entry   = VaultEntry(encryptedLabel: Data(), encryptedContent: Data())
            let pek     = Sealing.random(32)
            let label   = "entry \(index)"
            let content = Sealing.random(64 + index)

            entry.encryptedEntryKey = Sealing.seal(pek, key: VaultPins.legacyKey, aad: entry.aad(for: .entryKey))
            entry.encryptedLabel    = Sealing.seal(try JSONEncoder().encode(SealedLabelPayload(type: .note, label: label)),
                                                   key: SymmetricKey(data: pek), aad: entry.aad(for: .label))
            entry.encryptedContent  = Sealing.seal(content, key: SymmetricKey(data: pek), aad: entry.aad(for: .content))
            entry.visibleThroughDepth = try DepthCodec.encode(depth).encrypt()
            entry.deletionToken       = try (index % 7 == 6 ? VaultEntry.orphanedToken : VaultEntry.liveToken).encrypt()
            context.insert(entry)

            self.pendingEntries.append((entry, entry.id, pek, label, content, depth))
        }
    }

    private func seedBackupTable(depths: [Int], into context: ModelContext) throws {
        for (index, depth) in depths.enumerated() {
            let orphaned = index == depths.count - 1 && depths.count > 1
            let payload  = BackupEncryptionKey.Payload(bekBytes: Sealing.random(32), distributionID: UUID(), shardMetadata: nil)
            let plain    = try VaultManager.Backup.PayloadCodec.encode(payload)

            let row = BackupEncryptionKey(
                depth: try DepthCodec.encode(depth).encrypt(),
                deletionToken: try (orphaned ? BackupEncryptionKey.orphanedToken : BackupEncryptionKey.liveToken).encrypt(),
                encryptedPayload: Data()
            )
            row.encryptedPayload = Sealing.seal(plain, key: VaultPins.legacyKey, aad: row.aad())
            context.insert(row)
            self.pendingBackupRows.append((row, row.id, depth, plain, orphaned))
        }

        // Filler to the baseline: random in every field, as `ensureBackupKeyFillerRows` writes it.
        for _ in self.pendingBackupRows.count..<32 {
            let row = BackupEncryptionKey(
                depth: Sealing.random(DepthCodec.sealedSize), deletionToken: Sealing.random(29),
                encryptedPayload: Sealing.random(VaultManager.Backup.PayloadCodec.payloadSize + 28)
            )
            context.insert(row)
            self.pendingBackupRows.append((row, row.id, nil, nil, false))
        }
    }

    private func seedExportMeta() throws {
        self.exportMetaPlain = Sealing.random(VaultPins.exportMetaPlainSize)
        try self.writeExportMeta(Sealing.seal(self.exportMetaPlain, key: VaultPins.legacyKey, aad: VaultPins.exportMetaAAD))
    }

    func writeExportMeta(_ bytes: Data) throws {
        try bytes.write(to: self.exportMetaURL)
    }

    // MARK: Reading

    func newContext() -> ModelContext {
        let context = ModelContext(self.container)
        context.autosaveEnabled = false
        return context
    }

    var locations: KeyReseal.Locations {
        KeyReseal.Locations(applicationSupport: self.directory, store: nil)
    }

    func config() -> AppLayerConfig? {
        try? self.newContext().fetch(FetchDescriptor<AppLayerConfig>()).first
    }

    /// The vault epoch as stored: 1 or 2, or nil.
    func epoch() -> UInt8? {
        KeyReseal.Epoch.opening(self.config()?.vaultKeyEpoch, using: Frozen.newKey(.local, form: .hybrid))?.number
    }

    func state(of sealed: Data?, aad: Data) -> VaultState {
        guard let sealed else { return .absent }
        if Sealing.open(sealed, key: VaultPins.newKey(self.form), aad: aad) != nil { return .new }
        if Sealing.open(sealed, key: VaultPins.legacyKey, aad: aad) != nil { return .legacy }
        return .neither
    }

    func entryKeyStates() -> [UUID: VaultState] {
        let context = self.newContext()
        var out: [UUID: VaultState] = [:]
        for item in self.entries {
            guard let entry = context.model(for: item.id) as? VaultEntry else { out[item.uuid] = .absent; continue }
            out[item.uuid] = self.state(of: entry.encryptedEntryKey, aad: entry.aad(for: .entryKey))
        }
        return out
    }

    /// The PEK as it now unwraps under `key`, or nil.
    func pek(of item: Entry, using key: SymmetricKey) -> Data? {
        guard let entry = self.newContext().model(for: item.id) as? VaultEntry else { return nil }
        return Sealing.open(entry.encryptedEntryKey, key: key, aad: entry.aad(for: .entryKey))
    }

    func backupStates() -> [UUID: VaultState] {
        let context = self.newContext()
        var out: [UUID: VaultState] = [:]
        for item in self.backupRows {
            guard let row = context.model(for: item.id) as? BackupEncryptionKey else { out[item.uuid] = .absent; continue }
            out[item.uuid] = self.state(of: row.encryptedPayload, aad: row.aad())
        }
        return out
    }

    func fileState() -> VaultState {
        guard let bytes = try? Data(contentsOf: self.exportMetaURL) else { return .absent }
        return self.state(of: bytes, aad: VaultPins.exportMetaAAD)
    }

    /// Every stored byte the rewrap may touch or must not, by name.
    func snapshot() -> [String: Data] {
        let context = self.newContext()
        var out: [String: Data] = [:]
        for item in self.entries {
            guard let entry = context.model(for: item.id) as? VaultEntry else { continue }
            out["entryKey:\(item.uuid)"] = entry.encryptedEntryKey
            out["label:\(item.uuid)"]    = entry.encryptedLabel
            out["content:\(item.uuid)"]  = entry.encryptedContent
        }
        for item in self.backupRows {
            guard let row = context.model(for: item.id) as? BackupEncryptionKey else { continue }
            out["backup:\(item.uuid)"]         = row.encryptedPayload
            out["backupDepth:\(item.uuid)"]    = row.depth
            out["backupToken:\(item.uuid)"]    = row.deletionToken
        }
        if let epoch = self.config()?.vaultKeyEpoch { out["epoch"] = epoch }
        if let file = try? Data(contentsOf: self.exportMetaURL) { out["file"] = file }
        return out
    }

    func rowCounts() -> [String: Int] {
        let context = self.newContext()
        return [
            "VaultEntry": (try? context.fetchCount(FetchDescriptor<VaultEntry>())) ?? -1,
            "BackupEncryptionKey": (try? context.fetchCount(FetchDescriptor<BackupEncryptionKey>())) ?? -1,
        ]
    }

    @discardableResult
    func rewrap() throws -> KeyReseal.VaultReport {
        try KeyReseal.rewrapVault(context: self.newContext(), keyManager: self.keys, authContext: LAContext(), locations: self.locations)
    }

    func vaultManager() -> VaultManager {
        let vault = VaultManager(modelContainer: self.container, keyManager: self.keys)
        vault.rewrapLocations = self.locations
        return vault
    }
}

@MainActor
private func prepareVault(
    _ form: KeyForm, entries: Int = 12, backupDepths: [Int] = [0, 2, 5], file: Bool = true, epoch: UInt8? = 1
) throws -> (keys: TestKeyManager, store: VaultStore) {
    let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
    return (keys, try VaultStore(keys: keys, form: form, entries: entries, backupDepths: backupDepths, file: file, epoch: epoch))
}

// MARK: - Pins and fixtures

@Suite("Vault rewrap — pins and fixtures", .ambientFrozenTestKeyManager)
@MainActor
struct VaultRewrapFixtureTests {

    @Test("Pin: the legacy vault key and the Enclave-bound ones of both forms are the pinned bytes (passes today)", arguments: KeyForm.allCases)
    func vaultKeysArePinned(form: KeyForm) throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.tierPQRecordB = VaultPins.record(form)
        let context = LAContext()

        #expect(keyBytes(try #require(try keys.legacyKey(.vault(context)))) == keyBytes(VaultPins.legacyKey))
        #expect(keyBytes(try #require(try keys.enclaveBoundKey(.vault(context)))) == keyBytes(VaultPins.newKey(form)))
    }

    @Test("The fixture is what the previous release left: every key, payload and the file under the legacy key, filler under neither (passes today)",
          arguments: KeyForm.allCases)
    func fixtureIsLegacy(form: KeyForm) throws {
        let (_, store) = try prepareVault(form)

        #expect(Set(store.entryKeyStates().values) == [.legacy])
        let backup = store.backupStates()
        for row in store.backupRows {
            #expect(backup[row.uuid] == (row.payload == nil ? .neither : .legacy), "row at depth \(String(describing: row.depth))")
        }
        #expect(store.backupRows.count == 32 && store.backupRows.filter { $0.payload != nil }.count == 3)
        #expect(store.fileState() == .legacy)
        #expect(store.epoch() == 1)
    }

    @Test("Before the first unlock the vault is untouched and derives its legacy key: nothing at launch moves it (passes today)",
          arguments: KeyForm.allCases)
    func launchLeavesTheVaultAlone(form: KeyForm) throws {
        let (keys, store) = try prepareVault(form)
        let before = store.snapshot()

        LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)

        #expect(Manager.Ambient.vaultKeys == .legacy)
        #expect(keyBytes(try #require(try keys.deriveVaultKey(context: LAContext()))) == keyBytes(VaultPins.legacyKey))
        let after = store.snapshot()
        let changed = before.keys.filter { $0.hasPrefix("entryKey:") || $0.hasPrefix("backup:") || $0 == "file" }.filter { before[$0] != after[$0] }
        #expect(changed.isEmpty, "the vault's own values: \(shown(changed.sorted()))")
        #expect(store.epoch() == 1)
    }

    @Test("deriveVaultKey follows Manager.Ambient.vaultKeys: the legacy key, then the Enclave-bound one", arguments: KeyForm.allCases)
    func accessorFollowsTheState(form: KeyForm) throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.tierPQRecordB = VaultPins.record(form)
        let context = LAContext()

        #expect(Manager.Ambient.vaultKeys == .legacy, "the default")
        #expect(keyBytes(try #require(try keys.deriveVaultKey(context: context))) == keyBytes(VaultPins.legacyKey))

        Manager.Ambient.setVaultKeys(.enclaveBound)
        #expect(keyBytes(try #require(try keys.deriveVaultKey(context: context))) == keyBytes(VaultPins.newKey(form)))

        keys.derivesLegacyKeysOnly = true
        #expect(keyBytes(try #require(try keys.deriveVaultKey(context: context))) == keyBytes(VaultPins.legacyKey), "what a downgraded build derives")
    }
}

// MARK: - The pass

@Suite("Vault rewrap — the pass", .ambientFrozenTestKeyManager)
@MainActor
struct VaultRewrapPassTests {

    @Test("Every entry key, every backup payload and the export file come across, and nothing opens under the legacy key afterwards",
          arguments: KeyForm.allCases)
    func rewrapsEverything(form: KeyForm) throws {
        let (_, store) = try prepareVault(form)
        let counts = store.rowCounts()

        let report = try store.rewrap()

        #expect(report.outcome == .rewrapped)
        #expect(report.form == (form == .hybrid ? .hybrid : .classical))
        #expect(Set(store.entryKeyStates().values) == [.new])
        let backup = store.backupStates()
        for row in store.backupRows where row.payload != nil { #expect(backup[row.uuid] == .new, "backup row at depth \(String(describing: row.depth))") }
        #expect(store.fileState() == .new)
        #expect(store.epoch() == 2, "the epoch is 2")
        #expect(KeyReseal.Epoch.opening(store.config()?.vaultKeyEpoch, using: Frozen.newKey(.local, form: .hybrid))?.form == (form == .hybrid ? .hybrid : .classical))
        #expect(store.rowCounts() == counts, "row counts")

        #expect(report.entryKeys.resealed == store.entries.count && report.entryKeys.failed == 0)
        #expect(report.backupPayloads.resealed == 3 && report.backupPayloads.refreshed == 29 && report.backupPayloads.failed == 0)
        #expect(report.exportMetadata == true)
    }

    @Test("Each per-entry key unwraps to the same 32 bytes under the new key, and the labels and contents are not touched",
          arguments: KeyForm.allCases)
    func entriesStillOpen(form: KeyForm) throws {
        let (_, store) = try prepareVault(form)
        let before = store.snapshot()

        try store.rewrap()

        for item in store.entries {
            #expect(store.pek(of: item, using: VaultPins.newKey(form)) == item.pek, "\(item.label)")
            #expect(store.pek(of: item, using: VaultPins.legacyKey) == nil)
        }
        let after = store.snapshot()
        let touched = before.keys.filter { $0.hasPrefix("label:") || $0.hasPrefix("content:") || $0.hasPrefix("backupDepth:") || $0.hasPrefix("backupToken:") }
            .filter { before[$0] != after[$0] }
        #expect(touched.isEmpty, "labels, contents and the local-key fields stay byte for byte: \(shown(touched.sorted()))")
    }

    @Test("A backup payload opens to the same plaintext under the new key, whatever its row: claimed, orphaned, every depth",
          arguments: KeyForm.allCases)
    func backupPayloadsOpen(form: KeyForm) throws {
        let (_, store) = try prepareVault(form)
        try store.rewrap()

        let context = store.newContext()
        for item in store.backupRows {
            let row = try #require(context.model(for: item.id) as? BackupEncryptionKey)
            #expect(row.encryptedPayload.count == VaultManager.Backup.PayloadCodec.payloadSize + 28, "same length, filler included")
            guard let plain = item.payload else { continue }
            #expect(Sealing.open(row.encryptedPayload, key: VaultPins.newKey(form), aad: row.aad()) == plain, "depth \(String(describing: item.depth)), orphaned \(item.orphaned)")
        }
    }

    @Test("The backup-key table changes whole: every payload, filler and real, has different bytes afterwards (the uniform-change rule)",
          arguments: KeyForm.allCases)
    func backupTableChangesWhole(form: KeyForm) throws {
        let (_, store) = try prepareVault(form)
        let before = store.snapshot()

        try store.rewrap()

        let after = store.snapshot()
        let kept = store.backupRows.map { "backup:\($0.uuid)" }.filter { before[$0] == after[$0] }
        #expect(kept.isEmpty, "payloads that kept their bytes: \(kept.count) of \(store.backupRows.count)")
    }

    @Test("A second run finds the epoch at 2 and reads and writes nothing", arguments: KeyForm.allCases)
    func secondRunDoesNothing(form: KeyForm) throws {
        let (_, store) = try prepareVault(form)
        try store.rewrap()
        let before = store.snapshot()

        let report = try store.rewrap()

        #expect(report.outcome == .alreadyDone)
        #expect(store.snapshot() == before)
    }

    @Test("Interrupted at each point: nothing changes, the file is back as it was, and the next run moves everything once",
          arguments: KeyReseal.VaultFaultPoint.allCases, KeyForm.allCases)
    func interruptionLosesNothing(point: KeyReseal.VaultFaultPoint, form: KeyForm) throws {
        let (_, store) = try prepareVault(form)
        let before = store.snapshot()

        let faults = KeyReseal.Faults(interruptAtVault: point)
        var thrown: (any Error)?
        do {
            try KeyReseal.$faults.withValue(faults) { _ = try store.rewrap() }
        } catch {
            thrown = error
        }

        #expect(faults.reachedVault.contains(point), "the pass never reached \(point)")
        #expect((thrown as? KeyReseal.InjectedVaultFault)?.point == point, "the pass was to be interrupted at \(point)")
        #expect(store.snapshot() == before, "every byte the pass may touch is as it was, the file included")
        #expect(Set(store.entryKeyStates().values) == [.legacy] && store.fileState() == .legacy && store.epoch() == 1)
        #expect(!FileManager.default.fileExists(atPath: store.exportMetaTemporaryURL.path), "and no temp file is left behind")

        let second = try store.rewrap()
        #expect(second.outcome == .rewrapped)
        #expect(Set(store.entryKeyStates().values) == [.new] && store.fileState() == .new && store.epoch() == 2)

        let done = store.snapshot()
        #expect(try store.rewrap().outcome == .alreadyDone)
        #expect(store.snapshot() == done, "a third run changes no byte")
    }

    @Test("A kill between the file and the commit (the file under the new key, every row and the epoch still old): nothing the vault needs is unreadable, and the next run finishes",
          arguments: KeyForm.allCases)
    func killBetweenFileAndCommit(form: KeyForm) throws {
        let (_, store) = try prepareVault(form)
        // The state a kill leaves: the rename happened, the transaction did not.
        try store.writeExportMeta(Sealing.seal(store.exportMetaPlain, key: VaultPins.newKey(form), aad: VaultPins.exportMetaAAD))
        #expect(store.fileState() == .new && Set(store.entryKeyStates().values) == [.legacy] && store.epoch() == 1)
        for item in store.entries { #expect(store.pek(of: item, using: VaultPins.legacyKey) == item.pek, "the vault still opens under the legacy key") }

        let report = try store.rewrap()

        #expect(report.outcome == .rewrapped)
        #expect(report.exportMetadata == false, "the file was already under the new key")
        #expect(Set(store.entryKeyStates().values) == [.new] && store.fileState() == .new && store.epoch() == 2)
        let file = try Data(contentsOf: store.exportMetaURL)
        #expect(Sealing.open(file, key: VaultPins.newKey(form), aad: VaultPins.exportMetaAAD) == store.exportMetaPlain, "the same plaintext")
    }

    @Test("A stale temp file from a killed run is replaced, not left or read", arguments: KeyForm.allCases)
    func staleTemporaryFile(form: KeyForm) throws {
        let (_, store) = try prepareVault(form)
        try Sealing.random(924).write(to: store.exportMetaTemporaryURL)

        try store.rewrap()

        #expect(!FileManager.default.fileExists(atPath: store.exportMetaTemporaryURL.path))
        #expect(store.fileState() == .new)
    }

    @Test("Each new ciphertext is opened and compared before it replaces the old: a corrupt sealer leaves every byte, the file and the epoch, and reports it",
          arguments: KeyForm.allCases)
    func readBackBeforeReplace(form: KeyForm) throws {
        let (_, store) = try prepareVault(form)
        let before = store.snapshot()

        let report = try KeyReseal.$faults.withValue(KeyReseal.Faults(corruptsNewCiphertext: true)) { try store.rewrap() }

        #expect(report.outcome == .incomplete)
        #expect(report.entryKeys.failed == store.entries.count && report.backupPayloads.failed > 0)
        #expect(store.snapshot() == before, "not one byte, filler included, may change when the new ciphertexts are bad")
        #expect(store.epoch() == 1 && store.fileState() == .legacy)
    }

    @Test("One entry key that opens under neither is left as it is; the rest move and the epoch is set", arguments: KeyForm.allCases)
    func oneEntryOpensUnderNeither(form: KeyForm) throws {
        let (_, store) = try prepareVault(form)
        let stranded = try #require(store.entries.first)
        let context = store.newContext()
        let entry = try #require(context.model(for: stranded.id) as? VaultEntry)
        let bytes = Sealing.seal(Sealing.random(32), key: Sealing.stranger, aad: entry.aad(for: .entryKey))
        entry.encryptedEntryKey = bytes
        try context.save()

        let report = try store.rewrap()

        #expect(report.outcome == .rewrapped)
        #expect(report.entryKeys.left == 1 && report.entryKeys.resealed == store.entries.count - 1)
        #expect(store.snapshot()["entryKey:\(stranded.uuid)"] == bytes, "its bytes are untouched")
        #expect(store.epoch() == 2)
    }

    @Test("Entries added by the previous release after a downgrade (a key under the legacy key) are picked up; the rest are skipped", arguments: KeyForm.allCases)
    func reUpgrade(form: KeyForm) throws {
        let (_, store) = try prepareVault(form)
        try store.rewrap()

        // The downgrade: the epoch column is gone and re-seeded at 1; the previous release adds an entry under the legacy
        // key and rewrites the depth-0 backup payload under it.
        let context = store.newContext()
        let config = try #require(try context.fetch(FetchDescriptor<AppLayerConfig>()).first)
        config.vaultKeyEpoch = try KeyReseal.Epoch(number: 1, form: .classical).sealed(using: Frozen.newKey(.local, form: .hybrid))

        let added = VaultEntry(encryptedLabel: Data(), encryptedContent: Data())
        let pek = Sealing.random(32)
        added.encryptedEntryKey = Sealing.seal(pek, key: VaultPins.legacyKey, aad: added.aad(for: .entryKey))
        context.insert(added)

        let depth0 = try #require(store.backupRows.first)
        let row = try #require(context.model(for: depth0.id) as? BackupEncryptionKey)
        let rewritten = Sealing.random(32)
        row.encryptedPayload = Sealing.seal(rewritten, key: VaultPins.legacyKey, aad: row.aad())
        try context.save()
        let addedID = added.persistentModelID

        let report = try store.rewrap()

        #expect(report.outcome == .rewrapped)
        #expect(report.entryKeys.resealed == 1 && report.entryKeys.skipped == store.entries.count, "one to move, the rest already done")
        let fresh = store.newContext()
        let movedEntry = try #require(fresh.model(for: addedID) as? VaultEntry)
        #expect(Sealing.open(movedEntry.encryptedEntryKey, key: VaultPins.newKey(form), aad: movedEntry.aad(for: .entryKey)) == pek)
        let movedRow = try #require(fresh.model(for: depth0.id) as? BackupEncryptionKey)
        #expect(Sealing.open(movedRow.encryptedPayload, key: VaultPins.newKey(form), aad: movedRow.aad()) == rewritten, "what the previous release wrote is carried over")
        #expect(Set(store.entryKeyStates().values) == [.new])
    }

    // MARK: Creation, and failures

    @Test("r_B and the tier B record are created if absent while the epoch is 1, and only then", arguments: KeyForm.allCases)
    func createsWhatIsMissing(form: KeyForm) throws {
        let (keys, store) = try prepareVault(form)
        keys.tierSecretB   = nil
        keys.tierPQRecordB = nil

        let report = try store.rewrap()

        #expect(report.outcome == .rewrapped)
        #expect(keys.tierSecretB?.count == 32 && keys.tierPQRecordB != nil, "created by the first unlock")

        // The new key is made of what was just created, so it is not a pinned one: read it back from the manager.
        let created = try #require(try keys.enclaveBoundKey(.vault(LAContext())))
        #expect(keyBytes(created) != keyBytes(VaultPins.newKey(form)) && keyBytes(created) != keyBytes(VaultPins.legacyKey))
        for item in store.entries { #expect(store.pek(of: item, using: created) == item.pek, "the data is under keys that include them") }
        let file = try Data(contentsOf: store.exportMetaURL)
        #expect(Sealing.open(file, key: created, aad: VaultPins.exportMetaAAD) == store.exportMetaPlain)
    }

    @Test("At epoch 2 nothing is created, and a missing r_B or record is not replaced by a new one", arguments: KeyForm.allCases)
    func creationRule(form: KeyForm) throws {
        let (keys, store) = try prepareVault(form)
        try store.rewrap()
        keys.tierSecretB   = nil
        keys.tierPQRecordB = nil
        let before = store.snapshot()

        let report = try store.rewrap()

        #expect(report.outcome == .alreadyDone)
        #expect(keys.tierSecretB == nil && keys.tierPQRecordB == nil, "a new r_B would leave everything under the old one unreadable")
        #expect(store.snapshot() == before)
    }

    @Test("r_B unreadable: nothing is written and nothing is created, and the vault still opens under the legacy key",
          arguments: KeyForm.allCases)
    func tierSecretUnreadable(form: KeyForm) throws {
        let (keys, store) = try prepareVault(form)
        let before = store.snapshot()
        keys.simulatesVaultSecretUnreadable = true

        let report = try store.rewrap()

        #expect(report.outcome == .aborted(.tierSecretUnreadable))
        #expect(store.snapshot() == before)
        for item in store.entries { #expect(store.pek(of: item, using: VaultPins.legacyKey) == item.pek) }
        keys.simulatesVaultSecretUnreadable = false
        #expect(try store.rewrap().outcome == .rewrapped, "and the next run moves it")
    }

    @Test("A locked device: the epoch, sealed under the tier U key, can't be read, so nothing is written or created", arguments: KeyForm.allCases)
    func lockedDevice(form: KeyForm) throws {
        let (keys, store) = try prepareVault(form)
        let before = store.snapshot()
        keys.simulatesLockedDevice = true

        let report = try store.rewrap()

        #expect(report.outcome == .aborted(.epochUnreadable))
        #expect(store.snapshot() == before)
        keys.simulatesLockedDevice = false
        #expect(try store.rewrap().outcome == .rewrapped)
    }

    @Test("The vault key unavailable (the Enclave refuses): nothing is written", arguments: KeyForm.allCases)
    func vaultKeyUnavailable(form: KeyForm) throws {
        let (keys, store) = try prepareVault(form)
        let before = store.snapshot()
        keys.simulateVaultKeyFailure = true

        let report = try store.rewrap()

        #expect(report.outcome == .aborted(.vaultKeyUnavailable))
        #expect(store.snapshot() == before)
        keys.simulateVaultKeyFailure = false
        #expect(try store.rewrap().outcome == .rewrapped)
    }

    @Test("A vault epoch that can't be read, or no config row: nothing is written", arguments: KeyForm.allCases)
    func epochUnreadable(form: KeyForm) throws {
        let (_, noEpoch) = try prepareVault(form, epoch: nil)
        let before = noEpoch.snapshot()
        #expect(try noEpoch.rewrap().outcome == .aborted(.epochUnreadable), "a nil column isn't an epoch")
        #expect(noEpoch.snapshot() == before)

        let (_, noConfig) = try prepareVault(form)
        let context = noConfig.newContext()
        context.delete(try #require(try context.fetch(FetchDescriptor<AppLayerConfig>()).first))
        try context.save()
        #expect(try noConfig.rewrap().outcome == .aborted(.configMissing))
    }

    @Test("A store with no backup export file, or no entries, rewraps what there is", arguments: KeyForm.allCases)
    func nothingToMove(form: KeyForm) throws {
        let (_, store) = try prepareVault(form, entries: 0, backupDepths: [], file: false)

        let report = try store.rewrap()

        #expect(report.outcome == .rewrapped)
        #expect(report.exportMetadata == nil)
        #expect(store.epoch() == 2)
        #expect(!FileManager.default.fileExists(atPath: store.exportMetaURL.path), "and no file appears")
        #expect(Set(store.backupStates().values) == [.neither], "the filler table still changes whole, and stays random")
    }

    // MARK: Volume

    @Test("1,000 entries at every depth, orphaned ones included: the pass completes; time is attached", arguments: KeyForm.allCases)
    func thousandEntries(form: KeyForm) throws {
        let (_, store) = try prepareVault(form, entries: 1_000, backupDepths: [0, 1, 2, 3, 4, 5, 6, 7])

        let started = ContinuousClock.now
        let report = try store.rewrap()
        let elapsed = ContinuousClock.now - started

        let milliseconds = Double(elapsed.components.seconds) * 1_000 + Double(elapsed.components.attoseconds) / 1e15
        Attachment.record(
            "\(form.rawValue): 1,000 entries (depths 0...5, every 7th orphaned), 8 backup keys, 24 filler rows, the export file\n"
            + "rewrap: \(String(format: "%.1f", milliseconds)) ms (\(String(format: "%.3f", milliseconds / 1_000)) ms an entry)\n"
            + "outcome: \(report.outcome); entry keys \(report.entryKeys); backup payloads \(report.backupPayloads)\n"
            + "Software keys on the Simulator; a device adds the Enclave's cost of two derivations, once.",
            named: "vault-rewrap-1000-\(form.rawValue).txt"
        )

        #expect(report.outcome == .rewrapped)
        #expect(report.entryKeys.resealed == 1_000 && report.entryKeys.failed == 0)
        #expect(Set(store.entryKeyStates().values) == [.new])
        #expect(elapsed < .seconds(60), "the pass took \(elapsed)")
    }
}

// MARK: - Unlock

@Suite("Vault rewrap — VaultManager.unlock", .ambientFrozenTestKeyManager, .serialized)
@MainActor
struct VaultRewrapUnlockTests {

    @Test("The first unlock rewraps once; the process then derives the Enclave-bound key; later unlocks do nothing", arguments: KeyForm.allCases)
    func firstUnlockRewrapsOnce(form: KeyForm) throws {
        let (keys, store) = try prepareVault(form)
        let vault = store.vaultManager()
        #expect(Manager.Ambient.vaultKeys == .legacy)

        let faults = KeyReseal.Faults()
        KeyReseal.$faults.withValue(faults) { vault.unlock(context: LAContext()) }

        #expect(store.epoch() == 2)
        #expect(Set(store.entryKeyStates().values) == [.new])
        #expect(Manager.Ambient.vaultKeys == .enclaveBound, "the switch, inside unlock")
        #expect(keyBytes(try #require(try keys.deriveVaultKey(context: LAContext()))) == keyBytes(VaultPins.newKey(form)))
        #expect(faults.reachedVault.filter { $0 == .beforeCommit }.count == 1)

        // The entries open through the vault's own API.
        for item in store.entries {
            let entry = try #require(try vault.fetchEntry(by: item.uuid))
            #expect(try vault.decryptLabel(for: entry) == item.label)
            #expect(try vault.decryptContent(for: entry) == item.content)
        }

        // Lock, unlock again, and again from a fresh manager: exactly once.
        let done = store.snapshot()
        vault.lock()
        KeyReseal.$faults.withValue(faults) { vault.unlock(context: LAContext()) }
        KeyReseal.$faults.withValue(faults) { store.vaultManager().unlock(context: LAContext()) }
        #expect(faults.reachedVault.filter { $0 == .beforeCommit }.count == 1, "the rewrap ran exactly once")
        #expect(store.snapshot() == done)
    }

    @Test("A process that starts with the epoch at 2 derives the Enclave-bound key from its first unlock, and reads everything",
          arguments: KeyForm.allCases)
    func epochTwoAtLaunch(form: KeyForm) throws {
        let (_, store) = try prepareVault(form)
        try store.rewrap()
        Manager.Ambient.setVaultKeys(.legacy)    // a new process starts here
        let vault = store.vaultManager()

        vault.unlock(context: LAContext())

        #expect(Manager.Ambient.vaultKeys == .enclaveBound)
        let item = try #require(store.entries.first)
        let entry = try #require(try vault.fetchEntry(by: item.uuid))
        #expect(try vault.decryptLabel(for: entry) == item.label)
    }

    @Test("A rewrap that fails leaves the vault readable under the legacy key and the process on it; the next unlock retries",
          arguments: KeyReseal.VaultFaultPoint.allCases, KeyForm.allCases)
    func failedRewrapRetries(point: KeyReseal.VaultFaultPoint, form: KeyForm) throws {
        let (_, store) = try prepareVault(form)
        let vault = store.vaultManager()
        let before = store.snapshot()

        KeyReseal.$faults.withValue(KeyReseal.Faults(interruptAtVault: point)) { vault.unlock(context: LAContext()) }

        #expect(Manager.Ambient.vaultKeys == .legacy)
        #expect(store.epoch() == 1)
        #expect(store.snapshot() == before)
        for item in store.entries {
            let entry = try #require(try vault.fetchEntry(by: item.uuid))
            #expect(try vault.decryptLabel(for: entry) == item.label, "still readable")
        }

        vault.lock()
        vault.unlock(context: LAContext())
        #expect(store.epoch() == 2 && Manager.Ambient.vaultKeys == .enclaveBound)
        #expect(Set(store.entryKeyStates().values) == [.new])
        let last = try #require(store.entries.last)
        let entry = try #require(try vault.fetchEntry(by: last.uuid))
        #expect(try vault.decryptLabel(for: entry) == last.label)
    }

    @Test("r_B unreadable at the first unlock: the vault opens under the legacy key, nothing is rewrapped, and the next unlock does it",
          arguments: KeyForm.allCases)
    func unreadableSecretAtUnlock(form: KeyForm) throws {
        let (keys, store) = try prepareVault(form)
        let vault = store.vaultManager()
        let before = store.snapshot()
        keys.simulatesVaultSecretUnreadable = true

        vault.unlock(context: LAContext())

        #expect(vault.isUnlocked, "the vault itself opens: legacy derivations don't need r_B")
        #expect(Manager.Ambient.vaultKeys == .legacy && store.snapshot() == before)
        let first = try #require(store.entries.first)
        let entry = try #require(try vault.fetchEntry(by: first.uuid))
        #expect(try vault.decryptLabel(for: entry) == first.label)

        keys.simulatesVaultSecretUnreadable = false
        vault.lock()
        vault.unlock(context: LAContext())
        #expect(store.epoch() == 2 && Manager.Ambient.vaultKeys == .enclaveBound)
    }

    @Test("The vault key unavailable: unlock locks itself, writes nothing, and doesn't loop; once it's back the next unlock rewraps",
          arguments: KeyForm.allCases)
    func vaultKeyUnavailableAtUnlock(form: KeyForm) throws {
        let (keys, store) = try prepareVault(form)
        let vault = store.vaultManager()
        let before = store.snapshot()
        keys.simulateVaultKeyFailure = true

        vault.unlock(context: LAContext())

        #expect(!vault.isUnlocked, "a derivation that fails locks the vault, as it always did")
        #expect(store.snapshot() == before && Manager.Ambient.vaultKeys == .legacy)

        keys.simulateVaultKeyFailure = false
        vault.unlock(context: LAContext())
        #expect(vault.isUnlocked && store.epoch() == 2)
    }

    @Test("The tier B record missing after the epoch is 2: nothing is recreated, the vault locks, and it doesn't loop", arguments: KeyForm.allCases)
    func recordMissingAfterTheEpoch(form: KeyForm) throws {
        let (keys, store) = try prepareVault(form)
        store.vaultManager().unlock(context: LAContext())
        #expect(store.epoch() == 2)
        keys.tierPQRecordB = nil
        Manager.Ambient.setVaultKeys(.legacy)    // a new process
        let vault = store.vaultManager()

        vault.unlock(context: LAContext())

        #expect(keys.tierPQRecordB == nil, "a new record is a new key")
        #expect(!vault.isUnlocked, "every derivation fails loudly, and the vault locks")
        #expect(Manager.Ambient.vaultKeys == .enclaveBound, "the data is under the new keys; the legacy ones would read nothing")
    }

    @Test("The legacy backup-key array is migrated under the legacy vault key first: nothing it holds is stranded by the rewrap",
          arguments: KeyForm.allCases)
    func legacyArrayMigratesBeforeTheRewrap(form: KeyForm) throws {
        let (_, store) = try prepareVault(form, entries: 3, backupDepths: [])
        let payload = BackupEncryptionKey.Payload(bekBytes: Sealing.random(32), distributionID: UUID(), shardMetadata: nil)

        // The old 32-slot array file: slot 0 real, sealed under the legacy vault key with its own AAD; the rest random.
        let slotSize = VaultManager.Backup.PayloadCodec.payloadSize + 28
        var file = Data()
        for slot in 0..<32 {
            var aad = Data("occulta-bek-slot-v1".utf8)
            aad.append(UInt8(slot))
            let plain = slot == 0 ? try VaultManager.Backup.PayloadCodec.encode(payload) : Sealing.random(VaultManager.Backup.PayloadCodec.payloadSize)
            file.append(Sealing.seal(plain, key: VaultPins.legacyKey, aad: aad))
        }
        #expect(file.count == 32 * slotSize)
        let backend = InMemoryLayerStoreBackend()
        try backend.write(file)

        let vault = store.vaultManager()
        vault.unlock(context: LAContext(), legacyArrayBackend: backend)

        #expect(!backend.exists, "the array was read and deleted")
        #expect(store.epoch() == 2)
        let bek = try vault.currentBackupKey(currentDepth: 0)
        #expect(bek.withUnsafeBytes { Data($0) } == payload.bekBytes, "depth 0's key came through the migration and the rewrap")
    }

    @Test("A fresh vault: no entries, filler only. The first unlock sets the epoch, and everything made afterwards is under the new key",
          arguments: KeyForm.allCases)
    func freshVault(form: KeyForm) throws {
        let (keys, store) = try prepareVault(form, entries: 0, backupDepths: [], file: false)
        keys.tierSecretB = nil
        keys.tierPQRecordB = nil
        let vault = store.vaultManager()

        vault.unlock(context: LAContext())

        #expect(store.epoch() == 2 && Manager.Ambient.vaultKeys == .enclaveBound)
        #expect(keys.tierSecretB != nil && keys.tierPQRecordB != nil)

        let entry = try vault.addEntry(label: "first", content: Data("body".utf8), type: .note)
        let pek = try vault.unwrapPEK(for: entry, vaultKey: try vault.currentKey())
        #expect(pek.withUnsafeBytes { $0.count } == 32, "a new entry's key is wrapped under the key the vault now derives")
        #expect(Sealing.open(entry.encryptedEntryKey, key: VaultPins.legacyKey, aad: entry.aad(for: .entryKey)) == nil, "and not the legacy one")
        #expect(try vault.decryptLabel(for: entry) == "first")

        try vault.setupBackup(currentDepth: 0)
        #expect(throws: Never.self) { _ = try vault.currentBackupKey(currentDepth: 0) }
    }

    @Test("Backups: a file exported before the rewrap imports after it, one exported after imports too, and the backup key comes back from returned shards",
          arguments: KeyForm.allCases)
    func backupsSurvive(form: KeyForm) throws {
        let (keys, store) = try prepareVault(form, entries: 0, backupDepths: [], file: false, epoch: nil)
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: appSupport, withIntermediateDirectories: true)

        // The previous release: a backup key split two ways, an entry, and an export. No epoch yet, so nothing moves on unlock.
        let owner = store.vaultManager()
        owner.unlock(context: LAContext())
        try owner.setupBackup(currentDepth: 0)
        let recipients = (0..<2).map { _ in realFormatContactIdentifier() }
        let pieces = try owner.prepareBackupShards(threshold: 2, recipients: recipients, currentDepth: 0)
        try owner.setBackupShardStatuses(Dictionary(uniqueKeysWithValues: pieces.map { ($0.id, ShardStatus.confirmed) }), currentDepth: 0)
        _ = try owner.addEntry(label: "before", content: Data("before the rewrap".utf8), type: .note)
        let exportedBefore = try owner.exportBackup(currentDepth: 0)
        #expect(Manager.Ambient.vaultKeys == .legacy)

        // The upgrade: the epoch is seeded at 1, and the next unlock moves the vault.
        let context = store.newContext()
        let config = try #require(try context.fetch(FetchDescriptor<AppLayerConfig>()).first)
        config.vaultKeyEpoch = try KeyReseal.Epoch(number: 1, form: .classical).sealed(using: Frozen.newKey(.local, form: .hybrid))
        try context.save()
        owner.lock()
        owner.unlock(context: LAContext())
        #expect(store.epoch() == 2 && Manager.Ambient.vaultKeys == .enclaveBound)

        _ = try owner.addEntry(label: "after", content: Data("after the rewrap".utf8), type: .note)
        let exportedAfter = try owner.exportBackup(currentDepth: 0)
        #expect(try owner.currentBackupKey(currentDepth: 0).withUnsafeBytes { $0.count } == 32, "the owner's key opens under the new vault key")

        // A new phone banks the owner's two pieces and opens each file.
        for (name, file, entries) in [("exported before", exportedBefore, 1), ("exported after", exportedAfter, 2)] {
            let phoneStore = try VaultStore(keys: keys, form: form, entries: 0, backupDepths: [], file: false, epoch: nil)
            let phone = phoneStore.vaultManager()
            phone.unlock(context: LAContext())
            var senders = Set<String>()
            for piece in pieces {
                let sender = realFormatContactIdentifier()
                try phone.absorbShard(piece, senderIdentifier: sender)
                senders.insert(sender)
            }
            let imported = try phone.restoreBackup(from: file, currentDepth: 0, visibleContactIdentifiers: senders)
            #expect(imported, "\(name): the restore itself worked")
            #expect(try ModelContext(phoneStore.container).fetchCount(FetchDescriptor<VaultEntry>()) == entries, "\(name): entries")
        }
    }

    @Test("Erase All Data removes the vault's epoch and its temp file, and the next launch is a fresh vault", arguments: KeyForm.allCases)
    func eraseAllData(form: KeyForm) throws {
        let (keys, store) = try prepareVault(form)
        let vault = store.vaultManager()
        vault.unlock(context: LAContext())
        #expect(store.epoch() == 2)

        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: appSupport, withIntermediateDirectories: true)
        let leftover = KeyReseal.exportMetadataTemporaryURL(in: appSupport)
        try Sealing.random(924).write(to: leftover)

        try vault.deleteAllData()

        #expect(store.config() == nil, "the config row, and with it the vault epoch")
        #expect(!FileManager.default.fileExists(atPath: leftover.path), "a killed rewrap's temp file doesn't survive a wipe")
        #expect(try ModelContext(store.container).fetchCount(FetchDescriptor<VaultEntry>()) == 0)

        // The next launch: no epoch, nothing in the Keychain: the bootstrap seeds epoch 1 again.
        keys.tierSecretB = nil
        keys.tierPQRecordB = nil
        Manager.Ambient.setVaultKeys(.legacy)
        let launch = LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        guard case .success(let bootstrap) = launch.bootstrap else {
            Issue.record("the bootstrap failed: \(launch.bootstrap)")
            return
        }
        #expect(bootstrap.createdConfig && bootstrap.seededVaultKeyEpoch && bootstrap.createdVaultRecord)
        #expect(store.epoch() == 1)
    }
}

// MARK: - The bootstrap and the tier B record

@Suite("Vault rewrap — the bootstrap creates the tier B record", .ambientFrozenTestKeyManager)
@MainActor
struct VaultRecordBootstrapTests {

    @Test("A fresh install gets the tier B record at launch, with the vault epoch seeded at 1 (not at the first unlock)", arguments: KeyForm.allCases)
    func freshInstall(form: KeyForm) throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(form)
        keys.tierSecretU   = nil
        keys.tierPQRecordU = nil
        keys.tierPQRecordB = nil
        let store = try LegacyStore(keys: keys)

        let report = try KeyReseal.bootstrap(context: store.newContext(), keyManager: keys)

        #expect(report.createdVaultRecord)
        #expect(keys.tierPQRecordB?.mode == (form == .hybrid ? .hybrid : .classical), "in this device's form")
        #expect(report.seededVaultKeyEpoch)
        #expect(keys.tierSecretB == Frozen.tierSecretB, "r_B is not made here: it needs the vault's evaluated context")
    }

    @Test("An install whose tier U pass has run, with the vault epoch still 1, gets the record too", arguments: KeyForm.allCases)
    func installWithATierUEpoch(form: KeyForm) throws {
        let (keys, store) = try prepare(form)
        keys.tierPQRecordB = nil
        LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        #expect(keys.tierPQRecordB != nil, "the launch made it")

        keys.tierPQRecordB = nil
        let report = try KeyReseal.bootstrap(context: store.newContext(), keyManager: keys)
        #expect(report.createdVaultRecord, "while the vault epoch is 1, a missing record is made, whatever tier U's epoch says")
    }

    @Test("Once the vault epoch is 2 a missing record is not recreated, and the bootstrap says so", arguments: KeyForm.allCases)
    func notAfterTheEpoch(form: KeyForm) throws {
        let (keys, store) = try prepare(form)
        LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)

        // The vault has been opened since the upgrade.
        let context = store.newContext()
        let config = try #require(try context.fetch(FetchDescriptor<AppLayerConfig>()).first)
        config.vaultKeyEpoch = try KeyReseal.Epoch(number: 2, form: .classical).sealed(using: Frozen.newKey(.local, form: form))
        try context.save()
        keys.tierPQRecordB = nil

        let report = try KeyReseal.bootstrap(context: store.newContext(), keyManager: keys)

        #expect(!report.createdVaultRecord && keys.tierPQRecordB == nil)
        #expect(report.refusals.contains(.vaultRecordMissingAfterEpoch))
    }

    @Test("A locked device creates nothing on a guess", arguments: KeyForm.allCases)
    func lockedDevice(form: KeyForm) throws {
        let (keys, store) = try prepare(form)
        keys.tierPQRecordB = nil
        keys.simulatesLockedDevice = true

        let report = try KeyReseal.bootstrap(context: store.newContext(), keyManager: keys)

        #expect(!report.createdVaultRecord && keys.tierPQRecordB == nil)
        #expect(report.refusals.contains(.unreadable))
    }
}

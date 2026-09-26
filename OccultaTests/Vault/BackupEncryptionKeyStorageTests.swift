//
//  BackupEncryptionKeyStorageTests.swift
//  OccultaTests
//
//  BEK-to-database migration, 2026-09-11: the BEK moved off the 32-slot fixed-width
//  array file (`VaultManager.Backup.LayerStore`, deleted) onto ordinary
//  `BackupEncryptionKey` SwiftData rows — one per claimed depth, 32 prefilled as filler
//  at launch, uncapped beyond that. See `VAULT_KEY_LAYERING.md` for the full design.
//
//  Three areas of coverage:
//
//  1. **`BackupKeyFillerBaselineTests`** — the 32-row eager-creation baseline this
//     design relies on for "row count reveals nothing" up to the first 32
//     configure-events, and what happens once that baseline is exhausted.
//  2. **`BackupKeyOrphaningTests`** — the actual regression test for the bug that
//     motivated this refactor: `deactivateSecureMode`/`forceDeactivateForRecovery`
//     never touched the freed depth's BEK slot at all, so a later, unrelated duress
//     session reactivating at the same depth number inherited the old session's
//     backup key and trustee list untouched. Mirrors `VaultEntryOrphaningTests`
//     (`SecureModeActivationTests.swift`, Bug 110) exactly, one level over.
//  3. **`BackupKeyLegacyStorageMigrationTests`** — the three possible starting states
//     (old array only, original single legacy row only, both, neither) migration has
//     to reconcile into the new row model, and that running it twice is a no-op the
//     second time.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
import LocalAuthentication
@testable import Occulta

// MARK: - Shared helpers

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

@MainActor
private func makeContainer() throws -> ModelContainer {
    let schema = Schema([
        AppLayerConfig.self,
        BackupEncryptionKey.self,
        VaultEntry.self,
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
private func fetchAllBackupKeyRows(from container: ModelContainer) throws -> [BackupEncryptionKey] {
    try ModelContext(container).fetch(FetchDescriptor<BackupEncryptionKey>())
}

// MARK: - 1. Filler baseline

@Suite("Backup key filler baseline")
@MainActor
struct BackupKeyFillerBaselineTests {

    @Test("VaultManager construction tops up the BackupEncryptionKey table to exactly 32 rows")
    func topsUpToThirtyTwo() throws {
        // No secureEnclaveAvailable() gate — filler creation needs no key material at
        // all, by design (plain random bytes, never sealed). This must be true on
        // every host, Enclave or not.
        let container = try makeContainer()
        let vault = VaultManager(modelContainer: container, keyManager: TestKeyManager())
        _ = vault

        let rows = try fetchAllBackupKeyRows(from: container)
        #expect(rows.count == 32)
    }

    @Test("Filler top-up is idempotent — a second VaultManager against the same container adds nothing")
    func topUpIsIdempotent() throws {
        let container = try makeContainer()
        _ = VaultManager(modelContainer: container, keyManager: TestKeyManager())
        #expect(try fetchAllBackupKeyRows(from: container).count == 32)

        _ = VaultManager(modelContainer: container, keyManager: TestKeyManager())
        #expect(try fetchAllBackupKeyRows(from: container).count == 32,
                "a second construction against an already-filled container must not add more rows")
    }

    @Test("Filler rows report unclaimed and orphaned — never live", .enabled(if: secureEnclaveAvailable()))
    func fillerRowsReportCorrectly() throws {
        let container = try makeContainer()
        _ = VaultManager(modelContainer: container, keyManager: TestKeyManager())
        let key = try #require(try Manager.Key().createHybridLocalEncryptionKey())

        for row in try fetchAllBackupKeyRows(from: container) {
            #expect(row.isUnclaimed(usingKey: key), "a freshly-created filler row must report unclaimed")
            #expect(row.isOrphaned(usingKey: key), "a filler row's deletionToken never decrypts, so it must fail safe as orphaned too")
        }
    }

    @Test("Claiming all 32 filler rows, then setting up backup for a 33rd depth, inserts a genuinely new row",
          .enabled(if: secureEnclaveAvailable()))
    func overflowPastThirtyTwoInsertsFreshRow() throws {
        let container = try makeContainer()
        let vault = VaultManager(modelContainer: container, keyManager: TestKeyManager())
        vault.unlock(context: LAContext())

        for depth in 0..<32 {
            try vault.setupBackup(currentDepth: depth)
        }
        #expect(try fetchAllBackupKeyRows(from: container).count == 32,
                "claiming exactly the 32 prefilled rows must not grow the table")

        try vault.setupBackup(currentDepth: 32)
        #expect(try fetchAllBackupKeyRows(from: container).count == 33,
                "the 33rd depth has no filler row left to claim and must insert a fresh one")

        // Every depth, including the 33rd, must still resolve to its own distinct key.
        var keys = Set<Data>()
        for depth in 0...32 {
            let key = try vault.currentBackupKey(currentDepth: depth)
            let bytes = key.withUnsafeBytes { Data($0) }
            #expect(!keys.contains(bytes), "depth \(depth)'s key must not collide with an earlier depth's")
            keys.insert(bytes)
        }
    }

    @Test("A second setup call at an already-configured depth does not claim another filler row",
          .enabled(if: secureEnclaveAvailable()))
    func repeatedSetupClaimsOnlyOneRow() throws {
        let container = try makeContainer()
        let vault = VaultManager(modelContainer: container, keyManager: TestKeyManager())
        vault.unlock(context: LAContext())

        try vault.setupBackup(currentDepth: 5)
        let firstKey = try vault.currentBackupKey(currentDepth: 5)

        try vault.setupBackup(currentDepth: 5)
        let secondKey = try vault.currentBackupKey(currentDepth: 5)

        #expect(try fetchAllBackupKeyRows(from: container).count == 32,
                "the second setup call must not claim another filler row for the same depth")
        #expect(firstKey.withUnsafeBytes { Data($0) } == secondKey.withUnsafeBytes { Data($0) },
                "the second call must be a no-op, not a fresh key overwriting the first")
    }
}

// MARK: - 2. Orphaning on deactivation — the actual regression test

/// Mirrors `VaultEntryOrphaningTests` (`SecureModeActivationTests.swift`, Bug 110)
/// exactly, one container level down: this is the BEK-side twin of the bug that
/// motivated moving BEK storage onto SwiftData rows at all.
@Suite("Backup key orphaning on deactivation", .serialized)
struct BackupKeyOrphaningTests {

    private struct Components {
        let security: Manager.Security
        let container: ModelContainer
        let vault: VaultManager
    }

    @MainActor
    private func makeComponents() throws -> Components {
        let container = try makeContainer()
        let security  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        let vault     = VaultManager(modelContainer: container, keyManager: TestKeyManager())
        vault.unlock(context: LAContext())
        return Components(security: security, container: container, vault: vault)
    }

    @Test("A backup key from one duress session does not resurface in a later, unrelated session at the same depth",
          .enabled(if: secureEnclaveAvailable()))
    @MainActor
    func staleSessionBackupKeyDoesNotResurface() throws {
        let c = try self.makeComponents()
        try c.security.configurePIN("111111")

        // Session A: reach depth 1, set up backup — real trustees, real key.
        try c.security.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        c.security.applyVerifyState(for: try c.security.verify("999999"))
        #expect(c.security.currentDepth == 1)
        try c.vault.setupBackup(currentDepth: 1)
        let sessionAKey = try c.vault.currentBackupKey(currentDepth: 1)

        // End session A entirely.
        try c.security.deactivateSecureMode(confirmingEntryPIN: "999999")
        #expect(!c.security.isSecureModeActive)

        // The row itself must still physically exist, marked inert — never hard-deleted.
        let key = try #require(try Manager.Key().createHybridLocalEncryptionKey())
        let depth1Rows = try fetchAllBackupKeyRows(from: c.container).filter { row in
            guard let data = row.depth, let plain = data.decrypt(using: key),
                  let value = DepthCodec.decode(plain)
            else { return false }
            return value == 1
        }
        #expect(depth1Rows.count == 1, "the depth-1 row must still exist, not be deleted")
        #expect(depth1Rows.first?.isOrphaned(usingKey: key) == true)

        // Session B: a completely unrelated duress PIN, also reaching depth 1.
        try c.security.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "444444")
        c.security.applyVerifyState(for: try c.security.verify("444444"))
        #expect(c.security.currentDepth == 1)

        // The stale key must not resurface — depth 1 must look genuinely unconfigured
        // to session B, not like it inherited session A's key and trustees. Orphaned
        // rows are excluded from `liveRows`, so this must throw, not return the old key.
        #expect(throws: VaultManager.BackupError.bekNotSetup) {
            try c.vault.currentBackupKey(currentDepth: 1)
        }

        // Setting up backup fresh in session B must produce a *different* key than
        // session A's — proof this isn't just reading the same row back.
        try c.vault.setupBackup(currentDepth: 1)
        let sessionBKey = try c.vault.currentBackupKey(currentDepth: 1)
        let aBytes = sessionAKey.withUnsafeBytes { Data($0) }
        let bBytes = sessionBKey.withUnsafeBytes { Data($0) }
        #expect(aBytes != bBytes, "session B's fresh backup key must not equal session A's orphaned one")
    }

    @Test("A backup key at a shallower, still-live depth survives an unrelated deeper cascade deactivation",
          .enabled(if: secureEnclaveAvailable()))
    @MainActor
    func shallowerBackupKeySurvivesCascade() throws {
        let c = try self.makeComponents()
        try c.security.configurePIN("111111")

        try c.security.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        c.security.applyVerifyState(for: try c.security.verify("999999"))
        #expect(c.security.currentDepth == 1)
        try c.vault.setupBackup(currentDepth: 1)
        let depth1Key = try c.vault.currentBackupKey(currentDepth: 1)

        try c.security.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "777777")
        c.security.applyVerifyState(for: try c.security.verify("777777"))
        #expect(c.security.currentDepth == 2)

        // Deactivate the depth-2 layer only — depth 1's own backup key must be untouched.
        try c.security.deactivateSecureMode(confirmingEntryPIN: "777777")
        #expect(c.security.currentDepth == 1)

        let stillDepth1Key = try c.vault.currentBackupKey(currentDepth: 1)
        let originalBytes = depth1Key.withUnsafeBytes { Data($0) }
        let currentBytes  = stillDepth1Key.withUnsafeBytes { Data($0) }
        #expect(originalBytes == currentBytes, "must be the exact same key, not a fresh one")

        let key = try #require(try Manager.Key().createHybridLocalEncryptionKey())
        let depth1Rows = try fetchAllBackupKeyRows(from: c.container).filter { row in
            guard let data = row.depth, let plain = data.decrypt(using: key),
                  let value = DepthCodec.decode(plain)
            else { return false }
            return value == 1
        }
        #expect(depth1Rows.first?.isOrphaned(usingKey: key) == false,
                "must not be orphaned — its own depth was never freed")
    }

    @Test("updateShardStatus never mutates an orphaned row, even when it targets that row's own shard",
          .enabled(if: secureEnclaveAvailable()))
    @MainActor
    func updateShardStatusIgnoresOrphanedRow() throws {
        let c = try self.makeComponents()
        try c.security.configurePIN("111111")

        try c.security.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        c.security.applyVerifyState(for: try c.security.verify("999999"))
        #expect(c.security.currentDepth == 1)

        try c.vault.setupBackup(currentDepth: 1)
        let recipients = (0..<2).map { _ in UUID().uuidString }
        let shards = try c.vault.prepareBackupShards(threshold: 2, recipients: recipients, currentDepth: 1)
        let attributeID = shards[0].id

        // End the session — orphans the depth-1 BEK row. Its encryptedPayload (and the
        // still-pending shard inside it) is left in place, only the deletionToken flips.
        try c.security.deactivateSecureMode(confirmingEntryPIN: "999999")
        #expect(!c.security.isSecureModeActive)

        let key = try #require(try Manager.Key().createHybridLocalEncryptionKey())
        func depth1Row() throws -> BackupEncryptionKey {
            try #require(try fetchAllBackupKeyRows(from: c.container).first { row in
                guard let data = row.depth, let plain = data.decrypt(using: key),
                      let value = DepthCodec.decode(plain)
                else { return false }
                return value == 1
            })
        }
        let before = try depth1Row()
        #expect(before.isOrphaned(usingKey: key) == true)
        let payloadBefore = before.encryptedPayload

        // Targeting the orphaned row's own shard must be a silent no-op — the row is
        // excluded from `liveRows`, so `updateShardStatus` must never reach it at all.
        try c.vault.updateShardStatus(attributeID: attributeID, to: .confirmed)

        let after = try depth1Row()
        #expect(after.encryptedPayload == payloadBefore,
                "updateShardStatus must never touch an orphaned row's payload, even when its own attributeID is targeted")
    }
}

// MARK: - 3. Legacy storage migration

@Suite("Backup key legacy storage migration", .serialized)
@MainActor
struct BackupKeyLegacyStorageMigrationTests {

    /// Duplicated from `Vault+Manager+Backup.swift`, where it's `private static` —
    /// same rationale `VaultRestoreTrustTests.swift` already documents for
    /// `backupFileAAD`: if it changes there, these tests go quietly wrong (every
    /// slot fails to open) rather than failing loudly.
    private static func legacyArraySlotAAD(slotIndex: Int) -> Data {
        var out = Data("occulta-bek-slot-v1".utf8)
        out.append(UInt8(slotIndex))
        return out
    }

    /// Builds a 32-slot legacy array file, real payload at `realSlots`, random
    /// (never-decoding) filler everywhere else — matching the old array's own shape,
    /// where filler slots were genuinely sealed, just over random plaintext.
    private func makeLegacyArrayFile(vaultKey: SymmetricKey, realSlots: [Int: BackupEncryptionKey.Payload]) throws -> Data {
        let slotCiphertextSize = VaultManager.Backup.PayloadCodec.payloadSize + 28
        var file = Data()
        for slotIndex in 0..<32 {
            let plaintext: Data
            if let payload = realSlots[slotIndex] {
                plaintext = try VaultManager.Backup.PayloadCodec.encode(payload)
            } else {
                plaintext = Data.randomBytes(VaultManager.Backup.PayloadCodec.payloadSize)
            }
            let sealed = try AES.GCM.seal(
                plaintext, using: vaultKey, nonce: AES.GCM.Nonce(),
                authenticating: Self.legacyArraySlotAAD(slotIndex: slotIndex)
            )
            guard let combined = sealed.combined else { throw VaultManager.BackupError.encryptionFailed }
            #expect(combined.count == slotCiphertextSize)
            file.append(combined)
        }
        return file
    }

    @Test("Array-only: every real slot is claimed at its own depth, the file is deleted, filler slots are untouched",
          .enabled(if: secureEnclaveAvailable()))
    func migratesArrayOnly() throws {
        let container = try makeContainer()
        let vault     = VaultManager(modelContainer: container, keyManager: TestKeyManager())
        vault.unlock(context: LAContext())
        let vaultKey  = try vault.currentKey()

        let depth0Payload = BackupEncryptionKey.Payload(bekBytes: Data.randomBytes(32), distributionID: UUID(), shardMetadata: nil)
        let depth2Payload = BackupEncryptionKey.Payload(bekBytes: Data.randomBytes(32), distributionID: UUID(), shardMetadata: nil)
        let fileData = try self.makeLegacyArrayFile(vaultKey: vaultKey, realSlots: [0: depth0Payload, 2: depth2Payload])

        let backend = InMemoryLayerStoreBackend()
        try backend.write(fileData)

        try vault.migrateLegacyBackupStorageIfNeeded(vaultKey: vaultKey, legacyArrayBackend: backend)

        let migratedDepth0 = try vault.currentBackupKey(currentDepth: 0)
        #expect(migratedDepth0.withUnsafeBytes { Data($0) } == depth0Payload.bekBytes)
        let migratedDepth2 = try vault.currentBackupKey(currentDepth: 2)
        #expect(migratedDepth2.withUnsafeBytes { Data($0) } == depth2Payload.bekBytes)

        // An untouched slot must not become live.
        #expect(throws: VaultManager.BackupError.bekNotSetup) {
            try vault.currentBackupKey(currentDepth: 1)
        }

        #expect(!backend.exists, "the array file must be deleted once fully migrated")
    }

    @Test("Legacy-row-only: the nil/nil row migrates to depth 0 and is folded into filler, never deleted",
          .enabled(if: secureEnclaveAvailable()))
    func migratesLegacyRowOnly() throws {
        let container = try makeContainer()
        let vault     = VaultManager(modelContainer: container, keyManager: TestKeyManager())
        vault.unlock(context: LAContext())
        let vaultKey  = try vault.currentKey()

        // Insert a legacy row directly — depth/deletionToken nil, exactly as a
        // pre-refactor row would be, sealed with the old JSON format under the
        // model's own id-based AAD (unchanged by this migration).
        let legacyPayload = BackupEncryptionKey.Payload(bekBytes: Data.randomBytes(32), distributionID: UUID(), shardMetadata: nil)
        let plaintext = try JSONEncoder().encode(legacyPayload)
        let legacyRow = BackupEncryptionKey(encryptedPayload: Data())
        let sealed = try AES.GCM.seal(plaintext, using: vaultKey, nonce: AES.GCM.Nonce(), authenticating: legacyRow.aad())
        legacyRow.encryptedPayload = try #require(sealed.combined)
        let ctx = ModelContext(container)
        ctx.insert(legacyRow)
        try ctx.save()

        let rowCountBefore = try fetchAllBackupKeyRows(from: container).count

        try vault.migrateLegacyBackupStorageIfNeeded(vaultKey: vaultKey, legacyArrayBackend: InMemoryLayerStoreBackend())

        let migrated = try vault.currentBackupKey(currentDepth: 0)
        #expect(migrated.withUnsafeBytes { Data($0) } == legacyPayload.bekBytes)

        // Row count unchanged — the legacy row was folded into filler (or claimed
        // directly), never deleted, never duplicated.
        #expect(try fetchAllBackupKeyRows(from: container).count == rowCountBefore)

        // No row anywhere is still in the nil/nil legacy state.
        let stillLegacyShaped = try fetchAllBackupKeyRows(from: container).contains { $0.depth == nil && $0.deletionToken == nil }
        #expect(!stillLegacyShaped, "the legacy row must be folded into filler, not left in its distinguishable nil/nil state")
    }

    /// Inserts a row as v1.10.3 left it: depth and deletionToken nil, `plaintext` sealed under
    /// the vault key with the row's own id-based AAD. Returns the row's id.
    private func insertLegacyRow(_ plaintext: Data, vaultKey: SymmetricKey, in container: ModelContainer) throws -> UUID {
        let legacyRow = BackupEncryptionKey(encryptedPayload: Data())
        let sealed = try AES.GCM.seal(plaintext, using: vaultKey, nonce: AES.GCM.Nonce(), authenticating: legacyRow.aad())
        legacyRow.encryptedPayload = try #require(sealed.combined)
        let ctx = ModelContext(container)
        ctx.insert(legacyRow)
        try ctx.save()
        return legacyRow.id
    }

    private func row(_ id: UUID, in container: ModelContainer) throws -> BackupEncryptionKey {
        try #require(try fetchAllBackupKeyRows(from: container).first { $0.id == id })
    }

    /// Bug 138: the migration used to fold the legacy row into filler and save before the
    /// key reached its new row, so a row that decrypted but wouldn't decode lost the key.
    @Test("A legacy row that won't decode is left untouched for the next unlock",
          .enabled(if: secureEnclaveAvailable()))
    func undecodableLegacyRowIsUntouched() throws {
        let container = try makeContainer()
        let vault     = VaultManager(modelContainer: container, keyManager: TestKeyManager())
        vault.unlock(context: LAContext())
        let vaultKey  = try vault.currentKey()
        let id        = try self.insertLegacyRow(Data("not a payload".utf8), vaultKey: vaultKey, in: container)
        let before    = try self.row(id, in: container).encryptedPayload

        try vault.migrateLegacyBackupStorageIfNeeded(vaultKey: vaultKey, legacyArrayBackend: InMemoryLayerStoreBackend())

        let after = try self.row(id, in: container)
        #expect(after.encryptedPayload == before)
        #expect(after.depth == nil && after.deletionToken == nil)
        #expect((try? vault.currentBackupKey(currentDepth: 0)) == nil)
    }

    /// Bug 138: a failure after the key is staged must roll back, leaving the legacy row as
    /// the key's only copy rather than a folded row and no depth-0 key. 256 shard records
    /// decode from JSON but make `PayloadCodec.encode` throw `tooManyShards` inside `stage`,
    /// after a depth-0 row has been claimed.
    @Test("A failure after staging leaves the legacy row intact and no depth-0 key",
          .enabled(if: secureEnclaveAvailable()))
    func failureAfterStagingRollsBack() throws {
        let container = try makeContainer()
        let vault     = VaultManager(modelContainer: container, keyManager: TestKeyManager())
        vault.unlock(context: LAContext())
        let vaultKey  = try vault.currentKey()
        let records   = (0..<256).map { _ in
            ShardRecord(contactIdentifier: UUID().uuidString, attributeID: UUID(), status: .confirmed)
        }
        let payload   = BackupEncryptionKey.Payload(
            bekBytes: Data.randomBytes(32), distributionID: UUID(),
            shardMetadata: ShardDistributionMetadata(threshold: 2, shards: records)
        )
        let id        = try self.insertLegacyRow(try JSONEncoder().encode(payload), vaultKey: vaultKey, in: container)
        let before    = try self.row(id, in: container).encryptedPayload

        #expect(throws: (any Error).self) {
            try vault.migrateLegacyBackupStorageIfNeeded(vaultKey: vaultKey, legacyArrayBackend: InMemoryLayerStoreBackend())
        }

        let after = try self.row(id, in: container)
        #expect(after.encryptedPayload == before)
        #expect(after.depth == nil && after.deletionToken == nil)
        #expect((try? vault.currentBackupKey(currentDepth: 0)) == nil)
    }

    @Test("Both present: array data wins over the legacy row at depth 0, matching the original precedence",
          .enabled(if: secureEnclaveAvailable()))
    func arrayWinsOverLegacyRowAtDepthZero() throws {
        let container = try makeContainer()
        let vault     = VaultManager(modelContainer: container, keyManager: TestKeyManager())
        vault.unlock(context: LAContext())
        let vaultKey  = try vault.currentKey()

        let arrayPayload  = BackupEncryptionKey.Payload(bekBytes: Data.randomBytes(32), distributionID: UUID(), shardMetadata: nil)
        let legacyPayload = BackupEncryptionKey.Payload(bekBytes: Data.randomBytes(32), distributionID: UUID(), shardMetadata: nil)
        #expect(arrayPayload.bekBytes != legacyPayload.bekBytes)

        let fileData = try self.makeLegacyArrayFile(vaultKey: vaultKey, realSlots: [0: arrayPayload])
        let backend = InMemoryLayerStoreBackend()
        try backend.write(fileData)

        let legacyPlaintext = try JSONEncoder().encode(legacyPayload)
        let legacyRow = BackupEncryptionKey(encryptedPayload: Data())
        let sealed = try AES.GCM.seal(legacyPlaintext, using: vaultKey, nonce: AES.GCM.Nonce(), authenticating: legacyRow.aad())
        legacyRow.encryptedPayload = try #require(sealed.combined)
        let ctx = ModelContext(container)
        ctx.insert(legacyRow)
        try ctx.save()

        try vault.migrateLegacyBackupStorageIfNeeded(vaultKey: vaultKey, legacyArrayBackend: backend)

        let migrated = try vault.currentBackupKey(currentDepth: 0)
        #expect(migrated.withUnsafeBytes { Data($0) } == arrayPayload.bekBytes,
                "the array's slot-0 payload must win — the legacy row is only consulted if depth 0 is still unclaimed after the array pass")
    }

    @Test("Neither present: migration is a safe no-op", .enabled(if: secureEnclaveAvailable()))
    func noSourcesIsANoOp() throws {
        let container = try makeContainer()
        let vault     = VaultManager(modelContainer: container, keyManager: TestKeyManager())
        vault.unlock(context: LAContext())
        let vaultKey  = try vault.currentKey()

        let rowCountBefore = try fetchAllBackupKeyRows(from: container).count
        try vault.migrateLegacyBackupStorageIfNeeded(vaultKey: vaultKey, legacyArrayBackend: InMemoryLayerStoreBackend())
        #expect(try fetchAllBackupKeyRows(from: container).count == rowCountBefore)
        #expect(vault.backupSetupState(currentDepth: 0) == .notSetup)
    }

    @Test("Running migration twice is idempotent — the second pass claims nothing new",
          .enabled(if: secureEnclaveAvailable()))
    func secondPassIsNoOp() throws {
        let container = try makeContainer()
        let vault     = VaultManager(modelContainer: container, keyManager: TestKeyManager())
        vault.unlock(context: LAContext())
        let vaultKey  = try vault.currentKey()

        let payload = BackupEncryptionKey.Payload(bekBytes: Data.randomBytes(32), distributionID: UUID(), shardMetadata: nil)
        let fileData = try self.makeLegacyArrayFile(vaultKey: vaultKey, realSlots: [3: payload])
        let backend = InMemoryLayerStoreBackend()
        try backend.write(fileData)

        try vault.migrateLegacyBackupStorageIfNeeded(vaultKey: vaultKey, legacyArrayBackend: backend)
        let rowCountAfterFirst = try fetchAllBackupKeyRows(from: container).count
        #expect(!backend.exists)

        // Second pass: array is already gone, no legacy row exists — must be a
        // complete no-op, not throw, not duplicate anything.
        try vault.migrateLegacyBackupStorageIfNeeded(vaultKey: vaultKey, legacyArrayBackend: InMemoryLayerStoreBackend())
        #expect(try fetchAllBackupKeyRows(from: container).count == rowCountAfterFirst)
        let migrated = try vault.currentBackupKey(currentDepth: 3)
        #expect(migrated.withUnsafeBytes { Data($0) } == payload.bekBytes, "depth 3's key must be unchanged by the second pass")
    }
}

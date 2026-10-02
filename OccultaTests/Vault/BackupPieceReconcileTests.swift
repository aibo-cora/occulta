//
//  BackupPieceReconcileTests.swift
//  OccultaTests
//
//  Bugs 141 and 142. Implicit revoke is gone, so a depth keeps its backup-key pieces
//  delivered itself: `ShardCustodyManager.distributeBackup` re-splits and queues (a new key
//  when a trustee is dropped, the previous split's queued and watch rows removed first), and
//  `reconcileBackupPieces` confirms pieces, marks a deleted trustee's piece lost, and
//  re-sends one a trustee no longer has. Everything reads and writes only the current
//  depth's backup-key row.
//
//  Backup-key rows are found through the ambient local key (`Manager.Ambient`), so every test
//  runs under `.ambientTestKeyManager`, which supplies it.
//

import Testing
import Foundation
import CryptoKit
import LocalAuthentication
import SwiftData
@testable import Occulta

@MainActor
private struct Owner {
    let vault:     VaultManager
    let custody:   ShardCustodyManager
    let km:        TestKeyManager
    let container: ModelContainer

    init() throws {
        let schema = Schema([
            VaultEntry.self, BackupEncryptionKey.self, Vault.self, PendingShamirSecretRestore.self,
            CustodyShard.self, PendingShardDistribute.self, PendingShardStatusUpdate.self, PotentiallyLostShard.self,
        ])
        self.container = try ModelContainer(for: schema, configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)])
        self.km        = TestKeyManager()
        self.vault     = VaultManager(modelContainer: self.container, keyManager: self.km)
        self.custody   = ShardCustodyManager(modelContainer: self.container, keyManager: self.km)
        self.vault.unlock(context: LAContext())
        try self.vault.setupBackup(currentDepth: 0)
    }

    func bek(depth: Int = 0) throws -> Data {
        var bytes = Data()
        try self.vault.currentBackupKey(currentDepth: depth).withUnsafeBytes { bytes = Data($0) }
        return bytes
    }

    func records(depth: Int = 0) throws -> [ShardRecord] {
        try self.vault.backupShardMetadata(currentDepth: depth)?.shards ?? []
    }

    func pieceID(of trustee: String, depth: Int = 0) throws -> UUID {
        try #require(try self.records(depth: depth).first { $0.isHeld(by: trustee) }?.attributeID)
    }

    /// The queued operations the next message to `trustee` would carry.
    func queued(for trustee: String) throws -> [OccultaBundle.ShardOperation] {
        try self.custody.buildShardOperations(for: trustee, currentContactPublicKey: nil)
    }

    /// Watch rows (`PotentiallyLostShard`): piece ID → isAbsent.
    func watch() throws -> [UUID: Bool] {
        let key = try #require(try self.km.deriveShardCustodyKey())
        var out: [UUID: Bool] = [:]
        for row in try ModelContext(self.container).fetch(FetchDescriptor<PotentiallyLostShard>()) {
            let box   = try AES.GCM.SealedBox(combined: row.encryptedPayload)
            let plain = try AES.GCM.open(box, using: key, authenticating: row.aad())
            let payload = try JSONDecoder().decode(PotentiallyLostShard.Payload.self, from: plain)
            out[payload.attributeID] = payload.isAbsent
        }
        return out
    }

    /// A trustee's manifest arriving: `held` is what it reports holding from us.
    func manifest(from trustee: String, held: [UUID]) throws {
        try self.custody.processInboundManifest(held, from: trustee)
    }

    func reconcile(keyChangedFor changed: String? = nil, live: Set<String>, depth: Int = 0) {
        self.custody.reconcileBackupPieces(currentDepth: depth, keyChangedFor: changed, liveContacts: live, vaultManager: self.vault)
    }

    /// Distributes to `trustees` and has each confirm through a manifest and a reconcile.
    func distributeAndConfirm(_ trustees: [String], threshold: Int = 2) throws {
        try self.custody.distributeBackup(threshold: threshold, recipients: trustees, currentDepth: 0, vaultManager: self.vault)
        for trustee in trustees {
            try self.manifest(from: trustee, held: [try self.pieceID(of: trustee)])
        }
        self.reconcile(live: Set(trustees))
    }

    /// The sealed bytes of `depth`'s backup-key row.
    func rowBytes(depth: Int) throws -> Data {
        let key = try #require(try Manager.Ambient.keyManager.createHybridLocalEncryptionKey())
        let row = try #require(try ModelContext(self.container).fetch(FetchDescriptor<BackupEncryptionKey>()).first { row in
            guard !row.isOrphaned(usingKey: key), !row.isUnclaimed(usingKey: key),
                  let data = row.depth, let plain = data.decrypt(using: key) else { return false }
            return DepthCodec.decode(plain) == depth
        })
        return row.encryptedPayload
    }
}

private func trustees(_ n: Int) -> [String] { (0..<n).map { _ in realFormatContactIdentifier() } }

// MARK: - Distribution: new key on removal, and the queue (Bugs 141, 142)

@Suite("Backup-key distribution — rotation on removal and queue clean-up")
@MainActor
struct BackupDistributionTests {

    @Test("Dropping a trustee splits a new key; adding one keeps it", .ambientTestKeyManager)
    func removalRotatesAdditionKeeps() throws {
        let owner = try Owner()
        let t = trustees(4)

        try owner.custody.distributeBackup(threshold: 2, recipients: [t[0], t[1]], currentDepth: 0, vaultManager: owner.vault)
        let original = try owner.bek()

        try owner.custody.distributeBackup(threshold: 2, recipients: [t[0], t[1], t[2]], currentDepth: 0, vaultManager: owner.vault)
        #expect(try owner.bek() == original, "adding a trustee keeps the key")

        try owner.custody.distributeBackup(threshold: 2, recipients: [t[0], t[1], t[3]], currentDepth: 0, vaultManager: owner.vault)
        #expect(try owner.bek() != original, "dropping a trustee splits a new key")
    }

    /// Bug 142's reproduction: A, B, C, then A, B, D before anything was delivered.
    @Test("A new split replaces the previous split's queued pieces", .ambientTestKeyManager)
    func newSplitReplacesQueue() throws {
        let owner = try Owner()
        let t = trustees(4)
        let (a, b, c, d) = (t[0], t[1], t[2], t[3])

        try owner.custody.distributeBackup(threshold: 2, recipients: [a, b, c], currentDepth: 0, vaultManager: owner.vault)
        let roundOne = try [a, b, c].map { try owner.pieceID(of: $0) }

        try owner.custody.distributeBackup(threshold: 2, recipients: [a, b, d], currentDepth: 0, vaultManager: owner.vault)

        #expect(try owner.queued(for: c).isEmpty, "a trustee removed before delivery receives nothing")
        for kept in [a, b] {
            let ops = try owner.queued(for: kept)
            #expect(ops.count == 1, "only the new piece, not the stale one alongside it")
            #expect(ops.first?.kind == .replace)
            #expect(ops.first?.attribute?.id == (try owner.pieceID(of: kept)))
            #expect(!roundOne.contains(try #require(ops.first?.attribute?.id)))
        }
        let forD = try owner.queued(for: d)
        #expect(forD.count == 1 && forD.first?.kind == .distribute)
    }

    @Test("A new split deletes the previous split's watch rows", .ambientTestKeyManager)
    func newSplitDeletesWatchRows() throws {
        let owner = try Owner()
        let t = trustees(3)
        try owner.distributeAndConfirm([t[0], t[1]])
        let oldIDs = try [t[0], t[1]].map { try owner.pieceID(of: $0) }
        #expect(Set(try owner.watch().keys) == Set(oldIDs))

        try owner.custody.distributeBackup(threshold: 2, recipients: [t[0], t[2]], currentDepth: 0, vaultManager: owner.vault)

        #expect(try owner.watch().isEmpty)
    }
}

// MARK: - What counts as dropping a trustee (Bug 144)

@Suite("Backup-key distribution — any left-out trustee means a new key")
@MainActor
struct BackupDropRuleTests {

    @Test("Leaving out a trustee whose piece is still pending splits a new key", .ambientTestKeyManager)
    func droppingPendingRotates() throws {
        let owner = try Owner()
        let t = trustees(3)
        try owner.custody.distributeBackup(threshold: 2, recipients: t, currentDepth: 0, vaultManager: owner.vault)
        let key = try owner.bek()

        try owner.custody.distributeBackup(threshold: 2, recipients: [t[0], t[1]], currentDepth: 0, vaultManager: owner.vault)

        #expect(try owner.bek() != key, "the piece may already be on the trustee's phone")
    }

    @Test("Leaving out a deleted (lost) trustee splits a new key", .ambientTestKeyManager)
    func droppingLostRotates() throws {
        let owner = try Owner()
        let t = trustees(3)
        try owner.distributeAndConfirm(t)
        owner.reconcile(live: [t[0], t[1]])
        #expect(try owner.records().first { $0.isHeld(by: t[2]) }?.status == .lost)
        let key = try owner.bek()

        try owner.custody.distributeBackup(threshold: 2, recipients: [t[0], t[1]], currentDepth: 0, vaultManager: owner.vault)

        #expect(try owner.bek() != key, "a deleted contact still holds their piece")
    }

    @Test("Changing only the threshold keeps the key", .ambientTestKeyManager)
    func thresholdOnlyKeepsKey() throws {
        let owner = try Owner()
        let t = trustees(3)
        try owner.custody.distributeBackup(threshold: 2, recipients: t, currentDepth: 0, vaultManager: owner.vault)
        let key = try owner.bek()

        try owner.custody.distributeBackup(threshold: 3, recipients: t, currentDepth: 0, vaultManager: owner.vault)

        #expect(try owner.bek() == key)
    }

    /// What the setup screen asks before warning; it passes the real recipients, so a
    /// trustee hidden at the depth counts as left out.
    @Test("distributionDropsTrustee is true exactly when someone in the record is left out", .ambientTestKeyManager)
    func dropsTrusteeCheck() throws {
        let owner = try Owner()
        let t = trustees(4)
        try owner.custody.distributeBackup(threshold: 2, recipients: [t[0], t[1], t[2]], currentDepth: 0, vaultManager: owner.vault)

        func drops(_ r: [String]) -> Bool {
            owner.custody.distributionDropsTrustee(recipients: r, currentDepth: 0, vaultManager: owner.vault)
        }
        #expect(drops([t[0], t[1]]))
        #expect(!drops([t[0], t[1], t[2]]))
        #expect(!drops([t[0], t[1], t[2], t[3]]))
    }
}

// MARK: - Reconciliation and automatic re-send (Bug 141)

@Suite("Backup-key reconciliation — confirm, lose, re-send, one depth only")
@MainActor
struct BackupReconcileTests {

    @Test("A piece the trustee reports holding is confirmed", .ambientTestKeyManager)
    func manifestConfirms() throws {
        let owner = try Owner()
        let t = trustees(2)
        try owner.custody.distributeBackup(threshold: 2, recipients: t, currentDepth: 0, vaultManager: owner.vault)

        try owner.manifest(from: t[0], held: [try owner.pieceID(of: t[0])])
        owner.reconcile(live: Set(t))

        let records  = try owner.records()
        let statuses = Dictionary(uniqueKeysWithValues: t.map { id in (id, records.first { $0.isHeld(by: id) }?.status) })
        #expect(statuses[t[0]] == .confirmed)
        #expect(statuses[t[1]] == .pending, "no manifest from this trustee yet")
        #expect(try owner.queued(for: t[0]).isEmpty, "the confirmed piece left the queue")
    }

    @Test("A confirmed piece missing from a manifest is re-sent with the same key", .ambientTestKeyManager)
    func missingPieceResent() throws {
        let owner = try Owner()
        let t = trustees(2)
        try owner.distributeAndConfirm(t)
        let key = try owner.bek()
        let before = try t.map { try owner.pieceID(of: $0) }

        try owner.manifest(from: t[0], held: [])
        owner.reconcile(live: Set(t))

        #expect(try owner.bek() == key, "a re-send never changes the key")
        for trustee in t {
            let ops = try owner.queued(for: trustee)
            #expect(ops.count == 1 && ops.first?.kind == .replace, "every trustee gets a piece of the new split")
            #expect(!before.contains(try #require(ops.first?.attribute?.id)))
        }
    }

    /// Watch rows used to be deleted at every vault unlock, so a piece was only watched
    /// until the next one.
    @Test("A piece is still watched after the vault unlocks again", .ambientTestKeyManager)
    func watchSurvivesUnlock() throws {
        let owner = try Owner()
        let t = trustees(2)
        try owner.distributeAndConfirm(t)

        owner.vault.lock()
        owner.vault.unlock(context: LAContext())
        #expect(try owner.watch().count == 2)

        try owner.manifest(from: t[1], held: [])
        owner.reconcile(live: Set(t))
        #expect(try owner.queued(for: t[1]).count == 1)
    }

    @Test("A trustee's identity key change re-sends at once", .ambientTestKeyManager)
    func keyChangeResends() throws {
        let owner = try Owner()
        let t = trustees(2)
        try owner.distributeAndConfirm(t)

        owner.reconcile(keyChangedFor: t[0], live: Set(t))

        #expect(try owner.queued(for: t[0]).count == 1)
        #expect(try owner.queued(for: t[1]).count == 1)
    }

    @Test("A deleted trustee's piece is lost, and nothing is re-sent below the threshold", .ambientTestKeyManager)
    func deletedTrusteeLost() throws {
        let owner = try Owner()
        let t = trustees(2)
        try owner.distributeAndConfirm(t)

        owner.reconcile(live: [t[0]])

        #expect(try owner.records().first { $0.isHeld(by: t[1]) }?.status == .lost)
        #expect(try owner.queued(for: t[0]).isEmpty, "one trustee left is below the threshold of 2")
        owner.vault.refreshBackupErosion(currentDepth: 0)
        #expect(owner.vault.backupErosion?.active == 1)
    }

    /// A re-send leaving the deleted trustee out would have to split a new key, breaking
    /// exported backups without the owner's say (Bug 144).
    @Test("Nothing is re-sent while a trustee is lost", .ambientTestKeyManager)
    func noResendWhileLost() throws {
        let owner = try Owner()
        let t = trustees(3)
        try owner.distributeAndConfirm(t)
        let key = try owner.bek()
        owner.reconcile(live: [t[0], t[1]])   // t[2] deleted

        try owner.manifest(from: t[0], held: [])
        owner.reconcile(live: [t[0], t[1]])

        #expect(try owner.queued(for: t[0]).isEmpty)
        #expect(try owner.bek() == key)
    }

    @Test("A pending piece that was never queued is re-sent", .ambientTestKeyManager)
    func interruptedDistributionResent() throws {
        let owner = try Owner()
        let t = trustees(2)
        _ = try owner.vault.prepareBackupShards(threshold: 2, recipients: t, currentDepth: 0)   // split, never queued

        owner.reconcile(live: Set(t))

        #expect(try owner.queued(for: t[0]).count == 1)
        #expect(try owner.queued(for: t[1]).count == 1)
    }

    @Test("A confirmed piece with no watch row gets one, and is not re-sent", .ambientTestKeyManager)
    func confirmedWithoutWatchRowGetsOne() throws {
        let owner = try Owner()
        let t = trustees(2)
        _ = try owner.vault.prepareBackupShards(threshold: 2, recipients: t, currentDepth: 0)
        let ids = try t.map { try owner.pieceID(of: $0) }
        try owner.vault.setBackupShardStatuses(Dictionary(uniqueKeysWithValues: ids.map { ($0, .confirmed) }), currentDepth: 0)

        owner.reconcile(live: Set(t))

        #expect(try owner.watch() == Dictionary(uniqueKeysWithValues: ids.map { ($0, false) }))
        #expect(try owner.queued(for: t[0]).isEmpty)
    }

    @Test("Reconciling one depth leaves another depth's row untouched", .ambientTestKeyManager)
    func otherDepthUntouched() throws {
        let owner = try Owner()
        let t = trustees(2)
        try owner.vault.setupBackup(currentDepth: 1)
        _ = try owner.vault.prepareBackupShards(threshold: 2, recipients: t, currentDepth: 1)
        let depthOnePieces = try t.map { try owner.pieceID(of: $0, depth: 1) }
        let depthOneBytes  = try owner.rowBytes(depth: 1)

        try owner.distributeAndConfirm(t)
        try owner.manifest(from: t[0], held: [])
        owner.reconcile(live: Set(t))
        #expect(try owner.queued(for: t[0]).count == 1, "depth 0 re-sent")

        #expect(try owner.rowBytes(depth: 1) == depthOneBytes, "depth 1's row was never rewritten")
        #expect(try t.map { try owner.pieceID(of: $0, depth: 1) } == depthOnePieces)
    }

    @Test("A locked vault reconciles nothing", .ambientTestKeyManager)
    func lockedDoesNothing() throws {
        let owner = try Owner()
        let t = trustees(2)
        try owner.distributeAndConfirm(t)
        try owner.manifest(from: t[0], held: [])

        owner.vault.lock()
        owner.reconcile(live: Set(t))
        #expect(try owner.queued(for: t[0]).isEmpty)
    }
}

// MARK: - Setup state: the Vault tab's Backup Recovery row

@Suite("Backup-key setup state — confirmed of total, and the threshold")
@MainActor
struct BackupSetupStateTests {

    @Test("Three trustees, threshold two: counts all three, needs two", .ambientTestKeyManager)
    func countsEveryTrustee() throws {
        let owner = try Owner()
        let t = trustees(3)
        _ = try owner.vault.prepareBackupShards(threshold: 2, recipients: t, currentDepth: 0)
        #expect(owner.vault.backupSetupState(currentDepth: 0) == .waitingForConfirmations(confirmed: 0, total: 3, threshold: 2))

        try owner.vault.setBackupShardStatuses([try owner.pieceID(of: t[0]): .confirmed], currentDepth: 0)
        #expect(owner.vault.backupSetupState(currentDepth: 0) == .waitingForConfirmations(confirmed: 1, total: 3, threshold: 2))

        try owner.vault.setBackupShardStatuses([try owner.pieceID(of: t[1]): .confirmed], currentDepth: 0)
        #expect(owner.vault.backupSetupState(currentDepth: 0) == .ready)
    }

    @Test("A lost piece leaves the total", .ambientTestKeyManager)
    func lostPieceLeavesTotal() throws {
        let owner = try Owner()
        let t = trustees(3)
        _ = try owner.vault.prepareBackupShards(threshold: 2, recipients: t, currentDepth: 0)
        try owner.vault.setBackupShardStatuses([try owner.pieceID(of: t[2]): .lost], currentDepth: 0)
        #expect(owner.vault.backupSetupState(currentDepth: 0) == .waitingForConfirmations(confirmed: 0, total: 2, threshold: 2))
    }
}

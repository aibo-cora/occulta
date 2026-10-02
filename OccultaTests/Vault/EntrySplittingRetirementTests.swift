//
//  EntrySplittingRetirementTests.swift
//  OccultaTests
//
//  Per-entry splitting was retired (decisions.md, "Retire per-entry splitting").
//  `VaultManager.retireEntrySplittingIfNeeded`, run at every unlock, removes what it left:
//  entries' distribution records, status-update rows, queued per-entry pieces and banked
//  per-entry pieces. Backup-key state must come through untouched.
//
//  The restore buffer's rows are sealed under the ambient local key (`Manager.Ambient`), so
//  these run under `.ambientTestKeyManager`, which supplies it.
//

import Testing
import Foundation
import CryptoKit
import LocalAuthentication
import SwiftData
@testable import Occulta

@MainActor
private struct Device {
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
    }

    func piece(for secret: UUID, label: String) throws -> SignedAttribute {
        let id = UUID(), createdAt = Date(), value = Data([UInt8(1)]) + Data.randomBytes(32)
        let payload = SignedAttribute.signingPayload(id: id, category: .shard, value: value, entryID: secret, createdAt: createdAt, expiresAt: nil)
        return SignedAttribute(id: id, label: label, value: value, category: .shard,
                               signature: try self.km.signData(payload), createdAt: createdAt, expiresAt: nil, entryID: secret)
    }

    func queuedPieceIDs() throws -> Set<UUID> {
        Set(try self.custody.buildShardOperations(for: "trustee", currentContactPublicKey: nil).compactMap { $0.attribute?.id })
    }

    func count<T: PersistentModel>(_ type: T.Type) throws -> Int {
        try ModelContext(self.container).fetch(FetchDescriptor<T>()).count
    }

    /// What a device that used per-entry splitting holds, next to a live backup-key restore
    /// and a queued backup-key piece.
    func seed() throws -> (entry: VaultEntry, backupSecret: UUID, backupPiece: SignedAttribute, entryPiece: SignedAttribute) {
        self.vault.unlock(context: LAContext())
        let entry = try self.vault.addEntry(label: "seed", content: Data("words".utf8), type: .seedPhrase)
        entry.shardDistributionEncrypted = Data.randomBytes(64)

        let backupSecret = UUID()
        let entryPiece   = try self.piece(for: entry.id, label: "vault-shard")
        let backupPiece  = try self.piece(for: backupSecret, label: SignedAttribute.backupKeyPieceLabel)

        try self.custody.queueDistribute(attribute: entryPiece, for: "trustee")
        try self.custody.queueDistribute(attribute: backupPiece, for: "trustee")
        try self.vault.absorbShard(try self.piece(for: entry.id, label: "vault-shard"), senderIdentifier: "trustee")
        try self.vault.absorbShard(try self.piece(for: backupSecret, label: SignedAttribute.backupKeyPieceLabel), senderIdentifier: "trustee")

        let context = ModelContext(self.container)
        context.insert(PendingShardStatusUpdate(encryptedPayload: Data.randomBytes(48)))
        try context.save()
        return (entry, backupSecret, backupPiece, entryPiece)
    }
}

@Suite("Retired per-entry splitting — one-time clean-up", .serialized, .ambientTestKeyManager)
@MainActor
struct EntrySplittingRetirementTests {

    @Test("Per-entry state is removed and backup-key state is untouched")
    func removesPerEntryKeepsBackup() throws {
        let device = try Device()
        let (entry, backupSecret, backupPiece, entryPiece) = try device.seed()
        #expect(try device.queuedPieceIDs() == [backupPiece.id, entryPiece.id])

        device.vault.retireEntrySplittingIfNeeded()

        #expect(entry.shardDistributionEncrypted == nil)
        #expect(try device.count(PendingShardStatusUpdate.self) == 0)
        #expect(try device.queuedPieceIDs() == [backupPiece.id], "the queued per-entry piece is never delivered")
        #expect(try device.vault.collectedShards(forAttributeID: entry.id).isEmpty, "banked per-entry pieces are orphaned")
        #expect(try device.vault.collectedShards(forAttributeID: backupSecret).count == 1)
        #expect(try device.vault.bekRestoreDistributionIDs() == [backupSecret])
    }

    @Test("Running it again changes nothing")
    func idempotent() throws {
        let device = try Device()
        let (entry, backupSecret, backupPiece, _) = try device.seed()

        device.vault.retireEntrySplittingIfNeeded()
        device.vault.retireEntrySplittingIfNeeded()

        #expect(entry.shardDistributionEncrypted == nil)
        #expect(try device.queuedPieceIDs() == [backupPiece.id])
        #expect(try device.vault.collectedShards(forAttributeID: backupSecret).count == 1)
        #expect(try device.count(PendingShamirSecretRestore.self) == 2, "orphaned in place, not deleted or duplicated")
    }

    @Test("A device that never split an entry is left as it is")
    func nothingToDo() throws {
        let device = try Device()
        device.vault.unlock(context: LAContext())
        let entry = try device.vault.addEntry(label: "note", content: Data("x".utf8), type: .note)
        let backupSecret = UUID()
        try device.vault.absorbShard(try device.piece(for: backupSecret, label: SignedAttribute.backupKeyPieceLabel), senderIdentifier: "trustee")
        let bankedBefore = try ModelContext(device.container).fetch(FetchDescriptor<PendingShamirSecretRestore>()).map(\.shards)

        device.vault.retireEntrySplittingIfNeeded()

        #expect(entry.shardDistributionEncrypted == nil)
        #expect(try ModelContext(device.container).fetch(FetchDescriptor<PendingShamirSecretRestore>()).map(\.shards) == bankedBefore)
    }

    @Test("Unlocking runs it")
    func runsAtUnlock() throws {
        let device = try Device()
        let (entry, _, backupPiece, _) = try device.seed()
        device.vault.lock()

        device.vault.unlock(context: LAContext())

        #expect(entry.shardDistributionEncrypted == nil)
        #expect(try device.queuedPieceIDs() == [backupPiece.id])
    }
}

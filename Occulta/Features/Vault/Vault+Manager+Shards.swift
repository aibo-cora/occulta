//
//  Vault+Manager+Shards.swift
//  Occulta
//
//  Owner-side shard state for VaultManager: the backup key's erosion signal, and the
//  one-time clean-up after per-entry splitting was retired.
//
//  Per-entry splitting (each entry's PEK split among trustees) was retired 2026-09-27
//  (`decisions.md`, "Retire per-entry splitting"): reconstructing a PEK only ever worked on
//  the phone that still held the entry, where the entry was already readable, and a lost
//  phone is covered by the `.occbak` backup. The backup key is the only secret split now.
//

import Foundation
import SwiftData
import CryptoKit
import OccultaFormats

extension VaultManager {

    // MARK: - Backup-key erosion

    /// Recompute `backupErosion` for `currentDepth`'s own backup-key slot.
    ///
    /// Refreshed only by the views that display it, never from a save hook, which has no
    /// depth in scope. Not called from `unlock()` itself: the views' `onChange(of:
    /// vault.isUnlocked)` already fires right after unlock sets `authContext`, so a
    /// call there would just be a redundant second refresh. Called only from the
    /// views that display it (`Vault+Tab`, `VaultRecoverySettings`), mirroring
    /// `refreshBackupStaleness` exactly — must never be computed from any depth
    /// other than the one actually in scope where it's read, or it becomes a
    /// coercer-observable leak of a different depth's erosion state.
    func refreshBackupErosion(currentDepth: Int) {
        guard let vaultKey = try? self.currentKey() else {
            self.backupErosion = nil
            return
        }
        if let meta = try? self.backup.shardMetadata(vaultKey: vaultKey, currentDepth: currentDepth, modelContext: self.modelContext) {
            let active = meta.shards.filter { $0.status == .pending || $0.status == .confirmed }.count
            self.backupErosion = active < meta.threshold ? (active, meta.threshold) : nil
        } else {
            self.backupErosion = nil
        }
    }

    // MARK: - Retired per-entry splitting

    /// Removes what per-entry splitting left behind (`decisions.md`, "Retire per-entry
    /// splitting"). Runs at every unlock; after the first it finds nothing.
    ///
    /// - every `VaultEntry.shardDistributionEncrypted` is cleared, so no row still shows
    ///   whether its entry was split (the property leaves the schema next release);
    /// - every `PendingShardStatusUpdate` row is deleted: only per-entry pieces used them;
    /// - queued per-entry pieces (`PendingShardDistribute` rows whose piece names a
    ///   `VaultEntry.id`) are deleted, so they are never delivered;
    /// - banked per-entry pieces (`PendingShamirSecretRestore` rows for a `VaultEntry.id`)
    ///   are orphaned, so a restore never tries them.
    ///
    /// Needs no vault key and nothing depth-specific: entry IDs are plaintext, and the
    /// queue and restore rows open under the custody and local keys. Watch rows
    /// (`PotentiallyLostShard`) for per-entry pieces confirmed since the last unlock
    /// before the upgrade can't be told apart without opening every entry's distribution
    /// record, which would read every depth's; they're left, and nothing reads them.
    /// Pieces trustees hold are left too: nothing deletes a piece on a trustee's phone.
    func retireEntrySplittingIfNeeded() {
        let entries  = (try? self.modelContext.fetch(FetchDescriptor<VaultEntry>())) ?? []
        let entryIDs = Set(entries.map(\.id))
        var changed  = false

        for entry in entries where entry.shardDistributionEncrypted != nil {
            entry.shardDistributionEncrypted = nil
            changed = true
        }

        for row in (try? self.modelContext.fetch(FetchDescriptor<PendingShardStatusUpdate>())) ?? [] {
            self.modelContext.delete(row)
            changed = true
        }

        if let custodyKey = try? self.keyManager.deriveShardCustodyKey() {
            for row in (try? self.modelContext.fetch(FetchDescriptor<PendingShardDistribute>())) ?? [] {
                guard let box     = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                      let plain   = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
                      let payload = try? JSONDecoder().decode(PendingShardDistribute.Payload.self, from: plain),
                      let entryID = payload.signedAttribute.entryID, entryIDs.contains(entryID)
                else { continue }
                self.modelContext.delete(row)
                changed = true
            }
        }

        if self.orphanRestoreRows(forAttributeIDs: entryIDs) { changed = true }
        if changed { try? self.modelContext.save() }
    }
}

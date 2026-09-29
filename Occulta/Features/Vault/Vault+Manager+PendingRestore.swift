//
//  Vault+Manager+PendingRestore.swift
//  Occulta
//
//  Singleton access to the `Vault` row — the parent of `PendingShamirSecretRestore`.
//  This file only ever fetches/creates the `Vault` row itself, never the
//  `pendingRestores` relationship — the real read/write logic (absorb, collect,
//  orphan) lives in `Vault+Manager+ReturnBuffer.swift`, keyed by `attributeID` via a
//  direct `FetchDescriptor<PendingShamirSecretRestore>()`, not through this
//  relationship array. See `RECOVERY_BUFFER_LAYERING.md` §6 item 9.3.
//

import Foundation
import SwiftData

extension VaultManager {

    /// Ensures exactly one `Vault` row exists. Called unconditionally from `init`,
    /// alongside `ensureBackupKeyFillerRows()` — `Vault` carries no sensitive fields of
    /// its own (just `id` and the `pendingRestores` relationship), so there's no
    /// camouflage question here the way there was for `BackupEncryptionKey`'s 32-row
    /// baseline: this is one trivial row, always present, same reasoning as
    /// `AppLayerConfig`'s own "absence would itself be a tell" bootstrap
    /// (`Manager.Security.init`).
    func ensureVaultExists() {
        guard (try? self.modelContext.fetch(FetchDescriptor<Vault>()).first) == nil else { return }
        self.modelContext.insert(Vault())
        try? self.modelContext.save()
    }

    /// The singleton `Vault` row. Throws rather than creates — `ensureVaultExists()`
    /// running at every `init` should make this unreachable in practice; this is the
    /// defensive fetch-only half, mirroring `Manager.Security.requireConfig()`.
    func requireVault() throws -> Vault {
        guard let vault = try? self.modelContext.fetch(FetchDescriptor<Vault>()).first else {
            throw VaultError.vaultNotFound
        }
        return vault
    }
}

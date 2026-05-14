//
//  Vault+Manager+Reconstruction.swift
//  Occulta
//
//  SSS reconstruction path for VaultManager.
//  Collects ≥ k shards, reconstructs the PEK, verifies integrity via GCM
//  authentication, re-wraps the PEK under the current vault key, and saves.
//

import Foundation
import SwiftData
import CryptoKit

extension VaultManager {

    // MARK: - Reconstruction

    /// Reconstruct the per-entry key (PEK) from ≥ k shards and re-wrap it under
    /// the current vault key.
    ///
    /// Steps:
    ///   1. Verify all shards carry a matching `entryID`.
    ///   2. If the vault SE identity key is available, verify each shard's ECDSA
    ///      signature. On a new device (key non-migratable), skip signature
    ///      verification — GCM authentication in step 4 substitutes.
    ///   3. `ShamirSecretSharing.reconstruct(shares:)` → candidate PEK.
    ///   4. `AES.GCM.open(encryptedContent, using: candidatePEK)` — the GCM
    ///      authentication tag is the practical integrity check. If fewer than k
    ///      shards were supplied, or any shard byte was tampered, reconstruction
    ///      produces a random value and GCM decryption fails here.
    ///   5. Re-seal the PEK under the current vault key → update `encryptedEntryKey`.
    ///   6. Zero candidate PEK bytes immediately after re-wrapping.
    ///
    /// - Parameters:
    ///   - entryID:       The VaultEntry to recover.
    ///   - shards:        The collected `SignedAttribute` shards (category must be `.shard`).
    ///   - ownerIdentity: x963 P-256 public key (65 bytes) used to verify ECDSA signatures.
    ///                    Pass nil to skip signature verification (new-device recovery path).
    ///
    /// - Throws:
    ///   - `VaultError.locked` — vault not unlocked.
    ///   - `VaultError.entryNotFound` — no entry with this ID.
    ///   - `VaultError.decryptionFailed` — GCM authentication rejected the reconstructed
    ///     PEK (wrong shards, corrupt shard bytes, or wrong entry).
    ///   - `VaultError.encryptionFailed` — could not re-seal the recovered PEK.
    func reconstructEntry(
        entryID: UUID,
        shards: [SignedAttribute],
        ownerIdentity: Data?
    ) throws {
        let vaultKey    = try self.currentKey()
        guard let entry = try self.fetchEntry(by: entryID) else { throw VaultError.entryNotFound }

        // ── 1. Bind all shards to this entry ─────────────────────────────────
        guard shards.allSatisfy({ $0.entryID == entryID && $0.category == .shard }) else {
            throw VaultError.decryptionFailed
        }

        // ── 2. Signature verification (skipped on new-device path) ────────────
        if let pubKey = ownerIdentity {
            guard shards.allSatisfy({ $0.verify(against: pubKey) }) else {
                throw VaultError.decryptionFailed
            }
        }

        // ── 3. Reconstruct candidate PEK ─────────────────────────────────────
        let rawShares = shards.map { Array($0.value) }

        // Enforce threshold before handing to SSS. With fewer than k shares,
        // Lagrange interpolation silently produces garbage — GCM would catch it
        // eventually, but throwing here gives a clear, early failure.
        // tryFinalizeReconstruction already guards this for the normal path;
        // this check protects any direct callers of reconstructEntry.
        if let meta = try? self.shardDistributionMetadata(for: entryID),
           rawShares.count < meta.threshold {
            throw VaultError.decryptionFailed
        }

        var candidateData: Data
        do {
            candidateData = try ShamirSecretSharing.reconstruct(shares: rawShares)
        } catch {
            throw VaultError.decryptionFailed
        }
        defer { for i in candidateData.indices { candidateData[i] = 0 } }

        guard candidateData.count == 32 else { throw VaultError.decryptionFailed }
        let candidatePEK = SymmetricKey(data: candidateData)

        // ── 4. GCM authentication — integrity check ───────────────────────────
        // A wrong PEK produces a random value; the 128-bit GCM tag rejects it.
        let contentBox = try AES.GCM.SealedBox(combined: entry.encryptedContent)
        guard (try? AES.GCM.open(contentBox, using: candidatePEK,
                                  authenticating: entry.aad(for: .content))) != nil else {
            throw VaultError.decryptionFailed
        }

        // ── 5. Re-wrap PEK under current vault key ────────────────────────────
        let sealedKey = try AES.GCM.seal(
            candidateData,
            using:          vaultKey,
            nonce:          AES.GCM.Nonce(),
            authenticating: entry.aad(for: .entryKey)
        )
        guard let combinedKey = sealedKey.combined else { throw VaultError.encryptionFailed }

        entry.encryptedEntryKey = combinedKey
        try self.modelContext.save()

        // candidateData zeroed by defer ───────────────────────────────────────
    }
}

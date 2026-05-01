//
//  ShardCustody+Manager.swift
//  Occulta
//
//  Inbound router for `ShardOperation` traffic decoded from `.occ` bundles.
//  Mirrors the IdentityChallenge.Coordinator pattern: the OccultaApp peeks at
//  `SealedPayload.shardOperations` and hands the bundle here when non-nil.
//
//  Two roles, one router:
//    - Trustee path: accept `.distribute` (new shard) and `.replace`
//      (superseding shard) from the owner; store as encrypted CustodyShard rows;
//      serve `.revoke`; auto-return shards as `.handback` when the owner's
//      identity key changes.
//    - Owner path: receive `.handback`, `.acknowledge`, `.notFound` from
//      trustees; send `.returnAcknowledged` after absorbing returned shards;
//      update local recovery state.
//
//  Outbound operation queuing (`.acknowledge`, `.handback`, `.revoke`,
//  `.returnAcknowledged`, `.notFound`) is handled via Pending* SwiftData models
//  read before every outbound bundle: `pendingReturnOperations`,
//  `pendingAcknowledgeOperation`, `pendingShardAcknowledgeOperations`,
//  `pendingRevokeOperations`, `pendingNotFoundOperations`.
//

import Foundation
import SwiftData
import CryptoKit

@Observable
@MainActor
final class ShardCustodyManager {

    // MARK: - Dependencies

    private let modelContainer: ModelContainer
    private let modelContext:   ModelContext
    private let keyManager:     any KeyManagerProtocol

    // MARK: - Init

    init(modelContainer: ModelContainer, keyManager: any KeyManagerProtocol) {
        self.modelContainer = modelContainer
        self.modelContext   = ModelContext(modelContainer)
        self.keyManager     = keyManager
    }

    // MARK: - Inbound dispatch

    /// Route a decoded SealedPayload to the per-Kind handler.
    ///
    /// Returns `true` whenever a shard operation was present, even if the handler
    /// failed — the caller (OccultaApp.buildOwnedBasket) interprets `true` as
    /// "this bundle is not a basket" and must NOT fall back to message rendering.
    @discardableResult
    func handleInbound(
        sealed:            OccultaBundle.SealedPayload,
        senderPublicKey:   Data,
        senderIdentifier:  String,
        vaultManager:      VaultManager
    ) -> Bool {
        guard let ops = sealed.shardOperations, !ops.isEmpty else { return false }

        // Collect attrIDs from successfully absorbed .handback operations so we
        // can queue a single PendingReturnAcknowledge for this sender afterwards.
        var respondedAttrIDs: [UUID] = []
        var sawReturnAcknowledged   = false

        for op in ops {
            do {
                switch op.kind {
                case .distribute:
                    try self.handleDistribute(op: op, senderPublicKey: senderPublicKey, senderIdentifier: senderIdentifier)
                case .replace:
                    try self.handleReplace(op: op, senderPublicKey: senderPublicKey, senderIdentifier: senderIdentifier)
                case .revoke:
                    try self.handleRevoke(op: op)
                case .inquire:
                    try self.handleInquire(op: op, senderIdentifier: senderIdentifier)
                case .handback:
                    try self.handleHandback(op: op, vaultManager: vaultManager)
                    if let attrID = op.attribute?.id { respondedAttrIDs.append(attrID) }
                case .acknowledge:
                    try self.handleAcknowledge(op: op, vaultManager: vaultManager)
                case .notFound:
                    try self.handleNotFound(op: op, vaultManager: vaultManager)
                case .returnAcknowledged:
                    try self.handleReturnAcknowledged(op: op)
                    sawReturnAcknowledged = true
                case .unsupported:
                    break
                }
            } catch {
                #if DEBUG
                debugPrint("ShardCustodyManager dispatch failed for \(op.kind): \(error)")
                #endif
            }
        }

        // Queue one PendingReturnAcknowledge covering all returned shards.
        if !respondedAttrIDs.isEmpty {
            do { try self.queueReturnAcknowledge(attrIDs: respondedAttrIDs, for: senderIdentifier) }
            catch {
                #if DEBUG
                debugPrint("ShardCustodyManager: failed to queue return-ack: \(error)")
                #endif
            }
        }

        // If we processed any .returnAcknowledged ops, clean up PendingShardReturn
        // once — after all per-shard deletions have been applied.
        if sawReturnAcknowledged {
            try? self.cleanupPendingReturnIfComplete(for: senderIdentifier)
        }

        return true
    }

    // MARK: - Trustee path

    /// `.distribute` — owner sent us a shard to hold (first distribution).
    ///
    /// 1. Verify the SignedAttribute against the owner's public key.
    /// 2. Seal CustodyShard.Payload under the shard custody key + AAD.
    /// 3. Insert.
    /// 4. Upsert a `PendingShardAcknowledge` row for the owner.
    private func handleDistribute(op: OccultaBundle.ShardOperation, senderPublicKey: Data, senderIdentifier: String) throws {
        guard let attribute = op.attribute, attribute.category == .shard else {
            throw CustodyError.invalidPayload
        }
        guard attribute.verify(against: senderPublicKey) else {
            throw CustodyError.signatureRejected
        }

        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }

        let rowID     = UUID()
        let aad       = Self.rowAAD(id: rowID)
        let payload   = CustodyShard.Payload(
            ownerKeyFingerprint:    Self.fingerprint(of: senderPublicKey),
            ownerContactIdentifier: senderIdentifier,
            signedAttribute:        attribute
        )
        let plaintext = try JSONEncoder().encode(payload)
        let sealed    = try AES.GCM.seal(plaintext, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: aad)
        guard let combined = sealed.combined else { throw CustodyError.encryptionFailed }

        self.modelContext.insert(CustodyShard(id: rowID, encryptedPayload: combined))
        try self.modelContext.save()

        // Queue an outbound `.acknowledge` to the owner. Best-effort: if this
        // throws, the shard is still stored — the ack is cosmetic, not required
        // for correctness. Alice's ShardRecord status will lag at `.pending` until
        // the next successful queue + send cycle.
        try? self.queueShardAcknowledge(attrID: attribute.id, for: senderIdentifier)
    }

    /// `.replace` — owner sent a replacement shard; store the new one and delete the old.
    ///
    /// Same verification and storage as `.distribute`, then deletes the CustodyShard
    /// whose `signedAttribute.id` matches `op.attributeID` (the superseded shard).
    /// Insert-then-delete ordering ensures we never lose the shard even if the delete fails.
    private func handleReplace(op: OccultaBundle.ShardOperation, senderPublicKey: Data, senderIdentifier: String) throws {
        guard let attribute = op.attribute, attribute.category == .shard,
              let oldID = op.attributeID else {
            throw CustodyError.invalidPayload
        }
        guard attribute.verify(against: senderPublicKey) else {
            throw CustodyError.signatureRejected
        }

        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }

        // Store the new shard.
        let rowID     = UUID()
        let aad       = Self.rowAAD(id: rowID)
        let payload   = CustodyShard.Payload(
            ownerKeyFingerprint:    Self.fingerprint(of: senderPublicKey),
            ownerContactIdentifier: senderIdentifier,
            signedAttribute:        attribute
        )
        let plaintext = try JSONEncoder().encode(payload)
        let sealed    = try AES.GCM.seal(plaintext, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: aad)
        guard let combined = sealed.combined else { throw CustodyError.encryptionFailed }
        self.modelContext.insert(CustodyShard(id: rowID, encryptedPayload: combined))

        // Delete the superseded shard.
        for decoded in try self.decryptAllCustodyShards()
            where decoded.payload.signedAttribute.id == oldID {
            self.modelContext.delete(decoded.row)
        }

        try self.modelContext.save()
        try? self.queueShardAcknowledge(attrID: attribute.id, for: senderIdentifier)
    }

    /// `.inquire` — owner probes whether we still hold a specific shard.
    ///
    /// Looks up the CustodyShard whose `signedAttribute.id` matches `op.attributeID`:
    ///   • Found  → queue `.acknowledge` (already done for fresh distributes; this
    ///              re-confirms an existing shard without inserting a duplicate ack).
    ///   • Not found → queue `.notFound` so the owner can mark the ShardRecord `.lost`.
    private func handleInquire(op: OccultaBundle.ShardOperation, senderIdentifier: String) throws {
        guard let attributeID = op.attributeID else { throw CustodyError.invalidPayload }

        let found = try self.decryptAllCustodyShards()
            .contains { $0.payload.signedAttribute.id == attributeID }

        if found {
            try? self.queueShardAcknowledge(attrID: attributeID, for: senderIdentifier)
        } else {
            try self.queueShardNotFound(attributeID: attributeID, for: senderIdentifier)
        }
    }

    /// `.revoke` — owner asks us to discard a shard. Match by SignedAttribute.id.
    private func handleRevoke(op: OccultaBundle.ShardOperation) throws {
        guard let attributeID = op.attributeID else { throw CustodyError.invalidPayload }

        var deletedAny = false
        for decoded in try self.decryptAllCustodyShards()
            where decoded.payload.signedAttribute.id == attributeID {
            self.modelContext.delete(decoded.row)
            deletedAny = true
        }
        if deletedAny { try self.modelContext.save() }
    }

    // MARK: - Owner path

    /// `.handback` — trustee returned one of our shards (auto-return after key change).
    private func handleHandback(op: OccultaBundle.ShardOperation, vaultManager: VaultManager) throws {
        guard let attribute = op.attribute, attribute.category == .shard else {
            throw CustodyError.invalidPayload
        }
        try vaultManager.acceptReturnedShard(attribute)
    }

    /// `.acknowledge` — trustee confirmed receipt; mark our distribution record `.confirmed`.
    ///
    /// If the vault is locked the update cannot be applied immediately. A
    /// `PendingShardStatusUpdate` row is queued; `VaultManager.unlock()` drains
    /// it on the next biometric unlock.
    private func handleAcknowledge(op: OccultaBundle.ShardOperation, vaultManager: VaultManager) throws {
        guard let attributeID = op.attributeID else { throw CustodyError.invalidPayload }
        do {
            try vaultManager.updateShardStatus(attrID: attributeID, to: .confirmed)
        } catch VaultManager.VaultError.locked {
            try self.queueShardStatusUpdate(attributeID: attributeID, newStatus: .confirmed)
        } catch {
            // Entry not found or other unrecoverable error — silently drop.
        }
    }

    /// `.notFound` — trustee no longer has our shard; mark it `.lost`.
    ///
    /// Same deferred-update pattern as `handleAcknowledge`.
    private func handleNotFound(op: OccultaBundle.ShardOperation, vaultManager: VaultManager) throws {
        guard let attributeID = op.attributeID else { throw CustodyError.invalidPayload }
        do {
            try vaultManager.updateShardStatus(attrID: attributeID, to: .lost)
        } catch VaultManager.VaultError.locked {
            try self.queueShardStatusUpdate(attributeID: attributeID, newStatus: .lost)
        } catch {
            // Entry not found or other unrecoverable error — silently drop.
        }
    }

    /// `.returnAcknowledged` — owner confirmed receipt of one shard; delete our custody row.
    ///
    /// PendingShardReturn cleanup is deferred to `cleanupPendingReturnIfComplete` which
    /// is called once after all ops in the batch are processed.
    private func handleReturnAcknowledged(op: OccultaBundle.ShardOperation) throws {
        guard let attributeID = op.attributeID else { throw CustodyError.invalidPayload }
        var deletedAny = false
        for decoded in try self.decryptAllCustodyShards()
            where decoded.payload.signedAttribute.id == attributeID {
            self.modelContext.delete(decoded.row)
            deletedAny = true
        }
        if deletedAny { try self.modelContext.save() }
    }

    /// Delete the `PendingShardReturn` row for `ownerIdentifier` if we no longer
    /// hold any custody shards for them.
    ///
    /// Called once after all `.returnAcknowledged` ops in a bundle are processed,
    /// so the check reflects the fully-applied state rather than a mid-batch snapshot.
    private func cleanupPendingReturnIfComplete(for ownerIdentifier: String) throws {
        let remaining = try self.decryptAllCustodyShards()
            .filter { $0.payload.ownerContactIdentifier == ownerIdentifier }
        guard remaining.isEmpty else { return }

        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else { return }
        let rows = try self.modelContext.fetch(FetchDescriptor<PendingShardReturn>())
        var deletedAny = false
        for row in rows {
            guard
                let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                let plaintext = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
                let payload   = try? JSONDecoder().decode(PendingShardReturn.Payload.self, from: plaintext),
                payload.contactIdentifier == ownerIdentifier
            else { continue }
            self.modelContext.delete(row)
            deletedAny = true
        }
        if deletedAny { try self.modelContext.save() }
    }

    // MARK: - Global shard config

    /// Read the user's global trustee configuration. Returns `nil` if not yet set.
    func globalShardConfig() throws -> GlobalShardConfig.Payload? {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }
        let rows = try self.modelContext.fetch(FetchDescriptor<GlobalShardConfig>())
        for row in rows {
            guard
                let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                let plaintext = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
                let payload   = try? JSONDecoder().decode(GlobalShardConfig.Payload.self, from: plaintext)
            else { continue }
            return payload
        }
        return nil
    }

    /// Decrypt a single `GlobalShardConfig` row supplied by a `@Query`.
    ///
    /// Used by views that observe the store reactively and need to decrypt
    /// a row they already hold, without triggering a separate fetch.
    func decryptGlobalConfig(_ row: GlobalShardConfig) throws -> GlobalShardConfig.Payload? {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }
        guard
            let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
            let plaintext = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
            let payload   = try? JSONDecoder().decode(GlobalShardConfig.Payload.self, from: plaintext)
        else { return nil }
        return payload
    }

    /// Persist the user's global trustee configuration.
    ///
    /// Singleton semantics: deletes all existing rows then inserts a fresh one.
    func saveGlobalShardConfig(_ payload: GlobalShardConfig.Payload) throws {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }
        let existing = try self.modelContext.fetch(FetchDescriptor<GlobalShardConfig>())
        for row in existing { self.modelContext.delete(row) }

        let rowID    = UUID()
        let bytes    = try JSONEncoder().encode(payload)
        let aad      = Self.rowAAD(id: rowID)
        let sealed   = try AES.GCM.seal(bytes, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: aad)
        guard let combined = sealed.combined else { throw CustodyError.encryptionFailed }
        self.modelContext.insert(GlobalShardConfig(id: rowID, encryptedPayload: combined))
        try self.modelContext.save()
    }

    // MARK: - Revocation queuing

    /// Queue `.revoke` operations for every active shard in `metadata`.
    ///
    /// Called immediately after `VaultManager.deleteEntry` returns the metadata,
    /// and from `VaultShardSetup.markForDistribution` for trustees being removed
    /// before a re-distribution.
    ///
    /// For each trustee, upserts one `PendingShardRevoke` row — merging `attrIDs`
    /// if a row already exists (Alice may delete multiple entries before sending
    /// the next message to a given trustee).
    ///
    /// Skips shards already in a terminal or in-flight revocation state:
    /// `.revoked`, `.revokePending` (already queued), and `.lost` (shard gone).
    func queueRevokes(from metadata: ShardDistributionMetadata) {
        do {
            guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else { return }

            let pending = try self.modelContext.fetch(FetchDescriptor<PendingShardRevoke>())

            for shard in metadata.shards
                where shard.status != .revoked
                   && shard.status != .revokePending
                   && shard.status != .lost {
                let contactID = shard.contactIdentifier
                let attrID    = shard.attrID

                // Upsert: find an existing row for this trustee and merge attrIDs.
                if let existing = pending.first(where: { row in
                    guard
                        let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                        let plaintext = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
                        let payload   = try? JSONDecoder().decode(PendingShardRevoke.Payload.self, from: plaintext)
                    else { return false }
                    
                    return payload.contactIdentifier == contactID
                }) {
                    guard
                        let box       = try? AES.GCM.SealedBox(combined: existing.encryptedPayload),
                        let plaintext = try? AES.GCM.open(box, using: custodyKey, authenticating: existing.aad()),
                        let payload   = try? JSONDecoder().decode(PendingShardRevoke.Payload.self, from: plaintext)
                    else { continue }
                    
                    let merged  = PendingShardRevoke.Payload(contactIdentifier: contactID, attrIDs: Array(Set(payload.attrIDs).union([attrID])))
                    let bytes   = try JSONEncoder().encode(merged)
                    let sealed  = try AES.GCM.seal(bytes, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: existing.aad())
                    
                    guard let combined = sealed.combined else { continue }
                    
                    existing.encryptedPayload = combined
                } else {
                    // Insert a new row.
                    let rowID   = UUID()
                    let payload = PendingShardRevoke.Payload(contactIdentifier: contactID, attrIDs: [attrID])
                    let bytes   = try JSONEncoder().encode(payload)
                    let aad     = Self.rowAAD(id: rowID)
                    let sealed  = try AES.GCM.seal(bytes, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: aad)
                    
                    guard let combined = sealed.combined else { continue }
                    
                    self.modelContext.insert(PendingShardRevoke(id: rowID, encryptedPayload: combined))
                }
            }
            try self.modelContext.save()
        } catch {
            #if DEBUG
            debugPrint("ShardCustodyManager.queueRevokes failed: \(error)")
            #endif
        }
    }

    /// Queue a single-shard `.revoke` for `contactIdentifier`.
    ///
    /// Mirrors `queueRevokes(from:)` but for one attrID. Merges with any existing
    /// `PendingShardRevoke` row for this contact so multiple revocations accumulate
    /// in one outbound operation.
    func queueRevoke(attrID: UUID, for contactIdentifier: String) throws {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }

        let pending = try self.modelContext.fetch(FetchDescriptor<PendingShardRevoke>())

        if let existing = pending.first(where: { row in
            guard
                let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                let plaintext = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
                let payload   = try? JSONDecoder().decode(PendingShardRevoke.Payload.self, from: plaintext)
            else { return false }
            return payload.contactIdentifier == contactIdentifier
        }) {
            guard
                let box       = try? AES.GCM.SealedBox(combined: existing.encryptedPayload),
                let plaintext = try? AES.GCM.open(box, using: custodyKey, authenticating: existing.aad()),
                let payload   = try? JSONDecoder().decode(PendingShardRevoke.Payload.self, from: plaintext)
            else { return }
            let merged  = PendingShardRevoke.Payload(contactIdentifier: contactIdentifier, attrIDs: Array(Set(payload.attrIDs).union([attrID])))
            let bytes   = try JSONEncoder().encode(merged)
            let sealed  = try AES.GCM.seal(bytes, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: existing.aad())
            guard let combined = sealed.combined else { return }
            existing.encryptedPayload = combined
        } else {
            let rowID   = UUID()
            let payload = PendingShardRevoke.Payload(contactIdentifier: contactIdentifier, attrIDs: [attrID])
            let bytes   = try JSONEncoder().encode(payload)
            let aad     = Self.rowAAD(id: rowID)
            let sealed  = try AES.GCM.seal(bytes, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: aad)
            guard let combined = sealed.combined else { throw CustodyError.encryptionFailed }
            self.modelContext.insert(PendingShardRevoke(id: rowID, encryptedPayload: combined))
        }
        try self.modelContext.save()
    }

    /// Build `.revoke` operations for any pending revocations owed to `contactIdentifier`.
    ///
    /// Deletes the row on send (fire-and-forget). Trustees silently delete the
    /// matching `CustodyShard` rows; there is no `.revokeAcknowledged` response —
    /// no confirmation is needed because every `prepareShards` call generates fresh
    /// shard bytes, making old shards mathematically inert regardless of whether the
    /// trustee deleted them.
    ///
    /// Writes `.revoked` to each affected `ShardRecord` so recovery health reflects
    /// the actual distribution state. Best-effort: a no-op when the entry has been
    /// deleted (the `ShardRecord` no longer exists).
    func pendingRevokeOperations(for contactIdentifier: String, vaultManager: VaultManager) throws -> [OccultaBundle.ShardOperation]? {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }

        let rows = try self.modelContext.fetch(FetchDescriptor<PendingShardRevoke>())
        for row in rows {
            guard
                let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                let plaintext = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
                let payload   = try? JSONDecoder().decode(PendingShardRevoke.Payload.self, from: plaintext),
                payload.contactIdentifier == contactIdentifier
            else { continue }

            self.modelContext.delete(row)
            try self.modelContext.save()

            // Mark each shard .revoked on Alice's side. No-op when the entry was
            // deleted (updateShardStatus finds no matching ShardRecord and returns).
            for attrID in payload.attrIDs {
                try? vaultManager.updateShardStatus(attrID: attrID, to: .revoked)
            }

            return payload.attrIDs.map { OccultaBundle.ShardOperation(kind: .revoke, attributeID: $0) }
        }
        return nil
    }

    // MARK: - Auto-return delivery

    /// Build `.handback` shard operations for every `CustodyShard` we hold for
    /// `contactIdentifier`, provided a `PendingShardReturn` row exists for them.
    ///
    /// Returns ALL shards for the contact in one call — the bundle piggybacking
    /// these ops must carry the full set, not a subset. Returns `nil` when no
    /// `PendingShardReturn` exists or no matching shards can be decrypted.
    func pendingReturnOperations(for contactIdentifier: String) throws -> [OccultaBundle.ShardOperation]? {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }

        // Check for a pending return row for this contact.
        let pendingRows = try self.modelContext.fetch(FetchDescriptor<PendingShardReturn>())
        let hasPending  = pendingRows.contains { row in
            guard
                let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                let plaintext = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
                let payload   = try? JSONDecoder().decode(PendingShardReturn.Payload.self, from: plaintext)
            else { return false }
            return payload.contactIdentifier == contactIdentifier
        }
        guard hasPending else { return nil }

        // Build .handback operations from ALL matching custody shards.
        let ops = try self.decryptAllCustodyShards()
            .filter { $0.payload.ownerContactIdentifier == contactIdentifier }
            .map { decoded in
                OccultaBundle.ShardOperation(kind: .handback, attribute: decoded.payload.signedAttribute)
            }
        return ops.isEmpty ? nil : ops
    }

    /// Build `.returnAcknowledged` operations for Bob if Alice has a
    /// `PendingReturnAcknowledge` row for him, then delete that row (fire-and-forget;
    /// retry on the next outbound bundle if the acks were never delivered).
    ///
    /// Returns one operation per attrID — the outer `shardOperations` array handles
    /// batching. Returns `nil` when no pending ack exists for this contact.
    func pendingAcknowledgeOperation(for contactIdentifier: String) throws -> [OccultaBundle.ShardOperation]? {
        guard let bufferKey = try self.keyManager.deriveRecoveryBufferKey() else {
            throw CustodyError.keyDerivationFailed
        }

        let rows = try self.modelContext.fetch(FetchDescriptor<PendingReturnAcknowledge>())
        for row in rows {
            guard
                let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                let plaintext = try? AES.GCM.open(box, using: bufferKey, authenticating: row.aad()),
                let payload   = try? JSONDecoder().decode(PendingReturnAcknowledge.Payload.self, from: plaintext),
                payload.contactIdentifier == contactIdentifier
            else { continue }

            self.modelContext.delete(row)
            try self.modelContext.save()
            return payload.attrIDs.map { OccultaBundle.ShardOperation(kind: .returnAcknowledged, attributeID: $0) }
        }
        return nil
    }

    // MARK: - Shard-receipt acknowledgement (trustee → owner)

    /// Build `.acknowledge` operations for every shard Bob owes to `ownerIdentifier`.
    ///
    /// Returns one `ShardOperation(kind: .acknowledge, attrID:)` per queued attrID,
    /// then deletes the row (fire-and-forget). If the bundle is never delivered,
    /// Alice's ShardRecord remains `.pending`; the next outbound message retries
    /// automatically because the row was already deleted on this call.
    ///
    /// Returns `nil` when no pending ack exists for this contact.
    func pendingShardAcknowledgeOperations(for ownerIdentifier: String) throws -> [OccultaBundle.ShardOperation]? {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }

        let rows = try self.modelContext.fetch(FetchDescriptor<PendingShardAcknowledge>())
        for row in rows {
            guard
                let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                let plaintext = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
                let payload   = try? JSONDecoder().decode(PendingShardAcknowledge.Payload.self, from: plaintext),
                payload.ownerContactIdentifier == ownerIdentifier
            else { continue }

            self.modelContext.delete(row)
            try self.modelContext.save()
            return payload.attrIDs.map { OccultaBundle.ShardOperation(kind: .acknowledge, attributeID: $0) }
        }
        return nil
    }

    /// Upsert a `PendingShardAcknowledge` row for `ownerIdentifier`.
    ///
    /// If a row already exists (owner sent another shard before Bob acked the
    /// first), merge the attrIDs so the ack covers all received shards.
    private func queueShardAcknowledge(attrID: UUID, for ownerIdentifier: String) throws {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }

        let rows = try self.modelContext.fetch(FetchDescriptor<PendingShardAcknowledge>())
        for row in rows {
            guard
                let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                let plaintext = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
                let existing  = try? JSONDecoder().decode(PendingShardAcknowledge.Payload.self, from: plaintext),
                existing.ownerContactIdentifier == ownerIdentifier
            else { continue }
            // Merge: union of existing + new attrID.
            let merged  = Array(Set(existing.attrIDs).union([attrID]))
            let updated = PendingShardAcknowledge.Payload(ownerContactIdentifier: ownerIdentifier, attrIDs: merged)
            let bytes   = try JSONEncoder().encode(updated)
            let sealed  = try AES.GCM.seal(bytes, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: row.aad())
            guard let combined = sealed.combined else { return }
            row.encryptedPayload = combined
            try self.modelContext.save()
            return
        }

        // No existing row — insert a new one.
        let rowID   = UUID()
        let payload = PendingShardAcknowledge.Payload(ownerContactIdentifier: ownerIdentifier, attrIDs: [attrID])
        let bytes   = try JSONEncoder().encode(payload)
        let aad     = Self.rowAAD(id: rowID)
        let sealed  = try AES.GCM.seal(bytes, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: aad)
        guard let combined = sealed.combined else { throw CustodyError.encryptionFailed }
        self.modelContext.insert(PendingShardAcknowledge(id: rowID, encryptedPayload: combined))
        try self.modelContext.save()
    }

    /// Insert a `PendingShardStatusUpdate` row for a status change that could not
    /// be applied because the vault was locked.
    ///
    /// One row per `attributeID` — no merging needed since each shard identifier
    /// is globally unique. `VaultManager.drainPendingShardStatusUpdates()` replays
    /// the update on the next unlock.
    private func queueShardStatusUpdate(attributeID: UUID, newStatus: ShardStatus) throws {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }

        let rowID   = UUID()
        let payload = PendingShardStatusUpdate.Payload(attributeID: attributeID, newStatus: newStatus)
        let bytes   = try JSONEncoder().encode(payload)
        let aad     = Self.rowAAD(id: rowID)
        let sealed  = try AES.GCM.seal(bytes, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: aad)
        guard let combined = sealed.combined else { throw CustodyError.encryptionFailed }
        self.modelContext.insert(PendingShardStatusUpdate(id: rowID, encryptedPayload: combined))
        try self.modelContext.save()
    }

    /// Upsert a `PendingShardNotFound` row for `ownerIdentifier`.
    ///
    /// If a row already exists for this owner (Alice probed multiple shards before
    /// Bob's next outbound bundle), merge the attributeIDs so all missing-shard
    /// responses travel together.
    private func queueShardNotFound(attributeID: UUID, for ownerIdentifier: String) throws {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }

        let rows = try self.modelContext.fetch(FetchDescriptor<PendingShardNotFound>())
        for row in rows {
            guard
                let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                let plaintext = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
                let existing  = try? JSONDecoder().decode(PendingShardNotFound.Payload.self, from: plaintext),
                existing.ownerContactIdentifier == ownerIdentifier
            else { continue }
            // Merge: union of existing + new attributeID.
            let merged  = Array(Set(existing.attributeIDs).union([attributeID]))
            let updated = PendingShardNotFound.Payload(ownerContactIdentifier: ownerIdentifier, attributeIDs: merged)
            let bytes   = try JSONEncoder().encode(updated)
            let sealed  = try AES.GCM.seal(bytes, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: row.aad())
            guard let combined = sealed.combined else { return }
            row.encryptedPayload = combined
            try self.modelContext.save()
            return
        }

        // No existing row — insert a new one.
        let rowID   = UUID()
        let payload = PendingShardNotFound.Payload(ownerContactIdentifier: ownerIdentifier, attributeIDs: [attributeID])
        let bytes   = try JSONEncoder().encode(payload)
        let aad     = Self.rowAAD(id: rowID)
        let sealed  = try AES.GCM.seal(bytes, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: aad)
        guard let combined = sealed.combined else { throw CustodyError.encryptionFailed }
        self.modelContext.insert(PendingShardNotFound(id: rowID, encryptedPayload: combined))
        try self.modelContext.save()
    }

    /// Build `.notFound` operations for every missing-shard response owed to `ownerIdentifier`.
    ///
    /// Deletes the row on send (fire-and-forget). Returns `nil` when no pending
    /// not-found responses exist for this contact.
    func pendingNotFoundOperations(for ownerIdentifier: String) throws -> [OccultaBundle.ShardOperation]? {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }

        let rows = try self.modelContext.fetch(FetchDescriptor<PendingShardNotFound>())
        for row in rows {
            guard
                let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                let plaintext = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
                let payload   = try? JSONDecoder().decode(PendingShardNotFound.Payload.self, from: plaintext),
                payload.ownerContactIdentifier == ownerIdentifier
            else { continue }

            self.modelContext.delete(row)
            try self.modelContext.save()
            return payload.attributeIDs.map { OccultaBundle.ShardOperation(kind: .notFound, attributeID: $0) }
        }
        return nil
    }

    /// Upsert a `PendingReturnAcknowledge` row for `contactIdentifier`.
    ///
    /// If a row already exists for this contact (Bob resent shards before Alice
    /// acked the first batch), merge the attrIDs so the ack covers all of them.
    private func queueReturnAcknowledge(attrIDs: [UUID], for contactIdentifier: String) throws {
        guard let bufferKey = try self.keyManager.deriveRecoveryBufferKey() else {
            throw CustodyError.keyDerivationFailed
        }

        let rows = try self.modelContext.fetch(FetchDescriptor<PendingReturnAcknowledge>())
        for row in rows {
            guard
                let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                let plaintext = try? AES.GCM.open(box, using: bufferKey, authenticating: row.aad()),
                let existing  = try? JSONDecoder().decode(PendingReturnAcknowledge.Payload.self, from: plaintext),
                existing.contactIdentifier == contactIdentifier
            else { continue }
            // Merge: union of known + new attrIDs.
            let merged  = Array(Set(existing.attrIDs).union(attrIDs))
            let updated = PendingReturnAcknowledge.Payload(contactIdentifier: contactIdentifier, attrIDs: merged)
            let bytes   = try JSONEncoder().encode(updated)
            let sealed  = try AES.GCM.seal(bytes, using: bufferKey, nonce: AES.GCM.Nonce(), authenticating: row.aad())
            guard let combined = sealed.combined else { return }
            row.encryptedPayload = combined
            try self.modelContext.save()
            return
        }

        // No existing row — insert a new one.
        let rowID   = UUID()
        let payload = PendingReturnAcknowledge.Payload(contactIdentifier: contactIdentifier, attrIDs: attrIDs)
        let bytes   = try JSONEncoder().encode(payload)
        let aad     = Self.rowAAD(id: rowID)
        let sealed  = try AES.GCM.seal(bytes, using: bufferKey, nonce: AES.GCM.Nonce(), authenticating: aad)
        guard let combined = sealed.combined else { throw CustodyError.encryptionFailed }
        self.modelContext.insert(PendingReturnAcknowledge(id: rowID, encryptedPayload: combined))
        try self.modelContext.save()
    }

    // MARK: - Auto-return trigger

    /// Called when `ContactManager` emits `contactKeyRotated` for a contact we
    /// hold shards for. Upserts one `PendingShardReturn` row for that contact.
    ///
    /// Upsert: if a row already exists for this `contactIdentifier` (Alice
    /// re-exchanged again before delivery), only `scheduledAt` is updated so the
    /// retry sees the freshest exchange time.
    func scheduleReturnIfShardsCustodied(for contactIdentifier: String) {
        do {
            let shards = try self.decryptAllCustodyShards()
            guard shards.contains(where: { $0.payload.ownerContactIdentifier == contactIdentifier }) else {
                return // We hold no shards for this contact — nothing to return.
            }

            guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
                throw CustodyError.keyDerivationFailed
            }

            // Fetch existing row to implement upsert semantics.
            let existing = try self.modelContext.fetch(FetchDescriptor<PendingShardReturn>())
            for row in existing {
                guard
                    let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                    let plaintext = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
                    let payload   = try? JSONDecoder().decode(PendingShardReturn.Payload.self, from: plaintext),
                    payload.contactIdentifier == contactIdentifier
                else { continue }
                // Update the existing row: re-seal with a fresh scheduledAt.
                let updated  = PendingShardReturn.Payload(contactIdentifier: contactIdentifier, scheduledAt: Date.now)
                let bytes    = try JSONEncoder().encode(updated)
                let sealed   = try AES.GCM.seal(bytes, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: row.aad())
                guard let combined = sealed.combined else { return }
                row.encryptedPayload = combined
                try self.modelContext.save()
                return
            }

            // No existing row — insert a new one.
            let rowID   = UUID()
            let payload = PendingShardReturn.Payload(contactIdentifier: contactIdentifier, scheduledAt: Date.now)
            let bytes   = try JSONEncoder().encode(payload)
            let aad     = Self.rowAAD(id: rowID)
            let sealed  = try AES.GCM.seal(bytes, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: aad)
            guard let combined = sealed.combined else { throw CustodyError.encryptionFailed }
            self.modelContext.insert(PendingShardReturn(id: rowID, encryptedPayload: combined))
            try self.modelContext.save()
        } catch {
            #if DEBUG
            debugPrint("ShardCustodyManager.scheduleReturnIfShardsCustodied failed: \(error)")
            #endif
        }
    }

    // MARK: - Private helpers

    enum CustodyError: Error {
        case invalidPayload
        case signatureRejected
        case keyDerivationFailed
        case encryptionFailed
    }

    private struct DecodedCustodyShard {
        let row:     CustodyShard
        let payload: CustodyShard.Payload
    }

    /// Decrypt every CustodyShard row using the shard custody key. Rows that fail
    /// to decrypt are silently dropped — corrupt or from an unreachable key.
    private func decryptAllCustodyShards() throws -> [DecodedCustodyShard] {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }

        let rows = try self.modelContext.fetch(FetchDescriptor<CustodyShard>())
        var out  = [DecodedCustodyShard]()
        out.reserveCapacity(rows.count)

        for row in rows {
            guard
                let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                let plaintext = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
                let payload   = try? JSONDecoder().decode(CustodyShard.Payload.self, from: plaintext)
            else { continue }
            out.append(DecodedCustodyShard(row: row, payload: payload))
        }
        return out
    }

    private static func fingerprint(of publicKey: Data) -> Data {
        Data(SHA256.hash(data: publicKey))
    }

    /// Mirrors `CustodyShard.aad()` — computed before the @Model is constructed.
    private static func rowAAD(id: UUID) -> Data {
        id.uuidString.data(using: .utf8)!
    }
}

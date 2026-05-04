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
//  read before every outbound bundle: `buildShardOperations`
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

        // Queue one PendingReturnAcknowledge per returned shard.
        for attrID in respondedAttrIDs {
            do { try self.queueReturnAcknowledge(attributeID: attrID, for: senderIdentifier) }
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

        // Deduplicate: if we already hold a shard with this attributeID (e.g.,
        // Alice shared the same .occ bundle twice), skip the insert but still
        // queue the acknowledge so Alice's ShardRecord advances to .confirmed.
        let alreadyStored = (try? self.decryptAllCustodyShards()
            .contains { $0.payload.signedAttribute.id == attribute.id }) ?? false
        if alreadyStored {
            try? self.queueShardAcknowledge(attributeID: attribute.id, for: senderIdentifier)
            return
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
        try? self.queueShardAcknowledge(attributeID: attribute.id, for: senderIdentifier)
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
        try? self.queueShardAcknowledge(attributeID: attribute.id, for: senderIdentifier)
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
            .contains { decoded in
                let attr = decoded.payload.signedAttribute
                guard attr.id == attributeID else { return false }
                if let exp = attr.expiresAt { return exp > Date() }
                return true
            }

        if found {
            try? self.queueShardAcknowledge(attributeID: attributeID, for: senderIdentifier)
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
            try vaultManager.updateShardStatus(attributeID: attributeID, to: .confirmed)
        } catch VaultManager.VaultError.locked {
            try self.queueShardStatusUpdate(attributeID: attributeID, newStatus: .confirmed)
        } catch {
            // Entry not found or other unrecoverable error — silently drop.
        }
        
        try? self.deletePendingDistribute(attributeID: attributeID)
    }

    /// `.notFound` — trustee no longer has our shard; mark it `.lost`.
    ///
    /// Same deferred-update pattern as `handleAcknowledge`.
    private func handleNotFound(op: OccultaBundle.ShardOperation, vaultManager: VaultManager) throws {
        guard let attributeID = op.attributeID else { throw CustodyError.invalidPayload }
        
        do {
            try vaultManager.updateShardStatus(attributeID: attributeID, to: .lost)
        } catch VaultManager.VaultError.locked {
            try self.queueShardStatusUpdate(attributeID: attributeID, newStatus: .lost)
        } catch {
            // Entry not found or other unrecoverable error — silently drop.
        }
        
        try? self.deletePendingDistribute(attributeID: attributeID)
    }
    
    /// Delete the `PendingShardDistribute` row whose payload references `attributeID`.
    /// Best-effort: a missing row is a no-op (the trustee may be acking a row that
    /// was already drained or never queued under this device).
    private func deletePendingDistribute(attributeID: UUID) throws {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }
        let rows = try self.modelContext.fetch(FetchDescriptor<PendingShardDistribute>())
        var deletedAny = false
        for row in rows {
            guard
                let payload = try? self.openRow(row.encryptedPayload, as: PendingShardDistribute.Payload.self, using: custodyKey, id: row.id),
                payload.signedAttribute.id == attributeID
            else { continue }
            
            self.modelContext.delete(row)
            
            deletedAny = true
        }
        
        if deletedAny { try self.modelContext.save() }
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
                let payload = try? self.openRow(row.encryptedPayload, as: PendingShardReturn.Payload.self, using: custodyKey, id: row.id),
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
            if let payload = try? self.openRow(row.encryptedPayload, as: GlobalShardConfig.Payload.self, using: custodyKey, id: row.id) {
                return payload
            }
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
        return try? self.openRow(row.encryptedPayload, as: GlobalShardConfig.Payload.self, using: custodyKey, id: row.id)
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
        let rowID = UUID()
        let combined = try sealRow(payload, using: custodyKey, id: rowID)
        self.modelContext.insert(GlobalShardConfig(id: rowID, encryptedPayload: combined))
        try self.modelContext.save()
    }
    
    // MARK: Build shard operations
    
    func buildShardOperations(for contactID: String) throws -> [OccultaBundle.ShardOperation] {
        let revokeOperations = try self.pendingRevokeOperations(for: contactID) ?? []
        let returnOperations = try self.pendingReturnOperations(for: contactID) ?? []
        let acknowledgeOperations = try self.pendingAcknowledgeOperation(for: contactID) ?? []
        let shardAcknowledgeOperations = try self.pendingShardAcknowledgeOperations(for: contactID) ?? []
        let distributionOperations = try self.pendingDistributeOperations(for: contactID) ?? []
        let notFoundOperations = try self.pendingNotFoundOperations(for: contactID) ?? []
        
        let combines = revokeOperations + returnOperations + acknowledgeOperations + shardAcknowledgeOperations + distributionOperations + notFoundOperations
        
        return combines
    }

    private func pendingRevokeOperations(for contactIdentifier: String) throws -> [OccultaBundle.ShardOperation]? {
        guard
            let custodyKey = try self.keyManager.deriveShardCustodyKey()
        else {
            throw CustodyError.keyDerivationFailed
        }
        let rows = try self.modelContext.fetch(FetchDescriptor<PendingShardRevoke>())
        
        var ops  = [OccultaBundle.ShardOperation]()
        for row in rows {
            guard
                let payload = try? self.openRow(row.encryptedPayload, as: PendingShardRevoke.Payload.self, using: custodyKey, id: row.id),
                payload.ownerID == contactIdentifier
            else {
                continue
            }
            
            ops.append(OccultaBundle.ShardOperation(kind: .revoke, attributeID: payload.attributeID))
        }
        
        guard !ops.isEmpty else { return nil }
        
        return ops
    }

    // MARK: - Auto-return delivery

    /// Build `.handback` shard operations for every `CustodyShard` we hold for
    /// `contactIdentifier`, provided a `PendingShardReturn` row exists for them.
    ///
    /// Returns ALL shards for the contact in one call — the bundle piggybacking
    /// these ops must carry the full set, not a subset. Returns `nil` when no
    /// `PendingShardReturn` exists or no matching shards can be decrypted.
    private func pendingReturnOperations(for contactIdentifier: String) throws -> [OccultaBundle.ShardOperation]? {
        guard
            let custodyKey = try self.keyManager.deriveShardCustodyKey()
        else {
            throw CustodyError.keyDerivationFailed
        }

        // Check for a pending return row for this contact.
        let pendingRows = try self.modelContext.fetch(FetchDescriptor<PendingShardReturn>())
        
        let hasPending = pendingRows.contains {
            (try? self.openRow($0.encryptedPayload, as: PendingShardReturn.Payload.self, using: custodyKey, id: $0.id))?.contactIdentifier == contactIdentifier
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

    /// Build `.returnAcknowledged` operations for Bob if Alice has pending
    /// `PendingReturnAcknowledge` rows for him (one per attributeID)
    ///
    /// Returns `nil` when no pending acks exist for this contact.
    private func pendingAcknowledgeOperation(for contactIdentifier: String) throws -> [OccultaBundle.ShardOperation]? {
        guard
            let bufferKey = try self.keyManager.deriveRecoveryBufferKey()
        else {
            throw CustodyError.keyDerivationFailed
        }
        let rows = try self.modelContext.fetch(FetchDescriptor<PendingReturnAcknowledge>())
        
        var ops  = [OccultaBundle.ShardOperation]()
        for row in rows {
            guard
                let payload = try? self.openRow(row.encryptedPayload, as: PendingReturnAcknowledge.Payload.self, using: bufferKey, id: row.id),
                payload.ownerID == contactIdentifier
            else {
                continue
            }
            
            ops.append(OccultaBundle.ShardOperation(kind: .returnAcknowledged, attributeID: payload.attributeID))
            
            self.modelContext.delete(row)
        }
        
        guard !ops.isEmpty else { return nil }
        
        try self.modelContext.save()
        
        return ops
    }

    // MARK: - Shard-receipt acknowledgement (trustee → owner)

    /// Build `.acknowledge` operations for every shard Bob owes to `ownerIdentifier`.
    ///
    /// Collects all matching rows (one per attributeID), deletes them, and emits
    /// one `ShardOperation` per attributeID (fire-and-forget). If the bundle is
    /// never delivered, Alice's ShardRecord remains `.pending`; the next outbound
    /// message retries automatically because the rows were already deleted on this call.
    ///
    /// Returns `nil` when no pending acks exist for this contact.
    private func pendingShardAcknowledgeOperations(for ownerIdentifier: String) throws -> [OccultaBundle.ShardOperation]? {
        guard
            let custodyKey = try self.keyManager.deriveShardCustodyKey()
        else {
            throw CustodyError.keyDerivationFailed
        }
        let rows = try self.modelContext.fetch(FetchDescriptor<PendingShardAcknowledge>())
        
        var ops  = [OccultaBundle.ShardOperation]()
        for row in rows {
            guard
                let payload = try? self.openRow(row.encryptedPayload, as: PendingShardAcknowledge.Payload.self, using: custodyKey, id: row.id),
                payload.ownerID == ownerIdentifier
            else {
                continue
            }
            ops.append(OccultaBundle.ShardOperation(kind: .acknowledge, attributeID: payload.attributeID))
            
            self.modelContext.delete(row)
        }
        
        guard !ops.isEmpty else { return nil }
        
        try self.modelContext.save()
        
        return ops
    }
    
    /// Build `.distribute` / `.replace` operations for shards owed to `contactIdentifier`.
    private func pendingDistributeOperations(for contactIdentifier: String) throws -> [OccultaBundle.ShardOperation]? {
        guard
            let custodyKey = try self.keyManager.deriveShardCustodyKey()
        else {
            throw CustodyError.keyDerivationFailed
        }
        let rows = try self.modelContext.fetch(FetchDescriptor<PendingShardDistribute>())
        
        var ops  = [OccultaBundle.ShardOperation]()
        for row in rows {
            guard
                let payload = try? self.openRow(row.encryptedPayload, as: PendingShardDistribute.Payload.self, using: custodyKey, id: row.id),
                payload.contactIdentifier == contactIdentifier
            else {
                continue
            }
            
            ops.append(OccultaBundle.ShardOperation(
                kind:        payload.oldAttributeID != nil ? .replace : .distribute,
                attribute:   payload.signedAttribute,
                attributeID: payload.oldAttributeID
            ))
        }
        
        guard !ops.isEmpty else { return nil }
        
        return ops
    }
    
    /// Build `.notFound` operations for every missing-shard response owed to `ownerIdentifier`.
    ///
    /// Collects all matching rows (one per attributeID), deletes them, and emits
    /// one `ShardOperation` per attributeID (fire-and-forget). Returns `nil` when no
    /// pending not-found responses exist for this contact.
    private func pendingNotFoundOperations(for ownerIdentifier: String) throws -> [OccultaBundle.ShardOperation]? {
        guard
            let custodyKey = try self.keyManager.deriveShardCustodyKey()
        else {
            throw CustodyError.keyDerivationFailed
        }
        let rows = try self.modelContext.fetch(FetchDescriptor<PendingShardNotFound>())
        
        var ops  = [OccultaBundle.ShardOperation]()
        for row in rows {
            guard
                let payload = try? self.openRow(row.encryptedPayload, as: PendingShardNotFound.Payload.self, using: custodyKey, id: row.id),
                payload.ownerID == ownerIdentifier
            else {
                continue
            }
            
            ops.append(OccultaBundle.ShardOperation(kind: .notFound, attributeID: payload.attributeID))
            
            self.modelContext.delete(row)
        }
        
        guard !ops.isEmpty else { return nil }
        
        try self.modelContext.save()
        
        return ops
    }
    
    // MARK: - Revocation queuing

    /// Queue `.revoke` operations for every active shard in `metadata`.
    ///
    /// Called immediately after `VaultManager.deleteEntry` returns the metadata,
    /// and from `VaultShardSetup.markForDistribution` for trustees being removed
    /// before a re-distribution.
    ///
    /// Inserts one `PendingShardRevoke` row per shard. Skips attributeIDs that
    /// already have a pending row (duplicate check), and skips shards already in
    /// a terminal or in-flight revocation state: `.revoked`, `.revokePending`,
    /// `.lost`.
    func queueRevokes(from metadata: ShardDistributionMetadata, vaultManager: VaultManager?) {
        do {
            guard
                let custodyKey = try self.keyManager.deriveShardCustodyKey()
            else {
                return
            }
            let pending = try self.modelContext.fetch(FetchDescriptor<PendingShardRevoke>())

            for shard in metadata.shards
                where shard.status != .revoked
                   && shard.status != .revokePending
                   && shard.status != .lost {
                       let alreadyQueued = pending.contains {
                            (try? self.openRow($0.encryptedPayload, as: PendingShardRevoke.Payload.self, using: custodyKey, id: $0.id))?.attributeID == shard.attributeID
                       }
                               
                       guard !alreadyQueued else { continue }
                               
                       let rowID = UUID()
                       let combined = try self.sealRow(PendingShardRevoke.Payload(ownerID: shard.contactIdentifier, attributeID: shard.attributeID), using: custodyKey, id: rowID)
                               
                       self.modelContext.insert(PendingShardRevoke(id: rowID, encryptedPayload: combined))
                
                       try vaultManager?.updateShardStatus(attributeID: shard.attributeID, to: .revokePending)
            }
            
            try self.modelContext.save()
        } catch {
            #if DEBUG
            debugPrint("ShardCustodyManager.queueRevokes failed: \(error)")
            #endif
        }
    }

    /// Queue a single-shard `.revoke` for `ownerID`.
    ///
    /// Inserts one `PendingShardRevoke` row for this `attributeID`. Skips if a
    /// row already exists (idempotent).
    func queueRevoke(attributeID: UUID, for ownerID: String, vaultManager: VaultManager?) throws {
        guard
            let custodyKey = try self.keyManager.deriveShardCustodyKey()
        else {
            throw CustodyError.keyDerivationFailed
        }
        
        let pending = try self.modelContext.fetch(FetchDescriptor<PendingShardRevoke>())
        let alreadyQueued = pending.contains {
            (try? self.openRow($0.encryptedPayload, as: PendingShardRevoke.Payload.self, using: custodyKey, id: $0.id))?.attributeID == attributeID
        }
        guard !alreadyQueued else { return }
        
        let rowID = UUID()
        let combined = try self.sealRow(PendingShardRevoke.Payload(ownerID: ownerID, attributeID: attributeID), using: custodyKey, id: rowID)
        
        self.modelContext.insert(PendingShardRevoke(id: rowID, encryptedPayload: combined))
        try self.modelContext.save()
        
        try vaultManager?.updateShardStatus(attributeID: attributeID, to: .revokePending)
    }

    // MARK: - Shard distribute queuing (owner → trustee)

    /// Queue a `.distribute` or `.replace` op for `contactIdentifier`.
    ///
    /// Called from `markForDistribution` after `prepareShards`. One row per
    /// `attributeID`; skips if a row already exists (idempotent).
    /// `replacing` non-nil → `.replace` op; nil → `.distribute`.
    func queueDistribute(attribute: SignedAttribute, for contactIdentifier: String, replacing oldAttributeID: UUID? = nil) throws {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }
        
        let existing = try self.modelContext.fetch(FetchDescriptor<PendingShardDistribute>())
        let alreadyQueued = existing.contains {
            (try? self.openRow($0.encryptedPayload, as: PendingShardDistribute.Payload.self, using: custodyKey, id: $0.id))?.signedAttribute.id == attribute.id
        }
        
        guard !alreadyQueued else { return }
        
        let rowID    = UUID()
        let combined = try self.sealRow(PendingShardDistribute.Payload(contactIdentifier: contactIdentifier, signedAttribute: attribute, oldAttributeID: oldAttributeID), using: custodyKey, id: rowID)
        
        self.modelContext.insert(PendingShardDistribute(id: rowID, encryptedPayload: combined))
        try self.modelContext.save()
    }

    /// Insert a `PendingShardAcknowledge` row for `ownerIdentifier`.
    ///
    /// One row per `attributeID`. Skips if a row already exists (idempotent).
    private func queueShardAcknowledge(attributeID: UUID, for ownerIdentifier: String) throws {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }
        let rows = try self.modelContext.fetch(FetchDescriptor<PendingShardAcknowledge>())
        let alreadyQueued = rows.contains {
            (try? self.openRow($0.encryptedPayload, as: PendingShardAcknowledge.Payload.self, using: custodyKey, id: $0.id))?.attributeID == attributeID
        }
        guard !alreadyQueued else { return }
        let rowID    = UUID()
        let combined = try sealRow(PendingShardAcknowledge.Payload(ownerID: ownerIdentifier, attributeID: attributeID), using: custodyKey, id: rowID)
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
        let rowID    = UUID()
        let combined = try self.sealRow(PendingShardStatusUpdate.Payload(attributeID: attributeID, newStatus: newStatus), using: custodyKey, id: rowID)
        
        self.modelContext.insert(PendingShardStatusUpdate(id: rowID, encryptedPayload: combined))
        
        try self.modelContext.save()
    }

    /// Insert a `PendingShardNotFound` row for `ownerIdentifier`.
    ///
    /// One row per `attributeID`. Skips if a row already exists (idempotent).
    private func queueShardNotFound(attributeID: UUID, for ownerIdentifier: String) throws {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }
        let rows = try self.modelContext.fetch(FetchDescriptor<PendingShardNotFound>())
        let alreadyQueued = rows.contains {
            (try? self.openRow($0.encryptedPayload, as: PendingShardNotFound.Payload.self, using: custodyKey, id: $0.id))?.attributeID == attributeID
        }
        guard !alreadyQueued else { return }
        let rowID    = UUID()
        let combined = try sealRow(PendingShardNotFound.Payload(ownerID: ownerIdentifier, attributeID: attributeID), using: custodyKey, id: rowID)
        self.modelContext.insert(PendingShardNotFound(id: rowID, encryptedPayload: combined))
        try self.modelContext.save()
    }

    /// Insert a `PendingReturnAcknowledge` row for `contactIdentifier`.
    ///
    /// One row per `attributeID`. Skips if a row already exists (idempotent).
    private func queueReturnAcknowledge(attributeID: UUID, for contactIdentifier: String) throws {
        guard let bufferKey = try self.keyManager.deriveRecoveryBufferKey() else {
            throw CustodyError.keyDerivationFailed
        }
        let rows = try self.modelContext.fetch(FetchDescriptor<PendingReturnAcknowledge>())
        let alreadyQueued = rows.contains {
            (try? self.openRow($0.encryptedPayload, as: PendingReturnAcknowledge.Payload.self, using: bufferKey, id: $0.id))?.attributeID == attributeID
        }
        guard !alreadyQueued else { return }
        let rowID    = UUID()
        let combined = try sealRow(PendingReturnAcknowledge.Payload(ownerID: contactIdentifier, attributeID: attributeID), using: bufferKey, id: rowID)
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
                    let payload = try? self.openRow(row.encryptedPayload, as: PendingShardReturn.Payload.self, using: custodyKey, id: row.id),
                    payload.contactIdentifier == contactIdentifier
                else {
                    continue
                }
                // Update the existing row: re-seal with a fresh scheduledAt.
                row.encryptedPayload = try sealRow(PendingShardReturn.Payload(contactIdentifier: contactIdentifier, scheduledAt: .now), using: custodyKey, id: row.id)
                
                try self.modelContext.save()
                
                return
            }

            // No existing row — insert a new one.
            let rowID = UUID()
            let combined = try sealRow(PendingShardReturn.Payload(contactIdentifier: contactIdentifier, scheduledAt: .now), using: custodyKey, id: rowID)
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

    private func sealRow<T: Codable>(_ payload: T, using key: SymmetricKey, id: UUID) throws -> Data {
        let bytes  = try JSONEncoder().encode(payload)
        let sealed = try AES.GCM.seal(bytes, using: key, nonce: AES.GCM.Nonce(), authenticating: Self.rowAAD(id: id))
        guard let combined = sealed.combined else { throw CustodyError.encryptionFailed }
        return combined
    }

    private func openRow<T: Codable>(_ data: Data, as type: T.Type, using key: SymmetricKey, id: UUID) throws -> T {
        let box       = try AES.GCM.SealedBox(combined: data)
        let plaintext = try AES.GCM.open(box, using: key, authenticating: Self.rowAAD(id: id))
        return try JSONDecoder().decode(type, from: plaintext)
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
            guard let payload = try? self.openRow(row.encryptedPayload, as: CustodyShard.Payload.self, using: custodyKey, id: row.id)
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

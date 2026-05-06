//
//  ShardCustody+Manager.swift
//  Occulta
//
//  Inbound router for ShardOperation traffic + manifest reconciliation.
//
//  Two roles, one router:
//    - Trustee path: accept .distribute / .replace from the owner; store as encrypted
//      CustodyShard rows; return mismatch-fingerprint shards as .handback on every
//      outbound bundle; delete same-fingerprint shards absent from owner's expectedShards.
//    - Owner path: receive .handback from trustees; include custodyManifest (IDs held)
//      in every outbound bundle; include expectedShards (IDs expected) in every
//      outbound bundle to trigger implicit revoke.
//
//  Manifest reconciliation replaces the old Pending{Revoke,Acknowledge,Return,
//  ReturnAcknowledge,NotFound} models. State is a complete snapshot re-sent on every
//  bundle — missed updates are healed by the next exchange, not by queuing.
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

    /// Route decoded SealedPayload fields to per-role handlers.
    ///
    /// Returns `true` when any shard-protocol field was present — caller must not
    /// render the bundle as a regular message basket.
    @discardableResult
    func handleInbound(
        sealed:           OccultaBundle.SealedPayload,
        senderPublicKey:  Data,
        senderIdentifier: String,
        vaultManager:     VaultManager
    ) -> Bool {
        let hasOps      = (sealed.shardOperations?.isEmpty == false)
        let hasManifest = sealed.custodyManifest != nil
        let hasExpected = sealed.expectedShards  != nil
        
        guard hasOps || hasManifest || hasExpected else { return false }

        for op in sealed.shardOperations ?? [] {
            do {
                switch op.kind {
                case .distribute:
                    try self.handleDistribute(op: op, senderPublicKey: senderPublicKey, senderIdentifier: senderIdentifier)
                case .replace:
                    try self.handleReplace(op: op, senderPublicKey: senderPublicKey, senderIdentifier: senderIdentifier)
                case .handback:
                    try self.handleHandback(op: op, vaultManager: vaultManager)
                case .unsupported:
                    break
                }
            } catch {
                #if DEBUG
                debugPrint("ShardCustodyManager dispatch failed for \(op.kind): \(error)")
                #endif
            }
        }

        if let manifest = sealed.custodyManifest {
            do { try self.processInboundManifest(manifest, from: senderIdentifier, vaultManager: vaultManager) }
            catch {
                #if DEBUG
                debugPrint("ShardCustodyManager processInboundManifest failed: \(error)")
                #endif
            }
        }
        if let expected = sealed.expectedShards {
            do { try self.processExpectedShards(expected, from: senderIdentifier, senderPublicKey: senderPublicKey) }
            catch {
                #if DEBUG
                debugPrint("ShardCustodyManager processExpectedShards failed: \(error)")
                #endif
            }
        }

        return true
    }

    // MARK: - Trustee path: inbound

    /// `.distribute` — owner sent a shard to hold (first distribution).
    ///
    /// Verifies the ECDSA signature, deduplicates, stores the shard, then deletes
    /// any mismatch-fingerprint shards for this contact (Case 8 cleanup).
    private func handleDistribute(op: OccultaBundle.ShardOperation, senderPublicKey: Data, senderIdentifier: String) throws {
        guard let attribute = op.attribute, attribute.category == .shard else {
            throw CustodyError.invalidPayload
        }
        guard attribute.verify(against: senderPublicKey) else {
            throw CustodyError.signatureRejected
        }

        let alreadyStored = (try? self.decryptAllCustodyShards()
            .contains { $0.payload.signedAttribute.id == attribute.id }) ?? false
        guard !alreadyStored else { return }

        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }

        let rowID   = UUID()
        let newFP   = Self.fingerprint(of: senderPublicKey)
        let payload = CustodyShard.Payload(
            ownerKeyFingerprint:    newFP,
            ownerContactIdentifier: senderIdentifier,
            signedAttribute:        attribute
        )
        let combined = try self.sealRow(payload, using: custodyKey, id: rowID)
        self.modelContext.insert(CustodyShard(id: rowID, encryptedPayload: combined))

        try self.deleteMismatchShards(for: senderIdentifier, newFingerprint: newFP)
        try self.modelContext.save()
    }

    /// `.replace` — owner sent a replacement shard; store the new one and delete the old.
    ///
    /// Insert-then-delete ordering ensures the shard is never lost even if the delete fails.
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

        let rowID   = UUID()
        let newFP   = Self.fingerprint(of: senderPublicKey)
        let payload = CustodyShard.Payload(
            ownerKeyFingerprint:    newFP,
            ownerContactIdentifier: senderIdentifier,
            signedAttribute:        attribute
        )
        let combined = try self.sealRow(payload, using: custodyKey, id: rowID)
        self.modelContext.insert(CustodyShard(id: rowID, encryptedPayload: combined))

        let allShards = try self.decryptAllCustodyShards()
        for decoded in allShards where decoded.payload.signedAttribute.id == oldID {
            self.modelContext.delete(decoded.row)
        }
        try self.deleteMismatchShards(for: senderIdentifier, newFingerprint: newFP)
        try self.modelContext.save()
    }

    /// Delete all CustodyShard rows for `contactIdentifier` whose fingerprint ≠ `newFingerprint`.
    private func deleteMismatchShards(for contactIdentifier: String, newFingerprint: Data) throws {
        for decoded in try self.decryptAllCustodyShards()
            where decoded.payload.ownerContactIdentifier == contactIdentifier
               && decoded.payload.ownerKeyFingerprint != newFingerprint {
            self.modelContext.delete(decoded.row)
        }
    }

    // MARK: - Owner path: inbound

    /// `.handback` — trustee returned one of our shards after detecting a fingerprint mismatch.
    private func handleHandback(op: OccultaBundle.ShardOperation, vaultManager: VaultManager) throws {
        guard let attribute = op.attribute, attribute.category == .shard else {
            throw CustodyError.invalidPayload
        }
        try vaultManager.acceptReturnedShard(attribute)
    }

    // MARK: - Manifest reconciliation

    /// Process trustee's `custodyManifest` — the IDs of all shards they currently hold.
    ///
    /// - ID in manifest + active record: mark `.confirmed`, delete distribute row.
    /// - ID not in manifest + no distribute row in flight: mark `.lost`.
    /// - ID not in manifest + distribute row exists: delivery in flight; no change.
    /// - Vault locked: queue `.confirmed` for manifest IDs; skip `.lost` detection
    ///   (manifests are re-sent on next bundle, so lazy detection is safe).
    func processInboundManifest(_ manifest: [UUID], from senderIdentifier: String, vaultManager: VaultManager) throws {
        /// Received shard manifest, shards being help by contact.
        let manifestSet = Set(manifest)

        guard let custodyKey = try? self.keyManager.deriveShardCustodyKey() else { return }
        let distributeRows = (try? self.modelContext.fetch(FetchDescriptor<PendingShardDistribute>())) ?? []

        /// All shard IDs for this particular contact.
        let inFlightIDs: Set<UUID> = Set(distributeRows.compactMap {
            guard let payload = try? self.openRow($0.encryptedPayload, as: PendingShardDistribute.Payload.self, using: custodyKey, id: $0.id),
                  payload.contactIdentifier == senderIdentifier else { return nil }
            return payload.signedAttribute.id
        })
        /// This will always be empty because every time we open a file for decryption, the vault is locked (security feature)
        let trusteeShards = vaultManager.shardRecordsForTrustee(senderIdentifier)
        
        /// Reconcile received manifest with our own.
        
        for inFlightId in inFlightIDs {
            if manifestSet.contains(inFlightId) {
                do {
                    try vaultManager.updateShardStatus(attributeID: inFlightId, to: .confirmed)
                } catch VaultManager.VaultError.locked {
                    try? self.queueShardStatusUpdate(attributeID: inFlightId, newStatus: .confirmed)
                } catch {}
                
                try? self.deletePendingDistribute(attributeID: inFlightId, using: custodyKey, rows: distributeRows)
            } else {
                /// The manifest does not contain this ID
                /// We need to take care of the `.lost` case
            }
        }
    }

    /// Process owner's `expectedShards` — IDs the owner expects this trustee to hold.
    ///
    /// Deletes same-fingerprint shards absent from the list (implicit revoke).
    /// Mismatch-fingerprint shards are immune — only cleared by a new `.distribute`
    /// with the owner's updated fingerprint (Invariant 1 from SHARD_PROTOCOL_CASES.md).
    func processExpectedShards(_ expectedIDs: [UUID], from ownerIdentifier: String, senderPublicKey: Data) throws {
        let expectedSet   = Set(expectedIDs)
        let currentFP     = Self.fingerprint(of: senderPublicKey)
        var deletedAny    = false

        for decoded in try self.decryptAllCustodyShards()
            where decoded.payload.ownerContactIdentifier == ownerIdentifier
               && decoded.payload.ownerKeyFingerprint == currentFP
               && !expectedSet.contains(decoded.payload.signedAttribute.id) {
            self.modelContext.delete(decoded.row)
            deletedAny = true
        }
        if deletedAny { try self.modelContext.save() }
    }

    // MARK: - Outbound: build shard operations

    /// Build the outbound ShardOperation list for `contactIdentifier`.
    ///
    /// Owner side: `.distribute` / `.replace` from PendingShardDistribute rows.
    /// Trustee side: `.handback` for mismatch-fingerprint shards (signals key rotation).
    func buildShardOperations(for contactIdentifier: String, currentContactPublicKey: Data?) throws -> [OccultaBundle.ShardOperation] {
        var ops = [OccultaBundle.ShardOperation]()
        ops += try self.pendingDistributeOps(for: contactIdentifier)
        if let pubKey = currentContactPublicKey {
            ops += try self.mismatchHandbackOps(for: contactIdentifier, currentFP: Self.fingerprint(of: pubKey))
        }
        return ops
    }

    private func pendingDistributeOps(for contactIdentifier: String) throws -> [OccultaBundle.ShardOperation] {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }
        let rows = try self.modelContext.fetch(FetchDescriptor<PendingShardDistribute>())
        return rows.compactMap { row in
            guard let payload = try? self.openRow(row.encryptedPayload, as: PendingShardDistribute.Payload.self, using: custodyKey, id: row.id),
                  payload.contactIdentifier == contactIdentifier else { return nil }
            return OccultaBundle.ShardOperation(
                kind:        payload.oldAttributeID != nil ? .replace : .distribute,
                attribute:   payload.signedAttribute,
                attributeID: payload.oldAttributeID
            )
        }
    }

    /// Returns `.handback` ops for mismatch-fingerprint shards.
    ///
    /// Included on every outbound bundle to the owner until they redistribute with
    /// a new fingerprint, which triggers `deleteMismatchShards` in `handleDistribute`.
    private func mismatchHandbackOps(for contactIdentifier: String, currentFP: Data) throws -> [OccultaBundle.ShardOperation] {
        return try self.decryptAllCustodyShards()
            .filter { $0.payload.ownerContactIdentifier == contactIdentifier && $0.payload.ownerKeyFingerprint != currentFP }
            .map    { OccultaBundle.ShardOperation(kind: .handback, attribute: $0.payload.signedAttribute) }
    }

    // MARK: - Outbound: build manifest fields

    /// IDs of all shards currently held for `ownerIdentifier`. Sent in every outbound bundle.
    func buildCustodyManifest(for ownerIdentifier: String) throws -> [UUID] {
        return try self.decryptAllCustodyShards()
            .filter { $0.payload.ownerContactIdentifier == ownerIdentifier }
            .map    { $0.payload.signedAttribute.id }
    }

    /// IDs the owner expects `trusteeIdentifier` to hold. Sent in every outbound bundle.
    ///
    /// Includes `.pending` and `.confirmed` shards only — `.lost` and `.revoked` are
    /// already terminal and must not be re-sent (they would un-revoke on the trustee).
    func buildExpectedShards(for trusteeIdentifier: String, vaultManager: VaultManager) throws -> [UUID] {
        return vaultManager.shardRecordsForTrustee(trusteeIdentifier)
            .filter { $0.status == .pending || $0.status == .confirmed }
            .map    { $0.attributeID }
    }

    // MARK: - Shard distribute queuing (owner → trustee)

    /// Queue a `.distribute` or `.replace` op for `contactIdentifier`.
    ///
    /// One row per `attributeID`; idempotent. `replacing` non-nil → `.replace` op.
    /// Row is deleted only when the trustee's `custodyManifest` confirms the ID
    /// (not on send), enabling automatic retry on bundle loss.
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
        let combined = try self.sealRow(
            PendingShardDistribute.Payload(contactIdentifier: contactIdentifier, signedAttribute: attribute, oldAttributeID: oldAttributeID),
            using: custodyKey, id: rowID
        )
        self.modelContext.insert(PendingShardDistribute(id: rowID, encryptedPayload: combined))
        try self.modelContext.save()
    }

    // MARK: - Global shard config

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

    func decryptGlobalConfig(_ row: GlobalShardConfig) throws -> GlobalShardConfig.Payload? {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }
        return try? self.openRow(row.encryptedPayload, as: GlobalShardConfig.Payload.self, using: custodyKey, id: row.id)
    }

    func saveGlobalShardConfig(_ payload: GlobalShardConfig.Payload) throws {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }
        let existing = try self.modelContext.fetch(FetchDescriptor<GlobalShardConfig>())
        for row in existing { self.modelContext.delete(row) }
        let rowID    = UUID()
        let combined = try self.sealRow(payload, using: custodyKey, id: rowID)
        self.modelContext.insert(GlobalShardConfig(id: rowID, encryptedPayload: combined))
        try self.modelContext.save()
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

    private func deletePendingDistribute(attributeID: UUID, using custodyKey: SymmetricKey, rows: [PendingShardDistribute]) throws {
        var deletedAny = false
        for row in rows {
            guard let payload = try? self.openRow(row.encryptedPayload, as: PendingShardDistribute.Payload.self, using: custodyKey, id: row.id),
                  payload.signedAttribute.id == attributeID else { continue }
            self.modelContext.delete(row)
            deletedAny = true
        }
        if deletedAny { try self.modelContext.save() }
    }

    private func queueShardStatusUpdate(attributeID: UUID, newStatus: ShardStatus) throws {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }
        let rowID    = UUID()
        let combined = try self.sealRow(PendingShardStatusUpdate.Payload(attributeID: attributeID, newStatus: newStatus), using: custodyKey, id: rowID)
        self.modelContext.insert(PendingShardStatusUpdate(id: rowID, encryptedPayload: combined))
        
        try self.modelContext.save()
    }

    private static func fingerprint(of publicKey: Data) -> Data {
        Data(SHA256.hash(data: publicKey))
    }

    private static func rowAAD(id: UUID) -> Data {
        id.uuidString.data(using: .utf8)!
    }
}

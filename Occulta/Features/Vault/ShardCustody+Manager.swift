//
//  ShardCustody+Manager.swift
//  Occulta
//
//  Inbound router for `ShardOperation` traffic decoded from `.occ` bundles.
//  Mirrors the IdentityChallenge.Coordinator pattern: the OccultaApp peeks at
//  `SealedPayload.shardOperations` and hands the bundle here when non-nil.
//
//  Two roles, one router:
//    - Trustee path: accept `.distribute` shards, store them as encrypted
//      CustodyShard rows; serve `.revoke` from the owner; auto-return shards
//      as `.handback` when the owner's identity key changes.
//    - Owner path: receive `.handback`, `.acknowledge`, `.notFound` from
//      trustees and update local recovery state.
//
//  Outbound `.occ` packing (acks, responses, revokes) is intentionally
//  out of scope for this phase — see VAULT_SSS_GUIDE.md "Implementation status".
//  TODOs mark the wire-up sites for the next phase.
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

        for op in ops {
            do {
                switch op.kind {
                case .distribute:         try self.handleDistribute(op: op, senderPublicKey: senderPublicKey, senderIdentifier: senderIdentifier)
                case .revoke:             try self.handleRevoke(op: op)
                case .handback:
                    try self.handleHandback(op: op, vaultManager: vaultManager)
                    if let attrID = op.attribute?.id { respondedAttrIDs.append(attrID) }
                case .acknowledge:        try self.handleAcknowledge(op: op, vaultManager: vaultManager)
                case .notFound:           try self.handleNotFound(op: op, vaultManager: vaultManager)
                case .returnAcknowledged: try self.handleReturnAcknowledged(op: op, senderIdentifier: senderIdentifier)
                case .unsupported:        break
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

        return true
    }

    // MARK: - Trustee path

    /// `.distribute` — owner sent us a shard to hold.
    ///
    /// 1. Verify the SignedAttribute against the owner's public key.
    /// 2. Seal CustodyShard.Payload under the shard custody key + AAD.
    /// 3. Insert.
    /// 4. If `replacesID` is set, delete the prior CustodyShard whose decrypted
    ///    payload references that SignedAttribute.id.
    /// 5. (TODO Phase 2) Enqueue an outbound `.acknowledge` reply.
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

        let row = CustodyShard(id: rowID, encryptedPayload: combined)
        self.modelContext.insert(row)

        if let replacesID = op.replacesID {
            for decoded in try self.decryptAllCustodyShards()
                where decoded.payload.signedAttribute.id == replacesID {
                self.modelContext.delete(decoded.row)
            }
        }

        try self.modelContext.save()
    }

    /// `.revoke` — owner asks us to discard a shard. Match by SignedAttribute.id.
    private func handleRevoke(op: OccultaBundle.ShardOperation) throws {
        guard let attrID = op.attrID else { throw CustodyError.invalidPayload }

        var deletedAny = false
        for decoded in try self.decryptAllCustodyShards()
            where decoded.payload.signedAttribute.id == attrID {
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

    /// `.acknowledge` — trustee confirmed receipt; mark our distribution record.
    /// Best-effort: requires the vault to be unlocked. While locked, the update
    /// is dropped (cosmetic — delivery succeeded, only the local status lags).
    /// A persisted update queue is a Phase 2 follow-up if the cosmetic gap matters.
    private func handleAcknowledge(op: OccultaBundle.ShardOperation, vaultManager: VaultManager) throws {
        guard let attrID = op.attrID else { throw CustodyError.invalidPayload }
        try? vaultManager.updateShardStatus(attrID: attrID, to: .confirmed)
    }

    /// `.notFound` — trustee no longer has our shard. Mark `.lost`.
    private func handleNotFound(op: OccultaBundle.ShardOperation, vaultManager: VaultManager) throws {
        guard let attrID = op.attrID else { throw CustodyError.invalidPayload }
        try? vaultManager.updateShardStatus(attrID: attrID, to: .lost)
    }

    /// `.returnAcknowledged` — owner confirmed receipt; delete our custody rows and
    /// the PendingShardReturn record for this contact.
    private func handleReturnAcknowledged(op: OccultaBundle.ShardOperation, senderIdentifier: String) throws {
        guard let attrIDs = op.attrIDs, !attrIDs.isEmpty else { return }

        // Delete confirmed CustodyShard rows.
        var deletedAny = false
        let attrIDSet = Set(attrIDs)
        for decoded in try self.decryptAllCustodyShards()
            where attrIDSet.contains(decoded.payload.signedAttribute.id) {
            self.modelContext.delete(decoded.row)
            deletedAny = true
        }

        // If all our shards for this contact are now gone, delete the PendingShardReturn.
        let remainingShards = try self.decryptAllCustodyShards()
            .filter { $0.payload.ownerContactIdentifier == senderIdentifier }
        if remainingShards.isEmpty {
            guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else { return }
            let pendingRows = try self.modelContext.fetch(FetchDescriptor<PendingShardReturn>())
            for row in pendingRows {
                guard
                    let box       = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                    let plaintext = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
                    let payload   = try? JSONDecoder().decode(PendingShardReturn.Payload.self, from: plaintext),
                    payload.contactIdentifier == senderIdentifier
                else { continue }
                self.modelContext.delete(row)
            }
        }

        if deletedAny { try self.modelContext.save() }
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

    /// Build a `.returnAcknowledged` operation for Bob if Alice has a
    /// `PendingReturnAcknowledge` row for him, then delete that row (fire-and-forget;
    /// retry on the next outbound bundle if the ack was never delivered).
    ///
    /// Returns `nil` when no pending ack exists for this contact.
    func pendingAcknowledgeOperation(for contactIdentifier: String) throws -> OccultaBundle.ShardOperation? {
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
            return OccultaBundle.ShardOperation(kind: .returnAcknowledged, attrIDs: payload.attrIDs)
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

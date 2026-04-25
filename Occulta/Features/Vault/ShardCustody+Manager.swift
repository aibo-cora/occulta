//
//  ShardCustody+Manager.swift
//  Occulta
//
//  Inbound router for `ShardOperation` traffic decoded from `.occ` bundles.
//  Mirrors the IdentityChallenge.Coordinator pattern: the OccultaApp peeks at
//  `SealedPayload.shardOperation` and hands the bundle here when non-nil.
//
//  Two roles, one router:
//    - Trustee path: accept `.distribute` shards, store them as encrypted
//      CustodyShard rows; serve `.request` and `.revoke` from the owner.
//    - Owner path: receive `.respond`, `.acknowledge`, `.notFound` from
//      trustees and update local recovery state.
//
//  Outbound `.occ` packing (acks, responses, requests, revokes) is intentionally
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
        guard let op = sealed.shardOperation else { return false }
        do {
            switch op.kind {
            case .distribute:  try self.handleDistribute(op: op, senderPublicKey: senderPublicKey, senderIdentifier: senderIdentifier)
            case .revoke:      try self.handleRevoke(op: op)
            case .request:     try self.handleRequest(op: op, senderIdentifier: senderIdentifier)
            case .respond:     try self.handleRespond(op: op, vaultManager: vaultManager)
            case .acknowledge: try self.handleAcknowledge(op: op, vaultManager: vaultManager)
            case .notFound:    try self.handleNotFound(op: op, vaultManager: vaultManager)
            }
        } catch {
            #if DEBUG
            debugPrint("ShardCustodyManager dispatch failed for \(op.kind): \(error)")
            #endif
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
            ownerKeyFingerprint: Self.fingerprint(of: senderPublicKey),
            signedAttribute:     attribute
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

    /// `.request` — owner asks for a shard back. Persist a PendingShardRequest;
    /// auto-response is Phase 2.
    ///
    /// Deduplication: decrypt all rows to find an existing record for `attrID`.
    /// Re-seals the updated payload on duplicate; inserts a new sealed row otherwise.
    private func handleRequest(op: OccultaBundle.ShardOperation, senderIdentifier: String) throws {
        guard let attrID = op.attrID else { throw CustodyError.invalidPayload }
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }

        let existing = try self.decryptAllPendingRequests().first { $0.payload.attrID == attrID }

        if let existing {
            var updated = existing.payload
            updated.receivedAt                 = Date()
            updated.status                     = .pending
            updated.requesterContactIdentifier = senderIdentifier
            let pt     = try JSONEncoder().encode(updated)
            let sealed = try AES.GCM.seal(pt, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: existing.row.aad())
            guard let combined = sealed.combined else { throw CustodyError.encryptionFailed }
            existing.row.encryptedPayload = combined
        } else {
            let rowID  = UUID()
            let aad    = Self.pendingRequestAAD(id: rowID)
            let now    = Date()
            let payload = PendingShardRequest.Payload(
                attrID:                     attrID,
                requesterContactIdentifier: senderIdentifier,
                receivedAt:                 now,
                status:                     .pending
            )
            let pt     = try JSONEncoder().encode(payload)
            let sealed = try AES.GCM.seal(pt, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: aad)
            guard let combined = sealed.combined else { throw CustodyError.encryptionFailed }
            self.modelContext.insert(PendingShardRequest(id: rowID, encryptedPayload: combined))
        }
        try self.modelContext.save()
    }

    // MARK: - Trustee respond

    /// Prepare a response for a pending shard request from Bob's inbox.
    ///
    /// Returns `(attrID, attribute, requesterIdentifier)` when a matching
    /// `CustodyShard` is found — the caller encrypts the `.respond` bundle via
    /// `ContactManager.encryptShardBundle` and presents the share sheet.
    ///
    /// Returns `(attrID, nil, requesterIdentifier)` when no matching shard exists
    /// — the caller encrypts a `.notFound` bundle instead.
    ///
    /// Also updates `PendingShardRequest.status` to reflect the outcome so the
    /// inbox can show the correct state before the user shares.
    func shardForRequest(id: UUID) throws -> (attrID: UUID, attribute: SignedAttribute?, requesterIdentifier: String)? {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }

        let predicate = #Predicate<PendingShardRequest> { $0.id == id }
        guard let row = try self.modelContext.fetch(FetchDescriptor<PendingShardRequest>(predicate: predicate)).first else {
            return nil
        }

        guard
            let box     = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
            let pt      = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
            var payload = try? JSONDecoder().decode(PendingShardRequest.Payload.self, from: pt)
        else { throw CustodyError.decryptionFailed }

        let match = try self.decryptAllCustodyShards()
            .first { $0.payload.signedAttribute.id == payload.attrID }

        payload.status = match != nil ? .sent : .notFound
        let updated = try JSONEncoder().encode(payload)
        let sealed  = try AES.GCM.seal(updated, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: row.aad())
        guard let combined = sealed.combined else { throw CustodyError.encryptionFailed }
        row.encryptedPayload = combined
        try self.modelContext.save()

        return (payload.attrID, match?.payload.signedAttribute, payload.requesterContactIdentifier)
    }

    // MARK: - Owner path

    /// `.respond` — trustee returned one of our shards.
    private func handleRespond(op: OccultaBundle.ShardOperation, vaultManager: VaultManager) throws {
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

    // MARK: - Private helpers

    enum CustodyError: Error {
        case invalidPayload
        case signatureRejected
        case keyDerivationFailed
        case encryptionFailed
        case decryptionFailed
    }

    private struct DecodedCustodyShard {
        let row:     CustodyShard
        let payload: CustodyShard.Payload
    }

    private struct DecodedPendingRequest {
        let row:     PendingShardRequest
        let payload: PendingShardRequest.Payload
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

    /// Decrypt every PendingShardRequest row. Rows that fail to decrypt are dropped.
    private func decryptAllPendingRequests() throws -> [DecodedPendingRequest] {
        guard let custodyKey = try self.keyManager.deriveShardCustodyKey() else {
            throw CustodyError.keyDerivationFailed
        }
        let rows = try self.modelContext.fetch(FetchDescriptor<PendingShardRequest>())
        return rows.compactMap { row in
            guard
                let box     = try? AES.GCM.SealedBox(combined: row.encryptedPayload),
                let pt      = try? AES.GCM.open(box, using: custodyKey, authenticating: row.aad()),
                let payload = try? JSONDecoder().decode(PendingShardRequest.Payload.self, from: pt)
            else { return nil }
            return DecodedPendingRequest(row: row, payload: payload)
        }
    }

    private static func fingerprint(of publicKey: Data) -> Data {
        Data(SHA256.hash(data: publicKey))
    }

    /// Mirrors `CustodyShard.aad()` — computed before the @Model is constructed.
    private static func rowAAD(id: UUID) -> Data {
        id.uuidString.data(using: .utf8)!
    }

    /// Mirrors `PendingShardRequest.aad()`.
    private static func pendingRequestAAD(id: UUID) -> Data {
        id.uuidString.data(using: .utf8)!
    }
}

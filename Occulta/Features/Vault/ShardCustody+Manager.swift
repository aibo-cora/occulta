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
            case .request:     try self.handleRequest(op: op, senderPublicKey: senderPublicKey, senderIdentifier: senderIdentifier)
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
        let createdAt = Date()
        let aad       = Self.rowAAD(id: rowID, createdAt: createdAt)
        let payload   = CustodyShard.Payload(
            ownerKeyFingerprint: Self.fingerprint(of: senderPublicKey),
            signedAttribute:     attribute
        )
        let plaintext = try JSONEncoder().encode(payload)
        let sealed    = try AES.GCM.seal(plaintext, using: custodyKey, nonce: AES.GCM.Nonce(), authenticating: aad)
        guard let combined = sealed.combined else { throw CustodyError.encryptionFailed }

        let row = CustodyShard(id: rowID, encryptedPayload: combined, createdAt: createdAt)
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
    private func handleRequest(op: OccultaBundle.ShardOperation, senderPublicKey: Data, senderIdentifier: String) throws {
        guard let attrID = op.attrID else { throw CustodyError.invalidPayload }
        let requesterFingerprint = Self.fingerprint(of: senderPublicKey)

        let predicate = #Predicate<PendingShardRequest> { $0.attrID == attrID }
        let existing  = try self.modelContext.fetch(FetchDescriptor<PendingShardRequest>(predicate: predicate)).first

        if let existing {
            existing.receivedAt                 = Date()
            existing.status                     = .pending
            existing.requesterContactIdentifier = senderIdentifier
        } else {
            self.modelContext.insert(PendingShardRequest(
                attrID:                     attrID,
                requesterKeyFingerprint:    requesterFingerprint,
                requesterContactIdentifier: senderIdentifier
            ))
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
        let predicate = #Predicate<PendingShardRequest> { $0.id == id }
        guard let request = try self.modelContext.fetch(FetchDescriptor<PendingShardRequest>(predicate: predicate)).first else {
            return nil
        }

        let match = try self.decryptAllCustodyShards()
            .first { $0.payload.signedAttribute.id == request.attrID }

        request.status = match != nil ? .sent : .notFound
        try self.modelContext.save()

        return (request.attrID, match?.payload.signedAttribute, request.requesterContactIdentifier)
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

    /// Mirrors `CustodyShard.aad()` — kept here so the AAD bytes can be computed
    /// at sealing time before the @Model is constructed.
    private static func rowAAD(id: UUID, createdAt: Date) -> Data {
        var data = Data()
        data.append(id.uuidString.data(using: .utf8)!)
        var ts = UInt64(createdAt.timeIntervalSince1970).bigEndian
        data.append(Data(bytes: &ts, count: 8))
        return data
    }
}

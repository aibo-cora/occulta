//
//  PendingShardRequest+Model.swift
//  Occulta
//
//  SwiftData model for the shard-request queue.
//
//  Design:
//  - Stored plaintext — contains no sensitive material (only a shard ID and
//    the requester's key fingerprint, both of which the requester chose to send).
//  - Written when a .request ShardOperation arrives in an inbound bundle.
//  - Deduplication: if `attrID` already exists, only `receivedAt` is updated
//    and status resets to .pending. This re-surfaces a request Bob previously
//    declined without creating a duplicate record.
//  - Not deleted after completion — retained for audit. Prune periodically
//    (e.g. records older than 90 days in a terminal state) in a future pass.
//

import Foundation
import SwiftData

// MARK: - RequestStatus

/// Lifecycle state of a shard request from a contact.
///
/// Raw strings are stable identifiers — never rename or reorder.
enum RequestStatus: String, Codable {
    /// Request arrived, Bob has not yet acted on it.
    case pending
    /// Bob confirmed he sent the .respond bundle.
    case sent
    /// Bob explicitly chose not to respond.
    case declined
    /// Bob's app could not find a HeldShard matching the requested attrID.
    case notFound
}

// MARK: - PendingShardRequest

@Model
final class PendingShardRequest {

    // MARK: Persisted fields

    /// Deduplication key — one record per attrID.
    var id: UUID = UUID()

    /// Which shard is being requested (SignedAttribute.id).
    var attrID: UUID = UUID()

    /// SHA-256(requester's public key) — identifies who is asking.
    var requesterKeyFingerprint: Data = Data()

    /// Timestamp of the most recent request for this attrID.
    /// Updated on duplicate arrivals so the latest request surfaces again.
    var receivedAt: Date = Date()

    /// Current state of the request. Starts as .pending on arrival.
    var statusRaw: String = RequestStatus.pending.rawValue

    var status: RequestStatus {
        get { RequestStatus(rawValue: statusRaw) ?? .pending }
        set { statusRaw = newValue.rawValue }
    }

    // MARK: Init

    init(attrID: UUID, requesterKeyFingerprint: Data) {
        self.id                      = UUID()
        self.attrID                  = attrID
        self.requesterKeyFingerprint = requesterKeyFingerprint
        self.receivedAt              = Date()
        self.statusRaw               = RequestStatus.pending.rawValue
    }
}

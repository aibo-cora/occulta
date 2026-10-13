//
//  PrekeyRecord.swift
//  Occulta
//

import Foundation

/// The prekey state between us and one contact. Data only: `PrekeyRecordCodec` stores it and
/// `PrekeyBookkeeper` applies the rules (`Docs/Features/Prekey Continuity/DESIGN.md` §8, stage 1).
///
/// Sealed into `Contact.Profile`, never stored in the clear. Its encoded size is fixed by the codec, so
/// nothing here may grow without the bookkeeper's limits accounting for it (Bug 161).
nonisolated
struct PrekeyRecord: Codable, Equatable {

    /// Keys we issued to this contact, oldest first. We hold their private halves.
    var ownBatches: [OwnBatch]

    /// Keys this contact issued to us, oldest first. We seal messages to them with these.
    var inboundBatches: [InboundBatch]

    /// The last-resort key from the contact's latest batch: what we seal to once `inboundBatches` runs out,
    /// never removed by use (prekey continuity §3.1, stage 2). Held apart from the batches so it outlives their
    /// one-time keys, and replaced by the next batch accepted.
    var inboundLastResort: InboundKey? = nil

    /// IDs of inbound batches already accepted, so a repeat is dropped (Bug 158).
    var acceptedBatchIDs: [Data]

    /// `generatedAt` of the newest inbound batch accepted without an ID. Older builds send no ID, so their
    /// batches are still filtered by date.
    var latestInboundGeneratedAt: Date?

    /// Where the legacy keys we issued this contact before stage 1 stand. They retire when the contact first
    /// uses a key from one of our record-held batches, and the sweep deletes them 30 days later (D1).
    ///
    /// Three states rather than a date, so the deletion happens exactly once: a date that stayed set would make
    /// every later sweep delete by tag again, and clearing it would read as "not retired yet" and be set again by
    /// the next message.
    ///
    /// Legacy keys are Enclave keys in the keychain, tagged `prekey.<contactID>.<uuid>`. Their private halves
    /// can't be moved into this record: the keychain never returns an Enclave key's wrapped blob. So they aren't
    /// listed here. A message naming an unknown prekey ID is looked up in the keychain, and deletion goes by the
    /// contact's tag prefix. The only thing that has to be remembered is when they may go, and only this
    /// contact's own switch can say that:
    /// - deleting only by consumption leaves the unused ones, from lost or never-shared messages, forever
    ///   (Bug 156);
    /// - deleting at the switch loses messages sealed to them earlier and still in transit;
    /// - one deadline for everyone breaks contacts who still hold unused legacy keys and message rarely;
    /// - waiting for our first record-held batch to expire is safe but a batch late, and never for a contact
    ///   who stops before a second batch. Legacy tags name the contact in the keychain, so they should go as
    ///   early as is safe (`Docs/Features/Prekey Continuity/DESIGN.md` §8, stage 1, decided 2026-10-09).
    var legacyKeys: LegacyKeys

    static let empty = PrekeyRecord(
        ownBatches: [], inboundBatches: [], acceptedBatchIDs: [], latestInboundGeneratedAt: nil, legacyKeys: .none
    )

    enum LegacyKeys: Codable, Equatable {
        /// No legacy keys: a contact added after stage 1, or theirs have been deleted.
        case none
        /// Legacy keys may exist, and the contact hasn't used a record-held batch yet. Every record converted
        /// from today's format starts here.
        case inUse
        /// The contact switched at this moment; the legacy keys go 30 days later.
        case retired(since: Date)
    }

    /// A batch of keys we generated for this contact.
    struct OwnBatch: Codable, Equatable {
        /// 16 random bytes, sent with the batch while it is pending. `nil` once delivered, since it's needed only on
        /// the wire, and for a pending batch from before batch IDs existed, which must keep travelling without one.
        var id: Data?
        /// Sent as the batch's `generatedAt`, which older builds still filter by.
        var createdAt: Date
        /// When the contact first used a key from a newer batch. The leftover keys are deleted 30 days later (D1).
        var retiredAt: Date?
        /// Still waiting to reach the contact; attached to every message to them until they use a key from it.
        var isPending: Bool
        /// The keys not yet used. Using one removes it.
        var keys: [OwnKey]
        /// This batch's last-resort key, which the contact may seal to more than once once `keys` are used up
        /// (prekey continuity §3.1, stage 2). Never removed by use: it goes with its batch, 30 days after the batch
        /// retires. A batch keeps its entry while it holds one, even with no `keys` left. `nil` for batches made
        /// before stage 2 and those carried over from before stage 1.
        var lastResort: OwnKey? = nil
    }

    struct OwnKey: Codable, Equatable {
        /// The prekey's UUID as 16 bytes; on the wire it is the UUID string.
        var id: Data
        /// The Enclave-wrapped private key (`SecureEnclave.P256.KeyAgreement.PrivateKey.dataRepresentation`).
        /// `nil` only in a pending batch carried over from before stage 1: it still has to be sent, but its
        /// private halves are legacy keychain keys (see `legacyKeys`).
        var blob: Data?
        /// x963 public key, stored only for a key without a blob, a pending batch carried over from before stage 1,
        /// and dropped once that batch is delivered. A key with a blob has its public key derived from it when the
        /// batch is sent (`PrekeyBookkeeper.pendingBatch`).
        var publicKey: Data?
    }

    /// A batch of keys this contact generated for us.
    struct InboundBatch: Codable, Equatable {
        /// 16 bytes, or `nil` when the contact's build sends none.
        var id: Data?
        var keys: [InboundKey]
    }

    struct InboundKey: Codable, Equatable {
        /// As the contact's build wrote it.
        var id: String
        /// x963 public key.
        var publicKey: Data
    }
}

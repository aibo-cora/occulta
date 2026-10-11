//
//  PrekeyBookkeeper.swift
//  Occulta
//

import Foundation
import OccultaCore
import OccultaFormats

/// The rules for a contact's `PrekeyRecord`: which key to seal to, which batches to accept, what a used key
/// means, and when keys may go (`Docs/Features/Prekey Continuity/DESIGN.md` §8, stage 1).
///
/// Pure: it reads and changes the value it's given and touches nothing else. Generating keys and deleting
/// keychain items are `PrekeySecretsManager`'s; loading, storing and saving the record are `ContactManager`'s.
/// What those have to do as a result comes back as a return value.
///
/// It also keeps the record within the limits `PrekeyRecordCodec`'s fixed size is budgeted for, eviction
/// included (decided 2026-10-09). The codec never trims.
nonisolated
struct PrekeyBookkeeper {

    /// Leftover keys of a retired batch, and legacy keychain keys once retired, are kept this long for messages
    /// sealed to them earlier and still in transit (D1).
    static let gracePeriod: TimeInterval = 30 * 24 * 60 * 60

    /// Our own keys the record may hold: pending, current and retired leftovers.
    ///
    /// Only retired keys are ever evicted to stay within it, which works because the keys that aren't retired are
    /// at most two batches: the pending one and the one the contact is using (`install`). A later stage that adds to
    /// those, like stage 2's last-resort key, has to keep that true; `PrekeyBookkeeperEvictionTests` checks it.
    static let maxOwnKeys = 48
    /// Our batch size, and every build's: no build sends more. Holding two such batches from the contact (stage 4)
    /// next to `maxOwnKeys` of ours is what the codec's 16 KB is budgeted for.
    static let maxInboundKeysPerBatch = 15
    /// A UUID string, which every build sends as a prekey ID. The contact chooses it, so it is bounded like the rest.
    static let maxInboundKeyIDBytes = 36
    static let maxAcceptedBatchIDs = 8
    /// A batch ID is chosen by the sender and stored in the record, twice, so its size is fixed.
    static let batchIDBytes = 16

    enum BookkeeperError: Error, Equatable {
        /// An inbound batch with an ID that isn't 16 bytes, too many keys, a key that isn't a 65-byte public
        /// key, or an over-long key ID.
        case malformedBatch
    }

    /// A key just generated in the Enclave, as `install` takes it.
    struct GeneratedKey: Equatable {
        let blob: Data
        let publicKey: Data
    }

    /// The batch to attach to outbound messages, before it becomes wire format.
    struct OutboundBatch: Equatable {
        /// `nil` for a pending batch carried over from before stage 1, which must keep travelling without one.
        let id: Data?
        let generatedAt: Date
        let prekeys: [OccultaBundle.WirePrekey]
    }

    // MARK: - Sending to the contact

    /// The oldest key this contact gave us, removed so it's used once. `nil` when there's none left.
    func takeInboundPrekey(from record: inout PrekeyRecord, contactID: String) -> Prekey? {
        guard let first = record.inboundBatches.first, let key = first.keys.first else { return nil }
        record.inboundBatches[0].keys.removeFirst()
        if record.inboundBatches[0].keys.isEmpty {
            record.inboundBatches.removeFirst()
        }
        return Prekey(id: key.id, contactID: contactID, publicKey: key.publicKey)
    }

    /// The batch we're still waiting to deliver, to attach to every message to this contact.
    func pendingBatch(in record: PrekeyRecord) -> OutboundBatch? {
        guard let batch = record.ownBatches.first(where: \.isPending) else { return nil }
        return OutboundBatch(
            id: batch.id,
            generatedAt: batch.createdAt,
            prekeys: batch.keys.compactMap { key in
                key.publicKey.map { OccultaBundle.WirePrekey(id: Self.uuidString(key.id), publicKey: $0) }
            }
        )
    }

    // MARK: - Receiving from the contact

    /// Accepts a batch this contact sent us, replacing the keys we held from them.
    ///
    /// A batch with an ID is dropped if that ID was accepted before (Bug 158); its date doesn't matter, so a
    /// sender whose clock went back isn't stuck. A batch without one comes from an older build and keeps
    /// today's rule: accepted only if newer than the last one accepted without an ID.
    ///
    /// - Returns: whether the batch was accepted.
    /// - Throws: `malformedBatch` for a batch outside the record's limits, which no build of ours produces.
    func accept(
        id: Data?, generatedAt: Date, prekeys: [OccultaBundle.WirePrekey], into record: inout PrekeyRecord
    ) throws -> Bool {
        let keys = prekeys.map { PrekeyRecord.InboundKey(id: $0.id, publicKey: $0.publicKey) }
        guard id == nil || id?.count == Self.batchIDBytes, Self.fitsLimits(keys) else {
            throw BookkeeperError.malformedBatch
        }

        if let id {
            guard !record.acceptedBatchIDs.contains(id) else { return false }
            record.acceptedBatchIDs.append(id)
            if record.acceptedBatchIDs.count > Self.maxAcceptedBatchIDs {
                record.acceptedBatchIDs.removeFirst(record.acceptedBatchIDs.count - Self.maxAcceptedBatchIDs)
            }
        } else {
            guard generatedAt > (record.latestInboundGeneratedAt ?? .distantPast) else { return false }
            record.latestInboundGeneratedAt = generatedAt
        }

        record.inboundBatches = keys.isEmpty ? [] : [PrekeyRecord.InboundBatch(id: id, keys: keys)]
        return true
    }

    /// Whether one batch of the contact's keys is within the record's limits. `accept` holds every new batch to it;
    /// the launch migration holds keys carried over from before stage 1, which had looser bounds, to it too.
    static func fitsLimits(_ keys: [PrekeyRecord.InboundKey]) -> Bool {
        keys.count <= Self.maxInboundKeysPerBatch
            && keys.allSatisfy { $0.publicKey.count == 65 && $0.id.utf8.count <= Self.maxInboundKeyIDBytes }
    }

    /// The Enclave blob for one of our prekeys, or `nil` when the record doesn't hold it: a legacy key, whose
    /// private half is a keychain item, or no key of ours at all. The caller tries the keychain next.
    func blob(forPrekeyID prekeyID: String, in record: PrekeyRecord) -> Data? {
        guard let id = Self.idBytes(prekeyID) else { return nil }
        for batch in record.ownBatches {
            if let key = batch.keys.first(where: { $0.id == id }) { return key.blob }
        }
        return nil
    }

    /// Records that the contact used one of our prekeys: the key is removed, and what its use proves is applied.
    ///
    /// - A key from the pending batch proves they received it, so it stops being pending and its public keys,
    ///   needed only to send it, are dropped. A key from any other batch leaves the pending batch alone (Bug 157).
    /// - Every older batch retires now: they use keys oldest first, so they're done with those.
    /// - The first use of a record-held key retires the legacy keys we issued them.
    /// - A key the record doesn't hold, a legacy keychain key, changes nothing else.
    func consume(prekeyID: String, in record: inout PrekeyRecord, now: Date) {
        guard let id = Self.idBytes(prekeyID),
              let batchIndex = record.ownBatches.firstIndex(where: { $0.keys.contains { $0.id == id } }),
              let keyIndex = record.ownBatches[batchIndex].keys.firstIndex(where: { $0.id == id })
        else { return }

        let key = record.ownBatches[batchIndex].keys.remove(at: keyIndex)

        if record.ownBatches[batchIndex].isPending {
            record.ownBatches[batchIndex].isPending = false
            for index in record.ownBatches[batchIndex].keys.indices {
                record.ownBatches[batchIndex].keys[index].publicKey = nil
            }
        }

        for index in record.ownBatches.indices where index < batchIndex && record.ownBatches[index].retiredAt == nil {
            record.ownBatches[index].retiredAt = now
        }

        if key.blob != nil, record.legacyKeys == .inUse {
            record.legacyKeys = .retired(since: now)
        }

        record.ownBatches.removeAll { $0.keys.isEmpty && !$0.isPending }
    }

    /// Whether a batch is waiting to reach the contact. Until one has, no new one is generated.
    func hasPendingBatch(_ record: PrekeyRecord) -> Bool {
        record.ownBatches.contains(where: \.isPending)
    }

    /// Adds a batch just generated in the Enclave as the pending one.
    ///
    /// Then holds the record to `maxOwnKeys` by deleting the oldest retired keys first. A retired key can only open a
    /// file the contact sealed before moving to a newer batch and we haven't opened, so evicting one loses that file
    /// early; it is never a key the contact can still seal to.
    ///
    /// Keys that aren't retired are never evicted, even if that leaves the record over `maxOwnKeys`. They are at most
    /// the pending batch and the one before it, 2 × 15, so retired keys alone always make room. Deleting a key the
    /// contact still holds would silently lose every message they seal to it.
    ///
    /// - Precondition: no batch is pending. The caller checks `hasPendingBatch` first.
    func install(_ keys: [GeneratedKey], into record: inout PrekeyRecord, now: Date) {
        assert(!self.hasPendingBatch(record), "a second pending batch would leave the first one undeliverable")
        record.ownBatches.append(PrekeyRecord.OwnBatch(
            id: Self.randomBatchID(),
            createdAt: now,
            retiredAt: nil,
            isPending: true,
            keys: keys.map { PrekeyRecord.OwnKey(id: Self.idBytes(UUID()), blob: $0.blob, publicKey: $0.publicKey) }
        ))

        var excess = record.ownBatches.reduce(0) { $0 + $1.keys.count } - Self.maxOwnKeys
        let retired = record.ownBatches.indices.filter { record.ownBatches[$0].retiredAt != nil }
        for index in retired where excess > 0 {
            let dropped = min(excess, record.ownBatches[index].keys.count)
            record.ownBatches[index].keys.removeFirst(dropped)
            excess -= dropped
        }
        record.ownBatches.removeAll { $0.keys.isEmpty && !$0.isPending }
    }

    // MARK: - Maintenance

    /// Deletes what the grace period no longer protects: retired batches whose 30 days are up.
    ///
    /// - Returns: whether the contact's legacy keychain keys are now due for deletion. The caller deletes them by
    ///   tag prefix; the record already says they're gone, so this returns `true` once per contact.
    func sweep(_ record: inout PrekeyRecord, now: Date) -> Bool {
        record.ownBatches.removeAll { batch in
            guard let retiredAt = batch.retiredAt else { return false }
            return now >= retiredAt.addingTimeInterval(Self.gracePeriod)
        }

        guard case .retired(let since) = record.legacyKeys,
              now >= since.addingTimeInterval(Self.gracePeriod)
        else { return false }
        record.legacyKeys = .none
        return true
    }

    // MARK: - IDs

    /// Our prekey IDs are UUIDs: 16 bytes in the record, the UUID string on the wire.
    private static func idBytes(_ uuid: UUID) -> Data {
        withUnsafeBytes(of: uuid.uuid) { Data($0) }
    }

    private static func idBytes(_ string: String) -> Data? {
        UUID(uuidString: string).map(Self.idBytes)
    }

    private static func uuidString(_ bytes: Data) -> String {
        let b = [UInt8](bytes)
        return UUID(uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                           b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])).uuidString
    }

    private static func randomBatchID() -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<Self.batchIDBytes).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }
}

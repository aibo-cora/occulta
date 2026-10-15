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

    /// Our own keys the record may hold: pending, current and retired leftovers, last-resort keys included.
    ///
    /// Only retired keys are ever evicted to stay within it, which works because the keys that aren't retired are
    /// at most two batches: the pending one and the one the contact is using (`install`), each 15 one-time keys
    /// and a last-resort key. A later stage that adds to those has to keep that true;
    /// `PrekeyBookkeeperEvictionTests` checks it.
    static let maxOwnKeys = 48
    /// Our batch size, and every build's: no build sends more. Holding two such batches from the contact (stage 4)
    /// next to `maxOwnKeys` of ours is what the codec's 16 KB is budgeted for.
    static let maxInboundKeysPerBatch = 15
    /// The contact's batches the record may hold: the one we're using and the next, appended (stage 4, §3.3).
    static let maxInboundBatches = 2
    /// A UUID string, which every build sends as a prekey ID. The contact chooses it, so it is bounded like the rest.
    static let maxInboundKeyIDBytes = 36
    static let maxAcceptedBatchIDs = 8
    /// A new batch is due once the contact holds this many of our one-time keys or fewer (D4: 15/5, §3.3).
    static let refillThreshold = 5
    /// A batch ID is chosen by the sender and stored in the record, twice, so its size is fixed.
    static let batchIDBytes = 16

    enum BookkeeperError: Error, Equatable {
        /// An inbound batch with an ID that isn't 16 bytes, too many keys, a key that isn't a 65-byte public
        /// key, an over-long key ID, or a last-resort key whose ID isn't a UUID.
        case malformedBatch
    }

    /// The batch to attach to outbound messages, before it becomes wire format.
    struct OutboundBatch: Equatable {
        /// `nil` for a pending batch carried over from before stage 1, which must keep travelling without one.
        let id: Data?
        let generatedAt: Date
        let prekeys: [OccultaBundle.WirePrekey]
        /// `nil` for a batch made before stage 2, or one whose last-resort blob won't give a public key.
        let lastResort: OccultaBundle.WirePrekey?
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

    /// The contact's last-resort key, for when `takeInboundPrekey` finds none left. Not removed: it may be sealed
    /// to again until their next batch replaces it (§3.1).
    func lastResortPrekey(in record: PrekeyRecord, contactID: String) -> Prekey? {
        record.inboundLastResort.map { Prekey(id: $0.id, contactID: contactID, publicKey: $0.publicKey) }
    }

    /// The batch we're still waiting to deliver, to attach to every message to this contact.
    ///
    /// The record doesn't store the public keys of keys it holds a blob for; `publicKeyOfBlob` derives them, which
    /// the bookkeeper can't do itself without touching the Enclave. Measured at 0.2–0.3 ms a key, 3–6 ms for a
    /// batch of 16, on the Simulator (`PrekeyGenerationMeasurementTests`, decided 2026-10-11). A key carried over
    /// from before stage 1 has no blob, and its stored public key is used. A key whose blob won't give one is left
    /// out: no message sealed to it could be opened.
    func pendingBatch(in record: PrekeyRecord, publicKeyOfBlob: (Data) -> Data?) -> OutboundBatch? {
        guard let batch = record.ownBatches.first(where: \.isPending) else { return nil }
        let wire = { (key: PrekeyRecord.OwnKey) in
            (key.publicKey ?? key.blob.flatMap(publicKeyOfBlob))
                .map { OccultaBundle.WirePrekey(id: Self.uuidString(key.id), publicKey: $0) }
        }
        return OutboundBatch(
            id: batch.id,
            generatedAt: batch.createdAt,
            prekeys: batch.keys.compactMap(wire),
            lastResort: batch.lastResort.flatMap(wire)
        )
    }

    // MARK: - Receiving from the contact

    /// Accepts a batch this contact sent us, after the keys we already hold from them, so they're still used oldest
    /// first (prekey continuity §3.3, stage 4). Their retirement rule depends on that order: our first use of a key
    /// from the new batch tells them we're done with the older one. At most `maxInboundBatches` are kept; a third
    /// drops the oldest, which shouldn't happen, since they refill only once we've started their newest batch, and by
    /// then we've used up the one before it. Dropping keys we hold loses nothing: they keep the private halves until
    /// those retire, and we just won't seal to them. Their last-resort key becomes the new batch's.
    ///
    /// A batch with an ID is dropped if that ID was accepted before (Bug 158); its date doesn't matter, so a
    /// sender whose clock went back isn't stuck. A batch without one comes from an older build and keeps
    /// today's rule: accepted only if newer than the last one accepted without an ID.
    ///
    /// - Returns: whether the batch was accepted.
    /// - Throws: `malformedBatch` for a batch outside the record's limits, which no build of ours produces.
    func accept(
        id: Data?, generatedAt: Date, prekeys: [OccultaBundle.WirePrekey], lastResort: OccultaBundle.WirePrekey?,
        into record: inout PrekeyRecord
    ) throws -> Bool {
        let keys = prekeys.map { PrekeyRecord.InboundKey(id: $0.id, publicKey: $0.publicKey) }
        let lastResortKey = lastResort.map { PrekeyRecord.InboundKey(id: $0.id, publicKey: $0.publicKey) }
        // A last-resort key's ID keys the prekey IDs derived from it, which need it to be a UUID.
        guard id == nil || id?.count == Self.batchIDBytes, Self.fitsLimits(keys),
              lastResortKey.map({ Self.fitsLimits([$0]) && UUID(uuidString: $0.id) != nil }) ?? true
        else { throw BookkeeperError.malformedBatch }

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

        if !keys.isEmpty {
            record.inboundBatches.append(PrekeyRecord.InboundBatch(id: id, keys: keys))
            if record.inboundBatches.count > Self.maxInboundBatches {
                record.inboundBatches.removeFirst(record.inboundBatches.count - Self.maxInboundBatches)
            }
        }
        record.inboundLastResort = lastResortKey
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

    /// One of our last-resort keys that a bundle's derived `prekeyID` names, with its own ID and blob. Tried
    /// newest batch first; one HMAC per batch and no Enclave work, so cheap even for a large group bundle.
    func lastResort(
        matchingPrekeyID prekeyID: String, ephemeralPublicKey: Data, in record: PrekeyRecord
    ) -> (keyID: String, blob: Data)? {
        for batch in record.ownBatches.reversed() {
            guard let key = batch.lastResort, let blob = key.blob else { continue }
            let keyID = Self.uuidString(key.id)
            if OccultaBundle.SecrecyContext.lastResortPrekeyID(keyID: keyID, ephemeralPublicKey: ephemeralPublicKey)
                == prekeyID {
                return (keyID, blob)
            }
        }
        return nil
    }

    /// Records that the contact used one of our prekeys: the key is removed, and what its use proves is applied.
    ///
    /// - A key from the pending batch proves they received it, so it stops being pending and its ID and public
    ///   keys, needed only to send it, are dropped. Dropping the ID also keeps each retired entry's fixed cost down,
    ///   which the record's size budget counts on. A key from any other batch leaves the pending batch alone (Bug 157).
    /// - Every older batch retires now: they use keys oldest first, so they're done with those.
    /// - The first use of a record-held key retires the legacy keys we issued them.
    /// - A key the record doesn't hold, a legacy keychain key, changes nothing else.
    func consume(prekeyID: String, in record: inout PrekeyRecord, now: Date) {
        guard let id = Self.idBytes(prekeyID),
              let batchIndex = record.ownBatches.firstIndex(where: { $0.keys.contains { $0.id == id } }),
              let keyIndex = record.ownBatches[batchIndex].keys.firstIndex(where: { $0.id == id })
        else { return }

        let key = record.ownBatches[batchIndex].keys.remove(at: keyIndex)
        Self.applyUse(ofBatchAt: batchIndex, recordHeld: key.blob != nil, in: &record, now: now)
        record.ownBatches.removeAll(where: Self.isSpent)
    }

    /// Records that the contact sealed to one of our last-resort keys, which means they had no one-time key of ours
    /// left (§3.1, "Bookkeeping on receipt"). The key stays. What its use proves is applied as for a one-time key:
    /// its batch, if pending, is delivered; older batches retire; the legacy keys retire.
    ///
    /// - Returns: whether to generate a new batch. Only for the newest batch's key, and only with nothing pending
    ///   once that's applied: the pending batch's own key means the contact has it and has used it up; the newest
    ///   delivered batch's key means they've used everything; an older key means either the pending batch hasn't
    ///   reached them yet or this is a repeat delivery, and a repeat must not generate (D5).
    func useLastResort(keyID: String, in record: inout PrekeyRecord, now: Date) -> Bool {
        guard let id = Self.idBytes(keyID),
              let batchIndex = record.ownBatches.firstIndex(where: { $0.lastResort?.id == id })
        else { return false }
        Self.applyUse(ofBatchAt: batchIndex, recordHeld: true, in: &record, now: now)
        return batchIndex == record.ownBatches.indices.last && !self.hasPendingBatch(record)
    }

    /// What using a key from the batch at `batchIndex` proves (`consume`, `useLastResort`).
    private static func applyUse(ofBatchAt batchIndex: Int, recordHeld: Bool, in record: inout PrekeyRecord, now: Date) {
        if record.ownBatches[batchIndex].isPending {
            record.ownBatches[batchIndex].isPending = false
            record.ownBatches[batchIndex].id = nil
            for index in record.ownBatches[batchIndex].keys.indices {
                record.ownBatches[batchIndex].keys[index].publicKey = nil
            }
        }

        for index in record.ownBatches.indices where index < batchIndex && record.ownBatches[index].retiredAt == nil {
            record.ownBatches[index].retiredAt = now
        }

        if recordHeld, record.legacyKeys == .inUse {
            record.legacyKeys = .retired(since: now)
        }
    }

    /// Whether a batch is waiting to reach the contact. Until one has, no new one is generated.
    func hasPendingBatch(_ record: PrekeyRecord) -> Bool {
        record.ownBatches.contains(where: \.isPending)
    }

    /// Whether to generate a batch now, before the contact runs out (prekey continuity §3.3, stage 4): they hold
    /// `refillThreshold` of our one-time keys or fewer, and none is pending. It then rides our next message, so a
    /// two-way conversation never reaches the last-resort key.
    ///
    /// What they hold is counted from our side: the keys left in our delivered batches that haven't retired. A key is
    /// removed as it's used, so a key used for a message that never reached us still counts, and the refill comes later
    /// than it could; the last-resort key covers that. Nothing is generated while a batch is pending, so this makes one
    /// batch at a time whoever triggers it, and keys not yet retired stay within two batches (`install`).
    func needsRefill(_ record: PrekeyRecord) -> Bool {
        guard !self.hasPendingBatch(record) else { return false }
        let held = record.ownBatches
            .filter { !$0.isPending && $0.retiredAt == nil }
            .reduce(0) { $0 + $1.keys.count }
        return held <= Self.refillThreshold
    }

    /// Adds a batch just generated in the Enclave as the pending one.
    ///
    /// Then holds the record to `maxOwnKeys` by deleting the oldest retired keys first. A retired key can only open a
    /// file the contact sealed before moving to a newer batch and we haven't opened, so evicting one loses that file
    /// early; it is never a key the contact can still seal to.
    ///
    /// Keys that aren't retired are never evicted, even if that leaves the record over `maxOwnKeys`. They are at most
    /// the pending batch and the one before it, 2 × (15 + a last-resort key), so retired keys alone always make room.
    /// Within a retired batch the one-time keys go before its last-resort key. Deleting a key the
    /// contact still holds would silently lose every message they seal to it.
    ///
    /// - Precondition: no batch is pending. The caller checks `hasPendingBatch` first.
    func install(_ blobs: [Data], lastResort: Data? = nil, into record: inout PrekeyRecord, now: Date) {
        assert(!self.hasPendingBatch(record), "a second pending batch would leave the first one undeliverable")
        let ownKey = { (blob: Data) in PrekeyRecord.OwnKey(id: Self.idBytes(UUID()), blob: blob, publicKey: nil) }
        record.ownBatches.append(PrekeyRecord.OwnBatch(
            id: Self.randomBatchID(),
            createdAt: now,
            retiredAt: nil,
            isPending: true,
            keys: blobs.map(ownKey),
            lastResort: lastResort.map(ownKey)
        ))

        var excess = record.ownBatches.reduce(0) { $0 + Self.keyCount($1) } - Self.maxOwnKeys
        let retired = record.ownBatches.indices.filter { record.ownBatches[$0].retiredAt != nil }
        for index in retired where excess > 0 {
            let dropped = min(excess, record.ownBatches[index].keys.count)
            record.ownBatches[index].keys.removeFirst(dropped)
            excess -= dropped
            if excess > 0, record.ownBatches[index].lastResort != nil {
                record.ownBatches[index].lastResort = nil
                excess -= 1
            }
        }
        record.ownBatches.removeAll(where: Self.isSpent)
    }

    /// One-time keys and the last-resort key, as `maxOwnKeys` counts them.
    static func keyCount(_ batch: PrekeyRecord.OwnBatch) -> Int {
        batch.keys.count + (batch.lastResort == nil ? 0 : 1)
    }

    /// A batch with nothing left to open and nothing left to send. A last-resort key keeps its batch.
    private static func isSpent(_ batch: PrekeyRecord.OwnBatch) -> Bool {
        batch.keys.isEmpty && batch.lastResort == nil && !batch.isPending
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

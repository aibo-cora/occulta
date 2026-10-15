//
//  PrekeyBookkeeperTests.swift
//  OccultaTests
//
//  The rules for a contact's prekey record (prekey continuity stage 1; Bugs 156, 157, 158). Pure: no Enclave,
//  no SwiftData, so these run on CI.
//

import Testing
import Foundation
@testable import Occulta
@testable import OccultaCore
@testable import OccultaFormats

private func randomBytes(_ count: Int) -> Data {
    Data((0..<count).map { _ in .random(in: .min ... .max) })
}

private func generated(_ count: Int) -> [Data] {
    (0..<count).map { _ in randomBytes(143) }
}

/// Stands in for loading an Enclave key from its blob, which these tests don't do: any value that is a function of
/// the blob shows the right key's public key was used.
private func fakePublicKey(ofBlob blob: Data) -> Data? {
    blob.prefix(65)
}

private extension PrekeyBookkeeper {
    func pendingBatch(in record: PrekeyRecord) -> OutboundBatch? {
        self.pendingBatch(in: record, publicKeyOfBlob: fakePublicKey(ofBlob:))
    }
}

private func wire(_ count: Int) -> [OccultaBundle.WirePrekey] {
    (0..<count).map { _ in OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: randomBytes(65)) }
}

private let day: TimeInterval = 24 * 60 * 60

@Suite("PrekeyBookkeeper — sending to the contact")
struct PrekeyBookkeeperSendingTests {

    let bookkeeper = PrekeyBookkeeper()

    @Test("Inbound keys come out oldest first, once each, with the contact's ID filled in")
    func takeOldestFirst() throws {
        var record = PrekeyRecord.empty
        let keys = wire(3)
        #expect(try self.bookkeeper.accept(id: randomBytes(16), generatedAt: Date(), prekeys: keys, lastResort: nil, into: &record))

        for expected in keys {
            let prekey = try #require(self.bookkeeper.takeInboundPrekey(from: &record, contactID: "contact"))
            #expect(prekey.id == expected.id)
            #expect(prekey.publicKey == expected.publicKey)
            #expect(prekey.contactID == "contact")
        }
        #expect(self.bookkeeper.takeInboundPrekey(from: &record, contactID: "contact") == nil)
        #expect(record.inboundBatches.isEmpty)
    }

    @Test("A newly installed batch is pending and goes out with its ID, date and public keys, derived from its blobs")
    func installedBatchIsPending() throws {
        var record = PrekeyRecord.empty
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let keys = generated(15)

        #expect(!self.bookkeeper.hasPendingBatch(record))
        self.bookkeeper.install(keys, into: &record, now: now)
        #expect(self.bookkeeper.hasPendingBatch(record))

        let batch = try #require(self.bookkeeper.pendingBatch(in: record))
        #expect(batch.id?.count == 16)
        #expect(batch.generatedAt == now)
        #expect(batch.prekeys.map(\.publicKey) == keys.compactMap(fakePublicKey(ofBlob:)))
        #expect(record.ownBatches.last?.keys.allSatisfy { $0.publicKey == nil } == true, "public keys aren't stored")
        #expect(batch.prekeys.allSatisfy { UUID(uuidString: $0.id) != nil })
    }

    /// A blob that won't load can't open anything sealed to its key, so the key isn't handed out.
    @Test("A key whose blob gives no public key is left out of the batch")
    func underivableKeyLeftOut() throws {
        var record = PrekeyRecord.empty
        let keys = generated(3)
        self.bookkeeper.install(keys, into: &record, now: Date())

        let batch = try #require(self.bookkeeper.pendingBatch(in: record) { $0 == keys[1] ? nil : $0.prefix(65) })
        #expect(batch.prekeys.map(\.publicKey) == [keys[0].prefix(65), keys[2].prefix(65)])
    }

    @Test("A pending batch carried over from today's format goes out without an ID")
    func carriedOverBatchHasNoID() throws {
        let legacyPending = OccultaBundle.SealedPayload.PrekeySyncBatch(generatedAt: Date(), prekeys: wire(15))
        var secrecy = ForwardSecrecy()
        secrecy.pendingOutboundBatch = try JSONEncoder().encode(legacyPending)
        let record = try PrekeyRecordCodec().decode(try JSONEncoder().encode(secrecy))

        let batch = try #require(self.bookkeeper.pendingBatch(in: record))
        #expect(batch.id == nil)
        #expect(batch.prekeys == legacyPending.prekeys)
    }
}

@Suite("PrekeyBookkeeper — accepting the contact's batches (Bug 158)")
struct PrekeyBookkeeperAcceptTests {

    let bookkeeper = PrekeyBookkeeper()

    @Test("A batch with a new ID is accepted even if older-dated; a repeated ID is dropped")
    func dedupeByID() throws {
        var record = PrekeyRecord.empty
        let first = randomBytes(16)
        #expect(try self.bookkeeper.accept(id: first, generatedAt: Date(timeIntervalSince1970: 2_000), prekeys: wire(15), lastResort: nil, into: &record))

        let second = wire(15)
        #expect(try self.bookkeeper.accept(id: randomBytes(16), generatedAt: Date(timeIntervalSince1970: 1_000), prekeys: second, lastResort: nil, into: &record),
                "a sender whose clock went back must not be stuck")
        #expect(record.inboundBatches.last?.keys.map(\.id) == second.map(\.id))

        let held = record.inboundBatches
        #expect(try !self.bookkeeper.accept(id: first, generatedAt: Date(timeIntervalSince1970: 3_000), prekeys: wire(15), lastResort: nil, into: &record))
        #expect(record.inboundBatches == held, "a repeat must not bring back used keys")
    }

    @Test("A batch without an ID keeps the date rule")
    func noIDKeepsDateRule() throws {
        var record = PrekeyRecord.empty
        #expect(try self.bookkeeper.accept(id: nil, generatedAt: Date(timeIntervalSince1970: 2_000), prekeys: wire(15), lastResort: nil, into: &record))
        #expect(try !self.bookkeeper.accept(id: nil, generatedAt: Date(timeIntervalSince1970: 2_000), prekeys: wire(15), lastResort: nil, into: &record))
        #expect(try !self.bookkeeper.accept(id: nil, generatedAt: Date(timeIntervalSince1970: 1_000), prekeys: wire(15), lastResort: nil, into: &record))
        #expect(try self.bookkeeper.accept(id: nil, generatedAt: Date(timeIntervalSince1970: 3_000), prekeys: wire(15), lastResort: nil, into: &record))
    }

    @Test("Only the 8 most recent accepted IDs are kept")
    func acceptedIDsAreCapped() throws {
        var record = PrekeyRecord.empty
        let ids = (0..<10).map { _ in randomBytes(16) }
        for id in ids {
            _ = try self.bookkeeper.accept(id: id, generatedAt: Date(), prekeys: wire(1), lastResort: nil, into: &record)
        }
        #expect(record.acceptedBatchIDs == Array(ids.suffix(PrekeyBookkeeper.maxAcceptedBatchIDs)))
    }

    @Test("A batch outside the record's limits is rejected")
    func malformedBatchesRejected() {
        var record = PrekeyRecord.empty
        let tooMany = wire(PrekeyBookkeeper.maxInboundKeysPerBatch + 1)
        let badKey  = [OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: randomBytes(64))]
        let longID  = [OccultaBundle.WirePrekey(
            id: String(repeating: "k", count: PrekeyBookkeeper.maxInboundKeyIDBytes + 1), publicKey: randomBytes(65)
        )]
        for prekeys in [tooMany, badKey, longID] {
            #expect(throws: PrekeyBookkeeper.BookkeeperError.malformedBatch) {
                try self.bookkeeper.accept(id: randomBytes(16), generatedAt: Date(), prekeys: prekeys, lastResort: nil, into: &record)
            }
        }
        // A batch ID is stored in the record, so a sender can't choose its size.
        for badID in [randomBytes(15), randomBytes(17), randomBytes(1024)] {
            #expect(throws: PrekeyBookkeeper.BookkeeperError.malformedBatch) {
                try self.bookkeeper.accept(id: badID, generatedAt: Date(), prekeys: wire(1), lastResort: nil, into: &record)
            }
        }
        #expect(record == .empty, "a rejected batch must change nothing")
    }
}

@Suite("PrekeyBookkeeper — using our keys (Bug 157)")
struct PrekeyBookkeeperConsumeTests {

    let bookkeeper = PrekeyBookkeeper()

    /// Two delivered batches of ours and a pending third, as wire IDs per batch.
    private func threeBatches(now: Date) throws -> (record: PrekeyRecord, ids: [[String]]) {
        var record = PrekeyRecord.empty
        record.legacyKeys = .inUse
        var ids: [[String]] = []
        for _ in 0..<3 {
            self.bookkeeper.install(generated(5), into: &record, now: now)
            let pending = try #require(self.bookkeeper.pendingBatch(in: record))
            ids.append(pending.prekeys.map(\.id))
            if ids.count < 3 {
                // Delivered: the contact uses its first key.
                self.bookkeeper.consume(prekeyID: pending.prekeys[0].id, in: &record, now: now)
                ids[ids.count - 1].removeFirst()
            }
        }
        return (record, ids)
    }

    @Test("Using a key removes it, and its blob is found until then")
    func consumeRemovesKey() throws {
        var record = PrekeyRecord.empty
        let keys = generated(3)
        self.bookkeeper.install(keys, into: &record, now: Date())
        let id = try #require(self.bookkeeper.pendingBatch(in: record)?.prekeys.first?.id)

        #expect(self.bookkeeper.blob(forPrekeyID: id, in: record) == keys[0])
        self.bookkeeper.consume(prekeyID: id, in: &record, now: Date())
        #expect(self.bookkeeper.blob(forPrekeyID: id, in: record) == nil)
    }

    @Test("A key from the pending batch delivers it and drops its ID and public keys; one from an older batch doesn't")
    func onlyItsOwnKeyClearsPending() throws {
        let now = Date()
        var (record, ids) = try self.threeBatches(now: now)
        #expect(self.bookkeeper.hasPendingBatch(record))

        // An older batch's key, arriving late: the pending batch stays pending (Bug 157).
        self.bookkeeper.consume(prekeyID: ids[0][0], in: &record, now: now)
        #expect(self.bookkeeper.hasPendingBatch(record))

        self.bookkeeper.consume(prekeyID: ids[2][0], in: &record, now: now)
        #expect(!self.bookkeeper.hasPendingBatch(record))
        #expect(record.ownBatches.last?.keys.allSatisfy { $0.publicKey == nil } == true)
        #expect(record.ownBatches.allSatisfy { $0.id == nil }, "a delivered batch keeps no ID")
    }

    @Test("Using a key retires every older batch, and the first record-held key retires the legacy keys")
    func useRetiresOlder() throws {
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        var (record, ids) = try self.threeBatches(now: start)
        #expect(record.legacyKeys == .retired(since: start))
        #expect(record.ownBatches[0].retiredAt == start, "the second batch's first use retired the first")
        #expect(record.ownBatches[1].retiredAt == nil)

        let later = start.addingTimeInterval(day)
        self.bookkeeper.consume(prekeyID: ids[2][0], in: &record, now: later)
        #expect(record.ownBatches[0].retiredAt == start, "a retirement time is never moved")
        #expect(record.ownBatches[1].retiredAt == later)
        #expect(record.legacyKeys == .retired(since: start))
    }

    @Test("A key the record doesn't hold, a legacy keychain key, changes nothing")
    func unknownKeyChangesNothing() {
        var record = PrekeyRecord.empty
        record.legacyKeys = .inUse
        self.bookkeeper.install(generated(5), into: &record, now: Date())
        let before = record

        self.bookkeeper.consume(prekeyID: UUID().uuidString, in: &record, now: Date())
        self.bookkeeper.consume(prekeyID: "not-a-uuid", in: &record, now: Date())
        #expect(record == before)
    }

    @Test("A key from a carried-over pending batch delivers it but doesn't retire the legacy keys")
    func carriedOverKeyIsLegacy() throws {
        let legacyPending = OccultaBundle.SealedPayload.PrekeySyncBatch(generatedAt: Date(), prekeys: wire(15))
        var secrecy = ForwardSecrecy()
        secrecy.pendingOutboundBatch = try JSONEncoder().encode(legacyPending)
        var record = try PrekeyRecordCodec().decode(try JSONEncoder().encode(secrecy))

        self.bookkeeper.consume(prekeyID: legacyPending.prekeys[0].id, in: &record, now: Date())
        #expect(!self.bookkeeper.hasPendingBatch(record))
        #expect(record.legacyKeys == .inUse, "its private halves are keychain keys")
    }
}

@Suite("PrekeyBookkeeper — limits and the sweep (Bug 156, D1)")
struct PrekeyBookkeeperLimitTests {

    let bookkeeper = PrekeyBookkeeper()

    @Test("Past the own-key limit, the oldest retired keys go first, and the pending batch is never touched")
    func evictionOrder() throws {
        let now = Date()
        var record = PrekeyRecord.empty
        // Three delivered batches of 15, each retired by the next one's first use, then a 15-key pending batch.
        for _ in 0..<3 {
            self.bookkeeper.install(generated(15), into: &record, now: now)
            let first = try #require(self.bookkeeper.pendingBatch(in: record)?.prekeys.first?.id)
            self.bookkeeper.consume(prekeyID: first, in: &record, now: now)
        }
        let retiredBefore = record.ownBatches.filter { $0.retiredAt != nil }
        self.bookkeeper.install(generated(15), into: &record, now: now)

        let total = record.ownBatches.reduce(0) { $0 + $1.keys.count }
        #expect(total <= PrekeyBookkeeper.maxOwnKeys)
        #expect(record.ownBatches.last?.isPending == true)
        #expect(record.ownBatches.last?.keys.count == 15, "the pending batch is never evicted")
        #expect(record.ownBatches.first(where: { $0.retiredAt == nil && !$0.isPending })?.keys.count == 14,
                "keys still in use stay while retired ones can go")
        #expect(retiredBefore.count == 2)
    }

    @Test("A record at the limits still encodes")
    func limitsFitTheCodec() throws {
        let now = Date()
        var record = PrekeyRecord.empty
        for _ in 0..<6 {
            self.bookkeeper.install(generated(15), into: &record, now: now)
            let first = try #require(self.bookkeeper.pendingBatch(in: record)?.prekeys.first?.id)
            self.bookkeeper.consume(prekeyID: first, in: &record, now: now)
        }
        self.bookkeeper.install(generated(15), into: &record, now: now)
        _ = try self.bookkeeper.accept(id: randomBytes(16), generatedAt: now, prekeys: wire(PrekeyBookkeeper.maxInboundKeysPerBatch), lastResort: nil, into: &record)
        #expect(throws: Never.self) { try PrekeyRecordCodec().encode(record) }
    }

    @Test("Retired batches are swept after 30 days, not before")
    func sweepAfterGrace() throws {
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        var record = PrekeyRecord.empty
        self.bookkeeper.install(generated(5), into: &record, now: start)
        let firstBatch = try #require(self.bookkeeper.pendingBatch(in: record)).prekeys.map(\.id)
        self.bookkeeper.consume(prekeyID: firstBatch[0], in: &record, now: start)
        self.bookkeeper.install(generated(5), into: &record, now: start)
        let second = try #require(self.bookkeeper.pendingBatch(in: record)?.prekeys.first?.id)
        self.bookkeeper.consume(prekeyID: second, in: &record, now: start)
        #expect(record.ownBatches.count == 2)

        // A leftover of the retired first batch: kept through the grace period for a message still in transit.
        let leftover = firstBatch[1]
        _ = self.bookkeeper.sweep(&record, now: start.addingTimeInterval(29 * day))
        #expect(self.bookkeeper.blob(forPrekeyID: leftover, in: record) != nil)

        _ = self.bookkeeper.sweep(&record, now: start.addingTimeInterval(30 * day))
        #expect(self.bookkeeper.blob(forPrekeyID: leftover, in: record) == nil)
        #expect(record.ownBatches.count == 1)
    }

    @Test("Legacy keys come due 30 days after the switch, exactly once")
    func legacyKeysDueOnce() {
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        var record = PrekeyRecord.empty
        record.legacyKeys = .retired(since: start)

        #expect(!self.bookkeeper.sweep(&record, now: start.addingTimeInterval(29 * day)))
        #expect(self.bookkeeper.sweep(&record, now: start.addingTimeInterval(30 * day)))
        #expect(record.legacyKeys == .none)
        #expect(!self.bookkeeper.sweep(&record, now: start.addingTimeInterval(60 * day)))
    }

    @Test("Legacy keys never come due while the contact still uses them, or when there are none")
    func legacyKeysNotDue() {
        for state in [PrekeyRecord.LegacyKeys.inUse, .none] {
            var record = PrekeyRecord.empty
            record.legacyKeys = state
            #expect(!self.bookkeeper.sweep(&record, now: .distantFuture))
            #expect(record.legacyKeys == state)
        }
    }
}

@Suite("PrekeyBookkeeper — eviction never touches keys still in use")
struct PrekeyBookkeeperEvictionTests {

    let bookkeeper = PrekeyBookkeeper()

    /// Keys not yet retired are at most the pending batch and the one before it, so evicting retired keys alone can
    /// always meet `maxOwnKeys`. This is the arithmetic that makes that true; a stage that adds to those keys (a
    /// last-resort key, a bigger batch) has to change it on purpose.
    @MainActor
    @Test("Two batches, each with its last-resort key, fit within the own-key limit")
    func twoBatchesFitTheLimit() {
        #expect(2 * (Manager.PrekeySecretsManager.defaultBatchSize + 1) <= PrekeyBookkeeper.maxOwnKeys)
    }

    /// Batch after batch, the contact uses some keys of each and loses some files, and a new batch is sometimes made
    /// while they still hold keys of the current one (an identity challenge, Bug 155). Whatever the mix, the keys
    /// not yet retired never exceed two batches.
    @Test("Keys not yet retired never exceed two batches, whatever the contact uses")
    func unretiredKeysStayWithinTwoBatches() throws {
        var record = PrekeyRecord.empty
        let now = Date()
        for cycle in 0..<30 {
            self.bookkeeper.install(generated(15), lastResort: randomBytes(143), into: &record, now: now)
            let ids = try #require(self.bookkeeper.pendingBatch(in: record)).prekeys.map(\.id)
            // The contact uses the first key, then a varying share of the rest; the others are lost files, or keys
            // still in their store when the next batch is made.
            for id in ids.prefix(1 + cycle % 15) where cycle % 3 != 0 || id == ids[0] {
                self.bookkeeper.consume(prekeyID: id, in: &record, now: now)
            }
            let unretired = record.ownBatches.filter { $0.retiredAt == nil }.reduce(0) { $0 + PrekeyBookkeeper.keyCount($1) }
            #expect(unretired <= 32)
            #expect(record.ownBatches.reduce(0) { $0 + PrekeyBookkeeper.keyCount($1) } <= PrekeyBookkeeper.maxOwnKeys)
        }
    }

    /// A state the arithmetic above rules out, built by hand: more keys still in use than the limit allows. Eviction
    /// must leave every one of them, since deleting a key the contact holds loses whatever they seal to it.
    @Test("Keys still in use are kept even if that leaves the record over the limit")
    func keysInUseAreNeverEvicted() {
        let now = Date()
        var record = PrekeyRecord.empty
        record.ownBatches = [PrekeyRecord.OwnBatch(
            id: randomBytes(16), createdAt: now, retiredAt: nil, isPending: false,
            keys: (0..<40).map { _ in PrekeyRecord.OwnKey(id: randomBytes(16), blob: randomBytes(143), publicKey: nil) }
        )]
        let inUse = record.ownBatches[0].keys

        self.bookkeeper.install(generated(15), into: &record, now: now)

        #expect(record.ownBatches.first?.keys == inUse)
        #expect(record.ownBatches.reduce(0) { $0 + $1.keys.count } == 55)
    }
}

@Suite("PrekeyBookkeeper — last-resort keys (stage 2)")
struct PrekeyBookkeeperLastResortTests {

    let bookkeeper = PrekeyBookkeeper()

    @Test("A batch's last-resort key goes out with it, its public key derived from its blob")
    func lastResortGoesOut() throws {
        var record = PrekeyRecord.empty
        let lastResort = randomBytes(143)
        self.bookkeeper.install(generated(15), lastResort: lastResort, into: &record, now: Date())

        let batch = try #require(self.bookkeeper.pendingBatch(in: record))
        let wired = try #require(batch.lastResort)
        #expect(wired.publicKey == fakePublicKey(ofBlob: lastResort))
        #expect(UUID(uuidString: wired.id) != nil)
        #expect(!batch.prekeys.map(\.id).contains(wired.id))
        #expect(record.ownBatches.last?.lastResort?.publicKey == nil, "public keys aren't stored")
    }

    /// The last-resort key is what the contact seals to once the one-time keys are gone, so it must outlive them.
    @Test("A batch whose one-time keys are all used keeps its entry for its last-resort key")
    func lastResortKeepsItsBatch() throws {
        var record = PrekeyRecord.empty
        self.bookkeeper.install(generated(2), lastResort: randomBytes(143), into: &record, now: Date())
        let ids = try #require(self.bookkeeper.pendingBatch(in: record)).prekeys.map(\.id)
        for id in ids { self.bookkeeper.consume(prekeyID: id, in: &record, now: Date()) }

        #expect(record.ownBatches.count == 1)
        #expect(record.ownBatches.first?.keys.isEmpty == true)
        #expect(record.ownBatches.first?.lastResort != nil)
    }

    /// Its real ID is never written in a bundle, so a bundle naming it is no key of ours.
    @Test("The last-resort key isn't found by its own ID, nor consumed by it")
    func notFoundByItsOwnID() throws {
        var record = PrekeyRecord.empty
        self.bookkeeper.install(generated(1), lastResort: randomBytes(143), into: &record, now: Date())
        let id = try #require(self.bookkeeper.pendingBatch(in: record)?.lastResort?.id)

        #expect(self.bookkeeper.blob(forPrekeyID: id, in: record) == nil)
        let before = record
        self.bookkeeper.consume(prekeyID: id, in: &record, now: Date())
        #expect(record == before)
    }

    @Test("Eviction counts last-resort keys, and takes a retired batch's one-time keys before its last-resort key")
    func evictionCountsLastResort() {
        let now = Date()
        let key = { PrekeyRecord.OwnKey(id: randomBytes(16), blob: randomBytes(143), publicKey: nil) }
        let retired = PrekeyRecord.OwnBatch(id: nil, createdAt: now, retiredAt: now, isPending: false,
                                            keys: [key(), key()], lastResort: key())
        // A batch in use big enough that, with the 16 installed, the record is `over` keys past the limit. Only the
        // retired batch's 3 keys may go.
        let record = { (over: Int) -> PrekeyRecord in
            var record = PrekeyRecord.empty
            let inUse = PrekeyBookkeeper.maxOwnKeys + over - 3 - 16 - 1
            record.ownBatches = [retired, PrekeyRecord.OwnBatch(
                id: nil, createdAt: now, retiredAt: nil, isPending: false,
                keys: (0..<inUse).map { _ in key() }, lastResort: key()
            )]
            self.bookkeeper.install(generated(15), lastResort: randomBytes(143), into: &record, now: now)
            return record
        }

        let twoOver = record(2)
        #expect(twoOver.ownBatches.first?.keys.isEmpty == true, "the retired batch's one-time keys went first")
        #expect(twoOver.ownBatches.first?.lastResort == retired.lastResort, "its last-resort key stayed")

        let threeOver = record(3)
        #expect(threeOver.ownBatches.allSatisfy { $0.retiredAt == nil }, "then the last-resort key, and the batch with it")
        #expect(threeOver.ownBatches.reduce(0) { $0 + PrekeyBookkeeper.keyCount($1) } == PrekeyBookkeeper.maxOwnKeys)
    }

    @Test("The contact's last-resort key is stored, outlives their one-time keys, and is replaced by their next batch")
    func inboundLastResort() throws {
        var record = PrekeyRecord.empty
        let first = OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: randomBytes(65))
        _ = try self.bookkeeper.accept(id: randomBytes(16), generatedAt: Date(), prekeys: wire(1),
                                       lastResort: first, into: &record)
        #expect(record.inboundLastResort?.id == first.id)

        _ = self.bookkeeper.takeInboundPrekey(from: &record, contactID: "contact")
        #expect(record.inboundBatches.isEmpty)
        #expect(record.inboundLastResort?.id == first.id, "running out of one-time keys keeps it")

        let second = OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: randomBytes(65))
        _ = try self.bookkeeper.accept(id: randomBytes(16), generatedAt: Date(), prekeys: wire(1),
                                       lastResort: second, into: &record)
        #expect(record.inboundLastResort?.id == second.id)

        _ = try self.bookkeeper.accept(id: randomBytes(16), generatedAt: Date(), prekeys: wire(1),
                                       lastResort: nil, into: &record)
        #expect(record.inboundLastResort == nil, "the newest batch's last-resort key, or none")
    }

    @Test("A last-resort key that isn't a 65-byte key with a UUID ID makes the batch malformed")
    func malformedLastResortRejected() {
        var record = PrekeyRecord.empty
        let bad = [
            OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: randomBytes(64)),
            OccultaBundle.WirePrekey(id: "not-a-uuid", publicKey: randomBytes(65)),
        ]
        for lastResort in bad {
            #expect(throws: PrekeyBookkeeper.BookkeeperError.malformedBatch) {
                try self.bookkeeper.accept(id: randomBytes(16), generatedAt: Date(), prekeys: wire(1),
                                           lastResort: lastResort, into: &record)
            }
        }
        #expect(record == .empty)
    }
}

@Suite("PrekeyBookkeeper — receiving on a last-resort key (stage 2, §3.1's table)")
struct PrekeyBookkeeperLastResortUseTests {

    let bookkeeper = PrekeyBookkeeper()

    private func idString(_ bytes: Data) -> String {
        let b = [UInt8](bytes)
        return UUID(uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                           b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])).uuidString
    }

    private func lastResortID(ofBatchAt index: Int, in record: PrekeyRecord) throws -> String {
        self.idString(try #require(record.ownBatches[index].lastResort?.id))
    }

    /// Batch 0 delivered (its first key used), batch 1 pending; each with a last-resort key.
    private func deliveredThenPending(now: Date) throws -> PrekeyRecord {
        var record = PrekeyRecord.empty
        self.bookkeeper.install(generated(3), lastResort: randomBytes(143), into: &record, now: now)
        let first = try #require(self.bookkeeper.pendingBatch(in: record)?.prekeys.first?.id)
        self.bookkeeper.consume(prekeyID: first, in: &record, now: now)
        self.bookkeeper.install(generated(3), lastResort: randomBytes(143), into: &record, now: now)
        // As if legacy keys were still in use, so the tests can see a last-resort use retire them.
        record.legacyKeys = .inUse
        return record
    }

    @Test("The pending batch's own last-resort key delivers it and calls for a new batch")
    func pendingOwnKeyDeliversAndGenerates() throws {
        let now = Date()
        var record = try self.deliveredThenPending(now: now)
        let keyID = try self.lastResortID(ofBatchAt: 1, in: record)

        #expect(self.bookkeeper.useLastResort(keyID: keyID, in: &record, now: now))
        #expect(!self.bookkeeper.hasPendingBatch(record), "the contact has it, and has used all its one-time keys")
        #expect(record.ownBatches[1].id == nil)
        #expect(record.ownBatches[0].retiredAt == now, "the older batch retires, as for a one-time key")
        #expect(record.legacyKeys == .retired(since: now))
        #expect(record.ownBatches[1].lastResort != nil, "the last-resort key stays")
    }

    @Test("The newest delivered batch's last-resort key, with nothing pending, calls for a new batch")
    func newestDeliveredGenerates() throws {
        let now = Date()
        var record = PrekeyRecord.empty
        self.bookkeeper.install(generated(1), lastResort: randomBytes(143), into: &record, now: now)
        let first = try #require(self.bookkeeper.pendingBatch(in: record)?.prekeys.first?.id)
        self.bookkeeper.consume(prekeyID: first, in: &record, now: now)

        #expect(self.bookkeeper.useLastResort(keyID: try self.lastResortID(ofBatchAt: 0, in: record), in: &record, now: now))
    }

    @Test("An older last-resort key while a batch is pending leaves it riding")
    func olderKeyKeepsPendingRiding() throws {
        let now = Date()
        var record = try self.deliveredThenPending(now: now)

        #expect(!self.bookkeeper.useLastResort(keyID: try self.lastResortID(ofBatchAt: 0, in: record), in: &record, now: now))
        #expect(self.bookkeeper.hasPendingBatch(record), "the contact hasn't received it yet")
    }

    /// D5: only the current last-resort key signals "out of keys".
    @Test("A repeat delivery sealed to an older batch's last-resort key generates nothing")
    func repeatGeneratesNothing() throws {
        let now = Date()
        var record = try self.deliveredThenPending(now: now)
        let older = try self.lastResortID(ofBatchAt: 0, in: record)
        _ = self.bookkeeper.useLastResort(keyID: try self.lastResortID(ofBatchAt: 1, in: record), in: &record, now: now)
        #expect(!self.bookkeeper.hasPendingBatch(record))

        #expect(!self.bookkeeper.useLastResort(keyID: older, in: &record, now: now))
    }

    @Test("A key that isn't one of our last-resort keys changes nothing")
    func unknownKeyChangesNothing() throws {
        var record = try self.deliveredThenPending(now: Date())
        let before = record
        #expect(!self.bookkeeper.useLastResort(keyID: UUID().uuidString, in: &record, now: Date()))
        #expect(record == before)
    }

    @Test("A derived prekey ID is matched to its batch's last-resort key, and nothing else is")
    func derivedIDMatching() throws {
        let record = try self.deliveredThenPending(now: Date())
        let ephemeral = randomBytes(65)
        for index in 0..<2 {
            let keyID = try self.lastResortID(ofBatchAt: index, in: record)
            let derived = try #require(OccultaBundle.SecrecyContext.lastResortPrekeyID(keyID: keyID, ephemeralPublicKey: ephemeral))
            let match = try #require(self.bookkeeper.lastResort(matchingPrekeyID: derived, ephemeralPublicKey: ephemeral, in: record))
            #expect(match.keyID == keyID)
            #expect(match.blob == record.ownBatches[index].lastResort?.blob)
            #expect(self.bookkeeper.lastResort(matchingPrekeyID: derived, ephemeralPublicKey: randomBytes(65), in: record) == nil,
                    "another ephemeral key gives another ID")
            #expect(self.bookkeeper.lastResort(matchingPrekeyID: keyID, ephemeralPublicKey: ephemeral, in: record) == nil,
                    "the key's own ID is never what a bundle carries")
        }
    }

    @Test("The contact's last-resort key is what we seal to once their one-time keys are gone")
    func lastResortForSending() throws {
        var record = PrekeyRecord.empty
        let lastResort = OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: randomBytes(65))
        _ = try self.bookkeeper.accept(id: randomBytes(16), generatedAt: Date(), prekeys: [], lastResort: lastResort, into: &record)

        let prekey = try #require(self.bookkeeper.lastResortPrekey(in: record, contactID: "contact"))
        #expect(prekey.id == lastResort.id && prekey.publicKey == lastResort.publicKey && prekey.contactID == "contact")
    }
}


@Suite("PrekeyBookkeeper — appending the contact's batches (stage 4)")
struct PrekeyBookkeeperAppendTests {

    let bookkeeper = PrekeyBookkeeper()

    @Test("A second batch goes after the keys we hold, and comes out after them")
    func appendsAfterHeldKeys() throws {
        var record = PrekeyRecord.empty
        let first = wire(15), second = wire(15)
        _ = try self.bookkeeper.accept(id: randomBytes(16), generatedAt: Date(), prekeys: first, lastResort: nil, into: &record)
        for _ in 0..<10 { _ = self.bookkeeper.takeInboundPrekey(from: &record, contactID: "contact") }
        _ = try self.bookkeeper.accept(id: randomBytes(16), generatedAt: Date(), prekeys: second, lastResort: nil, into: &record)

        let used = (0..<20).compactMap { _ in self.bookkeeper.takeInboundPrekey(from: &record, contactID: "contact")?.id }
        #expect(used == Array(first.suffix(5).map(\.id)) + Array(second.map(\.id)))
        #expect(self.bookkeeper.takeInboundPrekey(from: &record, contactID: "contact") == nil)
    }

    @Test("A third batch drops the oldest")
    func thirdDropsOldest() throws {
        var record = PrekeyRecord.empty
        let batches = [wire(15), wire(15), wire(15)]
        for batch in batches {
            _ = try self.bookkeeper.accept(id: randomBytes(16), generatedAt: Date(), prekeys: batch, lastResort: nil, into: &record)
        }
        #expect(record.inboundBatches.count == PrekeyBookkeeper.maxInboundBatches)
        #expect(record.inboundBatches.map { $0.keys.map(\.id) } == batches.suffix(2).map { $0.map(\.id) })
    }

    @Test("The last-resort key is the newest batch's, and the record encodes with two full batches held")
    func lastResortIsNewest() throws {
        var record = PrekeyRecord.empty
        let older = OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: randomBytes(65))
        let newer = OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: randomBytes(65))
        _ = try self.bookkeeper.accept(id: randomBytes(16), generatedAt: Date(), prekeys: wire(15), lastResort: older, into: &record)
        _ = try self.bookkeeper.accept(id: randomBytes(16), generatedAt: Date(), prekeys: wire(15), lastResort: newer, into: &record)

        #expect(record.inboundLastResort?.id == newer.id)
        #expect(record.inboundBatches.count == 2)
        #expect(try PrekeyRecordCodec().encode(record).count == PrekeyRecordCodec.capacity)
    }
}

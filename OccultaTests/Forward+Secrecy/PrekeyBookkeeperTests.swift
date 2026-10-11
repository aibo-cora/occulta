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

private func generated(_ count: Int) -> [PrekeyBookkeeper.GeneratedKey] {
    (0..<count).map { _ in PrekeyBookkeeper.GeneratedKey(blob: randomBytes(143), publicKey: randomBytes(65)) }
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
        #expect(try self.bookkeeper.accept(id: randomBytes(16), generatedAt: Date(), prekeys: keys, into: &record))

        for expected in keys {
            let prekey = try #require(self.bookkeeper.takeInboundPrekey(from: &record, contactID: "contact"))
            #expect(prekey.id == expected.id)
            #expect(prekey.publicKey == expected.publicKey)
            #expect(prekey.contactID == "contact")
        }
        #expect(self.bookkeeper.takeInboundPrekey(from: &record, contactID: "contact") == nil)
        #expect(record.inboundBatches.isEmpty)
    }

    @Test("A newly installed batch is pending and goes out with its ID, date and public keys")
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
        #expect(batch.prekeys.map(\.publicKey) == keys.map(\.publicKey))
        #expect(batch.prekeys.allSatisfy { UUID(uuidString: $0.id) != nil })
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
        #expect(try self.bookkeeper.accept(id: first, generatedAt: Date(timeIntervalSince1970: 2_000), prekeys: wire(15), into: &record))

        let second = wire(15)
        #expect(try self.bookkeeper.accept(id: randomBytes(16), generatedAt: Date(timeIntervalSince1970: 1_000), prekeys: second, into: &record),
                "a sender whose clock went back must not be stuck")
        #expect(record.inboundBatches.first?.keys.map(\.id) == second.map(\.id))

        #expect(try !self.bookkeeper.accept(id: first, generatedAt: Date(timeIntervalSince1970: 3_000), prekeys: wire(15), into: &record))
        #expect(record.inboundBatches.first?.keys.map(\.id) == second.map(\.id), "a repeat must not bring back used keys")
    }

    @Test("A batch without an ID keeps the date rule")
    func noIDKeepsDateRule() throws {
        var record = PrekeyRecord.empty
        #expect(try self.bookkeeper.accept(id: nil, generatedAt: Date(timeIntervalSince1970: 2_000), prekeys: wire(15), into: &record))
        #expect(try !self.bookkeeper.accept(id: nil, generatedAt: Date(timeIntervalSince1970: 2_000), prekeys: wire(15), into: &record))
        #expect(try !self.bookkeeper.accept(id: nil, generatedAt: Date(timeIntervalSince1970: 1_000), prekeys: wire(15), into: &record))
        #expect(try self.bookkeeper.accept(id: nil, generatedAt: Date(timeIntervalSince1970: 3_000), prekeys: wire(15), into: &record))
    }

    @Test("Only the 8 most recent accepted IDs are kept")
    func acceptedIDsAreCapped() throws {
        var record = PrekeyRecord.empty
        let ids = (0..<10).map { _ in randomBytes(16) }
        for id in ids {
            _ = try self.bookkeeper.accept(id: id, generatedAt: Date(), prekeys: wire(1), into: &record)
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
                try self.bookkeeper.accept(id: randomBytes(16), generatedAt: Date(), prekeys: prekeys, into: &record)
            }
        }
        // A batch ID is stored in the record, so a sender can't choose its size.
        for badID in [randomBytes(15), randomBytes(17), randomBytes(1024)] {
            #expect(throws: PrekeyBookkeeper.BookkeeperError.malformedBatch) {
                try self.bookkeeper.accept(id: badID, generatedAt: Date(), prekeys: wire(1), into: &record)
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

        #expect(self.bookkeeper.blob(forPrekeyID: id, in: record) == keys[0].blob)
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
        _ = try self.bookkeeper.accept(id: randomBytes(16), generatedAt: now, prekeys: wire(PrekeyBookkeeper.maxInboundKeysPerBatch), into: &record)
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
    @Test("Two batches fit within the own-key limit")
    func twoBatchesFitTheLimit() {
        #expect(2 * Manager.PrekeySecretsManager.defaultBatchSize <= PrekeyBookkeeper.maxOwnKeys)
    }

    /// Batch after batch, the contact uses some keys of each and loses some files, and a new batch is sometimes made
    /// while they still hold keys of the current one (an identity challenge, Bug 155). Whatever the mix, the keys
    /// not yet retired never exceed two batches.
    @Test("Keys not yet retired never exceed two batches, whatever the contact uses")
    func unretiredKeysStayWithinTwoBatches() throws {
        var record = PrekeyRecord.empty
        let now = Date()
        for cycle in 0..<30 {
            self.bookkeeper.install(generated(15), into: &record, now: now)
            let ids = try #require(self.bookkeeper.pendingBatch(in: record)).prekeys.map(\.id)
            // The contact uses the first key, then a varying share of the rest; the others are lost files, or keys
            // still in their store when the next batch is made.
            for id in ids.prefix(1 + cycle % 15) where cycle % 3 != 0 || id == ids[0] {
                self.bookkeeper.consume(prekeyID: id, in: &record, now: now)
            }
            let unretired = record.ownBatches.filter { $0.retiredAt == nil }.reduce(0) { $0 + $1.keys.count }
            #expect(unretired <= 30)
            #expect(record.ownBatches.reduce(0) { $0 + $1.keys.count } <= PrekeyBookkeeper.maxOwnKeys)
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

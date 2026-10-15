//
//  PrekeyConversationSimulationTests.swift
//  OccultaTests
//
//  Prekey continuity stage 4 (§3.3): refill and append, over whole conversations. Both phones' records for each other
//  are driven through `PrekeyBookkeeper` exactly as `ContactManager` drives them: the sender takes the oldest key it
//  holds, else the contact's last-resort key, else the long-term key, and attaches its pending batch; the receiver
//  uses the key as the slot opens, then accepts the batch the message carries, then decides on a new batch
//  (`replenish`). Pure: no Enclave and no crypto, so thousands of messages run in moments, and on CI.
//
//  After every step both records are checked against the limits the fixed 16 KB record is budgeted for, and every
//  message must open: a one-time key the receiver still holds, used once, or the receiver's last-resort key.
//
//  Nothing marks a key expired: a receiver's batch retires when the sender first uses a newer one, and the sweep at
//  unlock deletes it 30 days later. What keeps a sender off an expired key is structural, so it's checked after
//  every step too: every key a phone holds for the other, one-time or last-resort, is one the other still holds in a
//  batch that hasn't retired. Long silences run the sweep on both phones.
//
//  `PrekeyConversationTests` drives the same conversations through the real send and receive paths.
//

import Testing
import Foundation
@testable import Occulta
@testable import OccultaFormats

/// SplitMix64, so a failing random run can be replayed from its seed.
private struct SeededGenerator: RandomNumberGenerator {
    var state: UInt64
    mutating func next() -> UInt64 {
        self.state &+= 0x9E37_79B9_7F4A_7C15
        var z = self.state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

private enum Side: Hashable {
    case alice, bob
    var other: Side { self == .alice ? .bob : .alice }
}

/// The key a message was sealed to, as its sender chose it.
private enum SealedTo: Equatable {
    case oneTime(String)
    case lastResort(String)
    case longTerm
}

private struct Message {
    let from: Side
    let sealedTo: SealedTo
    let batch: PrekeyBookkeeper.OutboundBatch?
}

private struct Unopenable: Error, CustomStringConvertible {
    let description: String
}

/// Both phones, as the bookkeeper sees them: each one's record for the other.
private struct Conversation {
    let bookkeeper = PrekeyBookkeeper()
    var records: [Side: PrekeyRecord] = [.alice: .empty, .bob: .empty]
    var now = Date(timeIntervalSince1970: 1_800_000_000)
    /// One-time keys already used, per receiver: none may be used twice.
    var used: [Side: Set<String>] = [.alice: [], .bob: []]
    /// What each side's messages were sealed to, in the order sent.
    var log: [Side: [SealedTo]] = [.alice: [], .bob: []]
    /// For conversations delivered in order and complete: the contact uses our keys oldest first, so by the time they
    /// start a newer batch they've used every key of the older one, and a retired batch of ours never holds an unused
    /// key. Wrong ordering, or replacing instead of appending, leaves keys unused there (stage 4, append).
    var expectsNoUnusedRetiredKeys = false

    mutating func send(from side: Side) throws -> Message {
        self.now += 60
        var record = try #require(self.records[side])
        let sealedTo: SealedTo
        if let key = self.bookkeeper.takeInboundPrekey(from: &record, contactID: "contact") {
            sealedTo = .oneTime(key.id)
        } else if let key = self.bookkeeper.lastResortPrekey(in: record, contactID: "contact") {
            sealedTo = .lastResort(key.id)
        } else {
            sealedTo = .longTerm
        }
        let batch = self.bookkeeper.pendingBatch(in: record) { $0.prefix(65) }
        self.records[side] = record
        self.log[side, default: []].append(sealedTo)
        try Self.checkLimits(record)
        try self.checkHeldKeysAreLive()
        return Message(from: side, sealedTo: sealedTo, batch: batch)
    }

    /// As `openGroup`: the key is used as the slot opens, then the batch the message carries is accepted, then
    /// `replenish` decides on a new batch.
    mutating func deliver(_ message: Message) throws {
        self.now += 60
        let receiver = message.from.other
        var record = try #require(self.records[receiver])

        switch message.sealedTo {
        case .oneTime(let id):
            guard self.bookkeeper.blob(forPrekeyID: id, in: record) != nil else {
                throw Unopenable(description: "\(receiver) no longer holds one-time key \(id)")
            }
            guard self.used[receiver, default: []].insert(id).inserted else {
                throw Unopenable(description: "one-time key \(id) used twice")
            }
            self.bookkeeper.consume(prekeyID: id, in: &record, now: self.now)
        case .lastResort(let keyID):
            let id = try Self.idBytes(keyID)
            guard record.ownBatches.contains(where: { $0.lastResort?.id == id && $0.lastResort?.blob != nil }) else {
                throw Unopenable(description: "\(receiver) no longer holds last-resort key \(keyID)")
            }
        case .longTerm:
            break
        }

        if let batch = message.batch {
            _ = try self.bookkeeper.accept(
                id: batch.id, generatedAt: batch.generatedAt, prekeys: batch.prekeys, lastResort: batch.lastResort,
                onReopenableSlot: !isOneTime(message.sealedTo), into: &record
            )
        }

        let due: Bool
        switch message.sealedTo {
        case .oneTime:                  due = self.bookkeeper.needsRefill(record)
        case .lastResort(let keyID):    due = self.bookkeeper.useLastResort(keyID: keyID, in: &record, now: self.now)
        case .longTerm:                 due = !self.bookkeeper.hasPendingBatch(record)
        }
        if due {
            let blob = { Data((0..<143).map { _ in UInt8.random(in: .min ... .max) }) }
            self.bookkeeper.install((0..<15).map { _ in blob() }, lastResort: blob(), into: &record, now: self.now)
        }

        self.records[receiver] = record
        try Self.checkLimits(record)
        try self.checkHeldKeysAreLive()
        if self.expectsNoUnusedRetiredKeys {
            let unused = record.ownBatches.filter { $0.retiredAt != nil }.reduce(0) { $0 + $1.keys.count }
            #expect(unused == 0, "\(receiver)'s retired batches hold \(unused) keys the contact never used")
        }
    }

    /// Days with no messages, ending in an unlock on both phones, which sweeps what the grace period no longer
    /// protects (`ContactManager.sweepPrekeys`).
    mutating func silence(days: Int) throws {
        self.now += TimeInterval(days) * 24 * 60 * 60
        for side in [Side.alice, .bob] {
            var record = try #require(self.records[side])
            _ = self.bookkeeper.sweep(&record, now: self.now)
            self.records[side] = record
        }
        try self.checkHeldKeysAreLive()
    }

    /// Every key a phone holds for the other is one the other still holds, in a batch that hasn't retired: a sender is
    /// never left with an expired key, though nothing on its side marks one.
    func checkHeldKeysAreLive() throws {
        for holder in [Side.alice, .bob] {
            let held = try #require(self.records[holder])
            let owner = try #require(self.records[holder.other])
            let live = owner.ownBatches.filter { $0.retiredAt == nil }
            let liveOneTime = Set(live.flatMap { $0.keys.filter { $0.blob != nil }.map(\.id) })
            let liveLastResort = Set(live.compactMap { $0.lastResort?.blob != nil ? $0.lastResort?.id : nil })
            for key in held.inboundBatches.flatMap(\.keys) {
                #expect(liveOneTime.contains(try Self.idBytes(key.id)), "\(holder) holds a one-time key \(holder.other) has retired or deleted")
            }
            if let lastResort = held.inboundLastResort {
                #expect(liveLastResort.contains(try Self.idBytes(lastResort.id)), "\(holder) holds a last-resort key \(holder.other) has retired or deleted")
            }
        }
    }

    static func idBytes(_ uuidString: String) throws -> Data {
        withUnsafeBytes(of: try #require(UUID(uuidString: uuidString)).uuid) { Data($0) }
    }

    /// One message, sent and delivered at once.
    mutating func exchange(from side: Side) throws {
        try self.deliver(try self.send(from: side))
    }

    /// Until each side holds the other's keys: Alice's first message is long-term and makes Bob a batch, Bob's
    /// long-term reply carries it and makes Alice one, and her next carries hers.
    mutating func warmUp() throws {
        try self.exchange(from: .alice)
        try self.exchange(from: .bob)
        try self.exchange(from: .alice)
        #expect(self.log[.alice]?.first == .longTerm)
        #expect(self.log[.alice]?.last.map(isOneTime) == true)
        #expect(self.log[.bob] == [.longTerm])
        self.log = [.alice: [], .bob: []]
    }

    /// What the fixed-size record is budgeted for.
    static func checkLimits(_ record: PrekeyRecord) throws {
        _ = try PrekeyRecordCodec().encode(record)
        #expect(record.ownBatches.filter { $0.retiredAt == nil }.count <= 2, "keys not retired stay within two batches")
        #expect(record.ownBatches.reduce(0) { $0 + PrekeyBookkeeper.keyCount($1) } <= PrekeyBookkeeper.maxOwnKeys)
        #expect(record.inboundBatches.count <= PrekeyBookkeeper.maxInboundBatches)
        #expect(record.acceptedBatchIDs.count <= PrekeyBookkeeper.maxAcceptedBatchIDs)
    }

    func count(_ side: Side, _ match: (SealedTo) -> Bool) -> Int {
        (self.log[side] ?? []).filter(match).count
    }
}

private func isOneTime(_ sealedTo: SealedTo) -> Bool { if case .oneTime = sealedTo { return true }; return false }
private func isLastResort(_ sealedTo: SealedTo) -> Bool { if case .lastResort = sealedTo { return true }; return false }

@Suite("Prekey conversations, simulated — refill and append (stage 4)")
struct PrekeyConversationSimulationTests {

    @Test("Alternating, 1,000 messages each way: every one on a one-time key")
    func alternating() throws {
        var conversation = Conversation()
        try conversation.warmUp()
        conversation.expectsNoUnusedRetiredKeys = true
        for _ in 0..<1_000 {
            try conversation.exchange(from: .alice)
            try conversation.exchange(from: .bob)
        }
        #expect(conversation.count(.alice, isOneTime) == 1_000)
        #expect(conversation.count(.bob, isOneTime) == 1_000)
    }

    /// A batch reaches Alice only with Bob's reply, and Bob refills once she holds 5 or fewer. At the start of a burst
    /// she can hold as few as 6 with no refill due, so 6 is the longest burst one-time keys always cover.
    @Test("Bursts of up to 6, one reply each, through 1,000 of Bob's keys: every one on a one-time key",
          arguments: [1, 2, 5, 6])
    func burstsWithinThreshold(burst: Int) throws {
        var conversation = Conversation()
        try conversation.warmUp()
        conversation.expectsNoUnusedRetiredKeys = true
        while conversation.count(.alice, isOneTime) < 1_000 {
            for _ in 0..<burst { try conversation.exchange(from: .alice) }
            try conversation.exchange(from: .bob)
        }
        #expect(conversation.count(.alice, { !isOneTime($0) }) == 0)
        #expect(conversation.count(.bob, { !isOneTime($0) }) == 0)
    }

    @Test("Bursts of 10: at most 4 per burst on the last-resort key, none long-term, all opened")
    func burstsPastThreshold() throws {
        var conversation = Conversation()
        try conversation.warmUp()
        conversation.expectsNoUnusedRetiredKeys = true
        for _ in 0..<100 {
            let before = conversation.count(.alice, isLastResort)
            for _ in 0..<10 { try conversation.exchange(from: .alice) }
            #expect(conversation.count(.alice, isLastResort) - before <= 10 - (PrekeyBookkeeper.refillThreshold + 1))
            try conversation.exchange(from: .bob)
        }
        #expect(conversation.count(.alice, { $0 == .longTerm }) == 0)
        #expect(conversation.count(.bob, { !isOneTime($0) }) == 0)
    }

    /// No reply means no new batch, so past the keys she holds Alice seals to Bob's last-resort key, as §3.3 expects.
    @Test("One way, 100 messages: the keys held, then the last-resort key, never long-term; one reply puts her back on one-time keys")
    func oneWay() throws {
        var conversation = Conversation()
        try conversation.warmUp()
        let held = try #require(conversation.records[.alice]).inboundBatches.reduce(0) { $0 + $1.keys.count }
        #expect(held == 14)

        for _ in 0..<100 { try conversation.exchange(from: .alice) }
        let sent = try #require(conversation.log[.alice])
        #expect(sent.prefix(held).allSatisfy(isOneTime))
        #expect(sent.dropFirst(held).allSatisfy(isLastResort))
        #expect(Set(sent.dropFirst(held).map { "\($0)" }).count == 1, "one last-resort key throughout")

        // Bob doesn't answer for 40 days. His batch never retired, so the sweep leaves the key Alice is using.
        try conversation.silence(days: 40)
        try conversation.exchange(from: .alice)
        #expect(conversation.log[.alice]?.last.map(isLastResort) == true)

        try conversation.exchange(from: .bob)
        try conversation.exchange(from: .alice)
        #expect(conversation.log[.alice]?.last.map(isOneTime) == true)
    }

    /// The unlock-time sweep deletes only retired batches, so a conversation picks up after weeks of silence on the keys
    /// both phones held before it.
    @Test("Alternating, with 40 days' silence every 50 messages: the sweeps delete nothing either phone still needs")
    func silences() throws {
        var conversation = Conversation()
        try conversation.warmUp()
        conversation.expectsNoUnusedRetiredKeys = true
        for round in 0..<1_000 {
            if round.isMultiple(of: 50) { try conversation.silence(days: 40) }
            try conversation.exchange(from: .alice)
            try conversation.exchange(from: .bob)
        }
        #expect(conversation.count(.alice, isOneTime) == 1_000)
        #expect(conversation.count(.bob, isOneTime) == 1_000)
    }

    /// Only the last 8 accepted batch IDs are remembered. A message on a slot that opens again — the long-term keys,
    /// or a last-resort key — kept and redelivered after its batch's ID has aged out must change nothing, and the
    /// conversation must carry on on keys the other phone still holds.
    @Test("A message on a reopenable slot, redelivered after its batch's ID has aged out, brings nothing back",
          arguments: [true, false])
    func replayAfterIDsAgeOut(onLastResort: Bool) throws {
        var conversation = Conversation()
        // Alice's first message is long-term; Bob's long-term reply carries his first batch: keep a copy of it.
        try conversation.exchange(from: .alice)
        var kept = try conversation.send(from: .bob)
        try conversation.deliver(kept)
        try conversation.exchange(from: .alice)
        if onLastResort {
            // Alice writes until Bob's refill is due; then Bob writes one way, past Alice's keys onto her last-resort
            // key. Keep his first message there, which carries his pending batch.
            for _ in 0..<15 {
                if conversation.bookkeeper.hasPendingBatch(try #require(conversation.records[.bob])) { break }
                try conversation.exchange(from: .alice)
            }
            for _ in 0..<20 {
                kept = try conversation.send(from: .bob)
                try conversation.deliver(kept)
                if isLastResort(kept.sealedTo) { break }
            }
            #expect(isLastResort(kept.sealedTo))
        }
        let keptID = try #require(kept.batch?.id)
        #expect(!isOneTime(kept.sealedTo))

        // Ten from Alice to each reply from Bob: his batches reach her one after another, well past 8, while he uses
        // few of hers. Her batch holding the kept last-resort key retires but is neither swept nor evicted, so the
        // kept message still opens, as a replay could in the app.
        for _ in 0..<20 {
            for _ in 0..<10 { try conversation.exchange(from: .alice) }
            try conversation.exchange(from: .bob)
        }
        let before = try #require(conversation.records[.alice])
        #expect(!before.acceptedBatchIDs.contains(keptID), "precondition: the kept batch's ID has aged out")

        try conversation.deliver(kept)
        #expect(conversation.records[.alice]?.inboundBatches == before.inboundBatches)
        #expect(conversation.records[.alice]?.inboundLastResort == before.inboundLastResort)

        conversation.log = [.alice: [], .bob: []]
        for _ in 0..<50 {
            try conversation.exchange(from: .alice)
            try conversation.exchange(from: .bob)
        }
        #expect(conversation.count(.bob, isOneTime) == 50, "Bob seals only to keys Alice still holds")
    }

    /// Every seventh message is never delivered, either way. A batch rides every message until delivered, so losing
    /// one loses no batch; Bob's count includes keys used for lost messages, so his refills come later.
    @Test("Alternating with one message in seven lost: every delivered message opens, all on one-time keys")
    func lostMessages() throws {
        var conversation = Conversation()
        try conversation.warmUp()
        for index in 0..<2_000 {
            let message = try conversation.send(from: index.isMultiple(of: 2) ? .alice : .bob)
            if !index.isMultiple(of: 7) { try conversation.deliver(message) }
        }
        #expect(conversation.count(.alice, { !isOneTime($0) }) == 0)
        #expect(conversation.count(.bob, { !isOneTime($0) }) == 0)
    }

    /// Each direction's messages arrive in shuffled order within windows of 4, and each side keeps sending before
    /// the other's arrive. A message sealed to a batch that retired meanwhile still opens, within the 30 days' grace.
    @Test("Out of order within windows of 4: every message opens", arguments: [1, 2, 3] as [UInt64])
    func outOfOrder(seed: UInt64) throws {
        var generator = SeededGenerator(state: seed)
        var conversation = Conversation()
        try conversation.warmUp()
        var inFlight: [Side: [Message]] = [.alice: [], .bob: []]
        for index in 0..<2_000 {
            let side: Side = index.isMultiple(of: 2) ? .alice : .bob
            inFlight[side, default: []].append(try conversation.send(from: side))
            if inFlight[side, default: []].count == 4 {
                for message in inFlight[side, default: []].shuffled(using: &generator) { try conversation.deliver(message) }
                inFlight[side] = []
            }
        }
        #expect(conversation.count(.alice, { $0 == .longTerm }) == 0)
        #expect(conversation.count(.bob, { $0 == .longTerm }) == 0)
    }

    /// Random bursts of 1–15 either way, a delay of up to 6 messages per direction, one message in twenty lost, and now
    /// and then weeks of silence ending in the sweep.
    @Test("Random conversations: every delivered message opens, never long-term after the first exchange",
          arguments: [11, 12, 13, 14, 15] as [UInt64])
    func random(seed: UInt64) throws {
        var generator = SeededGenerator(state: seed)
        var conversation = Conversation()
        try conversation.warmUp()
        var inFlight: [Side: [Message]] = [.alice: [], .bob: []]

        for _ in 0..<300 {
            let side: Side = Bool.random(using: &generator) ? .alice : .bob
            for _ in 0..<Int.random(in: 1...15, using: &generator) {
                let message = try conversation.send(from: side)
                if Int.random(in: 0..<20, using: &generator) != 0 { inFlight[side, default: []].append(message) }
                // Deliver whatever's waiting, in random order, once a direction has 6 in flight or by chance.
                for direction in [Side.alice, .bob] where inFlight[direction, default: []].count >= 6 || Bool.random(using: &generator) {
                    for message in inFlight[direction, default: []].shuffled(using: &generator) { try conversation.deliver(message) }
                    inFlight[direction] = []
                }
            }
            // Now and then weeks pass: everything in transit arrives first, as within the 30 days' grace.
            if Int.random(in: 0..<25, using: &generator) == 0 {
                for direction in [Side.alice, .bob] {
                    for message in inFlight[direction, default: []].shuffled(using: &generator) { try conversation.deliver(message) }
                    inFlight[direction] = []
                }
                try conversation.silence(days: Int.random(in: 31...90, using: &generator))
            }
        }
        #expect(conversation.count(.alice, { $0 == .longTerm }) == 0)
        #expect(conversation.count(.bob, { $0 == .longTerm }) == 0)
    }
}

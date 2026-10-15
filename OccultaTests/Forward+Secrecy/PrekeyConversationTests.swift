//
//  PrekeyConversationTests.swift
//  OccultaTests
//
//  ⚠️  Requires a Secure Enclave: prekeys are Enclave blobs, generated as each phone's refills come due.
//
//  Prekey continuity stage 4 (§3.3), end to end: two phones, each with its own identity and its own store, exchange
//  real bundles through `ContactManager.encryptBundle` and `openGroup`. Which phone is "this device" is the
//  `Manager.Ambient` task-local, bound per call. Before each send the sender's `nextSendSecrecy(for:)` says which key
//  the message goes on; every message must open on the other phone; and after every step both records stay within
//  the fixed record's limits.
//
//  `PrekeyConversationSimulationTests` runs the same conversations, longer and randomised, through the bookkeeper
//  alone, on CI too.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta
@testable import OccultaFormats

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

/// SplitMix64, so a shuffled run can be replayed.
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

/// One phone: its identity, its store, and the other phone as its one contact.
@MainActor
private final class Phone {
    let keyManager = TestKeyManager()
    let override: Manager.Ambient.Override
    let contactManager: ContactManager
    /// The other phone's identifier in this store.
    let contactID: String
    var log: [NextSendSecrecy] = []

    init(contactID: String) throws {
        self.override = Manager.Ambient.Override(self.keyManager)
        self.contactID = contactID
        let schema = Schema([
            Group.self,
            Contact.Profile.self,
            Contact.Profile.PhoneNumber.self,
            Contact.Profile.EmailAddress.self,
            Contact.Profile.PostalAddress.self,
            Contact.Profile.URLAddress.self,
            Contact.Profile.Key.self,
        ])
        let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
        self.contactManager = ContactManager(
            modelContainer: container, security: try Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        )
    }

    /// Runs `body` as this phone: `Manager.Ambient` is its identity, so its own store's sealed fields open.
    func run<Result>(_ body: () throws -> Result) throws -> Result {
        try Manager.Ambient.$override.withValue(self.override) { try body() }
    }

    /// The other phone as a contact on a build that signs the prefixed form (1.10.2+), holding no keys either way.
    func add(_ other: Phone) throws {
        try self.run {
            let profile = Contact.Profile(
                identifier: self.contactID, givenName: "", familyName: "", middleName: "",
                nickname: "", organizationName: "", departmentName: "", jobTitle: ""
            )
            profile.contactPublicKeys = [Contact.Profile.Key(
                material: try #require(try Manager.Crypto().encrypt(data: try other.keyManager.retrieveIdentity())),
                owner: Data(), date: Data(), quantumKeyMaterialEncrypted: nil
            )]
            let tier = try #require(OccultaBundle.Version.prefixedSenderSignatureCapable.wireByte)
            profile.maxBundleVersion = try Manager.Crypto().encrypt(data: Data([tier]))
            profile.prekeyRecordEncrypted = try PrekeyRecordCodec().encode(.empty).encrypt()
            try self.contactManager.insertProfile(profile)
        }
    }

    var contact: Contact.Profile {
        get throws { try #require(try self.contactManager.fetchContact(by: self.contactID)) }
    }

    var record: PrekeyRecord {
        get throws { try self.run { try self.contactManager.prekeyRecord(for: try self.contact) } }
    }

    /// A message to the other phone, recording which key it goes on.
    func send() throws -> Data {
        try self.run {
            self.log.append(self.contactManager.nextSendSecrecy(for: try self.contact))
            return try self.contactManager.encryptBundle(basket: Basket(files: []), for: self.contactID)
        }
    }

    func receive(_ encoded: Data) throws {
        try self.run {
            _ = try self.contactManager.openGroup(bundle: try OccultaBundle.decoded(from: encoded), ownerID: self.contactID)
        }
        try Self.checkLimits(try self.record)
    }

    /// What the fixed-size record is budgeted for.
    static func checkLimits(_ record: PrekeyRecord) throws {
        _ = try PrekeyRecordCodec().encode(record)
        #expect(record.ownBatches.filter { $0.retiredAt == nil }.count <= 2)
        #expect(record.ownBatches.reduce(0) { $0 + PrekeyBookkeeper.keyCount($1) } <= PrekeyBookkeeper.maxOwnKeys)
        #expect(record.inboundBatches.count <= PrekeyBookkeeper.maxInboundBatches)
        #expect(record.acceptedBatchIDs.count <= PrekeyBookkeeper.maxAcceptedBatchIDs)
    }

    func count(_ secrecy: NextSendSecrecy) -> Int { self.log.filter { $0 == secrecy }.count }
}

@MainActor
private struct Pair {
    let alice: Phone
    let bob: Phone

    init() throws {
        self.alice = try Phone(contactID: "bob")
        self.bob   = try Phone(contactID: "alice")
        try self.alice.add(self.bob)
        try self.bob.add(self.alice)
    }

    func exchange(from sender: Phone) throws {
        let receiver = sender === self.alice ? self.bob : self.alice
        try receiver.receive(try sender.send())
    }

    /// Alice's first message is long-term and makes Bob a batch; Bob's long-term reply carries it and makes Alice
    /// one; her next goes on one of his keys and carries hers.
    func warmUp() throws {
        try self.exchange(from: self.alice)
        try self.exchange(from: self.bob)
        try self.exchange(from: self.alice)
        #expect(self.alice.log == [.longTerm, .forwardSecret])
        #expect(self.bob.log == [.longTerm])
        self.alice.log = []
        self.bob.log = []
    }
}

@Suite("Prekey conversations, end to end — refill and append (stage 4)", .enabled(if: secureEnclaveAvailable()))
@MainActor struct PrekeyConversationTests {

    @Test("Alternating, 100 messages each way: every one on a one-time key")
    func alternating() throws {
        let pair = try Pair()
        try pair.warmUp()
        for _ in 0..<100 {
            try pair.exchange(from: pair.alice)
            try pair.exchange(from: pair.bob)
        }
        #expect(pair.alice.count(.forwardSecret) == 100)
        #expect(pair.bob.count(.forwardSecret) == 100)
    }

    @Test("Bursts of up to 6, one reply each, through 100 of Bob's keys: every one on a one-time key",
          arguments: [1, 5, 6])
    func burstsWithinThreshold(burst: Int) throws {
        let pair = try Pair()
        try pair.warmUp()
        while pair.alice.count(.forwardSecret) < 100 {
            for _ in 0..<burst { try pair.exchange(from: pair.alice) }
            try pair.exchange(from: pair.bob)
        }
        #expect(pair.alice.log.allSatisfy { $0 == .forwardSecret })
        #expect(pair.bob.log.allSatisfy { $0 == .forwardSecret })
    }

    @Test("Bursts of 10: at most 4 per burst on the temporary key, none long-term")
    func burstsPastThreshold() throws {
        let pair = try Pair()
        try pair.warmUp()
        for _ in 0..<10 {
            let before = pair.alice.count(.temporaryKey)
            for _ in 0..<10 { try pair.exchange(from: pair.alice) }
            #expect(pair.alice.count(.temporaryKey) - before <= 10 - (PrekeyBookkeeper.refillThreshold + 1))
            try pair.exchange(from: pair.bob)
        }
        #expect(pair.alice.count(.longTerm) == 0)
        #expect(pair.bob.log.allSatisfy { $0 == .forwardSecret })
    }

    /// No reply means no new batch, so past the keys she holds Alice seals to Bob's last-resort key (§3.3). It isn't
    /// used up, so all 100 open.
    @Test("One way, 100 messages: the keys held, then the temporary key, all opened; one reply puts her back on one-time keys")
    func oneWay() throws {
        let pair = try Pair()
        try pair.warmUp()
        let held = try pair.alice.record.inboundBatches.reduce(0) { $0 + $1.keys.count }
        #expect(held == 14)

        for _ in 0..<100 { try pair.exchange(from: pair.alice) }
        #expect(pair.alice.log.prefix(held).allSatisfy { $0 == .forwardSecret })
        #expect(pair.alice.log.dropFirst(held).allSatisfy { $0 == .temporaryKey })

        try pair.exchange(from: pair.bob)
        try pair.exchange(from: pair.alice)
        #expect(pair.alice.log.last == .forwardSecret)
    }

    @Test("Alternating with one message in seven lost: every delivered message opens, all on one-time keys")
    func lostMessages() throws {
        let pair = try Pair()
        try pair.warmUp()
        for index in 0..<200 {
            let (sender, receiver) = index.isMultiple(of: 2) ? (pair.alice, pair.bob) : (pair.bob, pair.alice)
            let message = try sender.send()
            if !index.isMultiple(of: 7) { try receiver.receive(message) }
        }
        #expect(pair.alice.log.allSatisfy { $0 == .forwardSecret })
        #expect(pair.bob.log.allSatisfy { $0 == .forwardSecret })
    }

    /// Each direction's messages arrive shuffled within windows of 4, while both keep sending.
    @Test("Out of order within windows of 4: every message opens", arguments: [1, 2] as [UInt64])
    func outOfOrder(seed: UInt64) throws {
        var generator = SeededGenerator(state: seed)
        let pair = try Pair()
        try pair.warmUp()
        var toBob: [Data] = [], toAlice: [Data] = []
        for index in 0..<200 {
            if index.isMultiple(of: 2) { toBob.append(try pair.alice.send()) } else { toAlice.append(try pair.bob.send()) }
            if toBob.count == 4 {
                for message in toBob.shuffled(using: &generator) { try pair.bob.receive(message) }
                toBob = []
            }
            if toAlice.count == 4 {
                for message in toAlice.shuffled(using: &generator) { try pair.alice.receive(message) }
                toAlice = []
            }
        }
        #expect(pair.alice.count(.longTerm) == 0)
        #expect(pair.bob.count(.longTerm) == 0)
    }
}

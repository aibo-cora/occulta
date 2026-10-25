//
//  IdentityChallengeDepthParityTests.swift
//  OccultaTests
//
//  `bugs.md` Bug 180: identity-challenge state is bound to the depth that created it, and a session at any
//  depth sees the same observables for the same actions. One scripted sequence runs on three phones, a
//  depth-0 session, a depth-1 (duress) session and one with Secure Mode off, and every step's observation must
//  be equal. A depth-conditional branch anywhere in the flow fails this.
//
//  Also the expiry rules of the ledger: an entry older than `timestampStaleThreshold` is free to overwrite,
//  the sweep clears it at every depth, and an unswept one still answers `.failed`.
//
//  None of it needs a Secure Enclave: `TestKeyManager` for Secure Mode and the ambient key.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta
@testable import OccultaFormats

// MARK: - Harness

/// A clock the test moves. The coordinator, the manager and Alice's phone all read it.
@MainActor
private final class Clock {
    var seconds: TimeInterval = 1_700_000_000
    var date: Date { Date(timeIntervalSince1970: self.seconds) }
}

/// What a person looking at the screen could tell, after one step.
private struct Observation: Equatable {
    var step: String
    var outcomePassed: Bool?
    var outcomeNote: String?
    var badge: String?
    var waiting: Bool
    var createError: String?
    var errorMessage: String?
    var sharing: Bool
}

@MainActor
private struct Phone {
    let coordinator: IdentityChallenge.Coordinator
    let contacts: ContactManager
    let security: Manager.Security
    let clock: Clock

    /// - Parameter depth: nil is Secure Mode off; 0 is the real layer with Secure Mode on; 1 is the duress layer.
    init(depth: Int?, clock: Clock) throws {
        let schema = Schema([
            AppLayerConfig.self, Group.self, Contact.Profile.self, Contact.Profile.PhoneNumber.self,
            Contact.Profile.EmailAddress.self, Contact.Profile.PostalAddress.self,
            Contact.Profile.URLAddress.self, Contact.Profile.Key.self, VaultEntry.self,
        ])
        let container = try ModelContainer(
            for: schema, configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
        )
        let security = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        let contacts = ContactManager(modelContainer: container, security: security)
        if let depth {
            try security.configurePIN("111111")
            try security.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
            if depth == 1 { try Self.unlock("999999", on: security) }
            #expect(security.currentDepth == depth)
        } else {
            #expect(security.currentDepth == 0)
        }
        self.coordinator = IdentityChallenge.Coordinator(ledger: contacts, sealer: contacts, now: { clock.date })
        self.contacts = contacts
        self.security = security
        self.clock = clock
    }

    static func unlock(_ pin: String, on security: Manager.Security) throws {
        security.applyVerifyState(for: try security.verify(pin))
    }

    func unlock(_ pin: String) throws {
        try Self.unlock(pin, on: self.security)
    }

    /// What `RootView.endSession` clears on a lock or a depth change.
    func endSession() {
        self.coordinator.outboundShare       = nil
        self.coordinator.incomingChallenge   = nil
        self.coordinator.verificationOutcome = nil
    }

    func observe(_ step: String, createError: Error? = nil) -> Observation {
        Observation(
            step: step,
            outcomePassed: self.coordinator.verificationOutcome?.passed,
            outcomeNote: self.coordinator.verificationOutcome?.contextNote,
            badge: self.coordinator.verifiedBadge(for: "alice", now: self.clock.date),
            waiting: self.contacts.hasOutstanding(for: "alice", now: self.clock.date),
            createError: createError.map { String(describing: $0) },
            errorMessage: self.coordinator.errorMessage,
            sharing: self.coordinator.outboundShare != nil
        )
    }
}

/// Alice's phone: she holds her own key, answers whatever we send her, and has no ledger entry of her own.
@MainActor
private struct Alice {
    let keys = TestKeyManager()
    let clock: Clock
    let envelope = IdentityChallengeEnvelope.response(payload: Data())

    func profile() throws -> Contact.Profile {
        let profile = Contact.Profile(
            identifier: "alice", givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        profile.contactPublicKeys = [Contact.Profile.Key(
            material: try Manager.Crypto().encrypt(data: try self.keys.retrieveIdentity()),
            owner: Data(), date: Data(), quantumKeyMaterialEncrypted: nil
        )]
        return profile
    }

    /// Alice answers the challenge in the share sheet now.
    func answer(_ coordinator: IdentityChallenge.Coordinator) throws -> OccultaBundle {
        let file = try #require(coordinator.outboundShare?.url)
        defer { try? FileManager.default.removeItem(at: file) }
        let manager = IdentityChallenge.Manager(
            crypto: Manager.Crypto(keyManager: self.keys), ledger: IdentityChallenge.OutstandingChallengeStore(),
            now: { [clock = self.clock] in clock.date }
        )
        let pending = try manager.decryptChallenge(
            bundle: try OccultaBundle.decoded(from: try Data(contentsOf: file)),
            senderKey: try Manager.Ambient.keyManager.retrieveIdentity(), senderQuantum: nil,
            senderID: "us", senderName: "Us"
        )
        return try manager.respond(to: pending)
    }

    /// A response to a challenge this phone never sent: the stray reply of the sequence.
    func strayAnswer() throws -> OccultaBundle {
        let elsewhere = IdentityChallenge.Manager(
            crypto: Manager.Crypto(), ledger: IdentityChallenge.OutstandingChallengeStore(), now: { [clock = self.clock] in clock.date }
        )
        let challenge = try elsewhere.createChallenge(
            recipientKey: try self.keys.retrieveIdentity(), recipientQuantum: nil, contactID: "alice"
        )
        let manager = IdentityChallenge.Manager(
            crypto: Manager.Crypto(keyManager: self.keys), ledger: IdentityChallenge.OutstandingChallengeStore(),
            now: { [clock = self.clock] in clock.date }
        )
        let pending = try manager.decryptChallenge(
            bundle: challenge, senderKey: try Manager.Ambient.keyManager.retrieveIdentity(), senderQuantum: nil,
            senderID: "us", senderName: "Us"
        )
        return try manager.respond(to: pending)
    }
}

// MARK: - Parity

@Suite("Identity challenge — the same actions look the same at every depth (Bug 180)")
@MainActor struct IdentityChallengeDepthParityTests {

    /// create, second create, badge, genuine reply, replay, stray reply, expired reply, swept reply.
    private func script(_ phone: Phone, clock: Clock) throws -> [Observation] {
        let alice = Alice(clock: clock)
        let profile = try alice.profile()
        var seen: [Observation] = []

        seen.append(phone.observe("open, nothing outstanding"))

        try phone.coordinator.createChallenge(for: profile, contextNote: "first question")
        seen.append(phone.observe("challenge created"))
        let first = try alice.answer(phone.coordinator)
        phone.endSession()

        var failure: Error?
        do { try phone.coordinator.createChallenge(for: profile, contextNote: "second question") } catch { failure = error }
        seen.append(phone.observe("second challenge refused", createError: failure))

        clock.seconds += 60
        phone.coordinator.handleInboundChallenge(bundle: first, envelope: alice.envelope, sender: profile)
        seen.append(phone.observe("genuine reply"))

        phone.coordinator.verificationOutcome = nil
        phone.coordinator.handleInboundChallenge(bundle: first, envelope: alice.envelope, sender: profile)
        seen.append(phone.observe("replay of the settled reply"))

        phone.coordinator.handleInboundChallenge(bundle: try alice.strayAnswer(), envelope: alice.envelope, sender: profile)
        seen.append(phone.observe("reply to a challenge we never sent"))

        // Unanswered past the window, not yet swept: the reply is a failure, with the question.
        try phone.coordinator.createChallenge(for: profile, contextNote: "third question")
        let late = try alice.answer(phone.coordinator)
        phone.endSession()
        clock.seconds += IdentityChallenge.timestampWindow + 1
        seen.append(phone.observe("window passed, not swept"))
        phone.coordinator.handleInboundChallenge(bundle: late, envelope: alice.envelope, sender: profile)
        seen.append(phone.observe("reply after the window, unswept"))

        // The same, swept first: nothing to match, nothing shown.
        phone.coordinator.verificationOutcome = nil
        try phone.coordinator.createChallenge(for: profile, contextNote: nil)
        let swept = try alice.answer(phone.coordinator)
        phone.endSession()
        clock.seconds += IdentityChallenge.timestampStaleThreshold
        phone.coordinator.sweepExpired()
        seen.append(phone.observe("window passed, swept"))
        phone.coordinator.handleInboundChallenge(bundle: swept, envelope: alice.envelope, sender: profile)
        seen.append(phone.observe("reply after the sweep"))

        return seen
    }

    @Test("Depth 0, depth 1 and Secure Mode off give the same observations for the same sequence", .ambientTestKeyManager)
    func sameObservationsEverywhere() throws {
        var results: [[Observation]] = []
        for depth in [0, 1, nil] as [Int?] {
            let clock = Clock()
            results.append(try self.script(try Phone(depth: depth, clock: clock), clock: clock))
        }

        #expect(results[0] == results[1], "depth 0 and depth 1")
        #expect(results[0] == results[2], "depth 0 and Secure Mode off")

        // The sequence did what it says, so equal is not vacuous.
        let seen = Dictionary(uniqueKeysWithValues: results[0].map { ($0.step, $0) })
        #expect(seen["challenge created"]?.waiting == true && seen["challenge created"]?.sharing == true)
        #expect(seen["second challenge refused"]?.createError?.contains("rateLimited") == true)
        #expect(seen["genuine reply"]?.outcomePassed == true && seen["genuine reply"]?.outcomeNote == "first question")
        #expect(seen["genuine reply"]?.badge != nil && seen["genuine reply"]?.waiting == false)
        #expect(seen["replay of the settled reply"]?.outcomePassed == nil)
        #expect(seen["reply to a challenge we never sent"]?.outcomePassed == nil)
        #expect(seen["window passed, not swept"]?.waiting == false, "an expired entry is free")
        #expect(seen["reply after the window, unswept"]?.outcomePassed == false)
        #expect(seen["reply after the window, unswept"]?.outcomeNote == "third question")
        #expect(seen["reply after the sweep"]?.outcomePassed == nil)
    }
}

// MARK: - Expiry

@Suite("Identity challenge ledger — expiry")
@MainActor struct IdentityChallengeLedgerExpiryTests {

    private func challenge(_ clock: Clock, byte: UInt8 = 1) -> IdentityChallenge.OutstandingChallenge {
        .init(nonce: Data(repeating: byte, count: 32), issuedAt: UInt64(clock.seconds))
    }

    @Test("An entry is free at exactly the threshold, and a new challenge overwrites it")
    func freeAtThreshold() throws {
        let clock = Clock()
        let store = IdentityChallenge.OutstandingChallengeStore()
        try store.record(self.challenge(clock, byte: 1), for: "alice", now: clock.date)

        clock.seconds += IdentityChallenge.timestampStaleThreshold - 1
        #expect(store.hasOutstanding(for: "alice", now: clock.date))
        #expect(throws: IdentityChallenge.LedgerError.alreadyOutstanding) {
            try store.record(self.challenge(clock, byte: 2), for: "alice", now: clock.date)
        }

        clock.seconds += 1
        #expect(!store.hasOutstanding(for: "alice", now: clock.date))
        let replacement = self.challenge(clock, byte: 3)
        try store.record(replacement, for: "alice", now: clock.date)
        #expect(store.challenge(for: "alice") == replacement)
        #expect(store.count == 1)
    }

    @Test("A future-dated entry expires by the absolute difference, so a clock set back can't keep it alive")
    func futureDatedExpires() throws {
        let clock = Clock()
        let store = IdentityChallenge.OutstandingChallengeStore()
        let future = IdentityChallenge.OutstandingChallenge(
            nonce: Data(repeating: 9, count: 32), issuedAt: UInt64(clock.seconds + IdentityChallenge.timestampStaleThreshold)
        )
        try store.record(future, for: "alice", now: clock.date)
        #expect(!store.hasOutstanding(for: "alice", now: clock.date), "an hour ahead is already out of the window")

        let nearFuture = IdentityChallenge.OutstandingChallenge(nonce: Data(repeating: 8, count: 32), issuedAt: UInt64(clock.seconds + 60))
        try store.record(nearFuture, for: "alice", now: clock.date)
        #expect(store.hasOutstanding(for: "alice", now: clock.date))
        store.sweepExpired(now: Date(timeIntervalSince1970: clock.seconds + 60 + IdentityChallenge.timestampStaleThreshold))
        #expect(store.count == 0)
    }

    @Test("The sweep clears an expired verified-at, and keeps one that hasn't")
    func sweepClearsVerifiedAt() throws {
        let clock = Clock()
        let store = IdentityChallenge.OutstandingChallengeStore()
        let issued = self.challenge(clock)
        try store.record(issued, for: "alice", now: clock.date)
        store.settle(nonce: issued.nonce, for: "alice", passedAt: clock.date)
        #expect(store.verifiedAt(for: "alice") == clock.date)

        store.sweepExpired(now: Date(timeIntervalSince1970: clock.seconds + IdentityChallenge.timestampStaleThreshold - 1))
        #expect(store.verifiedAt(for: "alice") == clock.date)
        store.sweepExpired(now: Date(timeIntervalSince1970: clock.seconds + IdentityChallenge.timestampStaleThreshold))
        #expect(store.verifiedAt(for: "alice") == nil)
    }

    @Test("Settling with another nonce changes nothing", .ambientTestKeyManager)
    func settleNeedsTheNonce() throws {
        let clock = Clock()
        let store = IdentityChallenge.OutstandingChallengeStore()
        try store.record(self.challenge(clock, byte: 1), for: "alice", now: clock.date)
        store.settle(nonce: Data(repeating: 2, count: 32), for: "alice", passedAt: clock.date)
        #expect(store.hasOutstanding(for: "alice", now: clock.date))
        #expect(store.verifiedAt(for: "alice") == nil)
    }

    @Test("The sweep clears every depth's expired entries and leaves live ones alone", .ambientTestKeyManager)
    func sweepCoversEveryDepth() throws {
        let clock = Clock()
        let phone = try Phone(depth: 0, clock: clock)
        let alice = Alice(clock: clock)
        let profile = try alice.profile()

        try phone.coordinator.createChallenge(for: profile, contextNote: nil)          // depth 0, at t
        phone.endSession()
        try phone.unlock("999999")
        clock.seconds += 1_000
        try phone.coordinator.createChallenge(for: profile, contextNote: nil)          // depth 1, at t + 1000
        let atDepthOne = try #require(phone.contacts.challenge(for: "alice"))
        phone.endSession()

        // Depth 0's is an hour old, depth 1's is not.
        clock.seconds += IdentityChallenge.timestampStaleThreshold - 1_000
        phone.coordinator.sweepExpired()

        #expect(phone.contacts.challenge(for: "alice") == atDepthOne, "the live entry at this depth is untouched")
        try phone.unlock("111111")
        #expect(phone.contacts.challenge(for: "alice") == nil, "the expired entry at the other depth is gone, though no one was there")
    }

    @Test("A late reply to an unswept entry fails, then the contact is free to challenge again", .ambientTestKeyManager)
    func unsweptEntryFailsThenFrees() throws {
        let clock = Clock()
        let phone = try Phone(depth: 0, clock: clock)
        let alice = Alice(clock: clock)
        let profile = try alice.profile()

        try phone.coordinator.createChallenge(for: profile, contextNote: "old question")
        let late = try alice.answer(phone.coordinator)
        clock.seconds += IdentityChallenge.timestampWindow + 1

        phone.coordinator.handleInboundChallenge(bundle: late, envelope: alice.envelope, sender: profile)
        #expect(phone.coordinator.verificationOutcome?.passed == false)
        #expect(phone.coordinator.verificationOutcome?.contextNote == "old question")
        #expect(phone.coordinator.verifiedBadge(for: "alice", now: clock.date) == nil)

        try phone.coordinator.createChallenge(for: profile, contextNote: "new question")
        let fresh = try alice.answer(phone.coordinator)
        phone.coordinator.handleInboundChallenge(bundle: fresh, envelope: alice.envelope, sender: profile)
        #expect(phone.coordinator.verificationOutcome?.passed == true)
        #expect(phone.coordinator.verificationOutcome?.contextNote == "new question", "the old question doesn't follow the contact")
    }

    @Test("A challenge that expires unanswered doesn't block the next one, and its question is replaced", .ambientTestKeyManager)
    func expiredChallengeIsOverwritten() throws {
        let clock = Clock()
        let phone = try Phone(depth: 0, clock: clock)
        let alice = Alice(clock: clock)
        let profile = try alice.profile()

        try phone.coordinator.createChallenge(for: profile, contextNote: "never answered")
        clock.seconds += IdentityChallenge.timestampStaleThreshold
        #expect(!phone.coordinator.hasOutstanding(for: "alice", now: clock.date), "the button is enabled again")

        try phone.coordinator.createChallenge(for: profile, contextNote: nil)
        let reply = try alice.answer(phone.coordinator)
        phone.coordinator.handleInboundChallenge(bundle: reply, envelope: alice.envelope, sender: profile)
        #expect(phone.coordinator.verificationOutcome?.passed == true)
        #expect(phone.coordinator.verificationOutcome?.contextNote == nil)
    }
}

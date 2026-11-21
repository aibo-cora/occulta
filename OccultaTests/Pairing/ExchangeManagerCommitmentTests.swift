//
//  ExchangeManagerCommitmentTests.swift
//  OccultaTests
//
//  Bugs 198 and 199 through the real `ExchangeManager`: two managers wired to each other in memory, each with its own
//  software identity key. No radio is used: messages go through `sendInterceptorForTesting`, the NearbyInteraction gate is
//  `startProtocol(with:)`, and the pauses between steps are milliseconds. What is not covered is the real Multipeer and
//  NearbyInteraction exchange, which needs two phones.
//
//  The classical exchanges run anywhere. The hybrid ones make a real ML-KEM key and carry `.enabled(if:)`.
//

import Testing
import Foundation
import CryptoKit
import MultipeerConnectivity
import NearbyInteraction
@testable import Occulta
@testable import OccultaFormats

// MARK: - Two phones, in memory

private func softwareRecord() -> PrekeyRecord {
    var record = PrekeyRecord.empty
    record.ownBatches = [PrekeyRecord.OwnBatch(
        id: randomBytes(16), createdAt: Date(timeIntervalSinceReferenceDate: 800_000_000), retiredAt: nil, isPending: true,
        keys: (0..<15).map { _ in PrekeyRecord.OwnKey(id: randomBytes(16), blob: nil, publicKey: randomPoint()) },
        lastResort: PrekeyRecord.OwnKey(id: randomBytes(16), blob: nil, publicKey: randomPoint())
    )]
    return record
}

@MainActor
private final class Phone {
    let id: MCPeerID
    let key = TestKeyManager()
    let manager = ExchangeManager()
    let nonce = randomBytes(16)
    /// Everything this phone sent, in order.
    private(set) var sent: [Data] = []

    init(name: String, pairing: Bool, quantum: Bool) {
        self.id = MCPeerID(displayName: name)
        let keys = SoftwareCardKeys()
        keys.failing = !pairing
        self.manager.multipeerSession = MCSession(peer: self.id)
        self.manager.pairKeyProvider = keys
        self.manager.prekeyMaker = { softwareRecord() }
        self.manager.identityProvider = { [key = self.key] in try key.retrieveIdentity() }
        self.manager.stepDelay = .milliseconds(5)
        // Other suites keep the main thread busy for seconds at a time in a full run; a test that is about the deadline sets its own.
        self.manager.stepTimeout = 600
        self.manager.prepareNonceForTesting(self.nonce)
        if quantum { self.manager.preparePostQuantumForTesting() }
    }

    func record(_ data: Data) { self.sent.append(data) }

    var payload: ExchangeManager.ExchangePhase.Payload? {
        switch self.manager.phase {
        case .mlKemExchanged(let payload), .confirming(let payload): return payload
        default: return nil
        }
    }

    var words: [String]? { self.payload.map { KeyExchange.words(for: $0, using: self.key) } }
    var sentExchanges: [Exchange] { self.sent.compactMap { try? JSONDecoder().decode(Exchange.self, from: $0) } }
}

/// Two phones, `a` the initiator (its name sorts lower), and the channel between them. `tamper` sees every message with the
/// sender, and returns what the receiver gets, or nil to drop it.
@MainActor
private final class Loopback {
    let a: Phone
    let b: Phone
    var tamper: ((_ from: Phone, _ data: Data) -> Data?)?
    /// Makes a phone's send of a message fail, as `session.send` can: sees the sender and what the message is.
    var failSend: ((_ from: Phone, _ kind: String) -> Bool)?
    private var queue: [(to: Phone, data: Data)] = []
    /// Sender, then what the message was, for every message on the channel.
    private(set) var log: [(from: Phone, kind: String)] = []

    init(pairing: Bool = false, quantum: Bool = false) {
        self.a = Phone(name: "a-\(UUID().uuidString)", pairing: pairing, quantum: quantum)
        self.b = Phone(name: "b-\(UUID().uuidString)", pairing: pairing, quantum: quantum)
        for (me, peer) in [(self.a, self.b), (self.b, self.a)] {
            // Weak: a task the manager queued can send after the test is over.
            me.manager.sendInterceptorForTesting = { [weak self, weak me] data in
                guard let self, let me else { return }
                if self.failSend?(me, Loopback.kind(of: data)) == true { throw CocoaError(.fileWriteUnknown) }
                me.record(data)
                self.log.append((me, Loopback.kind(of: data)))
                let delivered = self.tamper?(me, data) ?? (self.tamper == nil ? data : nil)
                if let delivered { self.queue.append((peer, delivered)) }
            }
        }
    }

    static func kind(of data: Data) -> String {
        guard let exchange = try? JSONDecoder().decode(Exchange.self, from: data) else { return "?" }
        if exchange.isCardProof { return "proof" }
        if exchange.isNonceReveal { return "reveal" }
        if exchange.isIdentity { return "identity" }
        if exchange.isCiphertext { return "ciphertext" }
        return "discovery"
    }

    /// Connects both phones and starts the exchange, as proximity would.
    func start() async {
        for (me, peer) in [(self.a, self.b), (self.b, self.a)] {
            me.manager.session(me.manager.multipeerSession!, peer: peer.id, didChange: .connected)
        }
        await self.settle()
        self.deliver()
        for (me, peer) in [(self.a, self.b), (self.b, self.a)] { me.manager.startProtocol(with: peer.id) }
    }

    /// Ends both exchanges, so nothing a manager queued acts after the test.
    func end() {
        self.a.manager.finish()
        self.b.manager.finish()
    }

    func settle() async { try? await Task.sleep(for: .milliseconds(100)) }

    /// Hands every queued message to its receiver, in the order they were sent. A discovery message goes to the receiver's
    /// discovery handler directly: its NearbyInteraction token can't be made here.
    func deliver() {
        while !self.queue.isEmpty {
            let item = self.queue.removeFirst()
            let from = item.to === self.a ? self.b : self.a
            if let exchange = try? JSONDecoder().decode(Exchange.self, from: item.data), exchange.isDiscovery {
                item.to.manager.handleDiscovery(exchange, data: item.data, from: from.id)
            } else {
                item.to.manager.handleReceivedData(item.data, from: from.id)
            }
        }
    }

    /// Runs until both phones hold a payload, or `timeout` passes. The timeout is only a ceiling: in a full run another suite can hold
    /// the main thread for minutes, and a test that gave up sooner would fail for that.
    func run(timeout: Duration = .seconds(900)) async {
        let deadline = ContinuousClock.now.advanced(by: timeout)
        while ContinuousClock.now < deadline {
            self.deliver()
            if self.a.payload != nil && self.b.payload != nil { return }
            try? await Task.sleep(for: .milliseconds(10))
        }
    }

    /// Runs until `condition` holds, or `timeout` passes.
    func run(until condition: () -> Bool, timeout: Duration = .seconds(900)) async {
        let deadline = ContinuousClock.now.advanced(by: timeout)
        while ContinuousClock.now < deadline {
            if condition() { return }
            self.deliver()
            try? await Task.sleep(for: .milliseconds(2))
        }
    }

    /// Runs for `duration` whatever happens.
    func runFor(_ duration: Duration) async {
        let deadline = ContinuousClock.now.advanced(by: duration)
        while ContinuousClock.now < deadline {
            self.deliver()
            try? await Task.sleep(for: .milliseconds(10))
        }
    }

    /// What each phone sent, without the discovery messages, which cross at connect.
    var kinds: [String] { self.log.map(\.kind) }
}

private let enclave = TestSupport.secureEnclaveAvailable()

// MARK: - An honest exchange

@MainActor
@Suite("Bug 198 — an honest committed exchange, through the state machine", .serialized)
struct CommittedExchangeTests {

    @Test("Classical, no pair keys: both phones reach the confirmation with the same words, committed")
    func classical() async throws {
        let loop = Loopback()
        defer { loop.end() }
        await loop.start()
        await loop.run()

        let a = try #require(loop.a.payload), b = try #require(loop.b.payload)
        let committed = a.committed
        #expect(committed.transcript == b.committed.transcript, "both hold the same messages")
        #expect(committed.ourNonce == loop.a.nonce && committed.peerNonce == loop.b.nonce)
        #expect(a.hybridResult == nil && a.pairing == nil)
        #expect(loop.a.words == loop.b.words && loop.a.words?.count == 5)
    }

    @Test("The reveals are the last messages, the initiator's first, after every identity message")
    func revealIsLast() async throws {
        let loop = Loopback()
        defer { loop.end() }
        await loop.start()
        await loop.run()

        let tail = loop.kinds.filter { $0 != "discovery" }
        #expect(tail == ["identity", "identity", "reveal", "reveal"], "\(tail)")
        let reveals = loop.log.filter { $0.kind == "reveal" }.map(\.from)
        #expect(reveals.first === loop.a && reveals.last === loop.b, "the initiator reveals first")
    }

    @Test("No nonce is on the wire before its reveal: discovery carries a commitment and nothing else of it")
    func nonceStaysSecret() async throws {
        let loop = Loopback()
        defer { loop.end() }
        await loop.start()
        await loop.run()

        for phone in [loop.a, loop.b] {
            for exchange in phone.sentExchanges where !exchange.isNonceReveal {
                #expect(exchange.nonce == nil, "no nonce in the clear")
            }
            let discovery = try #require(phone.sentExchanges.first { $0.isDiscovery })
            #expect(discovery.nonceCommitment == ExchangeCommitment.commitment(to: phone.nonce))
            let reveal = try #require(phone.sentExchanges.first { $0.isNonceReveal })
            #expect(reveal.revealedNonce == phone.nonce)
        }
    }

    @Test("A phone reveals only after it holds every message of the peer's that comes before the reveal")
    func revealFollowsEveryOtherMessage() async throws {
        let loop = Loopback()
        defer { loop.end() }
        await loop.start()
        await loop.run()

        // Each phone's first reveal comes after the last identity message that the other sent.
        for phone in [loop.a, loop.b] {
            let revealAt = try #require(loop.log.firstIndex { $0.from === phone && $0.kind == "reveal" })
            let lastOther = try #require(loop.log.lastIndex { $0.from !== phone && ($0.kind == "identity" || $0.kind == "discovery") })
            #expect(lastOther < revealAt)
        }
    }

    @Test("With pair keys: the offer carries the exchange transcript, and both phones derive the same routing key")
    func withPairKeys() async throws {
        let loop = Loopback(pairing: true)
        defer { loop.end() }
        await loop.start()
        await loop.run()

        let a = try #require(loop.a.payload), b = try #require(loop.b.payload)
        let offerA = try #require(a.pairing), offerB = try #require(b.pairing)
        #expect(offerA.exchangeTranscript == a.committed.transcript)
        let routingA = try #require(offerA.routingKey(withPeer: a.classicalKey, quantum: nil, using: loop.a.key))
        let routingB = try #require(offerB.routingKey(withPeer: b.classicalKey, quantum: nil, using: loop.b.key))
        #expect(routingA == routingB)
        #expect(loop.a.words == loop.b.words)
    }

    @Test("Hybrid: both phones reach the confirmation with the same words and a hybrid result, committed", .enabled(if: enclave))
    func hybrid() async throws {
        let loop = Loopback(pairing: true, quantum: true)
        defer { loop.end() }
        await loop.start()
        await loop.run()

        let a = try #require(loop.a.payload), b = try #require(loop.b.payload)
        #expect(a.hybridResult != nil && b.hybridResult != nil)
        #expect(a.committed.transcript == b.committed.transcript)
        #expect(loop.a.words == loop.b.words)
        let tail = loop.kinds.filter { $0 != "discovery" && $0 != "proof" }
        #expect(tail == ["identity", "identity", "ciphertext", "ciphertext", "reveal", "reveal"], "\(tail)")
    }
}

// MARK: - A man in the middle

@MainActor
@Suite("Bugs 198 and 199 — a relay that changes what it passes on", .serialized)
struct RelayTests {

    /// Re-encodes `data` as the same message with the ML-KEM key removed.
    private static func strippingKey(_ data: Data) -> Data {
        guard let exchange = try? JSONDecoder().decode(Exchange.self, from: data), exchange.isIdentity else { return data }
        let stripped = Exchange(
            id: exchange.id, token: exchange.token, version: exchange.version, identity: exchange.identity,
            encapsulationKey: nil, pairing: exchange.pairing
        )
        return (try? JSONEncoder().encode(stripped)) ?? data
    }

    @Test("Bug 199: a relay that removes the ML-KEM key from both identity messages makes the words differ, so the exchange does not match",
          .enabled(if: enclave))
    func strippedMLKEMChangesTheWords() async throws {
        let loop = Loopback(pairing: true, quantum: true)
        defer { loop.end() }
        loop.tamper = { _, data in Self.strippingKey(data) }
        await loop.start()
        await loop.run()

        let a = try #require(loop.a.payload), b = try #require(loop.b.payload)
        #expect(a.hybridResult == nil && b.hybridResult == nil, "both fell back to the classical branch")
        #expect(a.offeredQuantum && b.offeredQuantum, "each phone knows it sent a key and got none")
        #expect(loop.a.words != loop.b.words, "the people comparing the words find they differ")
    }

    @Test("A relay that changes a prekey batch's generatedAt on one leg makes the words differ")
    func changedBatchChangesTheWords() async throws {
        let loop = Loopback(pairing: true)
        defer { loop.end() }
        loop.tamper = { [unowned loop] from, data in
            guard from === loop.a, let exchange = try? JSONDecoder().decode(Exchange.self, from: data), exchange.isIdentity,
                  let pairing = exchange.pairing else { return data }
            let batch = pairing.prekeyBatch
            let moved = OccultaBundle.SealedPayload.PrekeySyncBatch(
                generatedAt: batch.generatedAt.addingTimeInterval(1), prekeys: batch.prekeys, id: batch.id, lastResort: batch.lastResort
            )
            let field = Exchange.PairingField(
                prekeyBatch: moved, agreementKey: pairing.agreementKey, signingKey: pairing.signingKey, mldsaKey: pairing.mldsaKey
            )
            let changed = Exchange(
                id: exchange.id, token: exchange.token, version: exchange.version, identity: exchange.identity,
                encapsulationKey: exchange.encapsulationKey, pairing: field
            )
            return (try? JSONEncoder().encode(changed)) ?? data
        }
        await loop.start()
        await loop.run()

        #expect(loop.a.payload != nil && loop.b.payload != nil)
        #expect(loop.a.words != loop.b.words)
    }

    @Test("A revealed nonce that does not open its commitment ends the exchange")
    func wrongNonceFails() async throws {
        let loop = Loopback()
        defer { loop.end() }
        loop.tamper = { from, data in
            guard let exchange = try? JSONDecoder().decode(Exchange.self, from: data), exchange.isNonceReveal else { return data }
            return try? JSONEncoder().encode(Exchange(id: exchange.id, token: Data(), version: .v1, revealedNonce: randomBytes(16)))
        }
        await loop.start()
        await loop.run(until: { loop.b.manager.phase == .failed })

        #expect(loop.a.payload == nil && loop.b.payload == nil)
        #expect(loop.b.manager.phase == .failed, "the responder got the initiator's altered reveal")
    }

    @Test("A reveal that reflects the receiver's own nonce ends the exchange")
    func reflectedNonceFails() async throws {
        let loop = Loopback()
        defer { loop.end() }
        loop.tamper = { [unowned loop] from, data in
            guard let exchange = try? JSONDecoder().decode(Exchange.self, from: data), exchange.isNonceReveal, from === loop.a else { return data }
            return try? JSONEncoder().encode(Exchange(id: exchange.id, token: Data(), version: .v1, revealedNonce: loop.b.nonce))
        }
        await loop.start()
        await loop.run(until: { loop.b.manager.phase == .failed })

        #expect(loop.b.manager.phase == .failed)
    }

    @Test("A reveal that arrives before the exchange is ready for it is ignored")
    func earlyRevealIgnored() async throws {
        let loop = Loopback()
        defer { loop.end() }
        await loop.start()
        // The initiator's first message is not out yet: the responder is waiting for an identity, not a reveal.
        let early = try JSONEncoder().encode(Exchange(id: "x", token: Data(), version: .v1, revealedNonce: loop.a.nonce))
        loop.b.manager.handleReceivedData(early, from: loop.a.id)

        #expect(loop.b.manager.phase != .failed)
        #expect(loop.b.manager.peerNonceForTesting == nil)
        await loop.run()
        #expect(loop.a.words == loop.b.words && loop.a.words != nil, "and the exchange still completes")
    }

    @Test("A second identity message, sent while the responder is about to answer, does not replace the first")
    func secondIdentityIgnored() async throws {
        let loop = Loopback()
        defer { loop.end() }
        loop.b.manager.stepDelay = .milliseconds(400)
        await loop.start()
        func holdsIdentity() -> Bool {
            if case .identityExchanged = loop.b.manager.phase { return true }
            return false
        }
        await loop.run(until: holdsIdentity)
        try #require(holdsIdentity(), "the responder holds the initiator's identity")

        // In the window before the responder answers, a second identity message from the pinned peer.
        let other = Exchange(id: "late", token: Data([1]), version: .v1, identity: randomPoint())
        loop.b.manager.handleReceivedData(try JSONEncoder().encode(other), from: loop.a.id)
        await loop.run()

        let payload = try #require(loop.b.payload)
        #expect(payload.classicalKey == (try loop.a.key.retrieveIdentity()), "the first identity message is the one that counts")
        #expect(loop.a.words == loop.b.words && loop.a.words != nil)
    }
}

// MARK: - One discovery message per exchange

@MainActor
@Suite("Bug 198 — one discovery message per exchange")
struct DiscoveryOnceTests {

    private func connected() async throws -> (manager: ExchangeManager, peer: MCPeerID) {
        let manager = ExchangeManager()
        manager.multipeerSession = MCSession(peer: MCPeerID(displayName: "a-\(UUID().uuidString)"))
        manager.prepareNonceForTesting(randomBytes(16))
        manager.sendInterceptorForTesting = { _ in }
        manager.prekeyMaker = { softwareRecord() }
        manager.pairKeyProvider = { let keys = SoftwareCardKeys(); keys.failing = true; return keys }()
        let peer = MCPeerID(displayName: "b-\(UUID().uuidString)")
        manager.session(manager.multipeerSession!, peer: peer, didChange: .connected)
        try await Task.sleep(for: .milliseconds(100))
        try #require(manager.connectedPeerID == peer)
        return (manager, peer)
    }

    private func discovery(commitment: Data? = nil, nonce: Data? = nil) throws -> (exchange: Exchange, data: Data) {
        let exchange = Exchange(id: UUID().uuidString, token: Data([1]), version: .v1, nonce: nonce, nonceCommitment: commitment)
        return (exchange, try JSONEncoder().encode(exchange))
    }

    @Test("A second discovery message does not replace the commitment")
    func commitmentKept() async throws {
        let (manager, peer) = try await self.connected()
        defer { manager.finish() }
        let first = try #require(ExchangeCommitment.commitment(to: randomBytes(16)))
        let second = try #require(ExchangeCommitment.commitment(to: randomBytes(16)))

        let one = try self.discovery(commitment: first), two = try self.discovery(commitment: second)
        #expect(manager.handleDiscovery(one.exchange, data: one.data, from: peer))
        #expect(!manager.handleDiscovery(two.exchange, data: two.data, from: peer))

        #expect(manager.peerCommitmentForTesting == first)
    }

    @Test("A nonce in the clear cannot follow a commitment to turn the exchange into an uncommitted one")
    func clearNonceAfterCommitment() async throws {
        let (manager, peer) = try await self.connected()
        defer { manager.finish() }
        let commitment = try #require(ExchangeCommitment.commitment(to: randomBytes(16)))

        let one = try self.discovery(commitment: commitment), two = try self.discovery(nonce: randomBytes(16))
        manager.handleDiscovery(one.exchange, data: one.data, from: peer)
        manager.handleDiscovery(two.exchange, data: two.data, from: peer)

        #expect(manager.peerCommitmentForTesting == commitment)
        #expect(manager.peerNonceForTesting == nil)
        #expect(manager.phase != .peerNeedsUpdate, "the second message is ignored, it does not end the exchange")
    }

    @Test("A discovery message from a peer that is not the pinned one changes nothing")
    func otherPeerIgnored() async throws {
        let (manager, _) = try await self.connected()
        defer { manager.finish() }
        let one = try self.discovery(nonce: randomBytes(16))

        #expect(!manager.handleDiscovery(one.exchange, data: one.data, from: MCPeerID(displayName: "intruder")))
        #expect(manager.peerNonceForTesting == nil)
        #expect(manager.phase != .peerNeedsUpdate, "a message from another peer neither ends the exchange nor counts")
    }
}

// MARK: - A peer that does not commit is refused

/// Counts calls, for a closure the manager holds.
private final class Counter { var count = 0 }

@MainActor
@Suite("Bug 198 — a peer whose discovery message carries no commitment is refused", .serialized)
struct UncommittedPeerTests {

    /// A phone with pair keys, connected to a scripted peer. `initiator` sets which role it has: the lower name initiates.
    private func connected(initiator: Bool) async throws -> (phone: Phone, peer: MCPeerID, prekeysMade: Counter) {
        let phone = Phone(name: "\(initiator ? "a" : "b")-\(UUID().uuidString)", pairing: true, quantum: false)
        let made = Counter()
        phone.manager.prekeyMaker = { made.count += 1; return softwareRecord() }
        phone.manager.sendInterceptorForTesting = { [weak phone] in phone?.record($0) }
        let peer = MCPeerID(displayName: "\(initiator ? "b" : "a")-\(UUID().uuidString)")
        phone.manager.session(phone.manager.multipeerSession!, peer: peer, didChange: .connected)
        try await Task.sleep(for: .milliseconds(100))
        try #require(phone.manager.connectedPeerID == peer)
        return (phone, peer, made)
    }

    /// A discovery message of a build older than 2.0.5: its nonce in the clear, and no commitment.
    private func olderDiscovery() throws -> (exchange: Exchange, data: Data) {
        let exchange = Exchange(id: UUID().uuidString, token: Data([1]), version: .v1, nonce: randomBytes(16))
        return (exchange, try JSONEncoder().encode(exchange))
    }

    @Test("An older build's discovery ends the exchange in either role, sends nothing, and keeps nothing", arguments: [true, false])
    func olderBuildRefused(initiator: Bool) async throws {
        let (phone, peer, made) = try await self.connected(initiator: initiator)
        defer { phone.manager.finish() }
        try #require(made.count == 1, "the first prekeys are made when the peer connects")
        try #require(phone.manager.ownPrekeys != nil)
        let sentBefore = phone.sent.count

        let older = try self.olderDiscovery()
        phone.manager.handleDiscovery(older.exchange, data: older.data, from: peer)

        #expect(phone.manager.phase == .peerNeedsUpdate)
        #expect(phone.sent.count == sentBefore, "nothing goes out in answer: no nonce, no identity")
        #expect(phone.manager.ownPrekeys == nil && phone.manager.ownPairKeys == nil && phone.manager.ownPairingField == nil,
                "the prekeys and pair keys made for this peer are discarded")
        #expect(phone.manager.connectedPeerID == nil && phone.manager.peerCommitmentForTesting == nil && phone.manager.peerNonceForTesting == nil)
        #expect(!phone.manager.isStepDeadlineArmed && !phone.manager.isWatchdogArmed, "nothing is left running")
        #expect(phone.payload == nil, "there is nothing to confirm and nothing to save")
    }

    @Test("The exchange cannot be started, and a later message from that peer is not taken", arguments: [true, false])
    func nothingFollows(initiator: Bool) async throws {
        let (phone, peer, _) = try await self.connected(initiator: initiator)
        defer { phone.manager.finish() }
        let older = try self.olderDiscovery()
        phone.manager.handleDiscovery(older.exchange, data: older.data, from: peer)
        try #require(phone.manager.phase == .peerNeedsUpdate)

        phone.manager.startProtocol(with: peer)
        #expect(!phone.manager.isStepDeadlineArmed)
        try await Task.sleep(for: .milliseconds(100))
        #expect(!phone.sentExchanges.contains { $0.isIdentity }, "no identity goes to a refused peer")

        // The peer follows with a discovery message that does commit, and with its identity.
        let commitment = try #require(ExchangeCommitment.commitment(to: randomBytes(16)))
        let late = Exchange(id: "x", token: Data([1]), version: .v1, nonceCommitment: commitment)
        #expect(!phone.manager.handleDiscovery(late, data: try JSONEncoder().encode(late), from: peer))
        phone.manager.handleReceivedData(try JSONEncoder().encode(Exchange(id: "y", token: Data([1]), version: .v1, identity: randomPoint())), from: peer)
        #expect(phone.manager.peerCommitmentForTesting == nil)
        #expect(phone.manager.phase == .peerNeedsUpdate && phone.payload == nil)
    }

    @Test("A discovery message with a malformed commitment is no commitment", arguments: [0, 31, 33])
    func malformedCommitment(size: Int) async throws {
        let (phone, peer, _) = try await self.connected(initiator: true)
        defer { phone.manager.finish() }
        let exchange = Exchange(id: "x", token: Data([1]), version: .v1, nonce: randomBytes(16), nonceCommitment: Data(count: size))

        phone.manager.handleDiscovery(exchange, data: try JSONEncoder().encode(exchange), from: peer)

        #expect(phone.manager.phase == .peerNeedsUpdate)
    }

    @Test("An identity or ciphertext message before the peer has committed is not taken")
    func identityBeforeCommitment() async throws {
        let (phone, peer, _) = try await self.connected(initiator: false)
        defer { phone.manager.finish() }
        // The exchange is somehow running, as a stale NearbyInteraction update could start it, with no commitment held.
        phone.manager.waitForPeerIdentityForTesting()

        let identity = Exchange(id: "x", token: Data([1]), version: .v1, identity: randomPoint())
        phone.manager.handleReceivedData(try JSONEncoder().encode(identity), from: peer)
        let ciphertext = Exchange(id: "y", token: Data([1]), version: .v1, ciphertext: randomBytes(64))
        phone.manager.handleReceivedData(try JSONEncoder().encode(ciphertext), from: peer)

        #expect(phone.manager.phase == .found, "nothing moved")
        #expect(phone.payload == nil)
    }

    // MARK: Between two phones

    /// A relay that passes everything on but rewrites the discovery message of `sender`.
    private func rewriting(_ sender: KeyPath<Loopback, Phone>, in loop: Loopback, to rewrite: @escaping (Exchange) -> Exchange) {
        loop.tamper = { [unowned loop] from, data in
            guard from === loop[keyPath: sender], let exchange = try? JSONDecoder().decode(Exchange.self, from: data), exchange.isDiscovery else {
                return data
            }
            return try? JSONEncoder().encode(rewrite(exchange))
        }
    }

    @Test("A relay that removes the commitment from one side's discovery: the receiving phone refuses, the other times out", arguments: [true, false])
    func removedFromOneSide(fromInitiator: Bool) async throws {
        let loop = Loopback(pairing: true)
        defer { loop.end() }
        let (sender, receiver) = fromInitiator ? (loop.a, loop.b) : (loop.b, loop.a)
        for phone in [loop.a, loop.b] { phone.manager.stepTimeout = 0.3 }
        self.rewriting(fromInitiator ? \.a : \.b, in: loop) { Exchange(id: $0.id, token: $0.token, version: $0.version) }
        await loop.start()
        await loop.run(until: { receiver.manager.phase == .peerNeedsUpdate && sender.manager.phase == .timedOut })

        #expect(receiver.manager.phase == .peerNeedsUpdate)
        #expect(receiver.manager.ownPrekeys == nil && receiver.manager.ownPairKeys == nil, "nothing made for the refused peer is kept")
        #expect(!receiver.sentExchanges.contains { $0.isIdentity || $0.isNonceReveal }, "it sent no identity and no nonce")
        #expect(sender.manager.phase == .timedOut, "the phone that was not refused waits out its deadline")
        #expect(loop.a.payload == nil && loop.b.payload == nil)
    }

    @Test("A relay that swaps the commitment for a nonce in the clear is refused the same way")
    func swappedForANonce() async throws {
        let loop = Loopback(pairing: true)
        defer { loop.end() }
        self.rewriting(\.a, in: loop) { Exchange(id: $0.id, token: $0.token, version: $0.version, nonce: randomBytes(16)) }
        await loop.start()
        await loop.run(until: { loop.b.manager.phase == .peerNeedsUpdate })

        #expect(loop.b.manager.phase == .peerNeedsUpdate)
        #expect(loop.b.payload == nil)
    }

    @Test("A relay that removes both commitments: both phones refuse")
    func removedFromBoth() async throws {
        let loop = Loopback(pairing: true)
        defer { loop.end() }
        loop.tamper = { _, data in
            guard let exchange = try? JSONDecoder().decode(Exchange.self, from: data), exchange.isDiscovery else { return data }
            return try? JSONEncoder().encode(Exchange(id: exchange.id, token: exchange.token, version: exchange.version))
        }
        await loop.start()
        await loop.run(until: { loop.a.manager.phase == .peerNeedsUpdate && loop.b.manager.phase == .peerNeedsUpdate })

        #expect(loop.a.manager.phase == .peerNeedsUpdate && loop.b.manager.phase == .peerNeedsUpdate)
        #expect(loop.kinds.filter { $0 != "discovery" }.isEmpty, "no message but the two discoveries was sent")
        #expect(loop.a.payload == nil && loop.b.payload == nil)
        for phone in [loop.a, loop.b] { #expect(phone.manager.ownPrekeys == nil && phone.manager.ownPairKeys == nil) }
    }

    @Test("Two phones that both commit still pair, with and without pair keys", arguments: [true, false])
    func committedPhonesPair(pairing: Bool) async throws {
        let loop = Loopback(pairing: pairing)
        defer { loop.end() }
        await loop.start()
        await loop.run()

        #expect(loop.a.manager.phase != .peerNeedsUpdate && loop.b.manager.phase != .peerNeedsUpdate)
        #expect(loop.a.payload != nil && loop.b.payload != nil)
        #expect(loop.a.words == loop.b.words && loop.a.words != nil)
    }

    @Test("A message of an older build's kind, with no new field, is byte-identical to what it was")
    func oldMessagesUnchanged() throws {
        let discovery = Exchange(id: "x", token: Data([1]), version: .v1, nonce: Data(count: 16))
        let identity = Exchange(id: "x", token: Data([1]), version: .v1, identity: Data(count: 65))
        for message in [discovery, identity] {
            let json = try #require(String(data: try JSONEncoder().encode(message), encoding: .utf8))
            #expect(!json.contains("nonceCommitment") && !json.contains("revealedNonce"))
        }
        let commit = Exchange(id: "x", token: Data([1]), version: .v1, nonceCommitment: Data(count: 32))
        #expect(commit.isDiscovery && !commit.isNonceReveal)
        let reveal = Exchange(id: "x", token: Data(), version: .v1, revealedNonce: Data(count: 16))
        #expect(reveal.isNonceReveal && !reveal.isDiscovery && !reveal.isIdentity && !reveal.isCiphertext)
    }
}

// MARK: - The deadline

@MainActor
@Suite("Bug 198 — a deadline for each step that ranging does not reset", .serialized)
struct StepDeadlineTests {

    @Test("A phone that is waiting and keeps being ranged times out; ranging does not keep it alive")
    func rangingDoesNotResetIt() async throws {
        let manager = ExchangeManager()
        manager.multipeerSession = MCSession(peer: MCPeerID(displayName: "a-\(UUID().uuidString)"))
        manager.sendInterceptorForTesting = { _ in }
        manager.prekeyMaker = { softwareRecord() }
        manager.pairKeyProvider = { let keys = SoftwareCardKeys(); keys.failing = true; return keys }()
        manager.prepareNonceForTesting(randomBytes(16))
        manager.stepTimeout = 0.4
        let peer = MCPeerID(displayName: "b-peer")
        manager.session(manager.multipeerSession!, peer: peer, didChange: .connected)
        try await Task.sleep(for: .milliseconds(100))
        let commitment = try #require(ExchangeCommitment.commitment(to: randomBytes(16)))
        let discovery = Exchange(id: "x", token: Data([1]), version: .v1, nonceCommitment: commitment)
        try #require(manager.handleDiscovery(discovery, data: try JSONEncoder().encode(discovery), from: peer))
        manager.startProtocol(with: peer)
        #expect(manager.isStepDeadlineArmed)

        let session = NISession()
        for _ in 0..<12 {
            manager.session(session, didUpdate: [])
            try await Task.sleep(for: .milliseconds(100))
        }

        #expect(manager.phase == .timedOut, "twelve ranging updates over 1.2 s did not move a 0.4 s deadline")
        #expect(!manager.isStepDeadlineArmed)
        manager.finish()
    }

    @Test("Before the exchange starts, ranging still resets the watchdog as it always did")
    func rangingResetsTheWatchdogBeforeTheStart() async throws {
        let manager = ExchangeManager()
        manager.multipeerSession = MCSession(peer: MCPeerID(displayName: "a-\(UUID().uuidString)"))
        manager.session(NISession(), didUpdate: [])
        try await Task.sleep(for: .milliseconds(100))
        #expect(manager.isWatchdogArmed)
        #expect(!manager.isStepDeadlineArmed)
        manager.finish()
    }

    @Test("Every step moves the deadline: it is armed at the start and again for each message sent or received")
    func progressMovesTheDeadline() async throws {
        let loop = Loopback()
        defer { loop.end() }
        await loop.start()
        await loop.run()

        // Classical: the start, then the initiator's identity out and in, the responder's identity out and in, a reveal out and
        // in on each side. Counted, not timed: a full run keeps the main thread busy for seconds at a time.
        for phone in [loop.a, loop.b] {
            #expect(phone.manager.stepDeadlineArmCountForTesting >= 5, "\(phone.manager.stepDeadlineArmCountForTesting) times")
        }
        #expect(loop.a.payload != nil && loop.b.payload != nil)
    }

    @Test("A deadline passing ends the exchange and nothing is left armed")
    func endsTheExchange() async throws {
        let loop = Loopback()
        defer { loop.end() }
        for phone in [loop.a, loop.b] { phone.manager.stepTimeout = 0.3 }
        // The discovery messages cross, so ranging starts the exchange; nothing after them does.
        loop.tamper = { _, data in Loopback.kind(of: data) == "discovery" ? data : nil }
        await loop.start()
        await loop.run(until: { loop.a.manager.phase == .timedOut && loop.b.manager.phase == .timedOut })

        #expect(loop.a.manager.phase == .timedOut && loop.b.manager.phase == .timedOut)
        #expect(loop.a.payload == nil && loop.b.payload == nil)
    }
}

// MARK: - A send that fails

@Suite("Bug 198 — a message that could not be sent ends the exchange", .serialized)
struct SendFailureTests {

    /// Only a ceiling, like the others: a full run can hold the main thread for minutes.
    static let ceiling: Duration = .seconds(900)

    /// Nothing but the failure is the reason for the end: the phone said so and nothing is left armed.
    @MainActor
    private func expectEnded(_ phone: Phone, sourceLocation: SourceLocation = #_sourceLocation) {
        #expect(phone.manager.phase == .failed, sourceLocation: sourceLocation)
        #expect(phone.payload == nil, sourceLocation: sourceLocation)
        #expect(!phone.manager.isStepDeadlineArmed, "no deadline is left running", sourceLocation: sourceLocation)
    }

    @Test("The initiator's identity cannot be sent")
    @MainActor func initiatorIdentity() async throws {
        let loop = Loopback()
        defer { loop.end() }
        loop.failSend = { from, kind in from === loop.a && kind == "identity" }
        await loop.start()
        await loop.run(until: { loop.a.manager.phase == .failed }, timeout: Self.ceiling)

        self.expectEnded(loop.a)
        #expect(!loop.kinds.contains("identity"), "nothing went out in its place")
    }

    @Test("Our identity key cannot be read")
    @MainActor func identityUnavailable() async throws {
        let loop = Loopback()
        defer { loop.end() }
        loop.a.manager.identityProvider = { throw CocoaError(.fileReadUnknown) }
        await loop.start()
        await loop.run(until: { loop.a.manager.phase == .failed }, timeout: Self.ceiling)

        self.expectEnded(loop.a)
    }

    @Test("The responder's identity cannot be sent: it does not go on to wait for a reveal")
    @MainActor func responderIdentity() async throws {
        let loop = Loopback()
        defer { loop.end() }
        loop.failSend = { from, kind in from === loop.b && kind == "identity" }
        await loop.start()
        await loop.run(until: { loop.b.manager.phase == .failed }, timeout: Self.ceiling)

        self.expectEnded(loop.b)
        #expect(!loop.log.contains { $0.from === loop.b && $0.kind == "reveal" })
    }

    @Test("The initiator's reveal cannot be sent")
    @MainActor func initiatorReveal() async throws {
        let loop = Loopback()
        defer { loop.end() }
        loop.failSend = { from, kind in from === loop.a && kind == "reveal" }
        await loop.start()
        await loop.run(until: { loop.a.manager.phase == .failed }, timeout: Self.ceiling)

        self.expectEnded(loop.a)
    }

    @Test("The responder's reveal cannot be sent: it does not conclude an exchange the peer cannot")
    @MainActor func responderReveal() async throws {
        let loop = Loopback()
        defer { loop.end() }
        loop.failSend = { from, kind in from === loop.b && kind == "reveal" }
        await loop.start()
        await loop.run(until: { loop.b.manager.phase == .failed }, timeout: Self.ceiling)

        self.expectEnded(loop.b)
    }

    @Test("The initiator's ciphertext cannot be sent", .enabled(if: enclave))
    @MainActor func initiatorCiphertext() async throws {
        let loop = Loopback(pairing: true, quantum: true)
        defer { loop.end() }
        loop.failSend = { from, kind in from === loop.a && kind == "ciphertext" }
        await loop.start()
        await loop.run(until: { loop.a.manager.phase == .failed }, timeout: Self.ceiling)

        self.expectEnded(loop.a)
    }

    @Test("The responder's ciphertext cannot be sent", .enabled(if: enclave))
    @MainActor func responderCiphertext() async throws {
        let loop = Loopback(pairing: true, quantum: true)
        defer { loop.end() }
        loop.failSend = { from, kind in from === loop.b && kind == "ciphertext" }
        await loop.start()
        await loop.run(until: { loop.b.manager.phase == .failed }, timeout: Self.ceiling)

        self.expectEnded(loop.b)
    }
}

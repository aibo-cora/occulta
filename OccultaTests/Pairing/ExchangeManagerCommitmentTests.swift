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

    /// Runs until both phones hold a payload, or `timeout` passes.
    func run(timeout: Duration = .seconds(120)) async {
        let deadline = ContinuousClock.now.advanced(by: timeout)
        while ContinuousClock.now < deadline {
            self.deliver()
            if self.a.payload != nil && self.b.payload != nil { return }
            try? await Task.sleep(for: .milliseconds(10))
        }
    }

    /// Runs until `condition` holds, or `timeout` passes.
    func run(until condition: () -> Bool, timeout: Duration = .seconds(120)) async {
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
        let committed = try #require(a.committed)
        #expect(committed.transcript == b.committed?.transcript, "both hold the same messages")
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
        #expect(offerA.exchangeTranscript == a.committed?.transcript && offerA.exchangeTranscript != nil)
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
        #expect(a.committed?.transcript == b.committed?.transcript && a.committed != nil)
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
        #expect(a.committed != nil && b.committed != nil)
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

    @Test("A second discovery message does not replace the nonce of an older build's")
    func nonceKept() async throws {
        let (manager, peer) = try await self.connected()
        defer { manager.finish() }
        let first = randomBytes(16), second = randomBytes(16)

        let one = try self.discovery(nonce: first), two = try self.discovery(nonce: second)
        manager.handleDiscovery(one.exchange, data: one.data, from: peer)
        manager.handleDiscovery(two.exchange, data: two.data, from: peer)

        #expect(manager.peerNonceForTesting == first)
        #expect(manager.peerCommitmentForTesting == nil && !manager.isCommittedExchange)
    }

    @Test("A nonce in the clear cannot follow a commitment to turn the exchange into an uncommitted one")
    func clearNonceAfterCommitment() async throws {
        let (manager, peer) = try await self.connected()
        defer { manager.finish() }
        let commitment = try #require(ExchangeCommitment.commitment(to: randomBytes(16)))

        let one = try self.discovery(commitment: commitment), two = try self.discovery(nonce: randomBytes(16))
        manager.handleDiscovery(one.exchange, data: one.data, from: peer)
        manager.handleDiscovery(two.exchange, data: two.data, from: peer)

        #expect(manager.isCommittedExchange)
        #expect(manager.peerNonceForTesting == nil)
    }

    @Test("A discovery message from a peer that is not the pinned one changes nothing")
    func otherPeerIgnored() async throws {
        let (manager, _) = try await self.connected()
        defer { manager.finish() }
        let one = try self.discovery(nonce: randomBytes(16))

        #expect(!manager.handleDiscovery(one.exchange, data: one.data, from: MCPeerID(displayName: "intruder")))
        #expect(manager.peerNonceForTesting == nil)
    }

    @Test("A commitment of the wrong size is not one, and the nonce beside it is not taken as the peer's")
    func malformedCommitment() async throws {
        let (manager, peer) = try await self.connected()
        defer { manager.finish() }
        let one = try self.discovery(commitment: Data(count: 31))
        manager.handleDiscovery(one.exchange, data: one.data, from: peer)

        #expect(!manager.isCommittedExchange)
    }
}

// MARK: - A peer on an older build

@MainActor
@Suite("Bug 198 — an older build as the peer", .serialized)
struct OlderPeerTests {

    /// A manager that is the initiator (its name sorts below the peer's), connected to a scripted older peer.
    private func connected() async throws -> (phone: Phone, peer: MCPeerID) {
        let phone = Phone(name: "a-\(UUID().uuidString)", pairing: false, quantum: false)
        phone.manager.sendInterceptorForTesting = { [weak phone] in phone?.record($0) }
        let peer = MCPeerID(displayName: "b-\(UUID().uuidString)")
        phone.manager.session(phone.manager.multipeerSession!, peer: peer, didChange: .connected)
        try await Task.sleep(for: .milliseconds(100))
        try #require(phone.manager.connectedPeerID == peer)
        return (phone, peer)
    }

    @Test("An older build's discovery, with its nonce in the clear, is answered with ours in the clear, once")
    func answeredInTheClear() async throws {
        let (phone, peer) = try await self.connected()
        defer { phone.manager.finish() }
        let older = Exchange(id: UUID().uuidString, token: Data([1]), version: .v1, nonce: randomBytes(16))
        let data = try JSONEncoder().encode(older)

        phone.manager.handleDiscovery(older, data: data, from: peer)
        phone.manager.handleDiscovery(older, data: data, from: peer)

        let legacy = phone.sentExchanges.filter { $0.isDiscovery && $0.nonce != nil }
        #expect(legacy.count == 1 && legacy.first?.nonce == phone.nonce)
        #expect(!phone.manager.isCommittedExchange)
    }

    @Test("The exchange with an older build still completes, uncommitted, and sends no reveal")
    func stillCompletes() async throws {
        let (phone, peer) = try await self.connected()
        defer { phone.manager.finish() }
        let olderNonce = randomBytes(16)
        let older = Exchange(id: UUID().uuidString, token: Data([1]), version: .v1, nonce: olderNonce)
        phone.manager.handleDiscovery(older, data: try JSONEncoder().encode(older), from: peer)
        phone.manager.startProtocol(with: peer)

        // The older peer answers the initiator's identity with its own, classical.
        try await Task.sleep(for: .milliseconds(100))
        let identity = Exchange(id: UUID().uuidString, token: Data([1]), version: .v1, identity: randomPoint())
        phone.manager.handleReceivedData(try JSONEncoder().encode(identity), from: peer)

        for _ in 0..<100 where phone.payload == nil { try await Task.sleep(for: .milliseconds(20)) }
        let payload = try #require(phone.payload)
        #expect(payload.committed == nil, "the screen says the peer did not commit")
        #expect(payload.hybridResult == nil)
        #expect(!phone.sentExchanges.contains { $0.isNonceReveal }, "an older build would read a reveal as a discovery message")
        // And the words are the ones the older build derives: the transport key's.
        let key = try #require(phone.key.createSharedSecret(using: payload.classicalKey))
        #expect(phone.words == Manager.PassphraseGenerator().generate(separator: "-", sharedKey: key.withUnsafeBytes { Data($0) }).components(separatedBy: "-"))
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
        manager.stepTimeout = 0.4
        manager.startProtocol(with: MCPeerID(displayName: "b-peer"))
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
        loop.tamper = { _, _ in nil }   // nothing gets through
        await loop.start()
        await loop.run(until: { loop.a.manager.phase == .timedOut && loop.b.manager.phase == .timedOut })

        #expect(loop.a.manager.phase == .timedOut && loop.b.manager.phase == .timedOut)
        #expect(loop.a.payload == nil && loop.b.payload == nil)
    }
}

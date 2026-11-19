//
//  ExchangeManagerTeardownCallbacksTests.swift
//  OccultaTests
//
//  Bug 200: ending a key exchange did not stop what was already queued. Multipeer and NearbyInteraction callbacks are
//  re-dispatched to the main queue and the classical path's steps are tasks that sleep, so a block or task queued before
//  `finish()` ran against the cleared manager: a force-unwrap of the session that was gone, a watchdog armed on a resting
//  manager, and a confirmation for an exchange that was ended. A callback also never said which session it came from.
//
//  Built without `start()`, as `ExchangeManagerPeerPinningTests` is: no radio is used.
//

import Testing
import MultipeerConnectivity
import NearbyInteraction
@testable import Occulta

@MainActor
@Suite("ExchangeManager — callbacks queued when the exchange ends (Bug 200)", .serialized)
struct ExchangeManagerTeardownCallbacksTests {

    private func makeManager() -> ExchangeManager {
        let manager = ExchangeManager()
        manager.multipeerSession = MCSession(peer: MCPeerID(displayName: "self-\(UUID().uuidString)"))
        return manager
    }

    private func settle() async { try? await Task.sleep(for: .milliseconds(300)) }

    @Test("A connect delivered just before finish() neither crashes nor pins a peer")
    func connectAroundFinish() async {
        let manager = self.makeManager()
        let session = manager.multipeerSession!

        // The delegate hops to the main queue; finish() runs first, so the hop lands on a cleared manager.
        manager.session(session, peer: MCPeerID(displayName: "peerA"), didChange: .connected)
        manager.finish()
        await self.settle()

        #expect(manager.connectedPeerID == nil)
        #expect(manager.phase == .resting)
    }

    @Test("A connect reported by a session that is not the current one is ignored")
    func connectFromAnotherSession() async {
        let manager = self.makeManager()
        let stale = MCSession(peer: MCPeerID(displayName: "old-\(UUID().uuidString)"))

        manager.session(stale, peer: MCPeerID(displayName: "peerA"), didChange: .connected)
        await self.settle()

        #expect(manager.connectedPeerID == nil, "a stale connect must not pin a new exchange to the old peer")
        #expect(manager.phase == .resting)
    }

    @Test("A NearbyInteraction update delivered just before finish() does not arm the watchdog")
    func nearbyUpdateAroundFinish() async {
        let manager = self.makeManager()

        manager.session(NISession(), didUpdate: [])
        manager.finish()
        await self.settle()

        #expect(!manager.isWatchdogArmed, "a watchdog armed on a resting manager later times it out")
    }

    @Test("A classical identity message followed by finish() leaves the phase resting seven seconds later")
    func classicalPathAfterFinish() async throws {
        let manager = self.makeManager()
        let peer = MCPeerID(displayName: "peerA")

        manager.session(manager.multipeerSession!, peer: peer, didChange: .connected)
        await self.settle()
        try #require(manager.connectedPeerID == peer)
        manager.waitForPeerIdentityForTesting()

        let identity = Exchange(id: UUID().uuidString, token: Data([1]), version: .v1, identity: Data(repeating: 4, count: 65))
        manager.handleReceivedData(try JSONEncoder().encode(identity), from: peer)
        try #require(manager.phase == .identityExchanged(fingerprint: Data(repeating: 4, count: 65).sha256))

        manager.finish()
        try? await Task.sleep(for: .seconds(7))

        #expect(manager.phase == .resting, "the classical path's tasks must not confirm an exchange that was ended")
    }

    @Test("The discovery tokens do not outlive the exchange")
    func tokensAreCleared() async throws {
        let manager = self.makeManager()
        let peer = MCPeerID(displayName: "peerA")

        manager.session(manager.multipeerSession!, peer: peer, didChange: .connected)
        await self.settle()
        try #require(manager.connectedPeerID == peer)

        let token = try #require(NISession().discoveryToken, "NIDiscoveryToken unavailable in this test environment")
        let archived = try NSKeyedArchiver.archivedData(withRootObject: token, requiringSecureCoding: true)
        manager.handleReceivedData(try JSONEncoder().encode(Exchange(id: UUID().uuidString, token: archived, version: .v1)), from: peer)
        try #require(manager.receivedDiscoveryTokens[token] == peer)

        manager.finish()

        #expect(manager.receivedDiscoveryTokens.isEmpty)
    }
}

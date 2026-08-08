//
//  ExchangeManagerPeerPinningTests.swift
//  OccultaTests
//
//  Regression coverage for the MITM/peer-pinning finding in Exchange+Manager.swift:
//  `connectedPeerID` was reassigned on every MC connection event instead of being
//  pinned to the first peer, so a second peer joining the MCSession mid-exchange could
//  hijack the "MITM guard" outright — not just slip past the phases that never checked
//  it. Ciphertext-phase coverage is intentionally omitted here: ExchangeManager's
//  PQProvider isn't injectable, so exercising that branch would require real Secure
//  Enclave hardware.
//

import Testing
import MultipeerConnectivity
import NearbyInteraction
@testable import Occulta

private func waitUntil(
    timeout: Duration = .seconds(5),
    poll: Duration = .milliseconds(20),
    _ condition: () -> Bool
) async {
    let deadline = ContinuousClock.now.advanced(by: timeout)
    while ContinuousClock.now < deadline {
        if condition() { return }
        try? await Task.sleep(for: poll)
    }
}

@MainActor
@Suite("ExchangeManager — peer pinning / MITM guard")
struct ExchangeManagerPeerPinningTests {

    /// Built without calling `start()` — that would trigger real Bluetooth
    /// advertising/browsing after a 3s delay, which has no place in a unit test.
    /// `multipeerSession` is set directly so the MCSessionDelegate conformance
    /// methods (already internal, reachable via `@testable import`) can be driven.
    private func makeManager() -> ExchangeManager {
        let manager = ExchangeManager()
        manager.multipeerSession = MCSession(peer: MCPeerID(displayName: "self-\(UUID().uuidString)"))
        return manager
    }

    @Test func secondPeerConnecting_doesNotOverwritePinnedPeer() async {
        let manager = makeManager()
        let peerA = MCPeerID(displayName: "peerA")
        let peerB = MCPeerID(displayName: "peerB")

        manager.session(manager.multipeerSession!, peer: peerA, didChange: .connected)
        await waitUntil { manager.connectedPeerID != nil }
        #expect(manager.connectedPeerID == peerA)

        manager.session(manager.multipeerSession!, peer: peerB, didChange: .connected)
        // Give the (buggy) overwrite a chance to happen before asserting it didn't.
        try? await Task.sleep(for: .milliseconds(200))
        #expect(manager.connectedPeerID == peerA)
    }

    @Test func discoveryFromSecondPeer_afterFirstPinned_isIgnored() async throws {
        let manager = makeManager()
        let peerA = MCPeerID(displayName: "peerA")
        let peerB = MCPeerID(displayName: "peerB")

        manager.session(manager.multipeerSession!, peer: peerA, didChange: .connected)
        await waitUntil { manager.connectedPeerID != nil }

        let niSession = NISession()
        let token = try #require(
            niSession.discoveryToken,
            "NIDiscoveryToken unavailable in this test environment"
        )
        let archived = try NSKeyedArchiver.archivedData(withRootObject: token, requiringSecureCoding: true)
        let discoveryMessage = Exchange(id: UUID().uuidString, token: archived, version: .v1)
        let data = try JSONEncoder().encode(discoveryMessage)

        manager.session(manager.multipeerSession!, didReceive: data, fromPeer: peerB)
        try? await Task.sleep(for: .milliseconds(200))

        #expect(manager.receivedDiscoveryTokens[token] == nil)
    }
}

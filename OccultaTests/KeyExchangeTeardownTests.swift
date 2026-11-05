//
//  KeyExchangeTeardownTests.swift
//  OccultaTests
//
//  Hardening step 10 (`Docs/v2.0.0/HARDENING_STEPS.md`). While an exchange is searching, the phone
//  advertises the Bonjour service `_peer-data-ex`, which is unique to Occulta, so a passive scanner
//  nearby learns an Occulta exchange is happening. Advertising stopped on timeout, failure, save and
//  backgrounding, but not when the user left the exchange screen: teardown then hung on the `@State`
//  manager being freed, which `ExchangeManager` (no `deinit`) does not guarantee stops the
//  advertiser, leaving the 30 s watchdog as the only bound.
//
//  These tests host the real `KeyExchange` screen with a manager in the searching phase, set without
//  calling `start()` so no radio is used, and check that removing the screen returns it to resting.
//

import Testing
import SwiftUI
import SwiftData
import UIKit
@testable import Occulta

@Suite("Hardening step 10 — leaving the exchange screen stops the exchange", .serialized)
@MainActor
struct KeyExchangeTeardownTests {

    @Test("Removing the screen mid-exchange returns the manager to resting")
    func leavingStopsExchange() throws {
        let manager = ExchangeManager()
        manager.phase = .searching
        let screen = try self.host(manager: manager)
        defer { screen.window.isHidden = true }
        try #require(screen.presence.isUp)

        // Replacing the hosted view and laying out fires `onDisappear` before `layoutIfNeeded`
        // returns. Swapping the window's root controller instead fires it a run-loop turn later.
        screen.controller.rootView = AnyView(EmptyView())
        screen.window.layoutIfNeeded()
        try #require(!screen.presence.isUp)

        #expect(manager.phase == .resting)
    }

    @Test("The pair keys are made once for the peer we're pinned to, both with the prekeys or neither, and dropped at teardown",
          .enabled(if: TestSupport.secureEnclaveAvailable()))
    func pairKeysDoNotOutliveTheExchange() throws {
        let manager = ExchangeManager()
        manager.pairKeyProvider = SoftwareCardKeys()
        #expect(manager.ownPairKeys == nil, "an exchange that never finds anyone makes none")

        manager.makeOwnPairing()
        let first = try #require(manager.ownPairKeys)
        manager.makeOwnPairing()
        #expect(manager.ownPairKeys == first, "made once, not again for the same peer")

        manager.finish()
        #expect(manager.ownPairKeys == nil, "the blobs do not outlive the exchange")
    }

    @Test("A failure making the pair keys leaves the prekeys and the pair keys both unmade",
          .enabled(if: TestSupport.secureEnclaveAvailable()))
    func pairKeyFailureSendsNothing() {
        let manager = ExchangeManager()
        let keys = SoftwareCardKeys()
        keys.failing = true
        manager.pairKeyProvider = keys

        manager.makeOwnPairing()
        #expect(manager.ownPairKeys == nil)
        #expect(manager.ownPrekeys == nil, "the prekeys made first are dropped too: a phone sends all of the pairing field or none")
    }

    /// Control: the screen staying up must not reset the exchange, or the test above proves nothing.
    /// It takes the same steps minus the removal, including the layout pass the removal runs in.
    @Test("The exchange keeps running while the screen stays up")
    func stayingKeepsExchange() throws {
        let manager = ExchangeManager()
        manager.phase = .searching
        let screen = try self.host(manager: manager)
        defer { screen.window.isHidden = true }
        try #require(screen.presence.isUp)

        screen.window.layoutIfNeeded()
        try #require(screen.presence.isUp)

        #expect(manager.phase == .searching)
    }

    // MARK: - Helpers

    /// Whether the screen is up, as SwiftUI reports it through `onAppear` and `onDisappear`.
    private final class Presence {
        var isUp = false
    }

    private struct HostedScreen {
        let window: UIWindow
        let controller: UIHostingController<AnyView>
        let presence: Presence
    }

    /// Hosts the screen in a window attached to the test host's scene. A window with no scene is not
    /// reliably laid out, and its views would then never appear or disappear.
    ///
    /// The layout is forced so the screen appears before this returns. Left to the run loop, it
    /// appears only when a layout is committed, which a loaded main actor can postpone past any fixed
    /// sleep, and a screen that never appeared never disappears: leaving it then looked exactly like
    /// a broken teardown.
    private func host(manager: ExchangeManager) throws -> HostedScreen {
        let scene = try #require(UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.first)
        let schema = Schema([
            AppLayerConfig.self,
            Contact.Profile.self,
            Contact.Profile.PhoneNumber.self,
            Contact.Profile.EmailAddress.self,
            Contact.Profile.PostalAddress.self,
            Contact.Profile.URLAddress.self,
            Contact.Profile.Key.self,
        ])
        let container = try ModelContainer(
            for: schema,
            configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
        )
        let presence = Presence()
        let screen = NavigationStack {
            KeyExchange(identifier: UUID().uuidString, exchangeManager: manager)
                .onAppear { presence.isUp = true }
                .onDisappear { presence.isUp = false }
        }
        .modelContainer(container)

        let controller = UIHostingController(rootView: AnyView(screen))
        let window = UIWindow(windowScene: scene)
        window.rootViewController = controller
        window.makeKeyAndVisible()
        window.layoutIfNeeded()
        return HostedScreen(window: window, controller: controller, presence: presence)
    }
}

// MARK: - What the exchange manager accepts of the peer's pairing field (Bug 196)

@Suite("Bug 196 — the exchange manager and the peer's pairing field", .serialized)
@MainActor
struct ExchangeManagerPairingTests {

    /// A peer's `pairing` field made with software keys, and the keys behind it.
    private func peerField() throws -> (field: Exchange.PairingField, keys: PairingOffer.OwnPairKeys) {
        let keys = try PairingOffer.makeOwnPairKeys(using: SoftwareCardKeys())
        let record = try PairingOffer.makeOwnPrekeys()
        let batch = try #require(PairingOffer.wireBatch(of: record))
        return (Exchange.PairingField(prekeyBatch: batch, agreementKey: keys.agreementKey, signingKey: keys.signingKey, mldsaKey: keys.mldsaKey), keys)
    }

    @Test("A good field is accepted with the pair-key ECDH both phones compute", .enabled(if: TestSupport.secureEnclaveAvailable()))
    func acceptsAGoodField() throws {
        let manager = ExchangeManager()
        manager.pairKeyProvider = SoftwareCardKeys()
        manager.makeOwnPairing()
        let ours = try #require(manager.ownPairKeys)
        let (field, peer) = try self.peerField()

        let accepted = try #require(manager.acceptedPairing(field, peerIdentity: Data(repeating: 0x22, count: 65)))

        #expect(accepted.keys.agreementKey == peer.agreementKey && accepted.keys.signingKey == peer.signingKey)
        let theirSide = Manager.Crypto.cardECDHOutput(try SoftwareCardKeys().sharedSecret(agreementBlob: peer.agreementBlob, peerPublicKey: ours.agreementKey))
        #expect(accepted.ecdh == theirSide, "the other phone computes the same bytes")
    }

    @Test("Nothing is accepted when we sent no pairing field ourselves", .enabled(if: TestSupport.secureEnclaveAvailable()))
    func refusesWhenWeOfferedNone() throws {
        let manager = ExchangeManager()
        manager.pairKeyProvider = SoftwareCardKeys()
        let (field, _) = try self.peerField()

        #expect(manager.ownPairKeys == nil)
        #expect(manager.acceptedPairing(field, peerIdentity: Data(repeating: 0x22, count: 65)) == nil)
        #expect(manager.acceptedPairing(nil, peerIdentity: Data(repeating: 0x22, count: 65)) == nil)
    }

    @Test("A field that reflects one of our own keys is refused", .enabled(if: TestSupport.secureEnclaveAvailable()))
    func refusesAReflection() throws {
        let manager = ExchangeManager()
        manager.pairKeyProvider = SoftwareCardKeys()
        manager.makeOwnPairing()
        let ours = try #require(manager.ownPairKeys)
        let (genuine, _) = try self.peerField()
        let reflected = Exchange.PairingField(
            prekeyBatch: genuine.prekeyBatch, agreementKey: ours.agreementKey, signingKey: genuine.signingKey, mldsaKey: nil
        )

        #expect(manager.acceptedPairing(reflected, peerIdentity: Data(repeating: 0x22, count: 65)) == nil)
    }
}

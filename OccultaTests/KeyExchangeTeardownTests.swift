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
    func leavingStopsExchange() async throws {
        let manager = ExchangeManager()
        let window = try self.host(manager: manager)
        defer { window.isHidden = true }
        manager.phase = .searching
        try await Task.sleep(for: .milliseconds(300))

        window.rootViewController = UIHostingController(rootView: EmptyView())
        await self.waitUntil { manager.phase == .resting }

        #expect(manager.phase == .resting)
    }

    /// Control: the screen staying up must not reset the exchange, or the test above proves nothing.
    @Test("The exchange keeps running while the screen stays up")
    func stayingKeepsExchange() async throws {
        let manager = ExchangeManager()
        let window = try self.host(manager: manager)
        defer { window.isHidden = true }
        manager.phase = .searching
        try await Task.sleep(for: .milliseconds(300))

        #expect(manager.phase == .searching)
    }

    // MARK: - Helpers

    /// Hosts the screen in a window attached to the test host's scene. A window with no scene is not
    /// reliably laid out, and its views would then never appear or disappear.
    private func host(manager: ExchangeManager) throws -> UIWindow {
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
        let screen = NavigationStack {
            KeyExchange(identifier: UUID().uuidString, exchangeManager: manager)
        }
        .modelContainer(container)

        let window = UIWindow(windowScene: scene)
        window.rootViewController = UIHostingController(rootView: screen)
        window.makeKeyAndVisible()
        return window
    }

    private func waitUntil(timeout: Duration = .seconds(2), _ condition: () -> Bool) async {
        let deadline = ContinuousClock.now.advanced(by: timeout)
        while ContinuousClock.now < deadline, !condition() {
            try? await Task.sleep(for: .milliseconds(20))
        }
    }
}

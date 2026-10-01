//
//  AppScreenLockTests.swift
//  OccultaTests
//
//  Bug 148: on a warm return past the grace period, `AppScreen` must be `.pinRequired` before
//  UIKit delivers a URL — that is, at `sceneWillEnterForeground`, not `sceneDidBecomeActive`.
//  `sceneWillEnterForeground` itself needs a live `UIScene`, so these drive
//  `lockIfGracePeriodExpired`, the whole of what it does to `phase`.
//
//  Uses `TestKeyManager`, but `configurePIN` also seals `AppLayerConfig` fields with the ambient
//  local key (`Data.encrypt()`), so the tests that configure a PIN need a Secure Enclave.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta

@MainActor
private func makeSecurity() throws -> Manager.Security {
    let schema = Schema([AppLayerConfig.self])
    let container = try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
    return Manager.Security(modelContainer: container, keyManager: TestKeyManager())
}

/// An `AppScreen` wired to `security` and past its cold-launch PIN, if it has one.
@MainActor
private func makeUnlockedScreen(_ security: Manager.Security) -> AppScreen {
    let screen = AppScreen()
    screen.wire(security: security)
    screen.pinDidSucceed()
    return screen
}

@Suite("AppScreen — locks at the start of a warm return (Bug 148)")
struct AppScreenLockTests {

    /// 5-minute grace period, as `AppScreen.gracePeriod`.
    private static let grace: TimeInterval = 5 * 60

    @Test("Past the grace period, the phase is .pinRequired before the scene becomes active", .ambientTestKeyManager)
    @MainActor
    func locksPastGracePeriod() throws {
        let security = try makeSecurity()
        try security.configurePIN("111111")
        let screen = makeUnlockedScreen(security)
        #expect(screen.phase == .unlocked)

        let entered = Date()
        screen.backgroundEntryDate = entered
        screen.lockIfGracePeriodExpired(now: entered.addingTimeInterval(Self.grace + 1))

        #expect(screen.phase == .pinRequired)
    }

    @Test("Within the grace period nothing changes; the unlock decision is left to activation", .ambientTestKeyManager)
    @MainActor
    func staysUnlockedWithinGracePeriod() throws {
        let security = try makeSecurity()
        try security.configurePIN("111111")
        let screen = makeUnlockedScreen(security)

        let entered = Date()
        screen.backgroundEntryDate = entered
        screen.lockIfGracePeriodExpired(now: entered.addingTimeInterval(Self.grace - 1))

        #expect(screen.phase == .unlocked)
    }

    @Test("No background entry recorded (an inactive-only interruption) never locks", .ambientTestKeyManager)
    @MainActor
    func noBackgroundEntryNeverLocks() throws {
        let security = try makeSecurity()
        try security.configurePIN("111111")
        let screen = makeUnlockedScreen(security)

        screen.backgroundEntryDate = nil
        screen.lockIfGracePeriodExpired(now: Date().addingTimeInterval(Self.grace * 10))

        #expect(screen.phase == .unlocked)
    }

    @Test("Without a PIN configured, a long background never locks")
    @MainActor
    func noPINNeverLocks() throws {
        let security = try makeSecurity()
        let screen = AppScreen()
        screen.wire(security: security)
        #expect(screen.phase == .unlocked)

        let entered = Date()
        screen.backgroundEntryDate = entered
        screen.lockIfGracePeriodExpired(now: entered.addingTimeInterval(Self.grace * 10))

        #expect(screen.phase == .unlocked)
    }

    @Test("With the PIN gate lowered, a long background never locks", .ambientTestKeyManager)
    @MainActor
    func loweredGateNeverLocks() throws {
        let security = try makeSecurity()
        try security.configurePIN("111111")
        try security.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        try security.disablePIN(at: security.currentDepth, confirmingPIN: "111111")
        let screen = AppScreen()
        screen.wire(security: security)
        #expect(screen.phase == .unlocked)

        let entered = Date()
        screen.backgroundEntryDate = entered
        screen.lockIfGracePeriodExpired(now: entered.addingTimeInterval(Self.grace * 10))

        #expect(screen.phase == .unlocked)
    }

    @Test("Before security is wired (cold launch), nothing changes")
    @MainActor
    func unwiredDoesNothing() {
        let screen = AppScreen()
        let entered = Date()
        screen.backgroundEntryDate = entered
        screen.lockIfGracePeriodExpired(now: entered.addingTimeInterval(Self.grace * 10))

        #expect(screen.phase == .covered)
    }
}

//
//  LockoutAntiRollbackTests.swift
//  OccultaTests
//
//  Regression coverage for SEC-1: the PIN lockout used to be gated on
//  Date.now < storedExpiry — a plain wall-clock comparison an attacker with physical
//  possession of the device can defeat by rolling Settings → Date & Time forward,
//  instantly clearing any lockout regardless of how deep into the escalation schedule
//  it was.
//
//  The fix gates the lockout on ProcessInfo.systemUptime instead (monotonic time since
//  boot, untouched by Settings changes), detecting an actual reboot (the only way
//  uptime can move backward) and re-anchoring rather than crediting free elapsed time.
//
//  These tests inject a FakeLockoutClock so they can simulate both attacks
//  deterministically, without touching the real system clock or actually rebooting.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta

// MARK: - Fake clock

/// Controllable LockoutClock for tests. `now` and `systemUptime` are independently
/// settable — real hardware keeps these in lockstep during a boot session and only
/// lets `now` jump without `systemUptime` moving (clock tampering) or lets
/// `systemUptime` decrease (reboot); this fake lets tests construct exactly those
/// scenarios on demand.
final class FakeLockoutClock: LockoutClock {
    var now: Date
    var systemUptime: TimeInterval

    init(now: Date = .now, systemUptime: TimeInterval = 10_000) {
        self.now = now
        self.systemUptime = systemUptime
    }
}

// MARK: - Helpers

@MainActor
private func makeLockoutContainer() throws -> ModelContainer {
    let schema = Schema([AppLayerConfig.self])
    return try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
}

@MainActor
private func makeSecurity(clock: FakeLockoutClock) throws -> Manager.Security {
    try Manager.Security(
        modelContainer: makeLockoutContainer(),
        keyManager: TestKeyManager(),
        clock: clock
    )
}

@MainActor
@Suite("Security — Lockout anti-rollback (SEC-1)")
struct LockoutAntiRollbackTests {

    /// The exact reported bug, reproduced: 6 wrong PINs trigger a 60s lockout: rolling
    /// the wall clock forward past that 60s window — WITHOUT any real time or uptime
    /// elapsing — must not clear it. This is the attack the fix exists to close.
    @Test func rollingClockForward_doesNotClearLockout() throws {
        let clock    = FakeLockoutClock()
        let security = try makeSecurity(clock: clock)
        try security.configurePIN("123456")

        for _ in 0..<6 { _ = try security.verify("000000") }
        // Confirm the lockout actually triggered before attempting to bypass it.
        if case .locked = try security.verify("000000") { } else {
            Issue.record("expected lockout to be active before the clock-rollback attempt")
        }

        // Attack: roll the wall clock forward 2 hours. systemUptime is untouched —
        // exactly what a Settings → Date & Time change does on a real device.
        clock.now = clock.now.addingTimeInterval(2 * 60 * 60)

        let result = try security.verify("123456")  // even the CORRECT PIN must be rejected while locked
        if case .locked = result { } else {
            Issue.record("clock rollback cleared the lockout — expected .locked, got \(result)")
        }
    }

    /// Control case: if real uptime actually advances past the required delay — no
    /// rollback, no reboot — the lockout must still clear normally. Confirms the fix
    /// isn't just "never unlock."
    @Test func sufficientUptimeElapsed_clearsLockout() throws {
        let clock    = FakeLockoutClock()
        let security = try makeSecurity(clock: clock)
        try security.configurePIN("123456")

        for _ in 0..<6 { _ = try security.verify("000000") }  // 60s delay (count = 6)

        clock.systemUptime += 61  // genuine elapsed time, past the 60s requirement

        let result = try security.verify("123456")
        #expect(result == .normal(depth: 0), "lockout should have cleared after the real delay elapsed")
    }

    /// The second attack: reboot the device (uptime resets toward 0) instead of
    /// changing the clock. Must not clear the lockout either — a reboot re-anchors
    /// and the same delay is owed again, not credited as elapsed time.
    @Test func simulatedReboot_doesNotClearLockout() throws {
        let clock    = FakeLockoutClock(systemUptime: 10_000)
        let security = try makeSecurity(clock: clock)
        try security.configurePIN("123456")

        for _ in 0..<6 { _ = try security.verify("000000") }  // anchor set at uptime 10_000, delay 60s

        // Attack: reboot — uptime resets to a small post-boot value, well below the anchor.
        clock.systemUptime = 5

        let result = try security.verify("123456")
        if case .locked = result { } else {
            Issue.record("simulated reboot cleared the lockout — expected .locked, got \(result)")
        }
    }

    /// After a simulated reboot re-anchors, the lockout must still eventually clear
    /// once the full delay has genuinely elapsed from the NEW anchor — the fix must
    /// not turn a reboot into a permanent lock.
    @Test func simulatedReboot_thenSufficientUptimeElapsed_clearsLockout() throws {
        let clock    = FakeLockoutClock(systemUptime: 10_000)
        let security = try makeSecurity(clock: clock)
        try security.configurePIN("123456")

        for _ in 0..<6 { _ = try security.verify("000000") }  // delay 60s, anchor at 10_000

        clock.systemUptime = 5                       // simulated reboot — re-anchors at uptime 5
        _ = try security.verify("123456")             // still locked, re-anchor confirmed by the test above

        clock.systemUptime = 5 + 61                   // 61s past the NEW anchor
        let result = try security.verify("123456")
        #expect(result == .normal(depth: 0),
                "lockout should clear once the full delay has elapsed from the post-reboot anchor")
    }

    /// The read-only display helper PINEntry uses must reflect the same "still locked"
    /// state after a simulated reboot as the real gate does — without needing to call
    /// verify() first, since PINEntry reads this on `.onAppear`, before any PIN is typed.
    @Test func lockoutExpiry_reflectsRebootWithoutClearing() throws {
        let clock    = FakeLockoutClock(systemUptime: 10_000)
        let security = try makeSecurity(clock: clock)
        try security.configurePIN("123456")

        for _ in 0..<6 { _ = try security.verify("000000") }
        clock.systemUptime = 5  // simulated reboot, no verify() call yet

        #expect(security.lockoutExpiry() != nil,
                "lockoutExpiry() must still report locked after a reboot, without needing verify() first")
    }
}

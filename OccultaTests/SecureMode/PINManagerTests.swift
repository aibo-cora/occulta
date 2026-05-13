//
//  PINManagerTests.swift
//  OccultaTests
//

import Testing
import Foundation
import SwiftData

@testable import Occulta

// MARK: - Helpers

@MainActor
private func makeContext() throws -> ModelContext {
    let schema = Schema([SecureModeConfig.self])
    let config = ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)
    let container = try ModelContainer(for: schema, configurations: [config])
    return ModelContext(container)
}

// MARK: - Configure

@MainActor
@Suite("PINManager — Configure")
struct PINManagerConfigureTests {

    @Test func configure_insertsConfig() throws {
        let context = try makeContext()
        let pm      = Manager.PINManager(keyManager: TestKeyManager())

        try pm.configure(normalPIN: "1234", duressPIN: "5678", wipeThreshold: 3, in: context)

        let configs = try context.fetch(FetchDescriptor<SecureModeConfig>())
        #expect(configs.count == 1)
        #expect(configs[0].wipeThreshold == 3)
        #expect(!configs[0].salt.isEmpty)
    }

    @Test func configure_replacesExistingConfig() throws {
        let context = try makeContext()
        let pm      = Manager.PINManager(keyManager: TestKeyManager())

        try pm.configure(normalPIN: "1111", duressPIN: "2222", wipeThreshold: 2, in: context)
        try pm.configure(normalPIN: "3333", duressPIN: "4444", wipeThreshold: 5, in: context)

        let configs = try context.fetch(FetchDescriptor<SecureModeConfig>())
        #expect(configs.count == 1)
        #expect(configs[0].wipeThreshold == 5)
    }

    @Test func configure_resetsCounters() throws {
        let context = try makeContext()
        let pm      = Manager.PINManager(keyManager: TestKeyManager())

        try pm.configure(normalPIN: "0000", duressPIN: "9999", wipeThreshold: 3, in: context)
        _ = try pm.verify("bad", in: context)
        _ = try pm.verify("bad", in: context)

        try pm.configure(normalPIN: "0000", duressPIN: "9999", wipeThreshold: 3, in: context)
        #expect(pm.wrongPINCount == 0)
        #expect(pm.consecutiveDuressCount == 0)
    }
}

// MARK: - Verify: correct PINs

@MainActor
@Suite("PINManager — Verify correct PINs")
struct PINManagerVerifyCorrectTests {

    @Test func normalPIN_returnsNormal() throws {
        let context = try makeContext()
        let pm      = Manager.PINManager(keyManager: TestKeyManager())

        try pm.configure(normalPIN: "1234", duressPIN: "5678", wipeThreshold: 3, in: context)
        #expect(try pm.verify("1234", in: context) == .normal)
    }

    @Test func duressPIN_returnsDuress() throws {
        let context = try makeContext()
        let pm      = Manager.PINManager(keyManager: TestKeyManager())

        try pm.configure(normalPIN: "1234", duressPIN: "5678", wipeThreshold: 3, in: context)
        #expect(try pm.verify("5678", in: context) == .duress)
    }

    @Test func wrongPIN_returnsWrong() throws {
        let context = try makeContext()
        let pm      = Manager.PINManager(keyManager: TestKeyManager())

        try pm.configure(normalPIN: "1234", duressPIN: "5678", wipeThreshold: 3, in: context)
        #expect(try pm.verify("0000", in: context) == .wrong)
    }
}

// MARK: - Verify: counter logic

@MainActor
@Suite("PINManager — Counter logic")
struct PINManagerCounterTests {

    @Test func normalPIN_resetsBothCounters() throws {
        let context = try makeContext()
        let pm      = Manager.PINManager(keyManager: TestKeyManager())

        try pm.configure(normalPIN: "1234", duressPIN: "5678", wipeThreshold: 5, in: context)
        _ = try pm.verify("5678", in: context)
        _ = try pm.verify("5678", in: context)
        _ = try pm.verify("0000", in: context)

        _ = try pm.verify("1234", in: context)
        #expect(pm.wrongPINCount == 0)
        #expect(pm.consecutiveDuressCount == 0)
    }

    @Test func duressPIN_resetsWrongCounter() throws {
        let context = try makeContext()
        let pm      = Manager.PINManager(keyManager: TestKeyManager())

        try pm.configure(normalPIN: "1234", duressPIN: "5678", wipeThreshold: 5, in: context)
        _ = try pm.verify("0000", in: context)
        _ = try pm.verify("0000", in: context)
        #expect(pm.wrongPINCount == 2)

        _ = try pm.verify("5678", in: context)
        #expect(pm.wrongPINCount == 0)
        #expect(pm.consecutiveDuressCount == 1)
    }

    @Test func wrongPIN_resetsDuressCounter() throws {
        let context = try makeContext()
        let pm      = Manager.PINManager(keyManager: TestKeyManager())

        try pm.configure(normalPIN: "1234", duressPIN: "5678", wipeThreshold: 5, in: context)
        _ = try pm.verify("5678", in: context)
        _ = try pm.verify("5678", in: context)
        #expect(pm.consecutiveDuressCount == 2)

        _ = try pm.verify("0000", in: context)
        #expect(pm.consecutiveDuressCount == 0)
        #expect(pm.wrongPINCount == 1)
    }
}

// MARK: - Verify: wipe thresholds

@MainActor
@Suite("PINManager — Wipe thresholds")
struct PINManagerWipeTests {

    @Test func threeWrongPINs_returnsWipe() throws {
        let context = try makeContext()
        let pm      = Manager.PINManager(keyManager: TestKeyManager())

        try pm.configure(normalPIN: "1234", duressPIN: "5678", wipeThreshold: 5, in: context)
        _ = try pm.verify("0000", in: context)
        _ = try pm.verify("0000", in: context)
        #expect(try pm.verify("0000", in: context) == .wipe)
    }

    @Test func consecutiveDuressHitsThreshold_returnsWipe() throws {
        let context = try makeContext()
        let pm      = Manager.PINManager(keyManager: TestKeyManager())

        try pm.configure(normalPIN: "1234", duressPIN: "5678", wipeThreshold: 3, in: context)
        _ = try pm.verify("5678", in: context)
        _ = try pm.verify("5678", in: context)
        #expect(try pm.verify("5678", in: context) == .wipe)
    }

    @Test func duressCounterResetsOnWrong_preventsEarlyWipe() throws {
        let context = try makeContext()
        let pm      = Manager.PINManager(keyManager: TestKeyManager())

        try pm.configure(normalPIN: "1234", duressPIN: "5678", wipeThreshold: 3, in: context)
        _ = try pm.verify("5678", in: context)
        _ = try pm.verify("5678", in: context)
        _ = try pm.verify("0000", in: context)   // resets duress counter
        _ = try pm.verify("5678", in: context)
        _ = try pm.verify("5678", in: context)
        #expect(try pm.verify("5678", in: context) == .wipe)
    }

    @Test func wrongCounterResetsOnDuress_preventsEarlyWipe() throws {
        let context = try makeContext()
        let pm      = Manager.PINManager(keyManager: TestKeyManager())

        try pm.configure(normalPIN: "1234", duressPIN: "5678", wipeThreshold: 5, in: context)
        _ = try pm.verify("0000", in: context)
        _ = try pm.verify("0000", in: context)
        _ = try pm.verify("5678", in: context)   // resets wrong counter
        _ = try pm.verify("0000", in: context)
        _ = try pm.verify("0000", in: context)
        #expect(try pm.verify("0000", in: context) == .wipe)
    }

    @Test func notConfigured_throwsError() throws {
        let context = try makeContext()
        let pm      = Manager.PINManager(keyManager: TestKeyManager())

        #expect(throws: Manager.PINManager.PINError.notConfigured) {
            try pm.verify("1234", in: context)
        }
    }
}

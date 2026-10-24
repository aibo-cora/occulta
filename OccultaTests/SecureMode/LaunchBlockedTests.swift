//
//  LaunchBlockedTests.swift
//  OccultaTests
//
//  Bug 171, Stage 2c (the user's decision of 2026-10-22): a launch whose tier U pass committed at least one batch and
//  ended without its epoch is blocked.
//
//  The store is then a mix of both keys while the process is on the legacy ones, and everything that opens a value and
//  writes after reading it (an unreadable prekey record starts over, an unreadable slot array reads as empty and is
//  overwritten) would destroy what it can't open. So the launch reports `blocked`, the app shows a neutral screen in
//  place of the PIN prompt, and nothing is decrypted, written or processed until the next launch finishes the pass.
//
//  Not blocked: a pass that stopped before it wrote anything (a locked device, a missing secret, a read-back that
//  fails from the first value): the store is not mixed, and the app runs on the legacy keys as Stage 2 made it.
//  A kill never reports at all; the stand-ins for one here are the fault points that fire before any batch is saved.
//
//  Written first: against the stubs `blocked` was never set, the screen was always the app, and the hosted blocking
//  screen was never shown.
//

import Testing
import CryptoKit
import Foundation
import LocalAuthentication
import SwiftData
import SwiftUI

@testable import Occulta
@testable import OccultaCore
@testable import OccultaFormats

// MARK: - The report

@Suite("Launch blocked — the report", .ambientFrozenTestKeyManager)
@MainActor
struct LaunchBlockedReportTests {

    /// A pass that commits a batch and then ends without the epoch.
    enum Partway: CaseIterable, CustomStringConvertible {
        /// The `save()` of the second batch throws.
        case saveFailsOnTheSecondBatch
        /// Every batch is saved, and the `save()` of the epoch throws.
        case epochSaveFails
        /// The new ciphertexts stop reading back after the first batch.
        case readBackFailsAfterTheFirstBatch
        /// A legacy key the pass needs later can't be derived, found after the first batch was saved.
        case legacyKeyLostAfterTheFirstBatch

        var description: String {
            switch self {
            case .saveFailsOnTheSecondBatch:         return "a save fails on the second batch"
            case .epochSaveFails:                    return "the epoch's save fails"
            case .readBackFailsAfterTheFirstBatch:   return "read-back fails after the first batch"
            case .legacyKeyLostAfterTheFirstBatch:   return "a legacy key is lost after the first batch"
            }
        }
    }

    /// A pass that ends without the epoch having written nothing.
    enum BeforeAnyWrite: CaseIterable, CustomStringConvertible {
        case deviceLocked
        case localKeyUnavailable
        case readBackFailsFromTheStart
        /// Stand-ins for a kill before the first batch is saved, which never reports at all.
        case stoppedAfterTheFirstRow
        case stoppedBeforeTheBatches

        var description: String {
            switch self {
            case .deviceLocked:                 return "the device is locked"
            case .localKeyUnavailable:          return "the local key is unavailable"
            case .readBackFailsFromTheStart:    return "read-back fails from the first value"
            case .stoppedAfterTheFirstRow:      return "stopped after the first row"
            case .stoppedBeforeTheBatches:      return "stopped before the first batch"
            }
        }
    }

    private func launch(keys: TestKeyManager, store: LegacyStore, faults: KeyReseal.Faults? = nil) -> LaunchSequence.Report {
        KeyReseal.$faults.withValue(faults) {
            LaunchSequence.run(context: store.newContext(), keyManager: keys, batchSize: 7)
        }
    }

    private func launch(_ stop: Partway, keys: TestKeyManager, store: LegacyStore) -> LaunchSequence.Report {
        switch stop {
        case .saveFailsOnTheSecondBatch:
            return self.launch(keys: keys, store: store, faults: KeyReseal.Faults(interruptAt: .midBatch))
        case .epochSaveFails:
            return self.launch(keys: keys, store: store, faults: KeyReseal.Faults(interruptAt: .afterLastBatchBeforeEpoch))
        case .readBackFailsAfterTheFirstBatch:
            return self.launch(keys: keys, store: store, faults: KeyReseal.Faults(corruptsNewCiphertext: true, corruptsFromBatch: 1))
        case .legacyKeyLostAfterTheFirstBatch:
            keys.simulatesLegacyCustodyKeyUnavailable = true
            defer { keys.simulatesLegacyCustodyKeyUnavailable = false }
            return self.launch(keys: keys, store: store)
        }
    }

    private func launch(_ stop: BeforeAnyWrite, keys: TestKeyManager, store: LegacyStore) -> LaunchSequence.Report {
        switch stop {
        case .deviceLocked:
            keys.simulatesLockedDevice = true
            defer { keys.simulatesLockedDevice = false }
            return self.launch(keys: keys, store: store)
        case .localKeyUnavailable:
            keys.simulatesLocalKeyUnavailable = true
            defer { keys.simulatesLocalKeyUnavailable = false }
            return self.launch(keys: keys, store: store)
        case .readBackFailsFromTheStart:
            return self.launch(keys: keys, store: store, faults: KeyReseal.Faults(corruptsNewCiphertext: true))
        case .stoppedAfterTheFirstRow:
            return self.launch(keys: keys, store: store, faults: KeyReseal.Faults(interruptAt: .afterFirstRow))
        case .stoppedBeforeTheBatches:
            return self.launch(keys: keys, store: store, faults: KeyReseal.Faults(interruptAt: .afterFilesBeforeBatches))
        }
    }

    // MARK: - Blocked

    @Test("A pass that committed a batch and ended without the epoch reports blocked, however it stopped",
          arguments: Partway.allCases, KeyForm.allCases)
    func blockedWhenABatchCommittedAndTheEpochIsMissing(stop: Partway, form: KeyForm) throws {
        let (keys, store) = try prepare(form)

        let report = self.launch(stop, keys: keys, store: store)

        #expect(report.blocked, "\(stop)")
        #expect(report.screen == .storageError)
        #expect(appConfig(store)?.keyEpoch == nil, "no epoch was written")

        // It really is the store the decision is about: values moved while the process is on the legacy keys. A mix of
        // both, except when the epoch's own save is what failed, and every batch had moved its values already.
        let context = store.newContext()
        let states = Set(store.slots.map { store.state(of: $0, form: form, in: context) })
        #expect(states.contains(.new), "values were moved: \(states)")
        #expect(states.contains(.legacy) == (stop != .epochSaveFails), "\(states)")
    }

    @Test("The cases that stop without the epoch end as the report says they do",
          arguments: Partway.allCases)
    func theOutcomeOfEachPartwayStop(stop: Partway) throws {
        let (keys, store) = try prepare(.hybrid)

        let report = self.launch(stop, keys: keys, store: store)

        switch stop {
        case .saveFailsOnTheSecondBatch, .epochSaveFails:
            guard case .failure = report.reseal else { Issue.record("the pass was to throw: \(report.reseal)"); return }
        case .readBackFailsAfterTheFirstBatch:
            #expect(resealReport(report)?.outcome == .incomplete)
        case .legacyKeyLostAfterTheFirstBatch:
            #expect(resealReport(report)?.outcome == .aborted(.custodyKeyUnavailable))
        }
    }

    @Test("A blocked launch runs nothing after the pass: no migration, no verifier wrap, and the process stays on the legacy keys and plain verifiers",
          arguments: Partway.allCases, KeyForm.allCases)
    func blockedLaunchRunsNothingElse(stop: Partway, form: KeyForm) throws {
        let (keys, store) = try prepare(form)
        let rowsBefore = try store.rowCounts(in: store.newContext())
        let verifiersBefore = appConfig(store).map { [$0.sealedNormalVerifier, $0.sealedDuressVerifier].compactMap { $0 } + $0.sealedNormalVerifiers + $0.sealedDuressVerifiers }

        let report = self.launch(stop, keys: keys, store: store)

        #expect(report.blocked)
        #expect(Manager.Ambient.tierUKeys == .legacy)
        #expect(Manager.Ambient.pinVerifiers == .plain)
        #expect(try store.rowCounts(in: store.newContext()) == rowsBefore, "the passes that delete or add rows did not run")
        #expect(!KeyReseal.verifiersAreWrapped(in: store.newContext()), "the verifier wrap did not run")
        let verifiersAfter = appConfig(store).map { [$0.sealedNormalVerifier, $0.sealedDuressVerifier].compactMap { $0 } + $0.sealedNormalVerifiers + $0.sealedDuressVerifiers }
        #expect(verifiersAfter == verifiersBefore, "no verifier byte changed")
    }

    // MARK: - Not blocked

    @Test("A pass that stopped before it wrote anything is not blocked: the store isn't mixed, and the app runs on the legacy keys",
          arguments: BeforeAnyWrite.allCases, KeyForm.allCases)
    func notBlockedWhenNothingWasWritten(stop: BeforeAnyWrite, form: KeyForm) throws {
        let (keys, store) = try prepare(form)

        let report = self.launch(stop, keys: keys, store: store)

        #expect(!report.blocked, "\(stop)")
        #expect(report.screen == .app)
        #expect(appConfig(store)?.keyEpoch == nil)
        #expect(Manager.Ambient.tierUKeys == .legacy)

        let context = store.newContext()
        let states = Set(store.slots.map { store.state(of: $0, form: form, in: context) })
        #expect(!states.contains(.new), "nothing was moved: \(states)")
    }

    @Test("A completed pass is not blocked, and neither is the launch after it", arguments: KeyForm.allCases)
    func notBlockedWhenCompleted(form: KeyForm) throws {
        let (keys, store) = try prepare(form)

        let first = self.launch(keys: keys, store: store)
        #expect(resealReport(first)?.outcome == .completed)
        #expect(!first.blocked && first.screen == .app)

        let second = self.launch(keys: keys, store: store)
        #expect(resealReport(second)?.outcome == .alreadyDone)
        #expect(!second.blocked && second.screen == .app)
    }

    // MARK: - The next launch

    @Test("A relaunch without the fault finishes the pass and opens normally", arguments: Partway.allCases, KeyForm.allCases)
    func relaunchCompletes(stop: Partway, form: KeyForm) throws {
        let (keys, store) = try prepare(form)
        let rowsBefore = try store.rowCounts(in: store.newContext())
        #expect(self.launch(stop, keys: keys, store: store).blocked)

        let next = self.launch(keys: keys, store: store)

        #expect(resealReport(next)?.outcome == .completed)
        #expect(!next.blocked && next.screen == .app)
        #expect(Manager.Ambient.tierUKeys == .enclaveBound)
        #expect(keyEpoch(store, form: form) == Frozen.epoch(form))
        #expect(slots(store, notIn: .new, form: form, afterLaunchPasses: true).isEmpty)
        #expect(try store.rowCounts(in: store.newContext()) != rowsBefore, "the passes that were held back ran")

        // And Manager.Security reads its gate under the key it is sealed under, as at any launch.
        let security = Manager.Security(modelContainer: store.container, keyManager: keys)
        #expect(security.currentDepth == 2 && security.pinEnabled == false)
    }

    // MARK: - What the app is built over

    @Test("A blocked launch builds the rest of the app over an empty in-memory store, so nothing it constructs can read or write the real one")
    func blockedLaunchBuildsOverAScratchStore() throws {
        let (keys, store) = try prepare(.hybrid)
        let blocked = self.launch(.saveFailsOnTheSecondBatch, keys: keys, store: store)
        #expect(blocked.blocked)

        let scratch = try blocked.container(real: store.container)

        #expect(scratch !== store.container)
        #expect(try ModelContext(scratch).fetchCount(FetchDescriptor<AppLayerConfig>()) == 0)
        #expect(try ModelContext(scratch).fetchCount(FetchDescriptor<Contact.Profile>()) == 0)
        #expect(scratch.configurations.allSatisfy { $0.isStoredInMemoryOnly })
    }

    @Test("An unblocked launch builds it over the real store")
    func unblockedLaunchBuildsOverTheRealStore() throws {
        let (keys, store) = try prepare(.hybrid)
        let report = self.launch(keys: keys, store: store)
        #expect(!report.blocked)

        #expect(try report.container(real: store.container) === store.container)
    }
}

// MARK: - The screen

@Suite("Launch blocked — the screen", .ambientTestKeyManager)
@MainActor
struct LaunchBlockedScreenTests {

    @Test("The words name no keys, encryption, PIN or Secure Mode, and say what to do")
    func messageIsNeutral() {
        let message = StorageErrorView.message
        let lowered = message.lowercased()

        #expect(message.contains("couldn't finish updating"))
        #expect(lowered.contains("free storage"))
        #expect(lowered.contains("reopen"))

        for word in ["key", "encrypt", "secure mode", "pin", "duress", "enclave", "keychain", "vault", "backup", "reseal", "migrat", "cipher", "epoch"] {
            #expect(!lowered.contains(word), "the message names \(word)")
        }
    }

    // MARK: AppScreen

    private func makeSecurity(pin: Bool) throws -> Manager.Security {
        let container = try makeStore()
        let security = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        if pin { try security.configurePIN("111111") }
        return security
    }

    @Test("Once the blocking screen is up, AppScreen never starts the PIN flow, even if it is wired")
    func blockedAppScreenNeverPromptsForAPIN() throws {
        let security = try self.makeSecurity(pin: true)

        let control = AppScreen()
        control.wire(security: security)
        #expect(control.phase == .pinRequired, "control: an unblocked launch with a PIN asks for it")

        let screen = AppScreen()
        screen.blockedViewAppeared()
        #expect(screen.isBlocked)

        screen.wire(security: security)
        #expect(screen.phase == .covered)
    }

    // MARK: Hosted

    /// The whole environment `RootView` reads, over one in-memory store.
    private struct Setup {
        let container: ModelContainer
        let security: Manager.Security
        let contacts: ContactManager
        let challenge: IdentityChallenge.Coordinator
        let vault: VaultManager
        let custody: ShardCustodyManager
        let appScreen: AppScreen
    }

    private func makeEnvironment(pin: Bool) throws -> Setup {
        let container = try makeStore()
        let keys = TestKeyManager()
        let security = Manager.Security(modelContainer: container, keyManager: keys)
        if pin { try security.configurePIN("111111") }

        let contacts = ContactManager(modelContainer: container, security: security)
        return Setup(
            container: container, security: security, contacts: contacts,
            challenge: IdentityChallenge.Coordinator(contactManager: contacts),
            vault: VaultManager(modelContainer: container, keyManager: keys),
            custody: ShardCustodyManager(modelContainer: container, keyManager: keys),
            appScreen: AppScreen()
        )
    }

    /// Hosts `RootView` in a window on the test host's scene, as `KeyExchangeTeardownTests` hosts its screen: a window
    /// with no scene is not reliably laid out, and its views would never appear.
    private func host(_ screen: LaunchScreen, in env: Setup) throws -> UIWindow {
        let scene = try #require(UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.first)
        let root = RootView(storeURL: FileManager.default.temporaryDirectory.appendingPathComponent("launch-blocked-test.store"), launchScreen: screen)
            .environmentObject(env.appScreen)
            .environment(env.security)
            .environment(env.contacts)
            .environment(env.challenge)
            .environment(env.vault)
            .environment(env.custody)
            .modelContainer(env.container)

        let window = UIWindow(windowScene: scene)
        window.rootViewController = UIHostingController(rootView: root)
        window.makeKeyAndVisible()
        window.layoutIfNeeded()
        return window
    }

    /// Spins the run loop until `condition` holds or about two seconds pass.
    private func settle(until condition: () -> Bool) async throws {
        for _ in 0..<40 {
            if condition() { return }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
    }

    @Test("RootView with the blocking screen shows it before the PIN flow: the app screen is told, and the PIN prompt never comes")
    func rootViewShowsTheBlockingScreen() async throws {
        let env = try self.makeEnvironment(pin: true)
        let window = try self.host(.storageError, in: env)
        defer { window.isHidden = true }

        try await self.settle { env.appScreen.isBlocked }
        #expect(env.appScreen.isBlocked)

        // Long enough for the wiring task of the normal screen to have run, were it there.
        try await Task.sleep(nanoseconds: 500_000_000)
        #expect(env.appScreen.phase == .covered)
    }

    @Test("RootView with the app screen starts the PIN flow (control for the test above)")
    func rootViewShowsThePINFlowWhenNotBlocked() async throws {
        let env = try self.makeEnvironment(pin: true)
        let window = try self.host(.app, in: env)
        defer { window.isHidden = true }

        try await self.settle { env.appScreen.phase == .pinRequired }
        #expect(env.appScreen.phase == .pinRequired)
        #expect(!env.appScreen.isBlocked)
    }
}

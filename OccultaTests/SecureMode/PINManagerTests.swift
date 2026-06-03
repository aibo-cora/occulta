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
private func makeContainer() throws -> ModelContainer {
    let schema = Schema([
        AppLayerConfig.self,
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
    ])
    let config = ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)
    return try ModelContainer(for: schema, configurations: [config])
}

@MainActor
private func makeSecurity() throws -> Manager.Security {
    return try Manager.Security(modelContainer: makeContainer(), keyManager: TestKeyManager())
}

/// Creates a security manager plus the contact/vault managers needed by `activateSecureMode`.
/// The vault manager starts locked (no LAContext) so vault PEK extraction is skipped.
/// An `InMemoryLayerStoreBackend` is injected so tests never touch the filesystem.
@MainActor
private func makeSecurityAndManagers() throws -> (security: Manager.Security,
                                                    container: ModelContainer,
                                                    contacts: ContactManager,
                                                    vault: VaultManager) {
    let container = try makeContainer()
    let security  = Manager.Security(modelContainer: container, keyManager: TestKeyManager(),
                                     layerStore: Manager.LayerStore(backend: InMemoryLayerStoreBackend()))
    let contacts  = ContactManager(modelContainer: container)
    let vault     = VaultManager(modelContainer: container, keyManager: TestKeyManager())
    return (security, container, contacts, vault)
}

// MARK: - State transitions

@MainActor
@Suite("Security — State transitions", .serialized)
struct SecurityStateTests {

    @Test func noPIN_verify_throwsNotConfigured() throws {
        let s = try makeSecurity()
        #expect(throws: Manager.Security.SecurityError.notConfigured) {
            try s.verify("000000")
        }
    }

    @Test func configurePIN_transitionsToPinOnly() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        #expect(s.requiresPIN && !s.isSecureModeActive)
    }

    @Test func configurePIN_insertsExactlyOneConfig() throws {
        let container = try makeContainer()
        let s = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        try s.configurePIN("123456")
        let context = ModelContext(container)
        let configs = try context.fetch(FetchDescriptor<AppLayerConfig>())
        #expect(configs.count == 1)
    }

    @Test func configurePIN_twice_replacesExistingConfig() throws {
        let container = try makeContainer()
        let s = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        try s.configurePIN("111111")
        try s.configurePIN("222222")
        let context = ModelContext(container)
        let configs = try context.fetch(FetchDescriptor<AppLayerConfig>())
        #expect(configs.count == 1)
    }

    @Test func deactivatePIN_fromPinOnly_transitionsToNoPIN() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        try s.deactivatePIN(confirmingNormalPIN: "123456")
        #expect(!s.requiresPIN)
    }

    @Test func deactivatePIN_wrongPIN_throwsIncorrectPIN() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        #expect(throws: Manager.Security.SecurityError.incorrectPIN) {
            try s.deactivatePIN(confirmingNormalPIN: "000000")
        }
    }

    @Test func deactivatePIN_fromActive_throwsInvalidStateTransition() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try await s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        #expect(throws: Manager.Security.SecurityError.invalidStateTransition) {
            try s.deactivatePIN(confirmingNormalPIN: "123456")
        }
    }

    @Test func activateSecureMode_fromNoPIN_throwsInvalidStateTransition() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        await #expect(throws: Manager.Security.SecurityError.invalidStateTransition) {
            try await s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999",
                                            contactManager: cm, vaultManager: vm)
        }
    }

    @Test func activateSecureMode_wrongNormalPIN_throwsIncorrectPIN() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        await #expect(throws: Manager.Security.SecurityError.incorrectPIN) {
            try await s.activateSecureMode(confirmingEntryPIN: "000000", duressPIN: "999999",
                                            contactManager: cm, vaultManager: vm)
        }
    }

    @Test func activateSecureMode_fromPinOnly_transitionsToActive() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try await s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        #expect(s.isSecureModeActive && s.state == .normal)
    }

    @Test func deactivateSecureMode_fromDepth0_transitionsToPinOnly() async throws {
        // Owner at depth 0 (real app) deactivates using master PIN.
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try await s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        // currentDepth is already 0 (real app) — no verify needed.
        try await s.deactivateSecureMode(confirmingEntryPIN: "123456",
                                         contactManager: cm, vaultManager: vm)
        #expect(s.requiresPIN && !s.isSecureModeActive)
    }

    @Test func deactivateSecureMode_fromDepth1_transitionsToPinOnly() async throws {
        // Coercer at depth 1 (decoy view, via routing alias) deactivates using duress PIN.
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try await s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        // Route to depth 1 via routing alias.
        s.applyVerifyState(for: try s.verify("999999"))
        #expect(s.currentDepth == 1)
        // Confirmation PIN at depth 1 is the routing alias = duress PIN.
        try await s.deactivateSecureMode(confirmingEntryPIN: "999999",
                                         contactManager: cm, vaultManager: vm)
        #expect(s.requiresPIN && !s.isSecureModeActive)
    }

    @Test func deactivateSecureMode_fromPinOnly_throwsInvalidStateTransition() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        await #expect(throws: Manager.Security.SecurityError.invalidStateTransition) {
            try await s.deactivateSecureMode(confirmingEntryPIN: "123456",
                                             contactManager: cm, vaultManager: vm)
        }
    }
}

// MARK: - Verify: pinOnly

@MainActor
@Suite("Security — Verify (pinOnly)")
struct SecurityVerifyPinOnlyTests {

    @Test func correctNormal_returnsNormal() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        #expect(try s.verify("123456") == .normal(depth: 0))
    }

    @Test func wrongPIN_returnsWrong() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        #expect(try s.verify("000000") == .wrong)
    }

    @Test func threeWrongPINs_returnsWrong_noWipe() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        // Third wrong attempt must not wipe — pinOnly has no wipe threshold.
        #expect(try s.verify("000000") == .wrong)
    }
}

// MARK: - Verify: active / duress

@MainActor
@Suite("Security — Verify (active/duress)")
struct SecurityVerifyActiveTests {

    @Test func active_correctNormal_returnsNormal() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try await s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        #expect(try s.verify("123456") == .normal(depth: 0))
    }

    @Test func active_duressPIN_routesToDepth1() async throws {
        // With routing aliases, entering the duress PIN hits sealedNormalVerifiers[1]
        // in step 1 of verify() and returns .normal(depth: 1) — not .duress.
        // The decoy view is reached at depth 1 in .normal state.
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try await s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        let result = try s.verify("999999")
        s.applyVerifyState(for: result)
        #expect(result == .normal(depth: 1))
        #expect(s.currentDepth == 1)
        #expect(s.state == .normal)
        #expect(s.isRestricted)  // depth > 0 → decoy filter active
    }

    @Test func active_threeWrongPINs_returnsWipe() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try await s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        #expect(try s.verify("000000") == .wipe)
    }

    @Test func depth1_masterPIN_routesToDepth0() async throws {
        // From depth 1 (decoy), entering master PIN routes directly back to depth 0.
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try await s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        s.applyVerifyState(for: try s.verify("999999"))   // → depth 1
        #expect(try s.verify("123456") == .normal(depth: 0))
        #expect(s.isSecureModeActive && s.state == .normal)
    }

    @Test func depth1_duressPIN_routesToDepth1() async throws {
        // Entering duress PIN always routes to depth 1 (routing alias in normalVerifiers[1]).
        // Does NOT accumulate a duress counter — step 1 match resets all counters.
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try await s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        s.applyVerifyState(for: try s.verify("999999"))   // → depth 1
        #expect(try s.verify("999999") == .normal(depth: 1))
    }

    @Test func depth1_wrongPIN_returnsWrong() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try await s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        s.applyVerifyState(for: try s.verify("999999"))   // → depth 1
        #expect(try s.verify("000000") == .wrong)
    }

    @Test func consecutiveDuressRoutings_doNotAccumulateDuressCounter() async throws {
        // Entering duress PIN hits routing alias (step 1) → .normal(depth:1) → resets counters.
        // The consecutive-duress panic trigger (Step 5) requires a separate mechanism
        // since step 1 always preempts step 2 when routing aliases are present.
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try await s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        _ = try s.verify("999999")   // step 1 match → .normal(depth:1), counter reset
        _ = try s.verify("999999")   // same
        // Third entry should NOT wipe — counter never accumulates via step 1 path.
        #expect(try s.verify("999999") == .normal(depth: 1))
    }
}

// MARK: - Counter cross-reset

@MainActor
@Suite("Security — Counter cross-reset")
struct SecurityCounterTests {

    @Test func normalPIN_resetsWrongCounter_preventsEarlyWipe() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try await s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        _ = try s.verify("123456")   // normal → resets wrong counter
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        // Only 2 wrongs since last reset — must not wipe yet.
        #expect(try s.verify("000000") == .wipe)  // 3rd wrong since reset
    }

    @Test func duressPIN_resetsWrongCounter() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try await s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        _ = try s.verify("999999")   // duress → resets wrong counter
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        // Only 2 wrongs since reset — not yet wipe.
        #expect(try s.verify("000000") == .wipe)  // 3rd wrong since reset
    }

    @Test func duressPINViaRoutingAlias_resetsWrongCounter() async throws {
        // Entering the duress PIN hits the routing alias via step 1 → .normal(depth:1),
        // which calls resetCounters(). This verifies wrong counter is cleared.
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try await s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        _ = try s.verify("999999")   // routing alias → .normal(depth:1), resets wrong counter
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        // Only 2 wrongs since reset — not yet wipe.
        #expect(try s.verify("000000") == .wipe)  // 3rd wrong since reset
    }
}

// MARK: - Wipe threshold fallback

@MainActor
@Suite("AppLayerConfig — Wipe threshold fallback")
struct WipeThresholdFallbackTests {

    @Test func nilEncryptedData_returnsFallback() throws {
        let container = try makeContainer()
        let ctx = ModelContext(container)
        let config = AppLayerConfig()
        // wipeThresholdEncrypted defaults to nil
        ctx.insert(config)
        try ctx.save()
        #expect(config.wipeThreshold() == 3)
    }

    @Test func corruptEncryptedData_returnsFallback() throws {
        let container = try makeContainer()
        let ctx = ModelContext(container)
        let config = AppLayerConfig()
        config.wipeThresholdEncrypted = Data([0xFF, 0xFE, 0xFD, 0x00])  // not valid AES-GCM
        ctx.insert(config)
        try ctx.save()
        #expect(config.wipeThreshold() == 3)
    }

    @Test func validThreshold_roundTrips() throws {
        let container = try makeContainer()
        let ctx = ModelContext(container)
        let config = AppLayerConfig()
        try config.setWipeThreshold(7)
        ctx.insert(config)
        try ctx.save()
        #expect(config.wipeThreshold() == 7)
    }
}

// MARK: - Safe contacts

@MainActor
@Suite("Security — Safe contacts")
struct SecuritySafeContactTests {

    private func insertContact(identifier: String, in context: ModelContext) {
        let contact = Contact.Profile(
            identifier: identifier, givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        context.insert(contact)
    }

    @Test func updateAndFetch_roundTrip() throws {
        let container = try makeContainer()
        let s = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        let ctx = ModelContext(container)
        self.insertContact(identifier: "abc", in: ctx)
        self.insertContact(identifier: "def", in: ctx)
        self.insertContact(identifier: "ghi", in: ctx)
        try ctx.save()

        // mark "abc" and "ghi" safe, "def" sensitive
        try s.updateSafeContacts(["abc", "ghi"])
        let safe = s.safeContactIDs()
        #expect(safe.contains("abc"))
        #expect(safe.contains("ghi"))
        #expect(!safe.contains("def"))
    }

    @Test func isSafeContact_unknownID_returnsFalse() throws {
        let s = try makeSecurity()
        #expect(s.isSafeContact("xyz") == false)
    }

    @Test func isSafeContact_markedSensitive_returnsFalse() throws {
        let container = try makeContainer()
        let s = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        let ctx = ModelContext(container)
        self.insertContact(identifier: "abc", in: ctx)
        self.insertContact(identifier: "def", in: ctx)
        try ctx.save()

        try s.updateSafeContacts(["abc"])  // "def" → sensitive
        #expect(s.isSafeContact("abc") == true)
        #expect(s.isSafeContact("def") == false)
    }

    @Test func isSafeContact_unclassified_returnsTrue() throws {
        let container = try makeContainer()
        let s = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        let ctx = ModelContext(container)
        self.insertContact(identifier: "abc", in: ctx)
        try ctx.save()

        // no updateSafeContacts call — nil visibleThroughDepth → always visible
        #expect(s.isSafeContact("abc") == true)
    }
}

// MARK: - Depth > 1 (multi-layer)

@MainActor
@Suite("Security — Depth > 1 (multi-layer)", .serialized)
struct SecurityMultiLayerTests {

    @Test func secondActivation_fromDepth1_succeeds() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)

        // Route to depth 1 via routing alias.
        s.applyVerifyState(for: try s.verify("999999"))
        #expect(s.currentDepth == 1)

        // Activate a second duress layer from depth 1.
        try await s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "777777",
                                        contactManager: cm, vaultManager: vm)
        #expect(s.isSecureModeActive)
    }

    @Test func thirdDuressPIN_routesToDepth2() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        s.applyVerifyState(for: try s.verify("999999"))
        try await s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "777777",
                                        contactManager: cm, vaultManager: vm)

        // Cold-start routing: "777777" matches normalVerifiers[2] via step 1.
        let result = try s.verify("777777")
        s.applyVerifyState(for: result)
        #expect(result == .normal(depth: 2))
        #expect(s.currentDepth == 2)
        #expect(s.isRestricted)
    }

    @Test func deactivation_fromDepth2_goesToDepth1() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        s.applyVerifyState(for: try s.verify("999999"))
        try await s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "777777",
                                        contactManager: cm, vaultManager: vm)
        s.applyVerifyState(for: try s.verify("777777"))
        #expect(s.currentDepth == 2)

        // Deactivate from depth 2 — per the two-step chain, should land at depth 1.
        try await s.deactivateSecureMode(confirmingEntryPIN: "777777",
                                         contactManager: cm, vaultManager: vm)
        #expect(s.currentDepth == 1)
        #expect(s.state == .duress)
        #expect(s.isSecureModeActive, "depth 0→1 layer must still be active")
    }

    @Test func deactivation_depth2_thenDepth1_reachesPinOnly() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        s.applyVerifyState(for: try s.verify("999999"))
        try await s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "777777",
                                        contactManager: cm, vaultManager: vm)
        s.applyVerifyState(for: try s.verify("777777"))

        // Two-step deactivation chain.
        try await s.deactivateSecureMode(confirmingEntryPIN: "777777",
                                         contactManager: cm, vaultManager: vm)  // depth 2 → depth 1
        #expect(s.currentDepth == 1)

        try await s.deactivateSecureMode(confirmingEntryPIN: "999999",
                                         contactManager: cm, vaultManager: vm)  // depth 1 → pinOnly
        #expect(s.currentDepth == 0)
        #expect(s.requiresPIN && !s.isSecureModeActive)
    }

    @Test func allThreePINs_routeToCorrectDepths() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        s.applyVerifyState(for: try s.verify("999999"))
        try await s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "777777",
                                        contactManager: cm, vaultManager: vm)

        // All three PINs must route to their respective depths via step-1 scan.
        #expect(try s.verify("111111") == .normal(depth: 0))
        #expect(try s.verify("999999") == .normal(depth: 1))
        #expect(try s.verify("777777") == .normal(depth: 2))
    }

    @Test func pinCollision_rejected_acrossAllDepths() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        s.applyVerifyState(for: try s.verify("999999"))

        // Attempting to reuse "111111" (master) or "999999" (depth-1 duress) must throw.
        await #expect(throws: Manager.Security.SecurityError.pinCollision) {
            try await s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "111111",
                                            contactManager: cm, vaultManager: vm)
        }
        await #expect(throws: Manager.Security.SecurityError.pinCollision) {
            try await s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "999999",
                                            contactManager: cm, vaultManager: vm)
        }
    }
}

// MARK: - disablePINFromCurrentDepth / reEnablePIN

@MainActor
@Suite("Security — Coercion gate (disable/re-enable PIN)", .serialized)
struct SecurityCoercionGateTests {

    @Test func disablePIN_wrongConfirmation_throws() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        #expect(throws: Manager.Security.SecurityError.incorrectPIN) {
            try s.disablePINFromCurrentDepth(confirmingPIN: "000000")
        }
    }

    @Test func disablePIN_atDepth0_withMasterPIN_lowersGate() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        try s.disablePINFromCurrentDepth(confirmingPIN: "111111")
        #expect(!s.appLockEnabled)
        // Verifiers must remain intact — Secure Mode still active.
        #expect(s.isSecureModeActive)
        #expect(s.currentDepth == 0)
    }

    @Test func disablePIN_atDepth1_withDuressPIN_lowersGate() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        s.applyVerifyState(for: try s.verify("999999"))
        #expect(s.currentDepth == 1)

        // Confirm with the depth-1 PIN (routing alias = duress PIN).
        try s.disablePINFromCurrentDepth(confirmingPIN: "999999")
        #expect(!s.appLockEnabled)
        #expect(s.isSecureModeActive)
        #expect(s.currentDepth == 1)
    }

    @Test func reEnablePIN_masterPIN_restoresDepth0() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        try s.disablePINFromCurrentDepth(confirmingPIN: "111111")
        #expect(!s.appLockEnabled)

        let matched = s.reEnablePIN("111111")
        #expect(matched)
        #expect(s.appLockEnabled)
        #expect(s.currentDepth == 0)
        #expect(s.state == .normal)
    }

    @Test func reEnablePIN_duressPIN_restoresDepth1() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        try s.disablePINFromCurrentDepth(confirmingPIN: "111111")

        // Re-enable with duress PIN → routes to depth 1.
        let matched = s.reEnablePIN("999999")
        #expect(matched)
        #expect(s.appLockEnabled)
        #expect(s.currentDepth == 1)
    }

    @Test func reEnablePIN_wrongPIN_returnsFalse() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        try s.disablePINFromCurrentDepth(confirmingPIN: "111111")

        #expect(s.reEnablePIN("000000") == false)
        #expect(!s.appLockEnabled)  // gate stays down
    }
}

// MARK: - checkNormalPIN / checkCurrentLayerPIN

@MainActor
@Suite("Security — PIN check helpers (no side effects)", .serialized)
struct SecurityPINCheckTests {

    @Test func checkNormalPIN_correctMasterPIN_returnsTrue() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        #expect(s.checkNormalPIN("111111"))
    }

    @Test func checkNormalPIN_wrongPIN_returnsFalse() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        #expect(!s.checkNormalPIN("000000"))
    }

    @Test func checkNormalPIN_doesNotIncrementWrongCounter() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        // Call wrong PIN twice — should NOT bring us closer to wipe.
        _ = s.checkNormalPIN("000000")
        _ = s.checkNormalPIN("000000")
        // Real verify with wrong PIN should still be at count 0 (not 2).
        _ = try s.verify("000000")  // count = 1
        _ = try s.verify("000000")  // count = 2
        #expect(try s.verify("000000") == .wipe)  // count = 3 → wipe threshold
    }

    @Test func checkCurrentLayerPIN_atDepth0_matchesMasterPIN() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        #expect(s.checkCurrentLayerPIN("111111"))
        #expect(!s.checkCurrentLayerPIN("999999"))
    }

    @Test func checkCurrentLayerPIN_atDepth1_matchesDuressPIN() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        s.applyVerifyState(for: try s.verify("999999"))
        #expect(s.currentDepth == 1)
        // At depth 1, normalVerifiers[1] = routing alias (built with normalLabel + "999999").
        #expect(s.checkCurrentLayerPIN("999999"))
        #expect(!s.checkCurrentLayerPIN("111111"))
    }

    @Test func checkCurrentLayerPIN_doesNotIncrementWrongCounter() async throws {
        let (s, _, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        _ = s.checkCurrentLayerPIN("000000")
        _ = s.checkCurrentLayerPIN("000000")
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        #expect(try s.verify("000000") == .wipe)
    }
}

// MARK: - Verifier array padding

@MainActor
@Suite("AppLayerConfig — Verifier array invariants")
struct VerifierArrayPaddingTests {

    @Test func freshConfig_arrays_paddedTo32() throws {
        let container = try makeContainer()
        let ctx       = ModelContext(container)
        let config    = AppLayerConfig()
        ctx.insert(config)
        try ctx.save()

        #expect(config.sealedNormalVerifiers.count == AppLayerConfig.maxVerifierCount)
        #expect(config.sealedDuressVerifiers.count == AppLayerConfig.maxVerifierCount)
        #expect(config.sealedBlobSlots.count       == AppLayerConfig.maxVerifierCount)
        #expect(config.layerSequenceNumbers.count  == AppLayerConfig.maxVerifierCount)
    }

    @Test func afterConfigurePIN_normalVerifiers_still32() throws {
        let container = try makeContainer()
        let s         = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        try s.configurePIN("111111")

        let ctx    = ModelContext(container)
        let config = try ctx.fetch(FetchDescriptor<AppLayerConfig>()).first!
        #expect(config.sealedNormalVerifiers.count == AppLayerConfig.maxVerifierCount)
        #expect(config.sealedDuressVerifiers.count == AppLayerConfig.maxVerifierCount)
    }

    @Test func afterActivation_arrays_still32() async throws {
        let (s, container, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)

        let ctx    = ModelContext(container)
        let config = try ctx.fetch(FetchDescriptor<AppLayerConfig>()).first!
        #expect(config.sealedNormalVerifiers.count == AppLayerConfig.maxVerifierCount)
        #expect(config.sealedDuressVerifiers.count == AppLayerConfig.maxVerifierCount)
        #expect(config.sealedBlobSlots.count       == AppLayerConfig.maxVerifierCount)
        #expect(config.layerSequenceNumbers.count  == AppLayerConfig.maxVerifierCount)
    }

    @Test func afterDeactivation_arrays_still32() async throws {
        let (s, container, cm, vm) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try await s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999",
                                        contactManager: cm, vaultManager: vm)
        try await s.deactivateSecureMode(confirmingEntryPIN: "111111",
                                          contactManager: cm, vaultManager: vm)

        let ctx    = ModelContext(container)
        let config = try ctx.fetch(FetchDescriptor<AppLayerConfig>()).first!
        #expect(config.sealedNormalVerifiers.count == AppLayerConfig.maxVerifierCount)
        #expect(config.sealedDuressVerifiers.count == AppLayerConfig.maxVerifierCount)
        #expect(config.sealedBlobSlots.count       == AppLayerConfig.maxVerifierCount)
        #expect(config.layerSequenceNumbers.count  == AppLayerConfig.maxVerifierCount)
    }

    @Test func fillerSize_matchesPINManagerVerifierSize() {
        #expect(AppLayerConfig.verifierFillerSize == Manager.PINManager.verifierSize)
    }
}

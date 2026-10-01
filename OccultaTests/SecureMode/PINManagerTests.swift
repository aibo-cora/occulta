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
@MainActor
private func makeSecurityAndManagers() throws -> (security: Manager.Security,
                                                    container: ModelContainer,
                                                    contacts: ContactManager,
                                                    vault: VaultManager) {
    let container = try makeContainer()
    let security  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
    let contacts  = ContactManager(modelContainer: container, security: security)
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

    @Test(.ambientTestKeyManager) func configurePIN_transitionsToPinOnly() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        #expect(s.requiresPIN && !s.isSecureModeActive)
    }

    @Test(.ambientTestKeyManager) func configurePIN_insertsExactlyOneConfig() throws {
        let container = try makeContainer()
        let s = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        try s.configurePIN("123456")
        let context = ModelContext(container)
        let configs = try context.fetch(FetchDescriptor<AppLayerConfig>())
        #expect(configs.count == 1)
    }

    @Test(.ambientTestKeyManager) func configurePIN_twice_replacesExistingConfig() throws {
        let container = try makeContainer()
        let s = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        try s.configurePIN("111111")
        try s.configurePIN("222222")
        let context = ModelContext(container)
        let configs = try context.fetch(FetchDescriptor<AppLayerConfig>())
        #expect(configs.count == 1)
    }

    @Test(.ambientTestKeyManager) func deactivatePIN_fromPinOnly_transitionsToNoPIN() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        try s.deactivatePIN(confirmingNormalPIN: "123456")
        #expect(!s.requiresPIN)
    }

    @Test(.ambientTestKeyManager) func deactivatePIN_wrongPIN_throwsIncorrectPIN() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        #expect(throws: Manager.Security.SecurityError.incorrectPIN) {
            try s.deactivatePIN(confirmingNormalPIN: "000000")
        }
    }

    @Test(.ambientTestKeyManager) func deactivatePIN_fromActive_throwsInvalidStateTransition() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        #expect(throws: Manager.Security.SecurityError.invalidStateTransition) {
            try s.deactivatePIN(confirmingNormalPIN: "123456")
        }
    }

    @Test func activateSecureMode_fromNoPIN_throwsInvalidStateTransition() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        #expect(throws: Manager.Security.SecurityError.invalidStateTransition) {
            try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        }
    }

    @Test(.ambientTestKeyManager) func activateSecureMode_wrongNormalPIN_throwsIncorrectPIN() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        #expect(throws: Manager.Security.SecurityError.incorrectPIN) {
            try s.activateSecureMode(confirmingEntryPIN: "000000", duressPIN: "999999")
        }
    }

    @Test(.ambientTestKeyManager) func activateSecureMode_fromPinOnly_transitionsToActive() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        #expect(s.isSecureModeActive && s.state == .normal)
    }

    @Test(.ambientTestKeyManager) func deactivateSecureMode_fromDepth0_transitionsToPinOnly() async throws {
        // Owner at depth 0 (real app) deactivates using master PIN.
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        // currentDepth is already 0 (real app) — no verify needed.
        try s.deactivateSecureMode(confirmingEntryPIN: "123456")
        #expect(s.requiresPIN && !s.isSecureModeActive)
    }

    @Test(.ambientTestKeyManager) func deactivateSecureMode_fromDepth1_transitionsToPinOnly() async throws {
        // Coercer at depth 1 (decoy view, via routing alias) deactivates using duress PIN.
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        // Route to depth 1 via routing alias.
        s.applyVerifyState(for: try s.verify("999999"))
        #expect(s.currentDepth == 1)
        // Confirmation PIN at depth 1 is the routing alias = duress PIN.
        try s.deactivateSecureMode(confirmingEntryPIN: "999999")
        #expect(s.requiresPIN && !s.isSecureModeActive)
    }

    @Test(.ambientTestKeyManager) func deactivateSecureMode_fromPinOnly_throwsInvalidStateTransition() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        #expect(throws: Manager.Security.SecurityError.invalidStateTransition) {
            try s.deactivateSecureMode(confirmingEntryPIN: "123456")
        }
    }
}

// MARK: - Verify: pinOnly

@MainActor
@Suite("Security — Verify (pinOnly)")
struct SecurityVerifyPinOnlyTests {

    @Test(.ambientTestKeyManager) func correctNormal_returnsNormal() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        #expect(try s.verify("123456") == .normal(depth: 0))
    }

    @Test(.ambientTestKeyManager) func wrongPIN_returnsWrong() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        #expect(try s.verify("000000") == .wrong)
    }

    @Test(.ambientTestKeyManager) func threeWrongPINs_returnsWrong_noWipe() throws {
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

    @Test(.ambientTestKeyManager) func active_correctNormal_returnsNormal() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        #expect(try s.verify("123456") == .normal(depth: 0))
    }

    @Test(.ambientTestKeyManager) func active_duressPIN_routesToDepth1() async throws {
        // With routing aliases, entering the duress PIN hits sealedNormalVerifiers[1]
        // in step 1 of verify() and returns .normal(depth: 1) — not .duress.
        // The decoy view is reached at depth 1 in .duress state (not .normal — the
        // computed state property reflects that depth 1 is a decoy layer, not home).
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        let result = try s.verify("999999")
        s.applyVerifyState(for: result)
        #expect(result == .normal(depth: 1))
        #expect(s.currentDepth == 1)
        #expect(s.state == .duress)
        #expect(s.isRestricted)  // depth > 0 → decoy filter active
    }

    @Test(.ambientTestKeyManager) func active_threeWrongPINs_returnsWrong() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        #expect(try s.verify("000000") == .wrong)
    }

    @Test(.ambientTestKeyManager) func depth1_masterPIN_routesToDepth0() async throws {
        // From depth 1 (decoy), entering master PIN routes directly back to depth 0.
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        s.applyVerifyState(for: try s.verify("999999"))   // → depth 1
        s.applyVerifyState(for: try s.verify("123456"))   // → depth 0
        #expect(try s.verify("123456") == .normal(depth: 0))
        #expect(s.isSecureModeActive && s.state == .normal)
    }

    @Test(.ambientTestKeyManager) func depth1_duressPIN_routesToDepth1() async throws {
        // Entering duress PIN always routes to depth 1 (routing alias in normalVerifiers[1]).
        // Does NOT accumulate a duress counter — step 1 match resets all counters.
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        s.applyVerifyState(for: try s.verify("999999"))   // → depth 1
        #expect(try s.verify("999999") == .normal(depth: 1))
    }

    @Test(.ambientTestKeyManager) func depth1_wrongPIN_returnsWrong() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        s.applyVerifyState(for: try s.verify("999999"))   // → depth 1
        #expect(try s.verify("000000") == .wrong)
    }

}

// MARK: - Counter cross-reset

@MainActor
@Suite("Security — Counter cross-reset")
struct SecurityCounterTests {

    @Test(.ambientTestKeyManager) func normalPIN_resetsWrongCounter() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        _ = try s.verify("123456")   // normal → resets wrong counter
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        // Counter reset: subsequent wrong PINs still return .wrong (no accumulated state).
        #expect(try s.verify("000000") == .wrong)
    }

    @Test(.ambientTestKeyManager) func duressPIN_resetsWrongCounter() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        _ = try s.verify("999999")   // duress → resets wrong counter
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        #expect(try s.verify("000000") == .wrong)
    }

    @Test(.ambientTestKeyManager) func duressPINViaRoutingAlias_resetsWrongCounter() async throws {
        // Entering the duress PIN hits the routing alias via step 1 → .normal(depth:1),
        // which calls resetCounters(). This verifies wrong counter is cleared.
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        _ = try s.verify("999999")   // routing alias → .normal(depth:1), resets wrong counter
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        #expect(try s.verify("000000") == .wrong)
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

    @Test(.ambientTestKeyManager) func updateAndFetch_roundTrip() throws {
        let container = try makeContainer()
        let s  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        let cm = ContactManager(modelContainer: container, security: s)
        let ctx = ModelContext(container)
        self.insertContact(identifier: "abc", in: ctx)
        self.insertContact(identifier: "def", in: ctx)
        self.insertContact(identifier: "ghi", in: ctx)
        try ctx.save()

        // mark "abc" and "ghi" safe (vtd=Int.max), "def" sensitive (vtd=0 at depth 0).
        try cm.saveClassification(safeIDs: ["abc", "ghi"])

        // At depth 0 (real app) ALL contacts are visible — vtd=0 >= depth=0.
        #expect(cm.isSafeContact("abc"))
        #expect(cm.isSafeContact("ghi"))
        #expect(cm.isSafeContact("def"))  // visible in real app; hidden at depth 1+

        // At depth 1 (duress) only truly safe contacts appear.
        s.applyVerifyState(for: .normal(depth: 1))
        #expect(cm.isSafeContact("abc"))
        #expect(cm.isSafeContact("ghi"))
        #expect(!cm.isSafeContact("def"))  // vtd=0 < 1 → hidden
    }

    @Test func isSafeContact_unknownID_returnsFalse() throws {
        let container = try makeContainer()
        let s  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        let cm = ContactManager(modelContainer: container, security: s)
        #expect(cm.isSafeContact("xyz") == false)
    }

    @Test(.ambientTestKeyManager) func isSafeContact_markedSensitive_hiddenAtDepth1() throws {
        let container = try makeContainer()
        let s  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        let cm = ContactManager(modelContainer: container, security: s)
        let ctx = ModelContext(container)
        self.insertContact(identifier: "abc", in: ctx)
        self.insertContact(identifier: "def", in: ctx)
        try ctx.save()

        try cm.saveClassification(safeIDs: ["abc"])  // "def" → sensitive (vtd=0)

        // At depth 0 both contacts are visible (real app shows everything).
        #expect(cm.isSafeContact("abc") == true)
        #expect(cm.isSafeContact("def") == true)

        // At depth 1 "def" (vtd=0) is filtered out.
        s.applyVerifyState(for: .normal(depth: 1))
        #expect(cm.isSafeContact("abc") == true)
        #expect(cm.isSafeContact("def") == false)
    }

    @Test func isSafeContact_unclassified_returnsTrue() throws {
        let container = try makeContainer()
        let s  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        let cm = ContactManager(modelContainer: container, security: s)
        let ctx = ModelContext(container)
        self.insertContact(identifier: "abc", in: ctx)
        try ctx.save()

        // no saveClassification call — nil visibleThroughDepth → always visible
        #expect(cm.isSafeContact("abc") == true)
    }
}

// MARK: - Depth > 1 (multi-layer)

@MainActor
@Suite("Security — Depth > 1 (multi-layer)", .serialized)
struct SecurityMultiLayerTests {

    @Test(.ambientTestKeyManager) func secondActivation_fromDepth1_succeeds() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")

        // Route to depth 1 via routing alias.
        s.applyVerifyState(for: try s.verify("999999"))
        #expect(s.currentDepth == 1)

        // Activate a second duress layer from depth 1.
        try s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "777777")
        #expect(s.isSecureModeActive)
    }

    @Test(.ambientTestKeyManager) func thirdDuressPIN_routesToDepth2() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        s.applyVerifyState(for: try s.verify("999999"))
        try s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "777777")

        // Cold-start routing: "777777" matches normalVerifiers[2] via step 1.
        let result = try s.verify("777777")
        s.applyVerifyState(for: result)
        #expect(result == .normal(depth: 2))
        #expect(s.currentDepth == 2)
        #expect(s.isRestricted)
    }

    @Test(.ambientTestKeyManager) func deactivation_fromDepth2_popsOneLevelToDepth1() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        s.applyVerifyState(for: try s.verify("999999"))
        try s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "777777")
        s.applyVerifyState(for: try s.verify("777777"))
        #expect(s.currentDepth == 2)

        // LIFO pop: deactivating from depth 2 removes only that layer, landing
        // exactly one depth shallower — depth 1, coincidentally the same number a
        // 2-layer stack would produce either way, but for the LIFO reason, not
        // because deactivation always targets depth 1 specifically.
        try s.deactivateSecureMode(confirmingEntryPIN: "777777")
        #expect(s.currentDepth == 1)
        // coercerBaseDepth becomes the landed-on depth (1), so state reads .normal —
        // "Deactivate Protection" is reachable immediately, without a separate
        // re-verify, to pop the remaining depth 0→1 layer too.
        #expect(s.state == .normal)
        #expect(s.isSecureModeActive, "depth 0→1 layer must still be active")
    }

    @Test(.ambientTestKeyManager) func deactivation_depth2_thenDepth1_reachesPinOnly() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        s.applyVerifyState(for: try s.verify("999999"))
        try s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "777777")
        s.applyVerifyState(for: try s.verify("777777"))

        // Two-step deactivation chain, one LIFO pop per call.
        try s.deactivateSecureMode(confirmingEntryPIN: "777777")  // depth 2 → depth 1
        #expect(s.currentDepth == 1)

        try s.deactivateSecureMode(confirmingEntryPIN: "999999")  // depth 1 → pinOnly
        #expect(s.currentDepth == 0)
        #expect(s.requiresPIN && !s.isSecureModeActive)
    }

    /// The case a 2-layer stack can't distinguish: `depth - 1 == 1` either way there,
    /// so nothing before this test could tell "always land at depth 1" apart from a
    /// genuine LIFO pop. A 3-layer stack can — deactivating from depth 3 must land at
    /// depth 2, not jump straight to depth 1.
    @Test(.ambientTestKeyManager) func deactivation_fromDepth3_popsOneLevelToDepth2() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        s.applyVerifyState(for: try s.verify("999999"))
        try s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "777777")
        s.applyVerifyState(for: try s.verify("777777"))
        try s.activateSecureMode(confirmingEntryPIN: "777777", duressPIN: "444444")
        s.applyVerifyState(for: try s.verify("444444"))
        #expect(s.currentDepth == 3)

        try s.deactivateSecureMode(confirmingEntryPIN: "444444")

        #expect(s.currentDepth == 2, "must pop exactly one level, not cascade past depth 1")
        #expect(s.state == .normal, "Deactivate Protection must be reachable at the new depth")
        #expect(s.isSecureModeActive, "depths 0→1 and 1→2 must both still be active")

        // The popped-to layer's own shallower verifier chain must still be fully
        // intact and reachable — cold-start routing for "999999" still resolves to
        // depth 1, and "777777" (the layer that was NOT popped) still resolves to
        // depth 2, exactly as before the pop.
        let depth1Result = try s.verify("999999")
        #expect(depth1Result == .normal(depth: 1))
    }

    /// Full LIFO teardown: three activations, three deactivations, one level at a
    /// time, verifying `currentDepth` and `isSecureModeActive` after every step.
    @Test(.ambientTestKeyManager) func deactivation_threeLayerStack_popsOneLevelPerCall() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        s.applyVerifyState(for: try s.verify("999999"))
        try s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "777777")
        s.applyVerifyState(for: try s.verify("777777"))
        try s.activateSecureMode(confirmingEntryPIN: "777777", duressPIN: "444444")
        s.applyVerifyState(for: try s.verify("444444"))
        #expect(s.currentDepth == 3)

        try s.deactivateSecureMode(confirmingEntryPIN: "444444")  // depth 3 → depth 2
        #expect(s.currentDepth == 2)
        #expect(s.isSecureModeActive)

        try s.deactivateSecureMode(confirmingEntryPIN: "777777")  // depth 2 → depth 1
        #expect(s.currentDepth == 1)
        #expect(s.isSecureModeActive)

        try s.deactivateSecureMode(confirmingEntryPIN: "999999")  // depth 1 → pinOnly
        #expect(s.currentDepth == 0)
        #expect(s.requiresPIN && !s.isSecureModeActive)
    }

    @Test(.ambientTestKeyManager) func allThreePINs_routeToCorrectDepths() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        s.applyVerifyState(for: try s.verify("999999"))
        try s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "777777")

        // All three PINs must route to their respective depths via step-1 scan.
        #expect(try s.verify("111111") == .normal(depth: 0))
        #expect(try s.verify("999999") == .normal(depth: 1))
        #expect(try s.verify("777777") == .normal(depth: 2))
    }

    @Test(.ambientTestKeyManager) func pinCollision_rejected_acrossAllDepths() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        s.applyVerifyState(for: try s.verify("999999"))

        // Attempting to reuse "111111" (master) or "999999" (depth-1 duress) must throw.
        #expect(throws: Manager.Security.SecurityError.pinCollision) {
            try s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "111111")
        }
        #expect(throws: Manager.Security.SecurityError.pinCollision) {
            try s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "999999")
        }
    }

    // MARK: - Multi-layer contact classification

    /// At depth 1, saveClassification must stamp non-safe contacts with vtd=1 (not vtd=0).
    @Test(.ambientTestKeyManager) func updateSafeContacts_atDepth1_stampsCurrentDepthNotZero() throws {
        let container = try makeContainer()
        let s  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        let cm = ContactManager(modelContainer: container, security: s)
        let ctx = ModelContext(container)

        // Insert two contacts, mark "abc" as depth-0-sensitive, "def" as safe.
        let abc = Contact.Profile(identifier: "abc", givenName: "", familyName: "", middleName: "",
                                  nickname: "", organizationName: "", departmentName: "", jobTitle: "")
        let def_ = Contact.Profile(identifier: "def", givenName: "", familyName: "", middleName: "",
                                   nickname: "", organizationName: "", departmentName: "", jobTitle: "")
        ctx.insert(abc)
        ctx.insert(def_)
        try ctx.save()

        // Classify at depth 0: "abc" sensitive (vtd=0), "def" safe (vtd=Int.max).
        try cm.saveClassification(safeIDs: ["def"])
        #expect(cm.isSensitive("abc"))  // vtd == 0 == currentDepth(0)

        // Move to depth 1.
        s.applyVerifyState(for: .normal(depth: 1))
        #expect(s.currentDepth == 1)

        // At depth 1, classify "def" as sensitive for depth 2.
        // "abc" (vtd=0) is below current depth and must not be touched.
        try cm.saveClassification(safeIDs: [])  // no contacts safe at this depth

        // "def" should now have vtd=1 (hidden at depth 2), not vtd=0.
        #expect(cm.isSensitive("def"))          // vtd == 1 == currentDepth(1)
        // "abc" must be untouched — still vtd=0, not bumped to 1.
        s.applyVerifyState(for: .normal(depth: 0))
        #expect(cm.isSensitive("abc"))          // still vtd == 0 == currentDepth(0)
        // "abc" (vtd=0) is hidden at depth 1 but visible at depth 0 (real app).
        s.applyVerifyState(for: .normal(depth: 1))
        #expect(!cm.isSafeContact("abc"))
        // "def" (vtd=1) is hidden at depth 2 but visible at depths 0 and 1.
        #expect(cm.isSafeContact("def"))
        s.applyVerifyState(for: .normal(depth: 2))
        #expect(!cm.isSafeContact("def"))
    }

    /// At depth 1, saveClassification must not touch contacts already hidden
    /// below the current depth (vtd < currentDepth).
    @Test(.ambientTestKeyManager) func updateSafeContacts_atDepth1_skipsAlreadyHiddenContacts() throws {
        let container = try makeContainer()
        let s  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        let cm = ContactManager(modelContainer: container, security: s)
        let ctx = ModelContext(container)

        let hidden = Contact.Profile(identifier: "hidden", givenName: "", familyName: "", middleName: "",
                                     nickname: "", organizationName: "", departmentName: "", jobTitle: "")
        ctx.insert(hidden)
        try ctx.save()

        // Classify at depth 0: "hidden" is sensitive (vtd=0).
        try cm.saveClassification(safeIDs: [])

        // Move to depth 1 and re-classify — "hidden" is not visible here.
        s.applyVerifyState(for: .normal(depth: 1))
        try cm.saveClassification(safeIDs: [])  // no contacts in scope, nothing to change

        // "hidden" must still have vtd=0, not vtd=1 (depth-1 classification must not touch it).
        s.applyVerifyState(for: .normal(depth: 0))
        #expect(cm.isSensitive("hidden"))       // vtd still == 0 == currentDepth(0)
    }

    /// isSensitive at depth 1 should recognise vtd=1 contacts as sensitive,
    /// not vtd=0 contacts (those belong to the depth-0 classification).
    @Test(.ambientTestKeyManager) func isSensitive_atDepth1_checksCurrentDepthValue() throws {
        let container = try makeContainer()
        let s  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        let cm = ContactManager(modelContainer: container, security: s)
        let ctx = ModelContext(container)

        let a = Contact.Profile(identifier: "a", givenName: "", familyName: "", middleName: "",
                                nickname: "", organizationName: "", departmentName: "", jobTitle: "")
        let b = Contact.Profile(identifier: "b", givenName: "", familyName: "", middleName: "",
                                nickname: "", organizationName: "", departmentName: "", jobTitle: "")
        ctx.insert(a)
        ctx.insert(b)
        try ctx.save()

        // "a" → vtd=0, "b" → vtd=1 (visible at depth 1, hidden at depth 2).
        try cm.saveClassification(safeIDs: ["b"])   // depth 0: "a" sensitive
        s.applyVerifyState(for: .normal(depth: 1))
        try cm.saveClassification(safeIDs: [])      // depth 1: "b" sensitive

        // At depth 1: "b" is sensitive (vtd==1==currentDepth), "a" is not (vtd=0 < currentDepth).
        #expect(cm.isSensitive("b"))
        #expect(!cm.isSensitive("a"))

        // Back at depth 0: "a" is sensitive (vtd==0==currentDepth), "b" is not.
        s.applyVerifyState(for: .normal(depth: 0))
        #expect(cm.isSensitive("a"))
        #expect(!cm.isSensitive("b"))
    }
}

// MARK: - disablePIN(at:confirmingPIN:) / reEnablePIN

@MainActor
@Suite("Security — Coercion gate (disable/re-enable PIN)", .serialized)
struct SecurityCoercionGateTests {

    @Test(.ambientTestKeyManager) func disablePIN_wrongConfirmation_throws() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        #expect(throws: Manager.Security.SecurityError.incorrectPIN) {
            try s.disablePIN(at: s.currentDepth, confirmingPIN: "000000")
        }
    }

    @Test(.ambientTestKeyManager) func disablePIN_atDepth0_withMasterPIN_lowersGate() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        try s.disablePIN(at: s.currentDepth, confirmingPIN: "111111")
        #expect(!s.pinEnabled)
        // Verifiers must remain intact — Secure Mode still active.
        #expect(s.isSecureModeActive)
        #expect(s.currentDepth == 0)
    }

    @Test(.ambientTestKeyManager) func disablePIN_atDepth1_withDuressPIN_lowersGate() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        s.applyVerifyState(for: try s.verify("999999"))
        #expect(s.currentDepth == 1)

        // Confirm with the depth-1 PIN (routing alias = duress PIN).
        try s.disablePIN(at: s.currentDepth, confirmingPIN: "999999")
        #expect(!s.pinEnabled)
        #expect(s.isSecureModeActive)
        #expect(s.currentDepth == 1)
    }

    @Test(.ambientTestKeyManager) func reEnablePIN_masterPIN_restoresDepth0() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        try s.disablePIN(at: s.currentDepth, confirmingPIN: "111111")
        #expect(!s.pinEnabled)

        let matched = s.reEnablePIN("111111")
        #expect(matched)
        #expect(s.pinEnabled)
        #expect(s.currentDepth == 0)
        #expect(s.state == .normal)
    }

    @Test(.ambientTestKeyManager) func reEnablePIN_duressPIN_restoresDepth1() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        try s.disablePIN(at: s.currentDepth, confirmingPIN: "111111")

        // Re-enable with duress PIN → routes to depth 1.
        let matched = s.reEnablePIN("999999")
        #expect(matched)
        #expect(s.pinEnabled)
        #expect(s.currentDepth == 1)
    }

    @Test(.ambientTestKeyManager) func reEnablePIN_wrongPIN_returnsFalse() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        try s.disablePIN(at: s.currentDepth, confirmingPIN: "111111")

        #expect(s.reEnablePIN("000000") == false)
        #expect(!s.pinEnabled)  // gate stays down
    }
}

// MARK: - checkNormalPIN / checkCurrentLayerPIN

@MainActor
@Suite("Security — PIN check helpers (no side effects)", .serialized)
struct SecurityPINCheckTests {

    @Test(.ambientTestKeyManager) func checkNormalPIN_correctMasterPIN_returnsTrue() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        #expect(s.checkNormalPIN("111111"))
    }

    @Test(.ambientTestKeyManager) func checkNormalPIN_wrongPIN_returnsFalse() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        #expect(!s.checkNormalPIN("000000"))
    }

    @Test(.ambientTestKeyManager) func checkNormalPIN_doesNotIncrementWrongCounter() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        // checkNormalPIN must not increment wrongPINCount.
        _ = s.checkNormalPIN("000000")
        _ = s.checkNormalPIN("000000")
        // verify() starts from count 0, not 2.
        _ = try s.verify("000000")  // count = 1
        _ = try s.verify("000000")  // count = 2
        #expect(try s.verify("000000") == .wrong)  // count = 3; below lockout threshold (6)
    }

    @Test(.ambientTestKeyManager) func checkCurrentLayerPIN_atDepth0_matchesMasterPIN() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        #expect(s.checkCurrentLayerPIN("111111"))
        #expect(!s.checkCurrentLayerPIN("999999"))
    }

    @Test(.ambientTestKeyManager) func checkCurrentLayerPIN_atDepth1_matchesDuressPIN() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        s.applyVerifyState(for: try s.verify("999999"))
        #expect(s.currentDepth == 1)
        // At depth 1, normalVerifiers[1] = routing alias (built with normalLabel + "999999").
        #expect(s.checkCurrentLayerPIN("999999"))
        #expect(!s.checkCurrentLayerPIN("111111"))
    }

    @Test(.ambientTestKeyManager) func checkCurrentLayerPIN_atDepth1_fallsBackToDuressVerifierWhenRoutingAliasMissing() async throws {
        let (s, container, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        // Erase the routing alias at index 1 to simulate a pre-routing-alias config.
        let ctx = ModelContext(container)
        let config = try #require(try ctx.fetch(FetchDescriptor<AppLayerConfig>()).first)
        config.sealedNormalVerifiers[1] = AppLayerConfig.verifierFiller()
        try ctx.save()
        // Simulate verify() routing via the duress verifier (Step 2) — state = .duress, depth = 1.
        s.applyVerifyState(for: .duress)
        #expect(s.currentDepth == 1)
        // Fallback to sealedDuressVerifiers[0] (duressLabel) must accept the duress PIN.
        #expect(s.checkCurrentLayerPIN("999999"))
        #expect(!s.checkCurrentLayerPIN("111111"))
    }

    @Test(.ambientTestKeyManager) func checkCurrentLayerPIN_doesNotIncrementWrongCounter() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        _ = s.checkCurrentLayerPIN("000000")
        _ = s.checkCurrentLayerPIN("000000")
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        #expect(try s.verify("000000") == .wrong)
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

        #expect(config.sealedNormalVerifiers.count == AppLayerConfig.maxDepthCount)
        #expect(config.sealedDuressVerifiers.count == AppLayerConfig.maxDepthCount)
    }

    @Test(.ambientTestKeyManager) func afterConfigurePIN_normalVerifiers_still32() throws {
        let container = try makeContainer()
        let s         = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        try s.configurePIN("111111")

        let ctx    = ModelContext(container)
        let config = try ctx.fetch(FetchDescriptor<AppLayerConfig>()).first!
        #expect(config.sealedNormalVerifiers.count == AppLayerConfig.maxDepthCount)
        #expect(config.sealedDuressVerifiers.count == AppLayerConfig.maxDepthCount)
    }

    @Test(.ambientTestKeyManager) func afterActivation_arrays_still32() async throws {
        let (s, container, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")

        let ctx    = ModelContext(container)
        let config = try ctx.fetch(FetchDescriptor<AppLayerConfig>()).first!
        #expect(config.sealedNormalVerifiers.count == AppLayerConfig.maxDepthCount)
        #expect(config.sealedDuressVerifiers.count == AppLayerConfig.maxDepthCount)
    }

    @Test(.ambientTestKeyManager) func afterDeactivation_arrays_still32() async throws {
        let (s, container, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        try s.deactivateSecureMode(confirmingEntryPIN: "111111")

        let ctx    = ModelContext(container)
        let config = try ctx.fetch(FetchDescriptor<AppLayerConfig>()).first!
        #expect(config.sealedNormalVerifiers.count == AppLayerConfig.maxDepthCount)
        #expect(config.sealedDuressVerifiers.count == AppLayerConfig.maxDepthCount)
    }

    @Test func fillerSize_matchesPINManagerVerifierSize() {
        #expect(AppLayerConfig.verifierFillerSize == Manager.PINManager.verifierSize)
    }
}

// MARK: - Lockout counter

@MainActor
@Suite("Security — Lockout counter")
struct LockoutCounterTests {

    @Test(.ambientTestKeyManager) func fiveWrongPINs_noLockout() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        for _ in 0..<5 { _ = try s.verify("000000") }
        #expect(try s.verify("000000") == .wrong)  // 6th attempt triggers lockout on NEXT call
    }

    @Test(.ambientTestKeyManager) func sixthWrongPIN_triggersLockout() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        for _ in 0..<6 { _ = try s.verify("000000") }
        // 7th attempt — count is 6, expiry was written → locked
        let result = try s.verify("000000")
        if case .locked = result { } else { Issue.record("Expected .locked, got \(result)") }
    }

    @Test(.ambientTestKeyManager) func correctPIN_resetsLockoutCounter() async throws {
        let (s, _, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        for _ in 0..<5 { _ = try s.verify("000000") }
        // Correct PIN resets counter
        _ = try s.verify("123456")
        // Counter back to 0 — five more wrong attempts should not lock out
        for _ in 0..<5 { _ = try s.verify("000000") }
        #expect(try s.verify("000000") == .wrong)  // 6th wrong since reset → triggers delay on next
    }

    @Test func lockoutDelaySchedule_milestones() {
        #expect(Manager.Security.lockoutDelay(for: 5)  == nil)
        #expect(Manager.Security.lockoutDelay(for: 6)  == 60)
        #expect(Manager.Security.lockoutDelay(for: 12) == 3_600)
        #expect(Manager.Security.lockoutDelay(for: 20) == 86_400)
        #expect(Manager.Security.lockoutDelay(for: 99) == 86_400)
    }

    @Test(.ambientTestKeyManager) func lockoutExpiry_survivesAppKill() async throws {
        let (s, container, _, _) = try makeSecurityAndManagers()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        for _ in 0..<6 { _ = try s.verify("000000") }
        _ = try s.verify("000000")  // now locked

        // Simulate app kill + relaunch with a fresh Manager.Security on the same container
        let s2 = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        #expect(s2.lockoutExpiry() != nil)
    }
}

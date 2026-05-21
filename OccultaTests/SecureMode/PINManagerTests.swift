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

// MARK: - State transitions

@MainActor
@Suite("Security — State transitions")
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
        #expect(s.state == .pinOnly)
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
        #expect(s.state == .noPIN)
    }

    @Test func deactivatePIN_wrongPIN_throwsIncorrectPIN() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        #expect(throws: Manager.Security.SecurityError.incorrectPIN) {
            try s.deactivatePIN(confirmingNormalPIN: "000000")
        }
    }

    @Test func deactivatePIN_fromActive_throwsInvalidStateTransition() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        #expect(throws: Manager.Security.SecurityError.invalidStateTransition) {
            try s.deactivatePIN(confirmingNormalPIN: "123456")
        }
    }

    @Test func activateSecureMode_fromNoPIN_throwsInvalidStateTransition() throws {
        let s = try makeSecurity()
        #expect(throws: Manager.Security.SecurityError.invalidStateTransition) {
            try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        }
    }

    @Test func activateSecureMode_wrongNormalPIN_throwsIncorrectPIN() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        #expect(throws: Manager.Security.SecurityError.incorrectPIN) {
            try s.activateSecureMode(confirmingEntryPIN: "000000", duressPIN: "999999")
        }
    }

    @Test func activateSecureMode_fromPinOnly_transitionsToActive() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        #expect(s.state == .active)
    }

    @Test func deactivateSecureMode_fromActive_transitionsToPinOnly() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        try s.deactivateSecureMode(confirmingEntryPIN: "123456")
        #expect(s.state == .pinOnly)
    }

    @Test func deactivateSecureMode_fromDuress_transitionsToPinOnly() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        _ = try s.verify("999999")   // → .duress
        try s.deactivateSecureMode(confirmingEntryPIN: "123456")
        #expect(s.state == .pinOnly)
    }

    @Test func deactivateSecureMode_fromPinOnly_throwsInvalidStateTransition() throws {
        let s = try makeSecurity()
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

    @Test func correctNormal_returnsNormal() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        #expect(try s.verify("123456") == .normal)
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

    @Test func active_correctNormal_returnsNormal() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        #expect(try s.verify("123456") == .normal)
    }

    @Test func active_duressPIN_returnsDuress_transitionsToDuress() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        #expect(try s.verify("999999") == .duress)
        #expect(s.state == .duress)
    }

    @Test func active_threeWrongPINs_returnsWipe() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        #expect(try s.verify("000000") == .wipe)
    }

    @Test func duress_correctNormal_returnsNormal_transitionsToActive() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        _ = try s.verify("999999")   // → .duress
        #expect(try s.verify("123456") == .normal)
        #expect(s.state == .active)
    }

    @Test func duress_duressPIN_returnsDuress() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        _ = try s.verify("999999")   // → .duress, count=1
        #expect(try s.verify("999999") == .duress)
    }

    @Test func duress_wrongPIN_returnsWrong() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        _ = try s.verify("999999")   // → .duress
        #expect(try s.verify("000000") == .wrong)
    }

    @Test func consecutiveDuressHitsThreshold_returnsWipe() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        _ = try s.verify("999999")   // count=1 → .duress
        _ = try s.verify("999999")   // count=2 → .duress
        #expect(try s.verify("999999") == .wipe)  // count=3, threshold=3
    }
}

// MARK: - Counter cross-reset

@MainActor
@Suite("Security — Counter cross-reset")
struct SecurityCounterTests {

    @Test func normalPIN_resetsWrongCounter_preventsEarlyWipe() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        _ = try s.verify("123456")   // normal → resets wrong counter
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        // Only 2 wrongs since last reset — must not wipe yet.
        #expect(try s.verify("000000") == .wipe)  // 3rd wrong since reset
    }

    @Test func duressPIN_resetsWrongCounter() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        _ = try s.verify("999999")   // duress → resets wrong counter
        _ = try s.verify("000000")
        _ = try s.verify("000000")
        // Only 2 wrongs since reset — not yet wipe.
        #expect(try s.verify("000000") == .wipe)  // 3rd wrong since reset
    }

    @Test func wrongPIN_resetsDuressCounter_preventsEarlyWipe() throws {
        let s = try makeSecurity()
        try s.configurePIN("123456")
        try s.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        _ = try s.verify("999999")   // count=1
        _ = try s.verify("999999")   // count=2
        _ = try s.verify("000000")   // wrong → resets duress counter
        _ = try s.verify("999999")   // count=1
        _ = try s.verify("999999")   // count=2
        #expect(try s.verify("999999") == .wipe)  // count=3, threshold=3
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

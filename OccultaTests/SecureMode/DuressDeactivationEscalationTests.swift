//
//  DuressDeactivationEscalationTests.swift
//  OccultaTests
//
//  Bug 220: a depth's PIN never reaches a shallower depth than that PIN opens. The tests use only calls the Settings screen makes, gated on the conditions
//  `Settings.swift` shows its buttons on.
//

import Testing
import Foundation
import SwiftData
import LocalAuthentication

@testable import Occulta

@MainActor
@Suite("Security — a duress PIN never reaches a shallower depth (Bug 220)", .serialized)
struct DuressDeactivationEscalationTests {

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

    /// `Settings.swift`'s `isAtSecureModeHomeDepth`: what shows "Deactivate Protection".
    private func deactivateIsShown(_ s: Manager.Security) -> Bool {
        s.isSecureModeActive && s.state == .normal
            && (s.currentDepth == 0 || s.currentDepth == s.coercerBaseDepth)
            && s.pinEnabled
    }

    /// `Settings.swift`'s condition for the "Learn more" (activate) section.
    private func activateIsShown(_ s: Manager.Security) -> Bool {
        !s.isSecureModeActive || s.state == .duress || !s.pinEnabled
    }

    /// The owner has one duress layer. The coercer is given the duress PIN and nothing else.
    @Test(.ambientTestKeyManager) func duressPINHolder_activateThenDeactivate_staysAtDepth1() throws {
        let container = try self.makeContainer()
        let s  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        let cm = ContactManager(modelContainer: container, security: s)

        // Owner: master PIN 111111, duress PIN 999999, one contact hidden from every duress depth.
        let ctx = ModelContext(container)
        for identifier in ["safe", "hidden"] {
            ctx.insert(Contact.Profile(
                identifier: identifier, givenName: "", familyName: "", middleName: "",
                nickname: "", organizationName: "", departmentName: "", jobTitle: ""
            ))
        }
        try ctx.save()
        try s.configurePIN("111111")
        try cm.saveClassification(safeIDs: ["safe"])
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")

        // Coercer: enters the duress PIN at the lock screen.
        s.applyVerifyState(for: try s.verify("999999"))
        #expect(s.currentDepth == 1)
        #expect(!cm.isSafeContact("hidden"))
        #expect(self.activateIsShown(s))
        #expect(!self.deactivateIsShown(s))

        // Coercer: Settings → "Learn more" → confirms with the PIN they hold, sets any new PIN.
        #expect(s.checkCurrentLayerPIN("999999"))
        try s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "222222")

        // Coercer: "Deactivate Protection" is now offered at depth 1; confirms with the same PIN.
        #expect(self.deactivateIsShown(s))
        try s.deactivateSecureMode(confirmingEntryPIN: "999999")

        // The master PIN was never entered. The session must not be at the real depth,
        // and the hidden contact must still be hidden.
        #expect(s.currentDepth == 1, "a duress PIN alone moved the session to depth \(s.currentDepth)")
        #expect(!cm.isSafeContact("hidden"), "the contact hidden from duress depths is visible to the duress PIN holder")
        // The screen is back to what a PIN-only install shows, and the owner's PINs still work.
        #expect(self.activateIsShown(s) && !self.deactivateIsShown(s))
        #expect(try s.verify("222222") == .wrong, "the layer the coercer made is gone")
        #expect(try s.verify("111111") == .normal(depth: 0))
        #expect(try s.verify("999999") == .normal(depth: 1))
    }

    /// The owner made a second layer from depth 1 at some point, which leaves
    /// `coercerBaseDepth == 1`. A later holder of the first duress PIN needs one step.
    @Test(.ambientTestKeyManager) func duressPINHolder_ownerHasTwoLayers_deactivateStaysAtDepth1() throws {
        let container = try self.makeContainer()
        // One key manager for both instances: a relaunch keeps the device's PIN key.
        let keys = TestKeyManager()
        let s = Manager.Security(modelContainer: container, keyManager: keys)

        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        s.applyVerifyState(for: try s.verify("999999"))
        try s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "777777")
        // Owner goes back to the real depth; the app is later killed and relaunched.
        s.applyVerifyState(for: try s.verify("111111"))
        let relaunched = Manager.Security(modelContainer: container, keyManager: keys)

        // Coercer: enters the first duress PIN.
        relaunched.applyVerifyState(for: try relaunched.verify("999999"))
        #expect(relaunched.currentDepth == 1)

        #expect(self.deactivateIsShown(relaunched))
        try relaunched.deactivateSecureMode(confirmingEntryPIN: "999999")

        #expect(relaunched.currentDepth == 1, "a duress PIN alone moved the session to depth \(relaunched.currentDepth)")
        #expect(try relaunched.verify("111111") == .normal(depth: 0), "the master PIN must still open the real depth")
    }
}

/// Bugs 221 and 223: with the lock lowered at a duress depth, the holder sees what an install
/// with no PIN shows, and setting a PIN changes nothing they can see: same depth, same vault,
/// and the Settings screen of an install with only a PIN.
@MainActor
@Suite("Security — a lowered lock looks like no PIN, and setting one changes nothing visible (Bugs 221, 223)", .serialized)
struct LoweredLockTests {

    private func makeContainer() throws -> ModelContainer {
        let schema = Schema([AppLayerConfig.self])
        let config = ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)
        return try ModelContainer(for: schema, configurations: [config])
    }

    /// The condition Settings dims "Learn more" on, the same one the "Enable PIN" toggle reads.
    private func learnMoreIsEnabled(_ s: Manager.Security) -> Bool {
        Settings.pinReadsAsOn(requiresPIN: s.requiresPIN, pinEnabled: s.pinEnabled)
    }

    /// `Settings.swift`'s condition for the "Learn more" section being shown at all.
    private func activateIsShown(_ s: Manager.Security) -> Bool {
        !s.isSecureModeActive || s.state == .duress || !s.pinEnabled
    }

    /// `Settings.swift`'s `isAtSecureModeHomeDepth`: what shows "Deactivate Protection".
    private func deactivateIsShown(_ s: Manager.Security) -> Bool {
        s.isSecureModeActive && s.state == .normal
            && (s.currentDepth == 0 || s.currentDepth == s.coercerBaseDepth)
            && s.pinEnabled
    }

    /// Bug 223: "Learn more" is dimmed on an install with no PIN, so it must be dimmed with the
    /// lock lowered too.
    @Test(.ambientTestKeyManager) func loweredLock_learnMoreIsDimmed_likeNoPIN() throws {
        let fresh = Manager.Security(modelContainer: try self.makeContainer(), keyManager: TestKeyManager())
        #expect(!self.learnMoreIsEnabled(fresh), "an install with no PIN dims Learn more")

        let s = Manager.Security(modelContainer: try self.makeContainer(), keyManager: TestKeyManager())
        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        s.applyVerifyState(for: try s.verify("999999"))
        try s.disablePIN(at: 1, confirmingPIN: "999999")

        #expect(!self.learnMoreIsEnabled(s), "a lowered lock must dim Learn more, as no PIN does")
    }

    /// Bug 221: the holder turns "Enable PIN" on with a PIN of their own. At
    /// the next lock screen that PIN must open the depth they were at, with the same vault.
    @Test(.ambientTestKeyManager) func loweredLock_settingAPIN_keepsTheSameDepthAndVault() throws {
        let container = try self.makeContainer()
        let s = Manager.Security(modelContainer: container, keyManager: TestKeyManager())

        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        s.applyVerifyState(for: try s.verify("999999"))
        try s.disablePIN(at: s.currentDepth, confirmingPIN: "999999")
        #expect(s.currentDepth == 1 && !s.pinEnabled)

        // A decoy vault entry the owner made at depth 1.
        let vaultContainer = try ModelContainer(
            for: Schema([VaultEntry.self]),
            configurations: ModelConfiguration(schema: Schema([VaultEntry.self]), isStoredInMemoryOnly: true)
        )
        let vm = VaultManager(modelContainer: vaultContainer, keyManager: TestKeyManager())
        vm.unlock(context: LAContext())
        let decoy = try vm.addEntry(label: "decoy", content: Data(), type: .note, currentDepth: 1)
        #expect(s.visibleVaultEntries(from: [decoy]).count == 1)

        // Holder: Settings → Enable PIN → enters a PIN of their own twice.
        #expect(s.reEnablePIN("555555"))
        #expect(s.pinEnabled)

        // Next lock screen: they enter the PIN they just set.
        s.applyVerifyState(for: try s.verify("555555"))
        #expect(s.currentDepth == 1, "setting a PIN moved the session from depth 1 to depth \(s.currentDepth)")
        #expect(s.visibleVaultEntries(from: [decoy]).count == 1, "the vault entry shown before the PIN was set is gone after it")
    }

    /// Bug 221: what the holder can see after setting their PIN is an install with only a PIN.
    /// The owner keeps the master PIN and every deeper layer; only depth 1's own PIN is replaced.
    @Test(.ambientTestKeyManager) func loweredLock_settingAPIN_looksLikePINOnly_andKeepsOtherLayers() throws {
        let container = try self.makeContainer()
        let s = Manager.Security(modelContainer: container, keyManager: TestKeyManager())

        try s.configurePIN("111111")
        try s.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        s.applyVerifyState(for: try s.verify("999999"))
        try s.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "777777")   // owner's depth 2
        try s.disablePIN(at: 1, confirmingPIN: "999999")

        #expect(s.reEnablePIN("555555"))
        #expect(s.currentDepth == 1)
        #expect(self.activateIsShown(s) && !self.deactivateIsShown(s), "right after setting the PIN")

        s.applyVerifyState(for: try s.verify("555555"))
        #expect(self.activateIsShown(s) && !self.deactivateIsShown(s), "after unlocking with it")

        #expect(try s.verify("111111") == .normal(depth: 0), "the master PIN still opens depth 0")
        #expect(try s.verify("777777") == .normal(depth: 2), "the owner's deeper layer is untouched")
        #expect(try s.verify("999999") == .wrong, "depth 1's old PIN is replaced by the holder's")
    }
}

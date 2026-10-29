//
//  EncryptedFieldCoverageTests.swift
//  OccultaTests
//
//  Regression coverage for Bug 80: `ContactManager.hasReadableBundleVersion` must
//  distinguish "never seen" (nil) from "present but undecryptable" (stranded) — collapsing
//  the two into a single nil check produced the false "they need to update" message about
//  apps that were current.
//
//  This file used to be much larger: field-level coverage for the Secure Mode key-rotation
//  machinery (`reencryptAllFields`, `Group.reencrypt`, `AppLayerConfig.reencrypt`, and their
//  tripwires against unreviewed stored properties). That machinery — and the whole bug class
//  of "a field silently escapes the rotation" it guarded against — was removed along with key
//  rotation itself (Removal Stage 3, `plan.md`). What remains here is unrelated to rotation:
//  `maxBundleVersion` can still be found stranded on installs that went through a rotation
//  before this removal shipped, and `hasReadableBundleVersion`'s three-state read stays
//  load-bearing for them indefinitely.
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta

private func canonicalKey() -> SymmetricKey? {
    try? Manager.Ambient.keyManager.createHybridLocalEncryptionKey()
}

private func makeProbeProfile() -> Contact.Profile {
    Contact.Profile(
        identifier: "probe", givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: "",
        phoneticGivenName: "", phoneticMiddleName: "", phoneticFamilyName: "", note: ""
    )
}

@Suite("Bug 80 — stranded vs never-seen bundle version", .ambientTestKeyManager)
struct EncryptedFieldRotationTests {

    /// Why `maxBundleVersion` must distinguish "present but unreadable" from "never seen":
    /// three states, three answers.
    @Test("hasReadableBundleVersion separates stranded from never-seen")
    func readabilitySeparatesStrandedFromAbsent() throws {
        _ = try #require(canonicalKey())

        let neverSeen = makeProbeProfile()
        neverSeen.maxBundleVersion = nil
        #expect(!ContactManager.hasReadableBundleVersion(neverSeen))

        let stranded = makeProbeProfile()
        stranded.maxBundleVersion = try Data([0x07]).encrypt(using: SymmetricKey(size: .bits256))
        #expect(!ContactManager.hasReadableBundleVersion(stranded))
        #expect(stranded.maxBundleVersion != nil, "stranded must stay distinguishable from absent")

        let known = makeProbeProfile()
        known.maxBundleVersion = try Data([0x07]).encrypt()
        #expect(ContactManager.hasReadableBundleVersion(known))
    }
}

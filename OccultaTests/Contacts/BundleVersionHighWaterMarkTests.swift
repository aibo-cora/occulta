//
//  BundleVersionHighWaterMarkTests.swift
//  OccultaTests
//
//  Bug 80, part 2. `Contact.Profile.maxBundleVersion` gates the sender-ephemeral-signature
//  check in `openGroup`: an unsigned forward-secret bundle is rejected only when the recorded
//  tier says the sender can sign. Two ways that gate could be defeated, both fixed here:
//
//  1. A marker stranded by a pre-1.10.2 key rotation read as `.v3fs`, which is not
//     `senderSignatureCapable`, so the check was skipped. It now fails closed.
//  2. `updateMaxVersion` overwrote unconditionally, and `appVersion` comes from the sealed
//     payload — authenticated only by a session key that, in FS mode, carries no sender
//     identity. So whoever could build one FS bundle could lower the recorded tier and then
//     send an unsigned one. The tier is now a high-water mark.
//
//  These exercise the recording rule directly. The gate itself needs a full bundle round trip
//  and is covered by the group-decrypt suites.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta



@MainActor
private func makeManager() throws -> ContactManager {
    let schema = Schema([
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
        Group.self,
        AppLayerConfig.self,
    ])
    let container = try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
    let security = Manager.Security(modelContainer: container, enabled: false)
    return ContactManager(modelContainer: container, security: security)
}

private func makeProfile() -> Contact.Profile {
    Contact.Profile(
        identifier: "probe", givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: "",
        phoneticGivenName: "", phoneticMiddleName: "", phoneticFamilyName: "", note: ""
    )
}

/// An in-memory crypto stack. Everything here is exercised through an injected key manager
/// rather than `Manager.Key()`, so these run on a GitHub runner with no Secure Enclave —
/// `updateMaxVersion`, `resolveTargetVersion` and `hasReadableBundleVersion` all take the
/// crypto to use, so nothing needs the real one.
@MainActor
private func makeTestCrypto() -> Manager.Crypto {
    Manager.Crypto(keyManager: TestKeyManager())
}

@MainActor
private func seal(_ version: OccultaBundle.Version, using crypto: Manager.Crypto) throws -> Data? {
    guard let byte = version.wireByte else { return nil }
    return try crypto.encrypt(data: Data([byte]))
}

@Suite("Bug 80 — bundle version is a high-water mark")
@MainActor
struct BundleVersionHighWaterMarkTests {

    @Test("A higher claim raises the recorded tier")
    func higherClaimRaises() throws {
        let crypto  = makeTestCrypto()
        let manager = try makeManager()
        let profile = makeProfile()
        profile.maxBundleVersion = try seal(.groupCapable, using: crypto)
        try manager.insertProfile(profile)

        try manager.updateMaxVersion(from: "1.10.0", for: profile, using: crypto)

        #expect(ContactManager.resolveTargetVersion(for: profile, using: crypto)
            .isAtLeast(.senderSignatureCapable))
    }

    /// The downgrade path. A signed bundle claiming an old build must not lower the tier,
    /// or the next unsigned bundle from the same attacker walks through the gate.
    @Test("A lower claim does not lower the recorded tier")
    func lowerClaimIsIgnored() throws {
        let crypto  = makeTestCrypto()
        let manager = try makeManager()
        let profile = makeProfile()
        profile.maxBundleVersion = try seal(.senderSignatureCapable, using: crypto)
        try manager.insertProfile(profile)

        try manager.updateMaxVersion(from: "1.9.0", for: profile, using: crypto)

        #expect(ContactManager.resolveTargetVersion(for: profile, using: crypto)
            .isAtLeast(.senderSignatureCapable), "tier must not fall")
    }

    /// A stranded marker is treated as the top tier, so a low claim cannot clear it and
    /// convert "cannot prove incapable" into a recorded "incapable".
    @Test("A low claim cannot clear a stranded marker")
    func lowClaimCannotClearStrandedMarker() throws {
        let crypto  = makeTestCrypto()
        let manager = try makeManager()
        let profile = makeProfile()
        // Sealed under a key nobody holds — the post-rotation state.
        profile.maxBundleVersion = try Data([0x07]).encrypt(using: SymmetricKey(size: .bits256))
        let stranded = profile.maxBundleVersion
        try manager.insertProfile(profile)

        try manager.updateMaxVersion(from: "1.9.0", for: profile, using: crypto)

        #expect(profile.maxBundleVersion == stranded, "stranded marker must survive a low claim")
        #expect(!ContactManager.hasReadableBundleVersion(profile, using: crypto))
    }

    /// Healing: a stranded contact who is genuinely current re-establishes a readable tier.
    @Test("A top-tier claim heals a stranded marker")
    func topTierClaimHealsStrandedMarker() throws {
        let crypto  = makeTestCrypto()
        let manager = try makeManager()
        let profile = makeProfile()
        profile.maxBundleVersion = try Data([0x07]).encrypt(using: SymmetricKey(size: .bits256))
        try manager.insertProfile(profile)

        try manager.updateMaxVersion(from: "1.10.0", for: profile, using: crypto)

        #expect(ContactManager.hasReadableBundleVersion(profile, using: crypto))
        #expect(ContactManager.resolveTargetVersion(for: profile, using: crypto)
            .isAtLeast(.senderSignatureCapable))
    }

    @Test("A first sighting records the claimed tier")
    func firstSightingRecords() throws {
        let crypto  = makeTestCrypto()
        let manager = try makeManager()
        let profile = makeProfile()
        profile.maxBundleVersion = nil
        try manager.insertProfile(profile)

        try manager.updateMaxVersion(from: "1.9.0", for: profile, using: crypto)

        #expect(ContactManager.hasReadableBundleVersion(profile, using: crypto))
        #expect(!ContactManager.resolveTargetVersion(for: profile, using: crypto)
            .isAtLeast(.senderSignatureCapable))
    }
}

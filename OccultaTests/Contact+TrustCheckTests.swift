//
//  Contact+TrustCheckTests.swift
//  OccultaTests
//
//  Eligibility tests for Trust Check (TrustCheckV2.swift). Covers what's
//  testable without real Secure Enclave access: `trustCheckCanRevokeKey` reads
//  only `expiredOn`, never decrypts anything, so it's fully covered here.
//  `trustCheckCanChallenge` and `ContactManager.isSensitive` both call through
//  to `Data.decrypt()`, which hardcodes `Manager.Crypto()` with no injection
//  point (see `SecureModeActivationTests.swift`'s header for the same
//  constraint) — only their SE-independent short-circuit branches (no active
//  key; `visibleThroughDepth == nil`) are covered here. The true/verified and
//  already-sensitive branches need a physical device and are exercised via
//  manual QA per the plan, not asserted here.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta

// MARK: - Container

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
    return try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
}

/// Direct insertion, no `ContactManager` field-encryption — SE-independent,
/// same technique `SecureModeActivationTests.swift` uses for the same reason.
@MainActor
@discardableResult
private func insertContact(
    identifier: String,
    in container: ModelContainer,
    key: Contact.Profile.Key? = nil,
    visibleThroughDepth: Data? = nil
) throws -> Contact.Profile {
    let ctx = ModelContext(container)
    let profile = Contact.Profile(
        identifier: identifier, givenName: "Test", familyName: "Contact", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.visibleThroughDepth = visibleThroughDepth
    if let key {
        key.profile = profile
        profile.contactPublicKeys = [key]
    }
    ctx.insert(profile)
    try ctx.save()
    return profile
}

private func makeKey(expiredOn: Data? = nil) -> Contact.Profile.Key {
    let key = Contact.Profile.Key(material: nil, owner: Data(), date: Data())
    key.expiredOn = expiredOn
    return key
}

// MARK: - trustCheckCanRevokeKey

@Suite("Trust Check — Revoke Key eligibility")
@MainActor struct TrustCheckRevokeEligibilityTests {

    @Test("No key at all → not revocable")
    func noKey() throws {
        let container = try makeContainer()
        let profile = try insertContact(identifier: "a", in: container)
        #expect(profile.trustCheckCanRevokeKey == false)
    }

    @Test("Active, non-expired key → revocable")
    func activeKey() throws {
        let container = try makeContainer()
        let profile = try insertContact(identifier: "a", in: container, key: makeKey())
        #expect(profile.trustCheckCanRevokeKey == true)
    }

    @Test("Already-expired key → not revocable")
    func expiredKey() throws {
        let container = try makeContainer()
        let profile = try insertContact(
            identifier: "a", in: container,
            key: makeKey(expiredOn: "revoked".data(using: .utf8))
        )
        #expect(profile.trustCheckCanRevokeKey == false)
    }
}

// MARK: - trustCheckCanChallenge

@Suite("Trust Check — Identity Challenge eligibility")
@MainActor struct TrustCheckChallengeEligibilityTests {

    @Test("No key at all → not eligible (SE-independent branch)")
    func noKey() throws {
        let container = try makeContainer()
        let profile = try insertContact(identifier: "a", in: container)
        #expect(profile.verificationStatus == .pending)
        #expect(profile.trustCheckCanChallenge == false)
    }

    @Test("Already-expired key → not eligible (SE-independent branch)")
    func expiredKey() throws {
        let container = try makeContainer()
        let profile = try insertContact(
            identifier: "a", in: container,
            key: makeKey(expiredOn: "revoked".data(using: .utf8))
        )
        #expect(profile.verificationStatus == .pending)
        #expect(profile.trustCheckCanChallenge == false)
    }

    // The `.verified` branch requires `Manager.Crypto().decrypt` to succeed
    // against a real owner-hash match — real Secure Enclave only, not
    // reachable from the simulator. Not asserted here; see file header.
}

// MARK: - Hide Contact eligibility (via ContactManager.isSensitive)

@Suite("Trust Check — Hide Contact eligibility")
@MainActor struct TrustCheckHideEligibilityTests {

    @Test("Fresh contact, visibleThroughDepth nil → not sensitive, Hide is eligible")
    func freshContactIsNotSensitive() throws {
        let container = try makeContainer()
        let keyManager = TestKeyManager()
        let security = Manager.Security(
            modelContainer: container,
            keyManager: keyManager,
            layerStore: Manager.LayerStore(backend: InMemoryLayerStoreBackend())
        )
        let contacts = ContactManager(modelContainer: container, security: security)
        try insertContact(identifier: "a", in: container)

        #expect(contacts.isSensitive("a") == false)
    }

    // "Already marked private" (visibleThroughDepth set) requires decrypting
    // that value, which hits the same SE-only `Data.decrypt()` path as above —
    // not asserted here; see file header.
}

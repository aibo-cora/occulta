//
//  DuressDraftPurgeTests.swift
//  OccultaTests
//
//  Pins when `Manager.Security.applyVerifyState` purges drafts for a real duress-PIN entry.
//  An activated duress PIN has a routing alias in `sealedNormalVerifiers[1]`, so `verify()`
//  step 1 returns `.normal(depth: 1)` and the `.duress` branch is never taken (Bug 172). The
//  purge therefore runs on any `.normal` that goes deeper, and on nothing else.
//
//  Runs under `.ambientTestKeyManager`: no Secure Enclave needed.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta
@testable import OccultaFormats

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
        Message.Draft.self,
    ])
    return try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
}

/// A contact classified real-only (`visibleThroughDepth == 0`): hidden at every duress depth.
@MainActor
private func insertHiddenContact(identifier: String, in container: ModelContainer) throws {
    let context = ModelContext(container)
    let profile = Contact.Profile(
        identifier: identifier, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.visibleThroughDepth = try DepthCodec.encode(0).encrypt()
    context.insert(profile)
    try context.save()
}

/// A contact created in the duress layer (`originDepth` 1): visible at depth 1, hidden at depth 0.
@MainActor
private func insertDuressOriginContact(identifier: String, in container: ModelContainer) throws {
    let context = ModelContext(container)
    let profile = Contact.Profile(
        identifier: identifier, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.originDepth = try DepthCodec.encode(1).encrypt()
    context.insert(profile)
    try context.save()
}

/// A draft addressed to `recipientID`, with the recipient sealed exactly as `DraftStore` seals it.
@MainActor
private func insertDraft(recipientID: String, in container: ModelContainer) throws {
    let key = try #require(try Manager.Ambient.keyManager.createHybridLocalEncryptionKey())
    let id  = UUID()
    let sealedRecipient = try AES.GCM.seal(
        Data(recipientID.utf8), using: key,
        authenticating: Message.Draft.aad(id: id, field: .recipientID)
    ).combined!
    let sealedContent = try AES.GCM.seal(
        Data("draft body".utf8), using: key,
        authenticating: Message.Draft.aad(id: id, field: .content)
    ).combined!

    let context = ModelContext(container)
    context.insert(Message.Draft(id: id, encryptedRecipientID: sealedRecipient, encryptedContent: sealedContent))
    try context.save()
}

@MainActor
private func draftCount(in container: ModelContainer) throws -> Int {
    try ModelContext(container).fetchCount(FetchDescriptor<Message.Draft>())
}

@MainActor
@Suite("Duress entry — draft purge reachability", .serialized)
struct DuressDraftPurgeTests {

    /// The lead: enter the activated duress PIN, expect a draft addressed to a contact hidden
    /// at depth 1 to be purged. A draft to a real-only contact is the exact thing the purge's
    /// doc comment says "would otherwise keep that draft across any number of duress-PIN entries".
    @Test(.ambientTestKeyManager) func duressPINEntry_purgesDraftToContactHiddenAtDepth1() throws {
        let container = try makeContainer()
        let security  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())

        try security.configurePIN("123456")
        try security.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")

        try insertHiddenContact(identifier: "hidden-contact", in: container)
        try insertDraft(recipientID: "hidden-contact", in: container)
        #expect(try draftCount(in: container) == 1)

        let result = try security.verify("999999")
        security.applyVerifyState(for: result)

        #expect(security.currentDepth == 1)
        #expect(try draftCount(in: container) == 0,
                "result was \(result): the draft to a contact hidden at depth 1 survived duress-PIN entry")
    }

    /// Going deeper is the only trigger: the master PIN at depth 0 purges nothing, so a draft to a
    /// contact hidden at a duress depth survives it.
    @Test(.ambientTestKeyManager) func masterPINEntry_doesNotPurge() throws {
        let container = try makeContainer()
        let security  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())

        try security.configurePIN("123456")
        try security.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")

        try insertHiddenContact(identifier: "hidden-contact", in: container)
        try insertDraft(recipientID: "hidden-contact", in: container)

        let result = try security.verify("123456")
        security.applyVerifyState(for: result)

        #expect(security.currentDepth == 0)
        #expect(try draftCount(in: container) == 1)
    }

    /// Re-entering the depth already held (a `.normal` at the same depth) does not purge.
    @Test(.ambientTestKeyManager) func sameDepthEntry_doesNotPurge() throws {
        let container = try makeContainer()
        let security  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())

        try security.configurePIN("123456")
        try security.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        security.applyVerifyState(for: try security.verify("999999"))
        #expect(security.currentDepth == 1)

        try insertHiddenContact(identifier: "hidden-contact", in: container)
        try insertDraft(recipientID: "hidden-contact", in: container)

        security.applyVerifyState(for: .normal(depth: 1))

        #expect(try draftCount(in: container) == 1)
    }

    /// A draft saved in the duress layer to a contact created there (`originDepth` 1) is not purged
    /// by the drop back to depth 0, and is safe at depth 1, so the next duress entry keeps it.
    @Test(.ambientTestKeyManager) func duressLayerDraft_survivesDropToRealAndReentry() throws {
        let container = try makeContainer()
        let security  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())

        try security.configurePIN("123456")
        try security.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
        security.applyVerifyState(for: try security.verify("999999"))

        try insertDuressOriginContact(identifier: "duress-contact", in: container)
        try insertDraft(recipientID: "duress-contact", in: container)

        security.applyVerifyState(for: try security.verify("123456"))
        #expect(security.currentDepth == 0)
        #expect(try draftCount(in: container) == 1)

        security.applyVerifyState(for: try security.verify("999999"))
        #expect(security.currentDepth == 1)
        #expect(try draftCount(in: container) == 1)
    }

    /// Control: the same fixture, with `.duress` handed to `applyVerifyState` directly, is purged.
    /// Proves the fixture is purgeable, so the test above fails because of routing, not setup.
    @Test(.ambientTestKeyManager) func duressResult_purgesDraftToContactHiddenAtDepth1() throws {
        let container = try makeContainer()
        let security  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())

        try security.configurePIN("123456")
        try security.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")

        try insertHiddenContact(identifier: "hidden-contact", in: container)
        try insertDraft(recipientID: "hidden-contact", in: container)

        security.applyVerifyState(for: .duress)

        #expect(try draftCount(in: container) == 0)
    }

    /// Pins the routing that makes the purge unreachable: the duress PIN never produces `.duress`.
    @Test(.ambientTestKeyManager) func activatedDuressPIN_neverRoutesAsDuress() throws {
        let container = try makeContainer()
        let security  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())

        try security.configurePIN("123456")
        try security.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")

        #expect(try security.verify("999999") != .duress)
    }
}

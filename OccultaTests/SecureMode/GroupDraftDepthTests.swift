//
//  GroupDraftDepthTests.swift
//  OccultaTests
//
//  Bug 178 — a group draft written at the real depth loaded into the group's compose field at a
//  duress depth. Groups are not depth-filtered and `isSensitive` is false for every group, so the
//  only thing standing between a coercer and the real-depth text is the purge on going deeper.
//  `purgeUnsafe` used to keep every draft addressed to a known group; it now keeps only drafts to
//  contacts visible at the depth just entered.
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
        Group.self,
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

/// A group in the store; returns the identifier a compose screen keys its draft by.
@MainActor
private func insertGroup(named name: String, in container: ModelContainer) throws -> String {
    let context = ModelContext(container)
    let group   = try Group(name: name)
    context.insert(group)
    try context.save()
    return try #require(group.readID()).uuidString
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

/// Writes a draft the way a compose screen does, so `DraftStore.load` can read it back.
@MainActor
private func writeDraft(recipientID: String, text: String, in container: ModelContainer) async {
    await DraftStore().flush(
        recipientID: recipientID, isSensitive: false, text: text,
        messages: [], useThread: false, modelContext: ModelContext(container)
    )
}

/// What `GroupDetailV3`'s `.task` would put in the compose field.
@MainActor
private func loadedText(recipientID: String, in container: ModelContainer) -> String? {
    DraftStore().load(recipientID: recipientID, modelContext: ModelContext(container))?.text
}

@MainActor
private func draftCount(in container: ModelContainer) throws -> Int {
    try ModelContext(container).fetchCount(FetchDescriptor<Message.Draft>())
}

@MainActor
private func activatedSecurity(_ container: ModelContainer) throws -> Manager.Security {
    let security = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
    try security.configurePIN("123456")
    try security.activateSecureMode(confirmingEntryPIN: "123456", duressPIN: "999999")
    return security
}

@MainActor
@Suite("Group drafts across depth changes (Bug 178)", .serialized)
struct GroupDraftDepthTests {

    /// The entry's validation test: a depth-0 group draft must not load at depth 1.
    @Test(.ambientTestKeyManager) func duressPINEntry_removesRealDepthGroupDraft() async throws {
        let container = try makeContainer()
        let security  = try activatedSecurity(container)
        let groupID   = try insertGroup(named: "G", in: container)

        await writeDraft(recipientID: groupID, text: "real-depth text", in: container)
        #expect(loadedText(recipientID: groupID, in: container) == "real-depth text")

        let result = try security.verify("999999")
        security.applyVerifyState(for: result)

        #expect(result == .normal(depth: 1))
        #expect(security.currentDepth == 1)
        #expect(loadedText(recipientID: groupID, in: container) == nil,
                "the depth-0 group draft loads at depth 1")
        #expect(try draftCount(in: container) == 0)
    }

    /// Same fixture through the `.duress` result, which the app can still produce directly.
    @Test(.ambientTestKeyManager) func duressResult_removesRealDepthGroupDraft() async throws {
        let container = try makeContainer()
        let security  = try activatedSecurity(container)
        let groupID   = try insertGroup(named: "G", in: container)

        await writeDraft(recipientID: groupID, text: "real-depth text", in: container)

        security.applyVerifyState(for: .duress)

        #expect(loadedText(recipientID: groupID, in: container) == nil)
        #expect(try draftCount(in: container) == 0)
    }

    /// The owner's normal login is not a descent, so their group draft stays.
    @Test(.ambientTestKeyManager) func masterPINEntry_keepsGroupDraft() async throws {
        let container = try makeContainer()
        let security  = try activatedSecurity(container)
        let groupID   = try insertGroup(named: "G", in: container)

        await writeDraft(recipientID: groupID, text: "real-depth text", in: container)

        security.applyVerifyState(for: try security.verify("123456"))

        #expect(security.currentDepth == 0)
        #expect(loadedText(recipientID: groupID, in: container) == "real-depth text")
    }

    /// Only group drafts are newly removed: a draft to a contact visible at the depth just
    /// entered still survives the same pass (the Bug 172 behavior is unchanged).
    @Test(.ambientTestKeyManager) func duressPINEntry_keepsDraftToContactVisibleAtDepth1() async throws {
        let container = try makeContainer()
        let security  = try activatedSecurity(container)
        let groupID   = try insertGroup(named: "G", in: container)
        try insertDuressOriginContact(identifier: "duress-contact", in: container)

        await writeDraft(recipientID: groupID, text: "group text", in: container)
        await writeDraft(recipientID: "duress-contact", text: "contact text", in: container)

        security.applyVerifyState(for: try security.verify("999999"))

        #expect(loadedText(recipientID: groupID, in: container) == nil)
        #expect(loadedText(recipientID: "duress-contact", in: container) == "contact text")
    }

    /// A draft typed into the group at the duress depth is not left for the next descent.
    @Test(.ambientTestKeyManager) func groupDraftWrittenAtDepth1_removedOnNextDescent() async throws {
        let container = try makeContainer()
        let security  = try activatedSecurity(container)
        let groupID   = try insertGroup(named: "G", in: container)

        security.applyVerifyState(for: try security.verify("999999"))
        await writeDraft(recipientID: groupID, text: "typed at depth 1", in: container)

        // A drop to a lower depth purges nothing.
        security.applyVerifyState(for: try security.verify("123456"))
        #expect(security.currentDepth == 0)
        #expect(loadedText(recipientID: groupID, in: container) == "typed at depth 1")

        security.applyVerifyState(for: try security.verify("999999"))
        #expect(security.currentDepth == 1)
        #expect(loadedText(recipientID: groupID, in: container) == nil)
    }
}

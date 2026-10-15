//
//  PrekeyReplayWiringTests.swift
//  OccultaTests
//
//  `PrekeyBookkeeper.accept` refuses, on a slot that can be opened again, a batch with a new ID that is older than
//  the newest batch accepted from the contact (`Docs/Features/Prekey Continuity/DESIGN.md` §3.3, Bug 158). That
//  keeps a bundle on the long-term keys or a last-resort key, replayed after its batch's ID has aged out of the
//  8 remembered, from bringing back keys already used up.
//
//  The bookkeeper tests pin the rule; these pin that `openGroup` and `decryptSealed` hand it the slot the bundle
//  opened with. Bundles here are on the long-term keys, so no prekey is made and no Secure Enclave is needed. The
//  same replay through two real phones, on the Enclave, is in `PrekeyConversationTests`.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta
@testable import OccultaFormats

@MainActor
private func makeContactManager() throws -> ContactManager {
    let schema = Schema([
        Group.self,
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    let security  = try Manager.Security(modelContainer: container, keyManager: TestKeyManager())
    return ContactManager(modelContainer: container, security: security)
}

/// `publicKey` as a contact on this device. A pending batch of ours stands waiting for them, so a long-term bundle
/// from them generates no new one, which would need an Enclave.
@MainActor
private func insertSender(identifier: String, publicKey: Data, in contactManager: ContactManager) throws {
    let profile = Contact.Profile(
        identifier: identifier, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.contactPublicKeys = [Contact.Profile.Key(
        material: try #require(try Manager.Crypto().encrypt(data: publicKey)), owner: Data(), date: Data(),
        quantumKeyMaterialEncrypted: nil
    )]
    var record = PrekeyRecord.empty
    record.ownBatches = [PrekeyRecord.OwnBatch(
        id: Data((0..<16).map { _ in .random(in: .min ... .max) }), createdAt: Date(), retiredAt: nil, isPending: true,
        keys: [PrekeyRecord.OwnKey(id: withUnsafeBytes(of: UUID().uuid) { Data($0) }, blob: nil,
                                   publicKey: try TestKeyManager().retrieveIdentity())]
    )]
    profile.prekeyRecordEncrypted = try PrekeyRecordCodec().encode(record).encrypt()
    try contactManager.insertProfile(profile)
}

private func wirePrekey() -> OccultaBundle.WirePrekey {
    OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
}

/// A batch with a fresh ID and keys, dated `generatedAt`.
private func batch(generatedAt: Date) -> OccultaBundle.SealedPayload.PrekeySyncBatch {
    OccultaBundle.SealedPayload.PrekeySyncBatch(
        generatedAt: generatedAt, prekeys: (0..<15).map { _ in wirePrekey() },
        id: Data((0..<PrekeyBookkeeper.batchIDBytes).map { _ in .random(in: .min ... .max) }), lastResort: wirePrekey()
    )
}

@Suite("A batch replayed on a slot that opens again is refused, through openGroup and decryptSealed")
@MainActor struct PrekeyReplayWiringTests {

    /// How the bundle is built and opened: a group bundle through `openGroup`, or a single-recipient one through
    /// `decryptSealed`. Both are on the sender's long-term keys, a slot that opens again.
    enum Route: CaseIterable {
        case group, single

        /// A bundle from `sender` to this device carrying `batch`, on the long-term keys.
        @MainActor
        func bundle(
            carrying batch: OccultaBundle.SealedPayload.PrekeySyncBatch, from sender: TestKeyManager
        ) throws -> OccultaBundle {
            let thisDevice = try Manager.Ambient.keyManager.retrieveIdentity()
            switch self {
            case .group:
                return try Manager.Crypto(keyManager: sender).seal(
                    sealedPayload: OccultaBundle.SealedPayload(message: Data("Lunch at one.".utf8)),
                    groupID: UUID(),
                    recipients: [GroupRecipient(publicKey: thisDevice, quantumMaterial: nil, contactPrekey: nil, pendingBatch: batch)]
                )
            case .single:
                return try Manager.Crypto(keyManager: sender).seal(
                    message: try WireHandle.encode(payload: OccultaBundle.SealedPayload(
                        message: Data("Lunch at one.".utf8), prekeyBatch: batch
                    )),
                    contactPrekey: nil, recipientMaterial: thisDevice, quantumMaterial: nil, version: .v4
                )
            }
        }

        /// Opens `bundle` as `ownerID`'s, and returns the message.
        @MainActor
        func open(_ bundle: OccultaBundle, ownerID: String, in contactManager: ContactManager) throws -> Data {
            switch self {
            case .group:  return try contactManager.openGroup(bundle: bundle, ownerID: ownerID).sealed.message
            case .single: return try contactManager.decryptSealed(bundle: bundle).sealed.message
            }
        }
    }

    @Test("A new-ID batch dated before the newest accepted opens but isn't taken; one dated after is",
          .ambientTestKeyManager, arguments: Route.allCases)
    func olderDatedBatchOnLongTermKeys(route: Route) throws {
        let sender = TestKeyManager()
        let cm = try makeContactManager()
        try insertSender(identifier: "sender", publicKey: try sender.retrieveIdentity(), in: cm)
        let message = Data("Lunch at one.".utf8)
        let newest = Date(timeIntervalSince1970: 1_800_000_000)
        func record() throws -> PrekeyRecord { try cm.prekeyRecord(for: try #require(try cm.fetchContact(by: "sender"))) }

        let first = batch(generatedAt: newest)
        #expect(try route.open(try route.bundle(carrying: first, from: sender), ownerID: "sender", in: cm) == message)
        let afterFirst = try record()
        #expect(afterFirst.inboundBatches.map { $0.keys.map(\.id) } == [first.prekeys.map(\.id)], "precondition: the first is taken")
        #expect(afterFirst.latestInboundGeneratedAt == newest)

        let older = batch(generatedAt: newest - 3_600)
        #expect(try route.open(try route.bundle(carrying: older, from: sender), ownerID: "sender", in: cm) == message,
                "the message opens; only the batch is left out")
        let afterOlder = try record()
        #expect(afterOlder.inboundBatches == afterFirst.inboundBatches)
        #expect(afterOlder.inboundLastResort == afterFirst.inboundLastResort)
        #expect(afterOlder.acceptedBatchIDs == afterFirst.acceptedBatchIDs)

        let newer = batch(generatedAt: newest + 60)
        #expect(try route.open(try route.bundle(carrying: newer, from: sender), ownerID: "sender", in: cm) == message)
        let afterNewer = try record()
        #expect(afterNewer.inboundBatches.map { $0.keys.map(\.id) } == [first.prekeys.map(\.id), newer.prekeys.map(\.id)])
        #expect(afterNewer.inboundLastResort?.id == newer.lastResort?.id)
        #expect(afterNewer.acceptedBatchIDs == afterFirst.acceptedBatchIDs + [newer.id].compactMap { $0 })
        #expect(afterNewer.latestInboundGeneratedAt == newest + 60)
    }
}

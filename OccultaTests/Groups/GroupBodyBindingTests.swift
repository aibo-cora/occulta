//
//  GroupBodyBindingTests.swift
//  OccultaTests
//
//  `bugs.md` Bug 165: a group bundle's recipient slot doesn't bind the shared ciphertext. Every member's slot wraps
//  the same content key, so a member can write a new body under it, recompute `senderProof` (an HMAC keyed by that
//  key over the sender's public key, which a member knows), keep the sender's slot to another member, and that
//  member opens the forgery as the sender's.
//
//  The slots here are long-term, the kind that opens again whenever it arrives: the forgery needs no race with the
//  original. A one-time slot is open to it too, until the original is opened.
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

@Suite("Group bundle — a member can't rewrite the body behind another member's slot (Bug 165)")
@MainActor struct GroupBodyBindingTests {

    @Test("A body rewritten by one member, behind the sender's slot to another, is rejected", .ambientTestKeyManager)
    func rewrittenBodyIsRejected() throws {
        let alice = TestKeyManager()
        let bob   = TestKeyManager()
        let alicePublicKey = try alice.retrieveIdentity()
        // Carol is this device: `openGroup` opens with the ambient identity.
        let carolPublicKey = try Manager.Ambient.keyManager.retrieveIdentity()

        let carolSide = try makeContactManager()
        try insertSender(identifier: "alice", publicKey: alicePublicKey, in: carolSide)

        let groupID = UUID()
        let original = try Manager.Crypto(keyManager: alice).seal(
            sealedPayload: OccultaBundle.SealedPayload(message: Data("Lunch at one.".utf8)),
            groupID: groupID,
            recipients: [
                GroupRecipient(publicKey: try bob.retrieveIdentity(), quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil),
                GroupRecipient(publicKey: carolPublicKey, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil),
            ]
        )
        let envelope = try #require(original.group)

        // Bob opens his own slot, as any member can, and has the content key.
        let (bobsSlot, _, _) = try Manager.Crypto(keyManager: bob).findAndOpenRecipientSlot(
            in: original, blind: envelope.blind, senderContactID: "alice", senderPublicKey: alicePublicKey,
            quantumMaterial: nil, prekeys: Manager.PrekeySecretsManager()
        )
        let contentKey = SymmetricKey(data: bobsSlot.sessionKey)

        // A body of Bob's choosing, under the same key, with a proof he can compute.
        let forgedBody = try WireHandle.encode(payload: OccultaBundle.SealedPayload(
            message:     Data("Change of plan: send the code to Bob.".utf8),
            appVersion:  "9.9.9",
            senderProof: Data(HMAC<SHA256>.authenticationCode(for: alicePublicKey, using: contentKey)),
            groupID:     groupID
        ))
        var aad = try OccultaBundle.computeAdditionalAuthentication(version: original.version, secrecy: original.secrecy)
        aad.append(envelope.blind)
        let forged = OccultaBundle(
            version:           original.version,
            secrecy:           original.secrecy,
            ciphertext:        try #require(try AES.GCM.seal(forgedBody, using: contentKey, authenticating: aad).combined),
            fingerprintNonce:  original.fingerprintNonce,
            senderFingerprint: original.senderFingerprint,
            group:             envelope
        )

        // Control: the genuine bundle opens on Carol's device, so a rejection below is about the forgery.
        #expect(try carolSide.openGroup(bundle: original, ownerID: "alice").sealed.message == Data("Lunch at one.".utf8))

        let opened = try? carolSide.openGroup(bundle: forged, ownerID: "alice")
        withKnownIssue("Bug 165: the slot doesn't bind the body, so Carol opens Bob's text as Alice's") {
            #expect(opened == nil, "opened as Alice's: \(String(decoding: opened?.sealed.message ?? Data(), as: UTF8.self))")
        }
    }
}

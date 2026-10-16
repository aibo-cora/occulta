//
//  GroupBodyBindingTests.swift
//  OccultaTests
//
//  `bugs.md` Bug 165: a group bundle's recipient slot didn't bind the shared ciphertext. Every member's slot wraps
//  the same content key, so a member could write a new body under it, recompute `senderProof` (an HMAC keyed by
//  that key over the sender's public key, which a member knows), keep the sender's slot to another member, and that
//  member opened the forgery as the sender's.
//
//  Each slot now carries `RecipientPayload.bodyDigest`, the SHA-256 of the ciphertext. A mismatch is rejected
//  without using up the slot's one-time key; a missing digest is rejected from a sender recorded at
//  `.bodyDigestCapable`, and around an identity challenge whatever the sender's tier.
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta
@testable import OccultaFormats

/// `publicKey` as a contact on this device, with `marker` as their recorded tier. A pending batch of ours stands
/// waiting for them, so a long-term bundle from them generates no new one, which would need an Enclave.
@MainActor
private func insertSender(
    identifier: String, publicKey: Data, marker: Data? = nil, in contactManager: ContactManager
) throws {
    let profile = Contact.Profile(
        identifier: identifier, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.contactPublicKeys = [Contact.Profile.Key(
        material: try #require(try Manager.Crypto().encrypt(data: publicKey)), owner: Data(), date: Data(),
        quantumKeyMaterialEncrypted: nil
    )]
    profile.maxBundleVersion = marker
    var record = PrekeyRecord.empty
    record.ownBatches = [PrekeyRecord.OwnBatch(
        id: Data((0..<16).map { _ in .random(in: .min ... .max) }), createdAt: Date(), retiredAt: nil, isPending: true,
        keys: [PrekeyRecord.OwnKey(id: withUnsafeBytes(of: UUID().uuid) { Data($0) }, blob: nil,
                                   publicKey: try TestKeyManager().retrieveIdentity())]
    )]
    profile.prekeyRecordEncrypted = try PrekeyRecordCodec().encode(record).encrypt()
    try contactManager.insertProfile(profile)
}

/// `original` with its body replaced by `body`, as a recipient holding `contentKey` can: same key, same `blind`,
/// a `senderProof` they compute themselves, and every slot left as the sender sealed it.
private func rewrite(
    _ original: OccultaBundle, contentKey: SymmetricKey, senderPublicKey: Data, body: OccultaBundle.SealedPayload
) throws -> OccultaBundle {
    let envelope = try #require(original.group)
    let forgedBody = try WireHandle.encode(payload: OccultaBundle.SealedPayload(
        message:           body.message,
        identityChallenge: body.identityChallenge,
        appVersion:        body.appVersion,
        senderProof:       Data(HMAC<SHA256>.authenticationCode(for: senderPublicKey, using: contentKey)),
        groupID:           body.groupID
    ))
    var aad = try OccultaBundle.computeAdditionalAuthentication(version: original.version, secrecy: original.secrecy)
    aad.append(envelope.blind)
    return OccultaBundle(
        version:           original.version,
        secrecy:           original.secrecy,
        ciphertext:        try #require(try AES.GCM.seal(forgedBody, using: contentKey, authenticating: aad).combined),
        fingerprintNonce:  original.fingerprintNonce,
        senderFingerprint: original.senderFingerprint,
        group:             envelope
    )
}

/// A one-recipient group bundle sealed long-term as a sender before `.bodyDigestCapable` sealed it: the slot
/// carries no `bodyDigest`.
@MainActor
private func sealWithoutDigest(
    _ body: OccultaBundle.SealedPayload, from sender: TestKeyManager, to recipientPublicKey: Data
) throws -> OccultaBundle {
    let senderPublicKey = try sender.retrieveIdentity()
    let groupID    = try #require(body.groupID)
    let contentKey = SymmetricKey(size: .bits256)
    let blindNonce = try OccultaBundle.SecrecyContext.generateNonce()
    let blind      = Data(HMAC<SHA256>.authenticationCode(
        for: blindNonce, using: SymmetricKey(data: withUnsafeBytes(of: groupID.uuid) { Data($0) })
    ))
    let outerSecrecy = OccultaBundle.SecrecyContext(mode: .group, ephemeralPublicKey: Data(), prekeyID: nil)
    var aad = try OccultaBundle.computeAdditionalAuthentication(version: .v4, secrecy: outerSecrecy)
    aad.append(blind)
    let sealedBody = try WireHandle.encode(payload: OccultaBundle.SealedPayload(
        message:           body.message,
        identityChallenge: body.identityChallenge,
        appVersion:        body.appVersion,
        senderProof:       Data(HMAC<SHA256>.authenticationCode(for: senderPublicKey, using: contentKey)),
        groupID:           groupID
    ))

    let (wrappingKey, context) = try Manager.Crypto(keyManager: sender).deriveOutboundKey(
        contactPrekey: nil, recipientPublicKey: recipientPublicKey, quantumMaterial: nil
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    let slot = try encoder.encode(OccultaBundle.RecipientPayload(
        sessionKey: contentKey.withUnsafeBytes { Data($0) }, senderEphemeralSignature: Data(count: 72)
    ))
    let outerNonce = try OccultaBundle.SecrecyContext.generateNonce()
    return OccultaBundle(
        version:           .v4,
        secrecy:           outerSecrecy,
        ciphertext:        try #require(try AES.GCM.seal(sealedBody, using: contentKey, authenticating: aad).combined),
        fingerprintNonce:  outerNonce,
        senderFingerprint: OccultaBundle.SecrecyContext.fingerprint(for: senderPublicKey, nonce: outerNonce),
        group: OccultaBundle.GroupEnvelope(blind: blind, blindNonce: blindNonce, recipients: [OccultaBundle.Recipient(
            secrecyContext: context,
            wrappedPayload: try #require(try AES.GCM.seal(slot, using: wrappingKey, authenticating: blind).combined)
        )])
    )
}

/// A one-time prekey held as a software key, which records what it was asked to consume.
private final class SoftwareOneTimePrekey: PrekeyPrivateKeys {
    let id = UUID().uuidString
    let privateKey: SecKey
    let publicKey: Data
    private(set) var consumed: [String] = []

    init() throws {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        let key = try #require(SecKeyCreateRandomKey(attributes as CFDictionary, &error))
        let publicKey = try #require(SecKeyCopyPublicKey(key))
        self.privateKey = key
        self.publicKey  = try #require(SecKeyCopyExternalRepresentation(publicKey, &error) as Data?)
    }

    func privateKey(forPrekeyID prekeyID: String, contactID: String) -> PrekeyPrivateKey? {
        prekeyID == self.id && !self.consumed.contains(prekeyID) ? .keychain(self.privateKey) : nil
    }
    func consume(prekeyID: String, contactID: String) { self.consumed.append(prekeyID) }
    func lastResortKey(forPrekeyID prekeyID: String, ephemeralPublicKey: Data) -> (keyID: String, key: PrekeyPrivateKey)? { nil }
}

@Suite("Group bundle — each slot binds the body (Bug 165)")
@MainActor struct GroupBodyBindingTests {

    let alice = TestKeyManager()
    let bob   = TestKeyManager()

    @Test("The tier starts at 2.0.0, with marker byte 0x09")
    func tier() {
        #expect(OccultaBundle.Version.max(forAppVersion: "2.0.0").isAtLeast(.bodyDigestCapable))
        #expect(!OccultaBundle.Version.max(forAppVersion: "1.11.1").isAtLeast(.bodyDigestCapable))
        #expect(OccultaBundle.Version.bodyDigestCapable.isAtLeast(.prefixedSenderSignatureCapable))
        #expect(OccultaBundle.Version.bodyDigestCapable.wireByte == 0x09)
    }

    @Test("Every slot carries the digest of the bundle's ciphertext", .ambientTestKeyManager)
    func everySlotCarriesTheDigest() throws {
        let carol = TestKeyManager()
        let alicePublicKey = try self.alice.retrieveIdentity()
        let bundle = try Manager.Crypto(keyManager: self.alice).seal(
            sealedPayload: OccultaBundle.SealedPayload(message: Data("Lunch at one.".utf8)),
            groupID: UUID(),
            recipients: try [self.bob, carol].map {
                GroupRecipient(publicKey: try $0.retrieveIdentity(), quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
            }
        )

        for member in [self.bob, carol] {
            let (slot, _, _) = try Manager.Crypto(keyManager: member).findAndOpenRecipientSlot(
                in: bundle, blind: try #require(bundle.group).blind, senderContactID: "alice",
                senderPublicKey: alicePublicKey, quantumMaterial: nil, prekeys: Manager.PrekeySecretsManager()
            )
            #expect(slot.bodyDigest == Data(SHA256.hash(data: bundle.ciphertext)))
        }
    }

    @Test("A body rewritten by one member, behind the sender's slot to another, is rejected", .ambientTestKeyManager)
    func rewrittenBodyIsRejected() throws {
        let alicePublicKey = try self.alice.retrieveIdentity()
        // Carol is this device: `openGroup` opens with the ambient identity.
        let carolPublicKey = try Manager.Ambient.keyManager.retrieveIdentity()

        let carolSide = try TestSupport.makeContactManager()
        try insertSender(identifier: "alice", publicKey: alicePublicKey, in: carolSide)

        let groupID = UUID()
        let original = try Manager.Crypto(keyManager: self.alice).seal(
            sealedPayload: OccultaBundle.SealedPayload(message: Data("Lunch at one.".utf8)),
            groupID: groupID,
            recipients: [
                GroupRecipient(publicKey: try self.bob.retrieveIdentity(), quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil),
                GroupRecipient(publicKey: carolPublicKey, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil),
            ]
        )

        // Bob opens his own slot, as any member can, and has the content key.
        let (bobsSlot, _, _) = try Manager.Crypto(keyManager: self.bob).findAndOpenRecipientSlot(
            in: original, blind: try #require(original.group).blind, senderContactID: "alice",
            senderPublicKey: alicePublicKey, quantumMaterial: nil, prekeys: Manager.PrekeySecretsManager()
        )
        let forged = try rewrite(
            original, contentKey: SymmetricKey(data: bobsSlot.sessionKey), senderPublicKey: alicePublicKey,
            body: OccultaBundle.SealedPayload(
                message: Data("Change of plan: send the code to Bob.".utf8), appVersion: "9.9.9", groupID: groupID
            )
        )

        // Control: the genuine bundle opens on Carol's device, so the rejection below is about the forgery.
        #expect(try carolSide.openGroup(bundle: original, ownerID: "alice").sealed.message == Data("Lunch at one.".utf8))

        #expect(throws: GroupDecryptError.bodyDigestMismatch) {
            try carolSide.openGroup(bundle: forged, ownerID: "alice")
        }
    }

    /// The forgery arriving first must not cost Carol the key Alice's genuine message is sealed to.
    @Test("A rewritten body doesn't use up the slot's one-time key; the genuine bundle still opens", .ambientTestKeyManager)
    func mismatchKeepsTheOneTimeKey() throws {
        let carol = TestKeyManager()
        let carolsKey = try SoftwareOneTimePrekey()
        let alicePublicKey = try self.alice.retrieveIdentity()

        let groupID = UUID()
        let original = try Manager.Crypto(keyManager: self.alice).seal(
            sealedPayload: OccultaBundle.SealedPayload(message: Data("Lunch at one.".utf8)),
            groupID: groupID,
            recipients: [
                GroupRecipient(publicKey: try self.bob.retrieveIdentity(), quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil),
                GroupRecipient(
                    publicKey: try carol.retrieveIdentity(), quantumMaterial: nil,
                    contactPrekey: Prekey(id: carolsKey.id, contactID: "carol", publicKey: carolsKey.publicKey),
                    pendingBatch: nil
                ),
            ]
        )
        let blind = try #require(original.group).blind
        let (bobsSlot, _, _) = try Manager.Crypto(keyManager: self.bob).findAndOpenRecipientSlot(
            in: original, blind: blind, senderContactID: "alice",
            senderPublicKey: alicePublicKey, quantumMaterial: nil, prekeys: Manager.PrekeySecretsManager()
        )
        let forged = try rewrite(
            original, contentKey: SymmetricKey(data: bobsSlot.sessionKey), senderPublicKey: alicePublicKey,
            body: OccultaBundle.SealedPayload(message: Data("Change of plan.".utf8), groupID: groupID)
        )

        let carolsCrypto = Manager.Crypto(keyManager: carol)
        #expect(throws: GroupDecryptError.bodyDigestMismatch) {
            try carolsCrypto.findAndOpenRecipientSlot(
                in: forged, blind: blind, senderContactID: "alice",
                senderPublicKey: alicePublicKey, quantumMaterial: nil, prekeys: carolsKey
            )
        }
        #expect(carolsKey.consumed.isEmpty)

        let (_, used, mode) = try carolsCrypto.findAndOpenRecipientSlot(
            in: original, blind: blind, senderContactID: "alice",
            senderPublicKey: alicePublicKey, quantumMaterial: nil, prekeys: carolsKey
        )
        #expect(mode == .forwardSecretNoPQ)
        #expect(used == .oneTime(Prekey(id: carolsKey.id, contactID: "alice", publicKey: Data())))
        #expect(carolsKey.consumed == [carolsKey.id], "the genuine bundle uses it up, as any other")
    }

    enum RecordedTier: String, CaseIterable {
        case atTheTier, belowTheTier, none, stranded

        func marker() throws -> Data? {
            switch self {
            case .atTheTier:    return try Manager.Crypto().encrypt(data: Data([try #require(OccultaBundle.Version.bodyDigestCapable.wireByte)]))
            case .belowTheTier: return try Manager.Crypto().encrypt(data: Data([try #require(OccultaBundle.Version.prefixedSenderSignatureCapable.wireByte)]))
            case .none:         return nil
            case .stranded:     return Data((0..<60).map { _ in .random(in: .min ... .max) })
            }
        }
    }

    /// A sender at the tier always sends it, so one without it is someone else's body. Below the tier, with no tier
    /// recorded, or with a stranded marker, it opens: refusing a stranded marker only would tell whether Secure
    /// Mode was used on 1.10.0/1.10.1.
    @Test("A slot without the digest is refused only from a sender recorded at the tier",
          .ambientTestKeyManager, arguments: RecordedTier.allCases)
    func missingDigest(tier: RecordedTier) throws {
        let carolSide = try TestSupport.makeContactManager()
        try insertSender(identifier: "alice", publicKey: try self.alice.retrieveIdentity(), marker: try tier.marker(), in: carolSide)
        let bundle = try sealWithoutDigest(
            OccultaBundle.SealedPayload(message: Data("Lunch at one.".utf8), groupID: UUID()),
            from: self.alice, to: try Manager.Ambient.keyManager.retrieveIdentity()
        )

        if tier == .atTheTier {
            #expect(throws: GroupDecryptError.missingBodyDigest) { try carolSide.openGroup(bundle: bundle, ownerID: "alice") }
        } else {
            #expect(try carolSide.openGroup(bundle: bundle, ownerID: "alice").sealed.message == Data("Lunch at one.".utf8))
        }
    }

    @Test("An identity challenge in a group body without the digest is refused, whatever the sender's tier", .ambientTestKeyManager)
    func challengeNeedsTheDigest() throws {
        let carolSide = try TestSupport.makeContactManager()
        try insertSender(identifier: "alice", publicKey: try self.alice.retrieveIdentity(),
                         marker: try RecordedTier.belowTheTier.marker(), in: carolSide)
        let bundle = try sealWithoutDigest(
            OccultaBundle.SealedPayload(
                message: Data(), identityChallenge: .challenge(payload: Data(count: 72), contextNote: nil), groupID: UUID()
            ),
            from: self.alice, to: try Manager.Ambient.keyManager.retrieveIdentity()
        )

        #expect(throws: GroupDecryptError.missingBodyDigest) { try carolSide.openGroup(bundle: bundle, ownerID: "alice") }
    }

    /// A rewrite of an older sender's bundle can't raise their recorded tier: the claim and the missing digest
    /// contradict each other. The same claim from an older build still opens, as does any claim with the digest.
    @Test("A body claiming 2.0.0 or later without the digest is refused, whatever the sender's tier",
          .ambientTestKeyManager, arguments: ["2.0.0", "2.1", "1.11.1"])
    func claimWithoutTheDigest(appVersion: String) throws {
        let carolSide = try TestSupport.makeContactManager()
        try insertSender(identifier: "alice", publicKey: try self.alice.retrieveIdentity(),
                         marker: try RecordedTier.belowTheTier.marker(), in: carolSide)
        let bundle = try sealWithoutDigest(
            OccultaBundle.SealedPayload(message: Data("Lunch at one.".utf8), appVersion: appVersion, groupID: UUID()),
            from: self.alice, to: try Manager.Ambient.keyManager.retrieveIdentity()
        )

        if OccultaBundle.Version.max(forAppVersion: appVersion).isAtLeast(.bodyDigestCapable) {
            #expect(throws: GroupDecryptError.missingBodyDigest) { try carolSide.openGroup(bundle: bundle, ownerID: "alice") }
            let alice = try #require(try carolSide.fetchContact(by: "alice"))
            #expect(ContactManager.resolveTargetVersion(for: alice, using: Manager.Crypto()) == .prefixedSenderSignatureCapable,
                    "the recorded tier didn't move")
        } else {
            #expect(try carolSide.openGroup(bundle: bundle, ownerID: "alice").sealed.message == Data("Lunch at one.".utf8))
        }
    }

    @Test("A body claiming 2.0.0 with the digest opens", .ambientTestKeyManager)
    func claimWithTheDigestOpens() throws {
        let carolSide = try TestSupport.makeContactManager()
        try insertSender(identifier: "alice", publicKey: try self.alice.retrieveIdentity(), in: carolSide)
        let bundle = try Manager.Crypto(keyManager: self.alice).seal(
            sealedPayload: OccultaBundle.SealedPayload(message: Data("Lunch at one.".utf8), appVersion: "2.0.0"),
            groupID: UUID(),
            recipients: [GroupRecipient(
                publicKey: try Manager.Ambient.keyManager.retrieveIdentity(), quantumMaterial: nil,
                contactPrekey: nil, pendingBatch: nil
            )]
        )

        #expect(try carolSide.openGroup(bundle: bundle, ownerID: "alice").sealed.message == Data("Lunch at one.".utf8))
    }

    @Test("An identity challenge in a group body with the digest opens", .ambientTestKeyManager)
    func challengeWithTheDigestOpens() throws {
        let carolSide = try TestSupport.makeContactManager()
        try insertSender(identifier: "alice", publicKey: try self.alice.retrieveIdentity(), in: carolSide)
        let bundle = try Manager.Crypto(keyManager: self.alice).seal(
            sealedPayload: OccultaBundle.SealedPayload(
                message: Data(), identityChallenge: .challenge(payload: Data(count: 72), contextNote: nil)
            ),
            groupID: UUID(),
            recipients: [GroupRecipient(
                publicKey: try Manager.Ambient.keyManager.retrieveIdentity(), quantumMaterial: nil,
                contactPrekey: nil, pendingBatch: nil
            )]
        )

        #expect(try carolSide.openGroup(bundle: bundle, ownerID: "alice").sealed.identityChallenge?.kind == .challenge)
    }
}

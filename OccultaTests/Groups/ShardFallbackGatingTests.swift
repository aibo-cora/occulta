//
//  ShardFallbackGatingTests.swift
//  OccultaTests
//
//  Regression coverage for the fallback-vs-forward-secrecy handling of shard-
//  protocol fields (shardOperations / custodyManifest / expectedShards):
//
//  1. Sender side (ContactManager.encryptBundle, single-recipient / ephemeral
//     group-envelope path): custodyManifest and expectedShards must be dropped
//     alongside shardOperations whenever no prekey is available for this send —
//     not just shardOperations, which is what the code checked before this fix.
//
//  2. Receiver side (ContactManager.openGroup / decryptSealed): even if a sender
//     ignores the rule above (stale build, or a crafted/malicious bundle), the
//     receiver must independently strip shard-protocol content whenever the
//     specific slot it decrypted used the long-term-key fallback path, since
//     that content requires forward secrecy by design.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta

// MARK: - Helpers

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

private func makeSignedShardAttr(signer: TestKeyManager) throws -> SignedAttribute {
    let attrID    = UUID()
    let createdAt = Date()
    let value     = Data((0..<33).map { _ in UInt8.random(in: .min ... .max) })
    let payload   = SignedAttribute.signingPayload(
        id: attrID, category: .shard, value: value, entryID: nil, createdAt: createdAt, expiresAt: nil
    )
    return SignedAttribute(
        id: attrID, label: "vault-shard", value: value, category: .shard,
        signature: try signer.signData(payload), createdAt: createdAt, expiresAt: nil, entryID: nil
    )
}

/// A contact profile whose public key belongs to a live `TestKeyManager` we keep
/// around, so the test can decrypt `encryptBundle`'s output exactly as the real
/// recipient device would. `encryptBundle` always seals via the app's own
/// default `Manager.Crypto()` (the real device identity, `Manager.Key()`), so
/// only the recipient side needs a controllable key manager here.
@MainActor
private func makeRecipient(
    identifier: String,
    contactManager: ContactManager,
    capability: OccultaBundle.Version,
    hasPrekey: Bool,
    hasQuantumMaterial: Bool = false
) throws -> (profile: Contact.Profile, km: TestKeyManager)? {
    let recipientKM = TestKeyManager()
    let realCrypto  = Manager.Crypto()
    guard let encryptedKey = try realCrypto.encrypt(data: try recipientKM.retrieveIdentity()) else {
        return nil
    }

    var encryptedQuantum: Data? = nil
    if hasQuantumMaterial {
        let quantum = QuantumKeyMaterial(
            encapsulatedSecret: Data(count: 32), decapsulatedSecret: Data(count: 32),
            ourCiphertext: Data(count: 32), peerCiphertext: Data(count: 32)
        )
        guard let encoded = try? JSONEncoder().encode(quantum) else { return nil }
        encryptedQuantum = try realCrypto.encrypt(data: encoded)
    }

    let profile = Contact.Profile(
        identifier: identifier, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.contactPublicKeys = [Contact.Profile.Key(
        material: encryptedKey, owner: Data(), date: Data(), quantumKeyMaterialEncrypted: encryptedQuantum
    )]
    if let byte = capability.wireByte {
        profile.maxBundleVersion = try realCrypto.encrypt(data: Data([byte]))
    }

    if hasPrekey {
        // Fake EC point (not a real SE keypair) -- only its *presence* matters for
        // the gating logic under test, matching GroupShardGatingTests' own approach.
        let prekeyPublicKey = try TestKeyManager().retrieveIdentity()
        let prekey  = Prekey(id: UUID().uuidString, contactID: identifier, publicKey: prekeyPublicKey)
        let encoded = try JSONEncoder().encode(prekey)
        var secrecy = ForwardSecrecy()
        secrecy.encodedPrekeys = [encoded]
        let encodedSecrecy = try JSONEncoder().encode(secrecy)
        profile.forwardSecrecyEncrypted = try encodedSecrecy.encrypt()
    }

    try contactManager.insertProfile(profile)
    return (profile, recipientKM)
}

/// Registers a `Contact.Profile` for `senderKM`'s identity in `contactManager`'s
/// store, so `ContactManager.openGroup`/`decryptSealed` (called with `ownerID:`)
/// can resolve the sender's key material without a fingerprint scan.
@MainActor
private func registerSender(_ senderKM: TestKeyManager, identifier: String, in contactManager: ContactManager) throws {
    let realCrypto = Manager.Crypto()
    guard let encryptedKey = try realCrypto.encrypt(data: try senderKM.retrieveIdentity()) else {
        throw TestSetupError.seUnavailable
    }
    let profile = Contact.Profile(
        identifier: identifier, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.contactPublicKeys = [Contact.Profile.Key(
        material: encryptedKey, owner: Data(), date: Data(), quantumKeyMaterialEncrypted: nil
    )]
    try contactManager.insertProfile(profile)
}

private enum TestSetupError: Error { case seUnavailable }

// MARK: - 1. Sender side — ContactManager.encryptBundle

@Suite("encryptBundle — shard-protocol fallback gate")
@MainActor struct EncryptBundleShardFallbackTests {

    @Test("no prekey available: custodyManifest/expectedShards are dropped even with no real shardOperations")
    func fallbackDropsManifestAndExpectedWithoutShardOps() throws {
        let cm = try makeContactManager()
        guard let (_, recipientKM) = try makeRecipient(
            identifier: "alice", contactManager: cm, capability: .groupCapable, hasPrekey: false
        ) else { print("⚠︎ Skipping — SE unavailable"); return }

        let encoded = try cm.encryptBundle(
            basket: Basket(files: []),
            for: "alice",
            shardOperations: nil,
            custodyManifest: [UUID()],
            expectedShards:  [UUID()]
        )

        let bundle = try OccultaBundle.decoded(from: encoded)
        #expect(bundle.group != nil, "1.9.0+ contact must still use the group-envelope format")

        let senderPub        = try Manager.Key().retrieveIdentity()
        let recipientCrypto  = Manager.Crypto(keyManager: recipientKM)
        let (recipientPayload, _, mode) = try recipientCrypto.findAndOpenRecipientSlot(
            in: bundle, blind: bundle.group!.blind,
            senderContactID: "self", senderPublicKey: senderPub,
            quantumMaterial: nil, prekeyManager: Manager.PrekeyManager()
        )
        #expect(mode == .longTermFallback || mode == .longTermNoPQ, "no prekey available -> must use fallback mode")

        let sessionKey  = SymmetricKey(data: recipientPayload.sessionKey)
        let payloadData = try recipientCrypto.openGroupCiphertext(bundle, using: sessionKey)
        let sealed      = try WireHandle.decode(payload: payloadData)

        #expect(sealed.custodyManifest == nil, "custodyManifest must not ride the fallback (non-FS) path")
        #expect(sealed.expectedShards  == nil, "expectedShards must not ride the fallback (non-FS) path")
    }

    @Test("no prekey available: shardOperations, custodyManifest, and expectedShards are all dropped together")
    func fallbackDropsAllThreeShardFields() throws {
        // isCarryingShard (a real .distribute attribute) requires ML-KEM material
        // (resolveKeyMaterial(requireQuantum: true)), which forces the hybrid PQ
        // key-derivation path -- not reproducible end-to-end with TestKeyManager's
        // synthetic ML-KEM material (see forwardSecretPathPreservesManifestAndExpected
        // for the same limitation). Proven structurally instead: a bundle carrying
        // real shardOperations/custodyManifest/expectedShards, sent with no prekey
        // available, must be exactly as small as the same call with all three fields
        // omitted entirely -- i.e. nothing from them survived into the ciphertext.
        //
        // Two separate ContactManagers (rather than two calls on the same one) so
        // prekey-batch replenishment side effects from the first call can't drift the
        // second call's bundle size for reasons unrelated to what's being tested here.
        let cmWithContent    = try makeContactManager()
        let cmWithoutContent = try makeContactManager()
        guard let (_, _) = try makeRecipient(
            identifier: "bob", contactManager: cmWithContent, capability: .groupCapable,
            hasPrekey: false, hasQuantumMaterial: true
        ) else { print("⚠︎ Skipping — SE unavailable"); return }
        guard let (_, _) = try makeRecipient(
            identifier: "bob", contactManager: cmWithoutContent, capability: .groupCapable,
            hasPrekey: false, hasQuantumMaterial: true
        ) else { print("⚠︎ Skipping — SE unavailable"); return }

        let op = OccultaBundle.ShardOperation(kind: .distribute, attribute: try makeSignedShardAttr(signer: TestKeyManager()))

        let encodedWithShardContent = try cmWithContent.encryptBundle(
            basket: Basket(files: []),
            for: "bob",
            shardOperations: [op],
            custodyManifest: [UUID()],
            expectedShards:  [UUID()]
        )
        let encodedWithoutShardContent = try cmWithoutContent.encryptBundle(
            basket: Basket(files: []),
            for: "bob",
            shardOperations: nil,
            custodyManifest: nil,
            expectedShards:  nil
        )

        // Small residual variance (a couple of bytes) comes from incidental DER/ASN.1
        // encoding differences elsewhere in the pipeline -- the same accepted residual
        // GroupShardGatingTests.mixedGroupSendsToAllWithUniformSlotSize documents and
        // tolerates. A real leak of a dropped UUID (16 bytes) or shard attribute
        // (~100+ bytes) would blow far past this tolerance, so it still proves nothing
        // from the three fields survived into the ciphertext.
        let sizeDelta = abs(encodedWithShardContent.count - encodedWithoutShardContent.count)
        #expect(
            sizeDelta <= 8,
            "shardOperations/custodyManifest/expectedShards must contribute (near-)nothing to the fallback bundle's size (delta: \(sizeDelta))"
        )
    }

    @Test("prekey available: custodyManifest/expectedShards are NOT stripped (control — fix isn't over-broad)")
    func forwardSecretPathPreservesManifestAndExpected() throws {
        let cmWithPrekey    = try makeContactManager()
        let cmWithoutPrekey = try makeContactManager()

        guard let (_, _) = try makeRecipient(
            identifier: "carol", contactManager: cmWithPrekey, capability: .groupCapable, hasPrekey: true
        ) else { print("⚠︎ Skipping — SE unavailable"); return }
        guard let (_, _) = try makeRecipient(
            identifier: "carol", contactManager: cmWithoutPrekey, capability: .groupCapable, hasPrekey: false
        ) else { print("⚠︎ Skipping — SE unavailable"); return }

        let manifest = [UUID(), UUID(), UUID()]
        let expected = [UUID(), UUID(), UUID()]

        // The FS path's wrapping key is derived from a one-time prekey whose private
        // half is intentionally not real SE material here (see makeRecipient), so full
        // decryption of the FS-wrapped payload isn't possible in this fixture -- proven
        // structurally instead, the same approach GroupShardGatingTests already uses
        // for FS-path assertions: a dropped (fallback) field measurably shrinks the
        // encoded bundle relative to the same call with the field preserved (FS).
        let encodedWithPrekey = try cmWithPrekey.encryptBundle(
            basket: Basket(files: []), for: "carol",
            shardOperations: nil, custodyManifest: manifest, expectedShards: expected
        )
        let encodedWithoutPrekey = try cmWithoutPrekey.encryptBundle(
            basket: Basket(files: []), for: "carol",
            shardOperations: nil, custodyManifest: manifest, expectedShards: expected
        )

        #expect(
            encodedWithPrekey.count > encodedWithoutPrekey.count,
            "manifest/expected content preserved on the FS path must make the bundle larger than the same call falling back (fields dropped)"
        )
    }
}

// MARK: - 2. Receiver side — ContactManager.openGroup / decryptSealed

@Suite("openGroup / decryptSealed — receiver strips shard content on fallback slot")
@MainActor struct ReceiverShardFallbackTests {

    @Test("openGroup drops per-recipient shard content when this recipient's own slot used fallback, regardless of what the sender sent")
    func openGroupStripsOnFallbackSlot() throws {
        let cm       = try makeContactManager()
        let senderKM = TestKeyManager()
        try registerSender(senderKM, identifier: "sender", in: cm)

        // "Self" (the party decrypting) is always the app's own default identity --
        // openGroup() hardcodes Manager.Crypto() (Manager.Key()) internally.
        let selfPub = try Manager.Key().retrieveIdentity()

        let realOp = OccultaBundle.ShardOperation(kind: .distribute, attribute: try makeSignedShardAttr(signer: senderKM))
        let recipient = GroupRecipient(
            publicKey: selfPub, quantumMaterial: nil,
            contactPrekey: nil,   // no prekey -> this slot seals via longTermFallback
            pendingBatch: nil,
            shardOperations: [realOp],
            custodyManifest: [UUID()], custodyManifestCount: 1,
            expectedShards:  [UUID()], expectedShardsCount: 1
        )

        let bundle = try Manager.Crypto(keyManager: senderKM).seal(
            message: Data("hi".utf8), groupID: UUID(), recipients: [recipient]
        )

        let result = try cm.openGroup(bundle: bundle, ownerID: "sender")

        #expect(result.recipientShardOperations == nil, "shard ops must be dropped when this recipient's slot used the fallback path")
        #expect(result.recipientCustodyManifest == nil, "custody manifest must be dropped when this recipient's slot used the fallback path")
        #expect(result.recipientExpectedShards  == nil, "expected shards must be dropped when this recipient's slot used the fallback path")
    }

    @Test("decryptSealed drops shard content on the legacy single-recipient path when the bundle used fallback")
    func decryptSealedStripsOnFallback() throws {
        let cm       = try makeContactManager()
        let senderKM = TestKeyManager()
        try registerSender(senderKM, identifier: "sender", in: cm)

        let selfPub = try Manager.Key().retrieveIdentity()

        let sealedPayload = OccultaBundle.SealedPayload(
            message: Data("hi".utf8),
            shardOperations: [OccultaBundle.ShardOperation(kind: .distribute, attribute: try makeSignedShardAttr(signer: senderKM))],
            custodyManifest: [UUID()],
            expectedShards:  [UUID()]
        )
        let encodedPayload = try WireHandle.encode(payload: sealedPayload)

        let bundle = try Manager.Crypto(keyManager: senderKM).seal(
            message: encodedPayload,
            contactPrekey: nil,   // no prekey -> longTermFallback
            recipientMaterial: selfPub,
            quantumMaterial: nil,
            version: .v4
        )

        let (sealed, ownerID) = try cm.decryptSealed(bundle: bundle)

        #expect(ownerID == "sender")
        #expect(sealed.shardOperations == nil, "shardOperations must be dropped on a fallback bundle")
        #expect(sealed.custodyManifest == nil, "custodyManifest must be dropped on a fallback bundle")
        #expect(sealed.expectedShards  == nil, "expectedShards must be dropped on a fallback bundle")
    }
}

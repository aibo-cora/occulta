//
//  ShardFallbackGatingTests.swift
//  OccultaTests
//
//  Regression coverage for the fallback-vs-forward-secrecy handling of shard-
//  protocol fields (shardOperations / custodyManifest; expectedShards was removed with
//  implicit revoke, bugs.md Bug 141):
//
//  1. Sender side (ContactManager.encryptBundle, single-recipient / ephemeral
//     group-envelope path): custodyManifest must be dropped
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

/// True when this host can derive the real hybrid local DB key. False on GitHub-hosted CI
/// runners, which are VMs with no Secure Enclave. Tests gated on this report as *skipped*
/// rather than silently passing, so the size of the untested surface stays visible.
private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}


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

/// The synthetic ML-KEM material `makeRecipient(hasQuantumMaterial: true)` stores
/// on the profile. Both sides of the long-term hybrid derivation are symmetric
/// (`sorted(ML-KEM secrets)` in the IKM, `XOR(peerPub, ourPub)` as the salt), so a
/// test holding these same values rederives the recipient's wrapping key exactly
/// as the recipient device would.
@MainActor
private func syntheticQuantumMaterial() -> QuantumKeyMaterial {
    QuantumKeyMaterial(
        encapsulatedSecret: Data(count: 32), decapsulatedSecret: Data(count: 32),
        ourCiphertext: Data(count: 32), peerCiphertext: Data(count: 32)
    )
}

/// A contact profile whose public key belongs to a live `TestKeyManager` we keep
/// around, so the test can decrypt `encryptBundle`'s output exactly as the real
/// recipient device would. `encryptBundle` always seals via the app's own
/// default `Manager.Crypto()` (the device identity, from `Manager.Ambient`), so
/// only the recipient side needs a controllable key manager here. Tests that read
/// "our" identity take it from `Manager.Ambient` too, so it matches what sealed.
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
        guard let encoded = try? JSONEncoder().encode(syntheticQuantumMaterial()) else { return nil }
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

    @Test("no prekey available: custodyManifest is dropped even with no real shardOperations", .ambientTestKeyManager)
    func fallbackDropsManifestWithoutShardOps() throws {
        let cm = try makeContactManager()
        let (_, recipientKM) = try #require(try makeRecipient(
            identifier: "alice", contactManager: cm, capability: .groupCapable, hasPrekey: false
        ))

        let encoded = try cm.encryptBundle(
            basket: Basket(files: []),
            for: "alice",
            shardOperations: nil,
            custodyManifest: [UUID()]
        )

        let bundle = try OccultaBundle.decoded(from: encoded)
        #expect(bundle.group != nil, "1.9.0+ contact must still use the group-envelope format")

        let senderPub        = try Manager.Ambient.keyManager.retrieveIdentity()
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
    }

    @Test("no prekey available: shardOperations and custodyManifest are dropped together", .ambientTestKeyManager)
    func fallbackDropsBothShardFields() throws {
        let cm = try makeContactManager()
        // A real .distribute attribute sets isCarryingShard, which sends encryptBundle
        // through resolveKeyMaterial(requireQuantum: true) -- hence the ML-KEM material
        // on the recipient. That only selects the hybrid variant of the *long-term*
        // derivation, which is symmetric on both sides, so the bundle stays openable
        // here with syntheticQuantumMaterial() (unlike the FS path, whose one-time
        // prekey private half this fixture does not hold -- see
        // forwardSecretPathPreservesManifest).
        let (_, recipientKM) = try #require(try makeRecipient(
            identifier: "bob", contactManager: cm, capability: .groupCapable,
            hasPrekey: false, hasQuantumMaterial: true
        ))

        let op = OccultaBundle.ShardOperation(kind: .distribute, attribute: try makeSignedShardAttr(signer: TestKeyManager()))

        let encoded = try cm.encryptBundle(
            basket: Basket(files: []),
            for: "bob",
            shardOperations: [op],
            custodyManifest: [UUID()]
        )

        let bundle = try OccultaBundle.decoded(from: encoded)
        #expect(bundle.group != nil, "1.9.0+ contact must still use the group-envelope format")

        let senderPub       = try Manager.Ambient.keyManager.retrieveIdentity()
        let recipientCrypto = Manager.Crypto(keyManager: recipientKM)
        let (recipientPayload, _, mode) = try recipientCrypto.findAndOpenRecipientSlot(
            in: bundle, blind: bundle.group!.blind,
            senderContactID: "self", senderPublicKey: senderPub,
            quantumMaterial: syntheticQuantumMaterial(), prekeyManager: Manager.PrekeyManager()
        )
        #expect(mode == .longTermFallback, "no prekey available, ML-KEM on file -> hybrid fallback mode")

        let sessionKey  = SymmetricKey(data: recipientPayload.sessionKey)
        let payloadData = try recipientCrypto.openGroupCiphertext(bundle, using: sessionKey)
        let sealed      = try WireHandle.decode(payload: payloadData)

        #expect(sealed.shardOperations == nil, "shardOperations must not ride the fallback (non-FS) path")
        #expect(sealed.custodyManifest == nil, "custodyManifest must not ride the fallback (non-FS) path")
    }

    @Test("prekey available: custodyManifest is NOT stripped (control — fix isn't over-broad)", .ambientTestKeyManager)
    func forwardSecretPathPreservesManifest() throws {
        let cmWithPrekey    = try makeContactManager()
        let cmWithoutPrekey = try makeContactManager()

        let (_, _) = try #require(try makeRecipient(
            identifier: "carol", contactManager: cmWithPrekey, capability: .groupCapable, hasPrekey: true
        ))
        let (_, _) = try #require(try makeRecipient(
            identifier: "carol", contactManager: cmWithoutPrekey, capability: .groupCapable, hasPrekey: false
        ))

        let manifest = [UUID(), UUID(), UUID()]

        // The FS path's wrapping key is derived from a one-time prekey whose private
        // half is intentionally not real SE material here (see makeRecipient), so full
        // decryption of the FS-wrapped payload isn't possible in this fixture -- proven
        // structurally instead, the same approach GroupShardGatingTests already uses
        // for FS-path assertions: a dropped (fallback) field measurably shrinks the
        // encoded bundle relative to the same call with the field preserved (FS).
        let encodedWithPrekey = try cmWithPrekey.encryptBundle(
            basket: Basket(files: []), for: "carol",
            shardOperations: nil, custodyManifest: manifest
        )
        let encodedWithoutPrekey = try cmWithoutPrekey.encryptBundle(
            basket: Basket(files: []), for: "carol",
            shardOperations: nil, custodyManifest: manifest
        )

        #expect(
            encodedWithPrekey.count > encodedWithoutPrekey.count,
            "manifest content preserved on the FS path must make the bundle larger than the same call falling back (fields dropped)"
        )
    }
}

// MARK: - 2. Receiver side — ContactManager.openGroup / decryptSealed

// Gated on a real Enclave, not `.ambientTestKeyManager`: receiving a fallback message
// with no pending batch makes the receive path generate a fresh prekey batch through
// `PrekeyManager`, whose private keys are created in the Enclave.
@Suite("openGroup / decryptSealed — receiver strips shard content on fallback slot")
@MainActor struct ReceiverShardFallbackTests {

    @Test("openGroup drops per-recipient shard content when this recipient's own slot used fallback, regardless of what the sender sent", .enabled(if: secureEnclaveAvailable()))
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
            shardOperations: [realOp]
        )

        let bundle = try Manager.Crypto(keyManager: senderKM).seal(
            message: Data("hi".utf8), groupID: UUID(), recipients: [recipient]
        )

        let result = try cm.openGroup(bundle: bundle, ownerID: "sender")

        #expect(result.recipientShardOperations == nil, "shard ops must be dropped when this recipient's slot used the fallback path")
        #expect(result.recipientCustodyManifest == nil, "custody manifest must be dropped when this recipient's slot used the fallback path")
    }

    @Test("decryptSealed drops shard content on the legacy single-recipient path when the bundle used fallback", .enabled(if: secureEnclaveAvailable()))
    func decryptSealedStripsOnFallback() throws {
        let cm       = try makeContactManager()
        let senderKM = TestKeyManager()
        try registerSender(senderKM, identifier: "sender", in: cm)

        let selfPub = try Manager.Key().retrieveIdentity()

        let sealedPayload = OccultaBundle.SealedPayload(
            message: Data("hi".utf8),
            shardOperations: [OccultaBundle.ShardOperation(kind: .distribute, attribute: try makeSignedShardAttr(signer: senderKM))],
            custodyManifest: [UUID()]
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
    }
}

// MARK: - 3. Prekey batch rides with a piece (Bug 152)
//
// A queued piece goes with every direct message until the trustee confirms it, and the
// trustee confirms only in a forward-secret reply. `encryptBundle` used to leave the
// pending prekey batch off any message carrying a piece, so once the trustee had used up
// our prekeys they never got more: every reply fell back, dropped its manifest, and the
// piece stayed queued forever.

/// A pending outbound batch of `count` prekeys, stored on `profile` as `encryptBundle` finds it.
@MainActor
private func storePendingBatch(count: Int, on profile: Contact.Profile) throws -> OccultaBundle.SealedPayload.PrekeySyncBatch {
    try profile.configureForwardSecrecy()
    let prekeys = try (0..<count).map { _ in
        OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: try TestKeyManager().retrieveIdentity())
    }
    let batch = OccultaBundle.SealedPayload.PrekeySyncBatch(generatedAt: Date(), prekeys: prekeys)
    try profile.store(batch: batch)
    return batch
}

/// A 1.9.0+ contact whose key material is `publicKey`, with the synthetic ML-KEM material,
/// so a bundle carrying a piece can be sealed to it and opened on the long-term path.
@MainActor
private func insertContact(
    identifier: String, publicKey: Data, in contactManager: ContactManager
) throws -> Contact.Profile {
    let realCrypto = Manager.Crypto()
    guard let encryptedKey = try realCrypto.encrypt(data: publicKey),
          let encryptedQuantum = try realCrypto.encrypt(data: try JSONEncoder().encode(syntheticQuantumMaterial()))
    else { throw TestSetupError.seUnavailable }
    let profile = Contact.Profile(
        identifier: identifier, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.contactPublicKeys = [Contact.Profile.Key(
        material: encryptedKey, owner: Data(), date: Data(), quantumKeyMaterialEncrypted: encryptedQuantum
    )]
    if let byte = OccultaBundle.Version.groupCapable.wireByte {
        profile.maxBundleVersion = try realCrypto.encrypt(data: Data([byte]))
    }
    try contactManager.insertProfile(profile)
    return profile
}

@Suite("encryptBundle — the pending prekey batch rides with a piece (Bug 152)")
@MainActor struct PieceCarriesPrekeyBatchTests {

    @Test("A message carrying a piece also carries the pending batch", .ambientTestKeyManager)
    func pieceCarriesBatch() throws {
        let cm = try makeContactManager()
        let recipientKM = TestKeyManager()
        let trustee = try insertContact(identifier: "trustee", publicKey: try recipientKM.retrieveIdentity(), in: cm)
        let batch   = try storePendingBatch(count: 15, on: trustee)

        let op = OccultaBundle.ShardOperation(kind: .distribute, attribute: try makeSignedShardAttr(signer: TestKeyManager()))
        let encoded = try cm.encryptBundle(basket: Basket(files: []), for: "trustee", shardOperations: [op])

        // No prekey from the trustee, so this opens on the long-term path, which the fixture can derive.
        let bundle = try OccultaBundle.decoded(from: encoded)
        let (recipientPayload, _, _) = try Manager.Crypto(keyManager: recipientKM).findAndOpenRecipientSlot(
            in: bundle, blind: try #require(bundle.group).blind,
            senderContactID: "self", senderPublicKey: try Manager.Ambient.keyManager.retrieveIdentity(),
            quantumMaterial: syntheticQuantumMaterial(), prekeyManager: Manager.PrekeyManager()
        )

        let delivered = try #require(recipientPayload.prekeyBatch)
        #expect(delivered.prekeys == batch.prekeys)
        #expect(delivered.generatedAt == batch.generatedAt)
    }

    /// Gated on a real Enclave: `openGroup` on the trustee side generates a fresh prekey batch
    /// through `PrekeyManager`, as `ReceiverShardFallbackTests` explains.
    @Test("The trustee's device stores the batch that came with the piece", .enabled(if: secureEnclaveAvailable()))
    func trusteeStoresBatch() throws {
        // Both ends are this device's own identity: the owner seals to it, and a second
        // store, holding the owner as a contact under the same key, opens it.
        let selfPub = try Manager.Key().retrieveIdentity()

        let ownerSide = try makeContactManager()
        let trustee   = try insertContact(identifier: "trustee", publicKey: selfPub, in: ownerSide)
        let batch     = try storePendingBatch(count: 15, on: trustee)

        let trusteeSide = try makeContactManager()
        let owner       = try insertContact(identifier: "owner", publicKey: selfPub, in: trusteeSide)
        try owner.configureForwardSecrecy()
        #expect(owner.availableInboundPrekeyCount == 0, "precondition: the trustee has used up the owner's prekeys")

        let op = OccultaBundle.ShardOperation(kind: .distribute, attribute: try makeSignedShardAttr(signer: TestKeyManager()))
        let encoded = try ownerSide.encryptBundle(basket: Basket(files: []), for: "trustee", shardOperations: [op])

        _ = try trusteeSide.openGroup(bundle: try OccultaBundle.decoded(from: encoded), ownerID: "owner")

        #expect(owner.availableInboundPrekeyCount == batch.prekeys.count,
                "the trustee can now reply forward-secret, so its manifest is no longer dropped")
    }
}

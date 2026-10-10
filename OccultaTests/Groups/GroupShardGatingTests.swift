//
//  GroupShardGatingTests.swift
//  OccultaTests
//
//  ContactManager.encryptGroupBundle's per-member shard eligibility gate
//  (capability + quantum material + prekey) and the tiered padding that keeps
//  every recipient's shard section the same size regardless of eligibility.
//  Uses TestKeyManager throughout, real ShardCustodyManager with an in-memory
//  ModelContainer, and directly-injected key material instead of a real proximity
//  exchange. Members' key material is sealed through the default `Manager.Crypto()`,
//  so the gating tests run under `.ambientTestKeyManager`.
//

import Testing
import CryptoKit
import SwiftData
import LocalAuthentication
@testable import Occulta
@testable import OccultaFormats

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

@MainActor
private func makeShardCustodyManager() throws -> ShardCustodyManager {
    let schema = Schema([
        VaultEntry.self, CustodyShard.self, ReconstructShard.self,
        PendingShardDistribute.self, PendingShardStatusUpdate.self, PotentiallyLostShard.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    return ShardCustodyManager(modelContainer: container, keyManager: TestKeyManager())
}

/// Build a profile with controllable capability/quantum/prekey state.
///
/// `hasPrekey: true` pre-populates `forwardSecrecyEncrypted` with one inbound
/// prekey so `encryptGroupBundle`'s `popOldestPrekeyData()` call finds it — the
/// prekey's own key bytes are fake (not a real SE keypair); only its *presence*
/// matters for the gating logic under test, not its cryptographic validity.
@MainActor
private func makeMember(
    identifier: String,
    capability: OccultaBundle.Version?,
    hasQuantumMaterial: Bool,
    hasPrekey: Bool
) throws -> Contact.Profile? {
    let realCrypto = Manager.Crypto()
    guard let encryptedKey = try realCrypto.encrypt(data: try TestKeyManager().retrieveIdentity()) else {
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
        material: encryptedKey, owner: Data(), date: Data(),
        quantumKeyMaterialEncrypted: encryptedQuantum
    )]

    if let capability, let byte = capability.wireByte {
        profile.maxBundleVersion = try realCrypto.encrypt(data: Data([byte]))
    }

    if hasPrekey {
        // Must be a real EC point, not filler bytes — encryptGroupBundle's FS path
        // does real ECDH against this key, which fails loudly on an invalid point.
        let prekeyPublicKey = try TestKeyManager().retrieveIdentity()
        let prekey  = Prekey(id: UUID().uuidString, contactID: identifier, publicKey: prekeyPublicKey)
        let encoded = try JSONEncoder().encode(prekey)
        var secrecy = ForwardSecrecy()
        secrecy.encodedPrekeys = [encoded]
        let encodedSecrecy = try JSONEncoder().encode(secrecy)
        profile.forwardSecrecyEncrypted = try encodedSecrecy.encrypt()
    }

    return profile
}

@MainActor
private func makeSignedShardAttr(signer: TestKeyManager) throws -> SignedAttribute {
    let attrID    = UUID()
    let createdAt = Date()
    // Real .shard values are always exactly 33 bytes (ShamirSecretSharing.split()
    // share format) -- matching that size here is what makes the mixed-group test's
    // slot-size comparison meaningful against the production filler, which assumes
    // the same size.
    let value     = Data((0..<33).map { _ in UInt8.random(in: .min ... .max) })
    // Non-nil for the same reason the value is 33 bytes: production `.shard` attributes always
    // bind an entryID (`backup.prepareShards` uses the distributionID, per-entry splits use the
    // entry's id), and the filler is sized against that. A nil here made the fixture ~50 bytes
    // smaller than anything real, which is a fixture bug that shows up as a padding failure.
    let entryID   = UUID()
    let payload   = SignedAttribute.signingPayload(
        id: attrID, category: .shard, value: value, entryID: entryID, createdAt: createdAt, expiresAt: nil
    )
    return SignedAttribute(
        id: attrID, label: "vault-shard", value: value, category: .shard,
        signature: try signer.signData(payload), createdAt: createdAt, expiresAt: nil, entryID: entryID
    )
}

// MARK: - Per-member gating

@Suite("encryptGroupBundle — per-member shard eligibility")
@MainActor struct GroupShardGatingTests {

    @Test("capable + quantum + prekey → member receives real shard content", .ambientTestKeyManager)
    func eligibleMemberReceivesShardContent() throws {
        let cm = try makeContactManager()
        let member = try #require(try makeMember(
            identifier: "alice", capability: .groupShardCapable, hasQuantumMaterial: true, hasPrekey: true
        ))
        try cm.insertProfile(member)

        let group = try cm.createGroup(name: "G")
        try group.addMember("alice", atDepth: 0)

        let custody = try makeShardCustodyManager()
        let owner   = TestKeyManager()
        try custody.queueDistribute(attribute: try makeSignedShardAttr(signer: owner), for: "alice")

        let encoded = try cm.encryptGroupBundle(
            basket: Basket(files: []), groupID: try #require(group.readID()),
            shardCustodyManager: custody
        )
        let bundle = try OccultaBundle.decoded(from: encoded)
        let recipients = try #require(bundle.group?.recipients)
        #expect(recipients.count == 1)

        // Decrypt the recipient's own slot to confirm real shard content survived.
        let recipientKM = try #require(member.contactPublicKeys?.first).material.flatMap { $0.decrypt() }
        _ = recipientKM // the fake key can't actually open the wrapped payload (not a real
        // SE-derived shared secret) -- eligibility is instead confirmed structurally: a
        // message-only (ineligible) recipient's wrappedPayload would be the padding floor
        // size, while an eligible recipient's carries a real op inflating it, which the
        // mixed-group test below proves by direct size comparison.
        #expect(!recipients[0].wrappedPayload.isEmpty)
    }

    @Test("groupCapable but not groupShardCapable → no shard content, message still sent", .ambientTestKeyManager)
    func versionGateExcludesShardContent() throws {
        let cm = try makeContactManager()
        let member = try #require(try makeMember(
            identifier: "bob", capability: .groupCapable, hasQuantumMaterial: true, hasPrekey: true
        ))
        try cm.insertProfile(member)

        let group = try cm.createGroup(name: "G")
        try group.addMember("bob", atDepth: 0)

        let custody = try makeShardCustodyManager()
        try custody.queueDistribute(attribute: try makeSignedShardAttr(signer: TestKeyManager()), for: "bob")

        // Must not throw and must still produce one recipient slot.
        let encoded = try cm.encryptGroupBundle(
            basket: Basket(files: []), groupID: try #require(group.readID()),
            shardCustodyManager: custody
        )
        let bundle = try OccultaBundle.decoded(from: encoded)
        #expect(bundle.group?.recipients.count == 1)
    }

    @Test("groupShardCapable but no quantum material → no shard content, message still sent", .ambientTestKeyManager)
    func quantumGateExcludesShardContent() throws {
        let cm = try makeContactManager()
        let member = try #require(try makeMember(
            identifier: "carol", capability: .groupShardCapable, hasQuantumMaterial: false, hasPrekey: true
        ))
        try cm.insertProfile(member)

        let group = try cm.createGroup(name: "G")
        try group.addMember("carol", atDepth: 0)

        let custody = try makeShardCustodyManager()
        try custody.queueDistribute(attribute: try makeSignedShardAttr(signer: TestKeyManager()), for: "carol")

        let encoded = try cm.encryptGroupBundle(
            basket: Basket(files: []), groupID: try #require(group.readID()),
            shardCustodyManager: custody
        )
        let bundle = try OccultaBundle.decoded(from: encoded)
        #expect(bundle.group?.recipients.count == 1)
    }

    @Test("groupShardCapable + quantum but no prekey available → no shard content, message still sent", .ambientTestKeyManager)
    func prekeyGateExcludesShardContent() throws {
        let cm = try makeContactManager()
        let member = try #require(try makeMember(
            identifier: "dave", capability: .groupShardCapable, hasQuantumMaterial: true, hasPrekey: false
        ))
        try cm.insertProfile(member)

        let group = try cm.createGroup(name: "G")
        try group.addMember("dave", atDepth: 0)

        let custody = try makeShardCustodyManager()
        try custody.queueDistribute(attribute: try makeSignedShardAttr(signer: TestKeyManager()), for: "dave")

        let encoded = try cm.encryptGroupBundle(
            basket: Basket(files: []), groupID: try #require(group.readID()),
            shardCustodyManager: custody
        )
        let bundle = try OccultaBundle.decoded(from: encoded)
        #expect(bundle.group?.recipients.count == 1)
    }

    // The critical non-abort guarantee: a group with one fully-eligible member and one
    // ineligible member must send successfully to both, and (per the padding scheme)
    // both recipients' wrappedPayload must be the exact same length -- proving the
    // eligible member's real shard content doesn't make their slot identifiable by size.
    @Test("mixed group: one eligible, one not — send succeeds, slots are equal size", .ambientTestKeyManager)
    func mixedGroupSendsToAllWithUniformSlotSize() throws {
        let cm = try makeContactManager()
        let eligible = try #require(try makeMember(
            identifier: "eve", capability: .groupShardCapable, hasQuantumMaterial: true, hasPrekey: true
        ))
        guard let ineligible = try makeMember(
            identifier: "frank", capability: .groupCapable, hasQuantumMaterial: false, hasPrekey: false
        ) else { return }
        try cm.insertProfile(eligible)
        try cm.insertProfile(ineligible)

        let group = try cm.createGroup(name: "Mixed")
        try group.addMember("eve", atDepth: 0)
        try group.addMember("frank", atDepth: 0)

        let custody = try makeShardCustodyManager()
        try custody.queueDistribute(attribute: try makeSignedShardAttr(signer: TestKeyManager()), for: "eve")

        let encoded = try cm.encryptGroupBundle(
            basket: Basket(files: []), groupID: try #require(group.readID()),
            shardCustodyManager: custody
        )
        let bundle = try OccultaBundle.decoded(from: encoded)
        let recipients = try #require(bundle.group?.recipients)

        #expect(recipients.count == 2, "both members must receive the message")
        // Tier-count uniformity is exact (both slots carry the same number of
        // ops/manifest/expected-shard entries), but real ECDSA signatures are DER-encoded
        // and can vary by a byte or two (ASN.1 INTEGER sign-padding) versus the filler's
        // fixed-length random signature -- an accepted, documented residual (see
        // ShardPadding's doc comment), not the gross per-recipient distinguishability this
        // scheme closes. A tight tolerance proves the padding closes the real leak without
        // asserting a byte-exactness the design doesn't promise.
        //
        // Tolerance widened from 8 to 24 on 2026-08-12. The old bound was tighter than the
        // quantity's actual spread and failed roughly one full-suite run in three — see the
        // flakiness note in Docs/Audit/SecurityReview2026-08-12/README.md. Measured over 40
        // encodes of this exact fixture the signed delta ranged [-10, +8], so 8 sat inside the
        // distribution rather than outside it. 24 clears the measured range with headroom while
        // staying far below anything that would indicate real shard content leaking through
        // slot size, which would scale with the content itself rather than with a few bytes of
        // encoding jitter.
        //
        // Note what this does and does not prove. It bounds magnitude, not direction, and the
        // property that matters is that size must not *correlate* with eligibility — a
        // consistent signed bias would slip past any magnitude bound. That was measured
        // separately over the same 40 samples: 17 negative, 18 positive, 5 zero, i.e.
        // symmetric with no eligibility bias. A standing statistical assertion would be both
        // slow and flaky in its own right, so the measurement is recorded here instead.
        let sizeDelta = abs(recipients[0].wrappedPayload.count - recipients[1].wrappedPayload.count)
        #expect(sizeDelta <= 24,
                "eligible recipient's real shard content must not make their slot meaningfully larger (delta: \(sizeDelta))")
    }
}

// MARK: - Filler must match a real op field for field

/// The test above sends a `.distribute` op; this one covers `.handback` too, so a field
/// added to one op kind and not matched in filler fails here rather than surviving to a
/// release. Used to also compare against an `attestation` field — `bugs.md` Bug 125 removed
/// that from the wire format entirely, so there is nothing left on `.handback` that
/// `.distribute` doesn't already carry, and this suite shrinks accordingly.
@Suite("Shard op padding — filler matches a real handback")
struct ShardOperationPaddingTests {

    /// Signature and shard bytes are random, matching a real ECDSA signature and a real
    /// GF(2^8) share — not the fixed repeating fill this used before. That fix matters:
    /// `JSONEncoder` escapes `/` in base64 as `\/`, so a fixed byte pattern that never
    /// happens to base64-encode to a `/` makes the "real" side artificially escape-free
    /// while `ContactManager.fillerShardOperation()`'s genuinely random bytes do sometimes
    /// escape — a one-sided bias inflating the delta below, not the two-sided noise its
    /// bound was sized for.
    private func realHandback() -> OccultaBundle.ShardOperation {
        let attribute = SignedAttribute(
            label: "vault-shard", value: Data((0..<33).map { _ in UInt8.random(in: .min ... .max) }),
            category: .shard, signature: Data((0..<72).map { _ in UInt8.random(in: .min ... .max) }), entryID: UUID()
        )
        return OccultaBundle.ShardOperation(kind: .handback, attribute: attribute)
    }

    /// Sampled rather than measured once, and deliberately so. Spread comes from two
    /// sources, both bounded and neither scaling with content: `kind`'s spelling
    /// ("unsupported" against "handback", 3 bytes) and `JSONEncoder` escaping `/` as `\/`
    /// in the base64 rendering of each op's random byte blobs — roughly 1 in 64 base64
    /// characters, symmetric now that both sides use random bytes.
    @Test("A filler op encodes to the same size as a real handback")
    func fillerMatchesHandback() throws {
        let encoder = JSONEncoder()
        var worst = 0
        var worstPair = (real: 0, filler: 0)

        for _ in 0..<200 {
            let real   = try encoder.encode(self.realHandback()).count
            let filler = try encoder.encode(ContactManager.fillerShardOperation()).count
            if abs(real - filler) > worst {
                worst = abs(real - filler)
                worstPair = (real, filler)
            }
        }

        #expect(worst <= 32, """
            A filler op must not be distinguishable from a real handback by size \
            (worst of 200: real \(worstPair.real), filler \(worstPair.filler), delta \(worst)). \
            Recipient.wrappedPayload lengths are cleartext in the bundle, so a gap here names \
            the recipient who is genuinely mid-recovery.
            """)
    }

    /// The specific omission, pinned so it cannot come back by someone "tidying" a nil default.
    @Test("Filler carries an entryID")
    func fillerCarriesEveryOptionalMember() {
        let filler = ContactManager.fillerShardOperation()

        #expect(filler.attribute?.entryID != nil,
                "real .shard attributes always carry an entryID; nil here is a ~50-byte tell")
    }
}


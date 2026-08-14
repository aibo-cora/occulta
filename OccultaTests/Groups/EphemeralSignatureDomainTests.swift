//
//  EphemeralSignatureDomainTests.swift
//  OccultaTests
//
//  Domain separation for `senderEphemeralSignature`, and the compatibility gate that
//  makes it deployable. All tests use TestKeyManager — no Secure Enclave, simulator safe.
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta

// MARK: - Helpers

/// Verify `signature` over *exactly* `signed` — no fallback arm.
///
/// `Manager.Crypto.verifySenderEphemeralSignature` accepts both the prefixed and the bare
/// form by design, so it cannot answer "which one did the sender actually produce?". These
/// tests need that answer, so they check the raw primitive directly.
@MainActor
private func verifiesExactly(_ signature: Data, over signed: Data, publicKey: Data) -> Bool {
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits as String: 256
    ]
    var error: Unmanaged<CFError>?
    guard let pubKey = SecKeyCreateWithData(publicKey as CFData, attrs as CFDictionary, &error)
    else { return false }
    return SecKeyVerifySignature(
        pubKey, .ecdsaSignatureMessageX962SHA256,
        signed as CFData, signature as CFData, &error
    )
}

/// Seal one FS-mode recipient and hand back everything needed to inspect its signature.
@MainActor
private func sealFSRecipient(prefixed: Bool) throws -> (signature: Data, ephemeralPub: Data, senderPub: Data) {
    let senderKM    = TestKeyManager()
    let recipientKM = TestKeyManager()
    let crypto      = Manager.Crypto(keyManager: senderKM)

    let (prekeyPriv, prekeyPub) = recipientKM.generateEphemeralKeyPair()!
    let prekey = Prekey(id: UUID().uuidString, contactID: "domain-sep", publicKey: prekeyPub)

    let recipient = GroupRecipient(
        publicKey:       try recipientKM.retrieveIdentity(),
        quantumMaterial: nil,
        contactPrekey:   prekey,
        pendingBatch:    nil,
        prefixesEphemeralSignature: prefixed
    )
    let bundle = try crypto.seal(
        message: Data("domain separation".utf8), groupID: UUID(), recipients: [recipient]
    )

    let entry = bundle.group!.recipients[0]
    let wrappingKey = recipientKM.createSharedSecret(
        ephemeralPrivateKey: prekeyPriv, recipientMaterial: entry.secrecyContext.ephemeralPublicKey
    )!
    let payload = try Manager.Crypto(keyManager: recipientKM)
        .openWrappedPayload(entry, blind: bundle.group!.blind, using: wrappingKey)

    return (
        signature:    try #require(payload.senderEphemeralSignature),
        ephemeralPub: entry.secrecyContext.ephemeralPublicKey,
        senderPub:    try senderKM.retrieveIdentity()
    )
}

// MARK: - What gets signed

@Suite("senderEphemeralSignature — domain separation")
@MainActor
struct EphemeralSignatureDomainTests {

    /// A recipient at `.prefixedSenderSignatureCapable` gets a signature over
    /// `"occulta-sender-ephemeral-v1" ‖ ephemeralPublicKey`, and specifically *not* over the
    /// bare key. The negative half is the point: without it this passes even if the flag is
    /// ignored, because the verifier accepts both forms.
    @Test func capableRecipient_signsPrefixedPayload_notBareKey() throws {
        let s = try sealFSRecipient(prefixed: true)
        let prefixed = Manager.Crypto.ephemeralSignaturePayload(s.ephemeralPub)

        #expect(verifiesExactly(s.signature, over: prefixed,       publicKey: s.senderPub) == true)
        #expect(verifiesExactly(s.signature, over: s.ephemeralPub, publicKey: s.senderPub) == false)
    }

    /// The compatibility half, and the regression guard that matters most here: a recipient
    /// below the tier must still receive a bare-key signature. Prefixing for a 1.10.0/1.10.1
    /// recipient makes the message unopenable on their side, and no patch can reach them.
    @Test func oldRecipient_signsBareKey_notPrefixedPayload() throws {
        let s = try sealFSRecipient(prefixed: false)
        let prefixed = Manager.Crypto.ephemeralSignaturePayload(s.ephemeralPub)

        #expect(verifiesExactly(s.signature, over: s.ephemeralPub, publicKey: s.senderPub) == true)
        #expect(verifiesExactly(s.signature, over: prefixed,       publicKey: s.senderPub) == false)
    }

    /// Defaulting matters: a `GroupRecipient` built without mentioning the flag must sign
    /// bare, because that is the form every build understands.
    @Test func flagDefaultsToBare() throws {
        let senderKM    = TestKeyManager()
        let recipientKM = TestKeyManager()
        let crypto      = Manager.Crypto(keyManager: senderKM)
        let (_, prekeyPub) = recipientKM.generateEphemeralKeyPair()!

        let r = GroupRecipient(
            publicKey:       try recipientKM.retrieveIdentity(),
            quantumMaterial: nil,
            contactPrekey:   Prekey(id: UUID().uuidString, contactID: "d", publicKey: prekeyPub),
            pendingBatch:    nil
        )
        #expect(r.prefixesEphemeralSignature == false)
        _ = crypto  // seal path covered above; this pins the default only
    }

    // MARK: Verification accepts both

    /// Receivers must accept either form for as long as 1.10.0/1.10.1 senders exist.
    @Test func verifierAcceptsBothForms() throws {
        let prefixedCase = try sealFSRecipient(prefixed: true)
        let bareCase     = try sealFSRecipient(prefixed: false)
        let crypto       = Manager.Crypto(keyManager: TestKeyManager())

        #expect(crypto.verifySenderEphemeralSignature(
            prefixedCase.signature,
            ephemeralPublicKey: prefixedCase.ephemeralPub,
            senderPublicKey: prefixedCase.senderPub
        ) == true)

        #expect(crypto.verifySenderEphemeralSignature(
            bareCase.signature,
            ephemeralPublicKey: bareCase.ephemeralPub,
            senderPublicKey: bareCase.senderPub
        ) == true)
    }

    /// Accepting two forms must not become accepting anything: a signature from a different
    /// identity still fails both arms.
    @Test func impostorFailsBothArms() throws {
        let s = try sealFSRecipient(prefixed: true)
        let impostorPub = try TestKeyManager().retrieveIdentity()
        let crypto = Manager.Crypto(keyManager: TestKeyManager())

        #expect(crypto.verifySenderEphemeralSignature(
            s.signature, ephemeralPublicKey: s.ephemeralPub, senderPublicKey: impostorPub
        ) == false)
    }

    /// The prefix changes the signed message, not the signature, so the fallback filler's
    /// fixed 72 bytes stays the right size for both forms. See
    /// `randomEphemeralSignatureFiller` on why the sizes have to line up.
    @Test func prefixDoesNotChangeSignatureLength() throws {
        let prefixed = try sealFSRecipient(prefixed: true)
        let bare     = try sealFSRecipient(prefixed: false)

        #expect((70...72).contains(prefixed.signature.count))
        #expect((70...72).contains(bare.signature.count))
    }
}

// MARK: - Capability tier

@Suite("Version — prefixedSenderSignatureCapable")
@MainActor
struct PrefixedSignatureTierTests {

    @Test func mapsFrom1_10_2AndAbove() {
        #expect(OccultaBundle.Version.max(forAppVersion: "1.10.2")
            .isAtLeast(.prefixedSenderSignatureCapable) == true)
        #expect(OccultaBundle.Version.max(forAppVersion: "1.11.0")
            .isAtLeast(.prefixedSenderSignatureCapable) == true)
    }

    /// The versions that would break if we prefixed for them.
    @Test func excludes1_10_0And1_10_1() {
        #expect(OccultaBundle.Version.max(forAppVersion: "1.10.0")
            .isAtLeast(.prefixedSenderSignatureCapable) == false)
        #expect(OccultaBundle.Version.max(forAppVersion: "1.10.1")
            .isAtLeast(.prefixedSenderSignatureCapable) == false)
    }

    /// A new top tier must not silently revoke older capabilities. This is the property the
    /// `== .groupShardCapable` comparison broke when `.senderSignatureCapable` was added in
    /// 1.10.0, which dropped shard content for every 1.10.0+ contact — so it is pinned here
    /// rather than left to the next tier to rediscover.
    @Test func newTierRetainsEveryOlderCapability() {
        let top = OccultaBundle.Version.max(forAppVersion: "1.10.2")
        #expect(top.isAtLeast(.senderSignatureCapable) == true)
        #expect(top.isAtLeast(.groupShardCapable) == true)
        #expect(top.isAtLeast(.groupCapable) == true)
        #expect(top.isAtLeast(.v4) == true)
        #expect(top.supportsGroups == true)
    }

    @Test func wireByteIsDistinctAndHighest() {
        #expect(OccultaBundle.Version.prefixedSenderSignatureCapable.wireByte == 0x08)
        #expect(OccultaBundle.Version.highestKnownWireByte == 0x08)
        #expect(OccultaBundle.Version.mostCapable == .prefixedSenderSignatureCapable)
    }

    /// Tripwire for a footgun this tier walked straight into. A capability tier's marker byte
    /// is stated three times — `Version.wireByte`, `WireHandle._versionToByte`, and
    /// `WireHandle._byteToVersion` — and adding the tier to the enum alone compiles fine and
    /// fails silently: the marker is written using the new `wireByte`, comes back unmappable,
    /// and `bundleVersionState` then compares it against `highestKnownWireByte`, which that
    /// same `wireByte` just raised. The byte lands on the "not newer than us" side and resolves
    /// to `.v3fs`, so the newest contacts are recorded as *least* capable and the `openGroup`
    /// signature gate fails open for them.
    ///
    /// Asserting the round trip catches it for every tier at once, including the next one.
    @Test func everyTierRoundTripsThroughItsMarkerByte() {
        let tiers: [OccultaBundle.Version] = [
            .prefixedSenderSignatureCapable, .senderSignatureCapable,
            .groupShardCapable, .groupCapable, .v4
        ]
        for tier in tiers {
            let byte = try? #require(tier.wireByte)
            #expect(byte != nil, "\(tier) has no wireByte")
            guard let byte else { continue }
            #expect(WireHandle.byteToVersion(byte) == tier,
                    "\(tier) marker byte \(byte) does not map back to it")
        }
    }

    /// The consequence the round-trip guard exists to prevent, stated directly: a contact
    /// recorded at the newest tier must read back as *more* capable than the tier below it,
    /// never as the `.v3fs` floor.
    @Test func newestTierMarkerDoesNotReadAsFloor() throws {
        let byte = try #require(OccultaBundle.Version.prefixedSenderSignatureCapable.wireByte)
        let mapped = try #require(WireHandle.byteToVersion(byte))
        #expect(mapped.isAtLeast(.senderSignatureCapable))
        #expect(mapped != .v3fs)
    }
}

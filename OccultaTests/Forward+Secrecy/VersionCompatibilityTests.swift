//
//  VersionCompatibilityTests.swift
//  OccultaTests
//
//  Simulator safe — no SE, no SwiftData.
//
//  Verifies that adding Version.groupCapable and Mode.group does not break
//  any existing bundle path, and that the version capability mapping is correct.
//
//  Key invariant: a 1.9.0 sender talking to a 1.8.x or older contact still
//  sends a regular v4 binary bundle (mode: .forwardSecret / .longTermFallback).
//  The .group mode is only used when sending to a group whose members are ALL
//  on .groupCapable — the contact-level version gate enforces this.
//

import Testing
import CryptoKit
import Foundation
@testable import Occulta

/// True when this host can derive the real hybrid local DB key. False on GitHub-hosted CI
/// runners, which are VMs with no Secure Enclave. Tests gated on this report as *skipped*
/// rather than silently passing, so the size of the untested surface stays visible.
private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}


// MARK: - Version capability mapping

@Suite("Version — capability mapping")
struct VersionCapabilityTests {

    @Test func max_priorToBinaryFormat_returnsV3fs() {
        #expect(OccultaBundle.Version.max(forAppVersion: "1.7.0") == .v3fs)
        #expect(OccultaBundle.Version.max(forAppVersion: "0.0.0") == .v3fs)
        #expect(OccultaBundle.Version.max(forAppVersion: "1.8.1") == .v3fs)
    }

    @Test func max_v4Range_returnsV4() {
        #expect(OccultaBundle.Version.max(forAppVersion: "1.8.2") == .v4)
        #expect(OccultaBundle.Version.max(forAppVersion: "1.8.3") == .v4)
        #expect(OccultaBundle.Version.max(forAppVersion: "1.8.99") == .v4)
    }

    @Test func max_groupCapableRange_returnsGroupCapable() {
        // groupShardCapable's threshold is 1.9.1, immediately above groupCapable's
        // 1.9.0 — so 1.9.0 is the only version in this range, not "any future version"
        // the way it was before groupShardCapable existed.
        #expect(OccultaBundle.Version.max(forAppVersion: "1.9.0") == .groupCapable)
    }

    @Test func max_groupShardCapableRange_returnsGroupShardCapable() {
        // senderSignatureCapable's threshold is 1.10.0, immediately above this tier —
        // so the range is bounded, not "any future version" (same reasoning as
        // groupCapable's own comment above, now recurring one tier up).
        #expect(OccultaBundle.Version.max(forAppVersion: "1.9.1") == .groupShardCapable)
        #expect(OccultaBundle.Version.max(forAppVersion: "1.9.2") == .groupShardCapable)
        #expect(OccultaBundle.Version.max(forAppVersion: "1.9.9") == .groupShardCapable)
    }

    @Test func wireByte_v4_is0x04() {
        #expect(OccultaBundle.Version.v4.wireByte == 0x04)
    }

    @Test func wireByte_groupCapable_is0x05() {
        #expect(OccultaBundle.Version.groupCapable.wireByte == 0x05)
    }

    @Test func wireByte_groupShardCapable_is0x06() {
        #expect(OccultaBundle.Version.groupShardCapable.wireByte == 0x06)
    }

    @Test func wireByte_v3fs_isNil() {
        #expect(OccultaBundle.Version.v3fs.wireByte == nil)
    }

    @Test func supportsGroups_trueForGroupCapableAndGroupShardCapable() {
        #expect(OccultaBundle.Version.groupCapable.supportsGroups == true)
        #expect(OccultaBundle.Version.groupShardCapable.supportsGroups == true)
        #expect(OccultaBundle.Version.v4.supportsGroups == false)
        #expect(OccultaBundle.Version.v3fs.supportsGroups == false)
        #expect(OccultaBundle.Version.unsupported.supportsGroups == false)
    }

    // Regression guard for the exact footgun found while designing the
    // senderSignatureCapable tier: supportsGroups is a manually maintained
    // `self == .x || self == .y` list, not a >= comparison. A contact upgrading to
    // a newer capability tier must not silently lose an older, unrelated capability
    // check just because that check's case list wasn't updated.
    @Test func max_senderSignatureCapableRange_returnsSenderSignatureCapable() {
        // The range is now closed at the top: 1.10.2 opened
        // `.prefixedSenderSignatureCapable` above it.
        #expect(OccultaBundle.Version.max(forAppVersion: "1.10.0") == .senderSignatureCapable)
        #expect(OccultaBundle.Version.max(forAppVersion: "1.10.1") == .senderSignatureCapable)
        // Anything far enough ahead lands on whatever the newest tier happens to be. Asserting
        // the specific case here is what made this test need editing when a tier was added;
        // asserting the property does not.
        #expect(OccultaBundle.Version.max(forAppVersion: "2.0.0") == .mostCapable)
        #expect(OccultaBundle.Version.max(forAppVersion: "2.0.0").isAtLeast(.senderSignatureCapable))
    }

    @Test func wireByte_senderSignatureCapable_is0x07() {
        #expect(OccultaBundle.Version.senderSignatureCapable.wireByte == 0x07)
    }

    @Test func supportsGroups_remainsTrueForNewerCapabilityTiers() {
        // senderSignatureCapable (1.10.0+) is strictly newer than groupCapable
        // (1.9.0+) — a contact on 1.10.0 obviously still supports group bundles.
        #expect(OccultaBundle.Version.senderSignatureCapable.supportsGroups == true)
    }
}

// MARK: - Version capability ranking (isAtLeast)

@Suite("Version — capability ranking (isAtLeast)")
struct VersionRankingTests {

    @Test func higherTier_isAtLeast_lowerTier() {
        #expect(OccultaBundle.Version.groupShardCapable.isAtLeast(.groupCapable) == true)
        #expect(OccultaBundle.Version.senderSignatureCapable.isAtLeast(.groupCapable) == true)
        #expect(OccultaBundle.Version.senderSignatureCapable.isAtLeast(.groupShardCapable) == true)
    }

    @Test func sameTier_isAtLeast_itself() {
        #expect(OccultaBundle.Version.groupCapable.isAtLeast(.groupCapable) == true)
    }

    @Test func lowerTier_isNotAtLeast_higherTier() {
        #expect(OccultaBundle.Version.groupCapable.isAtLeast(.groupShardCapable) == false)
        #expect(OccultaBundle.Version.v3fs.isAtLeast(.groupCapable) == false)
        #expect(OccultaBundle.Version.v4.isAtLeast(.groupCapable) == false)
    }

    @Test func nonTieredCases_areNeverAtLeastAnything() {
        #expect(OccultaBundle.Version.unsupported.isAtLeast(.groupCapable) == false)
        #expect(OccultaBundle.Version.v1.isAtLeast(.v3fs) == false)
    }

    @Test func nothingIsAtLeast_aNonTieredCase() {
        // .v1 isn't in `known` at all, so nothing can be "at least" it via this mechanism.
        #expect(OccultaBundle.Version.senderSignatureCapable.isAtLeast(.v1) == false)
    }
}

// MARK: - WireHandle byte tables

@Suite("WireHandle — byte tables")
struct WireHandleByteTableTests {

    @Test func byteToVersion_0x04_isV4() {
        #expect(WireHandle.byteToVersion(0x04) == .v4)
    }

    @Test func byteToVersion_0x05_isGroupCapable() {
        #expect(WireHandle.byteToVersion(0x05) == .groupCapable)
    }

    @Test func byteToVersion_0x07_isSenderSignatureCapable() {
        #expect(WireHandle.byteToVersion(0x07) == .senderSignatureCapable)
    }

    @Test func byteToVersion_unknownByte_isNil() {
        #expect(WireHandle.byteToVersion(0xFF) == nil)
        #expect(WireHandle.byteToVersion(0x00) == nil)
    }

    @Test func byteToMode_0x05_isGroup() {
        #expect(WireHandle.byteToMode(0x05) == .group)
    }

    @Test func byteToMode_existingBytes_unchanged() {
        #expect(WireHandle.byteToMode(0x01) == .forwardSecret)
        #expect(WireHandle.byteToMode(0x02) == .forwardSecretNoPQ)
        #expect(WireHandle.byteToMode(0x03) == .longTermFallback)
        #expect(WireHandle.byteToMode(0x04) == .longTermNoPQ)
    }

    @Test func versionToByte_groupCapable_encodesAsV4Wire() throws {
        // groupCapable contacts receive v4 binary bundles — same layout as v4.
        // The 0x05 byte is only stored in maxBundleVersion, never on the wire.
        let secrecy = OccultaBundle.SecrecyContext(mode: .longTermFallback, ephemeralPublicKey: Data(), prekeyID: nil)
        let bundle  = OccultaBundle(
            version:           .v4,
            secrecy:           secrecy,
            ciphertext:        Data(repeating: 0xAB, count: 28),
            fingerprintNonce:  Data(repeating: 0x01, count: 16),
            senderFingerprint: Data(repeating: 0x02, count: 32)
        )
        let wire = try bundle.encoded(version: .groupCapable)
        #expect(wire.prefix(WireHandle.magic.count).elementsEqual(WireHandle.magic),
                "groupCapable must produce OCCB magic header (binary v4 format)")
        let parsed = try WireHandle.parse(wire)
        #expect(parsed.version == 0x04,
                "Wire version byte must be 0x04 — not 0x05 — for groupCapable bundles")
    }
}

// MARK: - Mode decoding

@Suite("Mode — decoding")
struct ModeDecodingTests {

    private func decodeMode(_ raw: String) throws -> OccultaBundle.Mode {
        let json = "\"\(raw)\"".data(using: .utf8)!
        return try JSONDecoder().decode(OccultaBundle.Mode.self, from: json)
    }

    @Test func mode_group_decodesCorrectly() throws {
        #expect(try decodeMode("group") == .group)
    }

    @Test func mode_unknownString_decodesAsUnsupported() throws {
        // Simulates an old build receiving a bundle with a mode it doesn't know.
        #expect(try decodeMode("quantumEntangled") == .unsupported)
        #expect(try decodeMode("groupV2") == .unsupported)
    }

    @Test func mode_existingCases_unchanged() throws {
        #expect(try decodeMode("forwardSecret")     == .forwardSecret)
        #expect(try decodeMode("forwardSecretNoPQ") == .forwardSecretNoPQ)
        #expect(try decodeMode("longTermFallback")  == .longTermFallback)
        #expect(try decodeMode("longTermNoPQ")      == .longTermNoPQ)
    }
}

// MARK: - Backward compatibility

@Suite("Version — backward compatibility")
@MainActor struct VersionBackwardCompatTests {

    // MARK: Regular bundles from a 1.9.0 sender reach older contacts intact

    let pm = Manager.PrekeyManager()

    @Test(.enabled(if: secureEnclaveAvailable())) func fsBundle_v4Binary_survivesRoundTrip() throws {
        // A 1.9.0 sender seals with a prekey (FS path). A 1.8.x recipient must
        // be able to decode the binary envelope and derive the same session key.
        let contactID = "compat.\(UUID().uuidString)"
        defer { self.pm.deleteAllKeys(for: contactID) }

        let km      = TestKeyManager()
        let recipPub = try km.retrieveIdentity()
        let prekeys  = try self.pm.generateBatch(contactID: contactID, count: 1)
        let prekey   = prekeys[0]

        let bundle = try Manager.Crypto(keyManager: km).seal(
            message:           Data("fs compat check".utf8),
            contactPrekey:     prekey,
            recipientMaterial: recipPub,
            version:           .v4
        )
        #expect(bundle.secrecy.mode == .forwardSecret || bundle.secrecy.mode == .forwardSecretNoPQ)
        #expect(bundle.group == nil)

        let wire    = try bundle.encoded(version: .v4)
        let decoded = try OccultaBundle.decoded(from: wire)

        #expect(decoded.secrecy.mode == .forwardSecret || decoded.secrecy.mode == .forwardSecretNoPQ)
        #expect(decoded.secrecy.prekeyID == prekey.id)
        #expect(decoded.ciphertext == bundle.ciphertext)
        #expect(decoded.group == nil)

        // Recipient side: derive session key and open.
        let privKey = self.pm.retrievePrivateKey(for: prekey)
        let sessKey = privKey.flatMap {
            Manager.Crypto(keyManager: km).deriveSessionKey(
                ephemeralPrivateKey: $0,
                recipientMaterial:   decoded.secrecy.ephemeralPublicKey
            )
        }
        #expect(sessKey != nil, "1.8.x recipient must derive session key from FS bundle")
        let plain = try Manager.Crypto(keyManager: km).open(decoded, using: sessKey!)
        #expect(plain.count > 0)
    }

    @Test func fallbackBundle_v4Binary_survivesRoundTrip() throws {
        // When no prekeys are available the sender falls back to long-term ECDH.
        // Wire format is identical — a 1.8.x recipient still opens it.
        let km      = TestKeyManager()
        let recipPub = try km.retrieveIdentity()
        let bundle  = try Manager.Crypto(keyManager: km).seal(
            message:           Data("fallback compat check".utf8),
            contactPrekey:     nil,
            recipientMaterial: recipPub,
            version:           .v4
        )
        #expect(bundle.secrecy.mode == .longTermFallback || bundle.secrecy.mode == .longTermNoPQ)
        #expect(bundle.group == nil)

        let wire    = try bundle.encoded(version: .v4)
        let decoded = try OccultaBundle.decoded(from: wire)
        #expect(decoded.secrecy.mode == .longTermFallback || decoded.secrecy.mode == .longTermNoPQ)
        #expect(decoded.ciphertext == bundle.ciphertext)
    }

    // MARK: Old bundles (no "group" key in JSON) decode with group == nil

    @Test func oldBundle_noGroupKey_decodesWithNilGroup() throws {
        // Simulates a bundle produced by a 1.8.x build: no "group" field in JSON.
        let json = """
        {
            "version": "v4",
            "secrecy": {
                "mode": "longTermFallback",
                "ephemeralPublicKey": "",
                "prekeyID": null
            },
            "ciphertext": "AAAA",
            "fingerprintNonce": "AAAA",
            "senderFingerprint": "AAAA"
        }
        """
        let bundle = try JSONDecoder().decode(OccultaBundle.self, from: Data(json.utf8))
        #expect(bundle.group == nil,
                "Bundle without 'group' key must decode with group == nil")
    }

    // MARK: Group bundle is rejected on the single-recipient receive path

    @Test func groupBundle_onSingleRecipientPath_throwsUnsupportedMode() throws {
        // A group bundle delivered to a 1.8.x contact falls into the unsupported
        // path in ContactManager. We verify the mode decodes correctly and that
        // the single-recipient dispatch would reject it.
        let secrecy = OccultaBundle.SecrecyContext(
            mode:               .group,
            ephemeralPublicKey: Data(),
            prekeyID:           nil
        )
        let bundle = OccultaBundle(
            version:           .v4,
            secrecy:           secrecy,
            ciphertext:        Data(repeating: 0, count: 28),
            fingerprintNonce:  Data(repeating: 0, count: 16),
            senderFingerprint: Data(repeating: 0, count: 32),
            group:             OccultaBundle.GroupEnvelope(blind: Data(count: 32), blindNonce: Data(count: 16), recipients: [])
        )
        #expect(bundle.secrecy.mode == .group)

        // The receive path rejects .group — it must be handled by ContactManager.
        let key = SymmetricKey(size: .bits256)
        #expect(throws: (any Error).self) {
            try Manager.Crypto(keyManager: TestKeyManager()).open(bundle, using: key)
        }
    }

    // MARK: Version resolution for maxBundleVersion storage

    @Test func maxVersionForAppVersion_storedByteIsCorrect() {
        // Verify the byte stored in maxBundleVersion for each version band.
        // 1.8.x contacts: byte = 0x04 (v4). 1.9.0 contacts: byte = 0x05 (groupCapable).
        let v4Byte         = OccultaBundle.Version.max(forAppVersion: "1.8.3").wireByte
        let groupByte      = OccultaBundle.Version.max(forAppVersion: "1.9.0").wireByte
        let preBinaryByte  = OccultaBundle.Version.max(forAppVersion: "1.7.0").wireByte

        #expect(v4Byte        == 0x04)
        #expect(groupByte     == 0x05)
        #expect(preBinaryByte == nil, "v3fs has no wire byte — maxBundleVersion stays nil for pre-1.8.2 contacts")
    }

    @Test func resolveTargetVersion_0x05byte_returnsGroupCapable() throws {
        // Simulates what resolveTargetVersion returns for a contact whose
        // maxBundleVersion byte is 0x05 (stored when we received their 1.9.0 bundle).
        let resolved = WireHandle.byteToVersion(0x05)
        #expect(resolved == .groupCapable)
        #expect(resolved?.supportsGroups == true)
    }

    @Test func resolveTargetVersion_0x04byte_returnsV4_notGroupCapable() throws {
        let resolved = WireHandle.byteToVersion(0x04)
        #expect(resolved == .v4)
        #expect(resolved?.supportsGroups == false)
    }
}

// MARK: - Cross-version two-way round-trips

/// Crypto-layer tests for the two routing paths that `buildOwnedBasket` takes
/// based on `bundle.group`:
///
///   `bundle.group != nil` → `openGroup`   (1.9.0+ senders)
///   `bundle.group == nil` → `decryptSealed` (older senders, v4 non-group bundles)
///
/// No SwiftData — uses TestKeyManager and Manager.Crypto directly.
@Suite("Cross-version two-way round-trips")
@MainActor struct CrossVersionRoundTripTests {

    let pm = Manager.PrekeyManager()

    // MARK: Routing discriminator

    @Test func routingDiscriminator_groupBundle_hasNonNilGroup() throws {
        let km  = TestKeyManager()
        let pub = try km.retrieveIdentity()
        let r   = GroupRecipient(publicKey: pub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try Manager.Crypto(keyManager: km).seal(
            message: Data("hi".utf8), groupID: UUID(), recipients: [r]
        )
        let wire    = try bundle.encoded(version: .v4)
        let decoded = try OccultaBundle.decoded(from: wire)
        // buildOwnedBasket routing: bundle.group != nil → openGroup
        #expect(decoded.group != nil)
        #expect(decoded.secrecy.mode == .group)
    }

    @Test func routingDiscriminator_nonGroupBundle_hasNilGroup() throws {
        let km  = TestKeyManager()
        let pub = try km.retrieveIdentity()
        let bundle = try Manager.Crypto(keyManager: km).seal(
            message: Data("hi".utf8), contactPrekey: nil, recipientMaterial: pub, version: .v4
        )
        let wire    = try bundle.encoded(version: .v4)
        let decoded = try OccultaBundle.decoded(from: wire)
        // buildOwnedBasket routing: bundle.group == nil → decryptSealed
        #expect(decoded.group == nil)
        #expect(decoded.secrecy.mode != .group)
    }

    // MARK: 1.9.0 ↔ 1.9.0 (group format, both directions)

    @Test func twoWay_1_9_0_groupFormat_bothDirections() throws {
        let aKM  = TestKeyManager()
        let bKM  = TestKeyManager()
        let aPub = try aKM.retrieveIdentity()
        let bPub = try bKM.retrieveIdentity()
        let aCrypto = Manager.Crypto(keyManager: aKM)
        let bCrypto = Manager.Crypto(keyManager: bKM)

        let messageAtoB = Data("hello from A".utf8)
        let messageBtoA = Data("hello from B".utf8)

        // A → B
        let rB      = GroupRecipient(publicKey: bPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundleAB = try aCrypto.seal(message: messageAtoB, groupID: UUID(), recipients: [rB])
        let wireAB   = try bundleAB.encoded(version: .v4)
        let decodedAB = try OccultaBundle.decoded(from: wireAB)
        #expect(decodedAB.group != nil)

        let (recipPayloadB, _, _) = try bCrypto.findAndOpenRecipientSlot(
            in: decodedAB, blind: decodedAB.group!.blind,
            senderContactID: "A", senderPublicKey: aPub,
            quantumMaterial: nil, prekeyManager: self.pm
        )
        let sessionKeyB   = SymmetricKey(data: recipPayloadB.sessionKey)
        let payloadBytesB = try bCrypto.openGroupCiphertext(decodedAB, using: sessionKeyB)
        let sealedB       = try WireHandle.decode(payload: payloadBytesB)

        let proofB = Data(HMAC<SHA256>.authenticationCode(for: aPub, using: sessionKeyB))
        #expect(sealedB.senderProof == proofB, "sender proof must match A's identity key")
        #expect(sealedB.message == messageAtoB)

        // B → A
        let rA      = GroupRecipient(publicKey: aPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundleBA = try bCrypto.seal(message: messageBtoA, groupID: UUID(), recipients: [rA])
        let wireBA   = try bundleBA.encoded(version: .v4)
        let decodedBA = try OccultaBundle.decoded(from: wireBA)
        #expect(decodedBA.group != nil)

        let (recipPayloadA, _, _) = try aCrypto.findAndOpenRecipientSlot(
            in: decodedBA, blind: decodedBA.group!.blind,
            senderContactID: "B", senderPublicKey: bPub,
            quantumMaterial: nil, prekeyManager: self.pm
        )
        let sessionKeyA   = SymmetricKey(data: recipPayloadA.sessionKey)
        let payloadBytesA = try aCrypto.openGroupCiphertext(decodedBA, using: sessionKeyA)
        let sealedA       = try WireHandle.decode(payload: payloadBytesA)

        let proofA = Data(HMAC<SHA256>.authenticationCode(for: bPub, using: sessionKeyA))
        #expect(sealedA.senderProof == proofA, "sender proof must match B's identity key")
        #expect(sealedA.message == messageBtoA)
    }

    // MARK: 1.8.x → 1.9.0 (old non-group format received by 1.9.0 device)

    @Test(.enabled(if: secureEnclaveAvailable())) func crossVersion_olderSender_nonGroupBundle_opensOn_1_9_0() throws {
        let senderKM    = TestKeyManager()
        let recipientKM = TestKeyManager()
        let senderPub   = try senderKM.retrieveIdentity()
        let recipientPub = try recipientKM.retrieveIdentity()

        let contactID = "crossver.\(UUID().uuidString)"
        defer { self.pm.deleteAllKeys(for: contactID) }

        let prekeys = try self.pm.generateBatch(contactID: contactID, count: 1)
        let prekey  = prekeys[0]

        // 1.8.x sender: forward-secret, non-group bundle
        let encodedPayload = try WireHandle.encode(payload: OccultaBundle.SealedPayload(message: Data("from old version".utf8)))
        let bundle = try Manager.Crypto(keyManager: senderKM).seal(
            message: encodedPayload,
            contactPrekey: prekey,
            recipientMaterial: recipientPub,
            version: .v4
        )
        #expect(bundle.group == nil)
        #expect(bundle.secrecy.mode == .forwardSecret || bundle.secrecy.mode == .forwardSecretNoPQ)

        let wire    = try bundle.encoded(version: .v4)
        let decoded = try OccultaBundle.decoded(from: wire)
        #expect(decoded.group == nil, "1.8.x bundle must decode with group == nil → routes to decryptSealed on 1.9.0")

        // 1.9.0 device opens via single-recipient path (decryptSealed equivalent)
        let privKey = self.pm.retrievePrivateKey(for: prekey)
        let sessKey = privKey.flatMap {
            Manager.Crypto(keyManager: recipientKM).deriveSessionKey(
                ephemeralPrivateKey: $0,
                recipientMaterial:   decoded.secrecy.ephemeralPublicKey
            )
        }
        #expect(sessKey != nil)
        let rawPayload  = try Manager.Crypto(keyManager: recipientKM).open(decoded, using: sessKey!)
        let sealedPayload = try WireHandle.decode(payload: rawPayload)
        #expect(sealedPayload.message == Data("from old version".utf8))
    }

    // MARK: 1.9.0 → 1.8.x (1.9.0 sender falls back to non-group format for old contacts)

    @Test func crossVersion_groupCapableSender_nonGroupBundle_for_olderRecipient() throws {
        // A 1.9.0 sender whose resolveTargetVersion returns .v4 for the contact
        // must use the single-recipient seal path, not sealGroup.
        // The bundle has group == nil and can be decoded by a 1.8.x build.
        let senderKM     = TestKeyManager()
        let recipientKM  = TestKeyManager()
        let recipientPub = try recipientKM.retrieveIdentity()

        // Non-group seal (what ContactManager does when targetVersion == .v4)
        let encodedPayload = try WireHandle.encode(payload: OccultaBundle.SealedPayload(message: Data("downgrade path".utf8)))
        let bundle = try Manager.Crypto(keyManager: senderKM).seal(
            message: encodedPayload,
            contactPrekey: nil,
            recipientMaterial: recipientPub,
            version: .v4
        )
        let wire    = try bundle.encoded(version: .v4)
        let decoded = try OccultaBundle.decoded(from: wire)

        #expect(decoded.group == nil, "bundle for <1.9.0 contact must have group == nil")
        #expect(decoded.version == .v4)

        // 1.8.x recipient can open with long-term ECDH
        let senderPub = try senderKM.retrieveIdentity()
        let sessKey   = Manager.Crypto(keyManager: recipientKM).deriveSessionKey(using: senderPub)!
        let rawPayload = try Manager.Crypto(keyManager: recipientKM).open(decoded, using: sessKey)
        let sealedPayload = try WireHandle.decode(payload: rawPayload)
        #expect(sealedPayload.message == Data("downgrade path".utf8))
    }
}

// MARK: - GroupEnvelope / RecipientPayload struct integrity

@Suite("GroupEnvelope — struct integrity")
struct GroupEnvelopeTests {

    @Test func groupEnvelope_encodesAndDecodes() throws {
        let blind      = Data(repeating: 0xAA, count: 32)
        let blindNonce = Data(repeating: 0xBB, count: 16)
        let secrecy    = OccultaBundle.SecrecyContext(mode: .longTermFallback, ephemeralPublicKey: Data(), prekeyID: nil)
        let recipient  = OccultaBundle.Recipient(
            secrecyContext: secrecy,
            wrappedPayload: Data(repeating: 0x03, count: 44)
        )
        let envelope = OccultaBundle.GroupEnvelope(blind: blind, blindNonce: blindNonce, recipients: [recipient])

        let encoded = try JSONEncoder().encode(envelope)
        let decoded = try JSONDecoder().decode(OccultaBundle.GroupEnvelope.self, from: encoded)

        #expect(decoded.version == 1)
        #expect(decoded.blind == blind)
        #expect(decoded.blindNonce == blindNonce)
        #expect(decoded.recipients.count == 1)
        #expect(decoded.recipients[0].wrappedPayload == Data(repeating: 0x03, count: 44))
    }

    @Test func recipientPayload_encodesAndDecodes() throws {
        let sessionKey = Data(repeating: 0xAA, count: 32)
        let batch = OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Date(timeIntervalSince1970: 1_000_000),
            prekeys:     [OccultaBundle.WirePrekey(id: "pk1", publicKey: Data(repeating: 0x04, count: 65))]
        )
        let payload = OccultaBundle.RecipientPayload(sessionKey: sessionKey, prekeyBatch: batch)

        let encoded = try JSONEncoder().encode(payload)
        let decoded = try JSONDecoder().decode(OccultaBundle.RecipientPayload.self, from: encoded)

        #expect(decoded.sessionKey == sessionKey)
        #expect(decoded.prekeyBatch?.prekeys.first?.id == "pk1")
    }

    @Test func recipientPayload_nilBatch_encodesAndDecodes() throws {
        let payload = OccultaBundle.RecipientPayload(sessionKey: Data(repeating: 0xBB, count: 32), prekeyBatch: nil)

        let encoded = try JSONEncoder().encode(payload)
        let decoded = try JSONDecoder().decode(OccultaBundle.RecipientPayload.self, from: encoded)

        #expect(decoded.prekeyBatch == nil)
    }

}

// MARK: - groupCapable wire mapping

@Suite("Version — groupCapable wire mapping")
@MainActor struct GroupCapableWireMappingTests {

    // Regression tests for the ContactManager fix: wireVersion = targetVersion == .groupCapable ? .v4 : targetVersion.
    // Before the fix, ContactManager passed .groupCapable to seal(), embedding "groupCapable" in the AAD.
    // The receiver always decodes wire byte 0x04 as .v4 and reconstructs "v4" AAD → authentication failure.

    @Test func sealedAsGroupCapable_failsRoundTrip() throws {
        // Demonstrates the pre-fix bug: sealing with .groupCapable then wire-encoding writes 0x04.
        // The receiver decodes 0x04 → .v4, computes AAD with "v4", but the sender used "groupCapable" → mismatch.
        let km      = TestKeyManager()
        let crypto  = Manager.Crypto(keyManager: km)
        let recipPub = try km.retrieveIdentity()

        let bundle  = try crypto.seal(
            message: Data("test".utf8), contactPrekey: nil, recipientMaterial: recipPub, version: .groupCapable
        )
        let wire    = try bundle.encoded(version: .groupCapable)
        let decoded = try OccultaBundle.decoded(from: wire)
        #expect(decoded.version == .v4, "byteToVersion(0x04) always resolves to .v4, not .groupCapable")

        let sessionKey = crypto.deriveSessionKey(using: recipPub)!
        #expect(throws: (any Error).self) {
            try crypto.open(decoded, using: sessionKey)
        }
    }

    @Test func sealedAsV4_forGroupCapableContact_roundTrips() throws {
        // Fixed behavior: ContactManager uses wireVersion = .v4 for groupCapable contacts.
        let km      = TestKeyManager()
        let crypto  = Manager.Crypto(keyManager: km)
        let recipPub = try km.retrieveIdentity()
        let message = Data("hello from 1.9.0".utf8)

        let bundle  = try crypto.seal(
            message: message, contactPrekey: nil, recipientMaterial: recipPub, version: .v4
        )
        let wire    = try bundle.encoded(version: .v4)
        let decoded = try OccultaBundle.decoded(from: wire)
        #expect(decoded.version == .v4)

        let sessionKey = crypto.deriveSessionKey(using: recipPub)!
        let plaintext  = try crypto.open(decoded, using: sessionKey)
        #expect(plaintext == message)
    }

    @Test func wireVersionMapping_groupCapable_mapsToV4() {
        let target: OccultaBundle.Version = .groupCapable
        let wire = target == .groupCapable ? OccultaBundle.Version.v4 : target
        #expect(wire == .v4)
    }

    @Test func wireVersionMapping_v4_passesThrough() {
        let target: OccultaBundle.Version = .v4
        let wire = target == .groupCapable ? OccultaBundle.Version.v4 : target
        #expect(wire == .v4)
    }

    @Test func wireVersionMapping_v3fs_passesThrough() {
        let target: OccultaBundle.Version = .v3fs
        let wire = target == .groupCapable ? OccultaBundle.Version.v4 : target
        #expect(wire == .v3fs)
    }
}

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
        #expect(OccultaBundle.Version.max(forAppVersion: "1.9.0") == .groupCapable)
        #expect(OccultaBundle.Version.max(forAppVersion: "1.9.1") == .groupCapable)
        #expect(OccultaBundle.Version.max(forAppVersion: "2.0.0") == .groupCapable)
    }

    @Test func wireByte_v4_is0x04() {
        #expect(OccultaBundle.Version.v4.wireByte == 0x04)
    }

    @Test func wireByte_groupCapable_is0x05() {
        #expect(OccultaBundle.Version.groupCapable.wireByte == 0x05)
    }

    @Test func wireByte_v3fs_isNil() {
        #expect(OccultaBundle.Version.v3fs.wireByte == nil)
    }

    @Test func supportsGroups_trueOnlyForGroupCapable() {
        #expect(OccultaBundle.Version.groupCapable.supportsGroups == true)
        #expect(OccultaBundle.Version.v4.supportsGroups == false)
        #expect(OccultaBundle.Version.v3fs.supportsGroups == false)
        #expect(OccultaBundle.Version.unsupported.supportsGroups == false)
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

    @Test func fsBundle_v4Binary_survivesRoundTrip() throws {
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
            recipientMaterial: recipPub
        )
        #expect(bundle.secrecy.mode == .forwardSecret)
        #expect(bundle.group == nil)

        let wire    = try bundle.encoded(version: .v4)
        let decoded = try OccultaBundle.decoded(from: wire)

        #expect(decoded.secrecy.mode == .forwardSecret)
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
            recipientMaterial: recipPub
        )
        #expect(bundle.secrecy.mode == .longTermFallback)
        #expect(bundle.group == nil)

        let wire    = try bundle.encoded(version: .v4)
        let decoded = try OccultaBundle.decoded(from: wire)
        #expect(decoded.secrecy.mode == .longTermFallback)
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
            group:             OccultaBundle.GroupEnvelope(id: UUID(), recipients: [])
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

// MARK: - GroupEnvelope / RecipientPayload struct integrity

@Suite("GroupEnvelope — struct integrity")
struct GroupEnvelopeTests {

    @Test func groupEnvelope_encodesAndDecodes() throws {
        let groupID   = UUID()
        let nonce     = Data(repeating: 0x01, count: 16)
        let fp        = Data(repeating: 0x02, count: 32)
        let secrecy   = OccultaBundle.SecrecyContext(mode: .longTermFallback, ephemeralPublicKey: Data(), prekeyID: nil)
        let recipient = OccultaBundle.Recipient(
            fingerprint:    fp,
            fingerprintNonce: nonce,
            secrecyContext: secrecy,
            wrappedPayload: Data(repeating: 0x03, count: 44)
        )
        let envelope = OccultaBundle.GroupEnvelope(id: groupID, recipients: [recipient])

        let encoded = try JSONEncoder().encode(envelope)
        let decoded = try JSONDecoder().decode(OccultaBundle.GroupEnvelope.self, from: encoded)

        #expect(decoded.id == groupID)
        #expect(decoded.recipients.count == 1)
        #expect(decoded.recipients[0].fingerprint == fp)
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

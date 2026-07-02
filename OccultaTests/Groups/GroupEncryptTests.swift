//
//  GroupEncryptTests.swift
//  OccultaTests
//
//  All tests use TestKeyManager — no Secure Enclave, simulator safe.
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta

// MARK: - Helpers

/// Two independent TestKeyManagers: sender and a single simulated recipient.
@MainActor
private struct Pair {
    let senderKM: TestKeyManager
    let recipientKM: TestKeyManager
    let senderCrypto: Manager.Crypto
    let recipientPub: Data

    init() throws {
        self.senderKM      = TestKeyManager()
        self.recipientKM   = TestKeyManager()
        self.senderCrypto  = Manager.Crypto(keyManager: self.senderKM)
        self.recipientPub  = try self.recipientKM.retrieveIdentity()
    }

    /// Open `entry.wrappedPayload` from the recipient's side (fallback path).
    func openFallback(entry: OccultaBundle.Recipient, blind: Data) throws -> OccultaBundle.RecipientPayload {
        let senderPub = try self.senderKM.retrieveIdentity()
        let wrappingKey = self.recipientKM.createSharedSecret(using: senderPub)!
        return try Manager.Crypto(keyManager: self.recipientKM).openWrappedPayload(entry, blind: blind, using: wrappingKey)
    }

    /// Open `bundle.ciphertext` given a raw 32-byte session key Data.
    func openCiphertext(bundle: OccultaBundle, sessionKeyData: Data) throws -> OccultaBundle.SealedPayload {
        let sessionKey  = SymmetricKey(data: sessionKeyData)
        let payloadData = try Manager.Crypto(keyManager: self.senderKM).openGroupCiphertext(bundle, using: sessionKey)
        return try WireHandle.decode(payload: payloadData)
    }
}

// MARK: - Structural tests

@Suite("seal(recipients:) — structure")
@MainActor struct GroupEncryptStructuralTests {

    @Test func emptyRecipients_throws() throws {
        let km = TestKeyManager()
        let crypto = Manager.Crypto(keyManager: km)
        #expect(throws: Manager.Crypto.EncryptionError.noRecipients) {
            try crypto.seal(message: Data("hi".utf8), groupID: UUID(), recipients: [])
        }
    }

    @Test func outerMode_isGroup() throws {
        let pair = try Pair()
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.seal(message: Data("test".utf8), groupID: UUID(), recipients: [r])
        #expect(bundle.secrecy.mode == .group)
    }

    @Test func outerEphemeralKey_isEmpty() throws {
        let pair = try Pair()
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.seal(message: Data("test".utf8), groupID: UUID(), recipients: [r])
        #expect(bundle.secrecy.ephemeralPublicKey.isEmpty)
    }

    @Test func groupEnvelope_isPresent() throws {
        let pair = try Pair()
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.seal(message: Data("test".utf8), groupID: UUID(), recipients: [r])
        #expect(bundle.group != nil)
    }

    @Test func groupEnvelope_blind_isPresent_andVerifiable() throws {
        let pair    = try Pair()
        let groupID = UUID()
        let r       = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle  = try pair.senderCrypto.seal(message: Data("test".utf8), groupID: groupID, recipients: [r])
        let env     = try #require(bundle.group)

        #expect(env.blind.count == 32)
        #expect(env.blindNonce.count == 16)

        // Verify the blind was derived correctly from the known groupID
        let groupIDBytes = withUnsafeBytes(of: groupID.uuid) { Data($0) }
        let expected = Data(HMAC<SHA256>.authenticationCode(
            for: env.blindNonce, using: SymmetricKey(data: groupIDBytes)
        ))
        #expect(env.blind == expected)
    }

    @Test func multipleRecipients_envelopeCountMatches() throws {
        let km = TestKeyManager()
        let crypto = Manager.Crypto(keyManager: km)
        let recipients = try (0..<3).map { _ -> GroupRecipient in
            let rKM = TestKeyManager()
            return GroupRecipient(
                publicKey: try rKM.retrieveIdentity(),
                quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil
            )
        }
        let bundle = try crypto.seal(message: Data("multi".utf8), groupID: UUID(), recipients: recipients)
        #expect(bundle.group!.recipients.count == 3)
    }

    @Test func version_isV4() throws {
        let pair = try Pair()
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.seal(message: Data("test".utf8), groupID: UUID(), recipients: [r])
        #expect(bundle.version == .v4)
    }

    @Test func invalidRecipientPublicKey_throws() throws {
        let km = TestKeyManager()
        let crypto = Manager.Crypto(keyManager: km)
        let bad = GroupRecipient(publicKey: Data(count: 32), quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        #expect(throws: Manager.Crypto.EncryptionError.invalidRecipientMaterial) {
            try crypto.seal(message: Data("test".utf8), groupID: UUID(), recipients: [bad])
        }
    }
}

// MARK: - Fallback path round-trip

@Suite("seal(recipients:) — fallback path round-trip")
@MainActor struct GroupEncryptFallbackTests {

    @Test func fallbackMode_isLongTermNoPQ() throws {
        let pair = try Pair()
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.seal(message: Data("test".utf8), groupID: UUID(), recipients: [r])
        #expect(bundle.group!.recipients[0].secrecyContext.mode == .longTermNoPQ)
    }

    @Test func wrappedPayload_opens_sessionKeyIsPresent() throws {
        let pair = try Pair()
        let groupID = UUID()
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.seal(message: Data("hello".utf8), groupID: groupID, recipients: [r])

        let recipientPayload = try pair.openFallback(entry: bundle.group!.recipients[0], blind: bundle.group!.blind)
        #expect(recipientPayload.sessionKey.count == 32)
    }

    @Test func outerCiphertext_opens_messageMatches() throws {
        let pair = try Pair()
        let groupID = UUID()
        let original = Data("secret message".utf8)
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.seal(message: original, groupID: groupID, recipients: [r])

        let recipientPayload = try pair.openFallback(entry: bundle.group!.recipients[0], blind: bundle.group!.blind)
        let sealedPayload = try pair.openCiphertext(bundle: bundle, sessionKeyData: recipientPayload.sessionKey)

        #expect(sealedPayload.message == original)
    }

    @Test func pendingBatch_survivesRoundTrip() throws {
        let pair = try Pair()
        let groupID = UUID()
        let batch = OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Date(),
            prekeys: [OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: Data(count: 65))]
        )
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: batch)
        let bundle = try pair.senderCrypto.seal(message: Data("hi".utf8), groupID: groupID, recipients: [r])

        let recipientPayload = try pair.openFallback(entry: bundle.group!.recipients[0], blind: bundle.group!.blind)
        #expect(recipientPayload.prekeyBatch?.prekeys.count == 1)
    }
}

// MARK: - FS path round-trip

@Suite("seal(recipients:) — FS path round-trip")
@MainActor struct GroupEncryptFSTests {

    @Test func fsMode_isForwardSecretNoPQ() throws {
        let pair = try Pair()
        let groupID = UUID()
        let (prekeyPriv, prekeyPub) = pair.recipientKM.generateEphemeralKeyPair()!
        let prekey = Prekey(id: UUID().uuidString, contactID: "test", publicKey: prekeyPub)
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: prekey, pendingBatch: nil)
        let bundle = try pair.senderCrypto.seal(message: Data("test".utf8), groupID: groupID, recipients: [r])

        #expect(bundle.group!.recipients[0].secrecyContext.mode == .forwardSecretNoPQ)
        _ = prekeyPriv // hold reference
    }

    @Test func fsPath_wrappedPayload_opens_sessionKeyMatches() throws {
        let pair = try Pair()
        let groupID = UUID()
        let (prekeyPriv, prekeyPub) = pair.recipientKM.generateEphemeralKeyPair()!
        let prekey = Prekey(id: UUID().uuidString, contactID: "test", publicKey: prekeyPub)
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: prekey, pendingBatch: nil)
        let bundle = try pair.senderCrypto.seal(message: Data("fs hello".utf8), groupID: groupID, recipients: [r])

        let entry = bundle.group!.recipients[0]
        let senderEphemeralPub = entry.secrecyContext.ephemeralPublicKey

        // Recipient derives wrapping key: ECDH(prekeyPriv, senderEphemeralPub)
        let wrappingKey = pair.recipientKM.createSharedSecret(
            ephemeralPrivateKey: prekeyPriv, recipientMaterial: senderEphemeralPub
        )!
        let recipientPayload = try Manager.Crypto(keyManager: pair.recipientKM).openWrappedPayload(entry, blind: bundle.group!.blind, using: wrappingKey)

        #expect(recipientPayload.sessionKey.count == 32)

        // Verify outer ciphertext opens with the extracted session key
        let sealedPayload = try pair.openCiphertext(bundle: bundle, sessionKeyData: recipientPayload.sessionKey)
        #expect(sealedPayload.message == Data("fs hello".utf8))
    }

    @Test func fsPath_ephemeralKey_isPresent() throws {
        let pair = try Pair()
        let (_, prekeyPub) = pair.recipientKM.generateEphemeralKeyPair()!
        let prekey = Prekey(id: UUID().uuidString, contactID: "test", publicKey: prekeyPub)
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: prekey, pendingBatch: nil)
        let bundle = try pair.senderCrypto.seal(message: Data("test".utf8), groupID: UUID(), recipients: [r])

        let ephemeralPub = bundle.group!.recipients[0].secrecyContext.ephemeralPublicKey
        #expect(ephemeralPub.count == 65)
    }
}

// MARK: - Wire encode/decode round-trip

// Regression: WireHandle.encode previously dropped the group envelope (bundle.group was
// silently nil on decode), causing decryptSealed to throw BundleError.unsupportedMode
// and show "Your contact is using a newer version of Occulta."
@Suite("seal(recipients:) — wire encode/decode round-trip")
@MainActor struct GroupWireRoundTripTests {

    @Test func groupEnvelope_survivesWireEncodeDecode() throws {
        let pair    = try Pair()
        let groupID = UUID()
        let r       = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle  = try pair.senderCrypto.seal(message: Data("test".utf8), groupID: groupID, recipients: [r])

        let encoded = try bundle.encoded(version: .v4)
        let decoded = try OccultaBundle.decoded(from: encoded)

        #expect(decoded.group != nil)
        #expect(decoded.group?.blind.count == 32)
        #expect(decoded.group?.blindNonce.count == 16)
        #expect(decoded.group?.recipients.count == 1)
        #expect(decoded.secrecy.mode == .group)
        // Blind survives round-trip and is still consistent with the original groupID
        let groupIDBytes = withUnsafeBytes(of: groupID.uuid) { Data($0) }
        let expected = Data(HMAC<SHA256>.authenticationCode(
            for: decoded.group!.blindNonce, using: SymmetricKey(data: groupIDBytes)
        ))
        #expect(decoded.group?.blind == expected)
    }

    @Test func groupBundle_decodesViaWirePath() throws {
        let pair   = try Pair()
        let r      = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.seal(message: Data("x".utf8), groupID: UUID(), recipients: [r])
        let data   = try bundle.encoded(version: .v4)

        #expect(data.prefix(WireHandle.magic.count).elementsEqual(WireHandle.magic))
    }

    // Regression: duplicate TLV section 0x01 previously silently used the last one
    // instead of rejecting the bundle. A malformed or maliciously crafted bundle with
    // two 0x01 sections must throw BundleError.malformedBundle.
    @Test func duplicateTLVSection_throws() throws {
        let pair   = try Pair()
        let r      = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.seal(message: Data("dup".utf8), groupID: UUID(), recipients: [r])
        var wire   = try bundle.encoded(version: .v4)

        // Append a second TLV section 0x01 with 4 arbitrary payload bytes.
        let payload = Data([0xDE, 0xAD, 0xBE, 0xEF])
        wire.append(0x01)                               // type
        wire.append(contentsOf: [0x00, 0x00, 0x00, 0x04]) // length = 4, big-endian
        wire.append(contentsOf: payload)

        #expect(throws: OccultaBundle.BundleError.malformedBundle) {
            try WireHandle.parse(wire)
        }
    }

    @Test func unknownTLVSection_isSkipped() throws {
        let pair    = try Pair()
        let groupID = UUID()
        let r       = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle  = try pair.senderCrypto.seal(message: Data("skip".utf8), groupID: groupID, recipients: [r])
        var wire    = try bundle.encoded(version: .v4)

        // Append an unknown TLV section (type 0xFF) — must be silently skipped per §4.4.
        let payload = Data([0x01, 0x02, 0x03])
        wire.append(0xFF)
        wire.append(contentsOf: [0x00, 0x00, 0x00, 0x03])
        wire.append(contentsOf: payload)

        // Parse must succeed and group envelope must still be present.
        let parsed  = try WireHandle.parse(wire)
        #expect(parsed.groupEnvelope != nil)
    }
}

// MARK: - Group blind

@Suite("seal(recipients:) — group blind")
@MainActor struct GroupBlindTests {

    // Same groupID, two seals → different blindNonce → different blind each time.
    // A passive observer cannot cluster bundles by group identity.
    @Test func blind_differsAcrossSealsForSameGroup() throws {
        let pair    = try Pair()
        let groupID = UUID()
        let r       = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)

        let bundleA = try pair.senderCrypto.seal(message: Data("a".utf8), groupID: groupID, recipients: [r])
        let bundleB = try pair.senderCrypto.seal(message: Data("b".utf8), groupID: groupID, recipients: [r])

        #expect(bundleA.group!.blind     != bundleB.group!.blind)
        #expect(bundleA.group!.blindNonce != bundleB.group!.blindNonce)
    }

    // Different groupIDs → different blinds even if blindNonce happened to collide (astronomically unlikely).
    @Test func blind_differsAcrossDifferentGroups() throws {
        let pair     = try Pair()
        let groupIDA = UUID()
        let groupIDB = UUID()
        let r        = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)

        let bundleA = try pair.senderCrypto.seal(message: Data("a".utf8), groupID: groupIDA, recipients: [r])
        let bundleB = try pair.senderCrypto.seal(message: Data("b".utf8), groupID: groupIDB, recipients: [r])

        #expect(bundleA.group!.blind != bundleB.group!.blind)
    }

    // groupID inside the sealed payload matches the groupID passed to seal().
    @Test func groupID_isPresent_inSealedPayload() throws {
        let pair    = try Pair()
        let groupID = UUID()
        let r       = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle  = try pair.senderCrypto.seal(message: Data("gid".utf8), groupID: groupID, recipients: [r])

        let recipientPayload = try pair.openFallback(entry: bundle.group!.recipients[0], blind: bundle.group!.blind)
        let sealed           = try pair.openCiphertext(bundle: bundle, sessionKeyData: recipientPayload.sessionKey)

        #expect(sealed.groupID == groupID)
    }
}

// MARK: - Sender proof

@Suite("seal(recipients:) — sender proof")
@MainActor struct GroupSenderProofTests {

    // senderProof must be present in the decrypted SealedPayload and match
    // HMAC-SHA256(sessionKey, senderPublicKey).
    @Test func senderProof_isPresent_andVerifies() throws {
        let pair    = try Pair()
        let groupID = UUID()
        let r       = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle  = try pair.senderCrypto.seal(message: Data("proof test".utf8), groupID: groupID, recipients: [r])

        let entry            = bundle.group!.recipients[0]
        let recipientPayload = try pair.openFallback(entry: entry, blind: bundle.group!.blind)
        let sealed           = try pair.openCiphertext(bundle: bundle, sessionKeyData: recipientPayload.sessionKey)

        #expect(sealed.senderProof != nil)
        #expect(sealed.senderProof?.count == 32)

        let sessionKey = SymmetricKey(data: recipientPayload.sessionKey)
        let senderPub  = try pair.senderKM.retrieveIdentity()
        let expected   = Data(HMAC<SHA256>.authenticationCode(for: senderPub, using: sessionKey))
        #expect(sealed.senderProof == expected)
    }

    // Two bundles from the same sender share the same proof structure but
    // different session keys → different proof values.
    @Test func senderProof_differsAcrossSeals() throws {
        let pair = try Pair()
        let r    = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)

        let bundleA = try pair.senderCrypto.seal(message: Data("a".utf8), groupID: UUID(), recipients: [r])
        let bundleB = try pair.senderCrypto.seal(message: Data("b".utf8), groupID: UUID(), recipients: [r])

        let payloadA = try pair.openFallback(entry: bundleA.group!.recipients[0], blind: bundleA.group!.blind)
        let payloadB = try pair.openFallback(entry: bundleB.group!.recipients[0], blind: bundleB.group!.blind)
        let sealedA  = try pair.openCiphertext(bundle: bundleA, sessionKeyData: payloadA.sessionKey)
        let sealedB  = try pair.openCiphertext(bundle: bundleB, sessionKeyData: payloadB.sessionKey)

        #expect(sealedA.senderProof != sealedB.senderProof)
    }
}

// MARK: - Basket round-trip

// Validates the calling contract between encryptGroupBundle and seal(recipients:):
// seal receives basket bytes → outer ciphertext → decoded SealedPayload → basket.
// Would fail if encryptGroupBundle passed pre-encoded SealedPayload bytes (double-wrap).
@Suite("seal(recipients:) — basket round-trip")
@MainActor struct GroupBasketRoundTripTests {

    @Test func basket_survivesGroupRoundTrip() throws {
        let pair    = try Pair()
        let groupID = UUID()
        let content = Data("group round-trip test".utf8)

        let basketData = try WireHandle.encode(basket: Basket(files: [
            Occulta.File(content: content, format: .text, date: Date())
        ]))

        let r      = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.seal(message: basketData, groupID: groupID, recipients: [r])

        let senderPub        = try pair.senderKM.retrieveIdentity()
        let wrappingKey      = pair.recipientKM.createSharedSecret(using: senderPub)!
        let entry            = bundle.group!.recipients[0]
        let recipientPayload = try Manager.Crypto(keyManager: pair.recipientKM)
                                         .openWrappedPayload(entry, blind: bundle.group!.blind, using: wrappingKey)

        let sessionKey  = SymmetricKey(data: recipientPayload.sessionKey)
        let payloadData = try Manager.Crypto(keyManager: pair.recipientKM)
                                     .openGroupCiphertext(bundle, using: sessionKey)
        let sealed      = try WireHandle.decode(payload: payloadData)

        let recovered = try WireHandle.decode(basket: sealed.message)
        #expect(recovered.files.count == 1)
        #expect(recovered.files[0].content == content)
    }
}

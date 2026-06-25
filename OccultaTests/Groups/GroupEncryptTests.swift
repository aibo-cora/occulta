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
    func openFallback(entry: OccultaBundle.Recipient, groupID: UUID) throws -> OccultaBundle.RecipientPayload {
        let senderPub = try self.senderKM.retrieveIdentity()
        let wrappingKey = self.recipientKM.createSharedSecret(using: senderPub)!
        return try Manager.Crypto(keyManager: self.recipientKM).openWrappedPayload(entry, groupID: groupID, using: wrappingKey)
    }

    /// Open `bundle.ciphertext` given a raw 32-byte session key Data.
    func openCiphertext(bundle: OccultaBundle, sessionKeyData: Data) throws -> OccultaBundle.SealedPayload {
        let sessionKey  = SymmetricKey(data: sessionKeyData)
        let payloadData = try Manager.Crypto(keyManager: self.senderKM).openGroupCiphertext(bundle, using: sessionKey)
        return try WireHandle.decode(payload: payloadData)
    }
}

// MARK: - Structural tests

@Suite("sealGroup — structure")
@MainActor struct GroupEncryptStructuralTests {

    @Test func emptyRecipients_throws() throws {
        let km = TestKeyManager()
        let crypto = Manager.Crypto(keyManager: km)
        #expect(throws: Manager.Crypto.EncryptionError.noRecipients) {
            try crypto.sealGroup(message: Data("hi".utf8), groupID: UUID(), recipients: [])
        }
    }

    @Test func outerMode_isGroup() throws {
        let pair = try Pair()
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.sealGroup(message: Data("test".utf8), groupID: UUID(), recipients: [r])
        #expect(bundle.secrecy.mode == .group)
    }

    @Test func outerEphemeralKey_isEmpty() throws {
        let pair = try Pair()
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.sealGroup(message: Data("test".utf8), groupID: UUID(), recipients: [r])
        #expect(bundle.secrecy.ephemeralPublicKey.isEmpty)
    }

    @Test func groupEnvelope_isPresent() throws {
        let pair = try Pair()
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.sealGroup(message: Data("test".utf8), groupID: UUID(), recipients: [r])
        #expect(bundle.group != nil)
    }

    @Test func groupEnvelope_id_matchesInput() throws {
        let pair = try Pair()
        let groupID = UUID()
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.sealGroup(message: Data("test".utf8), groupID: groupID, recipients: [r])
        #expect(bundle.group!.id == groupID)
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
        let bundle = try crypto.sealGroup(message: Data("multi".utf8), groupID: UUID(), recipients: recipients)
        #expect(bundle.group!.recipients.count == 3)
    }

    @Test func version_isV4() throws {
        let pair = try Pair()
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.sealGroup(message: Data("test".utf8), groupID: UUID(), recipients: [r])
        #expect(bundle.version == .v4)
    }

    @Test func recipientFingerprint_is32Bytes() throws {
        let pair = try Pair()
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.sealGroup(message: Data("test".utf8), groupID: UUID(), recipients: [r])
        #expect(bundle.group!.recipients[0].fingerprint.count == 32)
    }

    @Test func recipientFingerprintNonce_is16Bytes() throws {
        let pair = try Pair()
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.sealGroup(message: Data("test".utf8), groupID: UUID(), recipients: [r])
        #expect(bundle.group!.recipients[0].fingerprintNonce.count == 16)
    }

    @Test func invalidRecipientPublicKey_throws() throws {
        let km = TestKeyManager()
        let crypto = Manager.Crypto(keyManager: km)
        let bad = GroupRecipient(publicKey: Data(count: 32), quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        #expect(throws: Manager.Crypto.EncryptionError.invalidRecipientMaterial) {
            try crypto.sealGroup(message: Data("test".utf8), groupID: UUID(), recipients: [bad])
        }
    }
}

// MARK: - Fallback path round-trip

@Suite("sealGroup — fallback path round-trip")
@MainActor struct GroupEncryptFallbackTests {

    @Test func fallbackMode_isLongTermNoPQ() throws {
        let pair = try Pair()
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.sealGroup(message: Data("test".utf8), groupID: UUID(), recipients: [r])
        #expect(bundle.group!.recipients[0].secrecyContext.mode == .longTermNoPQ)
    }

    @Test func wrappedPayload_opens_sessionKeyIsPresent() throws {
        let pair = try Pair()
        let groupID = UUID()
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.sealGroup(message: Data("hello".utf8), groupID: groupID, recipients: [r])

        let recipientPayload = try pair.openFallback(entry: bundle.group!.recipients[0], groupID: groupID)
        #expect(recipientPayload.sessionKey.count == 32)
    }

    @Test func outerCiphertext_opens_messageMatches() throws {
        let pair = try Pair()
        let groupID = UUID()
        let original = Data("secret message".utf8)
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try pair.senderCrypto.sealGroup(message: original, groupID: groupID, recipients: [r])

        let recipientPayload = try pair.openFallback(entry: bundle.group!.recipients[0], groupID: groupID)
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
        let bundle = try pair.senderCrypto.sealGroup(message: Data("hi".utf8), groupID: groupID, recipients: [r])

        let recipientPayload = try pair.openFallback(entry: bundle.group!.recipients[0], groupID: groupID)
        #expect(recipientPayload.prekeyBatch?.prekeys.count == 1)
    }
}

// MARK: - FS path round-trip

@Suite("sealGroup — FS path round-trip")
@MainActor struct GroupEncryptFSTests {

    @Test func fsMode_isForwardSecretNoPQ() throws {
        let pair = try Pair()
        let groupID = UUID()
        let (prekeyPriv, prekeyPub) = pair.recipientKM.generateEphemeralKeyPair()!
        let prekey = Prekey(id: UUID().uuidString, contactID: "test", publicKey: prekeyPub)
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: prekey, pendingBatch: nil)
        let bundle = try pair.senderCrypto.sealGroup(message: Data("test".utf8), groupID: groupID, recipients: [r])

        #expect(bundle.group!.recipients[0].secrecyContext.mode == .forwardSecretNoPQ)
        _ = prekeyPriv // hold reference
    }

    @Test func fsPath_wrappedPayload_opens_sessionKeyMatches() throws {
        let pair = try Pair()
        let groupID = UUID()
        let (prekeyPriv, prekeyPub) = pair.recipientKM.generateEphemeralKeyPair()!
        let prekey = Prekey(id: UUID().uuidString, contactID: "test", publicKey: prekeyPub)
        let r = GroupRecipient(publicKey: pair.recipientPub, quantumMaterial: nil, contactPrekey: prekey, pendingBatch: nil)
        let bundle = try pair.senderCrypto.sealGroup(message: Data("fs hello".utf8), groupID: groupID, recipients: [r])

        let entry = bundle.group!.recipients[0]
        let senderEphemeralPub = entry.secrecyContext.ephemeralPublicKey

        // Recipient derives wrapping key: ECDH(prekeyPriv, senderEphemeralPub)
        let wrappingKey = pair.recipientKM.createSharedSecret(
            ephemeralPrivateKey: prekeyPriv, recipientMaterial: senderEphemeralPub
        )!
        let recipientPayload = try Manager.Crypto(keyManager: pair.recipientKM).openWrappedPayload(entry, groupID: groupID, using: wrappingKey)

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
        let bundle = try pair.senderCrypto.sealGroup(message: Data("test".utf8), groupID: UUID(), recipients: [r])

        let ephemeralPub = bundle.group!.recipients[0].secrecyContext.ephemeralPublicKey
        #expect(ephemeralPub.count == 65)
    }
}

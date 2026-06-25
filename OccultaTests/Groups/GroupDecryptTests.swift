//
//  GroupDecryptTests.swift
//  OccultaTests
//
//  All tests use TestKeyManager — no Secure Enclave, simulator safe.
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta

// MARK: - Helpers

/// Sender + recipient key manager pair, with helpers for the group decrypt crypto layer.
@MainActor
private struct DecryptPair {
    let senderKM: TestKeyManager
    let recipientKM: TestKeyManager
    let senderCrypto: Manager.Crypto
    let recipientCrypto: Manager.Crypto
    let recipientPub: Data

    init() throws {
        self.senderKM       = TestKeyManager()
        self.recipientKM    = TestKeyManager()
        self.senderCrypto   = Manager.Crypto(keyManager: self.senderKM)
        self.recipientCrypto = Manager.Crypto(keyManager: self.recipientKM)
        self.recipientPub   = try self.recipientKM.retrieveIdentity()
    }

    func sealBundle(message: Data = Data("hello".utf8), groupID: UUID = UUID()) throws -> (bundle: OccultaBundle, groupID: UUID) {
        let r = GroupRecipient(publicKey: self.recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil)
        let bundle = try self.senderCrypto.sealGroup(message: message, groupID: groupID, recipients: [r])
        return (bundle, groupID)
    }
}

// MARK: - findRecipientSlot tests

@Suite("findRecipientSlot")
@MainActor struct FindRecipientSlotTests {

    @Test func findsOurSlot() throws {
        let pair = try DecryptPair()
        let (bundle, _) = try pair.sealBundle()
        let entry = try pair.recipientCrypto.findRecipientSlot(in: bundle)
        #expect(entry.fingerprint == bundle.group!.recipients[0].fingerprint)
    }

    @Test func missingGroupEnvelope_throws() throws {
        let km = TestKeyManager()
        let crypto = Manager.Crypto(keyManager: km)
        let bundle = try crypto.seal(
            message: Data("hi".utf8),
            contactPrekey: nil,
            recipientMaterial: try TestKeyManager().retrieveIdentity()
        )
        #expect(throws: GroupDecryptError.noGroupEnvelope) {
            try crypto.findRecipientSlot(in: bundle)
        }
    }

    @Test func noMatchingSlot_throws() throws {
        let pair = try DecryptPair()
        let (bundle, _) = try pair.sealBundle()
        // A third party has no matching slot
        let thirdParty = Manager.Crypto(keyManager: TestKeyManager())
        #expect(throws: GroupDecryptError.recipientSlotNotFound) {
            try thirdParty.findRecipientSlot(in: bundle)
        }
    }

    @Test func multipleRecipients_findsCorrectSlot() throws {
        let senderKM   = TestKeyManager()
        let crypto     = Manager.Crypto(keyManager: senderKM)
        let target     = TestKeyManager()
        let targetPub  = try target.retrieveIdentity()
        let decoy      = TestKeyManager()
        let decoyPub   = try decoy.retrieveIdentity()

        let recipients = [
            GroupRecipient(publicKey: decoyPub,  quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil),
            GroupRecipient(publicKey: targetPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil),
        ]
        let bundle = try crypto.sealGroup(message: Data("test".utf8), groupID: UUID(), recipients: recipients)

        let targetCrypto = Manager.Crypto(keyManager: target)
        let entry = try targetCrypto.findRecipientSlot(in: bundle)
        // Should match the second recipient's fingerprint
        #expect(entry.fingerprint == bundle.group!.recipients[1].fingerprint)
    }
}

// MARK: - openWrappedPayload tests

@Suite("openWrappedPayload")
@MainActor struct OpenWrappedPayloadTests {

    @Test func fallbackPath_opens_sessionKeySize() throws {
        let pair = try DecryptPair()
        let groupID = UUID()
        let (bundle, _) = try pair.sealBundle(groupID: groupID)

        let senderPub   = try pair.senderKM.retrieveIdentity()
        let wrappingKey = pair.recipientKM.createSharedSecret(using: senderPub)!
        let entry = bundle.group!.recipients[0]

        let payload = try pair.recipientCrypto.openWrappedPayload(entry, groupID: groupID, using: wrappingKey)
        #expect(payload.sessionKey.count == 32)
    }

    @Test func wrongKey_throws() throws {
        let pair = try DecryptPair()
        let groupID = UUID()
        let (bundle, _) = try pair.sealBundle(groupID: groupID)

        let wrongKey = SymmetricKey(size: .bits256)
        let entry = bundle.group!.recipients[0]
        #expect(throws: (any Error).self) {
            try pair.recipientCrypto.openWrappedPayload(entry, groupID: groupID, using: wrongKey)
        }
    }

    @Test func wrongGroupID_throws() throws {
        let pair = try DecryptPair()
        let groupID = UUID()
        let (bundle, _) = try pair.sealBundle(groupID: groupID)

        let senderPub   = try pair.senderKM.retrieveIdentity()
        let wrappingKey = pair.recipientKM.createSharedSecret(using: senderPub)!
        let entry = bundle.group!.recipients[0]

        #expect(throws: (any Error).self) {
            try pair.recipientCrypto.openWrappedPayload(entry, groupID: UUID(), using: wrappingKey)
        }
    }

    @Test func prekeyBatch_survives() throws {
        let senderKM = TestKeyManager()
        let crypto   = Manager.Crypto(keyManager: senderKM)
        let recipientKM = TestKeyManager()
        let recipientPub = try recipientKM.retrieveIdentity()

        let batch = OccultaBundle.SealedPayload.PrekeySyncBatch(
            generatedAt: Date(),
            prekeys: [OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: Data(count: 65))]
        )
        let r = GroupRecipient(publicKey: recipientPub, quantumMaterial: nil, contactPrekey: nil, pendingBatch: batch)
        let groupID = UUID()
        let bundle  = try crypto.sealGroup(message: Data("hi".utf8), groupID: groupID, recipients: [r])

        let senderPub   = try senderKM.retrieveIdentity()
        let wrappingKey = recipientKM.createSharedSecret(using: senderPub)!
        let entry = bundle.group!.recipients[0]
        let payload = try Manager.Crypto(keyManager: recipientKM).openWrappedPayload(entry, groupID: groupID, using: wrappingKey)
        #expect(payload.prekeyBatch?.prekeys.count == 1)
    }
}

// MARK: - openGroupCiphertext tests

@Suite("openGroupCiphertext")
@MainActor struct OpenGroupCiphertextTests {

    @Test func roundTrip_messageMatches() throws {
        let pair = try DecryptPair()
        let original = Data("group secret".utf8)
        let groupID  = UUID()
        let (bundle, _) = try pair.sealBundle(message: original, groupID: groupID)

        let senderPub   = try pair.senderKM.retrieveIdentity()
        let wrappingKey = pair.recipientKM.createSharedSecret(using: senderPub)!
        let entry       = bundle.group!.recipients[0]
        let recipientPayload = try pair.recipientCrypto.openWrappedPayload(entry, groupID: groupID, using: wrappingKey)

        let sessionKey  = SymmetricKey(data: recipientPayload.sessionKey)
        let payloadData = try pair.recipientCrypto.openGroupCiphertext(bundle, using: sessionKey)
        let decoded     = try WireHandle.decode(payload: payloadData)

        #expect(decoded.message == original)
    }

    @Test func wrongSessionKey_throws() throws {
        let pair = try DecryptPair()
        let (bundle, _) = try pair.sealBundle()

        let wrongKey = SymmetricKey(size: .bits256)
        #expect(throws: (any Error).self) {
            try pair.recipientCrypto.openGroupCiphertext(bundle, using: wrongKey)
        }
    }

    @Test func missingEnvelope_throws() throws {
        let km     = TestKeyManager()
        let crypto = Manager.Crypto(keyManager: km)
        let bundle = try crypto.seal(
            message: Data("hi".utf8),
            contactPrekey: nil,
            recipientMaterial: try TestKeyManager().retrieveIdentity()
        )
        #expect(throws: GroupDecryptError.noGroupEnvelope) {
            try crypto.openGroupCiphertext(bundle, using: SymmetricKey(size: .bits256))
        }
    }
}

// MARK: - deriveInboundKey tests

@Suite("deriveInboundKey")
@MainActor struct DeriveInboundKeyTests {

    @Test func fallbackPath_derivesKey() throws {
        let senderKM    = TestKeyManager()
        let recipientKM = TestKeyManager()
        let senderPub   = try senderKM.retrieveIdentity()
        let recipientPub = try recipientKM.retrieveIdentity()

        // Outbound: sender derives wrapping key for recipient
        let senderCrypto = Manager.Crypto(keyManager: senderKM)
        let (outboundKey, context) = try senderCrypto.deriveOutboundKey(
            contactPrekey: nil, recipientPublicKey: recipientPub, quantumMaterial: nil
        )
        #expect(context.mode == .longTermNoPQ)

        // Inbound: recipient derives wrapping key from sender
        let recipientCrypto = Manager.Crypto(keyManager: recipientKM)
        let (inboundKey, consumable) = try recipientCrypto.deriveInboundKey(
            secrecy: context,
            senderContactID: "test",
            senderPublicKey: senderPub,
            quantumMaterial: nil,
            prekeyManager: Manager.PrekeyManager()
        )
        #expect(consumable == nil)

        // Both sides derive the same key (ECDH symmetry + XOR salt symmetry in TestKeyManager)
        let outboundBytes = outboundKey.withUnsafeBytes { Data($0) }
        let inboundBytes  = inboundKey.withUnsafeBytes { Data($0) }
        #expect(outboundBytes == inboundBytes)
    }

    @Test func unsupportedMode_throws() throws {
        let km     = TestKeyManager()
        let crypto = Manager.Crypto(keyManager: km)
        let context = OccultaBundle.SecrecyContext(mode: .group, ephemeralPublicKey: Data(), prekeyID: nil)
        #expect(throws: (any Error).self) {
            try crypto.deriveInboundKey(
                secrecy: context,
                senderContactID: "test",
                senderPublicKey: Data(count: 65),
                quantumMaterial: nil,
                prekeyManager: Manager.PrekeyManager()
            )
        }
    }
}

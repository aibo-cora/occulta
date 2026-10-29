//
//  IntroCardEnclaveKeyPersistenceTests.swift
//  OccultaTests
//
//  ⚠️  Requires a Secure Enclave and iOS 26.
//
//  Supports `Docs/Features/Introduction Cards/SPEC.md` §1 and §13: a card's ML-KEM-1024 private key has
//  to outlive the call that made it (Bob's until Carol's first message, Carol's until Bob's first
//  reply), held only as an Enclave-wrapped blob in the card field. If the Enclave can't do that, the
//  build stops and the software-key fallback comes back as a decision.
//
//  Asserted:
//    - an Enclave ML-KEM-1024 key, created with the prekeys' access policy, reloads from its
//      `dataRepresentation` after the original is released, with the same public key, and decapsulates
//      a ciphertext made for that public key to the encapsulator's shared secret.
//
//  Measured and attached as `card-key-blob-sizes.txt`, not asserted, because the numbers belong to the
//  hardware they ran on: the blob sizes of the three card keys, which set the card field's size N
//  (SPEC §5).
//
//  ⚠️  Never run this on a phone that holds real Occulta data: the suite is hosted in Occulta.app.
//

import Testing
import CryptoKit
import Foundation
import Security

@testable import Occulta

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

private func enclaveMLKEMAvailable() -> Bool {
    guard #available(iOS 26, *) else { return false }
    return secureEnclaveAvailable()
}

@Suite("Introduction cards — Enclave key persistence (SPEC §1, §13)")
struct IntroCardEnclaveKeyPersistenceTests {

    /// The prekeys' policy (`PrekeyManager`): usable only while unlocked, never leaves this device.
    private static func accessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &error
        ) else { throw error!.takeRetainedValue() as Error }
        return access
    }

    @available(iOS 26, *)
    private static func makeMLKEMBlob() throws -> (blob: Data, publicKey: Data) {
        let key = try SecureEnclave.MLKEM1024.PrivateKey(accessControl: Self.accessControl())
        return (key.dataRepresentation, key.publicKey.rawRepresentation)
    }

    @Test("An Enclave ML-KEM-1024 key decapsulates from its blob after the original is released",
          .enabled(if: enclaveMLKEMAvailable()))
    func mlkemKeyDecapsulatesFromBlob() throws {
        guard #available(iOS 26, *) else { return }

        // Only the blob and the public key leave this call; the key itself is released at its end.
        let (blob, publicKeyData) = try Self.makeMLKEMBlob()

        // Carol's side: encapsulate to Bob's card key, from its public half only.
        let publicKey = try MLKEM1024.PublicKey(rawRepresentation: publicKeyData)
        let sent      = try publicKey.encapsulate()

        // Bob's side, later: rebuild from the blob and decapsulate.
        let reloaded = try SecureEnclave.MLKEM1024.PrivateKey(dataRepresentation: blob)
        #expect(reloaded.publicKey.rawRepresentation == publicKeyData)

        let received = try reloaded.decapsulate(sent.encapsulated)
        #expect(received.withUnsafeBytes { Data($0) } == sent.sharedSecret.withUnsafeBytes { Data($0) })
    }

    @Test("Card key blob sizes, attached for the card field's size", .enabled(if: enclaveMLKEMAvailable()))
    func cardKeyBlobSizes() throws {
        guard #available(iOS 26, *) else { return }

        let mlkem     = try Self.makeMLKEMBlob().blob
        let agreement = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: Self.accessControl()).dataRepresentation
        let signing   = try SecureEnclave.P256.Signing.PrivateKey(accessControl: Self.accessControl()).dataRepresentation

        let report = [
            "ML-KEM-1024 Enclave blob: \(mlkem.count) bytes",
            "P-256 agreement Enclave blob: \(agreement.count) bytes",
            "P-256 signing Enclave blob: \(signing.count) bytes"
        ]
        Attachment.record(report.joined(separator: "\n"), named: "card-key-blob-sizes.txt")

        #expect(!mlkem.isEmpty && !agreement.isEmpty && !signing.isEmpty)
    }
}

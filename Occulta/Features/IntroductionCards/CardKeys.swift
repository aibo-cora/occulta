//
//  CardKeys.swift
//  Occulta
//
//  The Secure Enclave keys of an introduction card (`Docs/Features/Introduction Cards/SPEC.md` §1): an
//  agreement key and a signing key, each held only as its `dataRepresentation` blob in the card field. CryptoKit's
//  Enclave keys create no keychain item, so a keychain listing says nothing about how many cards exist, and
//  overwriting the field with `.empty` deletes the keys. The ML-KEM key is `PostQuantumProvider`'s.
//

import Foundation
import CryptoKit
import Security

/// The P-256 operations a card needs, behind a protocol so tests can inject software keys.
nonisolated
protocol CardKeyProviding {
    /// A new agreement key: its X9.63 public key and the blob to store.
    func makeAgreementKey() throws -> (publicKey: Data, blob: Data)
    /// A new signing key: its X9.63 public key and the blob to store.
    func makeSigningKey() throws -> (publicKey: Data, blob: Data)
    /// 64-byte `r ‖ s`, for the card and the meeting proof.
    func signRaw(_ payload: Data, signingBlob: Data) throws -> Data
    /// DER, for an introduction and `senderEphemeralSignature`.
    func signDER(_ payload: Data, signingBlob: Data) throws -> Data
    /// The raw ECDH shared secret (CryptoKit's `SharedSecret` bytes) between the blob's key and an X9.63 public
    /// key. The app applies the X9.63 KDF the rest of its key derivation expects.
    func sharedSecret(agreementBlob: Data, peerPublicKey: Data) throws -> Data
    /// The X9.63 public key of an agreement blob, which the card field doesn't store beside it.
    func agreementPublicKey(blob: Data) throws -> Data
    /// The X9.63 public key of a signing blob.
    func signingPublicKey(blob: Data) throws -> Data
}

extension CardKeyProviding {
    /// Defaults so a conformer written before these two existed still compiles; a provider used for messages
    /// must implement them.
    func agreementPublicKey(blob: Data) throws -> Data { throw CardKeyError.publicKeyUnavailable }
    func signingPublicKey(blob: Data) throws -> Data { throw CardKeyError.publicKeyUnavailable }
}

nonisolated
enum CardKeyError: Error {
    case publicKeyUnavailable
}

/// Production: Secure Enclave keys, `WhenUnlockedThisDeviceOnly` with `.privateKeyUsage` (the policy of the
/// card's ML-KEM key, not CryptoKit's default `AfterFirstUnlock`).
nonisolated
struct EnclaveCardKeys: CardKeyProviding {

    enum KeyError: Error {
        case enclaveUnavailable
        case accessControlUnavailable
    }

    func makeAgreementKey() throws -> (publicKey: Data, blob: Data) {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: try Self.accessControl())
        return (key.publicKey.x963Representation, key.dataRepresentation)
    }

    func makeSigningKey() throws -> (publicKey: Data, blob: Data) {
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: try Self.accessControl())
        return (key.publicKey.x963Representation, key.dataRepresentation)
    }

    func signRaw(_ payload: Data, signingBlob: Data) throws -> Data {
        try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: signingBlob).signature(for: payload).rawRepresentation
    }

    func signDER(_ payload: Data, signingBlob: Data) throws -> Data {
        try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: signingBlob).signature(for: payload).derRepresentation
    }

    func sharedSecret(agreementBlob: Data, peerPublicKey: Data) throws -> Data {
        let key  = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: agreementBlob)
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: peerPublicKey)
        return try key.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
    }

    func agreementPublicKey(blob: Data) throws -> Data {
        try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob).publicKey.x963Representation
    }

    func signingPublicKey(blob: Data) throws -> Data {
        try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob).publicKey.x963Representation
    }

    private static func accessControl() throws -> SecAccessControl {
        guard SecureEnclave.isAvailable else { throw KeyError.enclaveUnavailable }
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error
        ) else { throw KeyError.accessControlUnavailable }
        return control
    }
}

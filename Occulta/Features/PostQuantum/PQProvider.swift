//
//  PQProvider.swift
//  Occulta
//
//  Post-quantum key encapsulation provider.
//  All iOS 26 / CryptoKit ML-KEM availability gating is confined to this file.
//
//  Production: SecureEnclave.MLKEM1024.PrivateKey — private key never leaves hardware.
//  Tests:      In-memory MLKEM1024 — no SE required in test runner.
//

import Foundation
import CryptoKit

// MARK: - Protocol

/// Abstracts ML-KEM operations behind a version-agnostic interface.
/// ExchangeManager and all call sites use this protocol — no ML-KEM types leak out.
protocol PQProvider {

    /// Generate an ML-KEM-1024 key pair.
    ///
    /// Production: the private key is created inside the Secure Enclave.
    /// Tests: the private key is created in memory.
    ///
    /// - Returns: The public key bytes (to send to the peer) and an opaque handle
    ///   wrapping the private key. Callers store the handle as `Any` and pass it back
    ///   to `decapsulate`. Returns nil if SE or ML-KEM is unavailable.
    func generateKeyPair() -> (publicKeyData: Data, privateKeyHandle: Any)?

    /// Encapsulate against a peer's ML-KEM-1024 public key.
    ///
    /// Produces a shared secret (32 bytes) and a ciphertext to send to the peer.
    /// This operation does NOT touch the Secure Enclave — it uses the peer's public key only.
    ///
    /// - Parameter peerPublicKeyData: Raw representation of the peer's ML-KEM public key.
    /// - Returns: (sharedSecret, ciphertext) or nil if the key data is malformed.
    func encapsulate(peerPublicKeyData: Data) -> (sharedSecret: Data, ciphertext: Data)?

    /// Decapsulate a ciphertext using the private key handle from `generateKeyPair`.
    ///
    /// Production: the Secure Enclave performs the lattice math internally.
    /// The 32-byte shared secret exits the SE; the private key never does.
    ///
    /// - Parameters:
    ///   - ciphertext: ML-KEM ciphertext received from the peer.
    ///   - privateKeyHandle: Opaque handle from `generateKeyPair`.
    /// - Returns: 32-byte shared secret, or nil on failure.
    func decapsulate(ciphertext: Data, privateKeyHandle: Any) -> Data?
}

// MARK: - Factory

enum PQProviderFactory {

    /// Returns a production PQ provider (SE-backed) if the platform supports ML-KEM.
    /// Returns nil on iOS < 26 — the exchange falls back to classical-only.
    static func create() -> PQProvider? {
        if #available(iOS 26, *) {
            return SecureEnclavePQProvider()
        }
        return nil
    }

    /// Returns an in-memory PQ provider for unit tests (no Secure Enclave required).
    /// Returns nil on iOS < 26.
    static func createForTesting() -> PQProvider? {
        if #available(iOS 26, *) {
            return InMemoryPQProvider()
        }
        return nil
    }
}

// MARK: - Production: Secure Enclave ML-KEM-1024

/// All ML-KEM private key operations run inside the Secure Enclave.
/// The private key never exists in app memory — only the SE chip can perform decapsulation.
///
/// Key lifecycle:
///   1. `generateKeyPair()` → SE creates MLKEM1024.PrivateKey internally.
///      Returns the public key (safe to send) and a handle wrapping the SE private key.
///   2. `encapsulate()` → CryptoKit encapsulation using peer's public key. No SE involvement.
///   3. `decapsulate()` → SE performs lattice math internally, returns shared secret.
///   4. Caller sets handle to nil → SE private key reference is released.
///
/// Access control: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (CryptoKit default).
/// The private key is available after the first unlock, matching the app's usage pattern
/// where the exchange happens while the device is unlocked and in active use.
@available(iOS 26, *)
private final class SecureEnclavePQProvider: PQProvider {

    func generateKeyPair() -> (publicKeyData: Data, privateKeyHandle: Any)? {
        guard
            let privateKey = try? SecureEnclave.MLKEM1024.PrivateKey()
        else { return nil }

        let publicKeyData = privateKey.publicKey.rawRepresentation
        return (publicKeyData, privateKey)
    }

    func encapsulate(peerPublicKeyData: Data) -> (sharedSecret: Data, ciphertext: Data)? {
        guard
            let peerPublicKey = try? MLKEM1024.PublicKey(rawRepresentation: peerPublicKeyData)
        else { return nil }

        guard
            let result = try? peerPublicKey.encapsulate()
        else { return nil }

        let sharedSecret = result.sharedSecret.withUnsafeBytes { Data($0) }
        return (sharedSecret, result.encapsulated)
    }

    func decapsulate(ciphertext: Data, privateKeyHandle: Any) -> Data? {
        guard
            let privateKey = privateKeyHandle as? SecureEnclave.MLKEM1024.PrivateKey
        else { return nil }

        guard
            let sharedSecret = try? privateKey.decapsulate(ciphertext)
        else { return nil }

        return sharedSecret.withUnsafeBytes { Data($0) }
    }
}

// MARK: - Testing: In-memory ML-KEM-1024

/// In-memory ML-KEM-1024 for unit tests. No Secure Enclave required.
/// Cryptographic operations are identical — only the key storage differs.
@available(iOS 26, *)
private final class InMemoryPQProvider: PQProvider {

    func generateKeyPair() -> (publicKeyData: Data, privateKeyHandle: Any)? {
        guard
            let privateKey = try? MLKEM1024.PrivateKey()
        else { return nil }

        let publicKeyData = privateKey.publicKey.rawRepresentation
        return (publicKeyData, privateKey)
    }

    func encapsulate(peerPublicKeyData: Data) -> (sharedSecret: Data, ciphertext: Data)? {
        guard
            let peerPublicKey = try? MLKEM1024.PublicKey(rawRepresentation: peerPublicKeyData)
        else { return nil }

        guard
            let result = try? peerPublicKey.encapsulate()
        else { return nil }

        let sharedSecret = result.sharedSecret.withUnsafeBytes { Data($0) }
        return (sharedSecret, result.encapsulated)
    }

    func decapsulate(ciphertext: Data, privateKeyHandle: Any) -> Data? {
        guard
            let privateKey = privateKeyHandle as? MLKEM1024.PrivateKey
        else { return nil }

        guard
            let sharedSecret = try? privateKey.decapsulate(ciphertext)
        else { return nil }

        return sharedSecret.withUnsafeBytes { Data($0) }
    }
}

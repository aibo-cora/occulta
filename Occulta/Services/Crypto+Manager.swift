//
//  Crypto+Manager.swift
//  Occulta
//
//  Updated for v2_hybridPQ encryption scheme.
//  Changes from original:
//    1. Local encrypt/decrypt uses hybrid key + AAD (EncryptionScheme.v2_hybridPQ)
//    2. Legacy decrypt path preserved for migration only
//    3. CryptoProtocol updated with AAD-aware signatures
//

import Foundation
import CryptoKit

enum Manager { }

/// A key manager that can derive the v1 local DB key: `ECDH(identity key, G)` with no authenticated data, a function of the
/// identity key's public point, which every contact holds (`bugs.md` Bug 171). Not part of `KeyManagerProtocol`, so nothing
/// that takes a key manager can reach it: only `LegacyCryptoManager` asks for it, to open what `migrateToV2` is still moving.
protocol LegacyLocalKeyProviding {
    func createLocalEncryptionKey() throws -> SymmetricKey?
}

/// Crypto manager that uses the v1 key path for decryptLegacy.
/// Used only during migration. Not stored or used after migration completes.
final class LegacyCryptoManager: LegacyCryptoProtocol {
    private let keyManager: (any LegacyLocalKeyProviding)?

    /// - Parameter keyManager: Where the v1 key comes from. The ambient key manager if it can derive one (the real one and
    ///   `TestKeyManager` can); one that can't makes `decryptLegacy` return nil.
    init(keyManager: (any LegacyLocalKeyProviding)? = Manager.Ambient.keyManager as? any LegacyLocalKeyProviding) {
        self.keyManager = keyManager
    }

    func decryptLegacy(data: Data?) throws -> Data? {
        guard let data, let key = try self.keyManager?.createLocalEncryptionKey() else { return nil }
        
        let box = try AES.GCM.SealedBox(combined: data)
        
        return try AES.GCM.open(box, using: key)
    }

    // All other methods delegate to Manager.Crypto (not used during migration).
    func encrypt(data: Data?) throws -> Data?                          { try Manager.Crypto().encrypt(data: data) }
    func decrypt(data: Data?) throws -> Data?                          { try Manager.Crypto().decrypt(data: data) }
    func encrypt(message: Data, using material: Data?) throws -> Data? { try Manager.Crypto().encrypt(message: message, using: material) }
    func decrypt(message: Data, using material: Data?) throws -> Data? { try Manager.Crypto().decrypt(message: message, using: material) }
    func sign(data: Data?) throws -> String { try Manager.Crypto().sign(data: data) }
}

extension Manager {
    class Crypto: CryptoProtocol {
        let keyManager: any KeyManagerProtocol

        init() {
            self.keyManager = Manager.Ambient.keyManager
        }

        init(keyManager: any KeyManagerProtocol) {
            self.keyManager = keyManager
        }

        // MARK: - Local encryption (v2 — hybrid key + AAD)

        func encrypt(data: Data?) throws -> Data? {
            guard
                let data,
                let key = try self.keyManager.createHybridLocalEncryptionKey()
            else {
                return nil
            }

            let aad = EncryptionScheme.v2_hybridPQ.aad
            let sealed = try AES.GCM.seal(data, using: key, nonce: AES.GCM.Nonce(), authenticating: aad)

            return sealed.combined
        }

        func decrypt(data: Data?) throws -> Data? {
            guard
                let data,
                let key = try self.keyManager.createHybridLocalEncryptionKey()
            else {
                return nil
            }

            let box = try AES.GCM.SealedBox(combined: data)
            let aad = EncryptionScheme.v2_hybridPQ.aad

            return try AES.GCM.open(box, using: key, authenticating: aad)
        }

        // MARK: - Local encryption with a caller-supplied key (skips derivation)

        /// Same as `encrypt(data:)` but uses an already-derived key instead of deriving
        /// one via `keyManager`. For batch callers that derive once and reuse the result
        /// across many calls (see `Group.reencryptAllDepths(usingKey:content:)`) rather
        /// than re-deriving per call.
        func encrypt(data: Data?, using key: SymmetricKey) throws -> Data? {
            guard let data else { return nil }

            let aad = EncryptionScheme.v2_hybridPQ.aad
            let sealed = try AES.GCM.seal(data, using: key, nonce: AES.GCM.Nonce(), authenticating: aad)

            return sealed.combined
        }

        /// Same as `decrypt(data:)` but uses an already-derived key instead of deriving
        /// one via `keyManager`.
        func decrypt(data: Data?, using key: SymmetricKey) throws -> Data? {
            guard let data else { return nil }

            let box = try AES.GCM.SealedBox(combined: data)
            let aad = EncryptionScheme.v2_hybridPQ.aad

            return try AES.GCM.open(box, using: key, authenticating: aad)
        }

        // MARK: - Transport encryption (unchanged)

        func encrypt(message: Data, using material: Data?) throws -> Data? {
            guard
                let key = self.keyManager.createSharedSecret(using: material)
            else {
                return nil
            }

            let sealed = try AES.GCM.seal(message, using: key, nonce: AES.GCM.Nonce())
            return sealed.combined
        }

        func decrypt(message: Data, using material: Data?) throws -> Data? {
            guard
                let key = self.keyManager.createSharedSecret(using: material)
            else {
                return nil
            }

            let sealed = try AES.GCM.SealedBox(combined: message)
            return try AES.GCM.open(sealed, using: key)
        }

        // MARK: - Signing

        func sign(data: Data?) throws -> String {
            let key = try Manager.Key().retrievePrivateKey()
            let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256

            guard let key, let data else {
                throw SigningError.missingKeyOrData
            }

            guard SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
                throw SigningError.unsupportedAlgorithm
            }

            var error: Unmanaged<CFError>?
            guard
                let signature = SecKeyCreateSignature(key, algorithm, data as CFData, &error) as Data?
            else {
                throw SigningError.signingFailed(underlying: error!.takeRetainedValue() as Error)
            }

            return signature.hexEncodedString()
        }
    }
}

// MARK: - Protocol

protocol CryptoProtocol {
    func encrypt(data: Data?) throws -> Data?
    func decrypt(data: Data?) throws -> Data?
    func encrypt(message: Data, using material: Data?) throws -> Data?
    func decrypt(message: Data, using material: Data?) throws -> Data?
    func sign(data: Data?) throws -> String
}

/// A crypto manager that can also open a value sealed under the v1 key (identity-derived, no authenticated data). Only
/// `DatabaseMigration.migrateToV2` takes one, and `LegacyCryptoManager` is the only conformer outside tests: after the
/// migration no v1 ciphertext remains, and until then nothing but the migration may open one (`bugs.md` Bug 171).
protocol LegacyCryptoProtocol: CryptoProtocol {
    func decryptLegacy(data: Data?) throws -> Data?
}

// MARK: - Signing errors

/// `sign(data:)` throws on any failure rather than returning a human-readable string —
/// a prior version returned strings like "Key or data is missing" as the signature
/// value itself, which callers could display/copy as if they were real signatures
/// (SecurityReview2026-07-24, finding #9 / SEC-3).
enum SigningError: Error {
    case missingKeyOrData
    case unsupportedAlgorithm
    case signingFailed(underlying: Error)
}

// MARK: - Convenience extensions (use v2 path post-migration)

extension String {
    func decrypt() -> String {
        let data = Data(base64Encoded: self)
        let cryptoOps: CryptoProtocol = Manager.Crypto()

        do {
            if let decrypted = try cryptoOps.decrypt(data: data) {
                return String(data: decrypted, encoding: .utf8) ?? ""
            } else {
                return ""
            }
        } catch {
            return ""
        }
    }

    /// Decrypts using an already-derived key instead of deriving one fresh.
    /// Swallows failure to "", matching `decrypt()`'s convention.
    func decrypt(using key: SymmetricKey) -> String {
        guard let data      = Data(base64Encoded: self),
              let decrypted = data.decrypt(using: key)
        else { return "" }
        return String(data: decrypted, encoding: .utf8) ?? ""
    }
}

extension Data {
    func hexEncodedString() -> String {
        self.map { String(format: "%02x", $0) }.joined()
    }

    func decrypt() -> Data? {
        let cryptoOps: CryptoProtocol = Manager.Crypto()
        return try? cryptoOps.decrypt(data: self)
    }

    func encrypt() throws -> Data? {
        let cryptoOps: CryptoProtocol = Manager.Crypto()
        return try cryptoOps.encrypt(data: self)
    }

    /// Encrypts using an already-derived key instead of deriving one fresh.
    func encrypt(using key: SymmetricKey) throws -> Data? {
        try Manager.Crypto().encrypt(data: self, using: key)
    }

    /// Decrypts using an already-derived key instead of deriving one fresh.
    /// Swallows failure to nil, matching `decrypt()`'s convention.
    func decrypt(using key: SymmetricKey) -> Data? {
        try? Manager.Crypto().decrypt(data: self, using: key)
    }
}

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
import Crypto

enum Manager { }

/// Crypto manager that uses the v1 key path for decryptLegacy.
/// Used only during migration. Not stored or used after migration completes.
final class LegacyCryptoManager: CryptoProtocol {
    private let keyManager = Manager.Key()

    func decryptLegacy(data: Data?) throws -> Data? {
        guard let data, let key = try self.keyManager.createLocalEncryptionKey() else { return nil }
        
        let box = try AES.GCM.SealedBox(combined: data)
        
        return try AES.GCM.open(box, using: key)
    }

    // All other methods delegate to Manager.Crypto (not used during migration).
    func encrypt(data: Data?) throws -> Data?                          { try Manager.Crypto().encrypt(data: data) }
    func decrypt(data: Data?) throws -> Data?                          { try Manager.Crypto().decrypt(data: data) }
    func encrypt(message: Data, using material: Data?) throws -> Data? { try Manager.Crypto().encrypt(message: message, using: material) }
    func decrypt(message: Data, using material: Data?) throws -> Data? { try Manager.Crypto().decrypt(message: message, using: material) }
    func sign(data: Data?) -> String { Manager.Crypto().sign(data: data) }
}

extension Manager {
    class Crypto: CryptoProtocol {
        let keyManager: any KeyManagerProtocol

        init() {
            self.keyManager = Manager.Key() as any KeyManagerProtocol
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

        // MARK: - Legacy local decrypt (v1 — identity-derived key, no AAD)

        /// Decrypt data encrypted under the v1 scheme (identity-derived key, no AAD).
        ///
        /// Used exclusively during migration from v1 → v2. After migration completes,
        /// no v1 ciphertext should remain in the database. This method should not be
        /// called from any path other than DatabaseMigration.
        func decryptLegacy(data: Data?) throws -> Data? {
            guard
                let data,
                let key = try self.keyManager.createLocalEncryptionKey()
            else {
                return nil
            }

            let box = try AES.GCM.SealedBox(combined: data)
            return try AES.GCM.open(box, using: key)
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

        // MARK: - Signing (unchanged)

        func sign(data: Data?) -> String {
            do {
                let key = try Manager.Key().retrievePrivateKey()
                let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256

                var error: Unmanaged<CFError>?

                guard let key, let data else {
                    return "Key or data is missing"
                }

                guard SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
                    return "Algorithm is not supported"
                }

                guard
                    let signature = SecKeyCreateSignature(key, algorithm, data as CFData, &error) as Data?
                else {
                    return "Error creating signature: \(error!.takeRetainedValue() as Error)"
                }

                return signature.hexEncodedString()
            } catch {
                return "Signature could not be created, try again."
            }
        }
    }
}

// MARK: - Protocol

protocol CryptoProtocol {
    func encrypt(data: Data?) throws -> Data?
    func decrypt(data: Data?) throws -> Data?
    func decryptLegacy(data: Data?) throws -> Data?
    func encrypt(message: Data, using material: Data?) throws -> Data?
    func decrypt(message: Data, using material: Data?) throws -> Data?
    func sign(data: Data?) -> String
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
}

//
//  PIN+Manager.swift
//  Occulta
//
//  Pure crypto utility for PIN verifier construction and checking.
//  No SwiftData dependency, no state. Used internally by Manager.Security.
//

import Foundation
import CryptoKit
import CommonCrypto

extension Manager {
    final class PINManager {

        // MARK: - Constants

        static let pbkdf2Iterations = 600_000
        static let wrongPINLimit    = 3

        private static let sentinel = Data("SECURE_MODE_VERIFIED_2026".utf8)

        // MARK: - Verifier construction

        /// Builds a two-layer sealed verifier: outer = AES-GCM(seKey), inner = AES-GCM(HKDF(PBKDF2(pin))).
        static func buildVerifier(pin: String, salt: Data, label: Data, seKey: SymmetricKey) throws -> Data {
            guard let pbkdf2Bytes = pbkdf2(pin: pin, salt: salt) else {
                throw PINError.keyDerivationFailed
            }
            let pinKey = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: pbkdf2Bytes),
                info:             label,
                outputByteCount:  32
            )
            guard let inner = try AES.GCM.seal(Self.sentinel, using: pinKey, nonce: AES.GCM.Nonce()).combined else {
                throw PINError.encryptionFailed
            }
            guard let outer = try AES.GCM.seal(inner, using: seKey, nonce: AES.GCM.Nonce()).combined else {
                throw PINError.encryptionFailed
            }
            return outer
        }

        // MARK: - Verifier checking

        /// Returns true if pin + seKey successfully open the verifier and the sentinel matches.
        static func checkVerifier(pin: String, salt: Data, label: Data, verifier: Data, seKey: SymmetricKey) -> Bool {
            guard
                let pbkdf2Bytes   = pbkdf2(pin: pin, salt: salt),
                let outerBox      = try? AES.GCM.SealedBox(combined: verifier),
                let innerCombined = try? AES.GCM.open(outerBox, using: seKey),
                let innerBox      = try? AES.GCM.SealedBox(combined: innerCombined)
            else { return false }

            let pinKey = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: pbkdf2Bytes),
                info:             label,
                outputByteCount:  32
            )
            guard let plaintext = try? AES.GCM.open(innerBox, using: pinKey) else { return false }
            return plaintext == Self.sentinel
        }

        // MARK: - PBKDF2

        static func pbkdf2(pin: String, salt: Data) -> Data? {
            guard let pinData = pin.data(using: .utf8) else { return nil }
            var derivedKey = [UInt8](repeating: 0, count: 32)
            let status: CCStatus = salt.withUnsafeBytes { saltPtr in
                pinData.withUnsafeBytes { pinPtr in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        pinPtr.baseAddress?.assumingMemoryBound(to: Int8.self),
                        pinData.count,
                        saltPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(Self.pbkdf2Iterations),
                        &derivedKey,
                        derivedKey.count
                    )
                }
            }
            return status == kCCSuccess ? Data(derivedKey) : nil
        }
    }
}

// MARK: - Result

enum PINVerifyResult: Equatable {
    case normal
    case duress
    case wrong
    case wipe
}

// MARK: - Errors

extension Manager.PINManager {
    enum PINError: Error {
        case keyDerivationFailed
        case encryptionFailed
    }
}

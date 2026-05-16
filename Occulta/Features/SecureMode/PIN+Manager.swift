//
//  PIN+Manager.swift
//  Occulta
//
//  Pure crypto utility for PIN verifier construction and checking.
//  No SwiftData dependency, no state. Used internally by Manager.Security.
//
//  Verifier = AES-GCM(HKDF(seKey, info: label ∥ pin), sentinel)
//  The SE key provides device binding; the PIN is bound via HKDF info.
//  Wrong PIN → wrong derived key → AES-GCM tag fails.
//

import Foundation
import CryptoKit

extension Manager {
    final class PINManager {

        // MARK: - Constants

        static let wrongPINLimit = 3

        private static let sentinel = Data("SECURE_MODE_VERIFIED_2026".utf8)

        // MARK: - Verifier construction

        /// Builds AES-GCM(HKDF(seKey, info: label ∥ pin), sentinel).
        static func buildVerifier(pin: String, label: Data, seKey: SymmetricKey) throws -> Data {
            let pinKey = try self.deriveKey(pin: pin, label: label, seKey: seKey)
            guard let sealed = try AES.GCM.seal(Self.sentinel, using: pinKey, nonce: AES.GCM.Nonce()).combined else {
                throw PINError.encryptionFailed
            }
            return sealed
        }

        // MARK: - Verifier checking

        /// Returns true if the verifier opens with the key derived from pin + seKey + label.
        static func checkVerifier(pin: String, label: Data, verifier: Data, seKey: SymmetricKey) -> Bool {
            guard
                let pinKey    = try? self.deriveKey(pin: pin, label: label, seKey: seKey),
                let box       = try? AES.GCM.SealedBox(combined: verifier),
                let plaintext = try? AES.GCM.open(box, using: pinKey)
            else { return false }
            return plaintext == Self.sentinel
        }

        // MARK: - Private

        private static func deriveKey(pin: String, label: Data, seKey: SymmetricKey) throws -> SymmetricKey {
            guard let pinData = pin.data(using: .utf8) else { throw PINError.keyDerivationFailed }
            var info = label
            info.append(pinData)
            return HKDF<SHA256>.deriveKey(inputKeyMaterial: seKey, info: info, outputByteCount: 32)
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

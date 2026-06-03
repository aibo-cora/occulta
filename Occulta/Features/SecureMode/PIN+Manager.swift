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

        /// Byte size of a verifier blob: nonce(12) + ciphertext(sentinel.count) + tag(16).
        /// Referenced by AppLayerConfig to generate indistinguishable random filler for
        /// the verifier arrays — filler must be identical in size to a real verifier.
        static let verifierSize: Int = 12 + sentinel.count + 16  // = 53

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
    /// PIN matched a normal verifier at the given depth. Depth 0 = real app; N > 0 = decoy layer N.
    case normal(depth: Int)
    /// PIN matched the duress verifier at `currentDepth` — push-down transition to the next depth.
    /// In the routing-alias design this result is only reached when no normal verifier exists yet
    /// for the next depth (i.e., the duress layer has not been activated). Kept for backward
    /// compatibility and for the single-layer cold-start path before routing aliases are written.
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

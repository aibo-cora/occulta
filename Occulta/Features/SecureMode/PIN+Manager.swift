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
//  Wrapped (Bug 171, Stage 3): that, sealed again under the wrap key, `enclaveBoundKey(.secureModeWrap)`. `seKey` is a
//  function of the PIN Enclave key's public point, so a holder of the config row and that point could test PIN guesses
//  against the 53-byte verifiers with no Enclave and no lockout counter; the wrap key needs `r_U` and the tier U record
//  as well. 53 → 81 bytes, no AAD, as the inner verifier has none.
//

import Foundation
import CryptoKit

extension Manager {
    final class PINManager {

        // MARK: - Constants

        private static let sentinel = Data("SECURE_MODE_VERIFIED_2026".utf8)

        /// Byte size of a plain verifier blob: nonce(12) + ciphertext(sentinel.count) + tag(16).
        static let plainVerifierSize: Int = 12 + sentinel.count + 16  // = 53

        /// A wrapped verifier is a plain one sealed again: nonce(12) + 53 + tag(16).
        static let wrappedVerifierSize: Int = 12 + plainVerifierSize + 16  // = 81

        /// Byte size of a verifier blob in this process (`Manager.Ambient.pinVerifiers`): what a new verifier is, and so
        /// what the random filler in the verifier arrays has to be. Referenced by AppLayerConfig — filler must be
        /// identical in size to a real verifier, and an array is never mixed.
        static var verifierSize: Int {
            Manager.Ambient.pinVerifiers == .wrapped ? Self.wrappedVerifierSize : Self.plainVerifierSize
        }

        // MARK: - Verifier construction

        /// Builds AES-GCM(HKDF(seKey, info: label ∥ pin), sentinel), and in a process whose verifiers are wrapped
        /// (`Manager.Ambient.pinVerifiers`) seals that under `wrapKey`. Never a plain verifier in a wrapped process, and
        /// never a wrapped one in a plain process: the arrays it ends up in stay one size.
        ///
        /// - Throws: `PINError.wrapKeyUnavailable` in a wrapped process with no `wrapKey`.
        static func buildVerifier(pin: String, label: Data, seKey: SymmetricKey, wrapKey: SymmetricKey?) throws -> Data {
            let pinKey = try self.deriveKey(pin: pin, label: label, seKey: seKey)
            guard let plain = try AES.GCM.seal(Self.sentinel, using: pinKey, nonce: AES.GCM.Nonce()).combined else {
                throw PINError.encryptionFailed
            }
            guard Manager.Ambient.pinVerifiers == .wrapped else { return plain }

            guard let wrapKey else { throw PINError.wrapKeyUnavailable }
            guard let wrapped = try AES.GCM.seal(plain, using: wrapKey, nonce: AES.GCM.Nonce()).combined else {
                throw PINError.encryptionFailed
            }
            return wrapped
        }

        // MARK: - Verifier checking

        /// Returns true if the verifier opens with the key derived from pin + seKey + label. Accepts both sizes: an
        /// 81-byte verifier is opened under `wrapKey` first and the 53 bytes inside checked as ever; a 53-byte one is
        /// checked as ever. Anything else, and an 81-byte one with no `wrapKey` or one that doesn't open, is false.
        ///
        /// The work is the same whether or not a slot unwraps: a slot of random filler gets the inner check on stand-in
        /// bytes. Otherwise how long a scan takes would count the slots that hold a real verifier.
        static func checkVerifier(pin: String, label: Data, verifier: Data, seKey: SymmetricKey, wrapKey: SymmetricKey?) -> Bool {
            let inner: Data
            switch verifier.count {
            case Self.plainVerifierSize:
                inner = verifier
            case Self.wrappedVerifierSize:
                guard let wrapKey else { return false }
                inner = Self.unwrapped(verifier, using: wrapKey) ?? Data(count: Self.plainVerifierSize)
            default:
                return false
            }

            guard
                let pinKey    = try? self.deriveKey(pin: pin, label: label, seKey: seKey),
                let box       = try? AES.GCM.SealedBox(combined: inner),
                let plaintext = try? AES.GCM.open(box, using: pinKey)
            else { return false }
            return plaintext == Self.sentinel
        }

        /// The 53 bytes inside a wrapped verifier, or nil if it doesn't open under `wrapKey`.
        private static func unwrapped(_ verifier: Data, using wrapKey: SymmetricKey) -> Data? {
            guard let box = try? AES.GCM.SealedBox(combined: verifier) else { return nil }
            return try? AES.GCM.open(box, using: wrapKey)
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
    /// Too many consecutive wrong attempts. No verification was performed; try again after `until`.
    case locked(until: Date)
}

// MARK: - Errors

extension Manager.PINManager {
    enum PINError: Error {
        case keyDerivationFailed
        case encryptionFailed
        /// A wrapped process was asked for a verifier and has no wrap key.
        case wrapKeyUnavailable
    }
}

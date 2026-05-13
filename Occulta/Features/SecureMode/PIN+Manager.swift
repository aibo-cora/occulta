//
//  PIN+Manager.swift
//  Occulta
//

import Foundation
import CryptoKit
import CommonCrypto
import SwiftData

extension Manager {
    final class PINManager {

        // MARK: - Constants

        /// Fixed sentinel value encrypted inside each verifier.
        /// Not secret — security comes from AES-GCM tag validation.
        private static let sentinel    = Data("SECURE_MODE_VERIFIED_2026".utf8)
        private static let normalLabel = Data("secure-mode-normal-pin-2026".utf8)
        private static let duressLabel = Data("secure-mode-duress-pin-2026".utf8)

        static let pbkdf2Iterations = 600_000
        static let wrongPINLimit    = 3

        // MARK: - Dependencies

        private let keyManager: any KeyManagerProtocol

        // MARK: - In-memory counters (never persisted)

        private(set) var wrongPINCount          = 0
        private(set) var consecutiveDuressCount = 0

        // MARK: - Init

        init(keyManager: any KeyManagerProtocol = Manager.Key()) {
            self.keyManager = keyManager
        }

        // MARK: - Configure

        /// Build and persist PIN sentinels for a new Secure Mode configuration.
        ///
        /// Replaces any existing config. Counters are reset.
        func configure(
            normalPIN: String,
            duressPIN: String,
            wipeThreshold: Int,
            in context: ModelContext
        ) throws {
            guard let seKey = try keyManager.deriveSecureModeKey() else {
                throw PINError.keyDerivationFailed
            }

            var saltBytes = [UInt8](repeating: 0, count: 32)
            guard SecRandomCopyBytes(kSecRandomDefault, 32, &saltBytes) == errSecSuccess else {
                throw PINError.randomGenerationFailed
            }
            let salt = Data(saltBytes)

            let sealedNormal = try buildSealedVerifier(pin: normalPIN, salt: salt, label: Self.normalLabel, seKey: seKey)
            let sealedDuress = try buildSealedVerifier(pin: duressPIN, salt: salt, label: Self.duressLabel, seKey: seKey)

            let existing = try context.fetch(FetchDescriptor<SecureModeConfig>())
            for config in existing { context.delete(config) }

            context.insert(SecureModeConfig(
                sealedNormalVerifier: sealedNormal,
                sealedDuressVerifier: sealedDuress,
                salt:                 salt,
                wipeThreshold:        wipeThreshold
            ))
            try context.save()

            wrongPINCount          = 0
            consecutiveDuressCount = 0
        }

        // MARK: - Verify

        /// Verify an entered PIN and update counters.
        ///
        /// - Returns:
        ///   - `.normal`  — correct normal PIN; both counters reset.
        ///   - `.duress`  — correct duress PIN; wrong counter reset, duress counter incremented.
        ///   - `.wrong`   — unrecognised PIN; duress counter reset, wrong counter incremented.
        ///   - `.wipe`    — threshold crossed (3 wrong or N consecutive duress); caller must wipe.
        func verify(_ pin: String, in context: ModelContext) throws -> PINVerifyResult {
            guard let config = try context.fetch(FetchDescriptor<SecureModeConfig>()).first else {
                throw PINError.notConfigured
            }
            guard let seKey = try keyManager.deriveSecureModeKey() else {
                throw PINError.keyDerivationFailed
            }

            if verifySentinel(pin: pin, salt: config.salt, label: Self.normalLabel,
                              sealedVerifier: config.sealedNormalVerifier, seKey: seKey) {
                wrongPINCount          = 0
                consecutiveDuressCount = 0
                return .normal
            }

            if verifySentinel(pin: pin, salt: config.salt, label: Self.duressLabel,
                              sealedVerifier: config.sealedDuressVerifier, seKey: seKey) {
                wrongPINCount           = 0
                consecutiveDuressCount += 1
                return consecutiveDuressCount >= config.wipeThreshold ? .wipe : .duress
            }

            consecutiveDuressCount  = 0
            wrongPINCount          += 1
            return wrongPINCount >= Self.wrongPINLimit ? .wipe : .wrong
        }

        // MARK: - Private

        private func buildSealedVerifier(pin: String, salt: Data, label: Data, seKey: SymmetricKey) throws -> Data {
            guard let pbkdf2Bytes = pbkdf2(pin: pin, salt: salt) else { throw PINError.keyDerivationFailed }
            let pinKey = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: pbkdf2Bytes),
                info: label,
                outputByteCount: 32
            )
            guard let innerCombined = try AES.GCM.seal(Self.sentinel, using: pinKey, nonce: AES.GCM.Nonce()).combined else {
                throw PINError.encryptionFailed
            }
            guard let outerCombined = try AES.GCM.seal(innerCombined, using: seKey, nonce: AES.GCM.Nonce()).combined else {
                throw PINError.encryptionFailed
            }
            return outerCombined
        }

        private func verifySentinel(pin: String, salt: Data, label: Data, sealedVerifier: Data, seKey: SymmetricKey) -> Bool {
            guard
                let pbkdf2Bytes   = pbkdf2(pin: pin, salt: salt),
                let outerBox      = try? AES.GCM.SealedBox(combined: sealedVerifier),
                let innerCombined = try? AES.GCM.open(outerBox, using: seKey),
                let innerBox      = try? AES.GCM.SealedBox(combined: innerCombined)
            else { return false }

            let pinKey = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: pbkdf2Bytes),
                info: label,
                outputByteCount: 32
            )
            guard let plaintext = try? AES.GCM.open(innerBox, using: pinKey) else { return false }
            return plaintext == Self.sentinel
        }

        private func pbkdf2(pin: String, salt: Data) -> Data? {
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

// MARK: - PINVerifyResult

enum PINVerifyResult: Equatable {
    case normal
    case duress
    case wrong
    case wipe
}

// MARK: - Errors

extension Manager.PINManager {
    enum PINError: Error {
        case notConfigured
        case keyDerivationFailed
        case randomGenerationFailed
        case encryptionFailed
    }
}

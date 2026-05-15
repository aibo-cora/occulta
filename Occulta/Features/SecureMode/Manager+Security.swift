//
//  Manager+Security.swift
//  Occulta
//
//  Single umbrella for all app-security hardening.
//  Owns the SecureModeConfig SwiftData row, PIN verification, and the
//  Secure Mode state machine. Replaces the former SecureModeManager +
//  Manager.PINManager public API.
//

import Foundation
import SwiftData
import Security

extension Manager {
    @Observable
    final class Security {

        // MARK: - State

        enum State {
            case noPIN      // no PIN configured; app opens directly
            case pinOnly    // PIN set, Secure Mode not activated
            case active     // Secure Mode active; full data visible
            case duress     // duress PIN entered; decoy view active
        }

        private(set) var state: State

        var requiresPIN:    Bool { self.state != .noPIN  }
        var isDuressActive: Bool { self.state == .duress }

        // MARK: - Private

        private let modelContext: ModelContext
        private let keyManager:   any KeyManagerProtocol

        private var wrongPINCount          = 0
        private var consecutiveDuressCount = 0

        private static let normalLabel = Data("secure-mode-normal-pin-2026".utf8)
        private static let duressLabel = Data("secure-mode-duress-pin-2026".utf8)

        // MARK: - Init

        init(modelContainer: ModelContainer, keyManager: any KeyManagerProtocol = Manager.Key()) {
            let context       = ModelContext(modelContainer)
            self.modelContext = context
            self.keyManager   = keyManager

            let config = try? context.fetch(FetchDescriptor<SecureModeConfig>()).first
            if config?.isSecureModeActivated == true {
                self.state = .active
            } else if config?.isPINEnabled == true {
                self.state = .pinOnly
            } else {
                self.state = .noPIN
            }
        }

        // MARK: - PIN Setup

        /// Builds a normal PIN verifier, persists config, and transitions .noPIN → .pinOnly.
        func configurePIN(_ pin: String) throws {
            guard let seKey = try self.keyManager.deriveSecureModeKey() else {
                throw SecurityError.keyDerivationFailed
            }
            var saltBytes = [UInt8](repeating: 0, count: 32)
            guard SecRandomCopyBytes(kSecRandomDefault, 32, &saltBytes) == errSecSuccess else {
                throw SecurityError.randomGenerationFailed
            }
            let salt         = Data(saltBytes)
            let sealedNormal = try PINManager.buildVerifier(pin: pin, salt: salt, label: Self.normalLabel, seKey: seKey)

            let existing = try self.modelContext.fetch(FetchDescriptor<SecureModeConfig>())
            for c in existing { self.modelContext.delete(c) }
            self.modelContext.insert(SecureModeConfig(sealedNormalVerifier: sealedNormal, salt: salt))
            try self.modelContext.save()

            self.resetCounters()
            self.state = .pinOnly
        }

        /// Verifies the normal PIN, removes config, and transitions .pinOnly → .noPIN.
        /// Throws .invalidStateTransition if not in .pinOnly — caller must deactivate Secure Mode first.
        func deactivatePIN(confirmingNormalPIN: String) throws {
            guard self.state == .pinOnly else { throw SecurityError.invalidStateTransition }
            let config = try self.requireConfig()
            guard let seKey = try self.keyManager.deriveSecureModeKey() else {
                throw SecurityError.keyDerivationFailed
            }
            guard PINManager.checkVerifier(pin: confirmingNormalPIN, salt: config.salt,
                                           label: Self.normalLabel, verifier: config.sealedNormalVerifier,
                                           seKey: seKey) else {
                throw SecurityError.incorrectPIN
            }
            self.modelContext.delete(config)
            try self.modelContext.save()
            self.resetCounters()
            self.state = .noPIN
        }

        // MARK: - Secure Mode

        /// Phase 1: verify existing normal PIN.
        /// Phase 2: build duress verifier, persist, transition .pinOnly → .active.
        /// Key rotation (blob, Step 4) is a placeholder — added in Step 4.
        func activateSecureMode(confirmingNormalPIN: String, duressPIN: String) throws {
            guard self.state == .pinOnly else { throw SecurityError.invalidStateTransition }
            let config = try self.requireConfig()
            guard let seKey = try self.keyManager.deriveSecureModeKey() else {
                throw SecurityError.keyDerivationFailed
            }
            guard PINManager.checkVerifier(pin: confirmingNormalPIN, salt: config.salt,
                                           label: Self.normalLabel, verifier: config.sealedNormalVerifier,
                                           seKey: seKey) else {
                throw SecurityError.incorrectPIN
            }
            config.sealedDuressVerifier  = try PINManager.buildVerifier(pin: duressPIN, salt: config.salt,
                                                                         label: Self.duressLabel, seKey: seKey)
            config.isSecureModeActivated = true
            try self.modelContext.save()

            // TODO: key rotation (Step 4)

            self.resetCounters()
            self.state = .active
        }

        /// Verifies the normal PIN, removes duress verifier, and transitions .active/.duress → .pinOnly.
        /// Blob unwind (Step 4) is a placeholder — added in Step 4.
        func deactivateSecureMode(confirmingNormalPIN: String) throws {
            guard self.state == .active || self.state == .duress else {
                throw SecurityError.invalidStateTransition
            }
            let config = try self.requireConfig()
            guard let seKey = try self.keyManager.deriveSecureModeKey() else {
                throw SecurityError.keyDerivationFailed
            }
            guard PINManager.checkVerifier(pin: confirmingNormalPIN, salt: config.salt,
                                           label: Self.normalLabel, verifier: config.sealedNormalVerifier,
                                           seKey: seKey) else {
                throw SecurityError.incorrectPIN
            }

            // TODO: blob unwind (Step 4)

            config.sealedDuressVerifier  = nil
            config.isSecureModeActivated = false
            try self.modelContext.save()
            self.resetCounters()
            self.state = .pinOnly
        }

        // MARK: - Verify

        /// Verifies a PIN entry and drives all state transitions.
        ///
        /// - `.noPIN`   — throws `.notConfigured` (PINEntry must not appear in this state)
        /// - `.pinOnly` — correct normal PIN → `.normal`; wrong → `.wrong`; no wipe threshold
        /// - `.active`  — normal → `.normal`; duress → `.duress` + state transition;
        ///                wrong ×3 → `.wipe`; N consecutive duress → `.wipe`
        /// - `.duress`  — normal → `.normal` + unwind to `.active`; duress → `.duress` (counter++);
        ///                wrong → `.wrong` + resets duress counter
        func verify(_ pin: String) throws -> PINVerifyResult {
            guard self.state != .noPIN else { throw SecurityError.notConfigured }
            let config = try self.requireConfig()
            guard let seKey = try self.keyManager.deriveSecureModeKey() else {
                throw SecurityError.keyDerivationFailed
            }

            if PINManager.checkVerifier(pin: pin, salt: config.salt, label: Self.normalLabel,
                                        verifier: config.sealedNormalVerifier, seKey: seKey) {
                if self.state == .duress { self.state = .active }
                self.resetCounters()
                return .normal
            }

            if let duressVerifier = config.sealedDuressVerifier,
               (self.state == .active || self.state == .duress),
               PINManager.checkVerifier(pin: pin, salt: config.salt, label: Self.duressLabel,
                                        verifier: duressVerifier, seKey: seKey) {
                self.wrongPINCount          = 0
                self.consecutiveDuressCount += 1
                self.state = .duress
                return self.consecutiveDuressCount >= config.wipeThreshold ? .wipe : .duress
            }

            self.consecutiveDuressCount  = 0
            self.wrongPINCount          += 1

            if (self.state == .active || self.state == .duress),
               self.wrongPINCount >= PINManager.wrongPINLimit {
                return .wipe
            }
            return .wrong
        }

        // MARK: - Safe contacts

        func isSafeContact(_ identifier: String) -> Bool {
            guard let config = try? self.modelContext.fetch(FetchDescriptor<SecureModeConfig>()).first else {
                return false
            }
            return config.isSafeContact(identifier)
        }

        func safeContactIDs() -> Set<String> {
            guard
                let config    = try? self.modelContext.fetch(FetchDescriptor<SecureModeConfig>()).first,
                let encrypted = config.safeContactIDsEncrypted,
                let decrypted = encrypted.decrypt(),
                let ids       = try? JSONDecoder().decode([String].self, from: decrypted)
            else { return [] }
            return Set(ids)
        }

        func updateSafeContacts(_ ids: Set<String>) throws {
            let config = try self.requireConfig()
            try config.updateSafeContacts(ids)
            try self.modelContext.save()
        }

        // MARK: - Private

        private func requireConfig() throws -> SecureModeConfig {
            guard let config = try self.modelContext.fetch(FetchDescriptor<SecureModeConfig>()).first else {
                throw SecurityError.notConfigured
            }
            return config
        }

        private func resetCounters() {
            self.wrongPINCount          = 0
            self.consecutiveDuressCount = 0
        }
    }
}

// MARK: - Errors

extension Manager.Security {
    enum SecurityError: Error {
        case notConfigured
        case keyDerivationFailed
        case randomGenerationFailed
        case incorrectPIN
        case invalidStateTransition
    }
}

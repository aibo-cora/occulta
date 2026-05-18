//
//  Manager+Security.swift
//  Occulta
//
//  Single umbrella for all app-security hardening.
//  Owns the AppLayerConfig SwiftData row, PIN verification, and the
//  Secure Mode state machine. Replaces the former SecureModeManager +
//  Manager.PINManager public API.
//

import Foundation
import SwiftData

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

            let config = try? context.fetch(FetchDescriptor<AppLayerConfig>()).first
            
            if config?.sealedDuressVerifier != nil {
                self.state = .active
            } else if config?.sealedNormalVerifier != nil {
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
            let sealedNormal = try PINManager.buildVerifier(pin: pin, label: Self.normalLabel, seKey: seKey)

            let existing = try self.modelContext.fetch(FetchDescriptor<AppLayerConfig>())
            for c in existing { self.modelContext.delete(c) }

            let config = AppLayerConfig()
            config.sealedNormalVerifier = sealedNormal
            try config.setWipeThreshold(3)
            self.modelContext.insert(config)
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
            guard
                let verifier = config.sealedNormalVerifier,
                PINManager.checkVerifier(pin: confirmingNormalPIN, label: Self.normalLabel,
                                         verifier: verifier, seKey: seKey)
            else { throw SecurityError.incorrectPIN }

            self.modelContext.delete(config)
            try self.modelContext.save()
            self.resetCounters()
            self.state = .noPIN
        }

        // MARK: - Secure Mode

        /// Phase 1: verify existing normal PIN.
        /// Phase 2: build duress verifier, persist, transition .pinOnly → .active.
        func activateSecureMode(confirmingNormalPIN: String, duressPIN: String) throws {
            guard self.state == .pinOnly else { throw SecurityError.invalidStateTransition }
            let config = try self.requireConfig()
            guard let seKey = try self.keyManager.deriveSecureModeKey() else {
                throw SecurityError.keyDerivationFailed
            }
            guard
                let verifier = config.sealedNormalVerifier,
                PINManager.checkVerifier(pin: confirmingNormalPIN, label: Self.normalLabel,
                                         verifier: verifier, seKey: seKey)
            else { throw SecurityError.incorrectPIN }

            guard !PINManager.checkVerifier(pin: duressPIN, label: Self.normalLabel,
                                            verifier: verifier, seKey: seKey)
            else { throw SecurityError.pinCollision }

            config.sealedDuressVerifier = try PINManager.buildVerifier(pin: duressPIN,
                                                                        label: Self.duressLabel,
                                                                        seKey: seKey)
            try self.modelContext.save()

            // TODO: key rotation (Step 4)

            self.resetCounters()
            self.state = .active
        }

        /// Verifies the normal PIN, removes duress verifier, and transitions .active/.duress → .pinOnly.
        func deactivateSecureMode(confirmingNormalPIN: String) throws {
            guard self.state == .active || self.state == .duress else {
                throw SecurityError.invalidStateTransition
            }
            let config = try self.requireConfig()
            guard let seKey = try self.keyManager.deriveSecureModeKey() else {
                throw SecurityError.keyDerivationFailed
            }
            guard
                let verifier = config.sealedNormalVerifier,
                PINManager.checkVerifier(pin: confirmingNormalPIN, label: Self.normalLabel,
                                         verifier: verifier, seKey: seKey)
            else { throw SecurityError.incorrectPIN }

            // TODO: blob unwind (Step 4)

            config.sealedDuressVerifier = nil
            try self.modelContext.save()
            self.resetCounters()
            self.state = .pinOnly
        }

        // MARK: - Verify

        /// Verifies a PIN entry and drives all state transitions.
        func verify(_ pin: String) throws -> PINVerifyResult {
            guard self.state != .noPIN else { throw SecurityError.notConfigured }
            let config = try self.requireConfig()
            guard let seKey = try self.keyManager.deriveSecureModeKey() else {
                throw SecurityError.keyDerivationFailed
            }

            if let verifier = config.sealedNormalVerifier,
               PINManager.checkVerifier(pin: pin, label: Self.normalLabel,
                                        verifier: verifier, seKey: seKey) {
                if self.state == .duress { self.state = .active }
                self.resetCounters()
                return .normal
            }

            if let duressVerifier = config.sealedDuressVerifier,
               (self.state == .active || self.state == .duress),
               PINManager.checkVerifier(pin: pin, label: Self.duressLabel,
                                        verifier: duressVerifier, seKey: seKey) {
                self.wrongPINCount          = 0
                self.consecutiveDuressCount += 1
                self.state = .duress
                return self.consecutiveDuressCount >= config.wipeThreshold() ? .wipe : .duress
            }

            self.consecutiveDuressCount  = 0
            self.wrongPINCount          += 1

            if (self.state == .active || self.state == .duress),
               self.wrongPINCount >= PINManager.wrongPINLimit {
                return .wipe
            }
            return .wrong
        }

        // MARK: - PIN check (no side effects)

        /// Returns true if pin matches the current normal verifier without modifying any counters.
        /// Use this for Settings-level confirmation — not the lock-screen path.
        func checkNormalPIN(_ pin: String) -> Bool {
            guard
                let config   = try? self.modelContext.fetch(FetchDescriptor<AppLayerConfig>()).first,
                let verifier = config.sealedNormalVerifier,
                let seKey    = try? self.keyManager.deriveSecureModeKey()
            else { return false }
            return PINManager.checkVerifier(pin: pin, label: Self.normalLabel,
                                            verifier: verifier, seKey: seKey)
        }

        // MARK: - Safe contacts

        /// Returns true if the contact is visible at duress depth 1.
        /// Unknown contacts (not in DB) return false — conservative default.
        func isSafeContact(_ identifier: String) -> Bool {
            let descriptor = FetchDescriptor<Contact.Profile>(
                predicate: #Predicate { $0.identifier == identifier && $0.deletionToken == nil }
            )
            guard let contact = try? self.modelContext.fetch(descriptor).first else { return false }
            return Self.isVisible(contact, atDepth: 1)
        }

        /// Returns identifiers of contacts visible at duress depth 1.
        func safeContactIDs() -> Set<String> {
            guard let contacts = try? self.modelContext.fetch(Contact.Profile.descriptor) else { return [] }
            return Set(contacts.compactMap { Self.isVisible($0, atDepth: 1) ? $0.identifier : nil })
        }

        /// Marks contacts in `ids` as always visible (nil) and all others as hidden (depth 0).
        func updateSafeContacts(_ ids: Set<String>) throws {
            let contacts = try self.modelContext.fetch(Contact.Profile.descriptor)
            for contact in contacts {
                if ids.contains(contact.identifier) {
                    contact.visibleThroughDepth = nil
                } else {
                    contact.visibleThroughDepth = try JSONEncoder().encode(0).encrypt()
                }
            }
            try self.modelContext.save()
        }

        /// Returns true if the contact is explicitly marked sensitive (depth 0).
        /// Does not infer from unknown contacts — only reads the stored field.
        func isSensitive(_ identifier: String) -> Bool {
            let descriptor = FetchDescriptor<Contact.Profile>(
                predicate: #Predicate { $0.identifier == identifier && $0.deletionToken == nil }
            )
            guard let contact = try? self.modelContext.fetch(descriptor).first,
                  let data = contact.visibleThroughDepth,
                  let decrypted = data.decrypt(),
                  let value = try? JSONDecoder().decode(Int.self, from: decrypted)
            else { return false }
            return value == 0
        }

        /// Sets a single contact's visibility without touching any other contact records.
        func setVisibility(for identifier: String, isSensitive: Bool) throws {
            let descriptor = FetchDescriptor<Contact.Profile>(
                predicate: #Predicate { $0.identifier == identifier && $0.deletionToken == nil }
            )
            guard let contact = try? self.modelContext.fetch(descriptor).first else { return }
            contact.visibleThroughDepth = isSensitive ? try JSONEncoder().encode(0).encrypt() : nil
            try self.modelContext.save()
        }

        private static func isVisible(_ contact: Contact.Profile, atDepth depth: Int) -> Bool {
            guard let data = contact.visibleThroughDepth else { return true }
            guard let decrypted = data.decrypt(),
                  let value = try? JSONDecoder().decode(Int.self, from: decrypted)
            else { return true }
            return value >= depth
        }

        // MARK: - Private

        private func requireConfig() throws -> AppLayerConfig {
            guard let config = try self.modelContext.fetch(FetchDescriptor<AppLayerConfig>()).first else {
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
        case pinCollision
    }
}

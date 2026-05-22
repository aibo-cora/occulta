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
        private(set) var currentDepth: Int = 0

        var requiresPIN:  Bool { self.state != .noPIN }
        var isRestricted: Bool { self.currentDepth > 0 }

        /// Date of the most recent successful PIN verification. In-memory only — nil after kill.
        /// Used by `OccultaApp` to skip the PIN prompt within the grace period.
        private(set) var lastUnlockDate: Date? = nil

        /// Whether the PIN overlay gate is currently enabled.
        ///
        /// When `false`, the app opens without showing the PIN prompt even though all PIN
        /// verifiers remain intact. This happens when the user explicitly lowers the gate
        /// via `disablePINFromCurrentDepth(confirmingPIN:)` — typically under coercion
        /// while in `.active` or `.duress` state — so that the Settings toggle shows no
        /// observable difference from a device with no PIN configured.
        ///
        /// Critically, depth-filtering still applies when the gate is down: contacts and vault
        /// entries whose `visibleThroughDepth` is set remain hidden at the stored depth,
        /// regardless of whether the PIN overlay fires on scene activation.
        ///
        /// Persisted across app kills via `AppLayerConfig.persistedDepth` (signed-Int encoding
        /// in `readLockGate` / `writeLockGate`). Restored in `init` from the same field.
        /// Always `true` for fresh configs and after any clean state transition.
        private(set) var appLockEnabled: Bool = true

        /// Record a successful authentication. Call from `PINEntry.onNormal` and `onDuress`.
        func recordUnlock() {
            self.lastUnlockDate = Date()
        }

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

            // Determine base state from which verifiers are present.
            if config?.sealedDuressVerifier != nil {
                self.state = .active
            } else if config?.sealedNormalVerifier != nil {
                self.state = .pinOnly
            } else {
                self.state = .noPIN
            }

            // Restore the persisted depth and gate-active flag so depth-filtering
            // and the PIN overlay behave correctly after an app kill or restart.
            // `readLockGate` falls back to (0, true) on any decode failure, so
            // a corrupted or absent field always results in the safe default.
            let (depth, gateActive) = config?.readLockGate() ?? (0, true)
            self.currentDepth   = depth
            self.appLockEnabled = gateActive

            // If the app was killed while at depth 1 (duress verifier present and
            // depth > 0), re-enter .duress immediately so depth-filtering applies
            // before any UI renders — no PIN re-entry required for the depth itself;
            // the overlay gate handles authentication separately.
            if depth > 0 && self.state == .active {
                self.state = .duress
            }
        }

        // MARK: - PIN Setup

        /// Builds a normal PIN verifier, persists config, and transitions `.noPIN` → `.pinOnly`.
        ///
        /// Also initialises `persistedDepth` to `encrypt(0)` (gate active at depth 0) so the
        /// field is always non-nil from the first config write onward. This prevents forensic
        /// tools from inferring special state from field presence or absence.
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
            try config.writeLockGate(depth: 0, gateActive: true)
            self.modelContext.insert(config)
            try self.modelContext.save()

            self.resetCounters()
            self.appLockEnabled = true
            self.state = .pinOnly
        }

        /// Verifies the normal PIN, removes the entire config row, and transitions `.pinOnly` → `.noPIN`.
        ///
        /// Throws `.invalidStateTransition` if not in `.pinOnly` — the caller must
        /// deactivate Secure Mode (removing the duress verifier) before removing the PIN entirely.
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
            self.appLockEnabled = true
            self.state = .noPIN
        }

        // MARK: - Secure Mode

        /// Activates Secure Mode in two phases: verify the existing normal PIN, then
        /// build the duress verifier and transition `.pinOnly` → `.active`.
        ///
        /// Also resets `persistedDepth` to gate-active at depth 0 so a prior coercion-
        /// lowered gate is automatically restored when Secure Mode is (re-)activated.
        func activateSecureMode(confirmingEntryPIN: String, duressPIN: String) throws {
            guard self.state == .pinOnly else { throw SecurityError.invalidStateTransition }
            let config = try self.requireConfig()
            guard let seKey = try self.keyManager.deriveSecureModeKey() else {
                throw SecurityError.keyDerivationFailed
            }
            guard
                let verifier = config.sealedNormalVerifier,
                PINManager.checkVerifier(pin: confirmingEntryPIN, label: Self.normalLabel,
                                         verifier: verifier, seKey: seKey)
            else { throw SecurityError.incorrectPIN }

            guard !PINManager.checkVerifier(pin: duressPIN, label: Self.normalLabel,
                                            verifier: verifier, seKey: seKey)
            else { throw SecurityError.pinCollision }

            config.sealedDuressVerifier = try PINManager.buildVerifier(pin: duressPIN,
                                                                        label: Self.duressLabel,
                                                                        seKey: seKey)
            try config.writeLockGate(depth: 0, gateActive: true)
            try self.modelContext.save()

            // TODO: key rotation (Step 4)

            self.resetCounters()
            self.appLockEnabled = true
            self.state = .active
        }

        /// Verifies the normal PIN, removes the duress verifier, and transitions
        /// `.active` / `.duress` → `.pinOnly`.
        ///
        /// Also resets `persistedDepth` to gate-active at depth 0 so the overlay
        /// is guaranteed active after deactivation, regardless of any prior coercion state.
        func deactivateSecureMode(confirmingEntryPIN: String) throws {
            guard self.state == .active || self.state == .duress else {
                throw SecurityError.invalidStateTransition
            }
            let config = try self.requireConfig()
            guard let seKey = try self.keyManager.deriveSecureModeKey() else {
                throw SecurityError.keyDerivationFailed
            }
            guard
                let verifier = config.sealedNormalVerifier,
                PINManager.checkVerifier(pin: confirmingEntryPIN, label: Self.normalLabel,
                                         verifier: verifier, seKey: seKey)
            else { throw SecurityError.incorrectPIN }

            // TODO: blob unwind (Step 4)

            config.sealedDuressVerifier = nil
            try config.writeLockGate(depth: 0, gateActive: true)
            try self.modelContext.save()
            self.resetCounters()
            self.currentDepth   = 0
            self.appLockEnabled = true
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
                self.currentDepth = 0
                self.resetCounters()
                return .normal
            }

            if let duressVerifier = config.sealedDuressVerifier,
               (self.state == .active || self.state == .duress),
               PINManager.checkVerifier(pin: pin, label: Self.duressLabel,
                                        verifier: duressVerifier, seKey: seKey) {
                self.wrongPINCount          = 0
                self.consecutiveDuressCount += 1
                self.currentDepth           = 1
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

        // MARK: - Coercion-resistant gate

        /// Lowers the PIN overlay gate while keeping all verifiers and depth-filtering intact.
        ///
        /// After this call:
        /// - `appLockEnabled` is `false` — the app opens without showing the PIN overlay.
        /// - `currentDepth` is unchanged — depth-1 filtering (hidden contacts and vault entries)
        ///   continues to apply, so a coerced device still shows the duress view.
        /// - All PIN verifiers are intact — the user can call `reEnablePIN(_:)` to restore the
        ///   gate without entering the setup flow again.
        ///
        /// The confirming PIN must match the verifier for the **current layer**:
        /// `sealedDuressVerifier` in `.duress` state, `sealedNormalVerifier` in `.active`.
        /// This ensures a coercer at depth 1 cannot lower the gate using a PIN they don't know.
        ///
        /// - Parameter confirmingPIN: Must match the current layer's verifier.
        /// - Throws: `SecurityError.invalidStateTransition` if not in `.active` or `.duress`.
        ///           `SecurityError.incorrectPIN` if the confirming PIN does not match.
        func disablePINFromCurrentDepth(confirmingPIN: String) throws {
            guard self.state == .active || self.state == .duress else {
                throw SecurityError.invalidStateTransition
            }
            guard self.checkCurrentLayerEntryPIN(confirmingPIN) else {
                throw SecurityError.incorrectPIN
            }
            let config = try self.requireConfig()
            try config.writeLockGate(depth: self.currentDepth, gateActive: false)
            try self.modelContext.save()
            self.appLockEnabled = false
        }

        /// Re-enables the PIN gate after it was lowered by `disablePINFromCurrentDepth`.
        ///
        /// The entered PIN is silently checked against all existing verifiers. No new verifier
        /// is created. The Settings UI uses `.setup` mode (enter + confirm) for this call,
        /// making the re-enable flow visually identical to initial PIN setup — no tell.
        ///
        /// - **Normal PIN match** → gate re-enabled at depth 0. `state` transitions to `.active`,
        ///   `currentDepth` resets to 0. The user returns to the real layer.
        /// - **Duress PIN match** → gate re-enabled at depth 1. `state` transitions to `.duress`,
        ///   `currentDepth` set to 1. The device continues showing the duress view.
        /// - **No match** → returns `false`; caller shows wrong-PIN feedback and allows retry.
        ///
        /// Returns a Bool rather than throwing so callers can stay in the `.setup` sheet and
        /// show feedback without catching errors through a multi-layer sheet hierarchy.
        ///
        /// - Parameter pin: The digit string entered and confirmed by the user.
        /// - Returns: `true` if a verifier matched and the gate was re-enabled; `false` otherwise.
        @discardableResult
        func reEnablePIN(_ pin: String) -> Bool {
            guard
                let config = try? self.modelContext.fetch(FetchDescriptor<AppLayerConfig>()).first,
                let seKey  = try? self.keyManager.deriveSecureModeKey()
            else { return false }

            // Normal PIN — restore to depth 0 (real layer).
            if let verifier = config.sealedNormalVerifier,
               PINManager.checkVerifier(pin: pin, label: Self.normalLabel, verifier: verifier, seKey: seKey) {
                try? config.writeLockGate(depth: 0, gateActive: true)
                try? self.modelContext.save()
                self.currentDepth   = 0
                self.state          = .active
                self.appLockEnabled = true
                return true
            }

            // Duress PIN — re-enable gate at depth 1 (duress layer stays active).
            if let verifier = config.sealedDuressVerifier,
               PINManager.checkVerifier(pin: pin, label: Self.duressLabel, verifier: verifier, seKey: seKey) {
                try? config.writeLockGate(depth: 1, gateActive: true)
                try? self.modelContext.save()
                self.currentDepth   = 1
                self.state          = .duress
                self.appLockEnabled = true
                return true
            }

            return false
        }

        /// Checks the entered PIN against the verifier for the **current layer**, with no side effects.
        ///
        /// In `.duress` state the check is against `sealedDuressVerifier`; in all other states
        /// (`.active`, `.pinOnly`) it is against `sealedNormalVerifier`. No counters are mutated
        /// and no state transitions occur — this is a read-only guard used exclusively by
        /// `disablePINFromCurrentDepth` to confirm the user's identity at the correct layer.
        private func checkCurrentLayerEntryPIN(_ pin: String) -> Bool {
            guard
                let config = try? self.modelContext.fetch(FetchDescriptor<AppLayerConfig>()).first,
                let seKey  = try? self.keyManager.deriveSecureModeKey()
            else { return false }
            switch self.state {
            case .duress:
                guard let verifier = config.sealedDuressVerifier else { return false }
                return PINManager.checkVerifier(pin: pin, label: Self.duressLabel,
                                                verifier: verifier, seKey: seKey)
            default:
                guard let verifier = config.sealedNormalVerifier else { return false }
                return PINManager.checkVerifier(pin: pin, label: Self.normalLabel,
                                                verifier: verifier, seKey: seKey)
            }
        }

        // MARK: - Safe contacts

        /// Returns true if the contact is visible at duress depth 1.
        /// Unknown contacts (not in DB) return false — conservative default.
        func isSafeContact(_ identifier: String) -> Bool {
            let descriptor = FetchDescriptor<Contact.Profile>(
                predicate: #Predicate { $0.identifier == identifier && $0.deletionToken == nil }
            )
            guard let contact = try? self.modelContext.fetch(descriptor).first else { return false }
            return Self.isVisible(contact, atDepth: self.currentDepth)
        }

        /// Returns identifiers of contacts visible at the current depth.
        func safeContactIDs() -> Set<String> {
            guard let contacts = try? self.modelContext.fetch(Contact.Profile.descriptor) else { return [] }
            return Set(contacts.compactMap { Self.isVisible($0, atDepth: self.currentDepth) ? $0.identifier : nil })
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

        // MARK: - Safe vault entries

        /// Returns true if the vault entry is visible at the current depth.
        func isEntryVisible(_ entry: VaultEntry) -> Bool {
            guard let data = entry.visibleThroughDepth else { return true }
            guard let decrypted = data.decrypt(),
                  let value = try? JSONDecoder().decode(Int.self, from: decrypted)
            else { return true }
            return value >= self.currentDepth
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

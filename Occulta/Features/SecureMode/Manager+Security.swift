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
import CryptoKit
import SQLite3

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

        private let modelContext:    ModelContext
        private let keyManager:      any KeyManagerProtocol
        /// SwiftData store URL for WAL checkpoint during key rotation.
        /// `nil` in tests (TestKeyManager, in-memory store).
        private let storeURL:        URL?
        /// Override for the blob directory used by `Manager.Blob.seal/unseal`.
        /// `nil` (default) → production app-group path.
        /// Non-nil → per-test temp directory that avoids cross-test blob collisions.
        private let blobDirectory:   URL?

        private var wrongPINCount          = 0
        private var consecutiveDuressCount = 0

        private static let normalLabel = Data("secure-mode-normal-pin-2026".utf8)
        private static let duressLabel = Data("secure-mode-duress-pin-2026".utf8)

        // MARK: - Init

        /// - Parameters:
        ///   - modelContainer: The shared SwiftData container.
        ///   - keyManager: Key manager implementation (injectable for testing).
        ///   - enabled: When `false` (feature flag `secureMode` is off), the manager
        ///     stays permanently in `.noPIN` state without reading `AppLayerConfig`
        ///     at all. All filtering and overlay logic becomes a no-op.
        init(modelContainer: ModelContainer,
             keyManager: any KeyManagerProtocol = Manager.Key(),
             storeURL: URL? = nil,
             blobDirectory: URL? = nil,
             enabled: Bool = true) {
            let context          = ModelContext(modelContainer)
            self.modelContext    = context
            self.keyManager      = keyManager
            self.storeURL        = storeURL
            self.blobDirectory   = blobDirectory

            // Feature-flag off path: skip all DB reads and sit permanently in .noPIN.
            // requiresPIN = false → overlay never shown. isRestricted = false →
            // no contact or vault filtering. All other properties stay at defaults.
            guard enabled else {
                self.state = .noPIN
                return
            }

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

        /// Activates Secure Mode: verify the existing normal PIN, run the 11-step key
        /// rotation, then transition `.pinOnly` → `.active`.
        ///
        /// - Parameters:
        ///   - confirmingEntryPIN: Must match the existing normal PIN verifier.
        ///   - duressPIN: The new duress PIN; must differ from the normal PIN.
        ///   - contactManager: Used to read, re-encrypt, and hard-delete contacts.
        ///   - vaultManager: Used to read vault PEKs for the blob (vault must be unlocked).
        func activateSecureMode(
            confirmingEntryPIN: String,
            duressPIN:          String,
            contactManager:     ContactManager,
            vaultManager:       VaultManager
        ) async throws {
            // ── Step 1: State guard + PIN verification ──────────────────────────────
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

            // ── Step 2: Create staged local DB key ──────────────────────────────────
            // On any failure past this point we rollback staged artefacts.
            let stagedKey = try self.keyManager.createStagedLocalDBKey()
            do {
                // ── Step 3: Derive blob key ──────────────────────────────────────────
                guard let blobKey = Manager.Blob.deriveBlobKey(from: seKey) else {
                    throw SecurityError.keyDerivationFailed
                }

                // ── Step 4: Classify contacts ────────────────────────────────────────
                // sensitive → blob; safe → re-encrypt in DB.
                let allProfiles = try contactManager.fetchAllContacts()
                var blobContacts:  [ContactBlobRecord] = []
                var safeProfiles:  [Contact.Profile]   = []

                for profile in allProfiles {
                    if Self.isVisible(profile, atDepth: 1) {
                        safeProfiles.append(profile)
                    } else {
                        // Sensitive: decrypt and capture for blob.
                        let draft = try contactManager.convertToMutableCopy(
                            using: profile.identifier
                        )
                        let signedAttrs: Data?
                        if let enc = profile.signedAttributes, !enc.isEmpty {
                            signedAttrs = enc.decrypt()
                        } else {
                            signedAttrs = nil
                        }
                        blobContacts.append(
                            ContactBlobRecord(draft: draft, signedAttributes: signedAttrs)
                        )
                    }
                }

                // ── Step 5: Migrate nil visibleThroughDepth (should be a no-op) ─────
                for profile in safeProfiles where profile.visibleThroughDepth == nil {
                    profile.visibleThroughDepth = try JSONEncoder().encode(Int.max).encrypt()
                }

                // ── Step 6: Unwrap vault PEKs ────────────────────────────────────────
                var blobPEKs: [VaultPEKRecord] = []
                if vaultManager.isUnlocked {
                    let vaultKey = try vaultManager.currentKey()
                    for entry in try vaultManager.fetchAllEntries() {
                        let pek   = try vaultManager.unwrapPEK(for: entry, vaultKey: vaultKey)
                        let dist  = try? vaultManager.shardDistributionMetadata(for: entry.id)
                        var bytes = pek.withUnsafeBytes { Data($0) }
                        blobPEKs.append(VaultPEKRecord(entryID: entry.id,
                                                        pekBytes: bytes,
                                                        shardDistribution: dist))
                        bytes.withUnsafeMutableBytes { memset($0.baseAddress!, 0, $0.count) }
                    }
                }

                // ── Step 7: Seal blob ────────────────────────────────────────────────
                let payload = BlobPayload(contacts: blobContacts, vaultPEKs: blobPEKs)
                try Manager.Blob.seal(payload, blobKey: blobKey, directory: self.blobDirectory)

                // ── Step 8: Re-encrypt safe contacts + vault depth fields ─────────────
                let stagedCrypto = StagedCryptoManager(key: stagedKey)
                let aad          = EncryptionScheme.v2_hybridPQ.aad

                for profile in safeProfiles {
                    // Pre-fix all fields that save(contact:using:) does not touch
                    // (visibleThroughDepth, signedAttributes, contactPublicKeys).
                    // These must be staged before the modelContext.save() inside
                    // save(contact:using:) so they land in the same write batch.
                    // Key records are fixed before convertToMutableCopy — convertToMutableCopy
                    // will produce nil keys for them (canonical-key decrypt fails on
                    // staged-key ciphertext), but the UPDATE save path ignores keys.
                    if let old = profile.visibleThroughDepth, let plain = old.decrypt() {
                        profile.visibleThroughDepth = try AES.GCM.seal(
                            plain, using: stagedKey, authenticating: aad
                        ).combined
                    }
                    if let old = profile.signedAttributes, !old.isEmpty, let plain = old.decrypt() {
                        profile.signedAttributes = try AES.GCM.seal(
                            plain, using: stagedKey, authenticating: aad
                        ).combined
                    }
                    try Self.reEncryptKeyRecords(for: profile, using: stagedKey, aad: aad)

                    let draft = try contactManager.convertToMutableCopy(using: profile.identifier)
                    try contactManager.save(contact: draft, using: stagedCrypto)
                }
                // Re-encrypt VaultEntry.visibleThroughDepth (encrypted under local DB key).
                for entry in try vaultManager.fetchAllEntries() {
                    if let old = entry.visibleThroughDepth, let plain = old.decrypt() {
                        entry.visibleThroughDepth = try AES.GCM.seal(
                            plain, using: stagedKey, authenticating: aad
                        ).combined
                    }
                }
                try vaultManager.modelContext.save()

                // Hard-delete sensitive contacts from DB after their data is safely in the blob.
                for profile in allProfiles where !safeProfiles.contains(where: { $0.identifier == profile.identifier }) {
                    try contactManager.hardDeleteContact(profile)
                }

                // ── Step 9: WAL checkpoint ────────────────────────────────────────────
                if let url = self.storeURL {
                    Self.walCheckpoint(at: url)
                }

                // ── Step 10: Commit staged key → point of no return ───────────────────
                try self.keyManager.commitStagedLocalDBKey()

                // ── Step 11: Cleanup + state transition ───────────────────────────────
                self.keyManager.deleteSupersededLocalDBArtefacts()

            } catch {
                self.keyManager.rollbackStagedLocalDBKey()
                throw error
            }

            self.resetCounters()
            self.lastUnlockDate = nil
            self.appLockEnabled = true
            self.state = .active
        }

        /// Verifies the normal PIN, unwinds the blob, reverse-rotates the local DB key,
        /// restores sensitive contacts, and transitions `.active` / `.duress` → `.pinOnly`.
        ///
        /// Mirror of `activateSecureMode`: creates a staged key, re-encrypts everything
        /// under it (safe contacts + restored blob contacts + vault depth fields), commits,
        /// then replaces the real blob with a fresh no-op payload.
        func deactivateSecureMode(
            confirmingEntryPIN: String,
            contactManager:     ContactManager,
            vaultManager:       VaultManager
        ) async throws {
            // ── Step 1: State guard + PIN verification ──────────────────────────────
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

            // ── Step 2: Derive blob key + unseal ────────────────────────────────────
            guard let blobKey = Manager.Blob.deriveBlobKey(from: seKey) else {
                throw SecurityError.keyDerivationFailed
            }
            let payload = try Manager.Blob.unseal(blobKey: blobKey, directory: self.blobDirectory)

            // ── Step 3: Create staged key (point of no return begins) ───────────────
            let stagedKey = try self.keyManager.createStagedLocalDBKey()
            do {
                let stagedCrypto = StagedCryptoManager(key: stagedKey)
                let aad          = EncryptionScheme.v2_hybridPQ.aad

                // ── Step 4: Re-encrypt safe contacts (currently in DB) ───────────────
                // Pre-fix visibleThroughDepth, signedAttributes, and contactPublicKeys
                // BEFORE the save so they land in the same modelContext.save() batch.
                for profile in try contactManager.fetchAllContacts() {
                    if let old = profile.visibleThroughDepth, let plain = old.decrypt() {
                        profile.visibleThroughDepth = try AES.GCM.seal(
                            plain, using: stagedKey, authenticating: aad
                        ).combined
                    }
                    if let old = profile.signedAttributes, !old.isEmpty, let plain = old.decrypt() {
                        profile.signedAttributes = try AES.GCM.seal(
                            plain, using: stagedKey, authenticating: aad
                        ).combined
                    }
                    try Self.reEncryptKeyRecords(for: profile, using: stagedKey, aad: aad)

                    let draft = try contactManager.convertToMutableCopy(using: profile.identifier)
                    try contactManager.save(contact: draft, using: stagedCrypto)
                }

                // ── Step 5: Re-insert sensitive contacts from blob ───────────────────
                // INSERT path in save(contact:using:) writes visibleThroughDepth and
                // contactPublicKeys with the canonical key. Fetch via self.modelContext
                // after each INSERT to overwrite those fields with staged-key encryption.
                let depthData        = try JSONEncoder().encode(Int.max)
                let visibleEncrypted = try AES.GCM.seal(
                    depthData, using: stagedKey, authenticating: aad
                ).combined

                for record in payload.contacts {
                    try contactManager.save(contact: record.draft, using: stagedCrypto)

                    let fetchDesc = FetchDescriptor<Contact.Profile>(
                        predicate: #Predicate { $0.identifier == record.draft.identifier }
                    )
                    guard let restored = try self.modelContext.fetch(fetchDesc).first else { continue }
                    restored.visibleThroughDepth = visibleEncrypted
                    if let attrs = record.signedAttributes, !attrs.isEmpty {
                        restored.signedAttributes = try AES.GCM.seal(
                            attrs, using: stagedKey, authenticating: aad
                        ).combined
                    }
                    try Self.reEncryptKeyRecords(for: restored, using: stagedKey, aad: aad)
                }
                if !payload.contacts.isEmpty {
                    try self.modelContext.save()
                }

                // ── Step 6: Restore all vault entries to visible under staged key ────
                // Sets every visibleThroughDepth to Int.max (always visible) so deactivation
                // clears depth-1 hiding. Falls back to nil (also always visible) implicitly
                // if no entries exist.
                let allVaultEntries = try vaultManager.fetchAllEntries()
                for entry in allVaultEntries {
                    entry.visibleThroughDepth = visibleEncrypted
                }
                if !allVaultEntries.isEmpty {
                    try vaultManager.modelContext.save()
                }

                // ── Step 7: WAL checkpoint ────────────────────────────────────────────
                if let url = self.storeURL {
                    Self.walCheckpoint(at: url)
                }

                // ── Step 8: Commit staged key (hard point of no return) ───────────────
                try self.keyManager.commitStagedLocalDBKey()

                // ── Step 9: Delete superseded artefacts ───────────────────────────────
                self.keyManager.deleteSupersededLocalDBArtefacts()

            } catch {
                self.keyManager.rollbackStagedLocalDBKey()
                throw error
            }

            // Remove duress verifier, reset gate, persist config, replace blob.
            config.sealedDuressVerifier = nil
            try config.writeLockGate(depth: 0, gateActive: true)
            try self.modelContext.save()
            Manager.Blob.rewriteNoOpBlob()
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
            guard self.checkCurrentLayerPIN(confirmingPIN) else {
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
        /// and no state transitions occur — used by `disablePINFromCurrentDepth` and by
        /// `PINEntry.submitConfirmPhase` so the activation flow's first phase accepts the
        /// correct PIN at any depth (duress PIN in `.duress`, normal PIN otherwise).
        func checkCurrentLayerPIN(_ pin: String) -> Bool {
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

        /// Marks contacts in `ids` as always visible (`encrypt(Int.max)`) and all others
        /// as hidden (`encrypt(0)`). Never writes nil — every row gets an encrypted value.
        func updateSafeContacts(_ ids: Set<String>) throws {
            let contacts = try self.modelContext.fetch(Contact.Profile.descriptor)
            for contact in contacts {
                let depthValue = ids.contains(contact.identifier) ? Int.max : 0
                contact.visibleThroughDepth = try JSONEncoder().encode(depthValue).encrypt()
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
            contact.visibleThroughDepth = try JSONEncoder().encode(isSensitive ? 0 : Int.max).encrypt()
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

        /// Forces a full WAL checkpoint (TRUNCATE mode) so all pending writes land in
        /// the main `.sqlite` file before the staged key is committed in step 10.
        private static func walCheckpoint(at url: URL) {
            var db: OpaquePointer?
            guard sqlite3_open_v2(url.path, &db, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK else { return }
            defer { sqlite3_close(db) }
            sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)", nil, nil, nil)
        }

        /// Re-encrypts every field of every `Contact.Profile.Key` child of `profile`
        /// from the current canonical key to `key` (the staged key).
        ///
        /// `save(contact:using:)` never touches `contactPublicKeys` in its UPDATE path
        /// and encrypts them with `self.cryptoManager` (canonical) in its INSERT path.
        /// This helper closes that gap for both activation (safe contacts) and deactivation
        /// (safe + restored blob contacts).
        ///
        /// Fields whose decrypt attempt returns `nil` are left unchanged — this covers
        /// nil/empty values and records that are already staged-key-encrypted (idempotent
        /// on second call).
        private static func reEncryptKeyRecords(
            for profile: Contact.Profile,
            using key: SymmetricKey,
            aad: Data
        ) throws {
            for keyRecord in (profile.contactPublicKeys ?? []) {
                if let plain = keyRecord.material?.decrypt() {
                    keyRecord.material = try AES.GCM.seal(
                        plain, using: key, authenticating: aad
                    ).combined
                }
                if !keyRecord.owner.isEmpty, let plain = keyRecord.owner.decrypt(),
                   let combined = try AES.GCM.seal(plain, using: key, authenticating: aad).combined {
                    keyRecord.owner = combined
                }
                if let plain = keyRecord.acquiredAt?.decrypt() {
                    keyRecord.acquiredAt = try AES.GCM.seal(
                        plain, using: key, authenticating: aad
                    ).combined
                }
                if let plain = keyRecord.expiredOn?.decrypt() {
                    keyRecord.expiredOn = try AES.GCM.seal(
                        plain, using: key, authenticating: aad
                    ).combined
                }
                if let plain = keyRecord.quantumKeyMaterialEncrypted?.decrypt() {
                    keyRecord.quantumKeyMaterialEncrypted = try AES.GCM.seal(
                        plain, using: key, authenticating: aad
                    ).combined
                }
            }
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

// MARK: - Staged crypto helper

/// Minimal CryptoProtocol that encrypts/decrypts with an explicit SymmetricKey.
///
/// Used by the Secure Mode activation sequence to re-encrypt safe contacts
/// under the staged DB key before it is promoted to canonical. Only
/// `encrypt(data:)` and `decrypt(data:)` are implemented — the activation
/// sequence never calls the other protocol methods.
private final class StagedCryptoManager: CryptoProtocol {
    private let key: SymmetricKey

    init(key: SymmetricKey) { self.key = key }

    func encrypt(data: Data?) throws -> Data? {
        guard let data else { return nil }
        let aad = EncryptionScheme.v2_hybridPQ.aad
        return try AES.GCM.seal(data, using: self.key, nonce: AES.GCM.Nonce(),
                                 authenticating: aad).combined
    }

    func decrypt(data: Data?) throws -> Data? {
        guard let data else { return nil }
        let box = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(box, using: self.key,
                                 authenticating: EncryptionScheme.v2_hybridPQ.aad)
    }

    func decryptLegacy(data: Data?) throws -> Data?                          { nil }
    func encrypt(message: Data, using material: Data?) throws -> Data?       { nil }
    func decrypt(message: Data, using material: Data?) throws -> Data?       { nil }
    func sign(data: Data?) -> String                                         { "" }
}

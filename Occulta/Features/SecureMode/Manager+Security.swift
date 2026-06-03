//
//  Manager+Security.swift
//  Occulta
//
//  Single umbrella for all app-security hardening.
//  Owns the AppLayerConfig SwiftData row, PIN verification, and the
//  Secure Mode state machine. The former SecureModeManager is gone;
//  Manager.PINManager (PIN+Manager.swift) handles pure crypto operations
//  internally and is not part of the public API.
//

import Foundation
import SwiftData
import CryptoKit
import SQLite3

extension Manager {
    @Observable
    final class Security {

        // MARK: - State

        private(set) var state:        RoutingDepth = .normal
        /// In-memory depth counter. Resets to 0 on every app kill — never persisted.
        /// `currentDepth > 0` means a decoy layer is active. The PIN is the routing key:
        /// after a cold start `verify()` scans all normal verifiers and sets `currentDepth`
        /// directly to the matched depth without walking through intermediate layers.
        private(set) var currentDepth: Int          = 0

        var isRestricted: Bool { self.currentDepth > 0 }

        /// Whether a normal PIN verifier exists. Reads config on every call — not reactive
        /// for SwiftUI; views that need reactive updates should use `@Query` on `AppLayerConfig`.
        var requiresPIN: Bool {
            (try? self.modelContext.fetch(FetchDescriptor<AppLayerConfig>()).first)?
                .sealedNormalVerifier != nil
        }

        /// Whether both verifiers exist (Secure Mode active). Same caveats as `requiresPIN`.
        var isSecureModeActive: Bool {
            (try? self.modelContext.fetch(FetchDescriptor<AppLayerConfig>()).first)?
                .sealedDuressVerifier != nil
        }

        /// Date of the most recent successful PIN verification. In-memory only — nil after kill.
        /// Used by `OccultaApp` to skip the PIN prompt within the grace period.
        private(set) var lastUnlockDate: Date? = nil

        /// Whether the PIN overlay gate is currently enabled.
        ///
        /// When `false`, the app opens without showing the PIN prompt even though all PIN
        /// verifiers remain intact. This happens when the user explicitly lowers the gate
        /// via `disablePINFromCurrentDepth(confirmingPIN:)` — typically under coercion
        /// while in `.normal` or `.duress` state — so that the Settings toggle shows no
        /// observable difference from a device with no PIN configured.
        ///
        /// Critically, depth-filtering still applies when the gate is down: contacts and vault
        /// entries whose `visibleThroughDepth` is set remain hidden at the stored depth,
        /// regardless of whether the PIN overlay fires on scene activation.
        ///
        /// Persisted across app kills via `AppLayerConfig.pinEnabled`. Restored in `init`.
        /// Always `true` after any clean state transition.
        private(set) var appLockEnabled: Bool = true

        /// Drives the opaque overlay — true means content is hidden.
        /// Set instantly in both directions; the overlay uses .animation(.none).
        private(set) var isContentHidden: Bool = false

        /// Drives the fullScreenCover PIN gate — true means the PIN entry sheet is presented.
        /// Not private(set) so the fullScreenCover binding can clear it on system-initiated dismiss.
        var needsPINEntry: Bool = false

        /// Record a successful authentication. Call from `PINEntry.onNormal` and `onDuress`.
        func recordUnlock() {
            self.lastUnlockDate = Date()
        }

        // MARK: - Private

        private let modelContext:    ModelContext
        private let keyManager:      any KeyManagerProtocol
        /// SwiftData store URL for WAL checkpoint during key rotation.
        /// `nil` in tests (TestKeyManager, in-memory store).
        private let storeURL:    URL?
        /// Layer store for push/pop during key rotation.
        /// Defaults to AppGroupLayerStoreBackend (production). Tests inject InMemoryLayerStoreBackend.
        private let layerStore: Manager.LayerStore

        private var wrongPINCount          = 0
        private var consecutiveDuressCount = 0

        private static let normalLabel = Data("secure-mode-normal-pin-2026".utf8)
        private static let duressLabel = Data("secure-mode-duress-pin-2026".utf8)

        // MARK: - Init

        /// - Parameters:
        ///   - modelContainer: The shared SwiftData container.
        ///   - keyManager: Key manager implementation (injectable for testing).
        ///   - enabled: When `false` (feature flag `secureMode` is off), the manager
        ///     skips all `AppLayerConfig` reads. `requiresPIN` returns `false`, all
        ///     filtering is inert, and the PIN overlay never appears.
        init(modelContainer: ModelContainer,
             keyManager: any KeyManagerProtocol = Manager.Key(),
             storeURL: URL? = nil,
             layerStore: Manager.LayerStore = Manager.LayerStore(),
             enabled: Bool = true) {
            let context        = ModelContext(modelContainer)
            self.modelContext  = context
            self.keyManager    = keyManager
            self.storeURL      = storeURL
            self.layerStore    = layerStore

            // Feature-flag off path: skip all DB reads. requiresPIN returns false,
            // isRestricted = false. All properties stay at defaults.
            guard enabled else { return }

            // Bootstrap: ensure the config row exists from the very first launch.
            // AppLayerConfig must always be present regardless of whether a PIN or
            // Secure Mode has ever been configured — its absence would be a forensic
            // tell that the feature was never used. All sensitive fields default to nil
            // (no PIN, no duress verifier), which is functionally equivalent to a
            // fresh install that has never touched Settings.
            let config: AppLayerConfig
            if let existing = try? context.fetch(FetchDescriptor<AppLayerConfig>()).first {
                config = existing
            } else {
                let seed = AppLayerConfig()
                try? seed.writeRoutingDepth(.normal)
                try? seed.writePinEnabled(true)
                try? seed.setWipeThreshold(3)
                context.insert(seed)
                try? context.save()
                config = seed
            }

            // Migration: populate verifier arrays from scalar fields on first launch after
            // the multi-layer upgrade. Scalars remain as nil/non-nil flags for requiresPIN
            // and isSecureModeActive; arrays are the source of truth for verify() scanning.
            if config.sealedNormalVerifiers.isEmpty {
                var normals = AppLayerConfig.verifierFillerArray()
                if let scalar = config.sealedNormalVerifier { normals[0] = scalar }
                config.sealedNormalVerifiers = normals

                var duresses = AppLayerConfig.verifierFillerArray()
                if let scalar = config.sealedDuressVerifier { duresses[0] = scalar }
                config.sealedDuressVerifiers = duresses

                try? context.save()
            }

            // Restore routing depth and gate state so depth-filtering and the PIN
            // overlay behave correctly after an app kill or restart. Both fields
            // fall back to the safe default on any decode failure.
            self.state          = config.readRoutingDepth()
            self.appLockEnabled = config.readPinEnabled()

            let pinRequired      = config.sealedNormalVerifier != nil
            self.isContentHidden = pinRequired && self.appLockEnabled
            self.needsPINEntry   = pinRequired && self.appLockEnabled
        }

        // MARK: - State transition

        /// Atomically writes routing depth and gate state to config and updates in-memory properties.
        /// The caller is responsible for calling `modelContext.save()` afterward.
        private func setState(_ depth: RoutingDepth, pinEnabled: Bool = true, config: AppLayerConfig) throws {
            try config.writeRoutingDepth(depth)
            try config.writePinEnabled(pinEnabled)
            self.state          = depth
            self.appLockEnabled = pinEnabled
        }

        // MARK: - App lock

        private static let gracePeriod: TimeInterval = 5 * 60

        private var isWithinGracePeriod: Bool {
            guard let last = self.lastUnlockDate else { return false }
            return Date().timeIntervalSince(last) < Self.gracePeriod
        }

        /// App went .inactive (share sheet, Spotlight). Cover content for screenshot protection;
        /// do not present the PIN gate (conflicts with UIActivityViewController).
        func handleInactive(vaultUnlocked: Bool) {
            guard self.requiresPIN, self.appLockEnabled, vaultUnlocked else { return }
            self.isContentHidden = true
        }

        /// App fully backgrounded. Cover content; raise PIN gate only when grace period has expired.
        func handleBackground() {
            guard self.requiresPIN, self.appLockEnabled else { return }
            self.isContentHidden = true
            self.needsPINEntry   = !self.isWithinGracePeriod
        }

        /// App returned to foreground. Auto-unlock within grace period; re-lock when expired.
        func handleActive() {
            guard self.requiresPIN, self.appLockEnabled else {
                self.isContentHidden = false
                self.needsPINEntry   = false
                return
            }
            if self.isWithinGracePeriod {
                self.isContentHidden = false
                self.needsPINEntry   = false
            } else {
                self.isContentHidden = true
                self.needsPINEntry   = true
            }
        }

        /// Call from onNormal after PIN entry — clears the lock gate and records the unlock.
        func unlockNormal() {
            self.recordUnlock()
            self.isContentHidden = false
            self.needsPINEntry   = false
        }

        /// Call from onDuress after duress PIN entry — same lock-state transition as unlockNormal.
        func unlockDuress() {
            self.recordUnlock()
            self.isContentHidden = false
            self.needsPINEntry   = false
        }

        // MARK: - Layer store maintenance

        /// Creates or refreshes the no-op layer store file on launch.
        ///
        /// Call once from `OccultaApp.init()`. No-op when Secure Mode is active
        /// (file holds a real payload) or when the feature flag is off.
        func maintainLayerStore() {
            guard !self.isSecureModeActive else { return }
            let store = self.layerStore
            DispatchQueue.global(qos: .background).async {
                store.maintain()
            }
        }

        /// Rewrites the no-op layer store file on a background thread.
        ///
        /// Call from `OccultaApp`'s debounced save notification so the file's
        /// Last-Modified timestamp correlates with normal app activity.
        /// No-op when Secure Mode is active or the feature flag is off.
        func rewriteLayerStore() {
            guard !self.isSecureModeActive else { return }
            let store = self.layerStore
            DispatchQueue.global(qos: .utility).async {
                store.rewrite()
            }
        }

        // MARK: - PIN Setup

        /// Builds a normal PIN verifier, persists config, and transitions from no-PIN to PIN-only
        /// (`requiresPIN` becomes `true`, `isSecureModeActive` remains `false`).
        ///
        func configurePIN(_ pin: String) throws {
            guard let seKey = try self.keyManager.deriveSecureModeKey() else {
                throw SecurityError.keyDerivationFailed
            }
            let sealedNormal = try PINManager.buildVerifier(pin: pin, label: Self.normalLabel, seKey: seKey)

            // Update the always-present row in place — never delete and recreate.
            let config = try self.requireConfig()
            config.sealedNormalVerifier = sealedNormal   // scalar: nil/non-nil flag for requiresPIN
            config.writeNormalVerifier(sealedNormal, at: 0)  // array[0]: scanned by verify()
            try config.setWipeThreshold(3)
            try self.setState(.normal, config: config)
            try self.modelContext.save()

            self.resetCounters()
        }

        /// Verifies the normal PIN and clears all verifiers, making `requiresPIN` false.
        ///
        /// The config row is **not** deleted — AppLayerConfig must always be present so its
        /// existence is not a forensic tell for PIN or Secure Mode usage. All sensitive fields
        /// are reset to nil; the row is otherwise identical to a fresh-install row.
        ///
        /// Throws `.invalidStateTransition` if `isSecureModeActive` is true — the caller must
        /// deactivate Secure Mode (removing the duress verifier) before removing the PIN entirely.
        func deactivatePIN(confirmingNormalPIN: String) throws {
            let config = try self.requireConfig()
            guard config.sealedDuressVerifier == nil else { throw SecurityError.invalidStateTransition }
            guard let seKey = try self.keyManager.deriveSecureModeKey() else {
                throw SecurityError.keyDerivationFailed
            }
            guard config.sealedNormalVerifiers.indices.contains(0),
                  PINManager.checkVerifier(pin: confirmingNormalPIN, label: Self.normalLabel,
                                           verifier: config.sealedNormalVerifiers[0], seKey: seKey)
            else { throw SecurityError.incorrectPIN }

            config.sealedNormalVerifier = nil  // scalar
            config.writeNormalVerifier(AppLayerConfig.verifierFiller(), at: 0)  // reset array[0]
            try self.setState(.normal, config: config)
            try self.modelContext.save()
            self.resetCounters()
            self.appLockEnabled  = true
            self.state           = .normal
            self.currentDepth    = 0
        }

        // MARK: - Secure Mode

        /// Activates Secure Mode: verify the existing normal PIN, run the 11-step key
        /// rotation, then transition from PIN-only to Secure Mode active (`isSecureModeActive` becomes `true`).
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
            // Prevent accidental mid-sequence autosaves on this context.
            // Explicit saves still work; only the RunLoop-triggered autosave is suppressed.
            self.modelContext.autosaveEnabled = false
            defer { self.modelContext.autosaveEnabled = true }

            // ── Step 1: State guard + PIN verification ──────────────────────────────
            // Activation is valid from: .pinOnly (depth 0, creating first duress layer)
            //                           .duress  (depth N, adding a deeper layer)
            // It is NOT valid from .normal when Secure Mode is already active — the
            // Activate button is hidden in that state; this guard prevents API misuse.
            guard self.requiresPIN else { throw SecurityError.invalidStateTransition }
            // Valid activation states:
            //   isRestricted (currentDepth > 0): inside a decoy layer — add a deeper layer.
            //   !isSecureModeActive: no layers yet (pinOnly) — create the first duress layer.
            // Invalid: depth 0 with Secure Mode already active (real app; Activate is hidden there).
            guard self.isRestricted || !self.isSecureModeActive else {
                throw SecurityError.invalidStateTransition
            }

            let config = try self.requireConfig()
            let depth  = self.currentDepth

            guard let seKey = try self.keyManager.deriveSecureModeKey() else {
                throw SecurityError.keyDerivationFailed
            }

            // Confirm entry PIN against the normal verifier at the current depth.
            guard depth < config.sealedNormalVerifiers.count,
                  PINManager.checkVerifier(pin: confirmingEntryPIN, label: Self.normalLabel,
                                           verifier: config.sealedNormalVerifiers[depth], seKey: seKey)
            else { throw SecurityError.incorrectPIN }

            // Duress PIN must not match ANY existing verifier (normal or duress at any depth).
            for v in config.sealedNormalVerifiers {
                guard !PINManager.checkVerifier(pin: duressPIN, label: Self.normalLabel, verifier: v, seKey: seKey)
                else { throw SecurityError.pinCollision }
            }
            for v in config.sealedDuressVerifiers {
                guard !PINManager.checkVerifier(pin: duressPIN, label: Self.duressLabel, verifier: v, seKey: seKey)
                else { throw SecurityError.pinCollision }
            }

            // Build verifiers now so they are in scope for the post-catch config write.
            let duressVerifier = try PINManager.buildVerifier(pin: duressPIN, label: Self.duressLabel, seKey: seKey)
            let routingAlias   = try PINManager.buildVerifier(pin: duressPIN, label: Self.normalLabel, seKey: seKey)

            // Depth-0 scalar written in-memory now; cleared by catch on failure.
            // All array writes happen in the post-catch section (new canonical key).
            if depth == 0 {
                config.sealedDuressVerifier = duressVerifier
                // Do NOT save yet — deferred until key rotation succeeds.
                // If anything below throws, catch clears this in-memory mutation.
            }

            // Slot index and sequence number chosen before the do/catch block so they
            // are in scope for the post-catch config write.
            // Slot exclusion: the real layer (depth 0) slot is permanently excluded from
            // all depth > 0 writes so it can never be overwritten or statistically identified.
            let excludedSlots: Set<Int> = depth == 0
                ? []
                : Set([config.readBlobSlot(at: 0)].compactMap { $0 })
            let slotIndex      = self.layerStore.randomSlot(excluding: excludedSlots)
            let sequenceNumber = Self.randomSequenceNumber()

            // ── Step 2: Create staged local DB key ──────────────────────────────────
            // On any failure past this point we rollback staged artefacts.
            // stagedKey is declared here so it's in scope for the catch's rollback call.
            do {
                let stagedKey = try self.keyManager.createStagedLocalDBKey()
                // ── Step 3: Derive blob key ──────────────────────────────────────────
                guard let layerKey = self.layerStore.deriveKey(from: seKey) else {
                    throw SecurityError.keyDerivationFailed
                }

                // ── Step 4: Classify contacts ────────────────────────────────────────
                // sensitive → blob; safe → re-encrypt in DB.
                let allProfiles = try contactManager.fetchAllContacts()
                var blobContacts:  [LayerContact] = []
                var safeProfiles:  [Contact.Profile]   = []

                for profile in allProfiles {
                    if Self.isVisible(profile, atDepth: .max) {
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
                        let depth: Int?
                        if let data = profile.visibleThroughDepth,
                           let plain = data.decrypt(),
                           let value = try? JSONDecoder().decode(Int.self, from: plain) {
                            depth = value
                        } else {
                            depth = nil
                        }
                        blobContacts.append(
                            LayerContact(draft: draft, signedAttributes: signedAttrs,
                                              visibleThroughDepth: depth)
                        )
                    }
                }

                // ── Step 5: Migrate nil visibleThroughDepth (should be a no-op) ─────
                for profile in safeProfiles where profile.visibleThroughDepth == nil {
                    profile.visibleThroughDepth = try JSONEncoder().encode(Int.max).encrypt()
                }

                // ── Step 6: Push blob ────────────────────────────────────────────────
                // Vault entries are not included in the blob. Their per-entry keys (PEKs)
                // are derived from a dedicated SE key entirely independent of the local DB
                // key rotation — vault entries never need re-keying during activation or
                // deactivation. Storing raw PEK bytes in the blob would unnecessarily widen
                // the attack surface: blob compromise (SE Secure Mode key, no biometrics)
                // would also yield all vault entry symmetric keys, bypassing the biometric gate.
                let payload = LayerPayload(
                    sequenceNumber: sequenceNumber,
                    slotIndex:      slotIndex,
                    contacts:       blobContacts
                )
                try self.layerStore.push(payload, key: layerKey, slotIndex: slotIndex)

                // ── Step 8: Re-encrypt ALL contacts + vault depth fields ──────────────
                //
                // Both safe and sensitive contacts must be re-encrypted under the staged
                // key. Sensitive contacts remain in the DB (not hard-deleted); after the
                // old canonical key is deleted in Step 11, any contact still encrypted
                // under it becomes permanently unreadable. Depth-based visibility
                // (visibleThroughDepth) controls what appears in the UI — not the key.
                let aad = EncryptionScheme.v2_hybridPQ.aad

                for profile in allProfiles {
                    try profile.reencryptAllFields(to: stagedKey, aad: aad)
                    try profile.reencryptKeyRecords(to: stagedKey, aad: aad)
                }
                // Flush re-encrypted contacts to the WAL BEFORE committing the staged key.
                // reencryptAllFields only mutates the in-memory SwiftData objects; without
                // an explicit save the WAL checkpoint in Step 10 would flush an empty WAL,
                // leaving the main SQLite file with pre-activation ciphertext. After Step 11
                // deletes the old canonical key, those rows become permanently unreadable.
                try contactManager.modelContext.save()

                // Re-encrypt VaultEntry.visibleThroughDepth (encrypted under local DB key).
                // Every entry must end up with a staged-key ciphertext — no silent skips:
                //   • nil depth (Bug 26): pre-existing entry never stamped → hide at all duress depths.
                //   • non-nil but unreadable (Bug 27): corrupt/wrong-key ciphertext → treat as hidden.
                //   • non-nil and readable: re-encrypt the existing value verbatim.
                let hiddenData = try JSONEncoder().encode(0)
                for entry in try vaultManager.fetchAllEntries() {
                    let plain = entry.visibleThroughDepth.flatMap { $0.decrypt() } ?? hiddenData
                    entry.visibleThroughDepth = try AES.GCM.seal(
                        plain, using: stagedKey, authenticating: aad
                    ).combined
                }
                try vaultManager.modelContext.save()

                // ── Step 9: Commit staged key → point of no return ───────────────────
                //
                // WAL checkpoint intentionally comes AFTER commit (Step 10).
                // If checkpoint ran before commit and the commit failed, the main
                // SQLite file would contain data encrypted with the staged (rolled-back)
                // key — permanently unreadable. Keeping all staged writes in the WAL
                // means a commit failure leaves the main file intact under the old
                // canonical key, which is fully readable after a rollback.
                try self.keyManager.commitStagedLocalDBKey()

                // ── Step 10: WAL checkpoint ───────────────────────────────────────────
                // Commit succeeded — flush the staged-key writes from the WAL to the
                // main file. Safe to checkpoint now because the commit is final.
                if let url = self.storeURL {
                    Self.walCheckpoint(at: url)
                }

                // ── Step 11: Cleanup ──────────────────────────────────────────────────
                self.keyManager.deleteSupersededLocalDBArtefacts()

                // Sensitive contacts are NOT hard-deleted from the DB.
                //
                // They remain in the DB with `visibleThroughDepth` set to a value that
                // hides them at duress depth (e.g. 0 = visible at depth 0 only). Depth
                // filtering in the contact list UI enforces visibility: at depth 0 (normal
                // PIN) they show; at depth 1+ (duress PIN) they are hidden.
                //
                // Page-slack forensics are handled by two existing mitigations that do not
                // require hard-deletion:
                //   • PRAGMA secure_delete = ON: SQLite zeroes freed pages on any row
                //     deletion or update, eliminating residual ciphertext from prior writes.
                //   • DB key rotation (S1): rows written before activation are encrypted
                //     under the old canonical key, which is deleted after commit. A forensic
                //     examiner with the current canonical key cannot decrypt pre-activation
                //     page slack.
                // Sensitive contacts that remain in the DB are encrypted under the new
                // canonical key. They are not accessible via the UI in duress mode; a raw
                // SQLite examiner with device access during duress exposure could decrypt
                // them. This is documented in forensic-trace-avoidance.md §S5 as an
                // accepted residual gap given the functional requirement that the real user
                // can see their sensitive contacts after entering the normal PIN.

            } catch {
                self.keyManager.rollbackStagedLocalDBKey()
                // Clear in-memory depth-0 scalar mutation so a retry doesn't hit the
                // `!isSecureModeActive` guard. Array writes are deferred so nothing to undo.
                if depth == 0 { config.sealedDuressVerifier = nil }
                throw error
            }

            // Key rotation succeeded. All config writes use the new canonical DB key
            // (post-commit) so they are encrypted correctly for the post-rotation state.
            //
            // Write duress verifier at `depth` and routing alias at `depth + 1`.
            // The routing alias is the SAME duress PIN built with normalLabel so that
            // verify()'s step-1 scan (which uses normalLabel for all entries) can find it
            // at cold start without walking through intermediate depths.
            config.writeDuressVerifier(duressVerifier, at: depth)
            config.writeNormalVerifier(routingAlias, at: depth + 1)
            // Update depth-0 scalar (isSecureModeActive / requiresPIN flags).
            if depth == 0 {
                config.sealedDuressVerifier = duressVerifier
            }
            try config.writeBlobSlot(slotIndex, at: depth)
            try config.writeSequenceNumber(sequenceNumber, at: depth)
            try self.modelContext.save()
            self.resetCounters()
            self.lastUnlockDate = nil
        }

        /// Verifies the normal PIN, unwinds the blob, reverse-rotates the local DB key,
        /// restores sensitive contacts, and removes the duress verifier (`isSecureModeActive` becomes `false`).
        ///
        /// Mirror of `activateSecureMode`: creates a staged key, re-encrypts everything
        /// under it (safe contacts + restored blob contacts + vault depth fields), commits,
        /// then replaces the real blob with a fresh no-op payload.
        func deactivateSecureMode(
            confirmingEntryPIN: String,
            contactManager:     ContactManager,
            vaultManager:       VaultManager
        ) async throws {
            self.modelContext.autosaveEnabled = false
            defer { self.modelContext.autosaveEnabled = true }

            // ── Step 1: State guard + PIN verification ──────────────────────────────
            let config = try self.requireConfig()
            let depth  = self.currentDepth

            guard config.sealedDuressVerifier != nil else { throw SecurityError.invalidStateTransition }
            // depth 0 (real app) and depth 1 (first duress view) both deactivate the
            // depth 0→1 layer and return to pinOnly. depth 0 is valid here — the real
            // app owner deactivates from their master view.

            guard let seKey = try self.keyManager.deriveSecureModeKey() else {
                throw SecurityError.keyDerivationFailed
            }
            // Confirm PIN against the normal verifier at the current depth.
            // depth 0 → sealedNormalVerifiers[0] (master PIN).
            // depth 1 → sealedNormalVerifiers[1] (routing alias = duress PIN).
            guard depth < config.sealedNormalVerifiers.count,
                  PINManager.checkVerifier(pin: confirmingEntryPIN, label: Self.normalLabel,
                                           verifier: config.sealedNormalVerifiers[depth], seKey: seKey)
            else { throw SecurityError.incorrectPIN }

            // ── Step 2: Derive blob key + pop ───────────────────────────────────────
            // Blob index per depth:
            //   depth 0 → blobDepth 0 (blob from activation at depth 0)
            //   depth 1 → blobDepth 0 (same blob; deactivating the depth 0→1 layer)
            //   depth N ≥ 2 → blobDepth N-1 (cascade: removes expendable layer,
            //                  preserves depth 0→1 layer until the final deactivation)
            guard let layerKey = self.layerStore.deriveKey(from: seKey) else {
                throw SecurityError.keyDerivationFailed
            }

            let blobDepth = max(0, depth - 1)

            // Both slot index and sequence number must be present. If either is missing,
            // skip pop — guessing a slot is not safe.
            let payload: LayerPayload
            if let slotIndex = config.readBlobSlot(at: blobDepth),
               let expectedSeq = config.readSequenceNumber(at: blobDepth) {
                do {
                    payload = try self.layerStore.pop(key: layerKey, slotIndex: slotIndex,
                                                      expectedSequenceNumber: expectedSeq)
                } catch {
                    // Blob corrupted, overwritten by maintain(), or seqnum mismatch.
                    // Sensitive contacts unrecoverable; safe contacts in DB are intact.
                    payload = LayerPayload(sequenceNumber: 0, slotIndex: 0, contacts: [])
                }
            } else {
                // No slot metadata — pre-upgrade install or config corruption.
                payload = LayerPayload(sequenceNumber: 0, slotIndex: 0, contacts: [])
            }

            // ── Step 3: Create staged key (point of no return begins) ───────────────
            let stagedKey = try self.keyManager.createStagedLocalDBKey()
            
            do {
                let stagedCrypto = StagedCryptoManager(key: stagedKey)
                let aad          = EncryptionScheme.v2_hybridPQ.aad

                // ── Step 4: Re-encrypt safe contacts (currently in DB) ───────────────
                // Pre-fix visibleThroughDepth, signedAttributes, and contactPublicKeys
                // BEFORE the save so they land in the same modelContext.save() batch.
                // visibleThroughDepth is set to nil (not re-encrypted) so the activation
                // watermark is erased: nil is the pre-activation default and functionally
                // identical to Int.max — isVisible returns true for both.
                //
                // convertToMutableCopy is wrapped in a local do/catch. Sensitive shells
                // have all text fields encrypted under the deleted activation key and
                // cannot be decrypted. On failure: skip without hard-deleting. Hard-delete
                // would write a delete record in the WAL at deactivation time — a forensic
                // tell that identifies exactly which contacts were hidden during Secure Mode.
                // Instead, the shell stays in the DB; Step 5 overwrites its text fields via
                // the UPDATE path using blob plaintext re-encrypted under the staged key.
                for profile in try contactManager.fetchAllContacts() {
                    try profile.reencryptAllFields(to: stagedKey, aad: aad)
                    try profile.reencryptKeyRecords(to: stagedKey, aad: aad)
                    // Clear visibleThroughDepth to erase the activation watermark — nil is
                    // the pre-activation default and isVisible treats it identically to Int.max.
                    // Sensitive shell text fields left unreadable here are overwritten in Step 5.
                    profile.visibleThroughDepth = nil
                }
                // Flush re-encrypted contacts to the WAL before the staged key is committed.
                // Same invariant as activation: in-memory changes must reach SQLite BEFORE
                // commitStagedLocalDBKey() or the WAL checkpoint will miss them.
                try contactManager.modelContext.save()

                // ── Step 5: Restore sensitive contacts from blob ────────────────────
                // Step 4's reencryptKeyRecords already migrated all contacts' key records
                // (including sensitive contacts') from K_activation → K_staged. This step
                // re-encrypts text fields from blob plaintext under the staged key and
                // restores depth / signedAttributes. Key records are not touched — they
                // are already under the staged key from Step 4.
                for record in payload.contacts {
                    try contactManager.save(contact: record.draft, using: stagedCrypto)

                    let fetchDesc = FetchDescriptor<Contact.Profile>(
                        predicate: #Predicate { $0.identifier == record.draft.identifier }
                    )
                    guard let restored = try self.modelContext.fetch(fetchDesc).first else { continue }

                    // Restore the depth stored at activation time, encrypted under the staged
                    // key so it is readable after commitStagedLocalDBKey(). Falls back to 0
                    // (sensitive) for blobs written before this field was added — any contact
                    // in the blob had a finite visibleThroughDepth by definition.
                    let depth     = record.visibleThroughDepth ?? 0
                    let depthData = try JSONEncoder().encode(depth)
                    restored.visibleThroughDepth = try AES.GCM.seal(
                        depthData, using: stagedKey, authenticating: aad
                    ).combined

                    if let attrs = record.signedAttributes, !attrs.isEmpty {
                        restored.signedAttributes = try AES.GCM.seal(
                            attrs, using: stagedKey, authenticating: aad
                        ).combined
                    }
                }
                if !payload.contacts.isEmpty {
                    try self.modelContext.save()
                }

                // ── Step 6: Restore all vault entries to visible under staged key ────
                // nil = always visible (pre-activation default). Erases the activation
                // watermark on vault entries the same way Step 4 does for contacts.
                let allVaultEntries = try vaultManager.fetchAllEntries()
                for entry in allVaultEntries {
                    entry.visibleThroughDepth = nil
                }
                if !allVaultEntries.isEmpty {
                    try vaultManager.modelContext.save()
                }

                // ── Step 7: Commit staged key (hard point of no return) ───────────────
                //
                // WAL checkpoint intentionally comes AFTER commit (Step 8).
                // If checkpoint ran before commit and the commit failed, the main
                // SQLite file would contain data encrypted with the staged (rolled-back)
                // key — permanently unreadable. Keeping all staged writes in the WAL
                // means a commit failure leaves the main file intact under the old
                // canonical key, which is fully readable after a rollback.
                try self.keyManager.commitStagedLocalDBKey()

                // ── Step 8: WAL checkpoint ────────────────────────────────────────────
                // Commit succeeded — flush the staged-key writes from the WAL to the
                // main file. Safe to checkpoint now because the commit is final.
                if let url = self.storeURL {
                    Self.walCheckpoint(at: url)
                }

                // ── Step 9: Delete superseded artefacts ───────────────────────────────
                self.keyManager.deleteSupersededLocalDBArtefacts()

            } catch {
                self.keyManager.rollbackStagedLocalDBKey()
                throw error
            }

            // Clear verifiers and blob metadata, then transition state.
            //
            // clearVerifiers(from: clearFrom) removes normalVerifiers[clearFrom..31]
            // and duressVerifiers[(clearFrom-1)..31], leaving shallower depths intact.
            //
            //   depth ≤ 1 (last layer): clearFrom = 1 keeps normalVerifiers[0] (master PIN)
            //             and removes the entire depth 0→1 configuration.
            //   depth ≥ 2 (expendable): clearFrom = depth keeps the first duress layer
            //             (depth 0→1) intact so the coercer still passes through it.
            let clearFrom = max(1, depth)
            config.clearVerifiers(from: clearFrom)
            config.clearBlobSlot(at: blobDepth)
            config.clearSequenceNumber(at: blobDepth)

            if depth <= 1 {
                // depth 0 (real app) or depth 1 (first duress view) — last duress layer
                // removed. Secure Mode fully off; return to pinOnly.
                config.sealedDuressVerifier = nil
                try self.setState(.normal, config: config)
                self.currentDepth = 0
            } else {
                // Expendable layer removed. Per the deactivation chain, always land at
                // depth 1 (.duress) — the convincing first-duress view must be the final
                // stop before the real app is reachable.
                try self.setState(.duress, config: config)
                self.currentDepth = 1
            }
            try self.modelContext.save()

            if depth <= 1 { self.layerStore.rewrite() }
            self.resetCounters()
        }

        // MARK: - Emergency recovery

        /// Clears Secure Mode state without performing a key rotation or re-encryption.
        ///
        /// Use only when the DB is in an inconsistent key state (e.g. a failed key
        /// rotation left contacts encrypted under a deleted staged key). Normal
        /// `deactivateSecureMode` rotates the key and restores blob contacts; this
        /// function skips both steps and simply removes the duress verifier
        /// (`isSecureModeActive` becomes `false`). The DB key stays at whatever it
        /// currently is — contacts may be unreadable if the key state is corrupted.
        func forceDeactivateForRecovery(confirmingEntryPIN: String) throws {
            let config = try self.requireConfig()
            guard config.sealedDuressVerifier != nil else { throw SecurityError.invalidStateTransition }
            guard let seKey = try self.keyManager.deriveSecureModeKey() else {
                throw SecurityError.keyDerivationFailed
            }
            // Use the master normal verifier (depth 0) for force-deactivation.
            guard config.sealedNormalVerifiers.indices.contains(0),
                  PINManager.checkVerifier(pin: confirmingEntryPIN, label: Self.normalLabel,
                                           verifier: config.sealedNormalVerifiers[0], seKey: seKey)
            else { throw SecurityError.incorrectPIN }

            // Clear everything — force deactivation resets all layers.
            config.sealedDuressVerifier = nil
            config.clearVerifiers(from: 1)  // keep normalVerifiers[0] (master PIN intact)
            config.clearBlobSlot(at: 0)
            config.clearSequenceNumber(at: 0)
            try self.setState(.normal, config: config)
            self.currentDepth = 0
            try self.modelContext.save()

            self.layerStore.rewrite()
            self.resetCounters()
        }

        // MARK: - Verify

        /// Verifies a PIN entry and drives all state transitions.
        ///
        /// Algorithm (given `currentDepth = N`):
        /// 1. Scan **all** `sealedNormalVerifiers` with `normalLabel` — first match at index K
        ///    returns `.normal(depth: K)`. This handles both the master PIN (K=0) and duress
        ///    PINs that have a routing alias written at K=N+1 during activation (enabling cold-start
        ///    routing: entering any duress PIN after a kill reaches the correct depth directly).
        /// 2. Try `sealedDuressVerifiers[N]` with `duressLabel` — match returns `.duress`
        ///    (push-down transition). This path fires only when no routing alias exists yet at
        ///    index N+1 (single-layer backward compat or pre-activation duress entry).
        /// 3. No match → `.wrong`; increment `wrongPINCount`.
        func verify(_ pin: String) throws -> PINVerifyResult {
            guard self.requiresPIN else { throw SecurityError.notConfigured }

            let config = try self.requireConfig()

            guard let seKey = try self.keyManager.deriveSecureModeKey() else {
                throw SecurityError.keyDerivationFailed
            }

            // ── Step 1: Scan all normal verifiers ────────────────────────────────────
            for (k, verifier) in config.sealedNormalVerifiers.enumerated() {
                if PINManager.checkVerifier(pin: pin, label: Self.normalLabel,
                                            verifier: verifier, seKey: seKey) {
                    self.resetCounters()
                    return .normal(depth: k)
                }
            }

            // ── Step 2: Try duress verifier at current depth ──────────────────────────
            if self.currentDepth < config.sealedDuressVerifiers.count {
                let dv = config.sealedDuressVerifiers[self.currentDepth]
                if PINManager.checkVerifier(pin: pin, label: Self.duressLabel,
                                            verifier: dv, seKey: seKey) {
                    self.wrongPINCount          = 0
                    self.consecutiveDuressCount += 1
                    return self.consecutiveDuressCount >= config.wipeThreshold() ? .wipe : .duress
                }
            }

            // ── Step 3: No match ──────────────────────────────────────────────────────
            self.consecutiveDuressCount  = 0
            self.wrongPINCount          += 1

            if self.isSecureModeActive,
               self.wrongPINCount >= PINManager.wrongPINLimit {
                return .wipe
            }
            return .wrong
        }

        /// Applies the routing-depth state transition for a verified result.
        ///
        /// Intentionally separated from `verify()` so the state mutation fires in
        /// the same synchronous context as `unlockNormal/Duress()` (inside PINEntry's
        /// gateDuration asyncAfter). SwiftUI then batches the state change and the
        /// cover dismissal into one render pass, preventing the vault tab from
        /// briefly showing a stale duress-mode render when the cover dismisses.
        func applyVerifyState(for result: PINVerifyResult) {
            switch result {
            case .normal(let depth):
                self.currentDepth = depth
                self.state        = .normal
            case .duress:
                self.currentDepth += 1
                self.state         = .duress
            case .wrong, .wipe:
                break
            }
        }

        // MARK: - PIN check (no side effects)

        /// Returns true if pin matches the current normal verifier without modifying any counters.
        /// Use this for Settings-level confirmation — not the lock-screen path.
        /// Returns true if `pin` matches the master normal verifier (depth 0).
        /// No counter mutation. Use for Settings-level confirmation, not the lock-screen path.
        func checkNormalPIN(_ pin: String) -> Bool {
            guard
                let config = try? self.modelContext.fetch(FetchDescriptor<AppLayerConfig>()).first,
                let seKey  = try? self.keyManager.deriveSecureModeKey(),
                config.sealedNormalVerifiers.indices.contains(0)
            else { return false }
            return PINManager.checkVerifier(pin: pin, label: Self.normalLabel,
                                            verifier: config.sealedNormalVerifiers[0], seKey: seKey)
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
        /// `sealedDuressVerifier` in `.duress` state, `sealedNormalVerifier` in `.normal`.
        /// This ensures a coercer at depth 1 cannot lower the gate using a PIN they don't know.
        ///
        /// - Parameter confirmingPIN: Must match the current layer's verifier.
        /// - Throws: `SecurityError.invalidStateTransition` if not in `.normal` or `.duress`.
        ///           `SecurityError.incorrectPIN` if the confirming PIN does not match.
        func disablePINFromCurrentDepth(confirmingPIN: String) throws {
            let config = try self.requireConfig()
            guard config.sealedDuressVerifier != nil else { throw SecurityError.invalidStateTransition }
            guard self.checkCurrentLayerPIN(confirmingPIN) else { throw SecurityError.incorrectPIN }
            try self.setState(self.state, pinEnabled: false, config: config)
            try self.modelContext.save()
        }

        /// Re-enables the PIN gate after it was lowered by `disablePINFromCurrentDepth`.
        ///
        /// The entered PIN is silently checked against all existing verifiers. No new verifier
        /// is created. The Settings UI uses `.setup` mode (enter + confirm) for this call,
        /// making the re-enable flow visually identical to initial PIN setup — no tell.
        ///
        /// - **Normal PIN match** → gate re-enabled at depth 0. `state` transitions to `.normal`,
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
        /// Re-enables the PIN gate by silently routing the entered PIN to its depth.
        /// Scans normal verifiers first (like `verify()` step 1), then duress verifiers.
        /// Sets `currentDepth` and `state` to match. No new verifier is written.
        @discardableResult
        func reEnablePIN(_ pin: String) -> Bool {
            guard
                let config = try? self.modelContext.fetch(FetchDescriptor<AppLayerConfig>()).first,
                let seKey  = try? self.keyManager.deriveSecureModeKey()
            else { return false }

            // Step 1: Scan normal verifiers — same logic as verify().
            for (k, verifier) in config.sealedNormalVerifiers.enumerated() {
                if PINManager.checkVerifier(pin: pin, label: Self.normalLabel,
                                            verifier: verifier, seKey: seKey) {
                    self.currentDepth = k
                    self.state        = .normal
                    try? self.setState(.normal, config: config)
                    try? self.modelContext.save()
                    return true
                }
            }

            // Step 2: Scan duress verifiers — match at K pushes to depth K+1.
            for (k, verifier) in config.sealedDuressVerifiers.enumerated() {
                if PINManager.checkVerifier(pin: pin, label: Self.duressLabel,
                                            verifier: verifier, seKey: seKey) {
                    self.currentDepth = k + 1
                    self.state        = .duress
                    try? self.setState(.duress, config: config)
                    try? self.modelContext.save()
                    return true
                }
            }

            return false
        }

        /// Checks the entered PIN against the verifier for the **current layer**, with no side effects.
        ///
        /// In `.duress` state the check is against `sealedDuressVerifier`; in all other states
        /// it is against `sealedNormalVerifier`. No counters are mutated
        /// and no state transitions occur — used by `disablePINFromCurrentDepth` and by
        /// `PINEntry.submitConfirmPhase` so the activation flow's first phase accepts the
        /// correct PIN at any depth (duress PIN in `.duress`, normal PIN otherwise).
        /// Returns true if `pin` matches the normal verifier for `currentDepth`.
        /// In `.duress` state, `sealedNormalVerifiers[currentDepth]` equals the routing alias
        /// for the duress PIN that triggered the push-down — the user's "current" PIN.
        /// No counter mutation. No state transition.
        func checkCurrentLayerPIN(_ pin: String) -> Bool {
            guard
                let config = try? self.modelContext.fetch(FetchDescriptor<AppLayerConfig>()).first,
                let seKey  = try? self.keyManager.deriveSecureModeKey(),
                config.sealedNormalVerifiers.indices.contains(self.currentDepth)
            else { return false }
            return PINManager.checkVerifier(pin: pin, label: Self.normalLabel,
                                            verifier: config.sealedNormalVerifiers[self.currentDepth],
                                            seKey: seKey)
        }

        // MARK: - Safe contacts

        /// Returns true if the contact should appear in the contact list at the current depth.
        ///
        /// Wraps `isVisible` for use with an already-fetched `Contact.Profile`, avoiding the
        /// per-identifier DB lookup cost of `isSafeContact`. Use this for list filtering.
        func isDisplayable(_ contact: Contact.Profile) -> Bool {
            Self.isVisible(contact, atDepth: self.currentDepth)
        }

        /// Returns true if the contact is visible at duress depth 1.
        /// Unknown contacts (not in DB) return false — conservative default.
        func isSafeContact(_ identifier: String) -> Bool {
            let descriptor = FetchDescriptor<Contact.Profile>(
                predicate: #Predicate { $0.identifier == identifier && $0.deletionToken == nil }
            )
            guard let contact = try? self.modelContext.fetch(descriptor).first else { return false }
            return Self.isVisible(contact, atDepth: self.currentDepth)
        }

        /// Returns identifiers of contacts visible at the given depth (defaults to `currentDepth`).
        ///
        /// Pass an explicit `depth` when querying from a context where `currentDepth` may not
        /// yet reflect the desired security level — e.g. when locking the app from `.normal`
        /// state to pre-filter the share index for the unauthenticated Share Extension process.
        func safeContactIDs(atDepth depth: Int? = nil) -> Set<String> {
            let d = depth ?? self.currentDepth
            guard let contacts = try? self.modelContext.fetch(Contact.Profile.descriptor) else { return [] }
            return Set(contacts.compactMap { Self.isVisible($0, atDepth: d) ? $0.identifier : nil })
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
            else { return false }   // non-nil field that won't decrypt = sensitive shell; exclude
            return value >= depth
        }

        // MARK: - Safe vault entries

        /// Returns true if the vault entry is visible at the current depth.
        func isEntryVisible(_ entry: VaultEntry) -> Bool {
            guard let data = entry.visibleThroughDepth else { return true }
            guard let decrypted = data.decrypt(),
                  let value = try? JSONDecoder().decode(Int.self, from: decrypted)
            else { return false }  // non-nil field that won't decrypt = sensitive shell; exclude
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

        /// A fresh random UInt32 cast to Int, used as the per-activation sequence number.
        /// Random rather than incrementing so no activation-count information persists in
        /// AppLayerConfig after deactivation clears the entry back to random filler.
        private static func randomSequenceNumber() -> Int {
            var value: UInt32 = 0
            _ = SecRandomCopyBytes(kSecRandomDefault, MemoryLayout<UInt32>.size, &value)
            return Int(value)
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
        /// Fields whose decrypt attempt returns `nil` are left unchanged. Two legitimate
        /// cases produce a nil decrypt:
        ///   1. The field is nil/empty — no data to migrate (e.g. no quantum material).
        ///   2. The field is already staged-key-encrypted — decrypt with the canonical key
        ///      naturally fails, making this call idempotent on a second pass (deactivation
        ///      Step 5 calls this after Step 4 already migrated sensitive contacts).
        ///
        /// ⚠️ Invariant: every non-nil field must be encrypted under the current canonical
        /// key when this function runs. If that invariant is violated — e.g. by a prior
        /// failed key rotation that left a field under a deleted key — the field will be
        /// silently skipped and become permanently unreadable after the new rotation
        /// commits. This is an accepted gap: storage corruption or partial-rotation
        /// state are prerequisites, both of which are beyond normal control flow.
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

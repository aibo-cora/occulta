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

        private(set) var state: RoutingDepth = .normal

        var currentDepth:      Int  { self.state.rawValue }
        var isRestricted:      Bool { self.state == .duress }

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
        ///     skips all `AppLayerConfig` reads. `requiresPIN` returns `false`, all
        ///     filtering is inert, and the PIN overlay never appears.
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

            // Feature-flag off path: skip all DB reads. requiresPIN returns false
            // (no config row), isRestricted = false. All properties stay at defaults.
            guard enabled else { return }

            let config = try? context.fetch(FetchDescriptor<AppLayerConfig>()).first

            // Restore routing depth and gate state so depth-filtering and the PIN
            // overlay behave correctly after an app kill or restart. Both fields
            // fall back to the safe default on any decode failure.
            self.state          = config?.readRoutingDepth() ?? .normal
            self.appLockEnabled = config?.readPinEnabled() ?? true
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

        // MARK: - PIN Setup

        /// Builds a normal PIN verifier, persists config, and transitions from no-PIN to PIN-only
        /// (`requiresPIN` becomes `true`, `isSecureModeActive` remains `false`).
        ///
        /// Also initialises `persistedDepth` and `pinEnabled` so both fields are non-nil
        /// from the first config write onward — a consistently present field prevents
        /// forensic tools from inferring special state from field presence or absence.
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
            try self.setState(.normal, config: config)
            self.modelContext.insert(config)
            try self.modelContext.save()

            self.resetCounters()
        }

        /// Verifies the normal PIN and removes the entire config row, making `requiresPIN` false.
        ///
        /// Throws `.invalidStateTransition` if `isSecureModeActive` is true — the caller must
        /// deactivate Secure Mode (removing the duress verifier) before removing the PIN entirely.
        func deactivatePIN(confirmingNormalPIN: String) throws {
            let config = try self.requireConfig()
            guard config.sealedDuressVerifier == nil else { throw SecurityError.invalidStateTransition }
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
            self.state = .normal
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
            // ── Step 1: State guard + PIN verification ──────────────────────────────
            guard self.requiresPIN else { throw SecurityError.invalidStateTransition }
            
            let config = try self.requireConfig()
            
            guard config.sealedDuressVerifier == nil else { throw SecurityError.invalidStateTransition }
            
            guard
                let seKey = try self.keyManager.deriveSecureModeKey()
            else {
                throw SecurityError.keyDerivationFailed
            }
            
            guard
                let verifier = config.sealedNormalVerifier,
                PINManager.checkVerifier(pin: confirmingEntryPIN, label: Self.normalLabel,
                                         verifier: verifier, seKey: seKey)
            else {
                throw SecurityError.incorrectPIN
            }

            guard !PINManager.checkVerifier(pin: duressPIN, label: Self.normalLabel,
                                            verifier: verifier, seKey: seKey)
            else { throw SecurityError.pinCollision }

            config.sealedDuressVerifier = try PINManager.buildVerifier(pin: duressPIN, label: Self.duressLabel, seKey: seKey)
            // Do NOT save the verifier yet — deferred until key rotation succeeds.
            // If anything below throws, the catch block clears this in-memory change so
            // a retry attempt doesn't hit `sealedDuressVerifier != nil` guard.

            // ── Step 2: Create staged local DB key ──────────────────────────────────
            // On any failure past this point we rollback staged artefacts.
            // stagedKey is declared here so it's in scope for the catch's rollback call.
            do {
                let stagedKey = try self.keyManager.createStagedLocalDBKey()
                // ── Step 3: Derive blob key ──────────────────────────────────────────
                guard
                    let blobKey = Manager.Blob.deriveBlobKey(from: seKey)
                else {
                    throw SecurityError.keyDerivationFailed
                }

                // ── Step 4: Classify contacts ────────────────────────────────────────
                // sensitive → blob; safe → re-encrypt in DB.
                let allProfiles = try contactManager.fetchAllContacts()
                var blobContacts:  [ContactBlobRecord] = []
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
                            ContactBlobRecord(draft: draft, signedAttributes: signedAttrs,
                                              visibleThroughDepth: depth)
                        )
                    }
                }

                // ── Step 5: Migrate nil visibleThroughDepth (should be a no-op) ─────
                for profile in safeProfiles where profile.visibleThroughDepth == nil {
                    profile.visibleThroughDepth = try JSONEncoder().encode(Int.max).encrypt()
                }

                // ── Step 6: Seal blob ────────────────────────────────────────────────
                // Vault entries are not included in the blob. Their per-entry keys (PEKs)
                // are derived from a dedicated SE key entirely independent of the local DB
                // key rotation — vault entries never need re-keying during activation or
                // deactivation. Storing raw PEK bytes in the blob would unnecessarily widen
                // the attack surface: blob compromise (SE Secure Mode key, no biometrics)
                // would also yield all vault entry symmetric keys, bypassing the biometric gate.
                let payload = BlobPayload(contacts: blobContacts)
                try Manager.Blob.seal(payload, blobKey: blobKey, directory: self.blobDirectory)

                // ── Step 8: Re-encrypt ALL contacts + vault depth fields ──────────────
                //
                // Both safe and sensitive contacts must be re-encrypted under the staged
                // key. Sensitive contacts remain in the DB (not hard-deleted); after the
                // old canonical key is deleted in Step 11, any contact still encrypted
                // under it becomes permanently unreadable. Depth-based visibility
                // (visibleThroughDepth) controls what appears in the UI — not the key.
                let stagedCrypto = StagedCryptoManager(key: stagedKey)
                let aad          = EncryptionScheme.v2_hybridPQ.aad

                for profile in allProfiles {
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
                // Clear the in-memory duress verifier so the context doesn't persist
                // a partial state — retrying activation must see nil here.
                config.sealedDuressVerifier = nil
                throw error
            }

            // Key rotation succeeded. Persist the duress verifier now that the DB
            // is fully consistent under the new canonical key.
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
            // ── Step 1: State guard + PIN verification ──────────────────────────────
            let config = try self.requireConfig()
            
            guard config.sealedDuressVerifier != nil else { throw SecurityError.invalidStateTransition }
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
            
            let payload: BlobPayload
            
            do {
                payload = try Manager.Blob.unseal(blobKey: blobKey, directory: self.blobDirectory)
            } catch {
                // Blob is missing or corrupted (e.g. overwritten by maintainNoOpBlob after 24 h).
                // Sensitive contacts that were hard-deleted during activation are unrecoverable,
                // but continuing with an empty list is strictly better than being permanently
                // stuck: safe contacts in the DB are intact and the key rotation still runs.
                payload = BlobPayload(contacts: [])
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
                    profile.visibleThroughDepth = nil
                    if let old = profile.signedAttributes, !old.isEmpty, let plain = old.decrypt() {
                        profile.signedAttributes = try AES.GCM.seal(
                            plain, using: stagedKey, authenticating: aad
                        ).combined
                    }
                    try Self.reEncryptKeyRecords(for: profile, using: stagedKey, aad: aad)

                    do {
                        let draft = try contactManager.convertToMutableCopy(using: profile.identifier)
                        try contactManager.save(contact: draft, using: stagedCrypto)
                    } catch {
                        // Sensitive shell — skip; restored from blob in Step 5.
                    }
                }

                // ── Step 5: Restore sensitive contacts from blob ────────────────────
                // Sensitive shells are still in the DB (not hard-deleted — see Step 4).
                // save(contact:using:) takes the UPDATE path, overwriting all text fields
                // with staged-key ciphertext from the blob draft. contactPublicKeys are
                // not touched by the UPDATE path, so they remain under the deleted
                // activation key. Detect this after reEncryptKeyRecords (which silently
                // skips unreadable records) and rebuild key records from blob plaintext.
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
                    try Self.reEncryptKeyRecords(for: restored, using: stagedKey, aad: aad)

                    // Rebuild key records that reEncryptKeyRecords could not decrypt
                    // (encrypted under the deleted activation key).
                    let hasUnreadableKeys = (restored.contactPublicKeys ?? []).contains {
                        $0.material != nil && $0.material?.decrypt() == nil
                    }
                    if hasUnreadableKeys {
                        restored.contactPublicKeys?.removeAll()
                        let crypto = Manager.Crypto()
                        // Resolve our identity key once for double-hash correction below.
                        let ourIdentityKey = try? self.keyManager.retrieveIdentity()
                        for key in record.draft.contactPublicKeys {
                            let encMat: Data?
                            if let mat = key.material {
                                encMat = try? crypto.encrypt(data: mat)
                            } else {
                                encMat = nil
                            }
                            // Correct the double-hash introduced by the convertToMutableCopy bug
                            // in blobs created before the fix. Old blobs store
                            // owner = SHA256(SHA256(identityKey)); the DB expects SHA256(identityKey).
                            // Detect by checking if key.owner == SHA256(SHA256(ourIdentityKey)).
                            var ownerToStore = key.owner
                            if let identityKey = ourIdentityKey {
                                let singleHash = identityKey.sha256
                                if key.owner == singleHash.sha256 {
                                    ownerToStore = singleHash
                                }
                            }
                            guard
                                let encOwner = (try? crypto.encrypt(data: ownerToStore)) ?? nil,
                                let dateData = key.acquiredAt.data(using: .utf8),
                                let encDate  = (try? crypto.encrypt(data: dateData)) ?? nil
                            else { continue }
                            restored.contactPublicKeys?.append(
                                Contact.Profile.Key(material: encMat, owner: encOwner, date: encDate)
                            )
                        }
                        // Re-encrypt freshly added records from canonical → staged.
                        try Self.reEncryptKeyRecords(for: restored, using: stagedKey, aad: aad)
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

            // Remove duress verifier, reset to normal layer, persist config, replace blob.
            config.sealedDuressVerifier = nil
            try self.setState(.normal, config: config)
            try self.modelContext.save()

            Manager.Blob.rewriteNoOpBlob()
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
            guard
                let verifier = config.sealedNormalVerifier,
                PINManager.checkVerifier(pin: confirmingEntryPIN, label: Self.normalLabel,
                                         verifier: verifier, seKey: seKey)
            else { throw SecurityError.incorrectPIN }

            config.sealedDuressVerifier = nil
            try self.setState(.normal, config: config)
            try self.modelContext.save()

            Manager.Blob.rewriteNoOpBlob()
            self.resetCounters()
        }

        // MARK: - Verify

        /// Verifies a PIN entry and drives all state transitions.
        func verify(_ pin: String) throws -> PINVerifyResult {
            guard self.requiresPIN else { throw SecurityError.notConfigured }
            
            let config = try self.requireConfig()
            
            guard let seKey = try self.keyManager.deriveSecureModeKey() else {
                throw SecurityError.keyDerivationFailed
            }

            if let verifier = config.sealedNormalVerifier,
               PINManager.checkVerifier(pin: pin, label: Self.normalLabel,
                                        verifier: verifier, seKey: seKey) {
                self.state = .normal
                self.resetCounters()
                return .normal
            }

            if let duressVerifier = config.sealedDuressVerifier,
               PINManager.checkVerifier(pin: pin, label: Self.duressLabel,
                                        verifier: duressVerifier, seKey: seKey) {
                self.wrongPINCount          = 0
                self.consecutiveDuressCount += 1
                self.state = .duress
                return self.consecutiveDuressCount >= config.wipeThreshold() ? .wipe : .duress
            }

            self.consecutiveDuressCount  = 0
            self.wrongPINCount          += 1

            if config.sealedDuressVerifier != nil,
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
        @discardableResult
        func reEnablePIN(_ pin: String) -> Bool {
            guard
                let config = try? self.modelContext.fetch(FetchDescriptor<AppLayerConfig>()).first,
                let seKey  = try? self.keyManager.deriveSecureModeKey()
            else { return false }

            // Normal PIN — restore to depth 0 (real layer).
            if let verifier = config.sealedNormalVerifier,
               PINManager.checkVerifier(pin: pin, label: Self.normalLabel, verifier: verifier, seKey: seKey) {
                try? self.setState(.normal, config: config)
                try? self.modelContext.save()
                return true
            }

            // Duress PIN — re-enable gate at depth 1 (duress layer stays active).
            if let verifier = config.sealedDuressVerifier,
               PINManager.checkVerifier(pin: pin, label: Self.duressLabel, verifier: verifier, seKey: seKey) {
                try? self.setState(.duress, config: config)
                try? self.modelContext.save()
                return true
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
            case .normal:
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

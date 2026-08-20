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

// MARK: - LockoutClock

/// Abstraction over wall-clock time and monotonic boot-relative uptime, used only by
/// the PIN lockout gate (SEC-1 fix). Injectable so tests can simulate a clock rollback
/// or a reboot deterministically, without touching the real system clock.
///
/// `now` is wall-clock time — user-adjustable via Settings, used only for *display*
/// estimates, never trusted for the actual gate. `systemUptime` is monotonic time since
/// the device last booted — unaffected by Settings changes, and can only decrease if
/// the device has actually rebooted. The lockout gate is built entirely on the latter.
protocol LockoutClock {
    var now: Date { get }
    var systemUptime: TimeInterval { get }
}

/// Production implementation — the real system clock and boot-relative uptime.
struct SystemLockoutClock: LockoutClock {
    var now: Date { Date.now }
    var systemUptime: TimeInterval { ProcessInfo.processInfo.systemUptime }
}

extension Manager {
    @Observable
    final class Security {

        // MARK: - State

        /// In-memory depth counter. Resets to 0 on every app kill — never persisted.
        /// `currentDepth > 0` means a decoy layer is active. The PIN is the routing key:
        /// after a cold start `verify()` scans all normal verifiers and sets `currentDepth`
        /// directly to the matched depth without walking through intermediate layers.
        private(set) var currentDepth: Int = 0

        /// Derived from `currentDepth` and `coercerBaseDepth` — never set manually.
        ///
        /// `.normal` — the current operator is at their home layer:
        ///   • depth 0 (real user), or
        ///   • depth == coercerBaseDepth (coercer who re-enabled the PIN with a foreign PIN).
        /// `.duress` — every other depth > 0 (decoy layer, or the coercer's own deeper layers).
        ///
        /// Making this computed eliminates an entire class of bugs where `state` could drift
        /// out of sync with `currentDepth` across the various code paths that set the depth.
        var state: RoutingDepth {
            let cbd = self.coercerBaseDepth
            return (self.currentDepth == 0 || (cbd > 0 && self.currentDepth == cbd))
                ? .normal : .duress
        }

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

        /// The depth that is the "home" layer for the current operator.
        ///
        /// For the real user this is always 0. For a coercer who re-enabled the PIN at
        /// gate-lowered depth N with a foreign PIN, this is N+1 — the depth their PIN
        /// cold-start routes them to via `sealedNormalVerifiers[N+1]`.
        ///
        /// **Why computed (not stored):**
        ///
        /// `coercerBaseDepth` only changes alongside other tracked `@Observable` properties
        /// (`pinEnabled`, `state`). SwiftUI re-renders triggered by those properties
        /// will re-read this computed property from the freshly saved config, so reactivity
        /// is preserved without maintaining a separate in-memory copy that could drift.
        ///
        /// **Why the predicate is `currentDepth == 0 || currentDepth == coercerBaseDepth`:**
        ///
        /// Using only `currentDepth == coercerBaseDepth` would break the real user after a
        /// coercion event: once `coercerBaseDepth = N+1 > 0`, the real user at depth 0
        /// sees `0 ≠ N+1` and loses the "Deactivate Protection" button and
        /// `ContactClassification`. The OR clause `currentDepth == 0` preserves
        /// depth-0 access unconditionally. The only side-effect is that an adversary at
        /// depth N where N happens to equal `coercerBaseDepth` also sees these affordances
        /// — but deactivating there only strips the coercer's layer, not the real user's
        /// sensitive contacts, so the security impact is limited.
        ///
        /// Defaults to 0 on any decode failure — the conservative, restricting choice.
        var coercerBaseDepth: Int {
            guard let config = try? self.modelContext.fetch(FetchDescriptor<AppLayerConfig>()).first
            else { return 0 }
            return config.readCoercerBaseDepth()
        }

        /// Whether the PIN overlay gate is enabled at the current depth.
        ///
        /// When `false`, the app opens without showing the PIN prompt even though all PIN
        /// verifiers remain intact. This happens when the user explicitly lowers the gate
        /// via `disablePIN(at:confirmingPIN:)` — typically under coercion while in
        /// `.normal` or `.duress` state — so that the Settings toggle shows no observable
        /// difference from a device with no PIN configured.
        ///
        /// Critically, depth-filtering still applies when the gate is down: contacts and vault
        /// entries whose `visibleThroughDepth` is set remain hidden at the stored depth,
        /// regardless of whether the PIN overlay fires on scene activation.
        ///
        /// Persisted per depth via `AppLayerConfig.pinEnabledPerDepth`. Restored in `init`.
        /// Always `true` after any clean state transition.
        private(set) var pinEnabled: Bool = true

        // MARK: - Private

        private let modelContext:    ModelContext
        private let keyManager:      any KeyManagerProtocol
        /// SwiftData store URL for WAL checkpoint during key rotation.
        /// `nil` in tests (TestKeyManager, in-memory store).
        private let storeURL:    URL?
        /// Layer store for push/pop during key rotation.
        /// Defaults to AppGroupLayerStoreBackend (production). Tests inject InMemoryLayerStoreBackend.
        private let layerStore: Manager.LayerStore
        /// Wall-clock + monotonic-uptime source for the lockout gate (SEC-1 fix).
        /// Defaults to the real system clock. Tests inject a fake to simulate clock
        /// rollback and reboot without touching the actual system clock.
        private let clock: any LockoutClock

        private static let normalLabel = Data("secure-mode-normal-pin-2026".utf8)
        private static let duressLabel = Data("secure-mode-duress-pin-2026".utf8)

        // MARK: - Init

        /// - Parameters:
        ///   - modelContainer: The shared SwiftData container.
        ///   - keyManager: Key manager implementation (injectable for testing).
        ///   - clock: Wall-clock/uptime source (injectable for testing the lockout gate).
        ///   - enabled: When `false` (feature flag `secureMode` is off), the manager
        ///     skips all `AppLayerConfig` reads. `requiresPIN` returns `false`, all
        ///     filtering is inert, and the PIN overlay never appears.
        init(modelContainer: ModelContainer,
             keyManager: any KeyManagerProtocol = Manager.Key(),
             storeURL: URL? = nil,
             layerStore: Manager.LayerStore = Manager.LayerStore(),
             clock: any LockoutClock = SystemLockoutClock(),
             enabled: Bool = true) {
            let context        = ModelContext(modelContainer)
            self.modelContext  = context
            self.keyManager    = keyManager
            self.storeURL      = storeURL
            self.layerStore    = layerStore
            self.clock         = clock

            // Feature-flag off path: skip all DB reads. requiresPIN returns false,
            // isRestricted = false. All properties stay at defaults.
            guard enabled else { return }

            // Bootstrap: ensure the Secure Mode SE key exists from the very first launch.
            //
            // Same reasoning as the config row below, applied to the one piece of this
            // subsystem that was still created lazily. `deriveSecureModeKey()` creates the
            // key on first use, and its only callers are `configurePIN` and the rotation
            // paths — so on an install that never set a PIN, the key simply does not exist.
            // Keychain items carry `kSecAttrCreationDate`, so lazy creation leaks not just
            // *whether* a PIN was ever configured but *when*. Creating it here makes both
            // facts uniform across installs: every device has it, dated at first launch.
            //
            // Deliberately discarding the result — this is a create-if-absent, not a use.
            // Nothing anywhere treats a nil return as "Secure Mode was never configured";
            // all call sites read it as a derivation failure, so seeding it changes no
            // behaviour. Silent and cheap: the key is `.privateKeyUsage` only, with no
            // biometry flag and no LAContext, so there is no prompt.
            _ = try? self.keyManager.deriveSecureModeKey()

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
                try? seed.writePersistedDepth(0)
                // pinEnabledPerDepth initialised to all-true in AppLayerConfig.init().
                // coercerBaseDepth seeded to 0 at row creation so its presence is
                // forensically constant — a field that first appears after a coercion
                // event would itself be a tell. Value 0 means "real user's depth is
                // home", which is always correct for a fresh install.
                try? seed.writeCoercerBaseDepth(0)
                context.insert(seed)
                try? context.save()
                config = seed
            }

            // Migration: ensure coercerBaseDepth is always non-nil on existing configs.
            // The field was added after the initial multi-layer release, so rows created
            // before this version have nil. Writing 0 here (the correct default — real
            // user's home is depth 0) makes the field forensically indistinguishable from
            // a freshly seeded row.
            if config.coercerBaseDepth == nil {
                try? config.writeCoercerBaseDepth(0)
                try? context.save()
            }

            // Bug 86: convert the blob-metadata arrays to the fixed-width format.
            //
            // Here rather than in `DatabaseMigration` for two reasons. This context owns the
            // AppLayerConfig row, so there is no second context whose cached copy could
            // overwrite the result. And the SE key is seeded just above, so deriving it
            // costs nothing and cannot mint a key as a side effect.
            self.migrateBlobMetadataArrays(config: config, context: context)

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

            // Migration: populate pinEnabledPerDepth from legacy scalar pinEnabled.
            // Installs created before per-layer PIN tracking have an empty array.
            // Seed all entries as `true`; if the old scalar was `false`, record that
            // at the persisted depth so the gate stays down after the upgrade.
            let persistedDepth = config.readPersistedDepth()
            if config.pinEnabledPerDepth.isEmpty {
                config.pinEnabledPerDepth = AppLayerConfig.pinEnabledFillerArray()
                // Through writePinEnabled, not a hand-rolled encode. It encodes UInt8, which
                // this array's whole design depends on: a Bool seals to 33 bytes ("false")
                // against every other entry's 29, so the disabled depth would be identifiable
                // by size alone — the exact hazard `pinEnabledFillerArray`'s doc comment
                // exists to prevent. `readPinEnabled` also decodes UInt8, so a Bool plaintext
                // was unreadable and fell back to `true`, meaning the gate this branch is
                // trying to keep down came straight back up. See Bug 86's amendment.
                if !config.readPinEnabledLegacy(), persistedDepth < config.pinEnabledPerDepth.count {
                    try? config.writePinEnabled(false, at: persistedDepth)
                }
                try? context.save()
            }

            // Restore routing depth and gate state so depth-filtering and the PIN
            // overlay behave correctly after an app kill or restart. Both fields
            // fall back to the safe default on any decode failure.
            //
            // `currentDepth` is only restored when the gate is down (`pinEnabled = false`).
            // When the gate is up, `verify()` + `applyVerifyState()` always re-establishes
            // `currentDepth` from the PIN scan, so pre-seeding it here would be wrong.
            // When the gate is down, no PIN entry occurs, so the persisted value is the
            // only source of truth — restoring it prevents the real layer from being
            // exposed after a kill/relaunch with the toggle disabled.
            self.pinEnabled = config.readPinEnabled(at: persistedDepth)
            if !self.pinEnabled { self.currentDepth = persistedDepth }

        }

        // MARK: - State transition

        /// Atomically writes routing depth and gate state to config and updates in-memory properties.
        /// The caller is responsible for calling `modelContext.save()` afterward.
        private func setState(_ depth: Int, pinEnabled: Bool = true, config: AppLayerConfig) throws {
            try config.writePersistedDepth(depth)
            try config.writePinEnabled(pinEnabled, at: depth)
            self.currentDepth = depth
            self.pinEnabled   = pinEnabled
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

        /// Converts `sealedBlobSlots` and `layerSequenceNumbers` to `LayerArrayCodec`'s
        /// fixed-width format, resizing filler to match (Bug 86).
        ///
        /// Three properties carry the safety here, and all three are load-bearing.
        ///
        /// **The key is derived once, up front, and failure aborts the whole pass.** Filler
        /// and an unreadable real entry are indistinguishable — that is exactly how
        /// `readBlobSlot` tells absence from presence — so the pass has to rewrite
        /// undecryptable elements as fresh filler, filler being what changes size. Without a
        /// good key every element looks undecryptable, all 32 entries of both arrays become
        /// filler, and every layer's blob metadata is destroyed at once on a device where
        /// nothing was wrong a moment earlier.
        ///
        /// **Every element uses that one in-memory key**, never an ambient `encrypt()`. A
        /// derived `SymmetricKey` survives a device lock; a Keychain read does not, and
        /// these items are `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
        ///
        /// **One `save()`, at the end.** SQLite transactions are atomic, so a lock mid-pass
        /// means the save fails and the next launch retries from the original bytes. Saving
        /// per element would defeat both properties above: the result would be a
        /// half-converted array with mismatched element sizes, which is this bug in a new
        /// shape. The in-memory key is what makes a complete result available at that single
        /// save; the single save is what makes a partial result impossible.
        private func migrateBlobMetadataArrays(config: AppLayerConfig, context: ModelContext) {
            // The single save() below is what makes this pass all-or-nothing; an autosave
            // firing mid-pass would commit a partially-converted array and defeat it. Same
            // idiom as the rotation paths in this file.
            context.autosaveEnabled = false
            defer { context.autosaveEnabled = true }

            guard let seKey = try? self.keyManager.deriveSecureModeKey() else { return }
            let blobKey = AppLayerConfig.blobMetadataKey(from: seKey)

            var didChange = false

            func converted(_ elements: [Data]) -> [Data] {
                elements.map { element in
                    guard let plain = element.decrypt(using: blobKey),
                          let value = LayerArrayCodec.decode(plain)
                    else {
                        // Filler, or a layer already lost — `readBlobSlot` returns nil for
                        // it either way, so deactivation already treats it as absent and
                        // replacing it destroys nothing that still worked. Left alone when
                        // it is already the right size, so the pass is idempotent rather
                        // than re-randomising all 32 entries on every launch.
                        guard element.count != LayerArrayCodec.sealedSize else { return element }
                        didChange = true
                        return AppLayerConfig.blobArrayFiller()
                    }
                    let reencoded = LayerArrayCodec.encode(value)
                    guard reencoded != plain else { return element }   // already converted
                    guard let sealed = (try? reencoded.encrypt(using: blobKey)) ?? nil else {
                        return element    // never replace a readable entry with filler
                    }
                    didChange = true
                    return sealed
                }
            }

            let slots = converted(config.sealedBlobSlots)
            let seqs  = converted(config.layerSequenceNumbers)

            guard didChange else { return }
            config.sealedBlobSlots      = slots
            config.layerSequenceNumbers = seqs
            try? context.save()
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
            try self.setState(0, config: config)
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
            try self.setState(0, config: config)
            try self.modelContext.save()
            self.resetCounters()
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

            // Derived here, before anything is staged, written or mutated (Bug 78).
            //
            // This guard first lived down at Step 8's draft/group/config pass, which was too
            // late to be worth much: by then `reencryptAllFields` had already run over every
            // contact and `modelContext.save()` had committed the result. Its `reencrypt(data:)`
            // helper returns nil for anything it cannot decrypt — deliberately, so callers
            // reinitialise — so a key outage nils `visibleThroughDepth`, `globalTrusteeDepth`,
            // `originDepth`, `signedAttributes`, `forwardSecrecyEncrypted` and both image fields
            // on every contact, writes that to disk, and only then hits the guard. Rolling back
            // the staged key does not bring those back. Losing `visibleThroughDepth` alone drops
            // the Secure Mode visibility ceiling for the whole address book.
            //
            // Deriving up front makes the failure inert: nothing is staged, so there is nothing
            // to roll back, and no row has been touched.
            guard let oldKey = try self.keyManager.createHybridLocalEncryptionKey() else {
                throw SecurityError.keyDerivationFailed
            }

            // Confirm entry PIN against the normal verifier at the current depth.
            guard depth < config.sealedNormalVerifiers.count,
                  PINManager.checkVerifier(pin: confirmingEntryPIN, label: Self.normalLabel,
                                           verifier: config.sealedNormalVerifiers[depth], seKey: seKey)
            else { throw SecurityError.incorrectPIN }

            // Duress PIN must not match ANY existing verifier (normal or duress at any depth).
            // On collision, write a dummy blob slot before throwing so the disk footprint
            // (blob file modification, WAL activity) is indistinguishable from a real activation.
            let collidesWithNormal = config.sealedNormalVerifiers.contains {
                PINManager.checkVerifier(pin: duressPIN, label: Self.normalLabel, verifier: $0, seKey: seKey)
            }
            let collidesWithDuress = config.sealedDuressVerifiers.contains {
                PINManager.checkVerifier(pin: duressPIN, label: Self.duressLabel, verifier: $0, seKey: seKey)
            }
            if collidesWithNormal || collidesWithDuress {
                self.pushDummyBlobSlot(config: config, seKey: seKey, depth: depth)
                throw SecurityError.pinCollision
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
            //   depth 1 activation → exclude slot 0 only (slot 1 doesn't exist yet)
            //   depth 2+ activation → exclude slots 0 and 1
            let blobKey        = AppLayerConfig.blobMetadataKey(from: seKey)
            let excludedSlots  = Self.protectedBlobSlots(config: config, depth: depth, blobKey: blobKey)
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
                    // Decode this contact's duress-origin floor first — a duress-origin
                    // contact (originDepth > 0) is exempt from the ceiling classification
                    // below entirely. It must never be sealed into the blob when a deeper
                    // layer activates: floor semantics (Contact+Model.swift's isVisible)
                    // keep it live and processable at every depth from its origin downward,
                    // the opposite of ceiling-classified real contacts, which get sealed
                    // away once a layer matches their ceiling exactly. Absent/undecryptable
                    // → 0 (not duress-origin), same fail-safe default as everywhere else.
                    let originDepth: Int = {
                        guard let data = profile.originDepth,
                              let plain = data.decrypt(),
                              let value = DepthCodec.decode(plain)
                        else { return 0 }
                        return value
                    }()
                    if originDepth > 0 {
                        // Always stays live, re-encrypted under the staged key in Step 8 —
                        // never blob-sealed, regardless of visibleThroughDepth.
                        safeProfiles.append(profile)
                        continue
                    }

                    // Decode the contact's visibility ceiling.
                    // nil = legacy pre-activation value; treat as Int.max (safe at all depths).
                    let contactDepth: Int = {
                        guard let data = profile.visibleThroughDepth,
                              let plain = data.decrypt(),
                              let value = DepthCodec.decode(plain)
                        else { return Int.max }
                        return value
                    }()

                    if contactDepth > depth {
                        // Safe for this activation: visible at the new deeper layer too.
                        safeProfiles.append(profile)
                    } else if contactDepth == depth {
                        // Sensitive for this layer: visible now, hidden at depth+1 → seal in blob.
                        let draft = try contactManager.convertToMutableCopy(using: profile.identifier)
                        let signedAttrs: Data? = {
                            guard let enc = profile.signedAttributes, !enc.isEmpty else { return nil }
                            return enc.decrypt()
                        }()
                        // Decode this contact's global-trustee depth stamp the same way as
                        // its visibility ceiling — undecryptable or absent → -1 (not a trustee).
                        let trusteeDepth: Int = {
                            guard let data = profile.globalTrusteeDepth,
                                  let plain = data.decrypt(),
                                  let value = DepthCodec.decode(plain)
                            else { return -1 }
                            return value
                        }()
                        // Strip images — they stay in the DB and are re-encrypted in
                        // Step 8, so the blob doesn't need to carry them. Including a
                        // contact photo can push the JSON over the 32 KB slot limit.
                        var blobDraft = draft
                        blobDraft.imageData          = nil
                        blobDraft.thumbnailImageData = nil
                        blobContacts.append(
                            LayerContact(draft: blobDraft, signedAttributes: signedAttrs,
                                         visibleThroughDepth: contactDepth,
                                         globalTrusteeDepth: trusteeDepth)
                        )
                    }
                    // contactDepth < depth: already hidden from a previous layer.
                    // Not sealed in this blob. Step 8 still re-encrypts under the staged key.
                }

                // ── Step 5: Migrate nil visibleThroughDepth / globalTrusteeDepth /
                // originDepth (should be a no-op — creation and the backfill migrations
                // already keep all three fields non-nil) ───────────────────────────────
                for profile in safeProfiles where profile.visibleThroughDepth == nil {
                    profile.visibleThroughDepth = try DepthCodec.encode(Int.max).encrypt()
                }
                for profile in safeProfiles where profile.globalTrusteeDepth == nil {
                    profile.globalTrusteeDepth = try DepthCodec.encode(-1).encrypt()
                }
                for profile in safeProfiles where profile.originDepth == nil {
                    profile.originDepth = try DepthCodec.encode(0).encrypt()
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
                let hiddenData = DepthCodec.encode(0)
                for entry in try vaultManager.fetchAllEntries() {
                    let plain = entry.visibleThroughDepth.flatMap { $0.decrypt() } ?? hiddenData
                    entry.visibleThroughDepth = try AES.GCM.seal(
                        plain, using: stagedKey, authenticating: aad
                    ).combined
                }
                try vaultManager.modelContext.save()

                // Re-key or purge Message.Draft rows — selective, matching §S7's
                // preserve-and-rekey precedent above, not a blanket wipe. Must run
                // before Step 9 commits the staged key: `oldKey` has to still be the
                // active canonical key to decrypt existing draft ciphertext.
                // `oldKey` was derived before Step 1's PIN check — see the guard there for why
                // it cannot be derived here. Skipping this pass on a missing key (which an
                // `if let` used to do) would leave groups and AppLayerConfig sealed under a key
                // Step 11 then deletes: Bugs 75 and 76 exactly, reached through the code that
                // fixes them.
                let groups = (try? contactManager.modelContext.fetch(FetchDescriptor<Group>())) ?? []
                let allGroupIdentifiers = Set(groups.compactMap { $0.readID()?.uuidString })
                try Message.Draft.reKeyOrPurgeAll(
                    safeContactIdentifiers: Set(safeProfiles.map(\.identifier)),
                    allGroupIdentifiers:    allGroupIdentifiers,
                    oldKey:  oldKey,
                    newKey:  stagedKey,
                    in:      contactManager.modelContext
                )

                // Re-key groups (Bug 75). Order is load-bearing: this must run AFTER the
                // draft pass above, never before. `readID()` decrypts with the canonical
                // key, which is still `oldKey` until Step 9 — so re-keying groups first
                // would leave every group unreadable to `readID()`, collapse
                // `allGroupIdentifiers` to the empty set, and make `reKeyOrPurgeAll`
                // delete every group-addressed draft as an unknown recipient.
                //
                // Reuses the `oldKey` already derived for the drafts rather than deriving
                // per group — the Bug 74 constraint. Groups whose ID no longer decrypts
                // are skipped inside `reencrypt`; they are orphans from a rotation that
                // predates this call and cannot be recovered here.
                for group in groups {
                    try group.reencrypt(from: oldKey, to: stagedKey)
                }
                try contactManager.modelContext.save()

                // Re-key AppLayerConfig's local-DB-key fields (Bug 76). Blob slots and
                // sequence numbers are deliberately not in here — they moved to the SE
                // key, which does not rotate. The post-commit writes below use `blobKey`
                // for exactly that reason.
                try config.reencrypt(from: oldKey, to: stagedKey)
                try self.modelContext.save()

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
            try config.writeBlobSlot(slotIndex, at: depth, using: blobKey)
            try config.writeSequenceNumber(sequenceNumber, at: depth, using: blobKey)

            // When activating from a duress depth (depth > 0), record the operator's
            // home depth and transition state to .normal so the "Deactivate Protection"
            // button becomes visible.
            //
            // coercerBaseDepth = depth (not depth+1): the operator is already AT depth
            // after entering their PIN; no future re-routing occurs. The Deactivate
            // condition is (currentDepth == coercerBaseDepth), so writing depth makes
            // currentDepth (1) == coercerBaseDepth (1) true immediately.
            //
            // For the Bug 47 coercer: reEnablePIN already wrote coercerBaseDepth = N+1
            // before the coercer re-entered at depth N+1. activateSecureMode runs with
            // depth = N+1, so this write is coercerBaseDepth = N+1 — the same value.
            // Idempotent; no regression. (Bug 58 fix, off-by-one corrected by Bug 61.)
            if depth > 0 {
                try? config.writeCoercerBaseDepth(depth)
            }

            try self.modelContext.save()
            self.resetCounters()
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

            // Derived up front for the same reason as in `activateSecureMode` (Bug 78):
            // deactivation runs the identical re-encrypt-then-save-then-commit sequence, so a
            // guard placed after Step 4 would fire only once every contact's `Data` fields had
            // already been nil-ed and written. Nothing here has been staged or mutated yet, so
            // failing at this point costs nothing.
            guard let oldKey = try self.keyManager.createHybridLocalEncryptionKey() else {
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
            let blobKey = AppLayerConfig.blobMetadataKey(from: seKey)
            if let slotIndex = config.readBlobSlot(at: blobDepth, using: blobKey),
               let expectedSeq = config.readSequenceNumber(at: blobDepth, using: blobKey) {
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
                //
                // visibleThroughDepth is re-encrypted preserving the contact's REAL
                // classification depth — never flattened to nil as a side effect of
                // deactivation. A contact classified "hide once beyond depth N" must keep
                // that exact threshold across ANY deactivation (full or a cascade that
                // only removes a deeper, unrelated layer) — otherwise a cascade exposes
                // shallower-hidden contacts, and a full deactivation erases a deeper
                // threshold the moment an intermediate layer is stripped. Step 5's
                // restoreContact overwrites this again (with the same value, from the
                // blob) for the specific contacts belonging to the layer actually being
                // removed — this loop just has to not corrupt anyone else's classification
                // in the meantime. A genuinely unclassified contact (decodes to Int.max) is
                // re-sealed as Int.max, never flattened to literal nil — every contact has
                // carried a non-nil visibleThroughDepth since creation, so nil would now
                // stand out rather than blend in. See forensic-trace-avoidance.md S6.
                //
                // Sensitive shells are re-encrypted by this loop like any other contact.
                // They are still readable here: activation never hard-deletes them, and its
                // own Step 8 re-keyed every field on every profile under the then-staged key,
                // which is the canonical key now — the staged key created above is not
                // committed until Step 7. So `fetchAllContacts()` (no depth filter, only
                // `deletionToken == nil`) is the correct set to walk.
                //
                // This was NOT always true, and the difference is worth keeping in mind
                // before treating the blob as expendable: until `reencryptAllFields` existed,
                // activation re-keyed only visibleThroughDepth, signedAttributes, and key
                // records. A sensitive shell's text fields stayed under the old canonical key,
                // which Step 11 then deleted, leaving them permanently unreadable — the blob
                // was the sole surviving copy, which is why Step 5 restores text fields from
                // blob plaintext at all. That path is now redundant on every normal cycle but
                // remains the only backstop if a field is ever stranded again, so it stays.
                //
                // A stranded field degrades quietly rather than aborting: reencryptAllFields
                // clears anything it cannot decrypt to nil instead of throwing. That is also
                // what keeps the no-hard-delete property below intact — hard-deleting an
                // unreadable shell would write a delete record to the WAL at deactivation
                // time, a forensic tell naming exactly which contacts were hidden while
                // Secure Mode was active.
                for profile in try contactManager.fetchAllContacts() {
                    // Decode the contact's current classification BEFORE re-encrypting
                    // other fields — this still uses the active OLD canonical key.
                    //
                    // Absent and undecryptable are deliberately NOT the same fallback here
                    // (Bug 87). Absent means never classified, so Int.max — safe — is right.
                    // Undecryptable means the value is *unknown*, and this loop re-seals
                    // whatever it decides into a readable field: resolving an unknown to
                    // Int.max persists "visible at every duress depth" for a contact that
                    // `isVisible` was correctly keeping hidden, irreversibly, because the
                    // original ciphertext is then gone.
                    //
                    // 0 is the fail-safe: hidden at every duress depth, still visible to the
                    // real user at depth 0. Same principle S7 states for vault entries — an
                    // entry invisible in duress mode is an inconvenience, one that is visible
                    // is a security failure.
                    let contactDepth: Int = {
                        guard let data = profile.visibleThroughDepth else { return Int.max }
                        guard let plain = data.decrypt(),
                              let value = DepthCodec.decode(plain)
                        else { return 0 }
                        return value
                    }()
                    // Same preserve-real-value treatment for the global-trustee stamp —
                    // undecryptable or absent → -1 (not a trustee), never silently dropped.
                    let trusteeDepth: Int = {
                        guard let data = profile.globalTrusteeDepth,
                              let plain = data.decrypt(),
                              let value = DepthCodec.decode(plain)
                        else { return -1 }
                        return value
                    }()
                    // Same preserve-real-value treatment for the duress-origin stamp —
                    // undecryptable or absent → 0 (not duress-origin), never silently
                    // dropped. A currently-live duress-origin contact reaches this loop
                    // (it's in the DB, not blob-sealed — see activation's Step 4 exemption)
                    // and its floor must survive deactivation exactly like a real contact's
                    // ceiling does, or it would fall back to ceiling-based classification
                    // afterward and could start rejecting bundles again.
                    let originDepth: Int = {
                        guard let data = profile.originDepth,
                              let plain = data.decrypt(),
                              let value = DepthCodec.decode(plain)
                        else { return 0 }
                        return value
                    }()

                    try profile.reencryptAllFields(to: stagedKey, aad: aad)
                    try profile.reencryptKeyRecords(to: stagedKey, aad: aad)

                    // Always re-seal, even for Int.max (safe/never-classified) contacts.
                    // Every contact has carried a non-nil visibleThroughDepth since creation
                    // (Contact+Manager.swift's "never nil" stamp) — resetting safe contacts to
                    // literal nil here would make them stand out against that baseline instead
                    // of blending into it. See forensic-trace-avoidance.md S6.
                    profile.visibleThroughDepth = try AES.GCM.seal(
                        DepthCodec.encode(contactDepth), using: stagedKey, authenticating: aad
                    ).combined
                    // Same non-nil invariant applies to the global-trustee stamp.
                    profile.globalTrusteeDepth = try AES.GCM.seal(
                        DepthCodec.encode(trusteeDepth), using: stagedKey, authenticating: aad
                    ).combined
                    // Same non-nil invariant applies to the duress-origin stamp.
                    profile.originDepth = try AES.GCM.seal(
                        DepthCodec.encode(originDepth), using: stagedKey, authenticating: aad
                    ).combined
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
                    try contactManager.restoreContact(record, using: stagedCrypto,
                                                     stagedKey: stagedKey, aad: aad)
                }
                if !payload.contacts.isEmpty {
                    try contactManager.modelContext.save()
                }

                // ── Step 6: Re-encrypt vault entry depth ceilings under the staged key ──
                // Vault entries have no blob/restore mechanism at all (see activation's
                // own comment on this), so this loop is the only thing that determines
                // their classification after a deactivation — it must preserve each
                // entry's REAL depth ceiling, mirroring Step 4's contact handling above,
                // rather than flattening every entry to nil. An entry with no depth stamp
                // (nil) needs no action: there is no ciphertext to strand under the old key.
                let allVaultEntries = try vaultManager.fetchAllEntries()
                for entry in allVaultEntries {
                    guard let data = entry.visibleThroughDepth else { continue }
                    // Undecryptable (Bug 27: corrupt/wrong-key ciphertext) → treat as
                    // hidden, matching activateSecureMode's own fallback for this field.
                    let entryDepth: Int = {
                        guard let plain = data.decrypt(),
                              let value = DepthCodec.decode(plain)
                        else { return 0 }
                        return value
                    }()
                    entry.visibleThroughDepth = try AES.GCM.seal(
                        DepthCodec.encode(entryDepth), using: stagedKey, authenticating: aad
                    ).combined
                }
                if !allVaultEntries.isEmpty {
                    try vaultManager.modelContext.save()
                }

                // ── Step 6b: Re-key drafts and groups under the staged key ───────────
                // Mirror of activation's Step 8 passes. Deactivation rotates the local DB key
                // exactly like activation does, so omitting any of them strands that model on
                // the way *out* of Secure Mode just as surely as on the way in.
                //
                // `oldKey` was derived before Step 1's PIN check — see the guard there. Runs
                // before the Step 7 commit so `oldKey` is still canonical and the writes land
                // in the WAL ahead of the checkpoint. Derived once and reused across every row
                // rather than per model (Bug 74).
                //
                // Order matters and is the same as activation's, for the same reason:
                // `readID()` decrypts with the *canonical* key, which is still `oldKey` until
                // Step 7. Re-keying groups first would make every `readID()` fail, collapse
                // `allGroupIdentifiers` to the empty set, and take `reKeyOrPurgeAll` down its
                // delete branch for every group-addressed draft.
                let groups = (try? contactManager.modelContext.fetch(FetchDescriptor<Group>())) ?? []
                let allGroupIdentifiers = Set(groups.compactMap { $0.readID()?.uuidString })

                // Drafts. Absent here until 2026-08-14, which silently destroyed every saved
                // draft on each deactivation: they stayed sealed under `oldKey`, Step 9 deleted
                // it, and the next `reKeyOrPurgeAll` took its delete branch for rows it could
                // no longer open. Found in review of the very changeset that added the group
                // and config passes above without adding this one.
                //
                // The survive set is *every* contact still present, unlike activation's, which
                // passes only the profiles that stay visible in the new layer. Nothing is
                // hidden on the way out — Step 5 has just restored the sensitive shells from
                // the blob — so a draft is purged here only when its recipient genuinely no
                // longer exists, which is what `reKeyOrPurgeAll` should do with it anyway.
                try Message.Draft.reKeyOrPurgeAll(
                    safeContactIdentifiers: Set(try contactManager.fetchAllContacts().map(\.identifier)),
                    allGroupIdentifiers:    allGroupIdentifiers,
                    oldKey:  oldKey,
                    newKey:  stagedKey,
                    in:      contactManager.modelContext
                )

                for group in groups {
                    try group.reencrypt(from: oldKey, to: stagedKey)
                }
                try contactManager.modelContext.save()

                // Same AppLayerConfig re-key as activation — deactivation rotates the
                // local DB key too, so omitting it would strand the row on the way out.
                try config.reencrypt(from: oldKey, to: stagedKey)
                try self.modelContext.save()

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

            if depth <= 1 {
                // Full deactivation — Secure Mode fully off; return to pinOnly.
                // Wipe all blob metadata in one shot: clearAllBlobMetadata() replaces
                // both arrays with fresh random filler regardless of how many layers
                // were activated above depth 0. No hardcoded indices needed.
                config.clearAllBlobMetadata()
                config.sealedDuressVerifier = nil
                try self.setState(0, config: config)
            } else {
                // Cascade deactivation — expendable layer removed. Only clear the
                // metadata for this specific layer; shallower blobs remain intact.
                // Always land at depth 1 (.duress) — the convincing first-duress view
                // must be the final stop before the real app is reachable.
                config.clearBlobSlot(at: blobDepth)
                config.clearSequenceNumber(at: blobDepth)
                try self.setState(1, config: config)
            }

            // Reset coercerBaseDepth to 0: the stripped layer is gone, so any previous
            // coercion re-enable is no longer relevant. After this deactivation, depth 0
            // is the effective home (real user) and the UI conditions
            // `currentDepth == 0 || currentDepth == coercerBaseDepth` collapse back to
            // `currentDepth == 0` — standard behaviour.
            try? config.writeCoercerBaseDepth(0)

            try self.modelContext.save()

            if depth <= 1 {
                let store = self.layerStore
                DispatchQueue.global(qos: .utility).async { store.rewrite() }
            }
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
            config.clearAllBlobMetadata()
            try self.setState(0, config: config)
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
        /// 3. No match → `.wrong`; increment persistent lockout counter; set expiry when threshold reached.
        func verify(_ pin: String) throws -> PINVerifyResult {
            guard self.requiresPIN else { throw SecurityError.notConfigured }

            let config        = try self.requireConfig()
            let currentUptime = self.clock.systemUptime

            // ── Lockout check ─────────────────────────────────────────────────────────
            // SEC-1 fix: gated on monotonic uptime, never wall-clock Date.now — Settings
            // → Date & Time changes have zero effect on systemUptime, so there's nothing
            // for that attack to bypass. The only way to move this value backward is an
            // actual reboot, and that's handled explicitly below rather than mistaken for
            // elapsed time.
            if let anchorUptime = config.readLockoutAnchorUptime() {
                let requiredDelay = Self.lockoutDelay(for: config.readLockoutCount()) ?? 0
                if currentUptime < anchorUptime {
                    // Uptime went backward — only possible if the device rebooted since
                    // this anchor was set. Re-anchor to now; the same required delay is
                    // owed again, measured from this point. A reboot buys nothing.
                    try config.writeLockoutAnchorUptime(currentUptime)
                    try self.modelContext.save()
                    return .locked(until: self.clock.now.addingTimeInterval(requiredDelay))
                }
                let elapsed = currentUptime - anchorUptime
                if elapsed < requiredDelay {
                    return .locked(until: self.clock.now.addingTimeInterval(requiredDelay - elapsed))
                }
                // Required delay has genuinely elapsed — fall through to verification.
            }

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
                    self.resetCounters()
                    return .duress
                }
            }

            // ── Step 3: No match — persist incremented counter and anchor ─────────────
            let newCount = config.readLockoutCount() + 1
            try config.writeLockoutCount(newCount)
            if Self.lockoutDelay(for: newCount) != nil {
                try config.writeLockoutAnchorUptime(currentUptime)
            }
            try self.modelContext.save()
            return .wrong
        }

        /// Incremental lockout delay for consecutive wrong attempts.
        /// Returns nil for the first 5 attempts (no lockout). Caps at 24 h from attempt 20 onward.
        static func lockoutDelay(for count: Int) -> TimeInterval? {
            switch count {
            case ..<6:  return nil
            case 6:     return 60         // 1 min
            case 7:     return 120        // 2 min
            case 8:     return 300        // 5 min
            case 9:     return 600        // 10 min
            case 10:    return 900        // 15 min
            case 11:    return 1_800      // 30 min
            case 12:    return 3_600      // 1 hr
            case 13:    return 7_200      // 2 hr
            case 14:    return 14_400     // 4 hr
            case 15:    return 21_600     // 6 hr
            case 16:    return 28_800     // 8 hr
            case 17:    return 43_200     // 12 hr
            case 18:    return 57_600     // 16 hr
            case 19:    return 72_000     // 20 hr
            default:    return 86_400     // 24 hr (attempt 20+)
            }
        }

        /// Returns an estimated wall-clock lockout-until date, for display only — the
        /// actual gate lives in `verify()` and is uptime-based; this never feeds back
        /// into it. Used by PINEntry on appear to restore a persisted lockout after an
        /// app kill. Read-only: unlike `verify()`, this never re-anchors on a detected
        /// reboot — it just reports "still locked, full delay remaining" without
        /// mutating state, since a passive display read shouldn't have side effects.
        func lockoutExpiry() -> Date? {
            guard let config        = try? self.modelContext.fetch(FetchDescriptor<AppLayerConfig>()).first,
                  let anchorUptime  = config.readLockoutAnchorUptime(),
                  let requiredDelay = Self.lockoutDelay(for: config.readLockoutCount())
            else { return nil }

            // A negative delta (uptime decreased — device rebooted since the anchor was
            // set) is clamped to 0 elapsed: still locked for the full remaining delay,
            // matching what verify() would do without this read needing to write anything.
            let elapsed = max(0, self.clock.systemUptime - anchorUptime)
            guard elapsed < requiredDelay else { return nil }
            return self.clock.now.addingTimeInterval(requiredDelay - elapsed)
        }

        /// Applies the routing-depth state transition for a verified result.
        ///
        /// Intentionally separated from `verify()` so the state mutation fires in
        /// the same synchronous context as the onAuthenticated/onDuress callbacks (inside
        /// PINEntry's timingPadDuration asyncAfter). SwiftUI then batches currentDepth and
        /// pinDidSucceed() into one render pass, preventing a stale duress-mode render
        /// from briefly appearing when the content transitions to .unlocked.
        func applyVerifyState(for result: PINVerifyResult) {
            switch result {
            case .normal(let depth): self.currentDepth = depth
            case .duress:
                self.currentDepth += 1
                self.purgeDraftsNotSafeAtCurrentDepth()
            case .wrong, .locked:    break
            }
        }

        /// Defense in depth alongside `reKeyOrPurgeAll` at activation (`Message+Draft.swift`):
        /// activation only purges at layer *creation*, not at every later entry into an
        /// already-created layer. A contact classified sensitive sometime after that layer
        /// was set up — with a draft saved before this pass existed, or before the sensitivity
        /// gate was in place — would otherwise keep that draft across any number of duress-PIN
        /// entries. Called after `currentDepth` has already advanced, so `isVisible` checks
        /// against the depth actually being entered.
        ///
        /// No key rotation happens at entry into an existing layer (only at activation), so
        /// this reuses `reKeyOrPurgeAll` with `oldKey == newKey` — surviving rows are re-sealed
        /// under an identical key with a fresh nonce, a no-op in effect, not a new crypto path —
        /// to get the exact same, already-reviewed survive/purge semantics rather than a second
        /// implementation of them.
        private func purgeDraftsNotSafeAtCurrentDepth() {
            guard let key = try? Manager.Key().createHybridLocalEncryptionKey() else { return }
            let profiles = (try? self.modelContext.fetch(
                FetchDescriptor<Contact.Profile>(predicate: #Predicate { $0.deletionToken == nil })
            )) ?? []
            let safeIdentifiers = Set(profiles.filter { $0.isVisible(atDepth: self.currentDepth, usingKey: key) }.map(\.identifier))
            let allGroupIdentifiers = Set(
                ((try? self.modelContext.fetch(FetchDescriptor<Group>())) ?? [])
                    .compactMap { $0.readID()?.uuidString }
            )
            try? Message.Draft.reKeyOrPurgeAll(
                safeContactIdentifiers: safeIdentifiers, allGroupIdentifiers: allGroupIdentifiers,
                oldKey: key, newKey: key, in: self.modelContext
            )
            self.checkpointStore()
        }

        /// Forces a WAL checkpoint on the persistent store after a `Message.Draft` purge.
        /// `PRAGMA secure_delete = ON` (`OccultaApp.swift`) only zeroes a page's content for
        /// the write that frees it — an earlier, un-checkpointed WAL frame from before the
        /// purge can still hold the real, recoverable ciphertext, decryptable by whatever key
        /// is still live, since none of these purge call sites rotates any key (only activation
        /// does). Matches what `activateSecureMode` already does after its own commit (below).
        ///
        /// Not `private`: `ContactManager` already holds a `security: Manager.Security`
        /// reference (`Contact+Manager.swift`) and calls this from its own purge sites
        /// (`setVisibility`, `saveClassification`) — reusing this rather than a third copy
        /// of the same SQLite pragma call.
        ///
        /// Must run unconditionally, every call, not only when a purge actually happened —
        /// same principle `cleanUpGroupDuressMembership` already applies to its own ciphertext
        /// refresh: a checkpoint that only fires when something was purged would turn
        /// checkpoint timing itself into the exact kind of differential signal this exists
        /// to remove.
        /// Moves blob metadata written under an old local DB key onto the SE-derived key that
        /// now seals it (Bug 76). No-op once every live entry has been moved, so it is safe on
        /// every launch and needs no completion flag — the same reasoning as the orphaned-group
        /// purge: a `UserDefaults` key naming this migration would advertise that blob metadata
        /// exists at all.
        ///
        /// Must run before the next activation or deactivation. Until it does, a still-live
        /// blob index reads as absent, which would silently orphan a blob that is currently
        /// perfectly reachable.
        ///
        /// Both keys are derived once here rather than per entry — Bug 74's constraint.
        func migrateBlobMetadataKeyIfNeeded() {
            guard let config = try? self.modelContext.fetch(FetchDescriptor<AppLayerConfig>()).first,
                  let seKey  = try? self.keyManager.deriveSecureModeKey(),
                  let dbKey  = try? self.keyManager.createHybridLocalEncryptionKey()
            else { return }

            let moved = config.migrateBlobMetadata(
                fromLocalDBKey: dbKey,
                toBlobKey:      AppLayerConfig.blobMetadataKey(from: seKey)
            )
            if moved {
                try? self.modelContext.save()
            }
            // Unconditional, per `checkpointStore()`'s own rule (Bug 79): a checkpoint that
            // fired only when something moved would make checkpoint timing itself the signal
            // for "this install still had pre-migration blob metadata". The `save()` above
            // stays conditional — there is genuinely nothing to write when nothing moved.
            self.checkpointStore()
        }

        func checkpointStore() {
            guard let url = self.storeURL else { return }
            Self.walCheckpoint(at: url)
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

        /// Lowers the PIN overlay gate at `depth` while keeping all verifiers and depth-filtering intact.
        ///
        /// After this call:
        /// - `pinEnabled` is `false` — the app opens without showing the PIN overlay.
        /// - `currentDepth` is unchanged — depth-filtering (hidden contacts and vault entries)
        ///   continues to apply, so a coerced device still shows the duress view.
        /// - All PIN verifiers are intact — the user can call `reEnablePIN(_:)` to restore the
        ///   gate without entering the setup flow again.
        ///
        /// The confirming PIN must match the verifier for the **current layer**:
        /// `sealedDuressVerifier` in `.duress` state, `sealedNormalVerifier` in `.normal`.
        /// This ensures a coercer at depth 1 cannot lower the gate using a PIN they don't know.
        ///
        /// - Parameters:
        ///   - depth: The depth whose gate is being lowered. Pass `currentDepth`.
        ///   - confirmingPIN: Must match the current layer's verifier.
        /// - Throws: `SecurityError.invalidStateTransition` if Secure Mode is not active.
        ///           `SecurityError.incorrectPIN` if the confirming PIN does not match.
        func disablePIN(at depth: Int, confirmingPIN: String) throws {
            let config = try self.requireConfig()
            
            guard config.sealedDuressVerifier != nil else { throw SecurityError.invalidStateTransition }
            guard self.checkCurrentLayerPIN(confirmingPIN) else { throw SecurityError.incorrectPIN }
            
            try self.setState(depth, pinEnabled: false, config: config)
            try self.modelContext.save()
        }

        /// Re-enables the PIN gate after it was lowered by `disablePIN(at:confirmingPIN:)`.
        ///
        /// The Settings UI always uses `.setup` mode (enter + confirm two matching entries),
        /// making this flow visually identical to initial PIN setup from the coercer's
        /// perspective — no observable tell from whichever branch fires.
        ///
        /// **Three outcomes, all indistinguishable to the caller:**
        ///
        /// 1. **Known PIN match (step-1 normal scan)** — the entered PIN matches an existing
        ///    normal verifier at index K. Gate re-enabled; `currentDepth` set to K, `state`
        ///    to `.normal`. The operator returns to their actual authenticated layer.
        ///
        /// 2. **Known PIN match (step-2 duress scan)** — the entered PIN matches an existing
        ///    duress verifier at index K. Gate re-enabled; `currentDepth` set to K+1, `state`
        ///    to `.duress`. The operator continues in the decoy view they were already in.
        ///
        /// 3. **Unknown PIN at depth > 0 — coercion acceptance (Bug 37 fix)** — the entered
        ///    PIN matches nothing AND `currentDepth > 0` (gate was lowered while in a duress
        ///    or coercer layer). Rather than returning `false` (which would leave the toggle
        ///    OFF — a tell that existing verifiers are present), the system silently accepts
        ///    the PIN as a new layer. See the "Coercion acceptance" block below for details.
        ///
        /// 4. **Unknown PIN at depth 0** — returns `false`. At depth 0 the coercion
        ///    acceptance path is not triggered because depth 0 is the real user's layer; a
        ///    foreign PIN there should not silently create a new verifier without key rotation.
        ///    This leaves the known tell at depth 0 (Bug 37 scope), which is accepted as
        ///    a low-severity edge case requiring more extreme prior coercion to reach.
        ///
        /// Returns `Bool` rather than throwing so callers can stay in the `.setup` sheet
        /// without catching errors through the sheet hierarchy.
        @discardableResult
        func reEnablePIN(_ pin: String) -> Bool {
            guard
                let config = try? self.modelContext.fetch(FetchDescriptor<AppLayerConfig>()).first,
                let seKey  = try? self.keyManager.deriveSecureModeKey()
            else { return false }

            // ── Step 1: Scan all normal verifiers (same ordering as verify()) ────────
            // A match at index K means the entered PIN is that layer's routing PIN.
            // Route to that depth and re-enable the gate.
            for (k, verifier) in config.sealedNormalVerifiers.enumerated() {
                if PINManager.checkVerifier(pin: pin, label: Self.normalLabel,
                                            verifier: verifier, seKey: seKey) {
                    try? self.setState(k, config: config)
                    try? self.modelContext.save()
                    return true
                }
            }

            // ── Step 2: Scan all duress verifiers ────────────────────────────────────
            // A match at index K means the entered PIN is the push-down from depth K to K+1.
            for (k, verifier) in config.sealedDuressVerifiers.enumerated() {
                if PINManager.checkVerifier(pin: pin, label: Self.duressLabel,
                                            verifier: verifier, seKey: seKey) {
                    try? self.setState(k + 1, config: config)
                    try? self.modelContext.save()
                    return true
                }
            }

            // ── Coercion acceptance (Bug 37 fix) ──────────────────────────────────────
            //
            // The entered PIN matched nothing. At depth 0, return false — creating a new
            // verifier at depth 0 without a full key rotation is not safe (and reaching
            // this path at depth 0 requires the coercer to already have the master PIN,
            // making it a minor remaining tell).
            //
            // At depth N > 0, returning false leaves the toggle OFF. The coercer observes:
            //   - In genuine `.noPIN` → `.pinOnly` setup: any PIN succeeds, toggle flips ON.
            //   - Here: PIN entered twice, sheet closed, toggle stays OFF.
            // This asymmetry reveals that verifiers already exist — i.e. Secure Mode is
            // running and the gate was deliberately lowered. The fix: silently create a new
            // layer for the coercer's PIN so the toggle always flips ON.
            //
            // What "creating a new layer" means:
            //   • `sealedDuressVerifiers[N]` — the push-down verifier: entering PIN C from
            //     depth N advances to depth N+1. Built with duressLabel.
            //   • `sealedNormalVerifiers[N+1]` — the routing alias: cold-start entry of
            //     PIN C matches here and routes directly to depth N+1 (state = .normal),
            //     exactly as if the coercer is at their "depth 0". Built with normalLabel
            //     (same label as all other normal verifiers so the step-1 scan in verify()
            //     finds it consistently).
            //   • `coercerBaseDepth = N+1` — records the coercer's home depth so the UI
            //     can present a fully functional Secure Mode experience from that depth
            //     (deactivation button, ContactClassification). See AppLayerConfig field docs.
            //
            // No DB key rotation is performed. The coercer's layer uses the same canonical
            // key as the existing stack. Key rotation is only needed when the user wants
            // to cryptographically hide contacts from a lower-depth examiner; the coercer
            // here is operating inside the already-restricted duress view and has no access
            // to the hidden contacts regardless.
            //
            // No blob is sealed. The blob is only needed for deactivation (to restore
            // sensitive contacts). The "Deactivate Protection" UI at the coercer's depth
            // is gated on `coercerBaseDepth`, and deactivating the coercer's own layer
            // (depth N+1) uses the existing layer store infrastructure from activateSecureMode;
            // the coercion-acceptance path itself is lightweight.
            guard self.currentDepth > 0 else { return false }

            guard
                let duressVerifier = try? PINManager.buildVerifier(pin: pin, label: Self.duressLabel, seKey: seKey),
                let routingAlias   = try? PINManager.buildVerifier(pin: pin, label: Self.normalLabel, seKey: seKey)
            else { return false }

            config.writeDuressVerifier(duressVerifier, at: self.currentDepth)
            config.writeNormalVerifier(routingAlias,   at: self.currentDepth + 1)

            // Record the coercer's home depth. UI checks use
            //   `currentDepth == 0 || currentDepth == coercerBaseDepth`
            // so this does not affect the real user at depth 0.
            try? config.writeCoercerBaseDepth(self.currentDepth + 1)

            // Re-enable the gate. State stays .duress (we are at a depth above 0);
            // currentDepth is unchanged (still N — the gate fires on next foreground and
            // verify() will set currentDepth = N+1 when the coercer enters PIN C).
            try? self.setState(self.currentDepth, pinEnabled: true, config: config)
            try? self.modelContext.save()
            return true
        }

        /// Checks the entered PIN against the verifier for the **current layer**, with no side effects.
        ///
        /// Primary check: `sealedNormalVerifiers[currentDepth]` with `normalLabel`.
        /// At depth 0 this is the master PIN. At depth > 0 this is the routing alias
        /// (duress PIN re-verified via `normalLabel`) written during activation.
        ///
        /// Fallback (depth > 0 only): `sealedDuressVerifiers[currentDepth - 1]` with
        /// `duressLabel`. Fires when the routing alias is absent — configs created before
        /// routing aliases were introduced, or migrated from scalar fields, hit this path.
        ///
        /// No counter mutation. No state transition.
        func checkCurrentLayerPIN(_ pin: String) -> Bool {
            guard
                let config = try? self.modelContext.fetch(FetchDescriptor<AppLayerConfig>()).first,
                let seKey  = try? self.keyManager.deriveSecureModeKey()
            else { return false }

            let depth = self.currentDepth

            if config.sealedNormalVerifiers.indices.contains(depth),
               PINManager.checkVerifier(pin: pin, label: Self.normalLabel,
                                        verifier: config.sealedNormalVerifiers[depth],
                                        seKey: seKey) {
                return true
            }

            let duressIdx = depth - 1
            guard depth > 0, config.sealedDuressVerifiers.indices.contains(duressIdx) else {
                return false
            }
            return PINManager.checkVerifier(pin: pin, label: Self.duressLabel,
                                            verifier: config.sealedDuressVerifiers[duressIdx],
                                            seKey: seKey)
        }

        // MARK: - Safe vault entries

        /// Returns true if the vault entry is visible at the current depth.
        ///
        /// Exact-depth match, not a ceiling: an entry is visible only at the exact
        /// depth it was created at (`nil` = never classified, always visible — see
        /// `VaultManager.addEntry`). Deliberately not `value >= currentDepth` — see
        /// `Docs/Bugs/v1.10.0/Vault-Entries-Created-At-A-Duress-Depth-Leak-Into-The-Real-Vault.md`
        /// for why a ceiling lets an entry created at a duress depth leak into every
        /// shallower depth, including the real depth 0.
        func isEntryVisible(_ entry: VaultEntry) -> Bool {
            guard let data = entry.visibleThroughDepth else { return true }
            guard let decrypted = data.decrypt(),
                  let value = DepthCodec.decode(decrypted)
            else { return false }  // non-nil field that won't decrypt = sensitive shell; exclude
            return value == self.currentDepth
        }

        // MARK: - Private

        private func requireConfig() throws -> AppLayerConfig {
            guard let config = try self.modelContext.fetch(FetchDescriptor<AppLayerConfig>()).first else {
                throw SecurityError.notConfigured
            }
            return config
        }

        private func resetCounters() {
            if let config = try? self.modelContext.fetch(FetchDescriptor<AppLayerConfig>()).first {
                config.resetLockout()
                try? self.modelContext.save()
            }
        }

        /// Blob slots a new activation must never overwrite: the real layer (depth 0) and
        /// the first duress layer (depth 1). Depth-2+ blobs are expendable and stay in the
        /// random pool so it remains as large as possible. This is the Bug 46 guarantee.
        ///
        /// An unreadable slot index is skipped, not treated as an error. Two reasons a read
        /// returns nil, and neither is worth failing an activation over:
        ///
        /// • **No blob exists at that depth.** `reEnablePIN`'s coercion-acceptance path
        ///   creates a layer with no key rotation and no blob push, leaving that depth's
        ///   entry as random filler indefinitely. There is nothing to protect.
        ///
        /// • **The index was stranded by a key rotation** (Bug 76 — `AppLayerConfig` is not
        ///   re-keyed, so an entry written before a rotation is sealed under a key that
        ///   Step 11 has since deleted). This looks like the dangerous case but is not:
        ///   `deactivateSecureMode` locates the blob to pop through this same
        ///   `readBlobSlot(at:using:)` call, and nothing ever rewrites a stranded index —
        ///   `writeBlobSlot(_:at:using:)` only ever writes the activating depth's own entry,
        ///   a depth-0 activation is blocked while Secure Mode is active, and `clearBlobSlot`
        ///   writes filler. Once nil, always nil. So a blob whose index is stranded is already
        ///   unreachable, and excluding its slot preserves a payload no code path can read.
        ///   The contacts it holds are in the DB regardless, re-keyed by every rotation and
        ///   never hard-deleted.
        ///
        ///   Since blob metadata moved to the non-rotating SE-derived key
        ///   (`AppLayerConfig.blobMetadataKey(from:)`), rotation can no longer produce this
        ///   case at all — it now means genuine corruption, or an install whose migration has
        ///   not run. Skipping stays the right response either way.
        ///
        /// Refusing to activate here would be strictly worse: it costs the user a real decoy
        /// layer, in the coercion scenario the feature exists for, to protect nothing.
        ///
        /// Static and non-private so the exclusion logic can be unit tested directly; it
        /// reads nothing from `self`.
        static func protectedBlobSlots(config: AppLayerConfig, depth: Int, blobKey: SymmetricKey) -> Set<Int> {
            // Activation at depth 0 creates the first layer — there is nothing to protect yet.
            guard depth > 0 else { return [] }

            return Set((0..<min(depth, 2)).compactMap { config.readBlobSlot(at: $0, using: blobKey) })
        }

        /// A fresh random UInt32 cast to Int, used as the per-activation sequence number.
        /// Random rather than incrementing so no activation-count information persists in
        /// AppLayerConfig after deactivation clears the entry back to random filler.
        // Writes a random-noise payload to a non-excluded blob slot so that a pinCollision
        // produces the same filesystem footprint as a real activation (blob file modified,
        // same fixed ciphertext size). Called before throwing pinCollision.
        private func pushDummyBlobSlot(config: AppLayerConfig, seKey: SymmetricKey, depth: Int) {
            guard let layerKey = self.layerStore.deriveKey(from: seKey) else { return }
            let excludedSlots = Self.protectedBlobSlots(
                config: config, depth: depth, blobKey: AppLayerConfig.blobMetadataKey(from: seKey)
            )
            let slotIndex = self.layerStore.randomSlot(excluding: excludedSlots)
            let payload   = LayerPayload(
                sequenceNumber: Self.randomSequenceNumber(),
                slotIndex:      slotIndex,
                contacts:       []
            )
            try? self.layerStore.push(payload, key: layerKey, slotIndex: slotIndex)
        }

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
    func sign(data: Data?) throws -> String                                  { "" }
}

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
import OccultaFormats

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

        /// Identifies the unlocked session at the current depth (`bugs.md` Bug 140). Changes
        /// whenever `currentDepth` changes while the app stays unlocked (`setState`, from
        /// `deactivateSecureMode`): `RootView` keys the unlocked view tree by it and resets the
        /// session state it holds above that tree, so nothing from the old depth reaches the new
        /// one. A PIN unlock needs no change: the PIN screen already tears the tree down, and
        /// `RootView` resets its state on leaving `.unlocked`.
        private(set) var sessionID = UUID()

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
             keyManager: any KeyManagerProtocol = Manager.Ambient.keyManager,
             storeURL: URL? = nil,
             clock: any LockoutClock = SystemLockoutClock(),
             enabled: Bool = true) {
            let context        = ModelContext(modelContainer)
            self.modelContext  = context
            self.keyManager    = keyManager
            self.storeURL      = storeURL
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
            let depthChanged  = depth != self.currentDepth
            self.currentDepth = depth
            self.pinEnabled   = pinEnabled
            if depthChanged { self.sessionID = UUID() }
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

        /// Creates a new duress layer: verifies the caller is legitimately at the current
        /// depth, rejects a colliding duress PIN, and writes the new depth's verifiers.
        ///
        /// **Removal Stage 1, 2026-09-10 (`plan.md`, "Removal — Stage 0: design decision").**
        /// No longer touches `Contact.Profile`, `VaultEntry`, `Message.Draft`, `Group`, or
        /// `AppLayerConfig`'s local-DB-key fields at all — there is no blob to seal sensitive
        /// contacts into and no staged key to re-encrypt anything under, because nothing is
        /// classified or re-keyed at activation any more. A contact's `visibleThroughDepth`
        /// is a standing property set independently via `ContactManager.setVisibility`,
        /// unrelated to the PIN lifecycle. This function's only job now is PIN state.
        /// No longer `async` — nothing left needs it.
        func activateSecureMode(confirmingEntryPIN: String, duressPIN: String) throws {
            // Prevent accidental mid-sequence autosaves on this context between the
            // several config mutations below and the explicit save at the end.
            self.modelContext.autosaveEnabled = false
            defer { self.modelContext.autosaveEnabled = true }

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
            // The old dummy-blob-slot write on collision is gone along with the blob itself —
            // there is no disk footprint left to make indistinguishable from a real activation.
            let collidesWithNormal = config.sealedNormalVerifiers.contains {
                PINManager.checkVerifier(pin: duressPIN, label: Self.normalLabel, verifier: $0, seKey: seKey)
            }
            let collidesWithDuress = config.sealedDuressVerifiers.contains {
                PINManager.checkVerifier(pin: duressPIN, label: Self.duressLabel, verifier: $0, seKey: seKey)
            }
            if collidesWithNormal || collidesWithDuress {
                throw SecurityError.pinCollision
            }

            let duressVerifier = try PINManager.buildVerifier(pin: duressPIN, label: Self.duressLabel, seKey: seKey)
            // The routing alias is the SAME duress PIN built with normalLabel so that
            // verify()'s step-1 scan (which uses normalLabel for all entries) can find it
            // at cold start without walking through intermediate depths.
            let routingAlias = try PINManager.buildVerifier(pin: duressPIN, label: Self.normalLabel, seKey: seKey)

            config.writeDuressVerifier(duressVerifier, at: depth)
            config.writeNormalVerifier(routingAlias, at: depth + 1)
            // Depth-0 scalar (isSecureModeActive / requiresPIN flags).
            if depth == 0 {
                config.sealedDuressVerifier = duressVerifier
            }

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

        /// Verifies the normal PIN and removes the duress verifier for this depth
        /// (`isSecureModeActive` becomes `false` if this was the last layer).
        ///
        /// **Removal Stage 1, 2026-09-10 (`plan.md`, "Removal — Stage 0: design decision").**
        /// No longer touches `Contact.Profile`, `VaultEntry`, `Message.Draft`, `Group`, or
        /// `AppLayerConfig`'s local-DB-key fields — nothing was ever sealed away or re-keyed
        /// at activation any more, so there is nothing to restore or reverse-rotate here.
        /// The one thing this function still owns is PIN/verifier state, exactly like
        /// `activateSecureMode`. No longer `async`.
        func deactivateSecureMode(confirmingEntryPIN: String) throws {
            self.modelContext.autosaveEnabled = false
            defer { self.modelContext.autosaveEnabled = true }

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

            // Clear verifiers and transition state.
            //
            // clearVerifiers(from: clearFrom) removes normalVerifiers[clearFrom..31]
            // and duressVerifiers[(clearFrom-1)..31], leaving shallower depths intact.
            //
            //   depth ≤ 1 (last layer): clearFrom = 1 keeps normalVerifiers[0] (master PIN)
            //             and removes the entire depth 0→1 configuration.
            //   depth ≥ 2 (expendable): clearFrom = depth keeps every shallower layer
            //             (0 through depth-1) intact — only the popped layer's own
            //             verifiers are removed.
            let clearFrom = max(1, depth)
            config.clearVerifiers(from: clearFrom)
            self.orphanVaultEntries(freedFrom: clearFrom)
            self.orphanBackupKeys(freedFrom: clearFrom)

            // LIFO pop: land exactly one depth shallower than the layer just removed,
            // never further. Every verifier for depths 0..depth-2 is untouched by the
            // clear above, so that shallower stack is still fully intact and correctly
            // becomes the new home. depth ≤ 1 has nowhere shallower than 0 to land —
            // that is also a full deactivation, so the duress scalar clears too.
            let newDepth = max(0, depth - 1)
            if newDepth == 0 {
                config.sealedDuressVerifier = nil
            }
            try self.setState(newDepth, config: config)

            // coercerBaseDepth becomes the depth just landed on, mirroring
            // activateSecureMode's own write (Bug 58/61) — 0 after a full deactivation
            // (the real user's own home), or the popped-to depth after a cascade pop, so
            // "Deactivate Protection" is reachable there immediately without a separate
            // re-verify to re-establish `state == .normal`.
            try? config.writeCoercerBaseDepth(newDepth)

            try self.modelContext.save()
            self.resetCounters()
        }

        // MARK: - Emergency recovery

        /// Clears every layer's verifiers unconditionally, authorized by the master PIN only.
        ///
        /// Unlike `deactivateSecureMode` — which verifies against the *current* depth's
        /// verifier and only cascades from that depth downward, leaving shallower layers
        /// intact — this always authenticates against `sealedNormalVerifiers[0]` and wipes
        /// every layer in one call, regardless of `currentDepth`. An emergency full reset,
        /// not a per-layer deactivation.
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
            self.orphanVaultEntries(freedFrom: 1)
            self.orphanBackupKeys(freedFrom: 1)
            try self.setState(0, config: config)
            try self.modelContext.save()

            self.resetCounters()
        }

        /// Orphans any `VaultEntry` whose duress-depth stamp names a depth `clearFrom` or
        /// deeper — depths a deactivation (or force-deactivation) just freed. Bug 110
        /// (`bugs.md`): depth *numbers* are reused across unrelated duress sessions (a
        /// fresh activation always counts back up 1, 2, 3... the same way, and
        /// deactivation always returns to 0 or one level shallower), so without this an
        /// entry created in one session stays exact-match-visible
        /// (`VaultEntry.isVisible`) to a later, unrelated session that reaches the same
        /// depth number.
        ///
        /// Marks `deletionToken` rather than touching `visibleThroughDepth` — see that
        /// field's own doc comment (`Vault+Model.swift`) for why: exclusion from
        /// `fetchAllEntries()` makes the entry inert everywhere at once (UI, shard
        /// custody, backup export), not just hidden from one depth's view, and
        /// `visibleThroughDepth` is left as a historical record of the depth the entry
        /// was actually created at.
        ///
        /// Not gated on Secure Mode's own injected key manager — `VaultEntry` fields are
        /// always sealed under the ambient real key (`Manager.Ambient`), the same
        /// key-manager split `purgeDraftsNotSafeAtCurrentDepth` already documents. Derives
        /// that key once and reuses it for every entry checked and orphaned, rather than
        /// paying a Secure Enclave round trip per row.
        private func orphanVaultEntries(freedFrom clearFrom: Int) {
            guard let key = try? Manager.Ambient.keyManager.createHybridLocalEncryptionKey() else { return }
            let allEntries = (try? self.modelContext.fetch(FetchDescriptor<VaultEntry>())) ?? []

            var toOrphan: [VaultEntry] = []
            var alreadyOrphaned: [VaultEntry] = []
            for entry in allEntries {
                if entry.isOrphaned(usingKey: key) {
                    alreadyOrphaned.append(entry)
                    continue
                }
                guard let data  = entry.visibleThroughDepth,
                      let plain = data.decrypt(using: key),
                      let value = DepthCodec.decode(plain),
                      value >= clearFrom
                else { continue }
                toOrphan.append(entry)
            }
            guard !toOrphan.isEmpty else { return }

            // Cap: 50 orphaned rows total, oldest evicted first — mirrors
            // Contact.Profile.deletionToken's own cap (Contact+Manager.swift). Both lists
            // sorted by creation date: an unsorted fetch can return `toOrphan` in any
            // order, and processing it oldest-first is what keeps `alreadyOrphaned`
            // correctly ordered as newly-orphaned entries are appended to it below.
            alreadyOrphaned.sort { $0.createdAt < $1.createdAt }
            toOrphan.sort { $0.createdAt < $1.createdAt }
            let sealedOrphanToken = try? VaultEntry.orphanedToken.encrypt(using: key)
            for entry in toOrphan {
                if alreadyOrphaned.count >= 50 {
                    self.modelContext.delete(alreadyOrphaned.removeFirst())
                }
                entry.deletionToken = sealedOrphanToken
                alreadyOrphaned.append(entry)
            }
        }

        /// Orphans any `BackupEncryptionKey` row whose depth stamp names a depth
        /// `clearFrom` or deeper — the BEK-side twin of `orphanVaultEntries`, closing
        /// the same class of gap (Bug 110's own bug, applied to backup keys instead
        /// of vault entries): without this, a depth's old backup key and trustee list
        /// survive deactivation untouched, and a later, unrelated duress session
        /// reactivating at the same depth number inherits it — fully configured, with
        /// trustees nobody in the new session ever picked. Filed and fixed together,
        /// same commit as the BEK-to-database migration this method belongs to.
        ///
        /// No cap, no eviction — unlike `orphanVaultEntries`'s 50-row cap. A
        /// `BackupEncryptionKey` row is only ever created by an explicit "set up
        /// backup at this depth" action, not everyday use, so the population this
        /// orphans grows far more slowly than vault entries do; unbounded growth past
        /// the 32-row filler baseline is accepted as simpler than reusing the
        /// cap-and-evict shape for a population that rarely needs it.
        ///
        /// Sealed under the local DB key, same as `orphanVaultEntries` and for the
        /// identical reason: this runs from `deactivateSecureMode`/
        /// `forceDeactivateForRecovery`, neither of which ever derives the vault key.
        /// Skips filler rows (`isUnclaimed`) the same way it skips already-orphaned
        /// ones — neither is a live row this depth-freeing event could possibly apply
        /// to.
        private func orphanBackupKeys(freedFrom clearFrom: Int) {
            guard let key = try? Manager.Ambient.keyManager.createHybridLocalEncryptionKey() else { return }
            let allRows = (try? self.modelContext.fetch(FetchDescriptor<BackupEncryptionKey>())) ?? []
            let sealedOrphanToken = try? BackupEncryptionKey.orphanedToken.encrypt(using: key)

            for row in allRows {
                guard !row.isOrphaned(usingKey: key), !row.isUnclaimed(usingKey: key) else { continue }
                guard let data  = row.depth, let plain = data.decrypt(using: key),
                      let value = DepthCodec.decode(plain), value >= clearFrom
                else { continue }
                row.deletionToken = sealedOrphanToken
            }
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

        /// Purges any `Message.Draft` not safe at the depth just entered. Called on every
        /// duress-depth entry, including the very first one right after a fresh
        /// activation — `Message.Draft` carries no `visibleThroughDepth`/`isVisible` field
        /// of its own (unlike `Contact.Profile`/`VaultEntry`), so purging is the only thing
        /// keeping an unsafe draft from existing at all; there is no UI-level filter as a
        /// backstop. A contact classified sensitive sometime after a layer was already
        /// created — with a draft saved before, or before the sensitivity gate existed —
        /// would otherwise keep that draft across any number of duress-PIN entries. Called
        /// after `currentDepth` has already advanced, so `isVisible` checks against the
        /// depth actually being entered.
        ///
        /// **Removal Stage 1, 2026-09-10:** `activateSecureMode` no longer runs a draft
        /// purge of its own at layer creation — there is nothing left to stage it around,
        /// and this function already covers the first entry into a freshly created layer
        /// (this always runs before any UI renders for that depth), not only later ones.
        /// A draft's only display surface (`ContactsListV2`'s "Draft" badge) is keyed off
        /// `contactIdentifiersWithDrafts` matched against already depth-filtered contact
        /// rows, so an unpurged draft attached to a hidden contact was never independently
        /// discoverable there either way — this function's real job is hygiene (nothing
        /// pointing at a hidden or gone recipient lingers in the DB), not a display gate.
        ///
        /// No key rotation happens anywhere any more, so this calls `Message.Draft.purgeUnsafe`
        /// — the purge-only half of what `reKeyOrPurgeAll` used to do with `oldKey == newKey`
        /// — rather than a no-op reseal of survivors.
        private func purgeDraftsNotSafeAtCurrentDepth() {
            guard let key = try? Manager.Ambient.keyManager.createHybridLocalEncryptionKey() else { return }
            let profiles = (try? self.modelContext.fetch(
                FetchDescriptor<Contact.Profile>(predicate: #Predicate { $0.deletionToken == nil })
            )) ?? []
            let safeIdentifiers = Set(profiles.filter { $0.isVisible(atDepth: self.currentDepth, usingKey: key) }.map(\.identifier))
            let allGroupIdentifiers = Set(
                ((try? self.modelContext.fetch(FetchDescriptor<Group>())) ?? [])
                    .compactMap { $0.readID()?.uuidString }
            )
            try? Message.Draft.purgeUnsafe(
                safeContactIdentifiers: safeIdentifiers, allGroupIdentifiers: allGroupIdentifiers,
                using: key, in: self.modelContext
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
            // Same shape as activateSecureMode's own verifier writes — no DB key rotation,
            // no blob, neither exists any more regardless of path (Removal Stage 2). The
            // "Deactivate Protection" UI at the coercer's depth is gated on `coercerBaseDepth`;
            // deactivating the coercer's own layer (depth N+1) goes through the same
            // deactivateSecureMode as any other layer.
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

        /// Vault entries visible at the current depth, from an already-fetched set —
        /// `Vault+Tab.swift`'s `@Query` results. Excludes orphaned rows (Bug 110) and
        /// applies the exact-depth match, including at depth 0 (Bug 113 — the previous
        /// `isEntryVisible(_:)` was only ever called when `isRestricted`, so depth 0
        /// bypassed depth filtering, and Bug 110's orphaning, entirely).
        ///
        /// Exact-depth match, not a ceiling: an entry is visible only at the exact
        /// depth it was created at. Deliberately not `value >= currentDepth` — see
        /// `Docs/Bugs/v1.10.0/Vault-Entries-Created-At-A-Duress-Depth-Leak-Into-The-Real-Vault.md`
        /// for why a ceiling lets an entry created at a duress depth leak into every
        /// shallower depth, including the real depth 0.
        ///
        /// `whenUnclassified: depth == 0`, not a constant: a legacy entry with a nil
        /// `visibleThroughDepth` is a real, persistent state, not something swept away
        /// before a duress depth becomes reachable — confirmed by
        /// `PQmigration.migrateDepthFieldsToFixedWidth`'s own doc comment ("VaultEntry nil
        /// is a legitimate steady state rather than a gap"), and by grep: no code
        /// anywhere stamps existing nil entries. It must stay visible at the real depth 0
        /// and stay hidden at every duress depth; a single fixed value can't do both.
        ///
        /// Derives the local DB key once and reuses it across every row, matching
        /// `VaultManager.fetchAllEntries()`/`entriesVisible(atDepth:)`'s pattern, rather
        /// than paying a Secure Enclave round trip per entry. Fails closed to `[]` on
        /// derivation failure — never falls back to returning `entries` unfiltered.
        func visibleVaultEntries(from entries: [VaultEntry]) -> [VaultEntry] {
            guard let key = try? Manager.Ambient.keyManager.createHybridLocalEncryptionKey() else { return [] }
            let depth = self.currentDepth
            return entries.filter {
                !$0.isOrphaned(usingKey: key) &&
                $0.isVisible(atDepth: depth, whenUnclassified: depth == 0, usingKey: key)
            }
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

        /// Forces a full WAL checkpoint (TRUNCATE mode) so all pending writes land in
        /// the main `.sqlite` file before the staged key is committed in step 10.
        private static func walCheckpoint(at url: URL) {
            var db: OpaquePointer?
            guard sqlite3_open_v2(url.path, &db, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK else { return }
            defer { sqlite3_close(db) }
            sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)", nil, nil, nil)
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

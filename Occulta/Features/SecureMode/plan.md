# Secure Mode — Implementation Plan

**2026-09-10 — decision made to simplify: drop the blob mechanism (`Manager.LayerStore`) and the
staged local-DB-key rotation entirely, reverting Secure Mode to pure UI-layer filtering.** Motivated by
a direct assessment of what either mechanism actually buys against an AFU-capable (After-First-Unlock
forensic extraction) adversary: nothing, since both the local-DB key and the blob key derive with equal
ease under that access level (no biometric gate on either), and the one piece that did add a real
guarantee — Design B item 1's key-record shelling, shipped and then found to leak its own occurrence,
`bugs.md` Bug 109 — cost more in forensic tells than it protected. Staged removal plan agreed in
conversation, not yet written up here; six stages (design decision → shrink `activate`/`deactivate` →
delete blob code → delete rotation code → rework tests → docs), each independently buildable and
committable. Not yet started as of this note. Once landed, this document's Steps 3+ (blob/rotation
build history below) describe removed machinery, kept for the record, not a live design.

**Proposed replacement for what this removal gives up — [`PASSPHRASE_LAYER_KEYS.md`](PASSPHRASE_LAYER_KEYS.md), filed for a future v2.0.0, not v1.11.0.**
Replaces the numeric PIN with a 6–7 word diceware phrase that's an actual key-derivation input (Argon2id
+ per-depth SE component via HKDF) rather than a pure UI-routing verifier — closes the AFU gap with a
human secret absent from the device, at the cost of a real UX/recovery tradeoff and a structural
tell-avoidance problem (§2 of that doc) comparable in shape to what's being removed here. Not started;
sequenced after this removal.

## Feature Flag

Secure Mode is governed by the `secureMode` key in `features.plist` (default `true`).

When `false`: `Manager.Security` initialises permanently in `.noPIN` without reading `AppLayerConfig`. The PIN overlay never appears, contact/vault filtering is inert, and the Security row is hidden in Settings. All call sites remain compiled in — they fall into dead paths because `requiresPIN` and `isRestricted` are always `false`. Flip to `false` in `features.plist` to develop without Secure Mode friction.

---

## Core Architecture — `Manager.Security`

`Manager.Security` is the single umbrella for all app-security hardening. `@Observable`, owned by `OccultaApp`, injected via `.environment`.

### Threat model

A coercer demands access at PIN-point. No matter how many PIN entries are coerced, the app behaves identically to an ordinary contacts app at every depth. The coercer cannot determine how many layers exist, whether they have reached the bottom, or whether any protected data has been withheld.

**State machine:**

```
.noPIN   — no PIN configured; app opens directly
.pinOnly — PIN set, Secure Mode not activated; PINEntry on every scene activation
.normal  — authenticated at currentDepth; shows data visible at that depth
           depth 0: real app (all contacts); depth N > 0: decoy for depth N
           (renamed from .active to avoid confusion with UIApplication's .active scene phase)
.duress  — pushed one level deeper from .normal; next PIN entry goes to depth N+1
```

State is derived from `AppLayerConfig` on every `init()` — never stored as a plaintext flag:
- `sealedDuressVerifiers` non-empty → `.normal` (Secure Mode configured; app will lock on foreground)
- `sealedNormalVerifiers` non-empty → `.pinOnly`
- no config → `.noPIN`

`currentDepth` is always 0 on init — restored to the correct depth when the user enters their PIN via `verify()`.

### Stack invariants

1. **Arbitrary depth.** No cap. A cap (e.g. VeraCrypt's 2-layer limit) is a smoking gun — a coercer who tries to activate another layer and finds it unavailable immediately knows hidden data exists. Every layer presents an identical "Activate Secure Mode" option.
2. **PIN entry on every foreground.** `PINEntry` is identical regardless of depth.
3. **`state == .duress` → Settings shows "Enable PIN" toggle + "Activate" only.** Never reveals whether a deeper layer is already configured. `state == .normal` at depth N > 0 shows the same Activate/Deactivate cycle as depth 0 — indistinguishable from any other active state.
4. **`currentDepth` is in-memory only.** Resets to 0 on every app kill. No persistent depth counter — that would be a forensic artifact. `currentDepth` is sufficient because the PIN itself is the routing key: after a cold start, entering any layer's PIN routes directly to that depth via the full normal-verifier scan (see `verify()` ordering below). `currentDepth` in memory only controls which duress push-down verifier is offered — you can only go one level deeper from where you currently are.
5. **`.normal` is relative to `currentDepth`.** At depth 0, `.normal` surfaces the real app. At depth N > 0, `.normal` surfaces the depth-N decoy — contacts with `visibleThroughDepth >= N`. Only the master PIN (depth 0) surfaces the real app. `.duress` means you were pushed one level deeper from your current `.normal` state — it is a transition, not a permanent classification. The same Activate/Deactivate cycle repeats at every depth: `.duress` → Activate → `.normal` at depth N+1 → Deactivate → back to `.duress` at depth N.

### PIN model — one PIN per layer boundary

Each boundary between depth N and N+1 is guarded by a single PIN:

```
sealedNormalVerifiers[0]   = master PIN          → .normal at depth 0 (real app)
sealedDuressVerifiers[0]   = duress PIN #0       → .duress; push depth 0 → depth 1
sealedNormalVerifiers[1]   = same value as sealedDuressVerifiers[0]  ← routing alias → .normal at depth 1 (decoy)
sealedDuressVerifiers[1]   = duress PIN #1       → .duress; push depth 1 → depth 2
sealedNormalVerifiers[2]   = same value as sealedDuressVerifiers[1]  ← routing alias → .normal at depth 2 (decoy)
...
```

`sealedNormalVerifiers[N]` (N > 0) and `sealedDuressVerifiers[N-1]` hold the same PIN value. The duress PIN that pushes you to depth N is the same PIN that returns you to depth N from any deeper level. This gives **K+1 distinct PINs for K layers** — no separate "return PIN" to remember per layer.

**Verifier scheme (no PBKDF2):**

`AES-GCM(HKDF(seKey, info: label ∥ pin), sentinel)`

SE key prevents all off-device attacks. PBKDF2 was removed: it added ~1s of main-thread blocking with no real security return — on-device code execution defeats any KDF regardless, and the 6-digit PIN space (1M) is brute-forceable in minutes on GPU independent of iteration count.

### `AppLayerConfig` schema

```swift
@Model final class AppLayerConfig {
    var sealedNormalVerifier:     Data?   // legacy scalar — migration source only; [0] of sealedNormalVerifiers is canonical
    var sealedDuressVerifier:     Data?   // legacy scalar — migration source only; [0] of sealedDuressVerifiers is canonical
    var persistedDepth:           Data?   // encrypted Int (widened from RoutingDepth in Bug 50); always non-nil after first config write
    var pinEnabled:               Data?   // legacy scalar — migration source only; pinEnabledPerDepth is canonical
    var pinEnabledPerDepth:       [Data]  // 32-entry padded array; encrypted UInt8 per depth (0=suppressed, 1=active)
    var coercerBaseDepth:         Data?   // encrypted Int; 0 default; set by reEnablePIN coercion-acceptance path

    // Verifier arrays (multi-layer)
    var sealedNormalVerifiers:    [Data]   // 32 entries; [0] is master; [N] == sealedDuressVerifiers[N-1] (routing alias)
    var sealedDuressVerifiers:    [Data]   // 32 entries; entry at N drives push to N+1

    // Blob tracking
    var sealedBlobSlots:          [Data]   // 32-entry padded; encrypted Int slot index per depth
    var layerSequenceNumbers:     [Data]   // 32-entry padded; encrypted Int sequence number per depth

    // Lockout
    var lockoutCountEncrypted:    Data?
    var lockoutExpiryEncrypted:   Data?
}
```

The scalar `sealedNormalVerifier` / `sealedDuressVerifier` fields are legacy migration sources; `sealedNormalVerifiers[0]` / `sealedDuressVerifiers[0]` are canonical. Migration runs in `Manager.Security.init()` on first launch after the multi-layer upgrade.

**[security]** Both verifier arrays are padded to 32 entries (`maxVerifierCount == LayerStore.slotCount`) with random filler of exactly `verifierFillerSize` (53) bytes — identical to real verifier size. `verify()` ignores entries that fail to open. A forensic examiner always sees exactly 32 blobs per array regardless of actual depth. The `pinEnabledPerDepth` array is also always 32 entries, each an encrypted `UInt8` (`1` for active, `0` for suppressed) — equal-length sealed boxes in all cases (Bool encoding would differ by one byte; see Bug 51).

`persistedDepth` stores the full `currentDepth` integer via `writePersistedDepth(_:)` / `readPersistedDepth()`. Widened from the two-case `RoutingDepth` enum (Bug 50) to carry depths > 1 from multi-layer coercion stacks.
`pinEnabledPerDepth[N]` stores the gate state for depth N via `writePinEnabled(_:at:)` / `readPinEnabled(at:)`. Falls back to `true` on any decode failure — always demand a PIN rather than silently opening the app.
Both structures are populated at first config creation so their presence never leaks state — consistently non-nil and constant-length fields are forensically opaque.

All properties optional to avoid SwiftData migration on schema evolution.

Contact visibility is tracked per-contact on `Contact.Profile` via `visibleThroughDepth` (see Step 3). There is no central safe-contact list on `AppLayerConfig`.

**Contact visibility invariants across layers:**

- A contact with `visibleThroughDepth = K` is visible at all depths 0..K and hidden at K+1 and deeper. Visibility is always a contiguous range from depth 0 — a contact cannot be hidden at depth 1 but visible at depth 2.
- When activating depth N+1, the user reviews contacts with `visibleThroughDepth >= N` (visible at current depth) and selects which should also be visible at N+1 (setting `visibleThroughDepth = N+1`; or retaining `encrypt(Int.max)` for contacts visible at all depths). Contacts not selected remain at their current value and become hidden at depth N+1.
- New contacts created at any depth receive `encrypt(Int.max)` (depth 0, safe) or `encrypt(N)` (depth N > 0). No contact ever holds a nil field after the activation migration.
- At activation, all N contact records receive a batch write to unify `ZMODIFICATIONDATE` — safe contacts get their fields re-encrypted under the new DB key; legacy nil `visibleThroughDepth` fields get `encrypt(Int.max)` stamped in the same pass. No count inference is possible from the timestamp distribution.

### `verify()` ordering at any depth

Given `currentDepth = N`:

1. Try **all** `sealedNormalVerifiers[0..max]` — first match at K: `currentDepth = K`, state = `.normal` (shows depth-K view — real app at K == 0, decoy at K > 0); restore blob payloads for depths K+1..N if K < N
2. Try `sealedDuressVerifiers[N]` → match: `currentDepth = N+1`, state = `.duress`
3. No match → `.wrong`; increment `wrongPINCount`

Step 1 scans all normal verifiers regardless of `currentDepth`. This is what makes cold-start routing work — entering duress PIN #1 after a kill matches `sealedNormalVerifiers[2]` and routes directly to depth 2, without having to walk through depth 1 first. Only the push-down (step 2) is depth-specific, preventing a coercer from jumping past an unvisited depth.

### PIN uniqueness constraint

At every setup step, validate the candidate PIN against all existing verifiers at all depths. Reject if any verifier opens with the candidate PIN.

**[security]** This validation must use a pure `checkPIN(_:against:)` method — not `verify()`. `verify()` increments `wrongPINCount` on each non-match. Checking N verifiers for uniqueness would increment the counter N times, falsely advancing the rate-limit counter. `PINManager.checkVerifier()` already exists as a pure function; the uniqueness check must call it directly without going through `Manager.Security.verify()`.

### `Manager.Security` public interface

```swift
// State
var requiresPIN:    Bool    // state != .noPIN
var isRestricted:   Bool    // currentDepth > 0
var pinEnabled: Bool        // whether the PIN overlay gate fires on scene activation (per-depth; see pinEnabledPerDepth)

// Setup
func configurePIN(_ pin: String) throws                                              // .noPIN → .pinOnly
func activateSecureMode(confirmingEntryPIN: String, duressPIN: String) throws        // .pinOnly/.duress → .normal
func deactivateSecureMode(confirmingEntryPIN: String) throws                         // .normal → .pinOnly (depth 0) / .duress at depth N-1 (depth N > 0)
func deactivatePIN(confirmingNormalPIN: String) throws                               // .pinOnly → .noPIN

// Coercion-resistant gate (sticky-depth)
func disablePIN(at depth: Int, confirmingPIN: String) throws      // lowers gate; verifiers intact; depth filter stays
func reEnablePIN(_ pin: String) -> Bool                           // routes PIN to matched verifier depth; at depth>0 accepts unknown PIN via coercion-acceptance path

// Verification (owns all state transitions)
func verify(_ pin: String) throws -> PINVerifyResult

// Safe contact membership
func isSafeContact(_ identifier: String) -> Bool
func safeContactIDs() -> Set<String>
func updateSafeContacts(_ ids: Set<String>) throws
```

**Interface contracts:**

- `deactivatePIN` is only valid in `.pinOnly`. Caller must deactivate Secure Mode first.
- `verify()` in `.noPIN` throws `.notConfigured` — `PINEntry` should never appear in that state.
- `isLocked: Bool` lives in `OccultaApp` (UI layer), not in `Manager.Security`. It is set to `true` on every `scenePhase == .active` when `security.requiresPIN`, and cleared to `false` in `onNormal`. `Manager.Security` owns state; `OccultaApp` owns the lock gate.

**Wipe threshold behaviour:** No wipe in any mode. Wrong PINs always return `.wrong`. SE hardware rate-limiting is the brute-force defence. `wipeThresholdEncrypted` and `PINVerifyResult.wipe` are removed; `consecutiveDuressCount` is removed.

---

## Step 1 — PIN Infrastructure ✅

- [x] `Tags` enum `CaseIterable`, `secureModePin` case, `deleteAllKeys()`
- [x] `deriveSecureModeKey()` on `Manager.Key` and `KeyManagerProtocol`
- [x] `TestKeyManager` in-memory implementation
- [x] `SecureModeConfig` SwiftData model — all optional, no salt, no boolean flags
- [x] `Manager.Security` — own `ModelContext`, `PINManager` internal, state machine `.noPIN/.pinOnly/.normal/.duress`
- [x] `Manager.Security.configurePIN(_:)` — builds `sealedNormalVerifier`, inserts config, transitions `.noPIN → .pinOnly`
- [x] `Manager.Security.activateSecureMode(confirmingNormalPIN:duressPIN:)` — verifies normal PIN, builds `sealedDuressVerifier`; key rotation TODO deferred to Step 4
- [x] `Manager.Security.verify(_:)` — owns all state transitions; duress + wrong counters in memory
- [x] `Manager.Security.deactivatePIN(confirmingNormalPIN:)` — `.pinOnly → .noPIN`
- [x] `Manager.Security.deactivateSecureMode(confirmingNormalPIN:)` — `.normal/.duress → .pinOnly`; blob unwind TODO deferred to Step 4
- [x] `OccultaApp` schema includes `SecureModeConfig`
- [x] `Manager.App` with `eraseAllData()`
- [x] Unit tests via `TestKeyManager` + in-memory `ModelContainer` (29 tests)
- [x] **[security]** Rename SE key tag from `"secure.mode.pin"` to an opaque string (UUID or similar). The current tag explicitly names the feature — Keychain enumeration by a forensic tool directly reveals Secure Mode infrastructure. The master identity key uses `"master.key.privacy.turtles.are.cute"` (opaque); the Secure Mode key should follow the same pattern.
- [x] **[security]** Rename `SecureModeConfig` to an opaque class name (e.g. `AppLayerConfig`). SwiftData derives the SQLite table name from the class name — `ZSECUREMODECONFIG` in a raw database dump directly names the feature. Renaming to something non-descriptive changes the table name to `ZAPPLAYERCONFIG` or similar. Class is only referenced internally; surgical rename with no public API impact. Requires a SwiftData migration (lightweight: rename only).
- [x] **[security]** Set `NSPersistentStoreFileProtectionKey: FileProtectionType.complete` on the SwiftData persistent store. The current default (`completeUntilFirstUserAuthentication`) leaves the SQLite file readable after first device unlock even when the screen is locked. SwiftData's `ModelConfiguration` doesn't expose this — requires setting file attributes on the store URL post-creation via `FileManager.setAttributes`. Note: all field values are additionally encrypted at the app level, so the exposure is schema + row count, not plaintext data.
- [x] **[security]** `FileManager.setAttributes` for `.completeFileProtection` is applied once at container creation. SwiftData can create new `-wal` or `-shm` files outside the app's init lifecycle (WAL merges, schema migrations, conflict resolution). The attribute must be reapplied after every `ModelContext.didSave` notification — subscribe in `OccultaApp` and call `setAttributes` on all three paths (`store`, `store-wal`, `store-shm`) each time. Implemented: `storeURL` stored as property; `reapplyFileProtection()` helper; `.onReceive(NSManagedObjectContextDidSaveNotification)` in `body`.
- [x] **[security]** Set `PRAGMA secure_delete = ON` on the SQLite connection before any writes. Without this, deleted and updated rows leave plaintext content in SQLite free-list pages that survive WAL checkpoint. A hidden contact's name or vault label could persist in raw page data long after the row is soft-deleted or re-encrypted. Applied via a short-lived C API helper connection in `OccultaApp.init()` immediately after store creation — in SQLite 3.12+ the setting is stored in the database header and persists for all future connections including SwiftData's. Step 4's key-rotation path sets it explicitly on its direct connection as belt-and-suspenders, independent of header persistence.
- [x] **[security]** Create the no-op blob payload at Step 1 migration time, not at Step 4 activation. A forensic timeline that shows the blob file appearing when the user updates to the Step 4 version directly correlates blob presence with Secure Mode usage on all pre-Step-4 installs. Backporting blob creation to the Step 1 migration (already shipped) decouples the timestamps: every Occulta install will have had a blob file for months before Step 4 ships. Implemented in `SecureMode+Blob.swift` (`Manager.Blob`): UUID-named `.occbak` file in `group.com.occulta.shared/blobs/`, AES-GCM with HKDF-SHA256 blob key, bucket-padded random plaintext, 24-hour rewrite. Called from `OccultaApp.init()` behind the `secureMode` feature flag.

---

## Step 2 — PIN Entry UI ✅

- [x] `PINEntry` view — neutral black, no branding
- [x] 6-digit keypad, `isVerifying` lock preventing double-submission
- [x] Fixed 500ms gate equalising timing across all outcomes
- [x] Two-phase setup: first entry stores PIN, second confirms; label switches "Passcode" → "Confirm Passcode"
- [x] Routes on result: `.normal` → `onNormal(String)`, `.duress` → `onDuress()`, `.wrong` → shake. `.wipe` case and `onWipe` callback removed.
- [x] Reads `Manager.Security` from environment; counter lifetime off the view
- [x] `onNormal: (String) -> Void` (widened from `()` so Settings can pass PIN to `deactivatePIN`)
- [x] App launch gate in `OccultaApp` — `isLocked` state, `.overlay` on `TabView`, no animation, locks on every `scenePhase == .active`
- [x] **[security]** OS app-switcher snapshot and KTX forensic file protection — implemented via `SceneDelegate` (`UIWindowSceneDelegate`, `ObservableObject`). `sceneWillResignActive` synchronously injects a cover `UIView` (`.systemBackground` + spinner) into the existing `UIWindowScene` window using `CATransaction.setDisableActions(true)`. Covers the live app-switcher card immediately. The cover remains in the window hierarchy when `sceneDidEnterBackground` fires — iOS photographs it for the KTX file. `sceneDidBecomeActive` removes the cover unconditionally. The cover is injected as a subview of the existing window (not a new `UIWindow`) to avoid blocking `UIActivityViewController`. `Manager.Security` is injected into `SceneDelegate` via a one-time SwiftUI bootstrapping view (`SecuritySetting`) that reads both from the SwiftUI environment before any content is shown. (Bug 54)
- [x] **[security]** Cover removal timing — `sceneDidBecomeActive` calls `handleActive()` first, then skips `removeCover()` when `needsPINEntry = true`. The UIKit cover is held in place until `PINEntry.onAppear` removes it, eliminating the frame window where contacts were visible between cover teardown and `fullScreenCover` presentation. Cover is always torn down: immediately on grace-period foreground, in `PINEntry.onAppear` otherwise. (Bug 56)
- [x] **[security]** Zero PIN digits after use. Replace `[Int]` digits storage with a `Data`-backed buffer; after `submit()` routes the result, zero the buffer with `memset`. Removes PIN heap residue. Low practical exploit risk given SE binding, but correct hygiene and removes the finding from security audits.

---

## Step 3 — Settings UI + Contact Classification + Decoy View

### Settings → Security (4-state)

- [x] "Enable PIN" toggle — transitions `.noPIN ↔ .pinOnly` via `PINEntry` sheet
- [x] **[security]** Add `checkNormalPIN(_ pin: String) -> Bool` to `Manager.Security` — thin wrapper around `PINManager.checkVerifier` with no counter mutation. Replace the `security.verify()` call in `PINEntry.submitConfirmPhase` with this method. Using `verify()` for Settings-level PIN confirmation incorrectly increments `wrongPINCount` on each wrong attempt, which is semantically wrong (a Settings confirmation is not a lock-screen attack attempt) and pollutes the in-memory counter state.
- [x] "Activate" button confirmation PIN (depth 0): `checkNormalPIN`. Sheet calls `activateSecureMode(confirmingEntryPIN:duressPIN:)` on success.
- [x] "Activate" button confirmation PIN (depth N > 0): `checkCurrentLayerPIN(_:)` on `Manager.Security` checks `sealedDuressVerifier` in `.duress` state, `sealedNormalVerifier` otherwise — no counter mutation. `PINEntry.submitConfirmPhase` (`.confirmThenSet` phase 1) already calls it. Activation actually succeeding at depth N > 0 (writing to `sealedNormalVerifiers[N]` / `sealedDuressVerifiers[N]`) deferred to Step 4 `AppLayerConfig` array migration.
- [x] **[design — pre-ship]** Biometric unlock is not possible. `LAContext` cannot be routed to different app states — Face ID success always returns the same result regardless of which depth is active, meaning biometrics would always open the real app and bypass the duress view entirely. The app is PIN-only. Lock gate uses a **background-duration model**: the PIN gate only re-engages if the app has been in the background for longer than 5 minutes — i.e. genuinely unattended — not based on time since last authentication. `backgroundEntryDate: Date?` on `Manager.Security` (in-memory only); set in `handleBackground()`, consumed and cleared in `handleActive()`. Brief interruptions (share sheets, Face ID prompts, notification banners) do not background the app and never trigger a re-lock. Grace period applies uniformly at all depths (Bug 41 — asymmetric zero-grace in restricted mode was itself a tell). (Bug 55)
- [x] "Deactivate" button — visible when `state == .normal`. Sheet calls `deactivateSecureMode(confirmingNormalPIN:)` on success.
- [x] **[design]** Activate / Deactivate button visibility — multi-layer implemented:
  - Activate ("Learn more") visible at: `!isSecureModeActive` (covers `.noPIN`/`.pinOnly`) and `currentDepth > 0`; hidden at `currentDepth == 0` with Secure Mode active. ✓
  - Deactivate visible at: `isSecureModeActive && state == .normal && (currentDepth == 0 || currentDepth == coercerBaseDepth) && pinEnabled` — hidden at all other depths. ✓ (Bugs 45, 47, 58, 61)
  - Toggle disabled when `isSecureModeActive && state == .normal && pinEnabled`; intentionally enabled in `.duress` so `disablePIN(at:confirmingPIN:)` remains accessible via toggle tap (uses `.verifyCurrentLayer`, no `verify()` counter mutation). ✓
  - `SecureModeDeactivateFlow` uses `.verifyCurrentLayer` → confirmation PIN = current layer's PIN at depth 0. ✓
  - `activateSecureMode` at depth > 0: after config writes, writes `coercerBaseDepth = depth` (not `depth+1`) and sets `state = .normal` so "Deactivate Protection" appears immediately. (Bugs 58, 61)
  - `ContactClassification.loadSensitiveIDs()` and `save()` depth guard removed entirely — `classifiableContacts` filters through `isDisplayable(atDepth: currentDepth)` and `isSensitive` is depth-relative, preventing info leak and mutation at any depth without an outer guard. (Bugs 48, 57)
- [x] **[design]** Contact selection must be part of the activation flow, not a standalone Settings item visited later. Implemented as `SecureModeSetupFlow`: Education → PIN setup (confirmThenSet) → Contact classification → Summary/Activate (4 steps, step-dots indicator). `activateSecureMode` called only on the final confirm step.
- [x] **Bug 24** — "Activation Failed" alert reveals Secure Mode state when flow is traversed in duress mode. See `Docs/bugs.md`.
- [x] **Bug 25** — `ContactClassification` exposes sensitive contacts when opened in duress mode. See `Docs/bugs.md`.
- [x] **[design]** "Deactivate Secure Mode" sheet calls `verify()` internally (via `PINEntry` in `.verify` mode), then `onNormal` calls `deactivateSecureMode(confirmingNormalPIN:)` which calls `PINManager.checkVerifier` again — double-verification plus counter mutation. Wrong attempts in this sheet increment `wrongPINCount` and pollute the rate-limit counter. Replace with a verify-without-counters path using `checkNormalPIN`, same as the activate flow's phase 1. Requires either a new `PINEntry` mode or calling `checkNormalPIN` directly in the sheet.
- [x] **[design]** "Enable PIN" toggle was initially disabled in `.normal` and `.duress` states. Revisited by the sticky-depth design and the Settings UI re-evaluation (both below). Final state: toggle remains disabled in `.duress` — this is load-bearing, not cosmetic (see Settings UI entry for rationale). `disablePIN(at:confirmingPIN:)` is the coercion-safe gate mechanism that doesn't go through the toggle.
- [x] **[security]** `activateSecureMode` must validate that the proposed duress PIN does not open any existing normal verifier. Currently no collision check — if duress PIN == normal PIN, `verify()` always matches normal first and duress is never triggerable. Validate with `PINManager.checkVerifier` (not `verify()`) before building the duress verifier; reject with a user-facing error if any existing verifier opens.
- [x] **[design — pre-ship]** `Enable PIN` toggle in `.duress`: the goal was to make the gate lowerable under coercion without exposing the master PIN. Enabling the toggle trivially is not safe: the Settings sheet calls `security.verify()` internally, so entering the normal PIN from `.duress` would silently transition to `.normal` at depth 0, breaking duress. The final resolution (see Settings UI entry below): toggle stays disabled in `.duress`; `disablePIN(at:confirmingPIN:)` is the coercion-safe gate mechanism. The residual tell (toggle appearance differs from `.pinOnly`) is accepted — the alternative is worse.

  **Chosen design — sticky depth with `pinEnabledPerDepth`:**

  The insight is to decouple the PIN gate from depth routing. "Disable PIN" does not mean "forget all verifiers" — it means "lower the gate while remembering where we are." Verifiers remain intact.

  **`AppLayerConfig` fields (see schema above):**
  - `persistedDepth: Data?` — encrypted `Int` (full `currentDepth`). Widened from `RoutingDepth` enum (Bug 50) to carry depths > 1. Always non-nil after first config write.
  - `pinEnabledPerDepth: [Data]` — 32-entry padded array. `pinEnabledPerDepth[N]` is an encrypted `UInt8`; `1` = gate active at depth N, `0` = gate suppressed. Encoded as `UInt8` (not `Bool`) so both values produce equal-length sealed boxes (Bug 51). Always 32 entries, all non-nil.

  **`Manager.Security` in-memory property:**
  - `pinEnabled: Bool` — restored from `config.readPinEnabled(at: persistedDepth)` in `init`. `false` only when gate was deliberately lowered at the restored depth.

  **Disable PIN (`disablePIN(at:confirmingPIN:)`):**
  1. Checks entered PIN against the current layer's verifier — no `verify()`, no counter mutation, no state transition.
  2. On pass: calls `writePersistedDepth(currentDepth)` + `writePinEnabled(false, at: currentDepth)`, saves, sets `pinEnabled = false`. Verifiers are left untouched.
  3. App opens directly to depth-N content. Coercer sees: toggle OFF, no PIN required, decoy content.

  **Re-enable PIN (enter + confirm — same UX as always):**
  `PINEntry` in `.setup` mode collects two matching entries and delivers the confirmed PIN to Settings. Settings calls `reEnablePIN(_:)`:
  - PIN matches an existing verifier → gate re-enabled at matched depth.
  - No match at depth > 0 → coercion-acceptance path creates a new layer for the PIN; `coercerBaseDepth = currentDepth + 1` recorded (Bug 37 fix).
  - No match at depth 0 → gate stays down (accepted tell at depth 0).

  **Why all structures are always fully populated:** a nil field or short array that only appears when the gate has been force-disabled is itself a forensic tell. `configurePIN` seeds `persistedDepth`, all 32 `pinEnabledPerDepth` entries, and `coercerBaseDepth` immediately so every install shows the same field structure regardless of gate state.

- [x] **[design — pre-ship]** `Settings → Security` appearance in `.duress` is wrong. The duress experience must be indistinguishable from `.pinOnly` — the coercer must believe Secure Mode was never activated. Correct state table:

  | State | Enable PIN toggle | "Learn more" / Activate section | "Deactivate Protection" |
  |---|---|---|---|
  | `.noPIN` | enabled | shown (dimmed, blocked) | hidden |
  | `.pinOnly` | enabled | shown | hidden |
  | `.duress` | **disabled** | **shown** | **hidden** |
  | `.normal` | disabled | hidden | shown |

  **Toggle disabled in `.duress`:** Load-bearing, not cosmetic. PIN cannot be removed while Secure Mode is active — this is correct in both `.normal` and `.duress`. More critically: if the toggle were enabled, opening it would present a `PINEntry` sheet that calls `security.verify()` internally. Entering the normal PIN in `.duress` triggers the `.normal` route and transitions state to `.normal`, breaking duress and silently exiting the decoy view. Even if we substituted `checkNormalPIN` to avoid the state transition: correct PIN + sheet closes + PIN still enabled + nothing changes = a suspicious silent failure that tells the coercer something is wrong. Toggle disabled is the only safe option.

  **"Learn more" section must be shown in `.duress`:** Hiding it (the current bug) is a direct tell — `.normal` is the only state that hides it, so a coercer who knows the UI sees `.normal` unambiguously. Showing it in `.duress` makes the screen identical to `.pinOnly`. The button works at any depth: it opens `SecureModeSetupFlow`, which creates a new layer.

  **"Deactivate Protection" must be hidden in `.duress`:** Showing it (the current bug — `.duress` is included in the condition alongside `.normal`) is the exact signature of `.normal` state and directly reveals Secure Mode is on.

  **Fix in `Settings.swift`:**
  ```swift
  // "Learn more" — add .duress
  if state == .noPIN || state == .pinOnly || state == .duress { ... }

  // "Deactivate" — remove .duress
  if state == .normal { ... }
  ```

### Contact classification

Contact visibility is tracked per-contact, not in a central list on `AppLayerConfig`. A single encrypted field on `Contact.Profile` encodes depth-aware visibility, scales to the multi-layer stack without schema changes, and produces no central field whose size can be compared against total row count.

**`visibleThroughDepth: Data?`** on `Contact.Profile` — encrypted `Int`, **never nil in new code**:
- `Int.max` — visible at all depths (safe contact; sentinel written for all depth-0 safe contacts)
- `0` — visible at true layer only (sensitive contact, hidden from all duress depths)
- `N` — visible at depths 0 through N; hidden at N+1 and deeper

`nil` is treated as a legacy pre-Secure-Mode value and migrated to `encrypt(Int.max)` at activation. No new code ever writes nil.

Filter at depth N — four cases:
- `nil` → show (pre-Secure-Mode contact; `?? Int.max` fallback applies)
- non-nil, decryption succeeds, value ≥ N → show
- non-nil, decryption succeeds, value < N → hide (depth-gated)
- non-nil, **decryption fails** → **exclude entirely** (defense-in-depth; should not occur in normal operation under Design A since all contacts are re-encrypted at activation and remain readable)

All contacts (safe and sensitive) are re-encrypted under the new DB key at activation. Sensitive contacts are depth-gated by their `visibleThroughDepth` value, not by key inaccessibility. The decrypt-failure exclusion is a defensive fallback for corrupted rows; it must return `false` (fixed). See "Post-activation contact access" for the full design rationale and the Design B alternative.

**Write rule:** contacts created or exchanged at depth 0 always receive `encrypt(Int.max)` (safe) or `encrypt(0)` (sensitive). Contacts created at depth N > 0 receive `encrypt(N)`. No contact ever gets a nil field after the first activation migration.

**Forensic profile:** `AES-GCM(Int.max)`, `AES-GCM(0)`, `AES-GCM(1)` all produce identically-sized ciphertexts — no size-based count inference. Critically, every contact row always has a non-nil encrypted blob in this column regardless of classification — a NULL vs non-NULL count in a raw SQLite dump cannot reveal how many contacts are hidden. No central list to compare against total row count. The primary residual tell is the mass `ZMODIFICATIONDATE` update on safe contacts at activation time. Mitigated by touching all N contact records in a single batch write at activation (re-encrypting fields under the new DB key for safe contacts; writing `encrypt(Int.max)` to the `visibleThroughDepth` column of any legacy nil contacts), making all records share the same modification timestamp — no count inference possible.

- [x] `isSafeContact(_:)`, `safeContactIDs()`, `updateSafeContacts(_:)` on `Manager.Security` updated to read `visibleThroughDepth` from contact records, not from `AppLayerConfig`
- [x] `visibleThroughDepth: Data?` added to `Contact.Profile` model (encrypted `Int`, default nil — migrated to `encrypt(Int.max)` at first activation)
- [x] User chooses contact type (safe / sensitive) during contact creation — VISIBILITY section in `ContactFormV2`; no Secure Mode framing; shown in both create and edit modes
- [x] At Secure Mode activation: review step shows existing contacts and lets the user confirm or change classifications before activating. This is step 3 of the 4-step activation sheet (`SecureModeSetupFlow`).
- [x] `safeContactIDsEncrypted` removed from `AppLayerConfig` and all call sites
- [x] **[security]** All contact creation / import paths (`ContactFormV2`, `ContactsListV2`, `ExchangeResult`) must write `encrypt(Int.max)` for safe contacts instead of leaving `visibleThroughDepth = nil`. Both `createContacts` and `save(contact:currentDepth:)` write `encrypt(Int.max)` at depth 0 unconditionally. `ContactFormV2` calls `setVisibility` immediately after save to apply the user's choice. `ExchangeResult` only updates key records — contact already has its depth stamp from creation.

### Decoy view

- [x] `ContactsV2` checks `security.isRestricted` (`currentDepth > 0`); filters fetch to `safeContactIDs()` when true — `safeContactIDs()` uses `currentDepth` to filter at the correct depth
- [x] `VaultTab` shows the normal list (not "unavailable") when `isRestricted` — vault appears empty because no entries exist for this layer yet, indistinguishable from a user who has never used the vault
- [x] **[security]** `Vault+Tab` Face ID gate fires uniformly at all depths — `isRestricted` short-circuit removed from the gate condition. `visibleEntries` depth filter remains separate and orthogonal to the gate: the gate fires on every tab open; entries shown after unlock are filtered to `isEntryVisible`. Skipping the gate in duress mode was a forensic tell (absence of Face ID prompt reveals non-normal state). (Bug 53)
- [x] `onDuress` in `OccultaApp` wired: set `isLocked = false` (decoy view is the real app filtered — no special navigation)
- [x] **[security]** Share index management — ownership consolidated to authentication events, not scene phase handlers. (Bugs 65–68) **Superseded 2026-08-16: the share index no longer exists.** The recipient picker moved into the main app behind the PIN gate (Bug 84), so there is no mirror to keep at a depth and no rule below still applies. Retained as history.

  **Rule:** `shareIndexAllowedIDs` is always `safeContactIDs(atDepth: max(currentDepth, 1))` when `isSecureModeActive`, `nil` otherwise.

  **Canonical write sites:**
  - `onAuthenticated` (normal PIN): evaluates `isSecureModeActive`; writes restricted or nil. (Bug 65)
  - `onDuress`: writes `safeContactIDs(atDepth: currentDepth)`.
  - `activateSecureMode`: writes `safeContactIDs(atDepth: max(currentDepth, 1))` after final save. (Bug 67)
  - `deactivateSecureMode` (full path, depth ≤ 1): writes `nil` (Secure Mode inactive). (Bug 67)
  - `deactivateSecureMode` (cascade path, depth ≥ 2): writes `safeContactIDs(atDepth: max(currentDepth, 1))` (Secure Mode still active). (Bug 68)

  **Removed:** per-transition syncs from `.inactive` and `.active` scene handlers — these fired too late (`.inactive`) or conflicted with post-PIN state (`.active`). Scene handlers do not write the share index.

  **~~Open (Bug 69)~~ — moot 2026-08-16.** Cold launch with `pinEnabled = false, isSecureModeActive = true` left the index uninitialised, so the first contact mutation wrote every contact to it. There is no index to write. Never fixed as stated; removed instead.
- [x] Safe contacts fully operational in decoy view (send, receive, decrypt `.occ`) — safe contacts visible, share index filtered, decrypt path unchanged (no suppression on inbound)
- [x] New contacts created or exchanged while `isRestricted` receive `visibleThroughDepth = currentDepth` — `ContactFormV2` and `ContactsListV2` (CNContact import) both pass `security.currentDepth`; VISIBILITY section hidden at depth > 0; `setVisibility` only called at depth 0. `ExchangeResult.update(key:for:)` touches key records only — contact already exists with its depth stamp from creation.
- [x] **[design]** `ExchangeManager` in duress mode — no gate. Exchanges proceed normally. `update(key:for:)` only touches the key record; the contact's `visibleThroughDepth` is unchanged. A re-exchange with a hidden contact produces an unnamed new key entry indistinguishable from a fresh exchange with a stranger.

### Vault visibility

Vault entries follow the same depth-aware visibility model as contacts. Each layer starts with an empty vault; entries added there propagate up to the true layer but are invisible to any deeper layer created later.

**`visibleThroughDepth: Data?`** on `VaultEntry` — encrypted `Int`, **never nil in new code**:
- `encrypt(0)` — belongs to the true layer (depth 0); hidden at depth 1 and deeper
- `encrypt(N)` — visible at depths 0 through N; hidden at N+1 and deeper

`nil` is treated as a legacy pre-Secure-Mode value and migrated to `encrypt(0)` at activation — these entries were created before Secure Mode existed and belong to the real layer; they must be hidden from the duress view.

**Write rule:** `addEntry(...)` always writes `encrypt(currentDepth)` — even at depth 0. No entry ever gets a nil field after the activation migration.

Filter at depth N: show entries where `(decrypt(visibleThroughDepth) ?? 0) >= N`.

- [x] `visibleThroughDepth: Data?` added to `VaultEntry` model (default `nil`, lightweight SwiftData migration — migrated to `encrypt(0)` at first activation)
- [x] `isEntryVisible(_ entry: VaultEntry) -> Bool` on `Manager.Security` — takes the already-fetched entry directly, applies `(value ?? 0) >= currentDepth` rule; mirrors the contacts `isVisible` helper
- [x] `Vault+Tab` computes `visibleEntries` filtered through `security.isEntryVisible` when `isRestricted`; filters attention section (`affected`) by `visibleIDs` as well — no hidden-entry labels leak through the recovery health display
- [x] `Vault+Manager.addEntry(...)` — writes `encrypt(currentDepth)` unconditionally regardless of depth. Depth 0 entries get `encrypt(0)` (real-layer items, hidden from all duress views).
- [x] `Vault+Manager+Backup.swift` — audited; imported entries leave `visibleThroughDepth = nil`. Migration at next activation will stamp them `encrypt(0)` (real-layer entries, correct).
- [x] **Blob interaction (Step 4):** vault PEKs are **not** stored in the blob (Bug 8 fix). The vault key is derived from a dedicated SE key independent of DB key rotation; `visibleThroughDepth` on each `VaultEntry` is the only vault-related field that requires re-encryption during key rotation. Activation re-encrypts this field under the staged DB key; deactivation clears it to `nil` (Bug 12 fix). No `LAContext` evaluation or biometrics required for vault data at activation/deactivation.

---

## Step 4 — Layer Store + Activation / Deactivation

See **[LayerStore.md](LayerStore.md)** for wire format, slot design, cryptography, no-op maintenance, and capacity estimation.

- [x] Layer store infrastructure: `LayerPayload` / `LayerContact` payload types; `seal`/`unseal` (→ `push`/`pop` pending wire format upgrade); HKDF key derivation; bucket padding; no-op `maintain()` called from `OccultaApp.init()`, 24 h rewrite schedule, `ModelContext.didSave` rewrite debounced 30 s (gated on `!isSecureModeActive`); App Group storage at `group.com.occulta.shared/blobs/` with `.completeFileProtection` and `isExcludedFromBackup = true`. Files: `SecureMode+LayerStore.swift`, `SecureMode+LayerStoreBackend.swift`; types: `Manager.LayerStore` / `LayerStoreBackend` / `AppGroupLayerStoreBackend`.
- [x] **Layer store wire format upgrade** — `push`/`pop` replacing `seal`/`unseal`, 32-slot fixed-size file, full slot regeneration on every write, sequence number validation, `payloadTooLarge` guard. Full design in **LayerStore.md**.
- [x] **`excludedSlots` covers depth-0 and depth-1 blobs permanently.** At depth ≥ 2 activations, `randomSlot()` excludes `(0..<min(depth, 2)).compactMap { config.readBlobSlot(at: $0) }` — protecting both the real-layer blob (depth 0) and the convincing duress blob (depth 1) from overwrite. Expendable blobs at depth 2+ remain freely selectable. (Bug 46)
- [x] **`clearAllBlobMetadata()` used in full deactivation.** Full deactivation (depth ≤ 1) calls `config.clearAllBlobMetadata()` — replaces both `sealedBlobSlots` and `layerSequenceNumbers` arrays wholesale with fresh random filler. Replaces the prior `clearBlobSlot(at: 0)`-only call that left higher-depth metadata stale. Cascade deactivation (depth ≥ 2) continues to use per-index clears. `forceDeactivateForRecovery` updated to match. (Bug 63)
- [x] **Activation sequence — implemented.** Full key rotation, blob seal, contact re-encryption, and state transition are in `Manager+Security.activateSecureMode`. `modelContext.autosaveEnabled = false` + `defer` guards against accidental mid-sequence autosaves. Current POI is `commitStagedLocalDBKey()` (Keychain rename); `modelContext.save()` follows milliseconds later to write the duress verifier and state transition. A kill in that window requires a manual re-activation — no data loss. Documented in Known Limitations.

  **Deferred upgrade — `activeDBKeyTagEncrypted` refactor:** make `modelContext.save()` the POI by storing the new SE key's UUID tag in `AppLayerConfig` before the save, then completing the Keychain rename as post-save cleanup. `Manager.Security.init` detects an uncleared tag on launch and finishes the rename automatically — no manual retry needed. Benefit: automatic crash recovery in a sub-millisecond window. Not a ship blocker; deferred. Full target sequence preserved below for when this is implemented:

  1. State guard + PIN verification (normal PIN check, duress PIN collision check) — abort immediately on failure, no side effects.
  2. ~~Evaluate `LAContext` for biometrics~~ — **removed** (Bug 8). Vault PEKs are not in the blob; no biometric gate needed.
  3. Create new SE key at a fresh UUID tag + new 32-byte random in Keychain. Derive `newDBKey`. **Old canonical key still valid. If the app crashes here, the new key is an orphaned Keychain entry — detect and delete on next launch.**
  4. `modelContext.autosaveEnabled = false`; `defer { modelContext.autosaveEnabled = true }`. All subsequent DB mutations accumulate in memory until the explicit save in step 11.
  5. Decrypt all contacts using old canonical DB key. Partition into sensitive and safe. Build `ContactBlobRecord` for each sensitive contact (includes `signedAttributes` and `visibleThroughDepth` — Bug 23 fix).
  6. Migrate `visibleThroughDepth` in memory: `encrypt(Int.max)` for all safe contacts with nil field; `encrypt(0)` for all vault entries with nil field. Batch mutation unifies `ZMODIFICATIONDATE` — no activation timestamp fingerprint.
  7. ~~Unwrap vault PEKs~~ — **removed** (Bug 8).
  8. Seal blob: `Manager.LayerStore.seal(LayerPayload(contacts: sensitiveRecords), layerKey:)`. Replaces the no-op blob. (→ `push` once 32-slot upgrade lands)
  9. Re-encrypt **all** contacts' fields (safe + sensitive) under `newDBKey` in memory. Sensitive contacts remain in the DB — depth-based visibility (`visibleThroughDepth`) gates the UI. See "Post-activation contact access" below.
  10. Accumulate remaining in-memory mutations: update `AppLayerConfig` with new key tag (encrypted), duress verifier, `lastUnlockDate = nil` (Bug 5 fix).
  11. `modelContext.save()` — **point of no return.** Single atomic SQLite commit: re-encrypted contacts + `visibleThroughDepth` values + `AppLayerConfig` (new key tag + duress verifier). A crash before this line leaves the DB byte-for-byte unchanged. A crash during this line is handled by SQLite WAL atomicity.
  12. `PRAGMA wal_checkpoint(TRUNCATE)`.
  13. Delete old SE key + old Keychain random — cleanup only. A crash here leaves an orphaned old key; harmless since `AppLayerConfig` now references the new key tag. Detect and delete on next launch.
  14. Transition state → `.normal`.

### Post-activation contact access

**Chosen design: UI-layer depth filtering (Design A).** Sensitive contacts remain in the DB, re-encrypted under the new canonical key alongside safe contacts. Access is controlled entirely by `visibleThroughDepth` and the `isRestricted` / `isSafeContact` UI filter — not by key inaccessibility.

| Source | Contents | Normal PIN | Duress PIN |
|---|---|---|---|
| Database | Safe contacts (`visibleThroughDepth = encrypt(Int.max)`) | Shown | Shown |
| Database | Sensitive contacts (`visibleThroughDepth = encrypt(0)`) | Shown | Hidden |

**Normal PIN** (`state = .normal`, `isRestricted = false`): no filtering applied — `visibleContacts` returns all DB contacts including sensitive ones.

**Duress PIN** (`state = .duress`, `isRestricted = true`): `visibleContacts` filters via `isSafeContact`, which calls `isVisible(profile, atDepth: 1)`. Sensitive contacts have `visibleThroughDepth = encrypt(0)` → `0 >= 1 = false` → hidden.

**Blob role under Design A.** The blob is sealed at activation with a snapshot of sensitive contacts. It is not loaded on normal unlock. Its roles are: (1) provide restoration data during deactivation (step 5b re-encrypts shells from blob plaintext under the staged key); (2) serve as forensic cover — present from first launch regardless of Secure Mode state.

**Design B considered and deferred.** The original design had sensitive contacts as unreadable shells (fields left under the deleted old key) with an `inMemorySensitiveContacts` array populated from the blob on normal unlock and wiped on lock. Design B provides a cryptographic guarantee — no DB-key access grants access to sensitive contacts during a duress exposure. It was deferred in favour of Design A for implementation simplicity. The residual forensic gap is explicitly accepted and documented in `forensic-trace-avoidance.md` S5. Design B remains the correct upgrade path if the threat model is elevated.

**What Design B requires before it can be implemented:**

**Items 1 and 3 built and shipped, 2026-09-10 — key records only, not the rest of Design B.**
Activation now genuinely leaves a sensitive contact's key records unreadable once the old
canonical key is deleted, and deactivation genuinely recovers them from the blob — a real,
live behavior change, not a dormant addition. This is *not* "Design B is now active": text
fields are still fully re-encrypted and DB-readable exactly as under Design A (Step 8's
`reencryptAllFields` call is untouched), there is still no `inMemorySensitiveContacts`
array, no merged contact-list view, and no mid-session resync — a raw SQLite read on an
unlocked device still sees every sensitive contact's name/phone/etc. regardless of depth,
same residual gap `forensic-trace-avoidance.md` S5 already documents. What changed is
narrower and self-contained: a sensitive contact's *messaging key material* specifically
now has the cryptographic guarantee Design B was proposed for, closing the concrete data-loss
risk that motivated Bug 108 in the first place (item 1 without item 3 would have made this
harm live on the very first activation). Verified by `SensitiveContactKeyRecordTests`
(`OccultaTests/SecureMode/SecureModeActivationTests.swift`) — the activation skip, the
deactivation rebuild's content-correctness, and Bug 108's own residual gap (a key rotation
received mid-session is still discarded by the rebuild — pinned as a known-gap regression
test, not fixed here) all have explicit coverage.

1. [x] **Skip sensitive contacts in activation Step 8's re-encryption loop.** Under Design A, all contacts (including sensitive) are re-encrypted to K_staged. Sensitive contacts' key records are now left under the old canonical key so they become genuinely unreadable after the key is deleted (`Manager+Security.swift`, Step 8 — `sensitiveIdentifiers`, derived from `blobContacts`). Text fields for sensitive contacts are still re-encrypted normally (so the shell stays syntactically valid) — only `reencryptKeyRecords` is skipped.

   **Found 2026-09-10, not yet fixed — `bugs.md` Bug 109: leaving the old ciphertext in place is itself a tell.** A row where every other field decrypts under the current canonical key and this one field category consistently fails `AES.GCM.open` is unmistakable, no-heuristic evidence that content was deliberately withheld — a structural leak Design A's uniform-decrypt-everywhere shape never had. Proposed remedy (not built): reseal those fields as random filler under the staged key instead of leaving them stale, mirroring `Manager.LayerStore`'s own `sealRandom` treatment of unused slots — see Bug 109 for the full tradeoff.

2. [x] **Fix `convertToMutableCopy` to carry `quantumKeyMaterialEncrypted` through to the draft.** `Contact+Manager.swift` now decrypts and JSON-decodes `record.quantumKeyMaterialEncrypted` and passes it as `quantumKeyMaterial` when constructing `Contact.Draft.Key`. This makes the blob complete under both designs — Design A ignores it (key records are never rebuilt from the blob); Design B depends on it.

3. [x] **Restore the `hasUnreadableKeys` rebuild path in deactivation Step 5b.** `ContactManager.restoreContact` (`ContactManager+Classification.swift`) now checks `hasUnreadableKeys` and, when true, rebuilds `contactPublicKeys` from the blob record's own `draft.contactPublicKeys` — the only surviving plaintext, captured before Step 11 deletes the old key — sealing each field (including `quantumKeyMaterialEncrypted`, via point 2) under the deactivation's own staged key via a new `rebuildKeyRecord` helper.

4. **No mechanism exists to persist an edit made mid-session, once the DB row is a dead shell — found 2026-09-09, checking whether it was already known.** Every `layerStore.push()` call site in the codebase was checked directly, not assumed: there are exactly two — activation's Step 6 (`Manager+Security.swift:643`, a one-time snapshot) and `pushDummyBlobSlot` (`Manager+Security.swift:1709-1720`, an empty decoy write on PIN collision, unrelated to real content). `rewrite()` (called at deactivation and force-recovery) doesn't refresh the real payload either — `writeNoOpFile()` overwrites all 32 slots with random junk, a wipe, not a content-preserving reseal. So under Design A this is harmless: the DB row stays the live, authoritative, editable copy for the whole session, and the blob is just a periodic snapshot taken once per activation. Under Design B it isn't harmless, because the DB row stops being able to hold anything readable the moment activation shells it — there is no other described path back to persistent storage. The four steps above cover activation (shell + snapshot), unlock (load blob into `inMemorySensitiveContacts`), and lock (wipe that array) — none of them says what writes an edit made *during* the unlocked session back to the blob before that wipe happens, or before a background kill skips the graceful-lock path entirely. As written, a sensitive contact edited mid-session and never re-sealed is lost the moment the process dies or backgrounds, not just hidden. **Needs a fifth step — reseal the blob (or the touched slot) whenever `inMemorySensitiveContacts` changes, not only at activation — designed and reasoned through before Design B is built, not discovered after.** `VAULT_KEY_LAYERING.md`'s S8 build stage inherits the identical gap if it copies these same four steps for vault entries; see its own item 12. Filed as `bugs.md` Bug 108.

5. **The fifth step Bug 108 asked for — designed 2026-09-09: reuse `push()` itself, not new machinery, and reuse the on-record sequence number rather than regenerating one.** Any mutation to `inMemorySensitiveContacts` — add, edit, delete, or a reclassification into/out of it — resyncs the blob synchronously, as part of the same operation that commits the mutation, before the caller can treat it as saved:

   1. Rebuild the full `LayerPayload.contacts` array from the *current* in-memory state — the same `LayerContact` construction activation's Step 6 already uses (strip images, etc.).
   2. Read this depth's `slotIndex` and `sequenceNumber` back from `AppLayerConfig` (`readBlobSlot(at:using:)`, `readSequenceNumber(at:using:)`) — both already written once at activation, unchanged by an edit, so reused as-is.
   3. Call `layerStore.push(payload, key: layerKey, slotIndex: slotIndex)` — the exact, already-shipped, already-tested function. Reseals all 32 slots with fresh nonces, the same cost `LayerStore` already pays for every classification change today (~1MB) — not a new cost category, since contact edits are occasional, not the "constantly" frequency `VAULT_KEY_LAYERING.md` item 11 weighed for vault entries.
   4. If `push()` throws, the mutation must not be reported as saved — mirroring how a normal contact save already requires `modelContext.save()` to succeed. An edit that lives only in memory must never look durable to the user.

   **Why the sequence number must be reused, not regenerated — checked directly, not assumed, before proposing this.** `pop()` validates `payload.sequenceNumber == expectedSequenceNumber`, where `expectedSequenceNumber` is whatever `AppLayerConfig` recorded once at activation (`writeSequenceNumber`, called from activation Step 6's own flow). A naive "just push again" design that generated a fresh random sequence number on every edit — matching how activation and `pushDummyBlobSlot` both call `Self.randomSequenceNumber()` — would make the *first* edit-triggered resync silently break every later `pop()` at deactivation with `sequenceNumberMismatch`, losing every edited contact. Reusing the on-record value avoids this. Random sequence numbers stay exactly what they already are — one per activation, not one per write — this step doesn't touch that.

   **Co-requisite this surfaces, fixed 2026-09-09: step 2 didn't have a sanctioned production read.** Step 2 needs a *repeatable, non-destructive* load on every unlock, but `pop()` is destructive — it erases the touched slot and reseals the rest — and the only non-destructive alternative, `readPayload(key:slotIndex:)` (`SecureMode+LayerStore.swift:244`), was explicitly commented *"Use for diagnostics and tests. Production code should use pop()."* Checked its actual body before promoting it, not just its comment: `readPayload` called `decodeSlot` directly, which only decrypts and JSON-decodes — neither of `pop()`'s two integrity checks (`sequenceNumber`, `slotIndex`) ran. Promoting it as-is would have silently accepted a stale blob from an older activation cycle, exactly what those checks exist to catch at deactivation. **Fixed:** `readPayload` now takes a required `expectedSequenceNumber` and runs both checks, throwing the same `Error.sequenceNumberMismatch`/`Error.slotIndexMismatch` cases `pop()` already defines — validated, non-destructive, the same shape minus the erasure. One call site (a test helper in `SecureModeActivationTests.swift`) updated; four new tests in `LayerStoreReadPayloadTests.swift` pin the round trip, both rejection paths, and repeatability across multiple reads. `LayerPayload.sequenceNumber`'s doc comment was also wrong — said "strictly increasing," actually a fresh random value per activation (`LayerStore.md`'s own "Sequence numbers" section confirms it deliberately isn't incrementing) — corrected in passing.

   **The mechanism itself is built, 2026-09-09 — `resyncSensitiveContactsBlob()` and
   `inMemorySensitiveContacts`, `Manager+Security.swift`, right before "Emergency recovery."
   Not wired to anything yet, and not independently meaningfully testable yet** —
   `inMemorySensitiveContacts` is `private(set)` with no writer, since steps 1-4 (which would
   populate it) aren't built, so there's no real content to push in a test beyond an empty
   array. Added `SecurityError.blobMetadataMissing` for the "no slot/sequence number on
   record" branches, replacing the `invalidStateTransition` misfit flagged when this was
   first designed. Blocked on steps 1, 3, and 4 above before it has a caller or a meaningful
   test.

- [x] **[bug]** Fix `isVisible(_:atDepth:)` fallback: `visibleThroughDepth` non-nil + decrypt failure → `return false`. Defense-in-depth — should not trigger in normal operation under Design A since all contacts are re-encrypted at activation and remain readable.
- [x] **[security]** `pinCollision` during activation silently dismissed — dedicated `catch Manager.Security.SecurityError.pinCollision` arm in `SummaryView` calls `onDone()` (same as `invalidStateTransition`), removing the binary oracle signal. A dummy blob slot (`pushDummyBlobSlot`) is written on collision to match the filesystem footprint of a real activation — same ciphertext size as a real blob slot write. Contact DB and `AppLayerConfig` are unmodified. (Bug 62, Gap 1 applied)

  **Remaining gaps (Bug 62):**
  - **Gap 2 — session-scoped rate limit (pending):** 1–2 activation attempts per authenticated session at a given depth. No persistent counter; immune to clock manipulation. Preferred over the rejected 24h-window approach (coercer has hours not days; counter presence is observable; non-colliding probes still create real layers).
  - **Gap 3 — targeted wipe blocked:** splitting `pinCollision` into `masterPINCollision` (hit `sealedNormalVerifiers[0]`) and wiping on master-PIN collision is blocked by the Design A hard-delete conflict (Bug 13). Sensitive contacts remain in the DB under Design A; wiping the blob without hard-deleting them leaves them visible at depth 0. No resolution path until Design B is implemented.

- [x] **[security]** `PINEntry` phase 2 (`.confirmThenSet`) rejects duress PIN == normal PIN — `submitSetPhase` checks `pin != normalPIN` before calling `onComplete`, providing a rejection at entry time rather than letting it silently fail at `SummaryView`. (Bug 64)

- [x] **Deactivation sequence — implemented.** Full key rotation, blob unseal, contact restoration, and state transition are in `Manager+Security.deactivateSecureMode`. `modelContext.autosaveEnabled = false` + `defer` added. Same crash window and deferred upgrade as activation above. Target sequence for `activeDBKeyTagEncrypted` refactor:

  1. State guard + verify normal PIN. Derive layer key from `deriveSecureModeKey()`.
  2. `unseal(layerKey:)` → `LayerPayload`. Abort if blob is missing or decryption fails. (→ `pop` once 32-slot upgrade lands)
  3. ~~Evaluate `LAContext` for biometrics~~ — **removed** (Bug 8). Vault PEKs not in blob; no biometrics needed.
  4. Create new SE key at a fresh UUID tag + new Keychain random. Derive `newDBKey`. **Old canonical key still valid. Crash here = orphaned new key, clean state.**
  5. `modelContext.autosaveEnabled = false`; `defer { modelContext.autosaveEnabled = true }`.
  6. Re-encrypt safe contacts in memory under `newDBKey`. Clear their `visibleThroughDepth` to `nil` in memory (erases activation watermark — Bug 12 fix).
  6b. Restore sensitive contacts from blob in memory: fetch existing shell by identifier, re-encrypt all fields under `newDBKey`, restore `signedAttributes` and `record.visibleThroughDepth ?? 0` (Bug 23 fix). Key records re-encrypted in-place via `reEncryptKeyRecords`. No rebuild path needed under Design A.
  7. ~~Restore vault PEKs~~ — **removed** (Bug 8). Restore vault entries in memory under `newDBKey`; clear `visibleThroughDepth` to `nil` (Bug 12 fix).
  8. ~~Generate fresh prekeys~~ — **not implemented**. Deferred.
  9. Accumulate remaining in-memory mutations: update `AppLayerConfig` with new key tag, clear `sealedDuressVerifier`. Cascade: truncate `sealedNormalVerifiers` and `sealedDuressVerifiers` arrays to depth N; restore blob payloads for any slots at indices N+1…end. Orphaned deeper configs are unreachable and must not be left in the store.
  10. `modelContext.save()` — **point of no return.** Single atomic commit: restored contacts + cleared watermarks + `AppLayerConfig` (new key tag, no duress verifier). Crash before = DB unchanged, old key still in config, Secure Mode still active. Crash after = deactivation complete.
  11. `PRAGMA wal_checkpoint(TRUNCATE)`.
  12. Delete old SE key + old Keychain random — cleanup only.
  13. `rewriteLayerStore()` — fresh no-op written.
  14. Transition state → `.pinOnly`.

- ~~`SecureModeOperation` SwiftData record~~ — **superseded.** The original design required a recovery record because Keychain key-promotion and DB writes were interleaved, creating a crash window between steps 10–11 that neither key could recover. The autosave approach above eliminates this: `modelContext.autosaveEnabled = false` accumulates all mutations in memory; a single `modelContext.save()` atomically commits contacts + `AppLayerConfig` (new key tag + verifier changes) as the sole point of no return. A crash before that save leaves the DB unchanged and the old key still authoritative. No stage tracking, no resume/rollback logic, no new data model required.

---

## Step 5 — Lock Gate & Counters

No wipe in any mode. `PINVerifyResult.wipe` is removed; `verify()` always returns `.wrong` on PIN mismatch. `consecutiveDuressCount` is removed. `wipeThresholdEncrypted` is removed from `AppLayerConfig`. Coercion resistance relies entirely on deniability (decoy view) and SE hardware rate-limiting for brute-force protection.

- [x] `PINEntry` shown on every `scenePhase == .active` when `security.requiresPIN`
- [x] `onDuress` stub in place. `onWipe` callback removed — `verify()` never returns `.wipe`.
- [x] **`identifyOwner` pre-check before `decryptSealed` in `buildOwnedBasket`.** `contactManager.identifyOwner(of:)` — a fingerprint-only lookup that never touches prekeys — is called before `decryptSealed`. If the sender is identified and `passSecurityControl` rejects them, the prekey is left intact. Without this, `decryptSealed` consumed the prekey before the depth gate could fire, making the bundle permanently undecryptable in normal mode. (Bug 49)
- [x] **`onOpenURL` respects Secure Mode — Option B: raw data queued, zero processing before PIN depth is known.**

  **Design:** one new `@State private var pendingFileData: Data?` and one new `private func processInboundFile(_ data: Data) async` that centralises all processing logic. `buildOwnedBasket` is only ever called from `processInboundFile` — both the unlocked-on-arrival path and the post-PIN path call the same function. No continuations, no advanced concurrency primitives.

  **`processInboundFile(_ data: Data) async` — the single processing path:**
  Contains everything that currently lives inline in the `onOpenURL` Task after the file is read: call `buildOwnedBasket(data)`, apply check point A (`isRestricted && !isSafeContact` gate), set `openedFileContents` or show error, handle all error cases. This function is called from two sites only — see below.

  **`onOpenURL`:**
  After reading file bytes into memory (`.occbak` vault restore check runs first, unaffected):
  - If `isLocked && security.requiresPIN`: store bytes in `pendingFileData`; return. No processing of any kind — no decryption, no sender identification, no shard operations, no identity challenge routing.
  - If not locked: `Task { await self.processInboundFile(data) }` — same as today, inline logic extracted to the shared function.
  - Share extension temp file deletion fires in `defer` after data is read into memory — unaffected.

  **`onNormal` (normal PIN entered):**
  After unlock: if `pendingFileData` is set, capture it, clear `pendingFileData`, dispatch `Task { await self.processInboundFile(captured) }`. One new block, three lines.

  **`onDuress` (duress PIN entered):**
  If `pendingFileData` is set: clear it without calling `processInboundFile`, show "This message was not addressed to you." Raw bytes discarded — identical error to any non-addressable file.

  **Already-unlocked paths (no queuing):**
  - Depth 0: `processInboundFile` runs immediately via `onOpenURL` — no change to observable behaviour.
  - Depth 1 (duress): same, check point A inside `processInboundFile` suppresses if sender not safe. Note: shard operations fire before check point A in this path — out of scope.

  **What does not change:** `openedFileContents` → `.sheet` pipeline, check point A logic, all error messages, `.occbak` vault restore path.
- [x] **[security]** Persistent incremental lockout counter stored in `AppLayerConfig` (two encrypted fields: `lockoutCountEncrypted`, `lockoutExpiryEncrypted`). Survives app kills. 5 free attempts; attempt 6 triggers a 1-minute lockout, escalating per attempt to a 24-hour cap at attempt 20. `verify()` checks the expiry before touching verifiers; wrong attempts persist count + expiry; any correct verification resets both fields to nil via `resetCounters()`. `PINEntry` shows a live countdown and disables the keypad while locked. `lockoutExpiry()` on `Manager.Security` lets `PINEntry.onAppear` restore a persisted lockout after an app kill.
- [x] **Decryption-failure contract** — enforced via `Manager.Security.isDisplayable(_:)` which wraps `isVisible(_:atDepth:)`. `ContactsListV2.visibleContacts` always filters through `isDisplayable` — a contact with a non-decryptable `visibleThroughDepth` is excluded regardless of depth or restricted state. `String.decrypt()` returning `""` on failure is intentional; the gate is at the list level, not the field level. `SECURE_MODE_DECRYPT_CONTRACT.md` documents every display call site. Timing normalisation deferred to Design B (see contract doc).
- [x] **Decryption side-channel audit** — all display paths enumerated in `SECURE_MODE_DECRYPT_CONTRACT.md`. Primary list gate (`isDisplayable`) provides consistent exclusion. Timing differences under Design A are theoretical (decrypt never fails in normal operation); documented as pre-Design-B requirement in contract doc.

---

### What Occulta adopts from VeraCrypt — and what it rejects

| Concept | Decision |
|---|---|
| No magic bytes in blob | **Adopted** |
| Fixed bucket sizes | **Adopted** |
| No-metadata blob format | **Adopted** |
| Two-layer cap | **Rejected** — any cap is a smoking gun |
| Outer/inner volume sharing physical space | **Not applicable** — Occulta uses an append-only stack file |

---

## Known Limitations

- **No deliberate data destruction mechanism.** The design relies entirely on deniability (decoy view) for coercion resistance. There is no panic trigger or wipe-on-wrong-PIN. Under severe coercion where deniability fails, the user has no in-app recourse beyond SE hardware rate-limiting. Explicit design decision — the wipe model was removed for simplicity and to eliminate accidental destruction risk.
- **Row count mismatch.** More rows exist than the app displays. Soft-deleted and locked rows each have plausible innocent explanations. Soft-deleted rows are capped at 50 per entity type (evicted FIFO) to prevent unbounded database growth. Soft-deleted rows must never appear in any UI, Share Index, or query result.
- **SE key rotation is observable. No mitigation.** A forensic examiner checking the Keychain will see a new SE key created and an old one deleted. The timestamp is correlatable with activation. The deletion IS the security mechanism — there is no way to hide it.
- **The blob file exists. Partially mitigated — backport pending.** The blob will be created at Step 1 migration time (see Step 1 security item), UUID-named, and continuously maintained via Step 4's background schedule. Until the backport ships, the blob file first appears with the Step 4 update, which correlates its presence with Secure Mode usage on all pre-Step-4 installs. After the backport, every Occulta install will have had a blob file for months before Step 4, decoupling the timestamps entirely.
- **App deletion while Secure Mode is active is unrecoverable. No mitigation.** The App Group container is deleted with the app. This is an OS constraint. Users must be warned before activation; no code fix is possible.
- **Counter resets on app kill. Mitigated by SE rate-limiting and persistent counter (Step 5).** `wrongPINCount` is in-memory only and resets on every app kill, enabling unlimited PIN attempts per session. SE hardware rate-limiting makes brute-force expensive regardless of counter state. The persistent Keychain-encrypted counter (Step 5) adds session-independent rate-limiting. No wipe is triggered — brute-force protection is entirely rate-based.
- **Crash logs may capture sensitive data.** iOS crash logs contain stack traces and register snapshots. A crash during blob serialization, contact re-encryption, or PIN verification could capture plaintext field data or PIN string fragments. Crash logs survive device wipe and are included in iCloud backups. If any external crash reporting (Crashlytics, Sentry, etc.) is ever added, it must sanitize all contact field data before transmission. Currently no crash reporting is used — document this constraint explicitly so it is not accidentally introduced.
- **SwiftData schema name is a forensic artifact. Mitigated.** Renaming `SecureModeConfig` to an opaque class name (Step 1) changes the table name to something non-descriptive. The schema fingerprint survives row deletion (store file is not deleted by `eraseAllData()`), but the table name no longer names the feature.
- **SwiftData WAL captures re-encryption transitions. Mitigated.** Activation sequence step 9 runs `PRAGMA wal_checkpoint(TRUNCATE)` before the staged key is promoted to canonical, zeroing the WAL and eliminating the re-encryption timestamp record.
- **Mass `ZMODIFICATIONDATE` update at activation is a deniability tell. Mitigated.** Re-encrypting safe contacts' fields under the new DB key at activation produces a mass timestamp update. Mitigated by writing all N contact records in a single batch at activation (step 5) — safe contacts get full field re-encryption, sensitive contacts get a `visibleThroughDepth` stamp — so every row shares the same modification timestamp. No count inference is possible.
- **`visibleThroughDepth` nil is a forensic tell. Mitigated.** A NULL vs non-NULL column value in a raw SQLite dump reveals which contacts are classified — even without decryption. Mitigated by always writing an encrypted value: safe contacts get `encrypt(Int.max)`, sensitive contacts get `encrypt(0)`. Legacy nil fields are migrated to `encrypt(Int.max)` or `encrypt(0)` in the activation batch write. After activation, no `visibleThroughDepth` field is ever nil.
- **Crash window between Keychain key promotion and AppLayerConfig save. Low severity.** The current activation and deactivation sequences call `commitStagedLocalDBKey()` (a Keychain rename — point of no return) and then `modelContext.save()` (writes the duress verifier / state transition) a few milliseconds later. A crash or process kill in that window leaves the DB in a consistent state but with a mismatched config: activation crash → contacts readable under new canonical key, but no duress verifier in AppLayerConfig → app boots as `.pinOnly`, user must re-activate. Deactivation crash → contacts readable under new canonical key, duress verifier still present → app boots as Secure Mode still active, user must re-deactivate (blob is intact). No data loss in either case; just a retry. `modelContext.autosaveEnabled = false` (added) prevents unrelated autosaves during the sequence but does not close this specific window. The `activeDBKeyTagEncrypted` design documented in the activation/deactivation sequences above closes it fully by making the DB save the point of no return; that refactor is deferred.
- **HKDF with PIN in the `info` field is non-standard. No mitigation planned.** `HKDF(inputKeyMaterial: seKey, info: label ∥ pin)` works correctly. Migrating to a more standard construction (PIN as IKM) would invalidate all existing verifiers. The current scheme has no known exploit; the finding is documented for external audits.
- **PIN strings are not zeroed after use. Mitigated.** Replacing `[Int]` digit storage with a `Data`-backed buffer and zeroing with `memset` after routing (Step 2) removes PIN heap residue.
- **~~Share index uninitialised on cold launch with gate down (Bug 69)~~. Resolved by removal, 2026-08-16.** The share index is gone — the recipient picker runs in the main app at the authenticated depth (Bug 84). No cold-launch initialisation to get wrong.
- **Bundle silently lost on cold-start after duress session. Intermittent (Bug 52).** iOS may drop the `onOpenURL` replay when the URL arrives via `connectionOptions.urlContexts` before the SwiftUI modifier is registered. Not consistently reproducible; no confirmed fix. User workaround: tap the bundle again.
- **`pinCollision` targeted wipe blocked. Design limitation (Bug 62 Gap 3).** Master-PIN collision wipe requires hard-deleting sensitive contacts (otherwise they remain visible at depth 0 after wipe). Hard-delete conflicts with the real user's normal-PIN access (Bug 13 resolution). No fix without Design B.
- **Secure Mode raises the bar against coercion and mid-tier adversaries. It is not state-actor proof.**

---

## Deferred: Panic Wipe

A deliberate, hard-to-trigger destruction mechanism for scenarios where deniability has failed and the user faces extreme duress with no exit. This is a future feature — **not implemented in the current version**. The wipe model (wrong-PIN counter → wipe) was removed for accidental-destruction risk; panic wipe replaces it with an explicit, deliberate trigger.

### Goals

- **Irreversible and immediate.** SE key deletion makes all encrypted artefacts permanently unreadable before the app closes. No network required.
- **Hard to trigger accidentally.** Cannot be initiated by a wrong PIN, a miscount, or a UI tap in a normal flow.
- **No forensic tell that the mechanism exists.** The trigger must be invisible from the normal UI; no button labelled "emergency erase."
- **No coercer-visible confirmation dialog.** A confirmation prompt would alert a coercer that destruction is in progress and give them time to abort. The trigger itself must be the confirmation.
- **Works in duress mode.** Must be reachable from the decoy view, not only from the real app.

### Candidate trigger designs

| Option | Mechanism | Notes |
|--------|-----------|-------|
| A | Hardware button sequence (hold Volume Up + Side Button ≥ 5 s while app is foregrounded) | No UI at all; very hard to discover accidentally; requires UIApplication event interception |
| B | Dedicated "destroy PIN" — a third PIN slot verified before the normal scan | Symmetric with the existing duress PIN; discoverable by an attacker who reads `AppLayerConfig` schema; requires a fourth verifier slot |
| C | Hidden gesture in the decoy contact list (e.g., three-finger long-press ≥ 3 s) | Low discoverability; gesture recogniser can be registered on the root view; risk of accidental trigger on a tablet |
| D | Remote kill switch — a specially crafted `.occ` message signed with a pre-registered kill key | Requires network; key management is a new attack surface; not offline-first |

**Preferred starting point: Option A (hardware button sequence).** It requires no new UI, no new crypto, and no additional verifier slots. The 5-second hold threshold and the requirement that the app be in the foreground make accidental triggering very unlikely.

### Implementation sketch (Option A)

1. **Register a `UILongPressGestureRecognizer` on the side button + volume-up chord** via `UIApplication.shared.beginReceivingRemoteControlEvents()` or a custom `UIEvent` subclass — or intercept via `UIWindow.sendEvent(_:)`. This requires UIKit bridging from the SwiftUI app.
2. **Threshold: 5 seconds continuous hold** before any action fires. Visual feedback must be absent or indistinguishable from the normal iOS screenshot/power-off affordance.
3. **Destruction sequence** (same order as the old `wipeAllSecureState` + `eraseAllData` chain):
   - Call `Manager.Security` to nil verifiers, replace arrays with fresh filler, and save `AppLayerConfig`.
   - Delete the blob file (`LayerStore.deleteFile()`).
   - Call `Manager.App.eraseAllData()` — deletes contacts, vault, prekeys, and finally SE keys.
   - On return, navigate to an empty app state (no splash, no error — indistinguishable from a first-launch install).
4. **No callback to `PINEntry`.** The trigger fires from the app level, bypassing the PIN flow entirely. `Manager.Security.needsPINEntry` is set to `false` after erasure.
5. **Forensic note.** After erasure, `maintainLayerStore()` on the next launch recreates the blob as a fresh no-op. The creation timestamp will postdate the wipe event — a forensic examiner can detect that the blob was recently recreated. This is the same limitation as the old wipe model and has no mitigation short of a secure-boot sealed log.

### Open questions before implementation

- Is UIKit event interception acceptable in a SwiftUI lifecycle app on iOS 16+?
- Should the trigger also post a silent iCloud note or AirDrop beacon so a remote party knows destruction succeeded? (Adds network dependency — conflicts with offline-first.)
- Should the destroy sequence be available before first Secure Mode activation (e.g., to destroy the app entirely before a border crossing)?

**Note, 2026-09-10:** step 3 of this sketch calls `LayerStore.deleteFile()`, which won't exist once the
removal below lands. This proposal was never built, so nothing to migrate — just don't resurrect that
call if this gets picked up later.

---

## Removal — Stage 0: design decision

**2026-09-10.** Settles what `activateSecureMode`/`deactivateSecureMode`/`purgeDraftsNotSafeAtCurrentDepth`
actually do once the blob mechanism and staged-key rotation are gone, so Stage 1 has something concrete
to implement against rather than deriving it while also deleting code. No code changes in this stage.
See the top-of-file note for why (AFU derivability, Bug 109) and `PASSPHRASE_LAYER_KEYS.md` for the
proposed v2.0.0 replacement.

### `activateSecureMode` — new shape

Signature changes: drops `contactManager`/`vaultManager` params (nothing left to re-key or classify —
see below) and drops `async` (nothing left that needs it; every remaining step is synchronous SE/Keychain
work and a `ModelContext.save()`). Stays `throws`.

1. Guard: `requiresPIN` true, and either `isRestricted` (nested activation, depth > 0) or
   `!isSecureModeActive` (fresh activation) — else `.invalidStateTransition`. Unchanged from today.
2. Verify `confirmingEntryPIN` against `sealedNormalVerifiers[currentDepth]`. Unchanged. No longer also
   derives `oldKey` up front — nothing downstream re-encrypts anything, so there's no key to derive.
3. Reject if `duressPIN` collides with any existing verifier at any depth — throw `.pinCollision`.
   **`pushDummyBlobSlot` is gone.** It existed to make a rejected collision leave the same filesystem
   footprint as a real activation; with no blob file at all, there's no footprint to match. The
   user-visible behavior this protected — `SummaryView`'s quiet `.pinCollision`/`.invalidStateTransition`
   dismissal, no oracle — is unaffected, since that's UI-level handling, not this internal side effect.
4. Build the new depth's duress verifier and a fresh normal verifier for depth+1 (`PINManager.buildVerifier`,
   unchanged mechanism).
5. Write both to `AppLayerConfig` (`writeDuressVerifier`, `writeNormalVerifier`), `writeCoercerBaseDepth(depth)`
   if `depth > 0`.
6. `modelContext.save()`, `resetCounters()`.

**Gone entirely, not just reordered:** `slotIndex`/`sequenceNumber` selection (blob-slot assignment —
no blob), `createStagedLocalDBKey()`, the Step-4-style contact classification pass (`blobContacts`/
`safeProfiles` split — nothing to classify *for*, since nothing gets sealed away or re-keyed; a
contact's `visibleThroughDepth` was set independently by the user via `setVisibility` and activation
never needs to touch it), `layerStore.push(...)`, the `reencryptAllFields`/`reencryptKeyRecords` loop
over every contact, vault-entry/`Message.Draft`/`Group`/`AppLayerConfig` re-keying, `commitStagedLocalDBKey()`,
the WAL checkpoint, `deleteSupersededLocalDBArtefacts()`, and the `catch`/rollback block — there is
nothing staged and nothing destructive, so nothing to roll back. A crash mid-function just means the
verifier write never landed; safely retryable, no partial state to reason about.

### `deactivateSecureMode` — new shape

Same signature changes as activation: drops `contactManager`/`vaultManager`, drops `async`, stays `throws`.

1. Guard: `sealedDuressVerifier != nil`.
2. Verify `confirmingEntryPIN` against `sealedNormalVerifiers[depth]`.
3. `config.clearVerifiers(from: max(1, depth))` — **the existing cascade logic, unchanged**: full
   deactivation (`sealedDuressVerifier = nil`, `setState(0, ...)`) if `depth <= 1`, otherwise a partial
   cascade (`setState(1, ...)`) leaving a shallower duress layer intact. This was always pure
   `AppLayerConfig` state, not rotation — it survives as-is.
4. `writeCoercerBaseDepth(0)`, `modelContext.save()`, `resetCounters()`.

**Gone entirely:** `layerStore.pop(...)` and its empty-payload fallback, `createStagedLocalDBKey()`,
the Step-4-style re-encryption loop over every contact (including the `restoreContact` calls for
blob-popped records), vault-entry/`Message.Draft`/`Group`/`AppLayerConfig` re-keying,
`commitStagedLocalDBKey()`, the WAL checkpoint, `deleteSupersededLocalDBArtefacts()`, the rollback
`catch`, `clearAllBlobMetadata()`/`clearBlobSlot`/`clearSequenceNumber`, and the async
`layerStore.rewrite()` on full deactivation.

**Also gone: the entire "preserve the real classification value across the cascade" problem.** Bug 23
and the extensive "never flatten to nil, preserve the real depth" commentary throughout the current
`Manager+Security.swift` exist because the old re-encryption loop touched every contact's
`visibleThroughDepth` on every cycle, and `restoreContact` had to put back the exact pre-existing value
for anyone tied to the departing layer. With activation/deactivation never touching that field, there is
nothing to preserve — it's a standing property of the row, decoupled from the PIN lifecycle entirely.

### `purgeDraftsNotSafeAtCurrentDepth` — needs a real (small) replacement, not a deletion

**Verified directly against `Manager+Security.swift:1414-1429`, not assumed.** Called from
`applyVerifyState` on every entry to a duress depth (not just activation) — the "defense in depth
alongside `reKeyOrPurgeAll` at activation" pass, since a contact classified sensitive *after* a layer
already existed could otherwise keep an old draft across any number of later duress-PIN entries. Current
body: fetch all `Contact.Profile` rows, compute `safeIdentifiers` via
`profile.isVisible(atDepth: currentDepth, usingKey: key)` (the hardcoded real-SE key, same
`Manager.Key().createHybridLocalEncryptionKey()` path every other classification check already uses —
nothing here goes through `Manager.Security`'s own injected `keyManager`), likewise
`allGroupIdentifiers`, then calls `Message.Draft.reKeyOrPurgeAll(safeContactIdentifiers:allGroupIdentifiers:oldKey:newKey:in:)`
with `oldKey == newKey` purely for its survive/purge semantics — surviving drafts get re-sealed under an
identical key with a fresh nonce, a no-op in effect. Finishes with `self.checkpointStore()` — **keep
this call**, it's not rotation-tied: the doc comment on `checkpointStore()` explains `PRAGMA secure_delete
= ON` only zeroes a freed page's content for the write that frees it, so an un-checkpointed WAL frame
from before the purge can still hold recoverable ciphertext under whatever key is still live. Still
needed once drafts are simply being deleted, no rotation involved.

**What Stage 1 replaces:** the identifier computation (`safeIdentifiers`/`allGroupIdentifiers` via
`isVisible(atDepth:usingKey:)`) stays exactly as-is — already SE-key-based and unrelated to rotation.
Only the `reKeyOrPurgeAll` call needs a lighter replacement that performs just its purge half (delete
whichever `Message.Draft` rows aren't tied to a safe contact/group) without the reseal-survivors half,
once `reKeyOrPurgeAll`'s rotation core is deleted in Stage 3.

**Still flagged, not resolved here:** `Message.Draft.reKeyOrPurgeAll`'s own internal purge logic (which
field(s) it reads to decide "not visible," whether it hard-deletes) wasn't read as part of this design
pass — Stage 1 should check `Message+Draft.swift` directly before writing the replacement, the same way
this section's own claims were checked against `Manager+Security.swift` rather than assumed.

### Call-site impact (cross-cutting, handled across Stages 1 and 4)

Every caller of `activateSecureMode`/`deactivateSecureMode` — `SecureModeSetupFlow`,
`SecureModeDeactivateFlow`, and every test that drives them — needs updating for the new signature
(fewer params, no longer `async`/`await`). Noted here so it isn't rediscovered mid-Stage-1; not scoped
in detail until that stage, since the mechanical fixups follow directly from the signature change above.

### What does not change

PIN verification and building (`PINManager`), the verifier arrays and cascade-clearing logic on
`AppLayerConfig`, `persistedDepth`/`pinEnabled(PerDepth)`/`coercerBaseDepth`/lockout fields and their
r/w helpers, `configurePIN`/`deactivatePIN` (the PIN-only, non-Secure-Mode-activation functions),
`Contact.Profile.isVisible(atDepth:)`/`VaultEntry.isVisible`, and everything in
`ContactManager+Classification.swift` except `restoreContact`'s key-rebuild block (which Stage 2 deletes
along with the rest of the blob machinery).

## Removal — Stage 1: done, 2026-09-10

`activateSecureMode`/`deactivateSecureMode` rewritten to exactly the Stage 0 shape — both now
`func ... throws` (no `async`, no `contactManager`/`vaultManager` params). `purgeDraftsNotSafeAtCurrentDepth`
now calls a new `Message.Draft.purgeUnsafe(safeContactIdentifiers:allGroupIdentifiers:using:in:)`
(`Message+Draft.swift`) — the purge-only half of `reKeyOrPurgeAll`, added rather than modifying
`reKeyOrPurgeAll` itself, which Stage 3 still deletes whole. `checkpointStore()` kept, per Stage 0's
own note.

**Confirmed safe to drop activation's own draft purge** (this was the one open question Stage 0 didn't
settle): checked directly that `Message.Draft` carries no `visibleThroughDepth`/`isVisible` field at
all — purging is its *only* mechanism for staying out of view, no UI-level filter backs it up. But its
one display surface (`ContactsListV2`'s "Draft" badge) is keyed off `contactIdentifiersWithDrafts`
matched only against contacts that already passed depth filtering, so an unpurged draft attached to a
hidden contact was never independently discoverable there regardless. Combined with
`purgeDraftsNotSafeAtCurrentDepth` still running on every duress-depth entry — including the first one
right after a fresh activation, before any UI renders — dropping activation's separate purge is safe.
Documented in the function's own doc comment, not just here.

**Deviation from the six-stage sketch, forced rather than chosen:** `DraftKeyRotationTests.swift`
called `deactivateSecureMode` with the old rotation-driving signature directly — its entire premise
(does key rotation preserve drafts) no longer has anything to test once deactivation doesn't rotate
any key, so it couldn't be patched to compile, only deleted. Deleted now rather than deferred to
Stage 3, since the test target has to compile as a whole. The other "fully dead" test files identified
in the scope map (`RotationRegistryTests`, `StagedKeyTests`, etc.) don't call activate/deactivate
directly, so they still compile for now and stay until Stage 3 as originally planned.

**Exit state, verified, not assumed:** app target and test target both build with zero errors.
`PINManagerTests.swift` (part of the "untouched" bucket) additionally cleaned of every stray
`await`/unused-binding warning the signature change produced, since it won't be revisited later.
`SecureModeActivationTests.swift`'s equivalent warnings were left as-is — that file gets substantially
rewritten in Stage 4 regardless, so cleaning warnings there now would mean touching most lines twice.
Full suite: 28 failures, all confined to `SecureModeActivationTests.swift` (blob lifecycle, WAL
persistence, cascade-depth-preservation, and `SensitiveContactKeyRecordTests` — all asserting on
behavior that no longer exists, exactly as scoped), 6 skips (unchanged `KeychainMigrationSETests`
baseline), every other suite green.

## Removal — Stage 2: done, 2026-09-10

Deleted the blob mechanism whole. `Occulta/Features/SecureMode/SecureMode+LayerStore.swift`
(`Manager.LayerStore`, `LayerContact`, `LayerPayload`) and `LayerArrayCodec.swift` removed outright.
`Manager+Security.swift` lost the `layerStore` property/init param, "Layer store maintenance"
(`maintainLayerStore`, `migrateBlobMetadataArrays`, `rewriteLayerStore`), "Design B: mid-session blob
resync" (`inMemorySensitiveContacts`, `resyncSensitiveContactsBlob`), `migrateBlobMetadataKeyIfNeeded`,
`protectedBlobSlots`/`pushDummyBlobSlot`/`randomSequenceNumber`, `StagedCryptoManager`, and
`SecurityError.blobMetadataMissing`; `forceDeactivateForRecovery` stripped of its blob lines and its
doc comment corrected to describe what it actually does now. `AppLayerConfig+Model.swift` lost
`sealedBlobSlots`/`layerSequenceNumbers` and every accessor/migration/filler method built around
them (`readBlobSlot`/`writeBlobSlot`/`clearBlobSlot`, the sequence-number trio, `clearAllBlobMetadata`,
`blobMetadataKey(from:)`, `migrateBlobMetadata`, `fillerSize`/`randomFiller`/`blobArrayFiller`/
`randomFillerArray`) — `ensurePadded()` now only pads `pinEnabledPerDepth`. `OccultaApp.swift` lost
the `maintainLayerStore()` launch call, `migrateBlobMetadataKeyIfNeeded()`, and the 30-second-debounced
`rewriteLayerStore()` view modifier. `ContactManager+Classification.swift` lost the whole
"Deactivation restore" section (`restoreContact`, `hasUnreadableKeys`, `rebuildKeyRecord`) — Design B
item 3, now vestigial since item 1's activation-side skip it paired with only mattered while
key-rotation-driven deletion of the superseded key was still a thing (removed in full by Stage 3, but
already unreachable in practice once Stage 1 stopped routing contacts through activation at all).

**Two pre-existing defects found and fixed while in this code, not caused by this removal:** a
dangling doc comment at the end of `Manager+Security.swift` describing a "re-encrypts every field of
every `Contact.Profile.Key` child" helper that had no function attached at all — confirmed via
`git show 880b980:...` to predate this entire session. And a bug introduced by this session's own
Stage 1: a stale duplicate old doc comment left above `activateSecureMode`'s new one instead of being
replaced — found on re-read, fixed.

**Deviations from the six-stage sketch, both forced by the same pattern as `DraftKeyRotationTests.swift`
in Stage 1 — a file slated for a later stage that already calls a symbol this stage deletes:**
- `AppLayerConfigRotationTests.swift` (Stage 3's bucket — rotation) had one test,
  `blobMetadataUnaffectedByRotation`, calling the deleted `writeBlobSlot`/`writeSequenceNumber`/
  `readBlobSlot`/`readSequenceNumber` directly. Mixed file, not wholly dead — removed that one test
  and its header's blob-orphaning sentence, kept the five scalar/gate-rotation tests (`reencrypt`
  itself is untouched until Stage 3).
- `SecureModeActivationTests.swift` needed the same treatment at larger scale: `ActivationComponents`/
  `makeComponents()` lost their `backend`/`layerStore` fields; the `readActivationPayload` helper and
  the whole `SecureModeBlobLifecycleTests` suite were deleted (wholly blob-dependent); two of three
  tests in `SecureModeClassificationTests` and one in `OriginDepthPreservationTests` that called
  `readActivationPayload` were deleted, keeping the one test in each suite that didn't touch it; the
  two `restoreContact`/`LayerContact`-based tests in `SensitiveContactKeyRecordTests` were deleted
  along with the now-unused `StubCrypto` helper, keeping the two tests covering item 1's activation-side
  skip itself. What's left in the file still compiles against the new PIN-only activate/deactivate but
  largely asserts on contact/vault-entry mutation that no longer happens — that's Stage 4's rework, not
  addressed here, exactly as Stage 1's own note anticipated.
- `EncryptedFieldCoverageTests.swift`'s `unprobedFields` still classified `sealedBlobSlots`/
  `layerSequenceNumbers`, now-deleted fields — its own tripwire (`appLayerConfigPropertiesReviewed`)
  caught this at runtime, not compile time, since dictionary literals don't reference the model's
  actual properties. Removed both entries.

**Exit state, verified, not assumed:** app target and test target build with zero errors. Full suite:
22 failures, all confined to `SecureModeActivationTests.swift` (`CascadeDeactivationDepthTests`,
`DepthMigrationRotationCompositionTests`, `GlobalTrusteeDepthPreservationTests`,
`OriginDepthPreservationTests`, `SecureModeRotationKeyGuardTests`, `SecureModeWALPersistenceTests`,
`SensitiveContactKeyRecordTests.safeContactKeyMaterial_reencryptedByActivation`,
`StrandedCeilingRotationTests`) — all asserting that activation/deactivation mutate contacts or vault
entries, which stopped being true in Stage 1, not anything this stage broke. 6 skips (unchanged
`KeychainMigrationSETests` baseline), every other suite green — including
`EncryptedFieldCoverageTests` and `AppLayerConfigRotationTests` after their fixes above.

## Removal — Stage 3: done, 2026-09-10

Deleted the rotation machinery whole, mapped by direct grep/read against the live tree rather than
trusting the original six-stage sketch — the sketch's own dead-test-file list turned out to be
partly wrong (see deviations below), the second time this removal effort has caught a scope-mapping
error by verifying directly instead of trusting a prior summary.

`Occulta/Data Models/Contact+Model+Reencrypt.swift` (`reencryptAllFields`, `reencryptKeyRecords`,
their private helpers) deleted outright — no production caller since Stage 1. `Group+Model.swift`
lost only its public `reencrypt(from:to:)` entry point and doc comment; the private
`reencryptAllDepths(usingKey:content:)` engine it shared with `purgeMembersFromDuressDepths`,
`refreshCiphertext`, and `purgeMember` stays, since those three have nothing to do with Secure Mode
key rotation. `AppLayerConfig+Model.swift` lost its "Key rotation" section (`reencrypt(from:to:)` and
the private `reseal` helper it alone used). `Occulta/Data Models/Message+Draft.swift` lost
`reKeyOrPurgeAll` — the rotation-driving function Stage 1's `purgeUnsafe` was added beside rather than
written in place of, exactly as that stage's `plan.md` entry flagged as deferred here.
`Occulta/Features/SecureMode/RotationRegistry.swift` deleted outright: a type-level classification
table with no purpose once nothing rotates.

`KeyManagerProtocol.swift` lost the protocol's four staged-key methods, `TestKeyManager`'s
`stagedLocalDBPrivateKey`/`stagedLocalDBPublicKeyData`/`stagedRandomComponent` and their
implementation section, and `simulatesHybridKeyUnavailable` (Bug 78's fault-injection flag — no
longer has any effect on the new PIN-only activate/deactivate, since neither calls
`createHybridLocalEncryptionKey()` at all). `localDBPrivateKey`/`localDBPublicKeyData`/
`randomComponent` changed `var` → `let`: `commitStagedLocalDBKey()` was their only mutator.
`Key+Manager.swift` lost `StagedKeyError` and the entire "Staged DB key (activation / deactivation
key rotation)" section including its private helpers (`retrieveExistingLocalDBPrivateKey`,
`generateAndStoreRandomComponent(account:)`, `retrieveRandomComponent(account:)`,
`deriveHybridKey(seTag:randomData:)`) — none shared with the canonical-key path, confirmed by grep
before deletion. `createLocalDBSEKey(tag:)` stays (still used by the canonical-key path), doc comment
corrected to drop its now-false "used for both the canonical key and the staged key" claim.

**Caught by the compiler, not the upfront map — `Manager.Key.deleteAllKeys()`** (the full-wipe
function) called `deleteSupersededLocalDBArtefacts()`/`rollbackStagedLocalDBKey()` directly to sweep
transient rotation artefacts in case a wipe fired mid-rotation. Missed in the initial grep because it
was checked by MARK-comment boundary rather than by searching the whole file for every call site of
the methods being deleted. Fixed by removing those two lines — nothing rotates any more, so there is
never a transient artefact to sweep.

**Deviations from the original dead-test-file list, both caught by direct verification before
deleting anything (the list itself, written before this stage, was checked against the live tree
first — unlike Stage 1/2's mid-execution catches):**
- `GroupOrphanPurgeTests.swift` was named as dead in the original sketch. It is not: it covers
  `ContactManager.purgeUnreadableGroups`, the *historical-damage repair* pass for groups stranded by
  a rotation that already happened — a live function, still called from `OccultaApp.swift`, with
  nothing to do with whether rotation exists going forward. It used `Group.reencrypt` only as a
  same-file test helper (`strand(_:from:)`) to manufacture a stranded group. Rewrote the helper to
  overwrite `encryptedID` with literal undecryptable bytes instead of rotating to a discarded key —
  same end state, no dependency on the deleted function. All 4 tests pass unchanged otherwise.
- `AppLayerConfigRotationTests.swift` was NOT in the original dead list (Stage 2 had already trimmed
  it to 5 scalar/gate-rotation tests, explicitly deferring full deletion to this stage per that
  entry's own note) — and turned out to be wholly dead now, since all 5 remaining tests call
  `AppLayerConfig.reencrypt` directly. Deleted outright.
- `SecureModeActivationTests.swift`'s `SecureModeRotationKeyGuardTests` (Bug 78, 2 tests) depended on
  `simulatesHybridKeyUnavailable`, which this stage deletes — forced the same treatment. Both tests
  already asserted on the old rotation-driven abort behavior, so nothing is lost that Stage 4 needed.

**`EncryptedFieldCoverageTests.swift` trimmed, not deleted, despite being named as fully dead in the
original sketch:** most of the file (the `FieldProbe` infrastructure, both models' `probes`/
`unprobedFields` tables, `AppLayerConfigFieldCoverageTests`, most of `EncryptedFieldTripwireTests`,
most of `EncryptedFieldRotationTests`) existed solely to guard the bug class of "a field silently
escapes the rotation" — which cannot happen once there is no rotation, so all of that is gone. One
test survives on different grounds: `readabilitySeparatesStrandedFromAbsent` doesn't call any deleted
function — it tests `ContactManager.hasReadableBundleVersion`'s three-state read directly, which
stays load-bearing forever for installs that went through a rotation before this removal shipped (the
stranding is permanent, historical damage, not an ongoing risk). File rewritten down to that one test
plus its fixtures; header rewritten to explain the reduced scope. Also dropped `sealString`, a
fixture helper with zero callers even before this stage's changes — flagging rather than silently
losing it, per the standing "mention pre-existing dead code" rule, since it did not survive the
rewrite.

**Flagged, not fixed — out of this stage's scope:** `KeyManagerProtocol.swift`'s
`simulatesSecureModeKeyUnavailable` flag is now completely unreferenced anywhere in the codebase
(confirmed by grep). Its own doc comment says it existed for Bug 86's migration guard
(`migrateBlobMetadataArrays`), which Stage 2 deleted — this is a Stage 2 orphan, not one this stage's
changes created, so left in place rather than removed under Stage 3's separate scope.

**Exit state, verified, not assumed:** app target and test target build with zero errors. Full suite:
20 failures, the same set Stage 2 left minus the 2 now-deleted `SecureModeRotationKeyGuardTests`, all
still confined to `SecureModeActivationTests.swift` and still asserting on contact/vault-entry
mutation that stopped happening in Stage 1 — nothing this stage's own changes broke. 6 skips
(unchanged `KeychainMigrationSETests` baseline). `GroupOrphanPurgeTests` (all 4) and the trimmed
`EncryptedFieldCoverageTests` (`readabilitySeparatesStrandedFromAbsent`) confirmed passing
individually, not just absent from the failure list.

## Removal — Stage 4: done, 2026-09-10

Rewrote `SecureModeActivationTests.swift` end to end rather than continuing to patch it —
everything Stage 2/3 left behind (`SecureModeWALPersistenceTests`, `CascadeDeactivationDepthTests`,
`GlobalTrusteeDepthPreservationTests`, `OriginDepthPreservationTests`,
`DepthMigrationRotationCompositionTests`'s two rotation-composition tests, `StrandedCeilingRotationTests`,
`SensitiveContactKeyRecordTests`'s two remaining tests, and `SecureModeClassificationTests`'s one
remaining test) asserted, in one form or another, that `activateSecureMode`/`deactivateSecureMode`
mutate `Contact.Profile`/`VaultEntry` fields — which stopped being true in Stage 1. There was nothing
left to patch; the file needed new content matching what the functions actually do now.

**What the new file covers, and why these three things specifically.** `activateSecureMode`/
`deactivateSecureMode`'s entire remaining job is PIN verification plus `AppLayerConfig` verifier
writes — so the file now tests exactly that surface, nothing broader:
- `SecureModeNonInterferenceTests` (4 tests) — the direct regression guard for the removal itself.
  A contact's depth fields and key material, and a vault entry's visibility ceiling, must be
  byte-identical before and after an activate/deactivate cycle — including a nested two-layer one,
  covering what `CascadeDeactivationDepthTests` used to check from the opposite (now-false)
  assumption — and regardless of whether the bytes are real ciphertext or garbage nothing can
  decrypt (`undecryptableBytesSurviveUnchanged`, replacing `StrandedCeilingRotationTests`'s concern
  with a simpler fact: unreadable bytes are no longer a special case at all, since nothing reads
  them). If a future change reintroduces data-touching in either function, this fails loudly.
- `SecureModeVerifierPersistenceTests` (2 tests) — a Bug-37-shaped check for the PIN-only shape,
  not a resurrection of the old one: the old regression was `contactManager.modelContext.save()`
  being skipped during a rotation that no longer exists; what's left to skip now is
  `Manager.Security`'s own `modelContext.save()` after its `AppLayerConfig` verifier writes. Fetches
  from a brand-new `ModelContext` after activation and after deactivation, confirming each reaches
  the persistent store rather than just the in-memory `AppLayerConfig` every other test in the file
  reads through `c.security` directly. No prior test anywhere verified this for the new shape —
  `SecurityStateTests` in `PINManagerTests.swift` checks `security.currentDepth`/`isSecureModeActive`
  in-memory, never a fresh-context fetch.
- `DepthMigrationInertnessTests` (1 test, `migrationIsInertAgainstForeignKeyRows`, carried over
  unchanged) — `DatabaseMigration.migrateDepthFieldsToFixedWidth` runs independently of Secure Mode
  entirely; its one piece of coverage that belonged in this file (a row sealed under an
  undecryptable key must be left alone, not resolved to a default) doesn't depend on activation at
  all and needed no rework, just a header and suite name no longer describing "composed with
  rotation" — a concept that no longer exists.

**Deliberately not added, and why:** `Message.Draft` purging (`purgeDraftsNotSafeAtCurrentDepth` /
`Message.Draft.purgeUnsafe`) has zero test coverage anywhere in the suite — confirmed by grep,
zero hits for either name outside their own definitions. This was a real gap left by Stage 1
(`DraftKeyRotationTests.swift` was deleted there with nothing added in its place), but it is not
this stage's gap to fill: `purgeDraftsNotSafeAtCurrentDepth` is called from `applyVerifyState`
(`Manager+Security.swift:643`), not from `activateSecureMode`/`deactivateSecureMode` at all — a
completely different code path this file was never about. Coverage for it belongs in
`PINManagerTests.swift`, which already exercises `applyVerifyState`/`verify()` extensively, not
here. Flagged for the user as a separate follow-up rather than pulled into this stage's scope.

**A structural side effect worth noting, not a deliberate design goal:** every test in the
rewritten file is SE-independent even though all are still gated `.enabled(if:
secureEnclaveAvailable())` for consistency with the rest of the Secure Mode suite. The old file's
gate existed because the old activation/deactivation touched `Contact.Profile` fields through the
**ambient** real `Manager.Key()`, forcing real Secure Enclave availability regardless of the
injected `TestKeyManager`. That coupling is gone along with the rotation it existed for — nothing
in the new file's call path touches the real key manager — but the gate was kept rather than
removed, matching the same convention `PINManagerTests.swift` uses for its own activate/deactivate
tests even though the same reasoning would apply there too. Not re-litigated here; out of scope.

**Exit state, verified, not assumed:** app target and test target build with zero errors and zero
warnings in the rewritten file (the stray `await`s on the now-synchronous `activateSecureMode`/
`deactivateSecureMode` that Stage 1 explicitly left for this stage are gone along with the code that
had them). Full suite: **`** TEST SUCCEEDED **`**, zero failures — the first fully green run since
this removal effort began. 6 skips (unchanged `KeychainMigrationSETests` baseline). All 7 new tests
(`SecureModeNonInterferenceTests` ×4, `SecureModeVerifierPersistenceTests` ×2,
`DepthMigrationInertnessTests` ×1) confirmed passing individually by name, not just inferred from a
clean overall result.

## Removal — Stage 5: done, 2026-09-10

Docs pass, no code changes — the four items from the original stage sketch plus doc debt found while
verifying against the live tree, following this feature's own standing rule (`bugs.md`, `plan.md`) to
document decisions in place rather than leave them implicit.

**`bugs.md`:** Bugs 106, 107, 108, 109 closed as moot, each with a **Status** update explaining why
(the exact mechanism each describes — `Manager.LayerStore`, its AAD fix, Design B, the sensitive-
contact key-record skip — was deleted whole in Stages 0-4) and the original text kept below verbatim,
matching this doc's existing "Closed (design decision — X removed)" convention (Bug 13). **A fifth
entry, Bug 110, was filed, not closed** — found while updating `forensic-trace-avoidance.md`'s S7:
`VaultEntry.visibleThroughDepth` is stamped once at creation and never reset, so a vault entry created
during one duress session can resurface in a later, unrelated session that reaches the same depth
number, since Stage 1 removed both the old bulk re-stamp (activation) and bulk reset (deactivation)
that used to prevent this. Surfaced to the user directly before writing anything, including a
correction of my own first-pass severity read (initially framed as a confidentiality leak; actually a
same-restriction-level stale-state issue, since anything stamped at a duress depth was already shown
to whoever reached that depth) — filed as Low severity, open, not fixed in this pass, per the user's
explicit choice to log it rather than fix it now.

**`forensic-trace-avoidance.md`:** the most substantial rewrite of this stage — its security model
rested on blob + DB-key-rotation, both gone. Added a top-of-document notice explaining the removal and
its reasoning (AFU threat model derives both keys equally, established earlier this session and
recorded in `plan.md`'s Stage 0 entry and `PASSPHRASE_LAYER_KEYS.md`). Retired in full, original text
kept as historical record: the entire **Blob File Forensics** section (B1-B7), **S1** (DB key
rotation), **K3** (blob key domain separation). Rewritten to describe current behavior rather than
retired outright, since the underlying invariant or field is unchanged and only the mechanism
maintaining it changed: **S5** (Design B is not a future upgrade path any more — the machinery it
depended on is gone, not merely deferred), **S6** (the invariant holds via creation-time stamping and
the launch migration alone now, not a second enforcement point at deactivation), **S7** (rewritten
around Bug 110's finding — this is the entry where writing the "what changed" section surfaced the
bug), **S9** (`globalTrusteeDepth` is simply never touched by Secure Mode's lifecycle now, and is
unaffected by Bug 110 for a stated reason: it is a deliberate depth-severity policy, not an accidental
session artifact, the same distinction that exempts `originDepth`). Minor stale-phrase fixes: S8's
"local DB key that rotates during activation," the OS-Level-Artifacts section's opening paragraph
naming S1 alongside file protection.

**Stale doc-comment references fixed in code**, found while doing the above and flagged during
Stages 2-4 rather than fixed inline at the time: `DepthCodec.swift` (two comments describing
"staged" vs. "canonical" keys and `commitStagedLocalDBKey()`, neither of which exist), `Contact+
Manager.swift` (the injectable-crypto `save` overload's doc comment claiming Secure Mode activation
as its user — it never had another one now that Stage 1 shipped), `Contact+Manager+Groups.swift`
(a dead pointer to `reencryptAllFields`'s deleted inline note, redirected to
`EncryptedFieldRotationTests.readabilitySeparatesStrandedFromAbsent`), `OccultaApp.swift` (the
`schema` array's doc comment claiming `RotationRegistryTests` as its reason for existing, which is
also gone). Two comments in `Group+FormV3.swift` and `OccultaApp.swift` that name `reencryptAllFields`
were deliberately left alone — they describe a specific historical version range (installs that
activated Secure Mode on 1.10.0/1.10.1), accurate as history, not implying the function exists today.

**Three dedicated docs retired with a top-of-file notice, original content kept as historical
record, not otherwise rewritten:** `ROTATION_COVERAGE.md` (never built — no code was ever written
against it), `SecureMode+RotationContract.md` (its mandatory-checklist framing corrected explicitly,
since "must pass through this before merge" would otherwise mislead a future contributor; one
invariant, I7 — `AppLayerConfig` must always exist — flagged as still true and pointed to where it's
now documented), `LayerStore.md` (entirely about the deleted mechanism, no mixed content).
`scenarios.md` got a file-level notice rather than per-scenario edits — dozens of its ~15 sections
describe the removed rotation/blob behavior verbatim, and annotating each individually was judged out
of proportion to a docs-cleanup pass; scenarios about PIN state, depth routing, lockout, and unrelated
UI tells are unaffected and still accurate.

**Explicitly out of scope, flagged rather than touched:** `VAULT_KEY_LAYERING.md`
(`Occulta/Features/Vault/`) references `Manager.LayerStore` extensively as design precedent for the
still-live, actively-developed `BEKArray` work — this is this branch's actual primary feature, not
part of the Secure Mode removal, and rewriting a live spec document belongs to whoever continues that
work, not to this pass. `secure-mode-architecture.html`, an interactive architecture diagram with
`Manager.LayerStore` as a graph node, was left untouched — editing diagram data is a different kind of
work than the prose changes in this stage, and wasn't named in the original stage sketch.

**Exit state:** app target and test target build with zero errors (verified — the stage touched a
handful of `.swift` doc comments alongside the `.md` files, so this wasn't purely a markdown-only
change). No test suite run: nothing in this stage changed runtime behavior, only documentation and
comments.

## Removal — Stage 6: done, 2026-09-10 — final verification

**A final sweep caught three more stale doc-comment references Stage 5 missed** — all stated as
*current* fact rather than history, unlike the ones Stage 5 correctly judged safe to leave:
`SecureMode+LayerStoreBackend.swift`'s header claimed `Manager.LayerStore` as an active co-consumer of
the shared backend protocol (it is deleted; `VaultManager.Backup.LayerStore` is the sole remaining
one — the file itself stays, only its header was wrong), `Vault+Manager.swift` claimed
`Manager.Security` "mirrors... holding a `layerStore: Manager.LayerStore`" (that property no longer
exists), and `InMemoryLayerStoreBackend.swift` claimed it was "injected via
`Manager.LayerStore(backend:)`" (nothing constructs one any more — `VaultManager.Backup.LayerStore` is
its only real caller, confirmed by `BEKArrayTests.swift`'s actual usage). Found via a repo-wide grep
for every deleted symbol name (`Manager.LayerStore`, `LayerContact`, `LayerPayload`,
`StagedKeyError`, the four staged-key methods, `reencryptAllFields`, `reencryptKeyRecords`,
`RotationRegistry`, `reKeyOrPurgeAll`, `sealedBlobSlots`, `layerSequenceNumbers`,
`blobMetadataMissing`/`blobMetadataKey`, `migrateBlobMetadata`, `inMemorySensitiveContacts`,
`resyncSensitiveContactsBlob`, `restoreContact`, `hasUnreadableKeys`, `rebuildKeyRecord`,
`pushDummyBlobSlot`, `maintainLayerStore`, `rewriteLayerStore`) across `Occulta/` and `OccultaTests/`,
checked one by one against whether each was a live compile-relevant reference (none were — everything
remaining was either these three stale doc comments or accurate historical/precedent citations,
matching the pattern Stage 5 already established for `Group+FormV3.swift`/`OccultaApp.swift`'s
version-specific historical mentions). `Occulta/Features/Vault/`'s own design docs and code
(`BEKArray.swift`, `Vault+Manager+Backup.swift`, `VAULT_KEY_LAYERING.md`) cite `Manager.LayerStore`
extensively as the precedent `VaultManager.Backup.LayerStore` was deliberately shaped after — left
untouched, same reasoning as Stage 5: accurate as design history for a still-live feature, not this
removal's scope to rewrite.

**Full local run, the actual exit criteria this project's own `CLAUDE.md` states:** 834 tests
executed, **`** TEST SUCCEEDED **`**, zero failures, exactly 6 skips — all `KeychainMigrationSETests`,
the documented device-only baseline. No other suite skipped, confirming a real Secure Enclave was
available for this run and the green result isn't hiding an unavailable-Enclave false pass.

**Cumulative diff for the whole effort** (`git diff --shortstat` from the last pre-removal commit,
`2ea7df3`, to this stage's `HEAD`, `Occulta/` and `OccultaTests/` only): **39 files changed, 1,062
insertions(+), 6,546 deletions(-)**. Net: the blob mechanism, the staged-key rotation protocol, and
every re-encryption pass built on top of either are gone; `activateSecureMode`/`deactivateSecureMode`
are PIN-verification-and-verifier-writes only, exactly the Stage 0 design decision, now built,
tested, and documented end to end.

**What this removal effort settled, for anyone picking this back up later:**
- Secure Mode's confidentiality guarantee against the realistic threat model (AFU extraction, no
  biometric gate) was never the blob or the rotation — it was always the file-protection/PRAGMA
  measures in `forensic-trace-avoidance.md`'s S2-S4, unaffected by any of this. The blob and rotation
  bought deniability-adjacent forensic cover (B1-B7, K3) and a *historical* page-slack erasure (S1)
  against a weaker, locked-device attacker — real, but not the one this app's own threat model
  centers on, and not worth the complexity once looked at directly.
- Design B (unreadable DB shells, blob as sole readable copy) is not a deferred future upgrade any
  more — it would need rebuilding from nothing, against the same analysis that concluded it wasn't
  buying real protection either.
- One open item from this effort, not closed here: `bugs.md` Bug 110 (`VaultEntry` depth-stamp reuse
  across unrelated duress sessions) — low severity, logged, not fixed, per the user's explicit choice
  in Stage 5.
- One real testing gap from Stage 1, not filled here: `Message.Draft` purging
  (`purgeDraftsNotSafeAtCurrentDepth`/`purgeUnsafe`) has zero test coverage anywhere, flagged in
  Stage 4's entry — belongs in `PINManagerTests.swift`, since the purge runs from `applyVerifyState`,
  not `activateSecureMode`/`deactivateSecureMode`.
- `PASSPHRASE_LAYER_KEYS.md` (v2.0.0 proposal, replacing numeric PINs with diceware phrases) remains
  filed and not started — explicitly out of scope for this removal, which was about deleting
  complexity, not adding a new layer.

Six stages, six commits (`880b980` through this one), each independently reviewable and revertable,
none skipped, none reordered from the original sketch except the two forced deviations Stage 1 and
Stage 3 each documented at the time they happened.

## Post-removal fix: `deactivateSecureMode` now pops one depth at a time (Bug 111)

Found immediately after Stage 6 closed, during a user conversation walking through what
`activateSecureMode`/`deactivateSecureMode` do now — unrelated to the removal itself, a pre-existing
state-machine defect dating to the first multi-layer commit (`22762fb`, 2026-06-03), never caught
because the only prior multi-layer test used a 2-layer stack, which can't distinguish "always land at
depth 1" from a genuine one-level LIFO pop (both give the same number there).

**Fixed:** cascade deactivation used to jump straight to depth 1 regardless of starting depth;
`deactivateSecureMode` now computes `newDepth = max(0, depth - 1)` and lands there, popping exactly
one layer per call — matching the stack model activation already uses (one layer pushed per call).
`coercerBaseDepth` now becomes `newDepth` instead of unconditionally resetting to `0`, so "Deactivate
Protection" stays reachable at each intermediate depth immediately, without a re-verify between pops.
Full writeup, root cause, and fix detail: `bugs.md` Bug 111 (Closed, Fixed).

Two new tests in `PINManagerTests.swift`'s `SecurityMultiLayerTests` build an actual 3-layer stack to
exercise this (`deactivation_fromDepth3_popsOneLevelToDepth2`,
`deactivation_threeLayerStack_popsOneLevelPerCall`); the existing 2-layer test's `state` assertion was
corrected from `.duress` to `.normal` to match the `coercerBaseDepth` change. Full suite: 0 failures,
6 skips (baseline), confirmed after the fix.

## Post-removal fix: VaultEntry orphaning closes the Bug 110 depth-reuse gap

Bug 110 (`bugs.md`, filed during the same post-Stage-6 conversation as Bug 111, unrelated to it):
`VaultEntry.visibleThroughDepth` is stamped once at creation and never reset, so an entry created in
one duress session stayed exact-match-visible to a later, unrelated session reaching the same depth
number — depth numbers are reused since Stage 1 stopped activation/deactivation touching application
data, and nothing replaced the old bulk re-stamp/reset that used to prevent this.

**Design, settled after exploring the shard-custody machinery together rather than guessing:** a new
`VaultEntry.deletionToken` field, mirroring `Contact.Profile.deletionToken` exactly — encrypted, fixed
sentinel content, physically kept rather than hard-deleted (the same forensic reasoning `bugs.md`
Bug 13 already established for contacts), capped at 50 with oldest-first eviction.
`VaultManager.fetchAllEntries()` — the single central read every consumer goes through — now filters
`deletionToken == nil`, making orphaning a real, one-change exclusion from every functional path:
shard custody, backup export, the return buffer, the UI list, not just the display layer. Caught in
the same pass: `deleteAllEntries()` (panic wipe) would have silently stopped erasing orphaned rows had
it kept routing through the now-filtered `fetchAllEntries()` — fixed to fetch unfiltered.

`Manager.Security.orphanVaultEntries(freedFrom:)` runs from `deactivateSecureMode` and
`forceDeactivateForRecovery`, orphaning any entry whose stamp names a depth the call just freed.
`visibleThroughDepth` itself is left untouched — a historical record now moot for every functional
purpose, since exclusion makes it unreachable regardless of its value.

**The shard-revocation side was traced end to end before concluding anything needed building for
it, and none did:** `ShardCustodyManager.buildExpectedShards` → `VaultManager.shardRecordsForTrustee`
already reads through `fetchAllEntries()`, so an orphaned entry's shards simply stop appearing in the
`expectedShards` list sent to a trustee on the next bundle — the trustee's existing
`processExpectedShards` already deletes anything absent from that list (a real implicit-revoke
mechanism documented in `SHARD_PROTOCOL_CASES.md`, initially and incorrectly assumed not to exist at
all before checking). Full writeup, including the rejected sentinel-on-`visibleThroughDepth`
alternative and why it was wrong: `bugs.md` Bug 110 (Closed, Fixed).

Three new tests in `VaultEntryOrphaningTests` (`SecureModeActivationTests.swift`) cover the core
resurfacing fix, a shallower-layer survival case, and cap eviction — the last of which caught a real
ordering bug in the first implementation pass (`toOrphan` needed sorting before processing, not just
`alreadyOrphaned`, for eviction to be reliably oldest-first within a single multi-entry batch). Full
suite: 0 failures, 6 skips (baseline), confirmed after the fix.

## Post-removal refinement: `VaultEntry.deletionToken` becomes always-populated, not nil-based

Raised in the same conversation, immediately after the fix above shipped: nil-vs-non-nil is itself a
free, zero-decryption signal (SQLite tracks column nullability independent of any encryption on the
value), so `deletionToken`'s original design — mirroring `Contact.Profile.deletionToken`'s nil/non-nil
pattern exactly — still let a `SELECT COUNT(*) WHERE deletionToken IS NOT NULL` answer "how many are
orphaned" with no key at all.

**Fixed by making the field always non-nil**, content instead of presence carrying the meaning —
`VaultEntry.liveToken`/`orphanedToken`, two fixed-width one-byte sentinels that encrypt to the same
ciphertext length, the identical principle `AppLayerConfig.pinEnabledPerDepth` already uses (Bug 51,
"no plaintext boolean flags"). `isOrphaned(usingKey:)` replaces every nil check, failing safe on
anything ambiguous. Stamped live at creation by `addEntry` and the backup-restore path.
`fetchAllEntries()` loses its free SQL predicate as a result — decrypting a column can't be pushed
into a `WHERE` clause, so it now fetches every row and filters in Swift with one derived key reused
across all of them. `deleteAllEntries()` (panic wipe) already fetched unfiltered and needed no
further change.

**Deliberately not extended to `Contact.Profile.deletionToken`**, discussed and declined in the same
conversation: it's shipped (a real migration, not a lightweight default), touches far more hot-path
call sites over a much larger row count, and — found while checking the full usage surface before
proposing anything — `PQmigration.swift`'s `migrateScrubDeletedDepthStamps` already uses its
nil/non-nil status as a readability oracle for rows stranded by an old key rotation; changing the
field's shape would mean redesigning that oracle, not just its predicates. Same marginal benefit,
much higher cost — left as-is.

All three `VaultEntryOrphaningTests` updated in place (same tests, assertions moved from `== nil`/
`!= nil` to `isOrphaned(usingKey:)`) and reconfirmed passing. Full suite: 0 failures, 6 skips
(baseline). Full writeup: `bugs.md` Bug 110's "Refined the same day" note.

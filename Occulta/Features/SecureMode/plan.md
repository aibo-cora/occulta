# Secure Mode — Implementation Plan

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
    var sealedNormalVerifier:     Data?   // nil → no PIN configured (requiresPIN == false)
    var sealedDuressVerifier:     Data?   // nil → Secure Mode not active (isSecureModeActive == false)
    var wipeThresholdEncrypted:   Data?   // encrypted Int; default 3
    var persistedDepth:           Data?   // encrypted RoutingDepth; always non-nil after first config write
    var pinEnabled:               Data?   // encrypted Bool; false = gate suppressed under coercion

    // Multi-layer fields — parallel arrays, one entry per depth
    var sealedNormalVerifiers:    [Data]   // index = depth; [0] is master; [N] == sealedDuressVerifiers[N-1]
    var sealedDuressVerifiers:    [Data]   // index = depth; entry at N drives push to N+1
}
```

The existing `sealedNormalVerifier` / `sealedDuressVerifier` scalar fields become `sealedNormalVerifiers[0]` / `sealedDuressVerifiers[0]`. Migration: on first launch after multi-layer support ships, wrap existing scalar values into index-0 of the arrays.

**[security]** Array length directly encodes layer depth to a forensic examiner. Both arrays must be padded to a fixed maximum length (e.g. 8) with random entries of identical byte size to real verifiers on every write. The padding entries must be indistinguishable from real verifiers (same-length AES-GCM ciphertext, randomly generated). `verify()` simply ignores entries that fail to open. A forensic examiner always sees exactly 8 blobs per array on every install, regardless of actual depth.

`persistedDepth` stores the current `RoutingDepth` (`.normal` or `.duress`) via `writeRoutingDepth` / `readRoutingDepth`.
`pinEnabled` stores the gate state (Bool) via `writePinEnabled` / `readPinEnabled`. Falls back to `true` on any decode failure — always demand a PIN rather than silently opening the app.
Both fields are written at first config creation so their presence never leaks state — a consistently non-nil field is forensically opaque.

All properties optional to avoid SwiftData migration on schema evolution. `wipeThreshold` is encrypted because it reveals Secure Mode configuration to a forensic examiner.

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

**[security]** This validation must use a pure `checkPIN(_:against:)` method — not `verify()`. `verify()` increments `wrongPINCount` on each non-match. Checking N verifiers for uniqueness would increment the counter N times, potentially triggering a spurious wipe. `PINManager.checkVerifier()` already exists as a pure function; the uniqueness check must call it directly without going through `Manager.Security.verify()`.

### `Manager.Security` public interface

```swift
// State
var requiresPIN:    Bool    // state != .noPIN
var isRestricted:   Bool    // currentDepth > 0
var appLockEnabled: Bool    // whether the PIN overlay gate fires on scene activation

// Setup
func configurePIN(_ pin: String) throws                                              // .noPIN → .pinOnly
func activateSecureMode(confirmingEntryPIN: String, duressPIN: String) throws        // .pinOnly/.duress → .normal
func deactivateSecureMode(confirmingEntryPIN: String) throws                         // .normal → .pinOnly (depth 0) / .duress at depth N-1 (depth N > 0)
func deactivatePIN(confirmingNormalPIN: String) throws                               // .pinOnly → .noPIN

// Coercion-resistant gate (sticky-depth)
func disablePINFromCurrentDepth(confirmingPIN: String) throws     // lowers gate; verifiers intact; depth filter stays
func reEnablePIN(_ pin: String) -> Bool                           // routes entered PIN to matched verifier depth; returns false on no match

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

**Wipe threshold behaviour:**
- `.noPIN` / `.pinOnly` — no wipe
- `.normal` / `.duress` — 3 wrong PINs → `.wipe`; N consecutive duress entries → `.wipe`

---

## Step 1 — PIN Infrastructure ✅

- [x] `Tags` enum `CaseIterable`, `secureModePin` case, `deleteAllKeys()`
- [x] `deriveSecureModeKey()` on `Manager.Key` and `KeyManagerProtocol`
- [x] `TestKeyManager` in-memory implementation
- [x] `SecureModeConfig` SwiftData model — all optional, `wipeThresholdEncrypted`, no salt, no boolean flags
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
- [x] **[security]** `wipeThreshold()` fallback behavior must be explicitly defined and tested. If `wipeThresholdEncrypted` fails to decrypt (corrupt data, wrong key, migration issue), the method must return a hardcoded secure default (3) — not 0 (immediate wipe on first wrong attempt) and not a large number (no wipe ever). Unit tests added: `nilEncryptedData_returnsFallback`, `corruptEncryptedData_returnsFallback`, `validThreshold_roundTrips`.
- [x] **[security]** Create the no-op blob payload at Step 1 migration time, not at Step 4 activation. A forensic timeline that shows the blob file appearing when the user updates to the Step 4 version directly correlates blob presence with Secure Mode usage on all pre-Step-4 installs. Backporting blob creation to the Step 1 migration (already shipped) decouples the timestamps: every Occulta install will have had a blob file for months before Step 4 ships. Implemented in `SecureMode+Blob.swift` (`Manager.Blob`): UUID-named `.occbak` file in `group.com.occulta.shared/blobs/`, AES-GCM with HKDF-SHA256 blob key, bucket-padded random plaintext, 24-hour rewrite. Called from `OccultaApp.init()` behind the `secureMode` feature flag.

---

## Step 2 — PIN Entry UI ✅

- [x] `PINEntry` view — neutral black, no branding
- [x] 6-digit keypad, `isVerifying` lock preventing double-submission
- [x] Fixed 500ms gate equalising timing across all outcomes
- [x] Two-phase setup: first entry stores PIN, second confirms; label switches "Passcode" → "Confirm Passcode"
- [x] Routes on result: `.normal` → `onNormal(String)`, `.duress` → `onDuress()`, `.wrong` → shake, `.wipe` → `onWipe()`
- [x] Reads `Manager.Security` from environment; counter lifetime off the view
- [x] `onNormal: (String) -> Void` (widened from `()` so Settings can pass PIN to `deactivatePIN`)
- [x] App launch gate in `OccultaApp` — `isLocked` state, `.overlay` on `TabView`, no animation, locks on every `scenePhase == .active`
- [x] **[security]** Also set `isLocked = true` on `scenePhase == .inactive`. iOS captures the app-switcher screenshot on `.inactive` (before going to background), while the current implementation only locks on `.active` (returning to foreground). Every time the user backgrounds the app, the live screen content is frozen in the app switcher and readable without unlocking.
- [x] **[security]** Zero PIN digits after use. Replace `[Int]` digits storage with a `Data`-backed buffer; after `submit()` routes the result, zero the buffer with `memset`. Removes PIN heap residue. Low practical exploit risk given SE binding, but correct hygiene and removes the finding from security audits.
- [ ] `onWipe` wired to `Manager.App.eraseAllData()` — **deferred; dry-test first**

---

## Step 3 — Settings UI + Contact Classification + Decoy View

### Settings → Security (4-state)

- [x] "Enable PIN" toggle — transitions `.noPIN ↔ .pinOnly` via `PINEntry` sheet
- [x] **[security]** Add `checkNormalPIN(_ pin: String) -> Bool` to `Manager.Security` — thin wrapper around `PINManager.checkVerifier` with no counter mutation. Replace the `security.verify()` call in `PINEntry.submitConfirmPhase` with this method. Using `verify()` for Settings-level PIN confirmation incorrectly increments `wrongPINCount` on each wrong attempt, which is semantically wrong (a Settings confirmation is not a lock-screen attack attempt) and pollutes the in-memory counter state.
- [x] "Activate" button confirmation PIN (depth 0): `checkNormalPIN`. Sheet calls `activateSecureMode(confirmingEntryPIN:duressPIN:)` on success.
- [ ] "Activate" button confirmation PIN (depth N > 0): `checkDuressPIN(N-1)` — the duress PIN that opened this layer. Requires `Manager.Security.checkCurrentLayerEntryPIN(_ pin: String) -> Bool`. Using `checkNormalPIN` at depth > 0 would expose the master PIN to an observer during setup.
- [x] **[design — pre-ship]** Biometric unlock is not possible. `LAContext` cannot be routed to different app states — Face ID success always returns the same result regardless of which depth is active, meaning biometrics would always open the real app and bypass the duress view entirely. The app is PIN-only. Grace period implemented: lock on `.inactive` for screenshot protection; suppress PIN prompt on `.active` if `lastUnlockDate` is within 5 min. Zero grace period in restricted mode. `lastUnlockDate: Date?` on `Manager.Security` (in-memory only). Overlay shows blank screen within grace period (screenshot protection without PIN friction), full `PINEntry` outside it.
- [x] "Deactivate" button — visible when `state == .normal`. Sheet calls `deactivateSecureMode(confirmingNormalPIN:)` on success.
- [ ] **[design]** Activate / Deactivate button visibility — same cycle repeats at every depth:
  - Activate visible at: `.pinOnly` and `.duress` (can always go one layer deeper from where you are)
  - Deactivate visible at: `.normal` only (never at `.duress` — coercer in duress mode never sees it)
  - After deactivating from "normal at depth N", returns to `.duress` at depth N-1 (the beginning of the cycle at this level)
  - Confirmation PIN = the PIN that unlocked the current depth (normal PIN at depth 0, duress PIN at depth N > 0)
- [x] **[design]** Contact selection must be part of the activation flow, not a standalone Settings item visited later. Implemented as `SecureModeSetupFlow`: Education → PIN setup (confirmThenSet) → Contact classification → Summary/Activate (4 steps, step-dots indicator). `activateSecureMode` called only on the final confirm step.
- [x] **Bug 24** — "Activation Failed" alert reveals Secure Mode state when flow is traversed in duress mode. See `Docs/bugs.md`.
- [x] **Bug 25** — `ContactClassification` exposes sensitive contacts when opened in duress mode. See `Docs/bugs.md`.
- [x] **[design]** "Deactivate Secure Mode" sheet calls `verify()` internally (via `PINEntry` in `.verify` mode), then `onNormal` calls `deactivateSecureMode(confirmingNormalPIN:)` which calls `PINManager.checkVerifier` again — double-verification plus counter mutation. Wrong attempts in this sheet increment `wrongPINCount` and can trigger wipe. Replace with a verify-without-counters path using `checkNormalPIN`, same as the activate flow's phase 1. Requires either a new `PINEntry` mode or calling `checkNormalPIN` directly in the sheet.
- [x] **[design]** "Enable PIN" toggle was initially disabled in `.normal` and `.duress` states. Revisited by the sticky-depth design and the Settings UI re-evaluation (both below). Final state: toggle remains disabled in `.duress` — this is load-bearing, not cosmetic (see Settings UI entry for rationale). `disablePINFromCurrentDepth` is the coercion-safe gate mechanism that doesn't go through the toggle.
- [x] **[security]** `activateSecureMode` must validate that the proposed duress PIN does not open any existing normal verifier. Currently no collision check — if duress PIN == normal PIN, `verify()` always matches normal first and duress is never triggerable. Validate with `PINManager.checkVerifier` (not `verify()`) before building the duress verifier; reject with a user-facing error if any existing verifier opens.
- [x] **[design — pre-ship]** `Enable PIN` toggle in `.duress`: the goal was to make the gate lowerable under coercion without exposing the master PIN. Enabling the toggle trivially is not safe: the Settings sheet calls `security.verify()` internally, so entering the normal PIN from `.duress` would silently transition to `.normal` at depth 0, breaking duress. The final resolution (see Settings UI entry below): toggle stays disabled in `.duress`; `disablePINFromCurrentDepth` is the coercion-safe gate mechanism. The residual tell (toggle appearance differs from `.pinOnly`) is accepted — the alternative is worse.

  **Chosen design — sticky depth with `appLockEnabled`:**

  The insight is to decouple the PIN gate from depth routing. "Disable PIN" does not mean "forget all verifiers" — it means "lower the gate while remembering where we are." Verifiers remain intact.

  **`AppLayerConfig` addition:**
  - `persistedDepth: Data?` — encrypted `RoutingDepth` (`.normal` / `.duress`). Always non-nil after first config write.
  - `pinEnabled: Data?` — encrypted `Bool`. `true` = gate active (PIN required on foreground); `false` = gate suppressed under coercion. Always non-nil after first config write. Decoding falls back to `true` (require PIN) on any failure.

  **`Manager.Security` in-memory property:**
  - `appLockEnabled: Bool` — restored from `config.readPinEnabled()` in `init`. `false` only when gate was deliberately lowered.

  **Disable PIN from current depth (`disablePINFromCurrentDepth(confirmingPIN:)`):**
  1. Checks entered PIN against the current layer's verifier via `checkCurrentLayerEntryPIN` (private) — no `verify()`, no counter mutation, no state transition.
  2. On pass: calls `writeRoutingDepth(currentDepth)` + `writePinEnabled(false)`, saves, sets `appLockEnabled = false`. Verifiers are left untouched.
  3. App opens directly to depth-N content. Coercer sees: toggle OFF, no PIN required, decoy content.

  **Re-enable PIN (enter + confirm — same UX as always):**
  `PINEntry` in `.setup` mode collects two matching entries and delivers the confirmed PIN to Settings. Settings calls `reEnablePIN(_:)` which silently checks against all existing verifiers: normal PIN match → depth 0, `.normal`; duress PIN match → depth 1, `.duress`. No new verifier is written; no observable UX difference.

  **Why both fields are always non-nil:** a field that is nil in normal operation and non-nil only when PIN has been force-disabled is itself a forensic tell. Always writing `writeRoutingDepth(.normal)` + `writePinEnabled(true)` at first config creation means every Occulta install shows the same field structure regardless of state.

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
- [x] `onDuress` in `OccultaApp` wired: set `isLocked = false` (decoy view is the real app filtered — no special navigation)
- [x] **[security — pre-ship]** `syncShareIndex()` in `OccultaApp` is called unconditionally on every `.active` transition. In duress mode the share extension's contact index contains hidden contact identifiers and public keys — a coercer who opens the iOS share sheet from any other app sees hidden contacts listed as Occulta recipients. Fix: pass `security.safeContactIDs()` into `syncShareIndex()` when `security.isRestricted`; the share extension only sees safe contacts. Note: inbound `.occ` files require explicit user action to open (user taps a file in an out-of-band channel) — no passive inbound leak exists there, and suppressing at `buildOwnedBasket` would itself be a tell (user opens file, nothing happens).
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

- [x] Layer store infrastructure (`SecureMode+Blob.swift`, `SecureMode+BlobStore.swift`): `LayerPayload` / `LayerContact` payload types; `seal`/`unseal` (→ `push`/`pop` pending upgrade); HKDF key derivation; bucket padding; no-op `maintain()` called from `OccultaApp.init()`, 24 h rewrite schedule, `ModelContext.didSave` rewrite debounced 30 s (gated on `!isSecureModeActive`); App Group storage at `group.com.occulta.shared/blobs/` with `.completeFileProtection` and `isExcludedFromBackup = true`. Rename to `Manager.Security.LayerStore` / `LayerStoreBackend` / `AppGroupLayerStoreBackend` pending.
- [ ] **Layer store wire format upgrade** — `push`/`pop` replacing `seal`/`unseal`, 32-slot fixed-size file, full slot regeneration on every write, sequence number validation, `payloadTooLarge` guard. Full design in **LayerStore.md**.
- [x] **Activation sequence — implemented.** Full key rotation, blob seal, contact re-encryption, and state transition are in `Manager+Security.activateSecureMode`. `modelContext.autosaveEnabled = false` + `defer` guards against accidental mid-sequence autosaves. Current POI is `commitStagedLocalDBKey()` (Keychain rename); `modelContext.save()` follows milliseconds later to write the duress verifier and state transition. A kill in that window requires a manual re-activation — no data loss. Documented in Known Limitations.

  **Deferred upgrade — `activeDBKeyTagEncrypted` refactor:** make `modelContext.save()` the POI by storing the new SE key's UUID tag in `AppLayerConfig` before the save, then completing the Keychain rename as post-save cleanup. `Manager.Security.init` detects an uncleared tag on launch and finishes the rename automatically — no manual retry needed. Benefit: automatic crash recovery in a sub-millisecond window. Not a ship blocker; deferred. Full target sequence preserved below for when this is implemented:

  1. State guard + PIN verification (normal PIN check, duress PIN collision check) — abort immediately on failure, no side effects.
  2. ~~Evaluate `LAContext` for biometrics~~ — **removed** (Bug 8). Vault PEKs are not in the blob; no biometric gate needed.
  3. Create new SE key at a fresh UUID tag + new 32-byte random in Keychain. Derive `newDBKey`. **Old canonical key still valid. If the app crashes here, the new key is an orphaned Keychain entry — detect and delete on next launch.**
  4. `modelContext.autosaveEnabled = false`; `defer { modelContext.autosaveEnabled = true }`. All subsequent DB mutations accumulate in memory until the explicit save in step 11.
  5. Decrypt all contacts using old canonical DB key. Partition into sensitive and safe. Build `ContactBlobRecord` for each sensitive contact (includes `signedAttributes` and `visibleThroughDepth` — Bug 23 fix).
  6. Migrate `visibleThroughDepth` in memory: `encrypt(Int.max)` for all safe contacts with nil field; `encrypt(0)` for all vault entries with nil field. Batch mutation unifies `ZMODIFICATIONDATE` — no activation timestamp fingerprint.
  7. ~~Unwrap vault PEKs~~ — **removed** (Bug 8).
  8. Seal blob: `Manager.Blob.push(BlobPayload(contacts: sensitiveRecords), blobKey:)`. Replaces the no-op blob.
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

1. **Skip sensitive contacts in activation Step 8's re-encryption loop.** Under Design A, all contacts (including sensitive) are re-encrypted to K_staged. Under Design B, sensitive contacts must be left with their key records under the old canonical key so they become genuinely unreadable after the key is deleted. Only text fields for sensitive contacts may be re-encrypted (so the shell is syntactically valid but cryptographically inaccessible).

2. [x] **Fix `convertToMutableCopy` to carry `quantumKeyMaterialEncrypted` through to the draft.** `Contact+Manager.swift` now decrypts and JSON-decodes `record.quantumKeyMaterialEncrypted` and passes it as `quantumKeyMaterial` when constructing `Contact.Draft.Key`. This makes the blob complete under both designs — Design A ignores it (key records are never rebuilt from the blob); Design B depends on it.

3. **Restore the `hasUnreadableKeys` rebuild path in deactivation Step 5b.** Under Design B, sensitive contacts' key records are left under the deleted activation key; `reEncryptKeyRecords` cannot decrypt them; the rebuild path is the correct recovery. The rebuild code that was removed from `deactivateSecureMode` belongs here. It must now also re-encrypt the `quantumKeyMaterialEncrypted` field from the blob draft's `key.quantumKeyMaterial` (point 2 above must be fixed first, or the rebuilt records will have nil quantum material).

- [x] **[bug]** Fix `isVisible(_:atDepth:)` fallback: `visibleThroughDepth` non-nil + decrypt failure → `return false`. Defense-in-depth — should not trigger in normal operation under Design A since all contacts are re-encrypted at activation and remain readable.

- [x] **Deactivation sequence — implemented.** Full key rotation, blob unseal, contact restoration, and state transition are in `Manager+Security.deactivateSecureMode`. `modelContext.autosaveEnabled = false` + `defer` added. Same crash window and deferred upgrade as activation above. Target sequence for `activeDBKeyTagEncrypted` refactor:

  1. State guard + verify normal PIN. Derive blob key from `deriveSecureModeKey()`.
  2. `pop(blobKey:)` → `BlobPayload`. Abort if blob is missing or decryption fails.
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
  13. `rewriteNoOpBlob()` — fresh no-op written.
  14. Transition state → `.pinOnly`.

- ~~`SecureModeOperation` SwiftData record~~ — **superseded.** The original design required a recovery record because Keychain key-promotion and DB writes were interleaved, creating a crash window between steps 10–11 that neither key could recover. The autosave approach above eliminates this: `modelContext.autosaveEnabled = false` accumulates all mutations in memory; a single `modelContext.save()` atomically commits contacts + `AppLayerConfig` (new key tag + verifier changes) as the sole point of no return. A crash before that save leaves the DB unchanged and the old key still authoritative. No stage tracking, no resume/rollback logic, no new data model required.

---

## Step 5 — Wipe + Panic Trigger

- [x] `PINEntry` shown on every `scenePhase == .active` when `security.requiresPIN`
- [x] `onDuress` / `onWipe` stubs in place (empty — dry-test deferred)
- [ ] `onWipe` wired to `Manager.App.eraseAllData()` — **after dry-testing the full flow**
- [ ] **[security]** `eraseAllData()` must also delete the blob file from the App Group container. Currently it covers prekeys, contacts, vault, and SE keys but has no knowledge of the blob. When Step 4 lands, `Manager.App.eraseAllData()` must receive a reference to the blob file path and delete it as part of the wipe sequence — before SE key deletion so the deletion itself cannot be blocked by an encrypted path lookup.
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

  **`onWipe` (wipe triggered):**
  Clear `pendingFileData` silently.

  **Already-unlocked paths (no queuing):**
  - Depth 0: `processInboundFile` runs immediately via `onOpenURL` — no change to observable behaviour.
  - Depth 1 (duress): same, check point A inside `processInboundFile` suppresses if sender not safe. Note: shard operations fire before check point A in this path — out of scope.

  **What does not change:** `openedFileContents` → `.sheet` pipeline, check point A logic, all error messages, `.occbak` vault restore path.
- [ ] Panic trigger accessible from decoy view. **Do not use back tap or shake.** Back tap requires Accessibility settings to be enabled (a tell on a forensic image), and shake fires accidentally. Preferred mechanism: entering the duress PIN three consecutive times without an intervening normal PIN triggers wipe while displaying identical "incorrect PIN" feedback to the coercer. The user memorises "duress PIN × 3 = wipe" — the gesture is indistinguishable from three failed attempts. Implement as: if `consecutiveDuressCount >= 3` return `.wipe` instead of `.duress`. Note: this changes `consecutiveDuressCount` from a "too many duress entries" guard to the panic trigger itself — set the threshold clearly and document it during activation setup.
- [ ] **[security]** Replace in-memory `wrongPINCount` with a Keychain-encrypted counter that survives app kills. A coercer who kills and relaunches currently resets the counter, enabling unlimited brute-force attempts. With a persistent counter, each `verify()` call decrements it before the check; a successful verification increments it back; reaching zero triggers wipe. The counter is stored as an AES-GCM–encrypted integer in the Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`), domain-separated from all other keys.

  **Time-based refill:** the counter refills to its starting value (e.g. 10) after a configurable period of continuous device lock (e.g. 24 h). This prevents permanent lockout from accidental wrong entries while keeping the brute-force window small. The refill timestamp is stored alongside the counter in the same Keychain item.

  **Design constraint:** the counter must be decremented *before* the verification attempt, not after failure. Decrement-after-failure allows an attacker to kill the app on failure before the decrement is written. Decrement-before + increment-on-success means a crash between decrement and verification counts as one consumed attempt — acceptable.

  **`consecutiveDuressCount`** stays in-memory. It drives the panic trigger, which the user invokes deliberately; it is not a brute-force defence and does not benefit from persistence.
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

- **`consecutiveDuressCount` is cyclable with both PINs.** A coercer who has extracted both the normal and duress PINs (through more extreme coercion) can cycle duress → normal → duress indefinitely without reaching the wipe threshold. `consecutiveDuressCount` resets to 0 on any normal PIN match. This is intentional — the threshold must not trigger on a user who accidentally enters their duress PIN and then corrects with the normal PIN — but it means the wipe condition is only effective against a coercer who has the duress PIN and not the normal PIN. Accepted; documented.
- **Row count mismatch.** More rows exist than the app displays. Soft-deleted and locked rows each have plausible innocent explanations. Soft-deleted rows are capped at 50 per entity type (evicted FIFO) to prevent unbounded database growth. Soft-deleted rows must never appear in any UI, Share Index, or query result.
- **SE key rotation is observable. No mitigation.** A forensic examiner checking the Keychain will see a new SE key created and an old one deleted. The timestamp is correlatable with activation. The deletion IS the security mechanism — there is no way to hide it.
- **The blob file exists. Partially mitigated — backport pending.** The blob will be created at Step 1 migration time (see Step 1 security item), UUID-named, and continuously maintained via Step 4's background schedule. Until the backport ships, the blob file first appears with the Step 4 update, which correlates its presence with Secure Mode usage on all pre-Step-4 installs. After the backport, every Occulta install will have had a blob file for months before Step 4, decoupling the timestamps entirely.
- **App deletion while Secure Mode is active is unrecoverable. No mitigation.** The App Group container is deleted with the app. This is an OS constraint. Users must be warned before activation; no code fix is possible.
- **Counter resets on app kill. Mitigated by panic trigger and persistent counter (Step 5).** `wrongPINCount` and `consecutiveDuressCount` are in-memory only. A coercer who kills and relaunches resets both counters, enabling unlimited PIN attempts. The SE hardware rate-limits verification operations, making brute-force expensive regardless of counter state. The panic trigger (duress PIN × 3) provides a user-controlled wipe independent of the wrong-PIN counter. The persistent Keychain-encrypted attempt counter (Step 5) closes the brute-force gap.
- **Crash logs may capture sensitive data.** iOS crash logs contain stack traces and register snapshots. A crash during blob serialization, contact re-encryption, or PIN verification could capture plaintext field data or PIN string fragments. Crash logs survive device wipe and are included in iCloud backups. If any external crash reporting (Crashlytics, Sentry, etc.) is ever added, it must sanitize all contact field data before transmission. Currently no crash reporting is used — document this constraint explicitly so it is not accidentally introduced.
- **SwiftData schema name is a forensic artifact. Mitigated.** Renaming `SecureModeConfig` to an opaque class name (Step 1) changes the table name to something non-descriptive. The schema fingerprint survives row deletion (store file is not deleted by `eraseAllData()`), but the table name no longer names the feature.
- **SwiftData WAL captures re-encryption transitions. Mitigated.** Activation sequence step 9 runs `PRAGMA wal_checkpoint(TRUNCATE)` before the staged key is promoted to canonical, zeroing the WAL and eliminating the re-encryption timestamp record.
- **Mass `ZMODIFICATIONDATE` update at activation is a deniability tell. Mitigated.** Re-encrypting safe contacts' fields under the new DB key at activation produces a mass timestamp update. Mitigated by writing all N contact records in a single batch at activation (step 5) — safe contacts get full field re-encryption, sensitive contacts get a `visibleThroughDepth` stamp — so every row shares the same modification timestamp. No count inference is possible.
- **`visibleThroughDepth` nil is a forensic tell. Mitigated.** A NULL vs non-NULL column value in a raw SQLite dump reveals which contacts are classified — even without decryption. Mitigated by always writing an encrypted value: safe contacts get `encrypt(Int.max)`, sensitive contacts get `encrypt(0)`. Legacy nil fields are migrated to `encrypt(Int.max)` or `encrypt(0)` in the activation batch write. After activation, no `visibleThroughDepth` field is ever nil.
- **Crash window between Keychain key promotion and AppLayerConfig save. Low severity.** The current activation and deactivation sequences call `commitStagedLocalDBKey()` (a Keychain rename — point of no return) and then `modelContext.save()` (writes the duress verifier / state transition) a few milliseconds later. A crash or process kill in that window leaves the DB in a consistent state but with a mismatched config: activation crash → contacts readable under new canonical key, but no duress verifier in AppLayerConfig → app boots as `.pinOnly`, user must re-activate. Deactivation crash → contacts readable under new canonical key, duress verifier still present → app boots as Secure Mode still active, user must re-deactivate (blob is intact). No data loss in either case; just a retry. `modelContext.autosaveEnabled = false` (added) prevents unrelated autosaves during the sequence but does not close this specific window. The `activeDBKeyTagEncrypted` design documented in the activation/deactivation sequences above closes it fully by making the DB save the point of no return; that refactor is deferred.
- **HKDF with PIN in the `info` field is non-standard. No mitigation planned.** `HKDF(inputKeyMaterial: seKey, info: label ∥ pin)` works correctly. Migrating to a more standard construction (PIN as IKM) would invalidate all existing verifiers. The current scheme has no known exploit; the finding is documented for external audits.
- **PIN strings are not zeroed after use. Mitigated.** Replacing `[Int]` digit storage with a `Data`-backed buffer and zeroing with `memset` after routing (Step 2) removes PIN heap residue.
- **Secure Mode raises the bar against coercion and mid-tier adversaries. It is not state-actor proof.**

# Secure Mode — Implementation Plan

## Implementation Order

**Phase 1 (ship-ready): Single-layer flat duress.** Steps 1–5 implement a fully functional PIN lock → duress PIN → decoy view with blob backup/restore and panic wipe. The plausible deniability stack (arbitrary-depth nesting) is designed but not built in Phase 1. The single-layer path covers 80% of the value and is the foundation everything else rests on.

> **⚠ Architecture caveat — Steps 1–3 are UI-layer filtering only.**
> All contact and vault data is encrypted under the same SE-derived key at every depth. `isRestricted` hides rows from the UI; it does not prevent their decryption. A forensic tool with SE access decrypts every row regardless of depth. **Step 4 (blob + key rotation) is what makes Secure Mode a cryptographic guarantee.** Until Step 4 ships: (a) the activation UI must not claim cryptographic separation, (b) the Step 4 migration must be treated as P0, (c) all inbound data paths (`.occ`, identity challenges, share index) must be hardened now so the UI guarantee at least holds against a coercer operating through the app.

**Phase 2 (post-ship): Multi-layer stacking.** Builds on Phase 1 without modifying its core flows. Begins after Phase 1 is tested end-to-end under adversarial conditions.

---

## Core Architecture — `Manager.Security`

`Manager.Security` is the single umbrella for all app-security hardening. `@Observable`, owned by `OccultaApp`, injected via `.environment`.

**State machine:**

```
.noPIN   — no PIN configured; app opens directly
.pinOnly — PIN set, Secure Mode not activated; PINEntry on every scene activation
.active  — authenticated at currentDepth; shows data visible at that depth
           depth 0: real app (all contacts); depth N > 0: decoy for depth N
.duress  — pushed one level deeper from .active; next PIN entry goes to depth N+1
```

State is derived from `AppLayerConfig` on every `init()` — never stored as a plaintext flag. Phase 1:
- `sealedDuressVerifier != nil` → `.active` (Secure Mode configured; app will lock on foreground)
- `sealedNormalVerifier != nil` → `.pinOnly`
- no config → `.noPIN`

Phase 2: same logic using array presence (`sealedDuressVerifiers.isEmpty` etc.). `currentDepth` is always 0 on init — restored to the correct depth when the user enters their PIN via `verify()`.

**Verifier scheme (no PBKDF2):**

`AES-GCM(HKDF(seKey, info: label ∥ pin), sentinel)`

SE key prevents all off-device attacks. PBKDF2 was removed: it added ~1s of main-thread blocking with no real security return — on-device code execution defeats any KDF regardless, and the 6-digit PIN space (1M) is brute-forceable in minutes on GPU independent of iteration count.

**`AppLayerConfig` — current schema (all properties optional, relevant ones encrypted):**

```swift
@Model final class AppLayerConfig {
    var sealedNormalVerifier:     Data?   // nil → .noPIN
    var sealedDuressVerifier:     Data?   // nil → .pinOnly
    var wipeThresholdEncrypted:   Data?   // encrypted Int; default 3
    var persistedDepth:           Data?   // always non-nil after first config write (see below)
}
```

`persistedDepth` encodes both routing depth and gate state in one encrypted signed Int:
`N ≥ 0` = gate active at depth N (normal operation);  `-(N+1)` = gate inactive at depth N (coercion path).
Always written as `encrypt(0)` on first config creation so field presence never leaks state.
`readLockGate()` falls back to `(depth:0, gateActive:true)` on any decode failure — corrupted field always errs secure.

All properties optional to avoid SwiftData migration on schema evolution. `wipeThreshold` is encrypted because it reveals Secure Mode configuration to a forensic examiner.

Contact visibility is tracked per-contact on `Contact.Profile` via `visibleThroughDepth` (see Step 3). There is no central safe-contact list on `AppLayerConfig`.

**`Manager.Security` public interface:**

```swift
// State
var requiresPIN:    Bool    // state != .noPIN
var isRestricted:   Bool    // currentDepth > 0
var appLockEnabled: Bool    // whether the PIN overlay gate fires on scene activation

// Setup
func configurePIN(_ pin: String) throws                                              // .noPIN → .pinOnly
func activateSecureMode(confirmingEntryPIN: String, duressPIN: String) throws        // .pinOnly/.duress → .active (Phase 1: depth 0 only)
func deactivateSecureMode(confirmingEntryPIN: String) throws                         // .active → .pinOnly (depth 0) / .duress at depth N-1 (depth N > 0)
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
- `.active` / `.duress` — 3 wrong PINs → `.wipe`; N consecutive duress entries → `.wipe`

---

## Step 1 — PIN Infrastructure ✅

- [x] `Tags` enum `CaseIterable`, `secureModePin` case, `deleteAllKeys()`
- [x] `deriveSecureModeKey()` on `Manager.Key` and `KeyManagerProtocol`
- [x] `TestKeyManager` in-memory implementation
- [x] `SecureModeConfig` SwiftData model — all optional, `wipeThresholdEncrypted`, no salt, no boolean flags
- [x] `Manager.Security` — own `ModelContext`, `PINManager` internal, state machine `.noPIN/.pinOnly/.active/.duress`
- [x] `Manager.Security.configurePIN(_:)` — builds `sealedNormalVerifier`, inserts config, transitions `.noPIN → .pinOnly`
- [x] `Manager.Security.activateSecureMode(confirmingNormalPIN:duressPIN:)` — verifies normal PIN, builds `sealedDuressVerifier`; key rotation TODO deferred to Step 4
- [x] `Manager.Security.verify(_:)` — owns all state transitions; duress + wrong counters in memory
- [x] `Manager.Security.deactivatePIN(confirmingNormalPIN:)` — `.pinOnly → .noPIN`
- [x] `Manager.Security.deactivateSecureMode(confirmingNormalPIN:)` — `.active/.duress → .pinOnly`; blob unwind TODO deferred to Step 4
- [x] `OccultaApp` schema includes `SecureModeConfig`
- [x] `Manager.App` with `eraseAllData()`
- [x] Unit tests via `TestKeyManager` + in-memory `ModelContainer` (29 tests)
- [x] **[security]** Rename SE key tag from `"secure.mode.pin"` to an opaque string (UUID or similar). The current tag explicitly names the feature — Keychain enumeration by a forensic tool directly reveals Secure Mode infrastructure. The master identity key uses `"master.key.privacy.turtles.are.cute"` (opaque); the Secure Mode key should follow the same pattern.
- [x] **[security]** Rename `SecureModeConfig` to an opaque class name (e.g. `AppLayerConfig`). SwiftData derives the SQLite table name from the class name — `ZSECUREMODECONFIG` in a raw database dump directly names the feature. Renaming to something non-descriptive changes the table name to `ZAPPLAYERCONFIG` or similar. Class is only referenced internally; surgical rename with no public API impact. Requires a SwiftData migration (lightweight: rename only).
- [x] **[security]** Set `NSPersistentStoreFileProtectionKey: FileProtectionType.complete` on the SwiftData persistent store. The current default (`completeUntilFirstUserAuthentication`) leaves the SQLite file readable after first device unlock even when the screen is locked. SwiftData's `ModelConfiguration` doesn't expose this — requires setting file attributes on the store URL post-creation via `FileManager.setAttributes`. Note: all field values are additionally encrypted at the app level, so the exposure is schema + row count, not plaintext data.
- [x] **[security]** `FileManager.setAttributes` for `.completeFileProtection` is applied once at container creation. SwiftData can create new `-wal` or `-shm` files outside the app's init lifecycle (WAL merges, schema migrations, conflict resolution). The attribute must be reapplied after every `ModelContext.didSave` notification — subscribe in `OccultaApp` and call `setAttributes` on all three paths (`store`, `store-wal`, `store-shm`) each time. Implemented: `storeURL` stored as property; `reapplyFileProtection()` helper; `.onReceive(NSManagedObjectContextDidSaveNotification)` in `body`.
- [ ] **[security]** Set `PRAGMA secure_delete = ON` on the SQLite connection before any writes. Without this, deleted and updated rows leave plaintext content in SQLite free-list pages that survive WAL checkpoint. A hidden contact's name or vault label could persist in raw page data long after the row is soft-deleted or re-encrypted. This must be applied before the first write after Step 4's key rotation.
- [x] **[security]** `wipeThreshold()` fallback behavior must be explicitly defined and tested. If `wipeThresholdEncrypted` fails to decrypt (corrupt data, wrong key, migration issue), the method must return a hardcoded secure default (3) — not 0 (immediate wipe on first wrong attempt) and not a large number (no wipe ever). Unit tests added: `nilEncryptedData_returnsFallback`, `corruptEncryptedData_returnsFallback`, `validThreshold_roundTrips`.
- [ ] **[security]** Create the no-op blob payload at Step 1 migration time, not at Step 4 activation. A forensic timeline that shows the blob file appearing when the user updates to the Step 4 version directly correlates blob presence with Secure Mode usage on all pre-Step-4 installs. Backporting blob creation to the Step 1 migration (already shipped) decouples the timestamps: every Occulta install will have had a blob file for months before Step 4 ships.

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
- [x] "Activate" button confirmation PIN (Phase 1, depth 0): `checkNormalPIN`. Sheet calls `activateSecureMode(confirmingEntryPIN:duressPIN:)` on success.
- [ ] "Activate" button confirmation PIN (Phase 2, depth N > 0): `checkDuressPIN(N-1)` — the duress PIN that opened this layer. Requires `Manager.Security.checkCurrentLayerEntryPIN(_ pin: String) -> Bool`. Using `checkNormalPIN` at depth > 0 would expose the master PIN to an observer during setup.
- [x] **[design — pre-ship]** Biometric unlock is not possible. `LAContext` cannot be routed to different app states — Face ID success always returns the same result regardless of which depth is active, meaning biometrics would always open the real app and bypass the duress view entirely. The app is PIN-only. Grace period implemented: lock on `.inactive` for screenshot protection; suppress PIN prompt on `.active` if `lastUnlockDate` is within 5 min. Zero grace period in restricted mode. `lastUnlockDate: Date?` on `Manager.Security` (in-memory only). Overlay shows blank screen within grace period (screenshot protection without PIN friction), full `PINEntry` outside it.
- [x] "Deactivate" button — visible when `state == .active`. Sheet calls `deactivateSecureMode(confirmingNormalPIN:)` on success.
- [ ] **[design]** Activate / Deactivate button visibility — same cycle repeats at every depth:
  - Activate visible at: `.pinOnly` and `.duress` (can always go one layer deeper from where you are)
  - Deactivate visible at: `.active` only (never at `.duress` — coercer in duress mode never sees it)
  - After deactivating from "active at depth N", returns to `.duress` at depth N-1 (the beginning of the cycle at this level)
  - Confirmation PIN = the PIN that unlocked the current depth (normal PIN at depth 0, duress PIN at depth N > 0)
  - Phase 1 restriction: Activate shown at `.pinOnly` only — `.duress` in Phase 1 has no Activate because "active at depth N" state does not exist yet (single-layer).
  - Phase 2: Activate at `.pinOnly` + `.duress`. Deactivate at `.active` (any depth).
- [x] **[design]** Contact selection must be part of the activation flow, not a standalone Settings item visited later. Implemented as `SecureModeSetupFlow`: Education → PIN setup (confirmThenSet) → Contact classification → Summary/Activate (4 steps, step-dots indicator). `activateSecureMode` called only on the final confirm step.
- [x] **[design]** "Deactivate Secure Mode" sheet calls `verify()` internally (via `PINEntry` in `.verify` mode), then `onNormal` calls `deactivateSecureMode(confirmingNormalPIN:)` which calls `PINManager.checkVerifier` again — double-verification plus counter mutation. Wrong attempts in this sheet increment `wrongPINCount` and can trigger wipe. Replace with a verify-without-counters path using `checkNormalPIN`, same as the activate flow's phase 1. Requires either a new `PINEntry` mode or calling `checkNormalPIN` directly in the sheet.
- [x] **[design]** "Enable PIN" toggle was disabled in `.active` and `.duress` states (the `.disabled(true)` fix). This was subsequently superseded by the sticky-depth design above, which makes the toggle fully interactive in every state. The `.disabled` modifier has been removed.
- [x] **[security]** `activateSecureMode` must validate that the proposed duress PIN does not open any existing normal verifier. Currently no collision check — if duress PIN == normal PIN, `verify()` always matches normal first and duress is never triggerable. Validate with `PINManager.checkVerifier` (not `verify()`) before building the duress verifier; reject with a user-facing error if any existing verifier opens.
- [x] **[design — pre-ship]** `Enable PIN` toggle must be interactive at every depth, including duress. The current disabled state in `.duress` is a tell — a coercer who notices the toggle is greyed out knows the app is in a protected state distinct from `.pinOnly`. Enabling it trivially is not safe either: the Settings sheet currently calls `security.verify()` internally, so entering the normal PIN from `.duress` would silently transition state to `.active` at depth 0, breaking duress.

  **Chosen design — sticky depth with `appLockEnabled`:**

  The insight is to decouple the PIN gate from depth routing. "Disable PIN" does not mean "forget all verifiers" — it means "lower the gate while remembering where we are." Verifiers remain intact.

  **`AppLayerConfig` addition:**
  - `persistedDepth: Data?` — always non-nil after first config write. Encodes both depth and gate state in a single signed Int: `N ≥ 0` = gate active at depth N; `-(N+1)` = gate inactive at depth N. No separate `appLockEnabled` field on the model — both values come from one blob. Decoding falls back to `(0, true)` on any failure.

  **`Manager.Security` in-memory property:**
  - `appLockEnabled: Bool` — restored from `persistedDepth.readLockGate()` in `init`. `false` only when gate was deliberately lowered.

  **Disable PIN from current depth (`disablePINFromCurrentDepth(confirmingPIN:)`):**
  1. Checks entered PIN against the current layer's verifier via `checkCurrentLayerEntryPIN` (private) — no `verify()`, no counter mutation, no state transition.
  2. On pass: calls `writeLockGate(depth: currentDepth, gateActive: false)`, saves, sets `appLockEnabled = false`. Verifiers are left untouched.
  3. App opens directly to depth-N content. Coercer sees: toggle OFF, no PIN required, decoy content.

  **Re-enable PIN (enter + confirm — same UX as always):**
  `PINEntry` in `.setup` mode collects two matching entries and delivers the confirmed PIN to Settings. Settings calls `reEnablePIN(_:)` which silently checks against all existing verifiers: normal PIN match → depth 0, `.active`; duress PIN match → depth 1, `.duress`. No new verifier is written; no observable UX difference.

  **Why `persistedDepth` is always non-nil:** a field that is nil in normal operation and non-nil only when PIN has been force-disabled is itself a forensic tell. Always writing `writeLockGate(depth:0, gateActive:true)` at first config creation means every Occulta install shows the same field structure regardless of state.

- [x] **[design — pre-ship]** `Settings → Security` appearance in `.duress` is wrong. The duress experience must be indistinguishable from `.pinOnly` — the coercer must believe Secure Mode was never activated. Correct state table:

  | State | Enable PIN toggle | "Learn more" / Activate section | "Deactivate Protection" |
  |---|---|---|---|
  | `.noPIN` | enabled | shown (dimmed, blocked) | hidden |
  | `.pinOnly` | enabled | shown | hidden |
  | `.duress` | **disabled** | **shown** | **hidden** |
  | `.active` | disabled | hidden | shown |

  **Toggle disabled in `.duress`:** Load-bearing, not cosmetic. PIN cannot be removed while Secure Mode is active — this is correct in both `.active` and `.duress`. More critically: if the toggle were enabled, opening it would present a `PINEntry` sheet that calls `security.verify()` internally. Entering the normal PIN in `.duress` triggers the `.normal` route and transitions state to `.active`, breaking duress and silently exiting the decoy view. Even if we substituted `checkNormalPIN` to avoid the state transition: correct PIN + sheet closes + PIN still enabled + nothing changes = a suspicious silent failure that tells the coercer something is wrong. Toggle disabled is the only safe option.

  **"Learn more" section must be shown in `.duress`:** Hiding it (the current bug) is a direct tell — `.active` is the only state that hides it, so a coercer who knows the UI sees `.active` unambiguously. Showing it in `.duress` makes the screen identical to `.pinOnly`. In Phase 2, the button works: it opens `SecureModeSetupFlow`, which creates a new layer.

  **"Deactivate Protection" must be hidden in `.duress`:** Showing it (the current bug — `.duress` is included in the condition alongside `.active`) is the exact signature of `.active` state and directly reveals Secure Mode is on.

  **Fix in `Settings.swift`:**
  ```swift
  // "Learn more" — add .duress
  if state == .noPIN || state == .pinOnly || state == .duress { ... }

  // "Deactivate" — remove .duress
  if state == .active { ... }
  ```

### Contact classification

Contact visibility is tracked per-contact, not in a central list on `AppLayerConfig`. A single encrypted field on `Contact.Profile` encodes depth-aware visibility, scales to the Phase 2 stack without schema changes, and produces no central field whose size can be compared against total row count.

**`visibleThroughDepth: Data?`** on `Contact.Profile` — encrypted `Int?`:
- `nil` — visible at all depths (existing contacts classified as safe at activation)
- `0` — visible at true layer only (sensitive contact, hidden from all duress depths)
- `N` — visible at depths 0 through N; hidden at N+1 and deeper

Filter at depth N: show contacts where `decrypt(visibleThroughDepth) == nil || decrypt(visibleThroughDepth) >= N`.

**Write rule:** contacts created or exchanged at depth N > 0 receive `visibleThroughDepth = N`, not `nil`. This means they are visible at the true layer and at the depth where they were added, but invisible to any deeper layer created later. Contacts at depth 0 keep `nil` (safe) or receive `0` (sensitive) via the classification step.

Phase 1 writes `nil` (safe), `0` (sensitive), or `1` (created/exchanged at depth 1). Phase 2 uses the full integer range without schema migration.

**Forensic profile:** `AES-GCM(nil)`, `AES-GCM(0)`, `AES-GCM(1)` all produce identically-sized ciphertexts — no size-based count inference. No central list to compare against total row count. The primary residual tell is the mass `ZMODIFICATIONDATE` update on safe contacts at activation time (Step 4 re-encrypts their fields under the new SE key). Mitigated by also touching hidden contacts' records with a no-op write at activation, making all N records share the same modification timestamp — no count inference possible.

- [x] `isSafeContact(_:)`, `safeContactIDs()`, `updateSafeContacts(_:)` on `Manager.Security` updated to read `visibleThroughDepth` from contact records, not from `AppLayerConfig`
- [x] `visibleThroughDepth: Data?` added to `Contact.Profile` model (encrypted `Int?`, default nil)
- [x] User chooses contact type (safe / sensitive) during contact creation — VISIBILITY section in `ContactFormV2`; no Secure Mode framing; shown in both create and edit modes
- [x] At Secure Mode activation: review step shows existing contacts and lets the user confirm or change classifications before activating. This is step 3 of the 4-step activation sheet (`SecureModeSetupFlow`).
- [x] `safeContactIDsEncrypted` removed from `AppLayerConfig` and all call sites

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

**`visibleThroughDepth: Data?`** on `VaultEntry` — encrypted `Int?`, same encoding as `Contact.Profile`:
- `nil` — visible at all depths (legacy / pre-Secure-Mode entries; can be set explicitly for entries that should appear in all layers)
- `N` — visible at depths 0 through N; hidden at N+1 and deeper

**Write rule:** `addEntry(...)` receives `currentDepth` and sets `visibleThroughDepth = currentDepth`. At depth 0 the field is `nil` (visible everywhere) to preserve pre-activation vault access.

Filter at depth N: show entries where `visibleThroughDepth == nil || decrypt(visibleThroughDepth) >= N`. Identical to the contact filter.

- [x] `visibleThroughDepth: Data?` added to `VaultEntry` model (default `nil`, lightweight SwiftData migration)
- [x] `isEntryVisible(_ entry: VaultEntry) -> Bool` on `Manager.Security` — takes the already-fetched entry directly, applies `value >= currentDepth` rule; mirrors the contacts `isVisible` helper
- [x] `Vault+Tab` computes `visibleEntries` filtered through `security.isEntryVisible` when `isRestricted`; filters attention section (`affected`) by `visibleIDs` as well — no hidden-entry labels leak through the recovery health display
- [x] `Vault+Manager.addEntry(...)` accepts `currentDepth: Int = 0`; stamps `entry.visibleThroughDepth = encrypt(currentDepth)` when `> 0`; default preserves existing call sites
- [x] `Vault+Manager+Backup.swift` — audited; imported entries leave `visibleThroughDepth = nil` (visible everywhere). Correct: backups originate from the true layer.
- [ ] **Blob interaction (Step 4):** blob serialises PEKs for entries with `visibleThroughDepth < currentDepth` at activation (entries that belong to the layer being locked). Entries with `nil` or `value >= currentDepth` remain accessible and are not serialised.

---

## Step 4 — Blob (Activation / Deactivation)

- [ ] `SecureMode+Blob` — each stack payload serialises:
  - Per sensitive contact: persistent model ID + plaintext field data re-encrypted under blob key
  - Sensitive contact identity public keys
  - **Vault PEKs only** (not vault file data). Each vault entry whose `visibleThroughDepth < currentDepth` (i.e. belongs to the layer being locked) has its Per-Entry Key unwrapped and re-wrapped under the blob key. Vault files remain on disk encrypted with their PEKs — locked in-place without moving file data. Blob size is independent of vault storage size. Entries with `nil` or `visibleThroughDepth >= currentDepth` are not serialised — they remain accessible at the current depth.
  - Prekeys are not serialised — locked in-place alongside contact rows; fresh prekeys generated on restore.
- [ ] Blob is a stack of independently-encrypted payloads in a single file. Push appends; pop removes outermost. Partial-read reveals nothing about other layers.
- [ ] Blob encryption: `AES-GCM(HKDF(seKey, info: "blob-key"), content)`. SE binding prevents offline attacks. No PBKDF2 (same rationale as PIN verifier).
- [ ] Each payload padded to nearest power-of-2 bucket boundary before encryption. File size reveals only bucket tier, not contact/vault count.
- [ ] Blob file: no header, no magic bytes, no version field, no layer count. UUID filename with `.occbak` extension — indistinguishable from vault backup.
- [ ] **[security]** Create the blob with a no-op encrypted payload on first app launch — before Secure Mode is ever configured. Every Occulta install then has a blob file in the App Group container from day one; its presence is no longer Secure Mode-specific. A forensic examiner seeing the blob cannot distinguish "Secure Mode was used" from "this is a normal Occulta install."
- [ ] Continuous background blob maintenance triggered by `ModelContext.didSave`. Debounced 30s. Blob exists with natural timestamps before first activation.
- [ ] No-op blob rewrites on a 24h schedule — decouples Last Modified timestamp from meaningful events.
- [ ] **Activation sequence — key rotation, no row deletion:**
  1. Generate new SE key for this layer
  2. Read safe contact IDs while old SE key is live
  3. Serialise sensitive contacts (not soft-deleted, not in safe set) → blob payload
  4. Serialise vault PEKs → blob payload
  5. Re-encrypt safe contacts' fields under new DB key
  6. `PRAGMA wal_checkpoint(TRUNCATE)` — zero the WAL before the point of no return; eliminates re-encryption record
  7. Delete old SE key — sensitive rows locked in-place (point of no return)
  8. Build verifiers; update `AppLayerConfig`
- [ ] **Deactivation sequence:**
  1. Decrypt blob payload (using current SE key — the one generated during activation)
  2. For each (persistentModelID, data): fetch row by ID, UPDATE fields re-encrypted under new DB key
  3. Generate new vault SE key; restore vault PEKs via UPDATE
  4. Generate fresh prekeys for restored contacts
  5. Remove blob payload; update `AppLayerConfig` verifiers
  6. Delete the layer SE key
- [ ] `SecureModeOperation` SwiftData record — tracks activation/deactivation stage. Written before operation begins, deleted on clean completion. All fields encrypted; record's existence must not reveal the operation type. **On next launch, incomplete record → automatic resume or rollback:**
  - Resume: re-enter the operation from the last completed stage (idempotent stage design required)
  - Rollback: restore the previous verifier state, delete any partial blob payload, leave DB rows in their pre-operation encrypted state
  - Activation failure before old SE key deletion → safe to retry from scratch
  - Activation failure after old SE key deletion → must complete forward (no rollback possible; resume is the only path)
  - Runs in a background `Task`; user sees a progress indicator; app backgrounding suspends and resumes on next foreground
- [ ] Blob stored in App Group container (`group.com.occulta.shared`) with `.completeFileProtection`.
- [ ] **[security]** Set `isExcludedFromBackup = true` (`URLResourceValues`) on the blob file immediately after creation. Without this, the blob is included in iCloud backups by default. A forensic examiner with iCloud credentials or a court order can recover the blob from a backup taken before a wipe, reversing the wipe entirely. `.completeFileProtection` does not prevent iCloud backup.

---

## Step 5 — Wipe + Panic Trigger

- [x] `PINEntry` shown on every `scenePhase == .active` when `security.requiresPIN`
- [x] `onDuress` / `onWipe` stubs in place (empty — dry-test deferred)
- [ ] `onWipe` wired to `Manager.App.eraseAllData()` — **after dry-testing the full flow**
- [ ] **[security]** `eraseAllData()` must also delete the blob file from the App Group container. Currently it covers prekeys, contacts, vault, and SE keys but has no knowledge of the blob. When Step 4 lands, `Manager.App.eraseAllData()` must receive a reference to the blob file path and delete it as part of the wipe sequence — before SE key deletion so the deletion itself cannot be blocked by an encrypted path lookup.
- [ ] `onOpenURL` respects Secure Mode — inbound `.occ` queued until PIN entered; hidden contact fingerprint lookup returns "unknown sender"
- [ ] Panic trigger accessible from decoy view. **Do not use back tap or shake.** Back tap requires Accessibility settings to be enabled (a tell on a forensic image), and shake fires accidentally. Preferred mechanism: entering the duress PIN three consecutive times without an intervening normal PIN triggers wipe while displaying identical "incorrect PIN" feedback to the coercer. The user memorises "duress PIN × 3 = wipe" — the gesture is indistinguishable from three failed attempts. Implement as: if `consecutiveDuressCount >= 3` return `.wipe` instead of `.duress`. Note: this changes `consecutiveDuressCount` from a "too many duress entries" guard to the panic trigger itself — set the threshold clearly and document it during activation setup.
- [ ] **Decryption-failure contract** — enforced at `ContactManager`, the single data authority. All fetch and search methods return `nil` (not empty string, not placeholder) for rows that fail decryption. The contract is: `decryptOrNil() == nil` is treated identically to "row never existed" by every caller — no secondary queries, no error logs, no timing differences.
  - A new wrapper type (`SecureModeDataProvider`) is explicitly rejected: it would create a parallel access path and the contract would only be as strong as adoption is universal. Enforce it at the source.
  - **`SECURE_MODE_DECRYPT_CONTRACT.md`** — living checklist of every `decryptOrNil` call site, indexed by layer, process boundary (main app / Share Extension / notifications), and test coverage. Must be updated on every PR that touches contacts or vault. Signed off before Phase 1 ships.
- [ ] **Decryption side-channel audit** before shipping: activate Secure Mode in-memory, hide a contact, assert every query path (`ContactManager`, `ExchangeManager`, `IdentityChallenge`, Share Extension, notifications) returns same result as if the contact never existed. Includes timing: no path should take measurably longer on a decryption failure than on a genuine empty result.

---

## Phase 2 — Plausible Deniability Stack *(post-Phase-1)*

### Threat model

A coercer demands access at PIN-point. No matter how many PIN entries are coerced, the app behaves identically to an ordinary contacts app at every depth. The coercer cannot determine how many layers exist, whether they have reached the bottom, or whether any protected data has been withheld.

### Stack invariants

1. **Arbitrary depth.** No cap. A cap (e.g. VeraCrypt's 2-layer limit) is a smoking gun — a coercer who tries to activate another layer and finds it unavailable immediately knows hidden data exists. Every layer presents an identical "Activate Secure Mode" option.
2. **PIN entry on every foreground.** `PINEntry` is identical regardless of depth.
3. **`state == .duress` → Settings shows "Enable PIN" toggle + "Activate" only.** Never reveals whether a deeper layer is already configured. `state == .active` at depth N > 0 shows the same Activate/Deactivate cycle as depth 0 — indistinguishable from any other active state.
4. **`currentDepth` is in-memory only.** Resets to 0 on every app kill. No persistent depth counter — that would be a forensic artifact. `currentDepth` is sufficient because the PIN itself is the routing key: after a cold start, entering any layer's PIN routes directly to that depth via the full normal-verifier scan (see `verify()` ordering below). `currentDepth` in memory only controls which duress push-down verifier is offered — you can only go one level deeper from where you currently are.
5. **`.active` is relative to `currentDepth`.** At depth 0, `.active` surfaces the real app. At depth N > 0, `.active` surfaces the depth-N decoy — contacts with `visibleThroughDepth >= N`. Only the master PIN (depth 0) surfaces the real app. `.duress` means you were pushed one level deeper from your current `.active` state — it is a transition, not a permanent classification. The same Activate/Deactivate cycle repeats at every depth: `.duress` → Activate → `.active` at depth N+1 → Deactivate → back to `.duress` at depth N.

### PIN model — one PIN per layer boundary

Each boundary between depth N and N+1 is guarded by a single PIN:

```
sealedNormalVerifiers[0]   = master PIN          → .active at depth 0 (real app)
sealedDuressVerifiers[0]   = duress PIN #0       → .duress; push depth 0 → depth 1
sealedNormalVerifiers[1]   = same value as sealedDuressVerifiers[0]  ← routing alias → .active at depth 1 (decoy)
sealedDuressVerifiers[1]   = duress PIN #1       → .duress; push depth 1 → depth 2
sealedNormalVerifiers[2]   = same value as sealedDuressVerifiers[1]  ← routing alias → .active at depth 2 (decoy)
...
```

`sealedNormalVerifiers[N]` (N > 0) and `sealedDuressVerifiers[N-1]` hold the same PIN value. The duress PIN that pushes you to depth N is the same PIN that returns you to depth N from any deeper level. This gives **K+1 distinct PINs for K layers** — no separate "return PIN" to remember per layer.

### `AppLayerConfig` — Phase 2 schema extension

Parallel arrays in the existing single row (no new rows, no joins):

```swift
// Added for Phase 2 — Phase 1 fields unchanged
var sealedNormalVerifiers:    [Data]   // index = depth; [0] is master; [N] == sealedDuressVerifiers[N-1]
var sealedDuressVerifiers:    [Data]   // index = depth; entry at N drives push to N+1
```

The existing `sealedNormalVerifier` / `sealedDuressVerifier` fields become `sealedNormalVerifiers[0]` / `sealedDuressVerifiers[0]`. Migration: on first Phase 2 launch, wrap existing single values into index-0 of the arrays.

**[security]** Array length directly encodes layer depth to a forensic examiner. A SQLite dump shows `sealedNormalVerifiers` as an array of N elements — N = layer count. Both arrays must be padded to a fixed maximum length (e.g. 8) with random entries of identical byte size to real verifiers on every write. The padding entries must be indistinguishable from real verifiers (same length AES-GCM ciphertext, randomly generated). `verify()` simply ignores entries that fail to open. A forensic examiner then always sees exactly 8 blobs per array on every install, regardless of actual depth.

There is no `safeContactIDsPerLevel` array. Contact visibility across all depths is encoded in `Contact.Profile.visibleThroughDepth` (see Step 3). Filter at depth N: show contacts where `decrypt(visibleThroughDepth) == nil || decrypt(visibleThroughDepth) >= N`.

**Contact visibility invariants across layers:**

- A contact with `visibleThroughDepth = K` is visible at all depths 0..K and hidden at K+1 and deeper. Visibility is always a contiguous range from depth 0 — a contact cannot be hidden at depth 1 but visible at depth 2.
- When activating depth N+1, the user reviews contacts with `visibleThroughDepth >= N` (visible at current depth) and selects which should also be visible at N+1 (setting `visibleThroughDepth = N+1` or leaving at `nil`). Contacts not selected remain at their current value and become hidden at depth N+1.
- New contacts created at any depth default to `visibleThroughDepth = nil` (visible at all depths). They were exchanged with openly; hiding them retroactively requires an explicit user action.
- At activation, all N contact records receive a no-op write to unify `ZMODIFICATIONDATE` — prevents count inference from timestamp distribution.

### `verify()` ordering at any depth

Given `currentDepth = N`:

1. Try **all** `sealedNormalVerifiers[0..max]` — first match at K: `currentDepth = K`, state = `.active` (shows depth-K view — real app at K == 0, decoy at K > 0); restore blob payloads for depths K+1..N if K < N
2. Try `sealedDuressVerifiers[N]` → match: `currentDepth = N+1`, state = `.duress`
3. No match → `.wrong`; increment `wrongPINCount`

Step 1 scans all normal verifiers regardless of `currentDepth`. This is what makes cold-start routing work — entering duress PIN #1 after a kill matches `sealedNormalVerifiers[2]` and routes directly to depth 2, without having to walk through depth 1 first. Only the push-down (step 2) is depth-specific, preventing a coercer from jumping past an unvisited depth.

### Activation at depth N — confirmation PIN

When at depth N and tapping "Activate Secure Mode" to add depth N+1:

- **N == 0**: confirm via `checkNormalPIN` (master PIN). Already implemented for Phase 1.
- **N > 0**: confirm via `checkDuressPIN(N-1)` — check `sealedDuressVerifiers[N-1]`, the PIN that brought the user to depth N. Requires a new `Manager.Security.checkCurrentLayerEntryPIN(_ pin: String) -> Bool` method for Phase 2. Using `checkNormalPIN` here would expose the master PIN to an observer during depth-2+ setup.

The activation flow at any depth: (1) confirm entry PIN for this depth, (2) enter + confirm new duress PIN, (3) select safe contacts for next level, (4) call `activateSecureModeAtCurrentDepth(confirmingEntryPIN:newDuressPIN:safeContacts:)`.

### PIN uniqueness constraint

At every setup step, validate the candidate PIN against all existing verifiers at all depths. Reject if any verifier opens with the candidate PIN.

**[security]** This validation must use a pure `checkPIN(_:against:)` method — not `verify()`. `verify()` increments `wrongPINCount` on each non-match. Checking N verifiers for uniqueness would increment the counter N times, potentially triggering a spurious wipe. `PINManager.checkVerifier()` already exists as a pure function; the Phase 2 uniqueness check must call it directly without going through `Manager.Security.verify()`.

### Cascade delete

Disabling Secure Mode at depth N (i.e. calling `deactivateSecureMode` at depth N) must truncate `sealedNormalVerifiers` and `sealedDuressVerifiers` to length N, and restore all blob payloads at indices N+1…end. Orphaned deeper configs are unreachable and must not be left in the store. Contact visibility (`visibleThroughDepth` per contact) is not cascaded — the values remain valid and the user retains whatever classifications they set. A contact visible only through depth N becomes unreachable after the stack is truncated to N; its `visibleThroughDepth` value is harmless to leave in place.

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

- **Steps 1–3 are UI-layer filtering only. Not cryptographic separation.** All data is encrypted under the same SE-derived key regardless of depth. `isRestricted` controls what is displayed; it does not prevent decryption. A forensic tool or exploited app bug can access all rows. Step 4 (blob + key rotation) provides the cryptographic guarantee. Until Step 4 ships, the activation UI must not imply cryptographic separation.
- **`consecutiveDuressCount` is cyclable with both PINs.** A coercer who has extracted both the normal and duress PINs (through more extreme coercion) can cycle duress → normal → duress indefinitely without reaching the wipe threshold. `consecutiveDuressCount` resets to 0 on any normal PIN match. This is intentional — the threshold must not trigger on a user who accidentally enters their duress PIN and then corrects with the normal PIN — but it means the wipe condition is only effective against a coercer who has the duress PIN and not the normal PIN. Accepted; documented.
- **Row count mismatch.** More rows exist than the app displays. Soft-deleted and locked rows each have plausible innocent explanations. Soft-deleted rows are capped at 50 per entity type (evicted FIFO) to prevent unbounded database growth. Soft-deleted rows must never appear in any UI, Share Index, or query result.
- **SE key rotation is observable. No mitigation.** A forensic examiner checking the Keychain will see a new SE key created and an old one deleted. The timestamp is correlatable with activation. The deletion IS the security mechanism — there is no way to hide it.
- **The blob file exists. Partially mitigated — backport pending.** The blob will be created at Step 1 migration time (see Step 1 security item), UUID-named, and continuously maintained via Step 4's background schedule. Until the backport ships, the blob file first appears with the Step 4 update, which correlates its presence with Secure Mode usage on all pre-Step-4 installs. After the backport, every Occulta install will have had a blob file for months before Step 4, decoupling the timestamps entirely.
- **App deletion while Secure Mode is active is unrecoverable. No mitigation.** The App Group container is deleted with the app. This is an OS constraint. Users must be warned before activation; no code fix is possible.
- **Counter resets on app kill. Partially mitigated by panic trigger.** `wrongPINCount` and `consecutiveDuressCount` are in-memory only. A coercer who kills and relaunches resets both counters, enabling unlimited PIN attempts. The SE hardware rate-limits verification operations, making brute-force expensive regardless of counter state. The panic trigger (Step 5, duress PIN × 3 design) provides a user-controlled wipe that does not depend on the wrong-PIN counter. A persistent encrypted attempt counter (stored in Keychain, decremented before each verification, with time-based reset) would close this gap entirely but adds complexity; deferred to Phase 2 threat review.
- **Crash logs may capture sensitive data.** iOS crash logs contain stack traces and register snapshots. A crash during blob serialization, contact re-encryption, or PIN verification could capture plaintext field data or PIN string fragments. Crash logs survive device wipe and are included in iCloud backups. If any external crash reporting (Crashlytics, Sentry, etc.) is ever added, it must sanitize all contact field data before transmission. Currently no crash reporting is used — document this constraint explicitly so it is not accidentally introduced.
- **SwiftData schema name is a forensic artifact. Mitigated.** Renaming `SecureModeConfig` to an opaque class name (Step 1) changes the table name to something non-descriptive. The schema fingerprint survives row deletion (store file is not deleted by `eraseAllData()`), but the table name no longer names the feature.
- **SwiftData WAL captures re-encryption transitions. Mitigated.** Activation sequence step 6 runs `PRAGMA wal_checkpoint(TRUNCATE)` before SE key deletion, zeroing the WAL and eliminating the re-encryption timestamp record.
- **Mass `ZMODIFICATIONDATE` update at activation is a deniability tell. Mitigated.** Re-encrypting safe contacts' fields under the new SE key at activation produces a mass timestamp update on a subset of contact rows — count inference possible by comparing updated rows against total row count. Mitigated by issuing a no-op write to all N contact records at activation, unifying `ZMODIFICATIONDATE` across the full table. No count inference is possible when every row shares the same modification timestamp.
- **HKDF with PIN in the `info` field is non-standard. No mitigation planned.** `HKDF(inputKeyMaterial: seKey, info: label ∥ pin)` works correctly. Migrating to a more standard construction (PIN as IKM) would invalidate all existing verifiers. The current scheme has no known exploit; the finding is documented for external audits.
- **PIN strings are not zeroed after use. Mitigated.** Replacing `[Int]` digit storage with a `Data`-backed buffer and zeroing with `memset` after routing (Step 2) removes PIN heap residue.
- **Secure Mode raises the bar against coercion and mid-tier adversaries. It is not state-actor proof.**

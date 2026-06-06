# Secure Mode — Scenario Catalogue

Documents every meaningful user flow and state permutation. Use this as the reference for test planning, code review, and evaluating new bug reports against expected behaviour.

---

## Notation

**State shorthand:**

| Symbol | Meaning |
|---|---|
| `SM` | Secure Mode active (`sealedDuressVerifier != nil`) |
| `!SM` | Secure Mode not active |
| `depth:N` | `currentDepth == N` (0 = real layer; N > 0 = duress/coercer layer) |
| `gate:up` | `appLockEnabled = true` (PIN required on foreground) |
| `gate:down` | `appLockEnabled = false` (gate deliberately lowered) |
| `locked` | PIN entry screen is showing (`needsPINEntry = true`) |
| `grace` | Within 5-minute grace period (`lastUnlockDate` recent) |

**Actors:**
- **User** — the real owner at depth 0
- **Adversary** — someone with the duress PIN; reaches depth N via duress route
- **Coercer** — someone who received the phone gate-down and re-enabled with a foreign PIN; operates at depth N+1

---

## 1. App Launch

### 1.1 Cold launch — no PIN configured
**State:** `.noPIN`
**Result:** App opens directly. No PIN prompt. No overlay. Settings shows "Enable PIN" toggle OFF.

### 1.2 Cold launch — PIN only, no Secure Mode
**State:** `.pinOnly`, gate:up
**Result:** `fullScreenCover` PIN gate shows immediately. `isContentHidden = true` prevents content flash during cover animation. Contacts and vault are fully behind the gate.

### 1.3 Cold launch — Secure Mode active, gate up
**State:** `SM`, `depth:0` (reset on launch), gate:up
**Result:** PIN gate shows. `state` restored from `persistedDepth`. `appLockEnabled` restored from `pinEnabled`. `currentDepth` always resets to 0 — routing depth is determined by PIN entry, not a persisted counter.

### 1.4 Cold launch — Secure Mode active, gate previously lowered
**State:** `SM`, gate:down (persisted)
**Result:** App opens directly to depth-filtered content. `appLockEnabled = false` restored from `pinEnabled`. Contacts visible at `currentDepth = 0` (full list, since depth restarts at 0 on launch). Gate does not fire.
**Note:** The adversary who had gate-lowered the device at depth N and killed the app will see depth 0 content on relaunch — not depth N — until they re-enter their PIN.

### 1.5 Cold launch — Secure Mode active, previously in duress (`persistedDepth = .duress`)
**State:** `SM`, `state = .duress` (restored), gate:up
**Result:** PIN gate shows. `state = .duress` means the app was last in a push-down in-progress context. `currentDepth = 0` always. Next PIN entry routes normally via step-1 scan.

### 1.6 Cold launch — `maintainLayerStore` race
**State:** Any
**Result:** `maintainLayerStore()` runs on `DispatchQueue.global(.background)`. No main-thread block. If Secure Mode is active, no-op maintenance is skipped (`isSecureModeActive` checked on main thread before dispatch). Layer store file always exists by the time any user action is possible.

---

## 2. Foreground / Background Transitions

### 2.1 Background then foreground — within grace period
**State:** `SM` or `.pinOnly`, gate:up, `depth:N`, `grace`
**Result:** `handleBackground()` sets `isContentHidden = true`, `needsPINEntry = false` (grace period still valid). `handleActive()` clears `isContentHidden`. No PIN prompt. Identical behaviour at all depths (Bug 41 fix — grace is not suppressed in duress).

### 2.2 Background then foreground — grace period expired
**State:** `SM` or `.pinOnly`, gate:up, `depth:N`, past grace
**Result:** `handleBackground()` sets `needsPINEntry = true`. `handleActive()` finds `needsPINEntry = true`, shows PIN gate. `isContentHidden` remains until PIN entered. Identical at all depths.

### 2.3 Inactive (screenshot / share sheet)
**State:** `SM` or `.pinOnly`, gate:up, vault unlocked
**Result:** `handleInactive()` sets `isContentHidden = true` (opaque overlay). No `fullScreenCover` — avoids UIKit conflict with `UIActivityViewController`. App-switcher thumbnail is blank.

### 2.4 Return from inactive — no background
**State:** Any
**Result:** `handleActive()` runs. If within grace: `isContentHidden` clears, no PIN. If past grace: gate shows. If gate was already showing: no change.

### 2.5 Background → foreground — gate previously lowered
**State:** `SM`, gate:down
**Result:** `handleBackground()` guard `requiresPIN && appLockEnabled` — `appLockEnabled = false` → returns immediately. No gate, no content hide. `handleActive()` similarly inert. The device opens to the same depth-filtered content. Coercer/adversary can background and foreground freely.

---

## 3. PIN Entry

### 3.1 Correct normal PIN (depth 0)
**State:** `SM`, locked
**Entry:** Master PIN
**Result:** `verify()` step 1 hits `sealedNormalVerifiers[0]` → `.normal(depth: 0)`. `applyVerifyState` sets `state = .normal`, `currentDepth = 0`. After 500ms gate-duration, `onNormal` fires: `isLocked = false`, pending file processed, share index rebuilt with all contacts.

### 3.2 Correct duress PIN — via routing alias
**State:** `SM`, locked, multi-layer configured
**Entry:** Duress PIN for depth N (also stored as `sealedNormalVerifiers[N]`)
**Result:** `verify()` step 1 scans all normal verifiers — finds match at index N → `.normal(depth: N)`. `currentDepth = N`, `state = .normal`. `isRestricted = true`. Gate lowers to duress view — contacts filtered to `visibleThroughDepth >= N`, vault filtered.
**Note:** Cold-start routing: entering any duress PIN jumps directly to its depth without walking through lower depths.

### 3.3 Correct duress PIN — legacy push-down (from current depth)
**State:** `SM`, `depth:N`, locked
**Entry:** Duress PIN for depth N (stored as `sealedDuressVerifiers[N]`)
**Result:** `verify()` step 1: no normal verifier match (routing alias written at depth N+1, not N). Step 2: `sealedDuressVerifiers[N]` matches → `.duress`. `currentDepth = N+1`, `state = .duress`. Gate lowers to depth N+1 view.
**Note:** This path only occurs when entering the duress PIN from WITHIN depth N (not from cold start). Cold start always routes via step 1.

### 3.4 Wrong PIN
**State:** `SM` or `.pinOnly`, locked
**Entry:** Unrecognised PIN
**Result:** `verify()` → `.wrong`. `wrongPINCount++`. Shake animation. No wipe in any mode — counter accumulates but never triggers data destruction. Counter resets on app kill (known limitation); persistent Keychain counter (Step 5) adds session-independent rate-limiting.

### 3.5 PIN entry with pending inbound file — normal unlock
**State:** Locked, `pendingFileData` set (file arrived while locked)
**Result:** Normal PIN entered → `onNormal` fires → captures `pendingFileData`, clears it, dispatches `processInboundFile`. File is processed after gate fully dismisses (`onDismiss` callback).

### 3.6 PIN entry with pending inbound file — duress unlock
**State:** Locked, `pendingFileData` set
**Result:** Duress PIN entered → `onDuress` fires → `pendingFileData` cleared without processing. "Not addressed to you" message shown. Raw bytes permanently discarded.

---

## 4. Settings — PIN Toggle

### 4.1 Toggle ON: from `.noPIN`
**Pre-state:** `.noPIN`
**Sheet:** `PINEntry(.setup)` — enter + confirm
**Result:** `configurePIN(pin)` → `sealedNormalVerifier` + `sealedNormalVerifiers[0]` written. State transitions to `.pinOnly`. `writeRoutingDepth(.normal)` + `writePinEnabled(true)` written for forensic consistency.

### 4.2 Toggle OFF: from `.pinOnly`
**Pre-state:** `.pinOnly`, gate:up
**Sheet:** `PINEntry(.verifyCurrentLayer)` — single entry
**Result:** PIN verified against `sealedNormalVerifiers[0]`. On match: `deactivatePIN` clears verifiers, state → `.noPIN`.

### 4.3 Toggle OFF: from depth 0 (SM active, gate up)
**Pre-state:** `SM`, `depth:0`, gate:up
**UI:** Toggle is disabled (`.disabled(isSecureModeActive && currentDepth == 0 && appLockEnabled)`).
**Result:** No-op. User must deactivate Secure Mode before removing PIN.

### 4.4 Toggle OFF: from depth N adversary view (SM active, gate up)
**Pre-state:** `SM`, `depth:N > 0`, gate:up
**Sheet:** `PINEntry(.verifyCurrentLayer)` — single entry
**Result:** `disablePINFromCurrentDepth(confirmingPIN:)` — checks `sealedNormalVerifiers[N]` (routing alias). On match: `appLockEnabled = false`, `writeRoutingDepth(.duress)`, `writePinEnabled(false)`. Gate lowered. Verifiers intact. Depth filter still active. Tell-avoidance: coercer at depth N receives phone with gate down and full depth-N decoy view.

### 4.5 Toggle ON: gate lowered at depth 0, correct PIN
**Pre-state:** `SM`, `depth:0`, gate:down
**Sheet:** `PINEntry(.setup)` → `reEnablePIN(pin)` called
**Result:** Step-1 scan finds match at `sealedNormalVerifiers[0]` → `currentDepth = 0`, `state = .normal`, gate re-enabled. Toggle flips ON. Normal depth-0 session resumes.

### 4.6 Toggle ON: gate lowered at depth 0, wrong PIN
**Pre-state:** `SM`, `depth:0`, gate:down
**Sheet:** `PINEntry(.setup)` → `reEnablePIN(pin)` returns `false`
**Result:** `currentDepth = 0` → coercion-acceptance path NOT triggered (guarded by `currentDepth > 0`). Sheet closes, toggle stays OFF.
**Tell:** Toggle remains OFF — coercer knows a PIN is configured. Low-severity; requires coercer with physical access to depth-0 gate-lowered device.

### 4.7 Toggle ON: gate lowered at depth N, matching PIN (routing alias)
**Pre-state:** `SM`, `depth:N`, gate:down
**Entry:** Routing alias for depth N (= duress PIN from depth N-1)
**Result:** Step-1 scan matches `sealedNormalVerifiers[N]` → `currentDepth = N`, gate re-enabled. Toggle ON. Adversary is re-locked at depth N — next foreground will require PIN.

### 4.8 Toggle ON: gate lowered at depth N, non-matching PIN (Bug 37)
**Pre-state:** `SM`, `depth:N > 0`, gate:down
**Entry:** Arbitrary PIN C that matches no existing verifier
**Proposed fix result:** `sealedDuressVerifiers[N]` and `sealedNormalVerifiers[N+1]` written for C. Gate re-enabled at `.duress`. Toggle ON. Next PIN entry with C routes to depth N+1.
**Remaining gaps:** See Bugs 47 and 48 — SM operations at depth N+1 have tells.

---

## 5. Activate Secure Mode

### 5.1 First activation — from `.pinOnly`
**Pre-state:** `.pinOnly`, `depth:0`
**Flow:** Settings → "Learn more" → `SecureModeSetupFlow` (Education → PIN setup → Contact classification → Summary/Activate)
**Result:** `activateSecureMode(confirmingEntryPIN: normalPIN, duressPIN: duressPIN)` runs full 14-step key rotation. `sealedDuressVerifiers[0]` and `sealedNormalVerifiers[1]` written. Blob sealed with sensitive contacts. State → `SM`, `.normal`, `depth:0`. `lastUnlockDate = nil` (grace period cleared — Bug 5 fix).

### 5.2 Re-activation after deactivation — depth 0
**Pre-state:** `.pinOnly`, `depth:0`
**Result:** Same as 5.1. Fresh staged key, fresh blob slot. Old blob slot (from prior activation) may still contain data but is unreachable without the old SE key (deleted at commit). No-op blob replaces it after deactivation.

### 5.3 Activation attempt from depth N (adversary traversal — tell avoidance)
**Pre-state:** `SM`, `depth:N > 0`, gate:up
**Actor:** Adversary who navigated to "Learn more" from duress depth N
**Flow:** Completes full `SecureModeSetupFlow`. Taps Activate.
**Result:** `activateSecureMode` guard: `isRestricted || !isSecureModeActive` — `isRestricted = true` → guard passes. Activation SUCCEEDS: creates depth N+1, seals a blob for N. `SecureModeSetupFlow.SummaryView` catches `invalidStateTransition`... wait — the guard passes here (not invalid state), so activation ACTUALLY RUNS.
**Correct tell-avoidance:** The adversary CAN activate a deeper layer. This is intentional — every depth presents an identical "Activate" option. The adversary creating a new layer is a valid outcome.

### 5.4 Activation from depth N — duplicate state transition
**Pre-state:** `SM`, `depth:N > 0`
**Entry PIN confirm:** `sealedNormalVerifiers[N]` (routing alias) — uses the adversary's known PIN
**Result:** Activation creates `sealedDuressVerifiers[N]` and `sealedNormalVerifiers[N+1]`. Key rotation runs from depth N. Blob for depth N sealed.

### 5.5 Activation attempt from duress state — the SummaryView catch
**Pre-state:** `SM`, `state = .duress` (pushed from depth N via legacy duress path, not routing alias)
**Result:** `activateSecureMode` — guard `isRestricted || !isSecureModeActive`. `isRestricted` = `currentDepth > 0` = true. Guard passes. Proceeds normally (same as 5.3).
**Note:** `invalidStateTransition` is only thrown when `!isRestricted && isSecureModeActive` — i.e., depth 0 with SM already active. Bug 24's catch arm handles that specific path silently.

### 5.6 Activation — duplicate PIN rejected
**Pre-state:** Any
**Entry:** Proposed duress PIN == existing normal or duress verifier at any depth
**Result:** `activateSecureMode` checks all verifiers via `PINManager.checkVerifier` (no counter mutation). Match found → throws `pinCollision`. User sees "PIN already in use" error. No state change.

### 5.7 ContactClassification during activation — depth 0
**Pre-state:** `!SM` or `SM`, `depth:0`
**Result:** `loadSensitiveIDs()` runs (not restricted). `classifiableContacts` = all contacts (depth 0 shows all). `isSensitive` = contacts with `visibleThroughDepth == 0`. User can move contacts between Visible/Sensitive. `save()` → `updateSafeContacts` → writes `encrypt(0)` for sensitive, `encrypt(Int.max)` for safe.

### 5.8 ContactClassification during activation — depth N (adversary)
**Pre-state:** `SM`, `depth:N`, gate:up
**Result:** `loadSensitiveIDs()` has `guard !isRestricted` → early return. `sensitiveIDs = []`. All visible contacts appear in Visible section. "None marked sensitive." `save()` also no-ops. Classification is frozen — adversary cannot reclassify, and no sensitive contacts are exposed. (Bug 25 fix)

### 5.9 ContactClassification during activation — depth N+1 (coercer)
**Pre-state:** `SM`, `depth:N+1` (after Bug 37 re-enable)
**Result:** Same `guard !isRestricted` triggers. `save()` no-ops. Coercer's classification does not stick. (Bug 48 — open)

### 5.10 Activation overlay — back button
**Pre-state:** Activation in progress (`isActivating = true`)
**Result:** `.disabled(isActivating)` on Activate button prevents concurrent calls (Bug 22 fix). Navigation back during overlay: overlay covers content area but not navigation bar — back button technically visible (Bug 32, status: working as expected per tracker). In practice, overlay blocks interaction via `interactiveDismissDisabled`.

### 5.11 Activation failure — error surfaced
**Pre-state:** Activation in progress
**Result:** Any throw from `activateSecureMode` caught by `do/catch` in `SummaryView`. Sets `activationFailed = true` → `.alert("Activation Failed")`. `isActivating = false`, sheet stays open for retry. Data unchanged. (Bug 21 fix)

### 5.12 Activation failure — in duress (tell avoidance)
**Pre-state:** `SM`, `depth:N` (duress via routing alias), coercer traverses activation flow
**Result:** If `activateSecureMode` throws `invalidStateTransition` (depth-0 already-active path — would not actually occur here since guard passes), `SummaryView` catches it with a dedicated arm: silent dismiss via `onDone()`, no alert. (Bug 24 fix)

---

## 6. Deactivate Secure Mode

### 6.1 Deactivation from depth 0
**Pre-state:** `SM`, `depth:0`, gate:up, `appLockEnabled = true`
**UI:** "Deactivate Protection" button visible (`isSecureModeActive && state == .normal && currentDepth == 0 && appLockEnabled`)
**Flow:** `SecureModeDeactivateFlow` → `PINEntry(.verifyCurrentLayer)` → `deactivateSecureMode(confirmingEntryPIN:)`
**Result:** Full reverse key rotation. Sensitive contacts restored from blob. `visibleThroughDepth` cleared to `nil` on all contacts and vault entries (Bug 12 fix). `sealedDuressVerifiers` cleared. Blob replaced with fresh no-op. State → `.pinOnly`.

### 6.2 Deactivation — loading overlay
**Pre-state:** Deactivation in progress
**Result:** `DeactivatingOverlay` covers screen. `interactiveDismissDisabled(true)`. Sheet dismisses only after `deactivateSecureMode` returns or sets `deactivationFailed = true`. (Bug 19 fix)

### 6.3 Deactivation failure — alert
**Pre-state:** Deactivation in progress
**Result:** Any throw from `deactivateSecureMode` → `deactivationFailed = true` → `.alert("Deactivation Failed")`. Data unchanged. User can retry. (Bug 20 fix)

### 6.4 Deactivation from depth N (strip top layer)
**Pre-state:** `SM`, `depth:N > 0`, gate:up
**UI:** "Deactivate Protection" button hidden (`currentDepth != 0`). Deactivation from depth N via UI is intentionally unreachable. (Bug 45 fix)
**Note:** `deactivateSecureMode` technically supports stripping the outermost layer from depth N, but the UI does not expose this path at any depth above 0. Only depth 0 can deactivate.

### 6.5 Deactivation from depth N+1 after coercer activation (Bug 47)
**Pre-state:** `SM`, `depth:N+1`, gate:up, `sealedDuressVerifiers[N+1]` exists
**UI:** "Deactivate Protection" button hidden (`currentDepth = N+1 ≠ 0`). (Bug 47 — open)
**Expected (post-fix):** Button shows when `currentDepth == coercerBaseDepth` and `sealedDuressVerifiers[coercerBaseDepth]` exists. Deactivation strips the coercer's layer and returns to state before their activation.

---

## 7. Contact Operations

### 7.1 New contact — created at depth 0
**Pre-state:** `SM`, `depth:0`
**Result:** `ContactFormV2` shows VISIBILITY section. User selects Safe or Sensitive. `setVisibility(isSensitive:)` writes `encrypt(Int.max)` (safe) or `encrypt(0)` (sensitive). Contact is visible at all depths or hidden at depth 1+.

### 7.2 New contact — created at depth N
**Pre-state:** `SM`, `depth:N > 0`
**Result:** VISIBILITY section hidden in `ContactFormV2` (only shown at depth 0). Contact receives `encrypt(N)` — visible at depths 0..N, hidden at N+1+. Contact is automatically part of the decoy at this depth.

### 7.3 Contact exchange (UWB) — at depth 0
**Pre-state:** `SM`, `depth:0`, proximity established
**Result:** Key exchange updates key records only. `visibleThroughDepth` already set from contact creation. Exchange does not change visibility classification.

### 7.4 Contact exchange (UWB) — at depth N (known safe contact)
**Pre-state:** `SM`, `depth:N`, proximity with a safe contact (visible at depth N)
**Result:** Exchange proceeds normally. Key records updated. `visibleThroughDepth` unchanged. Safe contact refreshed.

### 7.5 Contact exchange (UWB) — at depth N (sensitive contact tries to exchange)
**Pre-state:** `SM`, `depth:N`
**Result:** The sensitive contact is not in `safeContactIDs()` at depth N. Exchange manager receives their data but `update(key:for:)` updates only the key record — contact exists in DB (Design A), hidden by depth filter. An unnamed key entry is created, indistinguishable from a stranger exchange.

### 7.6 Contact list — at depth 0
**Pre-state:** `SM`, `depth:0`
**Result:** `visibleContacts` in `ContactsListV2` returns all contacts where `isDisplayable` at depth 0 = true. This includes all contacts (nil treated as Int.max, all encrypted values). Sensitive contacts (encrypt(0)) pass: `0 >= 0`.

### 7.7 Contact list — at depth N
**Pre-state:** `SM`, `depth:N`, `isRestricted = true`
**Result:** `visibleContacts` filtered via `isSafeContact` → `isVisible(atDepth: N)`. Contacts with `visibleThroughDepth` value < N are hidden. Contacts with nil (Int.max) or value >= N are shown. Sensitive contacts (value 0) hidden for all N > 0.

### 7.8 Decrypt failure — `visibleThroughDepth` non-nil but unreadable
**Pre-state:** Any
**Result:** `isVisible` returns `false` (defense-in-depth). Contact excluded from all UI, share index, and queries. Does not appear regardless of depth. (Design A fallback)

---

## 8. Vault Operations

### 8.1 Add vault entry — at depth 0
**Pre-state:** `SM`, `depth:0`
**Result:** `addEntry(...)` writes `encrypt(0)` to `visibleThroughDepth`. Entry is visible at depth 0, hidden at all duress depths.

### 8.2 Add vault entry — at depth N
**Pre-state:** `SM`, `depth:N`
**Result:** `addEntry(...)` writes `encrypt(N)`. Entry is visible at depths 0..N, hidden at N+1+. Appears in the decoy vault at depth N; also visible to the real user at depth 0.

### 8.3 View vault — at depth 0
**Pre-state:** `SM`, `depth:0`
**Result:** `visibleEntries` returns all entries (no `isRestricted` filter). All entries shown including those with `visibleThroughDepth = 0`.

### 8.4 View vault — at depth N
**Pre-state:** `SM`, `depth:N`, `isRestricted = true`
**Result:** `visibleEntries` filters via `isEntryVisible`: shows only entries where `(decrypt(visibleThroughDepth) ?? 0) >= N`. Depth-0 entries hidden. Depth-N entries shown.

### 8.5 Pre-existing vault entries (nil `visibleThroughDepth`) — at activation
**Pre-state:** Entries created before Secure Mode branch, `visibleThroughDepth = nil`
**Result:** Activation Step 8 stamps these `encode(0)` under staged key. They become hidden at all duress depths. (Bug 26 fix)

### 8.6 Vault entry — corrupt `visibleThroughDepth` at activation
**Pre-state:** Entry with non-nil but unreadable `visibleThroughDepth`
**Result:** Activation Step 8 treats as `encode(0)`: stamps hidden under staged key. Entry becomes inaccessible in duress. (Bug 27 fix)

### 8.7 Shard backup — trustee picker at depth N
**Pre-state:** `SM`, `depth:N`, `isRestricted = true`
**Result:** Trustee picker filtered through `isSafeContact`/depth filter. Sensitive contacts not shown as eligible trustees. (Bug 28 fix)

### 8.8 Vault — attention section at depth N
**Pre-state:** `SM`, `depth:N`, `isRestricted = true`
**Result:** `affected` entries (recovery health) filtered by `visibleIDs` — same depth filter as `visibleEntries`. No hidden-entry health labels leak through.

---

## 9. Inbound Messages

### 9.1 Inbound `.occ` — unlocked depth 0, safe contact
**Pre-state:** `SM`, `depth:0`, unlocked
**Result:** `buildOwnedBasket` runs. `passSecurityControl` at depth 0: `isRestricted = false` → gate open. Bundle decrypted. `openedFileContents` set. Message sheet presents.

### 9.2 Inbound `.occ` — unlocked depth N, safe contact
**Pre-state:** `SM`, `depth:N`, unlocked
**Result:** `passSecurityControl`: `isRestricted = true`, `isSafeContact(identifier) = true` (contact visible at depth N) → gate open. Bundle decrypted and displayed.

### 9.3 Inbound `.occ` — unlocked depth N, sensitive contact
**Pre-state:** `SM`, `depth:N`, unlocked
**Result:** `passSecurityControl`: `isRestricted = true`, `isSafeContact(identifier) = false` → throws. "Not addressed to you" shown. No decryption attempted, no sender identity revealed. (Bug 40 fix covers identity challenges and shard ops via same gate)

### 9.4 Inbound identity challenge — unlocked depth N
**Pre-state:** `SM`, `depth:N`, unlocked
**Result:** `passSecurityControl` fires before identity-challenge branch in `buildOwnedBasket`. If sender is hidden contact: throws → no challenge handled, no approval sheet. (Bug 40 fix)

### 9.5 Inbound `.occ` — app locked, file queued
**Pre-state:** Locked, file arrives via `onOpenURL`
**Result:** `isLocked && requiresPIN` → raw bytes stored in `pendingFileData`. No decryption. No sender identification. File waits for PIN.

### 9.6 Inbound `.occ` — queued, grace period auto-unlock
**Pre-state:** Locked, `pendingFileData` set, `handleActive()` fires within grace
**Result:** Grace path clears `isLocked = false`, but does NOT drain `pendingFileData` — that path is drained only by `onNormal`. File remains pending until next foreground outside grace (requires PIN). (Bug 35 fix)

### 9.7 Inbound `.occ` — queued, normal PIN entered
**Pre-state:** `pendingFileData` set, normal PIN entered
**Result:** `onNormal` fires. Captures + clears `pendingFileData`. Dispatches `processInboundFile` after gate fully dismisses (`onDismiss`). (Bug 1b fix — avoids race with cover dismiss animation)

### 9.8 Inbound `.occ` — queued, duress PIN entered
**Pre-state:** `pendingFileData` set, duress PIN entered
**Result:** `onDuress` clears `pendingFileData` without processing. "Not addressed to you" shown.

---

## 10. Share Extension

### 10.1 Share extension — app locked
**Pre-state:** `SM`, locked
**Result:** On `scenePhase == .inactive` with `requiresPIN && appLockEnabled`, share index rebuilt with `safeContactIDs(atDepth: 1)`. Sensitive contacts removed before app suspends. Extension reads depth-1 index. (Bug 6 fix)

### 10.2 Share extension — app unlocked depth 0
**Pre-state:** `SM`, `depth:0`, unlocked
**Result:** Index contains all contacts. Extension shows full recipient list.

### 10.3 Share extension — app unlocked depth N
**Pre-state:** `SM`, `depth:N`, unlocked
**Result:** `syncShareIndex` on `onNormal` passes `safeContactIDs()` at depth N. Extension shows only depth-N-visible contacts.

### 10.4 Share extension — app returns to foreground while locked
**Pre-state:** `SM`, locked, app foregrounded
**Result:** `handleActive()` — `isLocked = true` → share index rebuilt with depth-1 filter before any content is displayed. Index stays filtered until successful PIN entry. (Bug 6 fix)

---

## 11. Activation Sequence — Integrity

### 11.1 Crash at Step 3 — new SE key orphaned, no writes
**Pre-state:** Activation in progress
**Crash point:** After new SE key created at fresh UUID tag, before any DB writes
**Recovery:** On next launch: new SE key tag exists in Keychain with no matching `AppLayerConfig` reference. Old canonical key still valid. State still `.pinOnly`. User can retry activation. Orphaned key detected and deleted on launch (or cleaned up at retry).

### 11.2 Crash at Step 11 — SQLite WAL write interrupted
**Pre-state:** Activation in progress, `modelContext.save()` in progress
**Recovery:** SQLite WAL atomicity guarantees the write either fully committed or fully rolled back. If rolled back: old canonical key still authoritative, state unchanged, retry activation. If committed: full activation complete.

### 11.3 Crash between commit and old-key deletion (Step 13)
**Pre-state:** `modelContext.save()` succeeded, old SE key not yet deleted
**Recovery:** On next launch: both old and new SE keys in Keychain. `AppLayerConfig` references new key tag. Old key is orphaned — detected and deleted on launch. No data loss. Known limitation: very small window.

### 11.4 WAL checkpoint after commit (correct ordering)
**Result:** `walCheckpoint(TRUNCATE)` runs after `commitStagedLocalDBKey()`. Main SQLite file reflects new canonical key only after the commit is irrevocable. Pre-commit: WAL still contains old-key ciphertext (safe). Post-commit: WAL flushed. (Bug 14 fix)

---

## 12. Deactivation Sequence — Integrity

### 12.1 Crash at Step 4 — new key orphaned
**Pre-state:** Deactivation in progress
**Crash point:** New SE key created, no DB writes yet
**Recovery:** Old canonical key still valid. `AppLayerConfig` still has old key tag + duress verifier. State still `SM`. User can retry deactivation. Blob intact.

### 12.2 Crash at Step 10 (WAL commit)
**Recovery:** SQLite atomicity — either fully committed (deactivation complete: sensitive contacts restored, duress verifier cleared) or fully rolled back (old state intact). No data loss in either case.

### 12.3 Crash between Step 10 (commit) and Step 11 (WAL checkpoint)
**Recovery:** Next launch reads `AppLayerConfig` — duress verifier cleared → `.pinOnly`. Old canonical key deleted. WAL checkpoint runs at next normal launch. Functionally deactivated.

### 12.4 `rewriteLayerStore()` after deactivation
**Result:** Runs on `DispatchQueue.global(.utility)` — does not block main thread. Fresh no-op blob replaces real blob. All future `maintainLayerStore()` calls treat this as a normal no-op and rewrite on 24h schedule. (Bug 43 fix)

---

## 13. Multi-Layer Stack (N > 1 depths)

### 13.1 Cold start — enter depth-2 PIN directly
**Pre-state:** Three layers configured (depths 0, 1, 2)
**Entry:** Depth-2 PIN (stored as `sealedNormalVerifiers[2]`)
**Result:** `verify()` step 1 scans all normal verifiers — hits index 2. `currentDepth = 2`, `state = .normal`. Depth-2 decoy view presented. No walk through depths 0 and 1.

### 13.2 Enter depth-1 PIN from depth 1 — push down
**Pre-state:** `depth:1`, gate:up (depth-1 PIN is the duress PIN for depth-0→1 boundary, also stored as `sealedNormalVerifiers[1]`)
**Entry:** The depth-1 PIN at the lock screen while already at depth 1
**Result:** `verify()` step 1 finds `sealedNormalVerifiers[1]` — routes back to `currentDepth = 1` (not a push-down). Step 2 (`sealedDuressVerifiers[1]`) would push to depth 2 only if a different depth-2 duress PIN is entered.

### 13.3 Push from depth 1 to depth 2
**Pre-state:** `depth:1`, gate:up
**Entry:** The depth-2 duress PIN (stored as `sealedDuressVerifiers[1]`)
**Result:** `verify()` step 1: no match (depth-2 PIN not in normal verifiers at index matching current scan; the routing alias at index 2 uses normalLabel but scanning starts from 0 — it WILL match at index 2 in step 1). Actually: step 1 finds `sealedNormalVerifiers[2]` → routes to `currentDepth = 2` directly.
**Note:** Push-down via step 2 (`sealedDuressVerifiers[N]`) only fires if step 1 finds NO match. Since the depth-2 PIN's routing alias is at `sealedNormalVerifiers[2]`, step 1 always finds it. Step 2 only fires for a PIN that is a duress verifier but has no corresponding routing alias yet — which does not occur in the current design.

### 13.4 Activation from depth 2 (create depth 3)
**Pre-state:** `SM`, `depth:2`, gate:up
**Result:** `activateSecureMode` guard: `isRestricted = true` → passes. `excludedSlots` = `Set((0..<min(2,2)).compactMap {...})` = slots 0 and 1 excluded (real and convincing-duress blobs protected). Random slot chosen from remaining 30. Depth-2 blob may be overwritten (expendable). (Bug 46 fix)

### 13.5 Deactivation cascade from depth 3
**Pre-state:** `SM`, `depth:3`, gate:up (theoretical, UI unreachable)
**Note:** Deactivation UI is blocked at any depth > `coercerBaseDepth` (currently > 0). Only depth-0 deactivation is reachable via UI. Programmatic deactivation from depth 3 strips to depth 2; from depth 2 to depth 1; from depth 1 to depth 0 (full deactivation to `.pinOnly`).

### 13.6 Blob slot exhaustion (all 32 slots used)
**Pre-state:** 32 activations across the full stack
**Result:** `push()` throws `payloadTooLarge` or returns no valid slot. Activation fails. In practice, the maximum useful stack is far below 32 — each depth requires a new PIN and intentional adversarial setup. Not a realistic limit.

---

## 14. Coercion Scenarios

### 14.1 Single-layer coercion — adversary knows only duress PIN
**Sequence:**
1. Real user activates SM (depth 0 → depth 1 available)
2. Adversary coerces duress PIN → enters at depth 1
3. Adversary sees decoy contacts, vault appears empty (or contains depth-1 vault entries)
4. Adversary browses Settings → "Enable PIN" disabled, "Learn more" visible, "Deactivate Protection" hidden
5. Adversary attempts to activate a new layer → succeeds (creates depth 2)
6. Adversary enters new duress PIN → depth 2 (empty)
**What adversary cannot determine:** Whether depth 0 exists. Whether the decoy is convincing.

### 14.2 Multi-layer coercion — adversary traverses multiple layers
**Sequence:**
1. Real user has N layers configured
2. Adversary coerces first duress PIN → depth 1
3. Adversary finds "Learn more" → activates → depth 2 → and so on
4. At any depth > 0: "Deactivate Protection" hidden, decoy contacts shown, sensitive contacts inaccessible
**What adversary cannot determine:** How many layers the real user configured. Whether they have reached the bottom.

### 14.3 Gate-lowered device — adversary receives phone unlocked
**Sequence:**
1. Real user at depth N enables gate-lowered mode (`disablePINFromCurrentDepth`)
2. Device handed over — adversary sees depth-N decoy content without PIN prompt
3. Adversary browses everything visible at depth N
4. Adversary taps "Enable PIN" toggle → `PINEntry(.setup)` appears
**Fork A — adversary enters real PIN:** `reEnablePIN` matches normal verifier → gate re-enabled at matched depth → toggle ON.
**Fork B — adversary enters unknown PIN:** `reEnablePIN` returns false (depth 0) or coercion-acceptance path (depth N > 0, Bug 37 pending fix).

### 14.4 Gate-lowered device — adversary tests full SM functionality (Bugs 47, 48 — fixed)
**Sequence (depth N > 0):**
1. Adversary enters PIN C (not matching) → coercion-acceptance path creates depth N+1, gate re-enabled. `coercerBaseDepth = N+1`.
2. Adversary enters C at lock screen → depth N+1, `currentDepth = N+1`.
3. Adversary tries "Learn more" → activation flow opens. `ContactClassification` loads and saves (guard: `currentDepth == coercerBaseDepth`). ✓
4. Adversary activates SM from depth N+1 → creates depth N+2.
5. Adversary returns to Settings → "Deactivate Protection" visible (condition: `currentDepth == 0 || currentDepth == coercerBaseDepth`). ✓
6. Adversary deactivates → strips depth N+2. Returns to depth N+1 state.
**All tells from Bugs 47/48 resolved.** `coercerBaseDepth` persisted in `AppLayerConfig` enables the correct UI at depth N+1.

### 14.5 Adversary observes Settings PIN toggle state
**At depth 0 (SM active, gate up):** Toggle ON + disabled. Only "Deactivate Protection" distinguishes this from `.pinOnly` with toggle disabled for another reason.
**At depth N (adversary duress, gate up):** Toggle ON + disabled. "Learn more" visible. "Deactivate Protection" hidden. Identical to `.pinOnly` appearance for a user who has enabled SM elsewhere.
**At depth 0 (gate down):** Toggle OFF + enabled. "Deactivate Protection" hidden (requires `appLockEnabled`). "Learn more" visible. Identical to `.pinOnly` gate-down.

### 14.6 Adversary checks app switcher / screenshots
**Result:** `handleInactive()` fires on `.inactive` → `isContentHidden = true` → opaque overlay applied synchronously. App-switcher thumbnail is blank regardless of current depth or lock state. (Bug 33 / U5 fix)

### 14.7 Adversary uses Share extension to enumerate contacts
**Result:** Share index always filtered to `safeContactIDs(atDepth: 1)` when locked, or current-depth safe contacts when unlocked in duress. Sensitive contacts never appear in the extension's contact list. (Bug 6 fix)

---

## 15. Edge Cases

### 15.1 `maintainNoOpBlob` encounters real blob
**Pre-state:** SM active, `maintainNoOpBlob()` called on launch
**Result:** `init()` checks `AppLayerConfig` for duress verifier presence before calling `maintainNoOpBlob`. If SM active: skipped entirely. Real blob preserved. (Bug 11 fix)

### 15.2 Multiple `.occbak` files in App Group
**Result:** `findBlob` sorts by `contentModificationDateKey` descending and returns the most recently written file. Stale files from interrupted writes are ignored. (Bug 9 fix)

### 15.3 Sensitive contact with profile photo — activation blob
**Result:** `convertToMutableCopy` strips `imageData` and `thumbnailImageData` before building `LayerContact`. Images remain in DB (re-encrypted in Step 8). Blob stays within 32 KB slot limit. (Bug 44 fix)

### 15.4 Deactivation — `save(contact:using:)` UPDATE path with nil images
**Pre-state:** Blob draft has nil images (post Bug 44 fix)
**Result:** UPDATE path in `save(contact:using:)` uses `if let encryptedImageData { ... }` guard. Nil draft images do not overwrite the existing re-encrypted image data in the DB. (Bug 44 fix)

### 15.5 `visibleThroughDepth` watermark after deactivation
**Result:** Deactivation clears `visibleThroughDepth = nil` on all safe contacts and all vault entries. No activation-era encrypted blob remains in these fields. Raw SQLite dump post-deactivation is indistinguishable from a pre-activation state. (Bug 12 fix)

### 15.6 Sensitive contacts lose sensitivity after deactivation cycle
**Pre-state:** Activate → deactivate cycle
**Result:** `ContactBlobRecord.visibleThroughDepth` carries the original depth value through the blob. Deactivation restores `record.visibleThroughDepth ?? 0` — contacts classified as sensitive retain their classification after deactivation. (Bug 23 fix)

### 15.7 Quantum key material after deactivation cycle
**Result:** `convertToMutableCopy` carries `quantumKeyMaterialEncrypted` through to the draft. Restored contacts have quantum material intact. (Bug 30 fix)

### 15.8 Classical-only bundle sent to receiver with sender's quantum material
**Pre-state:** Sender's contact lacks quantum material (prior Bug 30 cycle); receiver has sender's quantum material stored
**Result:** Bundle sent with `forwardSecretNoPQ` or `longTermNoPQ` mode. Receiver decrypts using classical path (mode-matched). No CryptoKitError 3. (Bug 31 fix)

### 15.9 `AppLayerConfig` always present
**Pre-state:** Fresh install
**Result:** `init()` creates `AppLayerConfig` if absent. All `sealedNormalVerifiers` and `sealedDuressVerifiers` padded to `maxVerifierCount` with random filler of identical byte size. `persistedDepth` and `pinEnabled` both written immediately — always non-nil regardless of whether a PIN is ever configured.

### 15.10 File protection re-applied after WAL merge
**Result:** `OccultaApp` listens to `NSManagedObjectContextDidSaveObjectIDsNotification`. On each save, `reapplyFileProtection()` stamps `.completeFileProtection` on the main `.sqlite`, `-wal`, and `-shm` files. Sidecar files recreated by SwiftData always receive `complete` protection before the next read. (S3/S4 fix)

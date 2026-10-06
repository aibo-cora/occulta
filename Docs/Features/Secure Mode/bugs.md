# Bug Tracker

---

## Bug 1 — PIN gate / message sheet interaction on notification open

**Status:** Closed (Fixed)

### Severity: High

This entry covers two separate incidents with the same root area: the interaction between the PIN gate `fullScreenCover` and the message `.sheet` when the app is opened from a notification.

---

#### Incident A — Messages visible over PIN lock (original)

An authenticated attacker with brief physical access to an unlocked device can open a sheet (e.g. via a notification tap or an in-app action) and read message content without ever entering the PIN. The PIN layer is present but rendered below sheets in the SwiftUI hierarchy, making it visually and interactively bypassable.

A secondary issue exists independently of the z-order problem: if the app is locked and a message notification is tapped, `buildOwnedBasket` runs inside the `onOpenURL` Task before any PIN is entered. If the basket is from a safe contact and `openedFileContents` is set at that point, entering the duress PIN afterward would still present the sheet — because `openedFileContents` was populated while the security state had not yet been determined by PIN entry.

**Root Cause**

`PINEntry` was applied as an `.overlay` on `TabView`. SwiftUI overlays are layout primitives — iOS modal presentations (`.sheet`, `.fullScreenCover`) are UIKit-level operations that attach to the window's root view controller, completely outside the SwiftUI view tree. They render above any overlay regardless of z-order.

The content gate gap is a timing issue: `openedFileContents` is set inside an async Task that can run while the app is locked, before the user's PIN determines the security depth.

**Resolution**

Two fixes applied together:

**1. z-order fix** — replaced `.overlay { if self.isLocked { ... } }` with `.fullScreenCover(isPresented: self.$isLocked)`. A `fullScreenCover` is itself a UIKit modal presentation; iOS stacks it above any existing sheets so it cannot be underlapped.

**2. Content gate** — two check points added:
- *At set-time* (app already unlocked in restricted mode): after `buildOwnedBasket` returns, if `security.isRestricted` and the sender is not a safe contact, suppress the basket and show the standard "not addressed to you" error instead of setting `openedFileContents`.
- *After duress unlock* (message queued while locked, duress PIN entered after): in the `onDuress` callback, before clearing `isLocked`, check any pending `openedFileContents` against `isSafeContact`. If the sender is not visible at duress depth, clear the basket and surface the error. Sensitive contacts are absent from the DB in Secure Mode, so `isSafeContact` returns `false` for them naturally.

---

#### Incident B — PIN gate re-appears after dismissing message sheet (regression)

When the user cold-opens the app via a notification tap, enters their PIN, and then dismisses the resulting message sheet, the PIN gate re-presents itself:

1. App opens from notification → PIN gate appears (expected)
2. User enters PIN → gate lowers
3. Message sheet presents
4. User dismisses message sheet → PIN gate re-appears (unexpected)

**Root Cause**

`onNormal` drained `pendingFileData` by starting an async `Task { await processInboundFile(data) }` immediately after calling `unlockNormal()`. `unlockNormal()` sets `needsPINEntry = false`, triggering the `fullScreenCover` dismiss animation — but the animation takes ~300 ms to complete. The async task can set `openedFileContents` during this window, while the cover is still mid-dismiss.

UIKit prevents two modal presentations from the same host view controller simultaneously. The `.sheet` triggered by `openedFileContents` cannot present while the `fullScreenCover` is still animating out, so UIKit queues it for a retry. When the user later dismisses the message sheet, UIKit's presentation-hierarchy cleanup for the queued presentation causes the `fullScreenCover` binding setter to be called, re-raising the gate.

Introduced in commit `182bbd7` when the lock state moved from `OccultaApp.isLocked` into `Manager.Security.needsPINEntry`. The old code had the same structural pattern, but switching to a `Binding(get:set:)` on an `@Observable` property changed how SwiftUI reconciles presentation state, making the UIKit conflict more likely to surface.

**Resolution**

Moved the `pendingFileData` drain from `onNormal` to the `fullScreenCover`'s `onDismiss` callback. `onDismiss` fires after the cover has fully dismissed and its UIKit view controller is removed from the hierarchy, so the message sheet presentation no longer conflicts with a mid-dismiss cover.

Two drain paths:
- **Grace-period auto-unlock** (cover never presented): the `.active` scene handler drains `pendingFileData` immediately, as before.
- **Normal PIN entry**: `onDismiss` drains `pendingFileData` after the cover is gone.

`onDuress` and `onWipe` already clear `pendingFileData`, so `onDismiss` is a no-op for those paths.

---

## Bug 4 — Disabling PIN in duress mode prompts for PIN twice

**Status:** Closed (Fixed)

### Severity: Medium
Double prompting is a UX defect on its own, but in a coercion scenario it is worse: the unexpected second prompt is a behavioural tell that the device is in a special state. A coerced user asked to "turn off the PIN" would visibly hesitate or fail on the second prompt, signalling to an observer that something unusual is happening.

### Root Cause
`Settings.SecuritySettings` used `PINEntry(mode: .setup)` for the `.active`/`.duress` disable path and `PINEntry(mode: .verifyNormal)` for the `.pinOnly` path. `.setup` is a two-phase flow (enter, then confirm); `.verifyNormal` is single-entry. The asymmetry was a UI artifact — `disablePINFromCurrentDepth` itself performs exactly one check internally.

### Resolution
Introduced `PINEntry.Mode.verifyCurrentLayer`: single-entry, calls `checkCurrentLayerPIN` (no counter mutation, duress-verifier aware), delivers the PIN to `onNormal` on match. Replaced `.setup` in the `.active`/`.duress` branch and both `.verifyNormal` usages with `.verifyCurrentLayer`. All three Settings paths now present a single-entry prompt. The old `.verifyNormal` case was removed.

---

## Bug 5 — App stays in grace period after Secure Mode activation; PIN does not show on scene change for ~5 minutes

**Status:** Closed (Fixed)

### Severity: High
Immediately after Secure Mode is activated, the window during which the app can be backgrounded and foregrounded without triggering a PIN prompt is ~5 minutes. An adversary who witnesses activation (or checks the device shortly after) can access the app without a PIN during this window, defeating the purpose of activating Secure Mode in the first place.

### Root Cause
`activateSecureMode` did not clear `lastUnlockDate`. The field retained the timestamp from the most recent `recordUnlock()` call (the PIN entry that unlocked the app before the user started the setup flow). `isWithinGracePeriod` in `OccultaApp` returned `true` until that timestamp was more than 5 minutes old, so background → foreground transitions skipped the PIN prompt for the remainder of that window.

### Resolution
Set `self.lastUnlockDate = nil` in `activateSecureMode`, after `resetCounters()` and before the state transition to `.active`. `isWithinGracePeriod` already returns `false` when `lastUnlockDate` is `nil`, so the PIN is required on the very next background → foreground transition after activation.

---

## Bug 6 — Share Extension shows sensitive contacts while main app is locked

**Status:** Closed (Fixed)

### Severity: Critical
The Share Extension's recipient picker exposed the full contact list — including sensitive contacts — while the main app was locked. The extension runs as a separate process with no app-level authentication; it reads `ShareIndex.sqlite` directly. An adversary with brief physical access to an unlocked device could open any app (Photos, Files) and use the Occulta share target to enumerate the full contact list without ever entering a PIN.

### Root Cause
Two gaps in the share index rebuild logic:

1. **Lock handler** (`scenePhase == .inactive`): when the app locked, `isLocked` was set to `true` but the share index was not rebuilt. It retained whatever filter was in effect from the previous session — typically the full contact list from a normal-mode unlock.

2. **Foreground handler** (`scenePhase == .active`): the handler rebuilt the index based on `security.isRestricted`, which is `false` in `.active` state. When the app came to the foreground with `isLocked == true` (PIN prompt showing), it overwrote the index with all contacts before the user entered any PIN.

The extension reads the index at any point while suspended — it does not wait for the main app to foreground and re-filter.

### Resolution
Three changes applied together:

- `safeContactIDs(atDepth:)` — added an explicit depth parameter (defaults to `currentDepth`) so callers can request depth-1 visibility without being in `.duress` state.
- **Lock handler** — on `scenePhase == .inactive` when `requiresPIN && appLockEnabled`, immediately rebuild the share index filtered to depth-1 (`safeContactIDs(atDepth: 1)`). Sensitive contacts are removed from the index before the app suspends.
- **Foreground handler** — when `isLocked == true` (PIN not yet entered) or `isRestricted == true` (duress mode), apply depth-1 filtering instead of writing all contacts. Only after a successful PIN entry (`onNormal`) does the index expand to all contacts.


**Retired by the removal of the share index, 2026-08-16.** The `ShareIndex.sqlite` mirror this entry constrains no longer exists — the recipient picker moved into the main app, behind the PIN gate (Bug 84). The fix described above was correct for the design it was written against; it is recorded here as history, not as live behaviour.
---

## Bug 7 — Hard-delete inside staged key rollback scope causes irrecoverable data loss

**Stale, 2026-09-11:** `commitStagedLocalDBKey`/`rollbackStagedLocalDBKey` — the staged-key rollback
pattern this bug is about — no longer exist, deleted whole by Removal Stages 0-4, 2026-09-10.

**Status:** Closed (Fixed)

### Severity: High
In `activateSecureMode`, `hardDeleteContact` was called after all safe contacts were re-encrypted with the staged key and persisted to the DB — but still inside the `do { } catch { rollbackStagedLocalDBKey() }` block. If `hardDeleteContact` threw, the catch block deleted the staged key, but the DB already contained data encrypted exclusively with it. The canonical key could no longer decrypt any of those records. All contact data was permanently unrecoverable.

### Root Cause
The hard-delete loop sat after the Step 8 re-encryption writes but before `commitStagedLocalDBKey()` (Step 10). Any error in this window triggered a rollback that invalidated the only key capable of reading the already-written DB rows.

### Resolution
Moved the `hardDeleteContact` loop to after `commitStagedLocalDBKey()` (Step 10, the point of no return). Each call uses `try?` — a delete failure is silently absorbed and does not re-throw into the outer `catch`. After commit the staged key is the canonical key, so a delete failure leaves sensitive contacts in the DB encrypted under the canonical key. The user can retry activation; no rollback is triggered and no data is lost.

---

## Bug 8 — Vault PEKs unnecessarily stored in the blob

**Stale, 2026-09-11:** `BlobPayload`/`VaultPEKRecord` no longer exist — deleted whole by Removal
Stages 0-4, 2026-09-10.

**Status:** Closed (Fixed)

### Severity: Medium
`activateSecureMode` Step 6 unwrapped every vault entry's per-entry key (PEK) and stored the raw 32-byte key bytes inside `BlobPayload`. The vault key is derived from a dedicated SE key entirely independent of the local DB key rotation — vault entries never need re-keying during activation or deactivation.

`payload.vaultPEKs` was unsealed in `deactivateSecureMode` and silently ignored, confirming the data served no purpose. Meanwhile, storing raw PEK bytes in the blob unnecessarily widened the attack surface: a blob compromise (requiring only the SE Secure Mode key, no biometrics) also yielded the symmetric keys for all vault entry content, bypassing the biometric gate that normally protects them.

### Resolution
Removed `VaultPEKRecord` struct and the `vaultPEKs` field from `BlobPayload`. Removed Step 6 (vault PEK collection) from `activateSecureMode`. The vault's `visibleThroughDepth` re-encryption (Step 8) is the only vault-related work the key rotation requires.

---

## Bug 9 — `findBlob` returns an arbitrary file when multiple `.occbak` files exist

**Stale, 2026-09-11:** `findBlob` no longer exists — deleted whole by Removal Stages 0-4, 2026-09-10.

**Status:** Closed (Fixed)

### Severity: Low
`findBlob` requested `contentModificationDateKey` from the filesystem but never used it for sorting. `files?.first { $0.pathExtension == "occbak" }` returned whichever file appeared first in the enumeration order, which is unspecified on APFS. If two `.occbak` files were present — e.g. a stale file from a prior interrupted `seal()` — the wrong blob could be returned, causing deactivation to fail with `BlobError.decryptionFailed` or to silently unseal stale data.

### Root Cause
The sort step was omitted when the resource key was added. `FileManager.contentsOfDirectory` does not guarantee ordering.

### Resolution
`findBlob` now filters to `.occbak` files, sorts by `contentModificationDateKey` descending (falling back to `.distantPast` on read failure), and returns `first`. The most recently written file is always selected.

---

## Bug 10 — `reEncryptKeyRecords` after INSERT in deactivation

**Stale, 2026-09-11:** `reEncryptKeyRecords` no longer exists, and deactivation no longer does any
key-record re-encryption at all — deleted whole by Removal Stages 0-4, 2026-09-10.

**Status:** Closed (Invalid — proposed fix causes data loss)

### Severity: N/A
The original diagnosis claimed the `reEncryptKeyRecords` call after INSERT in `deactivateSecureMode` Step 5 is a no-op because `save(contact:using:stagedCrypto)` already encrypts `contactPublicKeys` via `stagedCrypto`.

This is incorrect. The INSERT path in `ContactManager.save` handles key records via `self.update(key:for:)`, which uses `self.cryptoManager` (the canonical key), not the `crypto` parameter. After INSERT, key records are canonical-key encrypted. `reEncryptKeyRecords` correctly decrypts them with the canonical key and re-encrypts with the staged key.

Removing the call — as the original resolution proposed — would leave key records for every restored contact encrypted with the deactivation-era canonical key. After `commitStagedLocalDBKey()` that key is superseded and deleted, making every restored contact's public key material permanently unreadable.

### Resolution
No code change. The call is correct and must stay.

---

## Bug 11 — `maintainNoOpBlob` destroys the real blob after 24 hours, breaking deactivation

**Stale, 2026-09-11:** `maintainNoOpBlob` no longer exists — deleted whole by Removal Stages 0-4,
2026-09-10.

**Status:** Closed (Fixed)

### Severity: Critical
`maintainNoOpBlob()` is called unconditionally from `OccultaApp.init()` on every launch. It calls `isStale()` on the existing `.occbak` file — the same function used for no-op blobs, which considers any file older than 24 hours stale. When Secure Mode is active, the blob holds a real payload (sensitive contact data, not random bytes). If the user activates Secure Mode and returns more than 24 hours later, `maintainNoOpBlob` deletes the real blob and writes a fresh random-byte no-op in its place. The blob key decrypts the no-op successfully (same SE-derived key), but the plaintext is random garbage. `JSONDecoder` fails immediately, surfacing as `"Unexpected character '\u{0C}' around line 1"`. Deactivation is permanently blocked until the blob is manually removed — but doing so also destroys all sensitive contact data.

### Root Cause
`maintainNoOpBlob` was designed for no-op blob maintenance and has no awareness of whether the current blob is a real payload. The 24-hour staleness check was intended to keep Last-Modified timestamps from being correlated with meaningful events — it was never meant to apply to real payloads.

### Resolution
In `OccultaApp.init()`, read `AppLayerConfig` from the already-initialized `ModelContainer` (no SE key required) and check whether a duress verifier is present before calling `maintainNoOpBlob`. A duress verifier indicates Secure Mode is active and the blob holds real data. If active, skip `maintainNoOpBlob` entirely. After deactivation, `rewriteNoOpBlob()` is called explicitly to install a fresh no-op, so the next launch will not see a stale real blob.

---

## Bug 12 — `visibleThroughDepth` watermark survives deactivation

**Stale, 2026-09-11:** The Steps 4/5/6 this bug describes no longer exist — `deactivateSecureMode`
no longer touches `visibleThroughDepth` at all, per Removal Stages 0-4, 2026-09-10.

**Status:** Closed (Fixed)

### Severity: Low-Medium
After Secure Mode activation, every contact that existed at activation time has `visibleThroughDepth` set to encrypted `Int.max` (migrated from `nil` in Step 5 of `activateSecureMode`). `deactivateSecureMode` re-encrypted this value under the new staged key but never cleared it. Even after deactivation, those contacts permanently retain a non-null `visibleThroughDepth` field — a forensic watermark detectable without decryption. An examiner inspecting the SQLite file after deactivation could identify which contacts predated Secure Mode activation by the presence of this field.

The same issue applied to vault entries restored in Step 6 of deactivation.

### Root Cause
`deactivateSecureMode` Step 4 re-encrypted the existing `visibleThroughDepth` value rather than erasing it. `nil` and `Int.max` are functionally identical (`isVisible` returns `true` for both), so clearing to `nil` loses no information but removes the activation-era artefact.

### Resolution
Three sites in `deactivateSecureMode` updated to set `visibleThroughDepth = nil` instead of re-encrypting:
- **Step 4** (safe contacts re-encryption loop): `profile.visibleThroughDepth = nil` unconditionally, replacing the `AES.GCM.seal` block.
- **Step 5** (sensitive contacts restored from blob): `restored.visibleThroughDepth = nil`, replacing assignment of `visibleEncrypted`.
- **Step 6** (vault entries): `entry.visibleThroughDepth = nil`, replacing assignment of `visibleEncrypted`.

The `depthData` / `visibleEncrypted` intermediates are now entirely unused and were removed.

---

## Bug 13 — Hard-delete of sensitive contacts conflicts with normal-mode visibility

**Stale, 2026-09-11:** `forensic-trace-avoidance.md` §S5, cited here as the accepted trade-off, is
itself marked Retired (2026-09-10) — the blob/rotation model this decision weighed against is gone.

**Status:** Closed (design decision — hard-delete removed)

### Severity: High
After `activateSecureMode` completes, sensitive contacts (those with `visibleThroughDepth < 1`) are supposed to be removed from the SQLite database — their data is sealed in the blob, and the DB hard-delete is the forensic protection that prevents a duress-mode examiner from finding them at the SQLite layer. In practice the hard-delete silently fails: sensitive contacts remain in the DB after activation, meaning the forensic protection does not apply even though depth filtering correctly hides them from the UI in duress mode.

### Root Cause
Hard-deleting sensitive contacts from the DB removes them from the normal-mode contact list. Sensitive contacts have `visibleThroughDepth = 0` (visible at depth 0, hidden at depth 1+). If they are not in the DB, `isVisible(atDepth: 0)` never runs for them — the real user entering the normal PIN cannot see their own sensitive contacts.

The original rationale for hard-delete was forensic: preventing a raw SQLite examination during duress exposure from finding sensitive contact rows encrypted under the canonical key. However, this conflicts with the primary functional requirement that the real user retains full access via the normal PIN.

### Resolution
The hard-delete loop was removed from `activateSecureMode`. Sensitive contacts remain in the DB with `visibleThroughDepth` controlling UI visibility. Depth filtering in `ContactsListV2` hides them at depth 1 (duress mode). Pre-activation page slack is covered by S1 (DB key rotation) and S2 (`PRAGMA secure_delete = ON`). The residual forensic gap (sensitive rows readable via raw SQLite during duress exposure) is documented in `forensic-trace-avoidance.md §S5` as an accepted trade-off.

---

## Bug 14 — `commitStagedLocalDBKey` uses invalid `SecItemUpdate` search attributes, causing permanent data loss on deactivation failure

**Stale, 2026-09-11:** `commitStagedLocalDBKey` no longer exists — deleted whole by Removal Stages
0-4, 2026-09-10.

**Status:** Closed (Fixed)

### Severity: Critical
`commitStagedLocalDBKey` failed consistently during deactivation with `errSecNoSuchAttr` (OSStatus -25303), triggering rollback. The rollback deleted the staged random component. Because the WAL checkpoint ran *before* the commit, the main SQLite file already contained all contact data re-encrypted under the staged key. With the staged random deleted, those contacts became permanently unreadable — all user contact data was destroyed.

### Root Cause
Three `SecItemUpdate` calls inside `commitStagedLocalDBKey` used attributes that are not valid search criteria for `SecItemUpdate`:

- **Steps A and B** (SE key tag renames): included `kSecAttrTokenID` and `kSecAttrKeyType` in the search dictionary. On the affected iOS version, `kSecAttrTokenID` as a `SecItemUpdate` search key returns `errSecNoSuchAttr` (-25303).
- **Step C** (Keychain random update): included `kSecAttrAccessible` in the search dictionary. `kSecAttrAccessible` is valid for `SecItemAdd` and `SecItemCopyMatching` but not for `SecItemUpdate` — when the item already exists it returns `errSecNoSuchAttr` instead of finding and updating it.

Steps A and B worked during activation because activations used an older build where those attributes were absent. Step C worked during first activation only because `localDBRandomKeychainAccount` did not yet exist, so `SecItemUpdate` returned `errSecItemNotFound` and the defensive `SecItemAdd` fallback ran successfully. All subsequent activations and all deactivations failed at Step C once the item existed.

A compounding factor: the WAL checkpoint (`PRAGMA wal_checkpoint(TRUNCATE)`) ran before `commitStagedLocalDBKey`. When the commit failed and rollback deleted the staged random, the main SQLite file already contained contacts encrypted exclusively under the staged key — permanently unreadable.

### Resolution
Two fixes applied together:

**1. `commitStagedLocalDBKey` search dictionaries** — all three steps now use only the minimal valid search keys:
- Steps A and B: `kSecClass` + `kSecAttrApplicationTag` only (sufficient to identify SE keys by tag uniquely).
- Step C: `kSecClass` + `kSecAttrAccount` only (sufficient to identify generic password items by account).

`kSecAttrTokenID`, `kSecAttrKeyType`, and `kSecAttrAccessible` were removed from all search dictionaries. They remain valid in the *attributes-to-update* dictionary (Step C's add fallback) where they are correctly used.

**2. WAL checkpoint moved after commit** — in both `activateSecureMode` (Step 10) and `deactivateSecureMode` (Step 8), the `walCheckpoint(at:)` call now runs *after* `commitStagedLocalDBKey`. If the commit fails, the main SQLite file still contains contacts encrypted under the old canonical key (intact), and rollback leaves the system in a recoverable state. Only after a successful commit — when the staged key is irrevocably canonical — does the checkpoint flush staged-key writes to the main file.

---

## Bug 15 — Contact classification uses hardcoded depth 1, breaks under multi-depth Secure Mode

**Stale, 2026-09-11:** `activateSecureMode`'s Step 4 (classification into DB vs. blob) no longer
exists — activation/deactivation no longer classify or move contacts at all, per Removal Stages 0-4,
2026-09-10.

**Status:** Closed (Fixed)

### Severity: Medium
`activateSecureMode` Step 4 classified contacts into safe (stay in DB) vs. sensitive (go to blob) using `Self.isVisible(profile, atDepth: 1)`. This is correct for the current two-level system (depth 0 = real, depth 1 = duress), but fails if the depth model ever extends to levels 2, 3, etc.

A contact with `visibleThroughDepth = 1` (visible at depth 1, hidden at depth 2) would pass the `atDepth: 1` check and remain in the DB. At depth 2 it would be filtered from the UI — but it sits in the DB unprotected, not in the blob. The invariant "sensitive contacts live only in the blob" is broken.

The single-blob design requires that any contact hidden at *any* duress depth be removed from the DB. Per-depth blobs are not viable (multiple distinct `.occbak` files are a forensic tell).

### Root Cause
The depth was a magic number rather than "the maximum possible depth," so new depth levels silently introduced unclassified contacts.

### Resolution
Changed `atDepth: 1` to `atDepth: .max` in `activateSecureMode` Step 4 (`Manager+Security.swift`). `isVisible(atDepth: .max)` returns `true` only for `nil` and `Int.max` — both mean "always visible." Any contact with a finite `visibleThroughDepth` (0, 1, 2, …) is classified sensitive and goes to the blob. This is future-proof for any number of depth levels.

---

## Bug 16 — PIN toggle interactive in `.active` state allows gate-drop without deactivating Secure Mode

**Status:** Closed (Fixed)

### Severity: Medium
In `.active` state (Secure Mode running, gate up), the "Enable PIN" toggle was fully interactive. Tapping it routed to `disablePINFromCurrentDepth`, lowering the gate at depth 0. This violated the stated invariant: "Secure Mode must be deactivated before the PIN can be removed." The gate-drop at depth 0 also left the "Deactivate Protection" button visible in Settings while the toggle showed OFF — a forensic tell revealing Secure Mode was active (see Bug 17).

### Root Cause
The `else` branch in `SecuritySettings.showingPINSheet` handled both `.active` and `.duress` with the same `disablePINFromCurrentDepth` path. Coercion gate-drop at depth 1 (`.duress`) is a valid and intentional flow; gate-drop at depth 0 (`.active`) is not.

### Resolution
Added `.disabled(self.isSecureModeActive && self.security.state == .normal && self.security.appLockEnabled)` to the Toggle in `Settings.swift` (`Settings.SecuritySettings`). The sheet's `else` branch was tightened to `else if self.security.state == .duress`, making the coercion-only intent explicit and making the normal-state path unreachable. In `.duress`, the toggle remains interactive to preserve coercion-resistance.

Note: the state case was renamed `.active` → `.normal` in a later refactor; the guard above reflects the current name.

---

## Bug 17 — "Deactivate Protection" button shown when gate is lowered in `.active` state — forensic tell

**Status:** Closed (Fixed)

### Severity: High (forensic)
When `disablePINFromCurrentDepth` is called from `.active` state (depth 0), `state` remains `.active` and `appLockEnabled` becomes `false`. The Settings condition `if self.security.state == .active` still shows the "Deactivate Protection" button. A coercer or forensic tool browsing Settings sees this button despite the PIN toggle appearing off — directly revealing that Secure Mode is active.

Additionally, the "Learn more" Secure Mode section (which would normally appear in `.pinOnly` as a cover story) is hidden in `.active` state, so Settings in this configuration looks neither like `.active` nor `.pinOnly` — it looks anomalous.

Note: Bug 16's fix prevents the gate from being lowered from `.active` via the toggle, but `disablePINFromCurrentDepth` remains callable from `.active` programmatically (e.g. future UI flows), so this forensic issue remains latent.

### Root Cause
The "Deactivate Protection" condition (`if self.security.state == .active`) does not account for `appLockEnabled`. Gate-down `.active` was never an intended user-facing configuration.

### Resolution
Two guards updated in `Settings.SecuritySettings`:

**1. "Deactivate Protection" button** — condition tightened to require `appLockEnabled`:
```swift
if self.isSecureModeActive && self.security.state == .normal && self.security.appLockEnabled { ... }
```
The button is now invisible when the gate is down, matching the visual of a PIN-only setup.

**2. "Learn more" section** — condition already covers gate-down `.normal` via the `!self.security.appLockEnabled` term:
```swift
if !self.isSecureModeActive || self.security.state == .duress || !self.security.appLockEnabled { ... }
```
When `appLockEnabled` is `false` the section renders regardless of `state`, so gate-down `.normal` is visually indistinguishable from `.pinOnly`.

---

## Bug 18 — `onWipe` closure is empty — wipe threshold triggers no action

**Status:** Closed (Fixed)

### Severity: High
When `Manager.Security.verify()` returns `.wipe` (wrong PIN limit reached, or duress consecutive-entry threshold exceeded), `PINEntry` calls `onWipe()`. The lock-screen `PINEntry` in `OccultaApp` passes `onWipe: {}`. No data is erased. The user stays on the PIN screen and can continue guessing indefinitely, defeating the entire wipe-threshold feature.

### Root Cause
`onWipe` was left unimplemented as a placeholder.

### Resolution
`onWipe` was wired to call `security.wipeAllSecureState()` followed by `appManager.eraseAllData()`. Subsequently, the entire wipe model was removed by design decision: `PINVerifyResult.wipe`, `onWipe`, `wipeAllSecureState()`, and the wrong-PIN threshold are all gone. Bug 18 is superseded — the scenario it describes cannot occur.

---

## Bug 19 — Secure Mode deactivation has no loading overlay; sheet dismissed before async task completes

**Status:** Closed (Fixed)

### Severity: Medium
`SecuritySettings.showingDeactivateSheet` dismisses the PINEntry sheet synchronously (`self.showingDeactivateSheet = false`) before the `Task { try await deactivateSecureMode(...) }` begins. The user sees the normal Settings screen immediately while a multi-step key rotation (re-encrypt all contacts, WAL checkpoint, commit staged key) runs in the background with no visual indicator. Contrast with activation, which shows `ActivatingOverlay` for exactly this duration.

If the task fails mid-rotation, the rollback runs silently with no user feedback. The state does not transition, but the user has already seen the normal Settings screen and receives no indication of failure.

### Root Cause
The deactivation sheet was written without the async-blocking pattern that activation uses.

### Resolution
Implemented in `SecureModeDeactivateFlow`. The sheet now:
- Holds `@State private var isDeactivating = false` and sets it to `true` before dispatching the Task.
- Renders `DeactivatingOverlay` (full-screen black spinner with "Removing protection…") while `isDeactivating` is `true`.
- Calls `interactiveDismissDisabled(self.isDeactivating)` to prevent swipe-to-dismiss during rotation.
- Clears `isDeactivating` and calls `dismiss()` only after `deactivateSecureMode` returns successfully; sets `deactivationFailed = true` on error (see Bug 20).

---

## Bug 20 — Deactivation errors silently dropped in production builds

**Status:** Closed (Fixed)

### Severity: Medium
The `catch` block in the deactivation Task is gated on `#if DEBUG`. In a release build, any throw from `deactivateSecureMode` (SE failure, context save error, key rotation error) produces zero user feedback. Combined with Bug 19's premature sheet dismissal, the user has no way to know whether deactivation succeeded or failed.

### Root Cause
`#if DEBUG` gate left on error handling during development.

### Resolution
The catch block in `SecureModeDeactivateFlow` has no `#if DEBUG` guard. On any throw it sets `deactivationFailed = true`, which triggers an `.alert("Deactivation Failed")` with the message: "Protection could not be removed. Your data is unchanged. Please try again." The user receives explicit feedback in both debug and release builds.

---

## Bug 21 — Secure Mode activation errors silently dropped via `try?`

**Status:** Closed (Fixed)

### Severity: Medium
In `SecureModeSetupFlow.onActivate`, the call to `activateSecureMode` is wrapped in `try?`:
```swift
try? await self.security.activateSecureMode(...)
self.isActivating = false
self.dismiss()
```
If activation throws (`.pinCollision`, `.keyDerivationFailed`, SE failure, DB save error), the overlay clears and the sheet dismisses as if activation succeeded. The state remains `.pinOnly` but the user believes Secure Mode is active — all subsequent assumptions about the blob and contact classification are wrong.

### Root Cause
`try?` was used for simplicity during initial implementation; error propagation path was not wired up.

### Resolution
`try?` was replaced with a proper `do / catch` block in `SecureModeSetupFlow.SummaryView`. On throw, `activationFailed = true` triggers an `.alert("Activation Failed")` with the message: "Secure Mode could not be activated. Your data is unchanged. Please try again." `isActivating` is cleared and the sheet stays open for a retry.

---

## Bug 22 — Activate button remains tappable during activation; concurrent calls possible

**Status:** Closed (Fixed)

### Severity: Medium
After the user taps Activate in `SecureModeSetupFlow`, `isActivating` is set to `true` but the activate button has no `.disabled(self.isActivating)` modifier. A rapid double-tap (or any second tap before the overlay appears) dispatches a second concurrent call to `activateSecureMode`. The second call creates a new staged key while the first is mid-rotation, leaving two conflicting staged artefacts in the Keychain and SE. At best, the second call fails and rolls back, stranding the first call with a partially committed state. At worst, both calls progress past the rollback window, resulting in contacts encrypted under different keys.

### Root Cause
The button's disabled state was not wired to `isActivating`. The overlay (`ActivatingOverlay`) blocks further interaction visually, but it appears asynchronously after the Task is dispatched — not synchronously on tap.

### Resolution
`.disabled(self.isActivating)` added to the Activate button in `SecureModeSetupFlow.SummaryView`. A second tap is rejected at the view layer before any `Task` is created, making concurrent calls impossible from the UI.

---

## Bug 23 — Sensitive contacts lose their sensitivity flag after deactivation; must be re-marked on every activation cycle

**Stale, 2026-09-11:** `ContactBlobRecord` no longer exists — deleted whole by Removal Stages 0-4,
2026-09-10.

**Status:** Closed (Fixed)

### Severity: Medium
When `deactivateSecureMode` Step 5 restores sensitive contacts from the blob, it sets `restored.visibleThroughDepth = nil` (per Bug 12's watermark-erasure fix). This clears the `visibleThroughDepth = 0` that originally caused the contact to be classified as sensitive during activation. On any subsequent re-activation, those contacts have `visibleThroughDepth = nil` — `isVisible(atDepth: .max)` treats `nil` as always-visible, so they are classified as safe and remain in the DB unprotected. The user must manually re-mark every sensitive contact before each activation. In practice this is silent data-exposure: the user believes those contacts are protected but they are not blobbed.

### Root Cause
`ContactBlobRecord` does not preserve the contact's original `visibleThroughDepth` value. Deactivation has no source of truth for what the depth was at activation time, so it unconditionally writes `nil` rather than restoring to `0`.

### Resolution
`visibleThroughDepth: Int?` added to `ContactBlobRecord` in `SecureMode+Blob.swift`. At activation (Step 6 of `activateSecureMode`), the decoded depth value is read from `profile.visibleThroughDepth` and stored verbatim in the blob record. At deactivation (Step 5 of `deactivateSecureMode`), `record.visibleThroughDepth ?? 0` is re-encoded and written back to `restored.visibleThroughDepth`. The `?? 0` fallback applies to blobs written before this field was added — any contact present in the blob by definition had a finite depth, so `0` (sensitive) is the correct default.

---

## Bug 24 — "Activation Failed" alert reveals Secure Mode state in duress mode

**Status:** Closed (Fixed)

### Severity: High
In duress mode the "Learn more" section in Settings is intentionally shown to make the screen indistinguishable from `.pinOnly`. A coercer who navigates through the full `SecureModeSetupFlow` and taps "Activate" triggers `activateSecureMode`, which throws `SecurityError.invalidStateTransition` because a duress verifier already exists. The catch-all block sets `activationFailed = true`, surfacing an "Activation Failed" alert. This directly tells the coercer that activation was blocked — implying Secure Mode is already active and the current view is the decoy.

### Root Cause
The `catch` block in `SecureModeSetupFlow.SummaryView` does not distinguish `invalidStateTransition` from genuine errors. In this context `invalidStateTransition` is the expected outcome when the flow is traversed from duress state for tell-avoidance purposes, not an error.

### Resolution
Added a dedicated `catch Manager.SecurityError.invalidStateTransition` arm before the catch-all in `SummaryView`. This arm sets `isActivating = false` and calls `onDone()` — a silent dismiss indistinguishable from a successful activation from `.pinOnly`. The catch-all block retains `activationFailed = true` for genuine errors only.

---

## Bug 25 — `ContactClassification` exposes sensitive contacts during activation flow in duress mode

**Status:** Closed (Fixed)

### Severity: Critical
When in duress mode, a coercer who navigates through `SecureModeSetupFlow` reaches the contact classification step (step 3). `ContactClassification` fetches all contacts via `@Query(Contact.Profile.descriptor)` with no depth filter. `loadSensitiveIDs()` calls `security.isSensitive` for every contact, which reads `visibleThroughDepth` and correctly identifies contacts with `encrypt(0)` as sensitive. These are then rendered in the "Sensitive contacts" section of the classification UI. The coercer sees the full list of contacts the real user has chosen to hide, including their names and verification status. The `guard !self.security.isRestricted` in `save()` prevents reclassification but does nothing to prevent display.

### Root Cause
`ContactClassification` was designed for the initial activation flow from `.pinOnly` state, where all contacts are visible. It has no guard against being presented from a restricted (duress) depth. The display path does not pass through `isDisplayable` / `isRestricted`.

### Resolution
Added `guard !self.security.isRestricted else { return }` at the top of `loadSensitiveIDs()`. In duress mode `sensitiveIDs` stays empty, so all contacts appear in "Visible" and the "Sensitive" section shows "None marked sensitive" — consistent with tell-avoidance (the screen looks identical to a first-time setup with no contacts classified). Both save and load are now blocked in restricted mode.

### Phase 2 note
This fix is complete for Phase 1 (two layers). For Phase 2 multi-layer, two further changes are required:
1. `isSensitive` hardcodes `value == 0` — must become depth-relative (`value < currentDepth`) so contacts sensitive at intermediate depths are recognised correctly.
2. `ContactClassification` should only be editable at depth 0; at depth N > 0, the same `isRestricted` guard applies but the definition of "sensitive at this depth" changes.

---

## Bug 26 — Pre-existing vault entries visible in duress mode after activation

**Stale, 2026-09-11:** `activateSecureMode`'s Step 8 (the blob-sealing step this bug is about) no
longer exists — deleted whole by Removal Stages 0-4, 2026-09-10.

**Status:** Closed (Fixed)

### Severity: High
`activateSecureMode` Step 8 re-encrypts `VaultEntry.visibleThroughDepth` but only touches entries where the field is non-nil. Entries created before this branch (i.e. before `addEntry` started stamping `encrypt(0)`) have `visibleThroughDepth = nil`. Step 8 skips them silently. After activation, `isEntryVisible` returns `true` for `nil`:

```swift
func isEntryVisible(_ entry: VaultEntry) -> Bool {
    guard let data = entry.visibleThroughDepth else { return true }  // nil → always visible
    ...
}
```

`visibleEntries` in `Vault+Tab` only filters when `isRestricted`:

```swift
private var visibleEntries: [VaultEntry] {
    guard self.security.isRestricted else { return self.entries }
    return self.entries.filter { self.security.isEntryVisible($0) }
}
```

Because `isEntryVisible` returns `true` for nil-depth entries, those entries pass through the duress filter and appear in the vault tab when the duress PIN is entered. The EducationView and SummaryView both promise "Vault items will not be visible in alternate views" — that promise is broken for any entry created before this branch.

### Root Cause
Step 8 uses `if let old = entry.visibleThroughDepth` to guard the re-encryption. When `nil`, the entry is not given a hidden-depth stamp; it simply carries no field at all, which `isEntryVisible` interprets as "always visible."

### Resolution
In `activateSecureMode` Step 8, entries where `visibleThroughDepth == nil` should be stamped with the hidden sentinel under the staged key rather than skipped:

```swift
for entry in try vaultManager.fetchAllEntries() {
    if let old = entry.visibleThroughDepth {
        guard let plain = old.decrypt() else { continue }
        entry.visibleThroughDepth = try AES.GCM.seal(
            plain, using: stagedKey, authenticating: aad
        ).combined
    } else {
        // Pre-existing entry: hide at all duress depths.
        let hidden = try JSONEncoder().encode(0)
        entry.visibleThroughDepth = try AES.GCM.seal(
            hidden, using: stagedKey, authenticating: aad
        ).combined
    }
}
```

Additionally, `deactivateSecureMode` Step 6 already sets `entry.visibleThroughDepth = nil` unconditionally, which correctly erases the activation-era stamp on deactivation. No change needed there.

---

## Bug 27 — Silent skip in Step 8 when `old.decrypt()` fails; entry hidden by stale ciphertext

**Stale, 2026-09-11:** Same Step 8 as Bug 26 — no longer exists, deleted by Removal Stages 0-4,
2026-09-10.

**Status:** Closed (Fixed)

### Severity: Medium
In `activateSecureMode` Step 8, the inner guard `if let old = entry.visibleThroughDepth, let plain = old.decrypt()` silently skips an entry when `old.decrypt()` returns `nil`. This can happen if the ciphertext is corrupt or was encrypted under a different key. The entry's `visibleThroughDepth` is left as-is — still encrypted under the old canonical key, which is deleted at Step 9 (`commitStagedLocalDBKey`). After commit, `isEntryVisible` cannot decrypt the field and reaches:

```swift
else { return false }  // non-nil but can't decrypt → hidden
```

The entry becomes permanently hidden in both normal and duress mode — not deleted, not visible, just silently inaccessible from the vault UI. No error is thrown; the activation completes successfully from the user's perspective.

### Root Cause
The `if let` double-bind swallows the decrypt failure and falls through. The fix for Bug 26 (splitting the nil and non-nil branches) should also surface or handle the decrypt-failure case explicitly.

### Resolution
In the non-nil branch (see Bug 26 resolution), replace the guard-based silent skip with an explicit `continue` after logging or — for maximum safety — stamp the entry as hidden under the staged key regardless of whether the old plaintext is recoverable:

```swift
if let old = entry.visibleThroughDepth {
    // If we can decrypt the old value, re-encrypt it; otherwise treat as hidden.
    let plain = old.decrypt() ?? (try JSONEncoder().encode(0))
    entry.visibleThroughDepth = try AES.GCM.seal(
        plain, using: stagedKey, authenticating: aad
    ).combined
}
```

This ensures every entry ends up with a `visibleThroughDepth` encrypted under the staged key regardless of the prior field state.

---

## Bug 28 — Sensitive contacts visible as eligible trustees in shard backup setup while in duress mode

**Status:** Closed (Fixed)

### Severity: Critical
When in duress mode, the vault backup / shard distribution trustee picker shows sensitive contacts as eligible trustees. These contacts are hidden from the main contact list at duress depth, but the shard setup UI fetches eligible trustees through a code path that does not apply the same depth filter. A coercer who navigates to vault backup setup can enumerate the sensitive contacts by observing which contacts appear as selectable trustees — contacts that are invisible everywhere else in the duress view.

### Root Cause
The trustee eligibility query (in `Vault+ShardSetup` or its backing manager) does not pass through `isDisplayable` / the depth filter that `ContactsListV2` and related views apply in `isRestricted` mode.

### Resolution
Working as expected.

---

## Bug 30 — Quantum key material destroyed for sensitive contacts after Secure Mode deactivation

**Stale, 2026-09-11:** `hasUnreadableKeys` and the deactivation Step 5b blob-rebuild this fix's
second half targets no longer exist — deleted whole by Removal Stages 0-4, 2026-09-10.

**Status:** Closed (Fixed)

### Severity: High
After a full activate → deactivate cycle, any contact that was classified as sensitive loses its ML-KEM quantum key material. Subsequent attempts to decrypt a hybrid-PQ message from that contact throw `ContactManager.Errors.quantumKeyMaterialCorrupted` (error 13), making all such messages permanently undecryptable.

### Root Cause
Two compounding bugs:

**1. `convertToMutableCopy` never extracted `quantumKeyMaterialEncrypted` into the draft.**
`Contact+Manager.swift` built each `Contact.Draft.Key` from material, owner, and date only — it never read `quantumKeyMaterialEncrypted` from the stored key record. Every blob sealed at activation was therefore missing quantum material for all contacts that had it.

**2. `hasUnreadableKeys` in deactivation Step 5b was a Design B artefact that fired spuriously under Design A.**
The check was written for a Design B world where sensitive contacts' key records would be left under the deleted activation key, making them genuinely unreadable during deactivation. Under Design A (the actual implementation), activation Step 8's `reEncryptKeyRecords` migrates *all* contacts' key records — including sensitive contacts' — from K_old → K_staged. The check tested readability using `Manager.Crypto()` (K_activation, the current canonical key), but by the time Step 5b ran, those records had already been migrated to K_staged by Step 4. Decryption with K_activation failed on K_staged ciphertext, so `hasUnreadableKeys` evaluated to `true` for every sensitive contact — not because the records were under a deleted key but because they had already been successfully re-encrypted. The check then wiped and rebuilt all key records from the blob draft, discarding intact quantum material and replacing it with nil (from bug 1).

### Resolution
Two fixes applied together:

**1. `convertToMutableCopy` now carries quantum material through to the draft** (`Contact+Manager.swift`). For each key record, `quantumKeyMaterialEncrypted` is decrypted and JSON-decoded to `QuantumKeyMaterial?` and passed as the `quantumKeyMaterial` parameter when constructing `Contact.Draft.Key`. The blob now carries complete key material for both Design A (where it is currently unused but correct) and Design B (where it is the sole restoration source).

**2. `hasUnreadableKeys` rebuild removed from `deactivateSecureMode` Step 5b** (`Manager+Security.swift`). Under Design A, Step 4's `reEncryptKeyRecords` already migrates all key records correctly; Step 5b only needs to restore text fields and depth metadata from the blob. The rebuild path, along with its redundant second `reEncryptKeyRecords` call, was deleted. The Design B path in `plan.md` documents when and how to restore it correctly (item 3 of Design B requirements).

---

## Bug 31 — Classical-only fallback bundle undecryptable by receivers with sender's quantum material

**Status:** Closed (Fixed)

### Severity: High
When a shard-carrying message fails with `trusteeLacksQuantumMaterial` (contact's ML-KEM key material is nil or corrupt), the b226068 fallback re-sends the message classically. The receiver, however, may still have the **sender's** quantum material stored from a prior UWB exchange. v1.7.0's (and current version's) receive path unconditionally uses hybrid key derivation when the sender's quantum material is available — regardless of what the sender actually used. The sender's classical session key and the receiver's hybrid session key are different. AES-GCM authentication fails with CryptoKitError 3.

### Root Cause

Two compounding issues:

**1. b226068 fallback sends classical without signalling this to the receiver.**
The catch-all for `trusteeLacksQuantumMaterial` re-calls `encryptBundle(data:for:)` with no shards and no quantum material. The resulting bundle (`.longTermFallback` or `.forwardSecret`) is encrypted with `createSharedSecret` — pure classical ECDH. No field in the bundle's wire format encodes whether quantum was included in the session key derivation.

**2. The receive path always uses hybrid if the sender's quantum material is available.**
`decryptSealed` resolves the sender's stored quantum material and passes it to `deriveSessionKey(using:quantumMaterial:)`. If non-nil, this calls `createHybridSharedSecret`, which produces a different key than `createSharedSecret`. There is no fallback attempt with classical on decryption failure.

**Why adding a signal to `SecrecyContext` is blocked:**
`computeAdditionalAuthentication` encodes the entire `SecrecyContext` as JSON for the GCM AAD. Adding any new field changes the AAD. Old builds that don't know the field compute a different AAD and fail authentication — a wire-format-breaking change for all deployed versions.

### Why this wasn't triggered before b226068
Before that commit, `trusteeLacksQuantumMaterial` was an unhandled throw — the send failed visibly with an error. No bundle reached the receiver. b226068 made the failure silent by swallowing the error and sending a classical bundle, which the receiver cannot decrypt when it has the sender's quantum material.

### Root cause of nil quantum material on the send side
The contact's quantum material becomes nil after a Secure Mode activation → deactivation cycle that predates Bug 30's fix. Bug 30 fixed future deactivations but did not retroactively restore quantum material for contacts already damaged by prior deactivations. The send side thus permanently lacks the contact's quantum material until a fresh UWB key exchange is performed.

### User-facing workaround
Re-exchange keys with the contact via UWB proximity. This rebuilds the contact's quantum material on the send side. Subsequent messages will use hybrid key derivation, which both parties can decrypt correctly.

### Resolution
Add two new `Mode` cases to `OccultaBundle` so the receiver knows exactly which key derivation to use — no ambiguity, no retry.

**Wire format — four unambiguous modes:**

| Mode | Key source | Quantum |
|---|---|---|
| `forwardSecret` | ephemeral/prekey ECDH | yes — `createHybridFSSharedSecret` |
| `longTermFallback` | long-term identity ECDH | yes — `createHybridSharedSecret` |
| `forwardSecretNoPQ` | ephemeral/prekey ECDH | no — `createSharedSecret(ephemeralPrivateKey:recipientMaterial:)` |
| `longTermNoPQ` | long-term identity ECDH | no — `createSharedSecret(using:)` |

Old builds decode `forwardSecretNoPQ` / `longTermNoPQ` as `.unsupported` and throw `BundleError.unsupportedMode` — an explicit, actionable error rather than CryptoKitError 3. The AAD includes the mode string, so new sender + new receiver always agree on the same AAD.

**Send side (`Crypto+Manager+ForwardSecrecy.swift`):**
In `seal()`, select mode based on whether `quantumMaterial` is non-nil:
- prekey present + quantum → `forwardSecret`
- prekey present + no quantum → `forwardSecretNoPQ`

In `fallback()`, same logic:
- quantum present → `longTermFallback`
- no quantum → `longTermNoPQ`

**Receive side (`Contact+Manager.swift` — `decryptSealed`):**
Restructure quantum material resolution to be mode-conditional — only resolve (and only throw `quantumKeyMaterialCorrupted`) for the two hybrid modes. Add two new switch cases for the NoPQ modes that derive with `quantumMaterial: nil`.

**Send side — b226068 fallback (UI layer):**
The existing encryption scheme label already surfaces the PQ degradation to the user. No additional action needed there.

---

## Bug 29 — Vault items flicker (show → blank → show) after entering normal PIN with Secure Mode active

**Status:** Closed (Fixed)

### Severity: Low
With Secure Mode active, after entering the normal PIN the vault tab briefly shows vault items, then goes blank, then shows the items again. The flicker is reproducible and creates a jarring UX. In a coercion scenario it could also briefly expose vault item content before the blank frame, though the window is sub-second.

### Root Cause
Not yet fully diagnosed. Likely candidates:
1. The vault lock (`willResignActiveNotification` or the activation flow triggering a lock) fires after PIN entry resolves, setting `vault.isUnlocked = false` momentarily, then Face ID re-authenticates and sets it back to `true`. The `Vault+Tab` gate (`if self.security.isRestricted || self.vault.isUnlocked`) reacts to each state change, producing the visible → blank → visible sequence.
2. A `@Observable` batch-update race: `security.state` and `vault.isUnlocked` update on different ticks, causing an intermediate render where `isRestricted` is `false` (normal depth) but `isUnlocked` has transiently reset.

### Resolution
`security.state` was mutated synchronously inside `verify()`, 500 ms before `isLocked = false` fires (due to `gateDuration`). SwiftUI defers re-renders of views behind a `fullScreenCover`; when the cover began its dismiss animation the vault tab was composited from its last committed CALayer content — the stale duress-mode list. The state mutation and the cover dismissal needed to land in the same SwiftUI render pass.

Two changes applied together:

**`Manager+Security.swift`** — `self.state = .normal` and `self.state = .duress` removed from `verify()`. A new `applyVerifyState(for:)` method added immediately after `verify()` that applies only the state transition.

**`PINEntry.swift`** — `submitVerify`'s `asyncAfter` callback now calls `security.applyVerifyState(for: result)` before `route(result, pin:)`. Both mutations (`state` and `isLocked = false` via `onNormal`) now occur in the same synchronous main-thread task; SwiftUI batches them into one render pass and the vault tab renders `lockGate` correctly on first reveal.

---

## Bug 32 — Back button visible through the "Securing your data…" activation overlay

**Status:** Closed (Fixed)

### Severity: Low
While Secure Mode activation is in progress, `ActivatingOverlay` is applied as a SwiftUI `.overlay` on `SummaryView`. SwiftUI overlays cover the view's content area but not the navigation bar. The `NavigationStack` back button remains visible and tappable in the navigation bar above the overlay, allowing the user to navigate back mid-rotation — potentially interrupting a critical key rotation step.

### Root Cause
`ActivatingOverlay` is a content overlay, not a full-screen modal. The navigation bar sits outside the overlay's layout rect and is unaffected by it.

### Resolution
Working as expected.

---

## Bug 33 — Contacts briefly flash on screen during app load when PIN is active

**Status:** Closed (Fixed)

### Severity: High
When the app launches with a PIN configured, the contacts list is rendered and visible for a brief moment before the `fullScreenCover` PIN gate appears. During this window, contact names and fingerprints are readable on screen. Reproducible on every cold launch; also visible in the app switcher thumbnail taken just before the cover appears.

### Root Cause
`isLocked` is initialised to `true` synchronously in `OccultaApp.init`, but `fullScreenCover` is a UIKit modal presentation — it cannot appear until after the first SwiftUI render pass completes. The contacts tab renders fully in that first pass, producing a frame of visible contact data before the cover dismisses it.

### Resolution
Place an opaque `Color(.systemBackground)` overlay (not a `ZStack` layer, to avoid re-introducing Bug 1) that renders in the same SwiftUI pass as the contacts list. The overlay fades out with a short `easeInOut` delay after PIN entry so contacts reveal smoothly rather than snapping into view.

---

## Bug 34 — White screen animation on every background/foreground cycle within grace period

**Status:** Closed (Fixed)

### Severity: Medium
Every time the app is backgrounded and returned to foreground within the 5-minute grace period, the user sees a blank white screen slide up and then immediately slide back down. This is jarring UX and leaks the fact that a PIN is configured — a no-PIN device would show nothing.

### Root Cause
The `.background` phase handler unconditionally sets `isLocked = true`, which triggers the `fullScreenCover`. Within grace period, the cover shows a blank `Color(.systemBackground)` rather than the PIN entry. The `.active` phase handler then immediately clears `isLocked = false` via the grace period check. The full UIKit modal present/dismiss cycle runs on every background/foreground switch, regardless of whether a PIN will actually be demanded.

### Resolution
Working as expected.

---

## Bug 35 — Pending bundle not processed after grace period auto-unlock

**Status:** Closed (Fixed)

### Severity: High
When a bundle notification is tapped while the app is backgrounded and locked, `onOpenURL` fires and hits the gate at line 307 (`if self.isLocked && self.security.requiresPIN`), storing the raw bytes in `pendingFileData` rather than processing them. If the app is within grace period, `.active` then sets `isLocked = false` — but the grace period unlock path never calls `processInboundFile`. `pendingFileData` is only consumed inside `onNormal` (the PIN entry success callback), which is never triggered by an auto-unlock. The bundle is silently discarded; the user sees only the white screen animation from Bug 34.

### Root Cause
The grace period unlock in the `.active` handler is a direct `isLocked = false` assignment — it has no awareness of `pendingFileData` and does not mirror the `onNormal` path that processes it.

### Resolution
Working as expected.

---

## Bug 37 — Re-enable PIN flow silently fails in duress-gate-lowered state when a non-matching PIN is entered

**Status:** Closed (Fixed)

### Severity: Low (forensic / deniability)
When the real user lowers the PIN gate under coercion via `disablePINFromCurrentDepth` and hands the phone over, the "Enable PIN" toggle is OFF. A coercer who taps the toggle to re-enable it enters the `PINEntry(.setup)` flow and is prompted to enter + confirm a PIN. If they enter any PIN that does not match an existing verifier, `reEnablePIN` returns `false`, the sheet closes, and nothing changes — the toggle stays OFF, the gate stays lowered.

In genuine `.noPIN` state, the same flow calls `configurePIN`, which accepts any PIN and successfully raises the gate. The asymmetry is observable: the coercer entered a PIN twice, the sheet closed normally, but the toggle did not flip ON. In `.noPIN` it always would have. A sophisticated coercer who notices this deduces that existing verifiers are present — i.e. a PIN was already configured before the phone was handed over.

The attack requires a coercer who: (a) receives the phone with the gate already lowered, (b) decides to try setting their own PIN rather than re-entering the user's demonstrated PIN, and (c) observes that the toggle did not come back on. This is a non-trivial coercion behaviour; the practical risk is low.

### Root Cause
The Settings sheet branch selection (`!security.appLockEnabled`) routes to `reEnablePIN`, which only succeeds on an existing verifier match. The `!requiresPIN` branch routes to `configurePIN`, which accepts any PIN unconditionally. Both present `PINEntry(.setup)` — identical UX — but one succeeds on any input and the other silently fails on a non-matching input. The sheet closes after both regardless of success or failure:

```swift
PINEntry(mode: .setup, onNormal: { pin in
    _ = self.security.reEnablePIN(pin)   // return value discarded
    self.showingPINSheet = false          // closes even on failure
})
```

### Resolution
`reEnablePIN(_:)` in `Manager+Security.swift` has two branches:

**Depth > 0 — coercion-acceptance path (the primary fix):** When the entered PIN matches no existing verifier, the coercion-acceptance path fires. It writes `sealedDuressVerifiers[currentDepth]` and `sealedNormalVerifiers[currentDepth + 1]` for the coercer's PIN, records `coercerBaseDepth = currentDepth + 1` in `AppLayerConfig`, saves, and transitions to depth N+1 `.normal` state. The toggle flips ON and the gate re-enables — the coercer's experience is indistinguishable from a real PIN re-enable.

**Depth 0 — accepted tell:** At depth 0, `reEnablePIN` still fails silently if no verifier matches (the toggle does not flip on). This is accepted as a lower-priority concern: the depth-0 gate-lowering scenario is a different threat model, and fixing it would require the same blob re-sealing machinery without the coercion-acceptance framing that makes depth > 0 viable. Documented as a known limitation.

---

## Bug 36 — Contacts briefly visible when returning to app after grace period expires

**Status:** Closed (Fixed)

### Severity: High
When the user returns to the app after the grace period has expired, `handleActive()` sets `isLocked = true`. The Bug 33 overlay (`Color(.systemBackground)` driven by `isLocked`) is supposed to immediately cover the contacts, but it doesn't — it fades in with the same `.easeInOut(duration: 0.25).delay(0.15)` animation that was added for the unlock reveal. The 0.15s delay plus a portion of the 0.25s fade means contacts are visible for ~0.3s before the overlay fully covers them. The `fullScreenCover` then appears on top once UIKit catches up.

### Root Cause
The overlay's `.animation(.easeInOut(duration: 0.25).delay(0.15), value: self.isLocked)` modifier fires in **both** directions — `false → true` (lock) and `true → false` (unlock). The delay was intentional for the unlock direction (smooth reveal after PIN entry), but it makes the lock direction slow, leaving a window where contacts are readable. `.animation(_:value:)` is a view-level modifier that overrides the transaction animation — `withAnimation(.none)` at the call site does not suppress it.

### Resolution
The overlay was changed to use `.animation(.none, value: self.security.isContentHidden)` — always instant in both directions. The lock direction is now immediate (Bug 36 fix); the unlock direction is also instant, which is acceptable. The `isUnlocking` directional approach was unnecessary.

---

## Bug 38 — `AppGroupLayerStoreBackend.write()` deletes old file before writing new one

**Status:** Closed (Fixed)

### Severity: Medium
The original write sequence was: (1) delete old `.occbak`, (2) write new `.occbak`. A crash or process kill between these two steps leaves the `blobs/` directory empty — no layer store file exists. On next launch `maintain()` recreates it, but the window where the file is absent is a forensic tell: a crash-report timestamp correlatable with "something was being written to the layer store" is visible to anyone who examines the filesystem. This violates Invariant I6 (the app group always contains a layer store file).

### Root Cause
Defensive ordering: the old file was deleted first to avoid having two `.occbak` files present simultaneously. The atomic-write requirement was not considered.

### Resolution
Write-new-first, delete-old-after: capture the old file URL before the write, write the new file, apply resource attributes, then delete the old file. A crash during write leaves the old file intact (I6 preserved). A crash between write and delete leaves two files; `findFile` returns the newer one by modification date (correct). Implemented in `SecureMode+LayerStoreBackend.swift`.

---

## Bug 39 — `maintainLayerStore()` blocks the main thread on launch

**Stale, 2026-09-11:** `Manager.LayerStore` no longer exists — deleted whole by Removal Stages 0-4,
2026-09-10.

**Status:** Closed (Fixed)

### Severity: Low
`maintainLayerStore()` is called synchronously from `OccultaApp.init()` on the main thread. Internally it calls `Manager.LayerStore.maintain()`, which performs Secure Enclave key derivation (`Manager.Key().deriveSecureModeKey()`) and file I/O. On first install the SE key is created here; on any launch where the no-op file is stale (>24 h), the old file is deleted and a new one written. Both operations block the main thread — SE access can take tens of milliseconds on first use, delaying app launch.

`rewriteLayerStore()` already dispatched to `DispatchQueue.global(qos: .utility)`. The two call sites were inconsistent.

### Root Cause
`maintainLayerStore()` was not given a background dispatch when the no-op blob maintenance was first implemented.

### Resolution
Added `DispatchQueue.global(qos: .background).async { }` wrapper inside `maintainLayerStore()`, matching `rewriteLayerStore()`. The `isSecureModeActive` guard check remains on the calling thread (main) before dispatch so no model-context access crosses threads. Implemented in `Manager+Security.swift`.

---

## Bug 41 — Grace period skipped in duress mode — behavioral tell

**Status:** Closed (Fixed)

### Severity: High

In duress mode, backgrounding the app via the app switcher raises the PIN gate immediately. In normal mode the 5-minute grace period holds. The different behavior is observable and reveals that duress mode is active.

### Root Cause

`isWithinGracePeriod` had an unconditional `guard !self.isRestricted` that short-circuited to `false` whenever `currentDepth > 0`, bypassing the grace period check entirely. `handleBackground()` then always set `needsPINEntry = true` in duress mode. The guard was apparently added to force re-lock in duress mode, but it produced a tell.

The `activateSecureMode` flow already sets `lastUnlockDate = nil` to force re-lock on activation — the `isRestricted` guard was redundant for that purpose and incorrect for the duress PIN entry path.

### Resolution

Removed `!self.isRestricted,` from the `isWithinGracePeriod` guard in `Manager+Security.swift`. Grace period now applies uniformly at any depth. The `lastUnlockDate = nil` in `activateSecureMode` continues to handle the post-activation re-lock case correctly.

---

## Bug 40 — Identity challenge packets from hidden contacts are processed in duress mode

**Status:** Closed (Fixed)

### Severity: Low
In `OccultaApp.buildOwnedBasket`, identity challenge packets are routed to `identityChallenge.handleInboundChallenge` and return `nil` before reaching check point A (the depth filter that suppresses messages from hidden contacts). If a hidden sensitive contact sends an identity challenge while the app is unlocked at duress depth, the challenge is processed: `contactManager.fetchContact(by: ownerID)` succeeds (hidden contacts are in the DB, only filtered at the UI layer), and the handler may produce visible state (e.g. an approval sheet).

The same gap exists for shard operations, which the plan notes as out of scope.

### Root Cause
`buildOwnedBasket` short-circuits on identity challenge packets before the depth check. Check point A only runs on the returned `OwnedBasket`, which is `nil` for challenges.

### Resolution
Added `passSecurityControl(identifier:)` — a throwing depth gate called inside `buildOwnedBasket` for every bundle format before any processing occurs:

- **`.v3fs`**: called immediately after `decryptSealed`, before the identity-challenge branch and before basket assembly. Blocks both challenges and regular messages from hidden contacts.
- **Legacy `default`** (nil/v1/v2): called after `decrypt` resolves the `ownerID`, before `JSONDecoder().decode(Basket.self, ...)`.

When `isRestricted && !isSafeContact(identifier)` the gate throws `ContactManager.Errors.noPublicKeyToEncryptWith`, which surfaces as the same generic decryption-failure message already shown for unrelated key errors — not a unique tell that a contact is being depth-filtered.

Check point A was removed from `processInboundFile` because the gate now fires inside `buildOwnedBasket` for all paths that can produce an `OwnedBasket`; the post-basket check is fully superseded.

---

## Bug 49 — Prekey consumed before depth gate fires; bundle from sensitive contact becomes permanently undecryptable

**Status:** Closed (Fixed)

### Severity: High

Opening a bundle from a sensitive contact while in duress mode consumes the prekey and then throws a depth-gate error. The bundle cannot be opened again in normal mode because the prekey is gone.

### Reproduction

1. Activate Secure Mode. Mark a contact as sensitive.
2. That contact sends a forward-secret message (`.v3fs`, `.forwardSecret` mode).
3. Enter the duress PIN. Open the `.occ` file.
4. The app shows the correct "not addressed to you" error (depth gate blocked it). ✓
5. Enter the normal PIN. Try to open the same `.occ` file again.
6. Decryption fails — the prekey was consumed in step 3 and is gone.

### Root Cause

Bug 40's resolution placed `passSecurityControl` immediately *after* `decryptSealed`:

```swift
let (sealed, ownerID) = try self.contactManager.decryptSealed(bundle: bundle)
try self.passSecurityControl(identifier: ownerID)
```

`decryptSealed` consumes the prekey on successful decryption — before `passSecurityControl` has had any chance to throw. The prekey is gone regardless of what the depth gate decides. The gate is then enforced correctly (the error is shown), but it arrives too late: the cryptographic state has already been mutated.

### Resolution

`ContactManager` gains a new private `identifyOwner(for:)` helper and a public `identifyOwner(of:)` wrapper. Both are fingerprint-only lookups — they iterate stored contact key records, compute `SHA-256(contactPublicKey ∥ fingerprintNonce)`, and return the matching contact identifier. No prekey is touched.

`buildOwnedBasket` now calls `identifyOwner(of:)` **before** `decryptSealed`, passes the result to `passSecurityControl`, and only reaches `decryptSealed` when the gate passes:

```swift
if let ownerID = try self.contactManager.identifyOwner(of: bundle) {
    try self.passSecurityControl(identifier: ownerID)
}
let (sealed, ownerID) = try self.contactManager.decryptSealed(bundle: bundle)
```

The depth gate now fires before any prekey is consumed. If a sensitive contact's bundle is rejected in duress mode, the prekey remains intact and the bundle is fully openable in normal mode.

Three regression tests added to `DuressModePrekeyTests.swift`:
- `identifyOwner_isPrekeySafe_noMatch` — prekey count unchanged after identification with no contact match.
- `identifyOwner_isPrekeySafe_withMatchingContact` — same, when the contact IS fingerprint-matched (device only).
- `isSafeContact_sensitiveContact_blockedInDuress` — depth gate fires correctly for sensitive contacts.

---

## Bug 42 — Duress PIN rejected during Secure Mode activation

**Status:** Closed (Fixed)

### Severity: High

Two distinct failure modes both result in the duress PIN being rejected when the user enters it during the `SecureModeSetupFlow` activation sequence. In both cases the user sees a shake animation with no explanation.

---

#### Failure Mode A — UX confusion at depth 0 (first activation)

**Scenario:** Secure Mode has never been activated. The user opens Settings → Security → "Learn more" and navigates to the `PINEntry(.confirmThenSet)` step.

`confirmThenSet` has two phases:
- **Phase 1** — verify identity: expects the user's CURRENT normal PIN (calls `checkCurrentLayerPIN`, which checks `sealedNormalVerifiers[0]` with `normalLabel`).
- **Phase 2** — set new PIN: the user enters and confirms the new duress PIN; this becomes the `duressPIN` argument to `activateSecureMode`.

The phase-1 title is `"Passcode"` — identical to every other PIN prompt in the app. There is no indication that this entry expects the *existing* normal PIN, not the new duress PIN being created. A user who enters their intended duress PIN in phase 1 receives a shake rejection with no feedback about which PIN was expected.

**Root Cause:** `PINEntry.title` for `.confirmThenSet` when `confirmedPIN == nil` returns `"Passcode"`, indistinguishable from the lock-screen entry prompt. No guidance text or sub-label distinguishes "confirm your identity" from "enter a new PIN."

**Resolution:** Changed the `.confirmThenSet` phase-1 case in `PINEntry.title` from `"Passcode"` to `"Current Passcode"`. Phase 2 already uses `"New Passcode"` / `"Confirm Passcode"`, which are unambiguous.

---

#### Failure Mode B — `checkCurrentLayerPIN` fails for pre-routing-alias configs at depth 1

**Scenario:** Secure Mode is active and the user enters their duress PIN at the lock screen. If the routing alias was not written at `sealedNormalVerifiers[1]` (e.g. the config was created before routing aliases were introduced, or the array was migrated from scalar fields), `verify()` cannot match the duress PIN via Step 1 (normal verifier scan). It falls through to Step 2, matching `sealedDuressVerifiers[0]` with `duressLabel`, and returns `.duress`. State becomes `(.duress, currentDepth = 1)`.

The user then opens "Learn more" → `SecureModeSetupFlow` → `PINEntry(.confirmThenSet)`. Phase 1 calls `checkCurrentLayerPIN(duressPIN)`:

```swift
func checkCurrentLayerPIN(_ pin: String) -> Bool {
    ...
    return PINManager.checkVerifier(pin: pin, label: Self.normalLabel,
                                    verifier: config.sealedNormalVerifiers[self.currentDepth],
                                    seKey: seKey)
}
```

`sealedNormalVerifiers[1]` is random filler (routing alias was never written) → `checkVerifier` returns `false` → the correct duress PIN is rejected.

The migration in `Manager.Security.init()` populates `sealedNormalVerifiers[0]` from the scalar `sealedNormalVerifier` and `sealedDuressVerifiers[0]` from `sealedDuressVerifier`, but cannot reconstruct the routing alias at index 1 because it requires the plaintext duress PIN.

**Root Cause:** `checkCurrentLayerPIN` unconditionally checks `sealedNormalVerifiers[currentDepth]` with `normalLabel`. This is correct only when the routing alias exists. When it is absent, the method has no fallback to check `sealedDuressVerifiers[currentDepth - 1]` with `duressLabel`, even though that verifier holds the correct answer.

**Resolution:** `checkCurrentLayerPIN` in `Manager+Security.swift` now tries `sealedNormalVerifiers[depth]` (routing alias, `normalLabel`) first. If that check fails and `depth > 0`, it falls back to `sealedDuressVerifiers[depth - 1]` with `duressLabel`. The fallback is safe: `duressLabel ≠ normalLabel`, so a normal PIN cannot satisfy the duress check. Existing configs with a valid routing alias are unaffected — the fallback only fires on a genuine routing-alias miss.

---

## Bug 43 — LayerStore `rewrite()` in `deactivateSecureMode` runs synchronously on calling thread; `LayerStore.Error` codes were unstable

**Stale, 2026-09-11:** `Manager.LayerStore` and its `Error` type no longer exist — deleted whole by
Removal Stages 0-4, 2026-09-10.

**Status:** Closed (Fixed)

### Severity: Low

**Part A — Synchronous rewrite:** `deactivateSecureMode` called `self.layerStore.rewrite()` synchronously at line 750, blocking the calling actor (typically the main thread) with SE key derivation and ~1 MB of file I/O. This was inconsistent with `maintainLayerStore()` and `rewriteLayerStore()`, which both dispatch to background queues (see Bug 39). Under memory pressure, the synchronous file write on the main thread could fail, leaving the system in a state where re-activation would fail on the very next attempt.

**Part B — Unstable error codes:** `Manager.LayerStore.Error` did not conform to `CustomNSError`. Swift's default NSError bridging produces implementation-defined codes (sometimes 0-indexed, sometimes 1-indexed depending on runtime version). A user reported `Occulta.Manager.LayerStore.Error error 2` during re-activation after deactivation — the ambiguous code made it impossible to determine from logs alone whether the error was `encryptionFailed` (code 1, thrown from `push()`) or `decryptionFailed` (code 2, not throwable from `push()`).

### Root Cause

Part A: The `rewrite()` call was written without the background-dispatch wrapper that the other layer store maintenance calls use.

Part B: No `CustomNSError` conformance — NSError bridging was left to the Swift runtime default.

### Resolution

**Part A:** `self.layerStore.rewrite()` in `deactivateSecureMode` now dispatches to `DispatchQueue.global(qos: .utility)` (matching `rewriteLayerStore()`). The file I/O no longer blocks the calling thread.

**Part B:** `Manager.LayerStore.Error` now conforms to `CustomNSError` with explicit, stable codes: `notFound`=0, `encryptionFailed`=1, `decryptionFailed`=2, `sequenceNumberMismatch`=3, `slotIndexMismatch`=4, `payloadTooLarge`=5. The `errorDomain` is pinned to `"Occulta.Manager.LayerStore.Error"`.

The activation error handler's `debugPrint` was also updated from `error.localizedDescription` to `"[\(type(of: error))]: \(error)"` so the Swift type name is always visible alongside the description, regardless of NSError bridging.

---

## Bug 44 — `payloadTooLarge` when sensitive contact has a photo; images included in blob unnecessarily

**Stale, 2026-09-11:** `LayerContact` and the blob payload machinery no longer exist — deleted whole
by Removal Stages 0-4, 2026-09-10.

**Status:** Closed (Fixed)

### Severity: High

Activation fails with `payloadTooLarge(contacts: 1, encodedBytes: 294562, limit: 32768)` when a sensitive contact has a full-resolution profile photo. The JSON-encoded `LayerContact` for a single contact with a ~220 KB photo exceeds the 32 KB slot limit by nearly 9×.

### Root Cause

`LayerContact.draft` carried the full `Contact.Draft` including `imageData` and `thumbnailImageData`. These fields are raw binary data (JPEG/PNG), which expands further when JSON-base64-encoded. A moderately sized contact photo is enough to exceed the slot.

Image data does not need to be in the blob for correctness. Sensitive contacts are never hard-deleted from the DB (Bug 13). Their image fields remain in the DB and are re-encrypted from K_old → K_staged in activation Step 8 and again from K_activation → K_staged in deactivation Step 4. By the time deactivation Step 5 runs, the DB already holds the correct image ciphertext under K_staged.

A secondary issue: the `save(contact:using:)` UPDATE path unconditionally set `existing.imageData = encryptedImageData`. When the blob draft had nil images (after this fix), that write would have cleared the re-encrypted image data from Step 4.

### Resolution

Three changes applied together:

**1. Strip images from blob draft** (`Manager+Security.swift`, activation Step 6): After `convertToMutableCopy`, create a `var blobDraft = draft` with `imageData = nil` and `thumbnailImageData = nil` before building `LayerContact`. Images stay in the DB, correctly re-encrypted in Steps 8 and 4.

**2. Preserve existing image data in `save(contact:using:)` UPDATE path** (`Contact+Manager.swift`): Changed `existing.imageData = encryptedImageData` and `existing.thumbnailImageData = encryptedThumbnailImageData` to guard on non-nil (`if let encryptedImageData { ... }`). This path is only called from deactivation Step 5 (key-rotation restore); the regular `save(contact:currentDepth:)` path is unchanged.

**3. Remove images from `estimatedSize(for:)`** (`SecureMode+LayerStore.swift`): The capacity indicator excluded images from its estimate since the blob no longer carries them.

---

## Bug 45 — "Deactivate Protection" visible in Settings at duress depth via routing alias — forensic tell

**Status:** Closed (Fixed)

### Severity: Critical (forensic)

When the duress PIN is entered and matched via the routing alias (`sealedNormalVerifiers[K]` for K > 0), Settings shows **both** "Deactivate Protection" and "Learn more" simultaneously. A coercer browsing Settings sees the deactivation button, directly confirming that Secure Mode is active.

The bug is not limited to depth 1. With N duress layers, every depth from 1 through N-1 is affected.

### Threat scenario

The entire forensic value of the "Learn more" cover in Settings is that it looks identical to a device that has never activated Secure Mode. Showing "Deactivate Protection" alongside it collapses the deniability completely — it is a literal label that says "Secure Mode is on."

### Root Cause

The "Deactivate Protection" condition was:
```swift
isSecureModeActive && security.state == .normal && security.appLockEnabled
```

Before the multi-layer routing-alias mechanism, entering the duress PIN always produced `state = .duress`, so this condition was reliably false in duress state. With routing aliases, `verify()` matches `sealedNormalVerifiers[K]` for any depth K and returns `.normal(depth: K)`. `applyVerifyState` then sets `state = .normal` and `currentDepth = K`. Because `state` is `.normal` at every depth reachable via routing alias — including all duress depths 1, 2, 3 ... N-1 — the condition evaluates to `true` for all of them.

The depth-0 guard was already present in the PIN toggle's `.disabled` modifier but was never applied to the Deactivate button.

### Why `currentDepth == 0` is the correct predicate for any number of layers

`currentDepth == 0` identifies the real app layer exactly, regardless of how many duress layers are stacked above it:

| Depth | Layer                        | Show Deactivate? | Reason                                                           |
|-------|------------------------------|------------------|------------------------------------------------------------------|
| 0     | Real app (master PIN)        | YES              | Real user. Deactivation terminates the depth-0→1 binding.       |
| 1     | First duress view            | NO               | Coercer is here. Button is a tell.                               |
| 2     | Expendable layer             | NO               | Coercer is here. Button is a tell.                               |
| N     | Any further expendable layer | NO               | Same — coercer could be at any depth above 0.                   |

The real user always reaches depth 0 by entering their master PIN. That is the only entry point from which deactivation is appropriate. Deactivation from depth > 0 is technically supported by `deactivateSecureMode` (it strips the outermost layer and returns to depth 1), but exposing that path in the UI would require showing a tell at every duress depth. The correct design is: deactivate only from depth 0, using the master PIN.

The `state` field is no longer a reliable proxy for "real app" now that routing aliases can produce `.normal` at any depth. `currentDepth` is the authoritative signal.

### Resolution

`Settings.swift` — "Deactivate Protection" condition updated from:
```swift
isSecureModeActive && security.state == .normal && security.appLockEnabled
```
to:
```swift
isSecureModeActive && security.state == .normal
    && security.currentDepth == 0 && security.appLockEnabled
```

At depth 1, 2, ... N, the button is suppressed regardless of `state`. At depth 0, behavior is unchanged. The PIN toggle's `.disabled` modifier already had `currentDepth == 0`; the deactivate button now matches it exactly.

---

## Bug 46 — `excludedSlots` only protects the real-layer blob; depth-1 (convincing duress) blob can be overwritten at depth ≥ 2 activation

**Status:** Closed (Fixed)

### Severity: High

When activating a third (or deeper) layer at depth ≥ 2, `randomSlot()` could select the same file slot that holds the depth-1 blob. `push()` would then overwrite that slot with the new payload, destroying the depth-1 layer's contact data. The next deactivation at depth ≥ 2 reads `blobDepth = depth - 1`, which resolves to the depth-1 slot. `pop()` decrypts it and finds a sequenceNumber mismatch (the depth-2 payload is there instead of the depth-1 payload), falls back to empty contacts, and the convincing duress view loses all its contacts.

### Two layers that must never be overwritten

The design has two permanently protected layers:

| Blob depth | Layer | Why permanent |
|---|---|---|
| 0 | Real layer (depth-0 activation) | Contains the user's real sensitive contacts |
| 1 | First duress layer (depth-1 activation) | The "convincing" decoy — must remain intact for deniability |

Blobs at depth 2+ are expendable fake data. Overwriting them is acceptable — the coercer sees the convincing depth-1 view either way, and the deactivation cascade at those depths falls back gracefully to empty contacts without data loss that matters.

### Root Cause

`excludedSlots` was built from only the depth-0 blob slot:
```swift
Set([config.readBlobSlot(at: 0)].compactMap { $0 })
```
The depth-1 blob slot was never added to the exclusion set, so at depth ≥ 2 activations the random slot picker could legitimately choose it.

The fix is narrower than excluding all prior blobs (`0..<depth`): only depths 0 and 1 need permanent protection. `min(depth, 2)` gives `[0]` at depth 1 (depth-1 blob doesn't exist yet) and `[0, 1]` at depth ≥ 2 (both permanent layers protected), leaving expendable blobs at depth 2+ freely selectable.

### Resolution

`Manager+Security.swift` — `excludedSlots` changed from:
```swift
Set([config.readBlobSlot(at: 0)].compactMap { $0 })
```
to:
```swift
Set((0..<min(depth, 2)).compactMap { config.readBlobSlot(at: $0) })
```

---

## Bug 47 — "Deactivate Protection" button invisible after coercer activates Secure Mode from their depth

**Status:** Closed (Fixed)

### Severity: Medium (forensic)

When a coercer re-enables the PIN at gate-lowered depth N (Bug 37 scenario) and the system routes them to depth N+1, the coercer can navigate to Settings → "Learn more" and activate Secure Mode, successfully creating a duress layer at depth N+2. However, after activation the "Deactivate Protection" button never appears. A normal user at depth 0 who activates Secure Mode sees the button immediately. The coercer, testing whether the app behaves normally, sees the screen look different from what they expect — directly revealing that the device was not in a pristine state when they received it.

### Root Cause

The "Deactivate Protection" condition in `Settings.swift`:
```swift
isSecureModeActive && state == .normal && currentDepth == 0 && appLockEnabled
```
`currentDepth == 0` is false at depth N+1, so the button is unconditionally hidden at any depth above 0, even if the user at that depth has their own active Secure Mode layer. The guard was introduced by Bug 45 to prevent the button appearing at duress depths, but it is now too broad: it blocks the button for the coercer who legitimately activated a new layer from their depth.

### Resolution

`coercerBaseDepth: Data?` field added to `AppLayerConfig` — an encrypted `Int` with `readCoercerBaseDepth()` / `writeCoercerBaseDepth(_:)` accessors. Written unconditionally at row creation (value 0) so its presence is always forensically opaque. A computed property `coercerBaseDepth: Int` on `Manager.Security` reads from config.

`reEnablePIN`'s coercion-acceptance path (Bug 37 fix) writes `coercerBaseDepth = currentDepth + 1` when it creates a new layer for the coercer's PIN. This value survives app kills, restored in `Manager.Security.init()`.

"Deactivate Protection" condition in `Settings.swift`:

```swift
isSecureModeActive && state == .normal
    && (currentDepth == 0 || currentDepth == coercerBaseDepth) && pinEnabled
```

The OR rather than a plain `== coercerBaseDepth` is necessary: once `coercerBaseDepth = N+1 > 0`, the real user at depth 0 would otherwise lose the button. The OR collapses to `currentDepth == 0` for installs that have never gone through a coercion re-enable (`coercerBaseDepth == 0`), preserving existing behaviour exactly.

At depth 0 (real user): `0 == 0` — button visible. ✓
At depth N+1 (coercer, `coercerBaseDepth = N+1`): `N+1 == N+1` — button visible after coercer activates their own layer. ✓
At depth N (adversary, `coercerBaseDepth = 0`): `N ≠ 0` and `N ≠ 0` — button hidden. ✓

---

## Bug 50 — Real layer exposed after disable-PIN in duress mode + kill/relaunch

**Status:** Closed (Fixed)

### Severity: High

After entering the app with the duress PIN (`currentDepth = 1`), disabling the PIN toggle (`disablePINFromCurrentDepth`), killing the app, and relaunching, the real layer is shown — all contacts visible, no depth-1 filtering.

### Root Cause

`currentDepth` is an in-memory `Int` that defaults to `0` on every cold start. It is set correctly during a live session by `applyVerifyState` (after PIN entry routes to the correct depth), but it was never persisted to `AppLayerConfig`.

This is safe when `appLockEnabled = true`: the PIN gate fires on launch, the user enters their PIN, `verify()` scans the normal verifier array and calls `applyVerifyState`, which sets `currentDepth` from the matched index. Depth filtering is established before any content is shown.

When `appLockEnabled = false` (gate deliberately lowered via `disablePINFromCurrentDepth`), there is no PIN entry on launch. `currentDepth` stays at `0` — the default — and no filtering is applied. All contacts are visible regardless of what `state` says.

`disablePINFromCurrentDepth` called `setState(self.state, pinEnabled: false, config:)`, which persisted `state = .duress` and `appLockEnabled = false` but wrote nothing for `currentDepth`. On cold relaunch, `init()` restored `state = .duress` and `appLockEnabled = false` but left `currentDepth = 0`. All contact and vault filtering predicates (`isDisplayable`, `isEntryVisible`, `isRestricted`) read `currentDepth` — with `currentDepth = 0`, everything is visible.

`state = .duress` with `currentDepth = 0` is an internally inconsistent state that `init()` never guarded against.

### Resolution

`persistedDepth` (stored in `AppLayerConfig` as an encrypted value) was widened from `RoutingDepth` enum (limited to `.normal = 0` / `.duress = 1`) to a raw `Int`, enabling it to carry the full `currentDepth` value including depths > 1 from multi-layer coercion stacks. The on-disk encoding is unchanged — existing rows store `0` or `1` as JSON integers, which decode correctly as `Int`.

Three changes applied together:

**1. `AppLayerConfig` — `readRoutingDepth` / `writeRoutingDepth` → `readPersistedDepth() -> Int` / `writePersistedDepth(_ depth: Int)`.**
Encoding and decoding changed from `RoutingDepth` to `Int`. Fallback changed from `.normal` to `0`. Backward compatible.

**2. `Manager.Security.setState` — signature changed from `(_ depth: RoutingDepth, ...)` to `(_ depth: Int, ...)`.**
Each call site now passes an explicit integer literal rather than an enum case, eliminating any hidden dependency on `self.currentDepth` mutation order. `self.state` is derived internally as `depth > 0 ? .duress : .normal`. The critical site — `disablePINFromCurrentDepth` — was changed from `setState(self.state, pinEnabled: false, ...)` to `setState(self.currentDepth, pinEnabled: false, ...)`, persisting the live authenticated depth at the moment of disable.

**3. `Manager.Security.init()` — `currentDepth` restored when gate is down.**

```swift
let persistedDepth   = config.readPersistedDepth()
self.state          = persistedDepth > 0 ? .duress : .normal
self.appLockEnabled = config.readPinEnabled()
if !self.appLockEnabled { self.currentDepth = persistedDepth }
```

The `!self.appLockEnabled` guard is intentional: when the gate is up, `verify()` + `applyVerifyState()` must re-establish `currentDepth` from the PIN scan on every cold start — pre-seeding it would bypass the routing design. When the gate is down, no PIN entry occurs, and the persisted value is the only source of truth.

---

## Bug 51 — `appLockEnabled` conflated with PIN toggle state; no dedicated PIN-appearance property

**Status:** Closed (Fixed)

### Severity: Low (architectural / forensic)

`appLockEnabled` was a lock screen scheduling flag — it controls whether the PIN overlay fires on launch and foreground. It is not a PIN state property. The PIN is on when a verifier exists (`requiresPIN`), regardless of whether the overlay fires.

Despite this, the PIN toggle's `get` was:

```swift
get: { self.requiresPIN && self.security.appLockEnabled }
```

`appLockEnabled` was drafted into the toggle formula as a tell-avoidance shortcut. After `disablePIN(at:confirmingPIN:)`, the overlay is suppressed (`appLockEnabled = false`) and the coercer should see a device that looks PIN-free. Since `appLockEnabled` happened to be `false` in exactly that scenario, it was used to suppress the toggle — conflating a lock screen concern with PIN appearance.

### Consequences

The conflation spread to every UI element that needs to reflect PIN state. Each must independently combine `requiresPIN` (from `@Query` / SwiftData) and `appLockEnabled` (from `@Observable`), two properties from two different reactive sources. Any guard that checks only one of the two will be wrong in the gate-down scenario.

Bug 51A — **"Learn more" section interactive when toggle is OFF.** The section's disabled guard checked only `!requiresPIN`. With the gate lowered, `requiresPIN = true` (verifiers intact), so the guard evaluated to `false` — section remained interactive. Tapping "Learn more" presented `SecureModeSetupFlow`, which cannot complete from this state (`activateSecureMode` checks `sealedNormalVerifiers[0]` specifically; the duress PIN matches only `sealedNormalVerifiers[1]`). A dead-end UX with no security impact.

### Why verifiers cannot replace `appLockEnabled` as the PIN state signal

The natural fix — drive toggle state from verifier presence at `sealedNormalVerifiers[currentDepth]` — requires clearing that slot in `disablePIN(at:confirmingPIN:)`. This cannot be done cleanly:

- `disablePIN(at:confirmingPIN:)` is specifically designed to keep all verifiers intact so `reEnablePIN` can restore the gate by matching the existing PIN. Clearing the routing alias at `[currentDepth]` would require `reEnablePIN` to write a brand new verifier instead of re-enabling the existing one.
- The routing alias at `sealedNormalVerifiers[N]` enables cold-start routing for the duress PIN. Clearing it forces all cold-start duress entry through the push-down path, adding a dependency on `persistedDepth` restoration being correct.
- "Lower the gate" and "partially tear down the layer" are distinct operations. Collapsing them changes the semantics of `disablePIN` and introduces new failure modes into the re-enable path.

### Resolution

Replaced the global `appLockEnabled: Bool` with a per-layer `pinEnabledPerDepth: [Data]` array on `AppLayerConfig` and a corresponding `private(set) var pinEnabled: Bool` on `Manager.Security`.

- `AppLayerConfig.pinEnabledPerDepth` is a 32-entry padded array of encrypted Bools (one per depth). All entries are initialised to encrypted `true` at row creation. Filler entries are also encrypted `true`, so array length and content are forensically indistinguishable from any other configuration.
- `AppLayerConfig.writePinEnabled(_:at:)` / `readPinEnabled(at:)` read and write a single depth's gate state.
- `Manager.Security.pinEnabled` is the in-memory mirror, updated by `setState(_:pinEnabled:config:)` on every clean transition and restored in `init` from `readPinEnabled(at: persistedDepth)`.
- Migration: on first launch after the upgrade, if `pinEnabledPerDepth` is empty, the legacy `pinEnabled` scalar is read and its value is written to `pinEnabledPerDepth[persistedDepth]`. All other entries default to `true`.
- All UI sites (`Settings.swift`, `OccultaApp.swift`) reference `security.pinEnabled` exclusively. `appLockEnabled` is fully removed.
- `disablePINFromCurrentDepth(confirmingPIN:)` renamed to `disablePIN(at:confirmingPIN:)` for clarity.

The "Learn more" section's `disabled` guard now evaluates `!security.pinEnabled`, which is `true` whenever the gate is deliberately lowered — fixing Bug 51A.

**Forensic note — UInt8 encoding, not Bool:**
Each `pinEnabledPerDepth` entry is JSON-encoded as `UInt8(1)` (enabled) or `UInt8(0)` (disabled). A `Bool` encoding would produce `"true"` (4 bytes) vs `"false"` (5 bytes). AES-GCM does not pad ciphertext, so the sealed-box sizes would differ by one byte. A forensic examiner with access to the database could identify the disabled slot by size alone — without the SE key and without decryption. Encoding as `UInt8` makes both values encode to a single byte (`"1"` vs `"0"`), producing equal-length sealed boxes across all 32 entries regardless of value.

---

## Bug 52 — Bundle message not shown after cold-start unlock following a duress session

**Status:** Closed (Fixed)

### Severity: High (usability)

After a session where a bundle was received and rejected via duress PIN, killing the app and tapping the same bundle again produces the wrong outcome: the app launches, the user enters the correct normal PIN, the PIN cover dismisses — but the message is never shown and no error appears. Tapping the bundle a second time from the backgrounded app (after a grace-period expiry, so PIN is required again) works correctly.

### Reproduction

1. Receive a bundle from a normal contact.
2. Enter duress PIN — error "not addressed to you" appears (correct).
3. Kill the app.
4. Tap the bundle again in iMessage → app cold-starts.
5. Enter normal PIN → app opens, message absent, no error.
6. Minimize app, wait for grace period to expire, tap bundle again → enter normal PIN → message shows correctly.

### Observed behaviour

- Step 5: `pendingFileData` appears to never be drained, or `processInboundFile` is called but produces no visible result.
- Step 6: the background → foreground path (non-cold-start) works correctly for the identical bundle data.

### Instrumentation findings (inconclusive)

Extensive `[Bug52]` logging was added across `onOpenURL`, `handleActive`, `fullScreenCover onDismiss`, `buildOwnedBasket`, and all `processInboundFile` catch branches. The bug could not be reproduced while logs were active. In one early capture (before full logging), `onOpenURL fired` was absent entirely and `onDismiss` showed `pendingFileData=false`. A subsequent reproduction with full logging showed the complete pipeline working correctly through to `openedFileContents` being set. The bug appears intermittent and may be sensitive to launch timing.

### Leading hypothesis

On cold start, iOS delivers the `occulta://inbound` URL via `connectionOptions.urlContexts` during scene connection — before SwiftUI has finished evaluating the `body` and registering the `onOpenURL` modifier. SwiftUI is expected to buffer and replay the URL once the modifier is ready, but may occasionally drop the replay. When this happens, `pendingFileData` is never set, `onDismiss` drains nothing, and the message is silently lost.

### Key code sites

- `OccultaApp.swift` — `onOpenURL` handler and `needsPINEntry` gate
- `OccultaApp.swift` — `fullScreenCover(isPresented:onDismiss:)` and drain logic
- `OccultaApp.swift` — `onChange(of: scenePhase)` calling `handleActive()`
- `Manager+Security.swift` — `handleActive()` / `handleBackground()` transitions

---

## Bug 53 — Vault tab skips Face ID gate in duress mode — forensic tell

**Status:** Closed (Fixed)

### Severity: High (forensic)

In normal mode (depth 0), opening the Vault tab presents a Face ID (biometric) authentication gate before any vault content is shown. In duress mode (depth ≥ 1), the Face ID gate does not appear — the vault tab renders directly without prompting for biometric authentication. A coercer who opens the vault tab in duress mode observes the absence of the Face ID prompt and can infer that the device is not in its normal unlocked state, collapsing deniability.

### Root Cause

`Vault+Tab.swift` line 103:

```swift
if self.security.isRestricted || self.vault.isUnlocked {
    self.list
} else {
    self.lockGate
}
```

The `isRestricted` short-circuit causes the Face ID gate to be unconditionally skipped whenever duress mode is active, regardless of `vault.isUnlocked`. The intent was presumably "in duress mode, the vault is safe to show (it's already filtered)" — but this trades depth-filtering correctness for a visible behavioral asymmetry.

`visibleEntries` in the same file already handles depth filtering independently:

```swift
private var visibleEntries: [VaultEntry] {
    guard self.security.isRestricted else { return self.entries }
    return self.entries.filter { self.security.isEntryVisible($0) }
}
```

The Face ID gate and the entry filter are orthogonal. The gate should fire at every depth; the list shows only depth-visible entries after authentication succeeds.

### Resolution

Remove the `isRestricted` short-circuit from the gate condition in `Vault+Tab.swift`:

```swift
// Before
if self.security.isRestricted || self.vault.isUnlocked {

// After
if self.vault.isUnlocked {
```

`visibleEntries` continues to filter entries by depth — in duress mode the vault shows only entries stamped with the appropriate `visibleThroughDepth`, but the Face ID gate precedes them uniformly at all depths.

---

## Bug 48 — ContactClassification save silently no-ops at coercer's re-enabled depth — tell during activation

**Status:** Closed (Fixed)

### Severity: Medium (forensic)

When the coercer is at depth N+1 (after Bug 37 re-enable) and opens the Secure Mode activation flow, step 3 is `ContactClassification`. The coercer can drag contacts to the Sensitive section — the UI responds normally. When they tap "Activate," `save()` silently returns without writing anything because of the `guard !isRestricted else { return }` guard (added in Bug 25). After activation, entering their duress PIN (depth N+2) reveals the same contacts the coercer thought they had classified as hidden. The classification did not stick. A coercer testing normal functionality would immediately notice the discrepancy.

### Root Cause

`ContactClassification.loadSensitiveIDs()` and `save()` both guard on `!security.isRestricted`. `isRestricted = currentDepth > 0` is absolute: depth N+1 is always restricted, even though it is the coercer's home layer. The guard was added to prevent two distinct problems at adversary-controlled duress depths:

1. **Info leak** — `loadSensitiveIDs` would expose contacts the real user classified as sensitive-at-depth-N (those with `visibleThroughDepth == N`) in the Sensitive section, revealing the depth structure.
2. **Mutation** — `save()` would allow the adversary to reclassify the real user's contacts.

Both problems exist at depth N (real adversary depth) but not at depth N+1 (coercer's fresh depth), because no contacts have `visibleThroughDepth == N+1` until the coercer themselves classifies some. The guard cannot distinguish between these cases using only `isRestricted`.

### Resolution

`ContactClassification.loadSensitiveIDs()` and `save()` guards replaced from `guard !isRestricted else { return }` to:

```swift
guard security.currentDepth == 0
        || security.currentDepth == security.coercerBaseDepth else { return }
```

At depth 0 (real user, `coercerBaseDepth = 0`): `0 == 0` — loads and saves. ✓
At depth N+1 (coercer, `coercerBaseDepth = N+1`): `N+1 == N+1` — loads and saves. ✓
At depth N (adversary, `coercerBaseDepth = 0`): `N ≠ 0` and `N ≠ 0` — blocked, no info leak, no mutation. ✓

`coercerBaseDepth` is the same field introduced for Bug 47. No additional model changes required.

---

## Bug 54 — `vaultManager.isUnlocked` always false in `.inactive` handler; share index unfiltered and screenshot overlay inactive

**Stale, 2026-09-11:** Incident A's `ShareIndex.sqlite`/`shareIndexAllowedIDs`/`syncShareIndex()`
mechanism was removed 2026-08-16 (Bug 84, recipient picker moved into the app). Its sibling bugs (6,
65-69) already carry a "retired by the removal of the share index" note; this one never got it.
Incident B (the screenshot overlay/`handleInactive`) is unaffected and still accurate.

**Status:** Closed (Fixed)

### Severity: High (security / forensic)

Two separate guards in `OccultaApp.swift` checked `self.vaultManager.isUnlocked` at the point where `onChange(of: scenePhase)` fires for `.inactive`. Both guards were structurally impossible to pass: `UIApplication.willResignActiveNotification` fires before SwiftUI's scene phase change, and `VaultManager` calls `lock()` synchronously in its subscription to that notification — clearing `authContext` and making `isUnlocked = false`. By the time the `.inactive` handler runs, the vault is already locked regardless of whether it was unlocked a moment earlier.

---

#### Incident A — Share extension shows all contacts when PIN is configured

**Severity:** High (security)

When PIN is configured and the app goes inactive (share sheet opens, home button pressed), the share index should be re-filtered to only the contacts visible at depth 1 — hiding any contacts the user has classified as sensitive. Instead, the share extension received the full contact list.

**Root Cause**

`OccultaApp.swift`, `.inactive` case:

```swift
if self.security.requiresPIN, self.security.pinEnabled,
   self.vaultManager.isUnlocked {         // always false here
    self.contactManager.shareIndexAllowedIDs = self.security.safeContactIDs(atDepth: 1)
    self.contactManager.syncShareIndex()
}
```

`vaultManager.isUnlocked` is always `false` by the time this executes (vault locked via `willResignActiveNotification` before `onChange` fires). The entire block is skipped. The share index retains whatever was written during the last `.active` sync — which used `shareIndexAllowedIDs = nil` (all contacts) whenever the user was authenticated within the grace period and not in restricted mode.

`syncShareIndex()` does not require vault access. It decrypts contact names via `String.decrypt()` / `Manager.Crypto.decrypt()`, which uses the contact DB key (`createHybridLocalEncryptionKey()`), entirely separate from the vault key. The `vaultManager.isUnlocked` guard was not necessary.

**Resolution**

Removed `self.vaultManager.isUnlocked` from the condition:

```swift
// Before
if self.security.requiresPIN, self.security.pinEnabled,
   self.vaultManager.isUnlocked {

// After
if self.security.requiresPIN, self.security.pinEnabled {
```

---

#### Incident B — Screenshot-protection overlay not shown when app becomes inactive

**Severity:** High (forensic — relates to Bugs 33/36)

When the app goes inactive (share sheet opens, home button pressed, incoming call, Control Center), the opaque `Color(.systemBackground)` overlay is supposed to cover the app content immediately so the OS app-switcher snapshot captures a blank screen instead of contact names or vault labels. The overlay was not activating.

**Root Cause**

`handleInactive` in `Manager+Security.swift`:

```swift
func handleInactive(vaultUnlocked: Bool) {
    guard self.requiresPIN, self.pinEnabled, vaultUnlocked else { return }  // vaultUnlocked always false
    self.isContentHidden = true
}
```

Same structural problem as Incident A: `vaultUnlocked` is always `false` by the time `handleInactive` is called from the `.inactive` handler. `isContentHidden` is never set to `true` here. The overlay stays transparent during the inactive transition.

`handleBackground` — the analogous function that fires on full background — correctly has no vault guard:

```swift
func handleBackground() {
    guard self.requiresPIN, self.pinEnabled else { return }
    self.isContentHidden = true
    self.needsPINEntry = !self.isWithinGracePeriod
}
```

The vault guard in `handleInactive` was an inconsistency: the overlay's job is to protect content from OS snapshots, which is independent of vault state.

**Resolution**

Removed `vaultUnlocked` parameter from `handleInactive` entirely, matching the `handleBackground` pattern:

```swift
// Before
func handleInactive(vaultUnlocked: Bool) {
    guard self.requiresPIN, self.pinEnabled, vaultUnlocked else { return }
    self.isContentHidden = true
}

// After
func handleInactive() {
    guard self.requiresPIN, self.pinEnabled else { return }
    self.isContentHidden = true
}
```

Call site updated to match:

```swift
// Before
self.security.handleInactive(vaultUnlocked: self.vaultManager.isUnlocked)

// After
self.security.handleInactive()
```

---

### OS app-switcher snapshot — Resolution

Two distinct surfaces were at risk:

**App-switcher card** — the live pixel buffer SpringBoard captures as the user swipes up into the app switcher. Visible to a physical co-present observer; not a persistent forensic file.

**KTX forensic file** (`Library/SplashBoard/Snapshots/`) — written by iOS after `sceneDidEnterBackground` returns when the user actually switches to another app. Persistent; recoverable by Cellebrite, Magnet AXIOM, and similar tools without decrypting the device.

**Resolution — synchronous UIKit cover via `SceneDelegate`**

A `SceneDelegate: NSObject, UIWindowSceneDelegate, ObservableObject` was introduced. SwiftUI's `@UIApplicationDelegateAdaptor` places the `AppDelegate` in the environment; because `SceneDelegate` conforms to `ObservableObject`, SwiftUI automatically injects it into the environment as well. A one-time bootstrapping view (`SecuritySetting`) reads both `SceneDelegate` and `Manager.Security` from the SwiftUI environment on first render and writes the security reference into the delegate, establishing the bridge before any content is shown.

Three delegate methods are wired:

- **`sceneWillResignActive`** — installs a cover `UIView` (`.systemBackground` + spinner) directly into the existing `UIWindowScene` window via `CATransaction.setDisableActions(true)`. Synchronous; completes before UIKit composites the frame. Covers the app-switcher card immediately.
- **`sceneDidBecomeActive`** — removes the cover unconditionally.
- **`sceneDidEnterBackground`** — calls `security.handleBackground()`. The cover installed by `sceneWillResignActive` is still in the window hierarchy at this point; iOS photographs it for the KTX file.

Injecting the cover into the *existing* UIWindow (not a new `UIWindow` at a higher level) was essential: a separate window at `.alert + 1` blocked `UIActivityViewController` (share sheet). Subview injection avoids any window-level conflict.

`sceneWillResignActive` fires for all resign-active events — share sheets, Face ID prompts, incoming calls — not only app-switching. The cover therefore installs and removes on every such event. This is acceptable: the cover is a progress indicator (not a lock screen), it appears and disappears in under a second for brief interruptions, and it ensures the app-switcher card is always covered regardless of what triggered the resign.

---

## Bug 55 — PIN gate fires mid-share flow; composed message lost

**Status:** Closed (Fixed)

### Severity: High (usability)

When sharing a bundle via an app that has its own Face ID gate (e.g. WhatsApp), the PIN gate appeared on return to Occulta. If the user had composed a long message (>5 minutes of active use), any in-progress state was lost. The issue was intermittent: it only triggered when the grace period had expired.

A compounding case: the user composes for more than 5 minutes without any app lifecycle transition. The grace period clock (based on time since last PIN entry) runs out during composition. When the user taps Share and WhatsApp opens, Occulta goes to background, `handleBackground()` evaluates an already-expired grace period, and sets `needsPINEntry = true`. On return from WhatsApp, the PIN sheet appears mid-flow.

### Root Cause

The grace period measured **time since last PIN entry** (`lastUnlockDate: Date?`). It answered the wrong question.

- If a user authenticated and immediately started composing, the clock ran from authentication — not from when they stopped being present.
- If active use lasted longer than 5 minutes, the clock expired even though the user never set the phone down.
- Any brief background (including a share sheet transition to WhatsApp) evaluated the expired clock and raised the PIN gate.

`sceneWillResignActive` fires for share sheet presentation, triggering `handleInactive()` → `isContentHidden = true` (cover installs). When WhatsApp opens, `sceneDidEnterBackground` fires, triggering `handleBackground()`, which evaluated `!isWithinGracePeriod` and set `needsPINEntry = true`.

### Resolution

Replaced the `lastUnlockDate`-based grace period with a **background-duration model**. The question is now: *how long was this app genuinely unattended?*

- `handleBackground()` records `backgroundEntryDate = Date()`. It no longer sets `needsPINEntry`.
- `handleActive()` computes `elapsed = now - backgroundEntryDate`. Only if `elapsed > gracePeriod` (5 minutes) is the PIN gate raised. Brief interruptions — share sheets, Face ID prompts, notification banners — never background the app, so `backgroundEntryDate` is nil and `elapsed = 0`.
- `backgroundEntryDate` is cleared on every foreground return.

Three properties removed: `lastUnlockDate`, `recordUnlock()`, and `isWithinGracePeriod`. `backgroundEntryDate` replaces them entirely.

**Outcome:** a user composing for 30 minutes who shares to WhatsApp and returns in under 5 minutes sees no PIN gate. A user who sets the phone down for 5+ minutes and returns sees the PIN gate. The gate is now tied to actual unattended time, not to authentication history.

---

## Bug 56 — Contacts briefly visible between UIKit cover removal and PIN fullScreenCover presentation

**Status:** Closed (Fixed)

### Severity: High

When returning to the app after the grace period has expired, there is a brief window where contacts are visible. The user observes: spinner cover → contacts → PIN view. Contacts should never be visible before PIN entry.

### Root Cause

Two compounding issues:

**1. Wrong call order in `sceneDidBecomeActive` (`SceneDelegate.swift:8–10`):**

```swift
func sceneDidBecomeActive(_ scene: UIScene) {
    self.removeCover()            // UIKit cover torn down first
    self.security?.handleActive() // needsPINEntry set second
}
```

The UIKit spinner cover is removed synchronously before `needsPINEntry` is set to `true`. Between these two lines the SwiftUI content (contacts) is live and unobscured.

**2. `fullScreenCover` presentation is asynchronous.** Even if the call order is swapped, SwiftUI does not present the PIN `fullScreenCover` in the same run loop cycle as the `needsPINEntry = true` state change. UIKit modal presentation requires multiple render passes; the contacts view is live beneath it for those frames.

The observable sequence:
1. Spinner cover (`UIActivityIndicatorView`) — installed by `sceneWillResignActive`
2. Contacts briefly visible — after `removeCover()`, before PINEntry finishes presenting
3. PIN view — `fullScreenCover` finally on screen

### Proposed Fix

Keep the UIKit cover in place until `PINEntry` confirms it is on screen via `onAppear`. Only remove the cover immediately when no PIN is needed (grace period still valid).

**`SceneDelegate.sceneDidBecomeActive`:** call `handleActive()` first; skip `removeCover()` when `needsPINEntry` is true.

```swift
func sceneDidBecomeActive(_ scene: UIScene) {
    self.security?.handleActive()
    guard self.security?.needsPINEntry != true else { return }
    self.removeCover()
}
```

**`OccultaApp` fullScreenCover content:** add `.onAppear` that removes the cover once PINEntry is on screen (safe to remove because PINEntry is already covering the content).

```swift
PINEntry(...)
    .environment(self.security)
    .onAppear {
        if let scene = UIApplication.shared.connectedScenes
            .first(where: { $0.activationState == .foregroundActive }) as? UIWindowScene,
           let delegate = scene.delegate as? SceneDelegate {
            delegate.removeCover()
        }
    }
```

`removeCover()` must be made non-private for the call site in the fullScreenCover to compile.

**Invariant:** the UIKit cover is always torn down — either immediately in `sceneDidBecomeActive` (no PIN needed) or in `PINEntry.onAppear` (PIN needed). There is no path where the cover is left up indefinitely.

---

## Bug 57 — Sensitive contact not sealed in blob during second-layer activation; visible in depth-2 duress view

**Status:** Closed (Fixed)

### Severity: High (security)

When the real user enters their own duress PIN (reaching `currentDepth = 1`) and activates a second Secure Mode layer via the setup flow, any contact dragged to the Sensitive section in `ContactClassification` is silently not classified. On cold launch with the depth-2 duress PIN the contact is visible — defeating the purpose of the classification step.

### Root Cause

`ContactClassification.save()` (and `loadSensitiveIDs()`) are guarded:

```swift
guard security.currentDepth == 0
        || security.currentDepth == security.coercerBaseDepth
else { return }
```

At `currentDepth = 1` with `coercerBaseDepth = 0` (real user, no coercion-acceptance path has run):

- `1 == 0` → false
- `1 == coercerBaseDepth (0)` → false

Both conditions fail. The guard returns early. `updateSafeContacts` is never called and the contact's `visibleThroughDepth` is never written.

Inside `activateSecureMode(depth: 1)`, the classification logic reads each contact's stored `visibleThroughDepth`. Because `save()` was a no-op, all contacts still have `visibleThroughDepth = nil`, which decodes as `Int.max`:

```swift
let contactDepth: Int = {
    guard let data = profile.visibleThroughDepth, ...
    else { return Int.max }   // nil → always safe
    return value
}()

if contactDepth > depth {       // Int.max > 1 → safe
    safeProfiles.append(profile)
} else if contactDepth == depth {  // never reached
    blobContacts.append(...)
}
```

The contact lands in `safeProfiles`; Step 5 stamps it with `visibleThroughDepth = encode(Int.max)`. On cold launch with depth-2 duress PIN, `isVisible` evaluates `Int.max >= 2` → true → contact is shown.

### Context

The Bug 48 fix changed the guard from `!security.isRestricted` to `currentDepth == 0 || currentDepth == coercerBaseDepth` to unblock the coercer who reached depth N+1 via `reEnablePIN`'s coercion-acceptance path (which writes `coercerBaseDepth = N+1`). That path is not taken here — the real user entered their own duress PIN and `activateSecureMode` does not write `coercerBaseDepth`. The guard is therefore never satisfied for this activation path: the real user's duress depth (1) matches neither `== 0` nor `== coercerBaseDepth (0)`.

### Resolution

Removed the depth guard from `ContactClassification.loadSensitiveIDs()` and `save()` entirely. The guard was redundant: `classifiableContacts` filters through `isDisplayable(atDepth: currentDepth)` (contacts hidden at shallower layers are never surfaced), and `isSensitive` returns true only for `visibleThroughDepth == currentDepth` (current-depth classifications only). `updateSafeContacts` has the same `isVisible` guard internally. These three invariants together prevent both info leak and mutation at any depth — the outer guard was not adding protection.

---

## Bug 58 — "Learn more" does not flip to "Deactivate Protection" after second-layer activation from duress depth

**Status:** Closed (Fixed)

### Severity: Medium (forensic tell)

After the real user activates a second Secure Mode layer from duress depth (depth 1), the "Deactivate Protection" button never appears and "Learn more" remains visible. The Settings security screen looks identical before and after activation — a tell that the activation either failed or is hiding state.

### Root Cause

`activateSecureMode` never calls `setState()` and does not update `coercerBaseDepth`. After a successful activation at `depth = 1`:

- `currentDepth` remains `1` (unchanged)
- `state` remains `.duress` (not updated by activation)
- `coercerBaseDepth` remains `0` (only written by `reEnablePIN`'s coercion-acceptance path, not by `activateSecureMode`)

The "Deactivate Protection" guard in `Settings.swift`:

```swift
isSecureModeActive && state == .normal
    && (currentDepth == 0 || currentDepth == coercerBaseDepth)
    && pinEnabled
```

Both `state == .normal` (state is `.duress`) and `currentDepth == coercerBaseDepth` (`1 == 0`) are false. The button never shows.

The "Learn more" guard:

```swift
!isSecureModeActive || currentDepth > 0 || !pinEnabled
```

`currentDepth > 0` (= `1 > 0`) remains true, so "Learn more" stays visible regardless of whether a new layer was created.

### Context

Bug 47 resolved the symmetric case for the coercer: after `reEnablePIN`'s coercion-acceptance path writes `coercerBaseDepth = N+1`, the button becomes visible because `currentDepth == coercerBaseDepth`. That fix does not apply here because `activateSecureMode` is not instrumented to write `coercerBaseDepth`. The result is that the real user activating from depth 1 is in a state where neither the coercer path (`coercerBaseDepth`) nor the real-user path (`currentDepth == 0`) satisfies the guard.

Bugs 57 and 58 are causally related: Bug 57 means the underlying contact data is wrong (no contacts sealed in the blob); Bug 58 means the UI gives no feedback that anything happened. Both trace to the same omission: `activateSecureMode` does not record depth 1 as an operator home depth the way `reEnablePIN` does via `coercerBaseDepth`.

### Resolution

At the end of `activateSecureMode`, after the config writes, when `depth > 0`:

1. Write `coercerBaseDepth = depth` — records the operator's home depth so that `currentDepth == coercerBaseDepth` passes in the Deactivate Protection guard. **Note:** the initial implementation incorrectly wrote `depth + 1`; see Bug 61 for the correction.
2. Set `self.state = .normal` — satisfies the `state == .normal` gate that was blocking the button.

Both writes land in the same `modelContext.save()` that follows, so they are atomic with the rest of the activation config writes.

---

## Bug 59 — PIN collision detected at activation summary after full flow; contact classification work lost

**Status:** Closed (resolved by Bug 58 + Bug 61 fixes; no code change required)

### Severity: Medium (UX)

When the user runs the Secure Mode activation flow from duress depth and proposes a new duress PIN that collides with an existing verifier at another layer (e.g. the proposed PIN is the same as the real normal PIN), `activateSecureMode` throws `pinCollision`. This error fires only at "Activate" in `SummaryView` — step 4 of 4 — after the user has already gone through Education, PIN entry, and Contact classification. The classification work is discarded and the user receives a generic "Activation Failed" alert with no explanation. They have no way to know the PIN was rejected, which PIN is conflicting, or that they need to choose a different PIN.

### Root Cause

**Why the collision fires:** The collision check inside `activateSecureMode` scans every slot in `sealedNormalVerifiers` with `normalLabel`. `sealedNormalVerifiers[0]` is the real master normal PIN. If the proposed new duress PIN matches that slot, the check throws `pinCollision`. This is a legitimate routing constraint — entering that PIN at cold start would match `normalVerifiers[0]` and route to depth 0, making the depth-N+1 routing alias unreachable. The rejection is correct.

**Why the timing is wrong:** The collision check only exists inside `activateSecureMode`, which runs at the very end of the 4-step flow. There is no validation at the point where the user enters and confirms the new PIN (step 2). The flow advances to Contact classification with a PIN that is destined to fail.

**Why the error is unhelpful:** `SummaryView` catches `pinCollision` in the generic `catch` block and shows "Activation Failed":

```swift
} catch {
    debugPrint("Error activating [\(type(of: error))]: \(error)")
    self.isActivating     = false
    self.activationFailed = true
}
```

The alert has no message that tells the user to choose a different PIN, and the sheet dismisses entirely — so the contact classification is lost.

### Root Cause

**Why the collision fires legitimately — but at the wrong time and for a non-obvious reason:**

The first activation attempt from depth 1 with duress PIN "2222" *succeeded* cryptographically. The post-catch section of `activateSecureMode` wrote:
- `sealedDuressVerifiers[1]` — duress verifier for "2222"
- `sealedNormalVerifiers[2]` — routing alias for "2222" (same PIN, `normalLabel`)

However, Bug 58 — which was present at the time — left `state` at `.duress` and `coercerBaseDepth` at `0`. The "Deactivate Protection" button never appeared. The user concluded activation had failed (the UI was indistinguishable from a no-op), dismissed the flow, and retried.

On the second attempt with the same PIN "2222", the collision check in `activateSecureMode` scans all `sealedNormalVerifiers` and finds the routing alias written during the first (silently-successful) run at index 2. It throws `pinCollision`. The generic `catch` in `SummaryView` shows "Activation Failed" with no explanation.

The device is now in an inconsistent state: activation succeeded (verifiers written, blob pushed, key rotated), but the session has no UI evidence of this. The user cannot reach "Deactivate Protection" from depth 1 because `state` is still `.duress` (Bug 58 was unfixed at activation time). The only recovery path is entering the normal (master) PIN at cold start — `currentDepth = 0`, `state = .normal` — which satisfies the `currentDepth == 0` arm of the Deactivate condition.

**This bug is a cascade of Bug 58.** With Bug 58 now fixed, activation from depth 1 transitions `state` to `.normal` and shows "Deactivate Protection" immediately after the flow dismisses. The user cannot be misled into thinking activation failed, so the retry-with-same-PIN path is no longer reachable in normal operation.

### Resolution

Bug 58 fix prevents recurrence. No code change needed for the collision check itself — rejecting a PIN that already has a routing alias in the array is correct behaviour.

Two hardening improvements remain worth considering as separate work:

**1. Specific `pinCollision` catch in `SummaryView`** — instead of the generic "Activation Failed" alert, navigate back to the PIN step and prompt the user to choose a different PIN. Gives actionable feedback without revealing which verifier collided.

**2. Recovery hint when `pinCollision` fires after a known-inconsistent activation** — if `sealedNormalVerifiers[depth+1]` already contains a valid verifier, the app could surface a recovery path rather than a dead end.

---

## Bug 60 — Visibility toggle hidden at coercer's home depth — forensic tell in contact edit

**Status:** Closed (Fixed)

### Severity: Medium (forensic)

At any depth > 0 (duress, or any decoy layer), opening contact edit presents a form missing the "VISIBILITY" section. At depth 0 the section is present. Any party operating at a depth above 0 — a coercer, an adversary, or the real user navigating their own duress layer — sees a shorter form, which is a tell that the current depth is not the base layer.

### Root Cause

`ContactFormV2.swift` guards the visibility section on `!security.isRestricted`:

```swift
// VISIBILITY only applies at depth 0. At depth > 0 the contact
// inherits its visibility from the depth stamp set at creation.
if !self.security.isRestricted {
    FormSectionV2(header: "VISIBILITY") { ... }
}
```

`isRestricted = currentDepth > 0` is true at every depth above 0, including the coercer's home depth. The same guard applies to the save path:

```swift
if self.security.currentDepth == 0 {
    try? self.security.setVisibility(for: self.contact.identifier,
                                     isSensitive: self.isSensitive)
}
```

Both guards use `currentDepth == 0` as a proxy for "real user," which has been incorrect since `coercerBaseDepth` was introduced (Bug 47). `setVisibility` itself is already depth-aware — it encodes `self.currentDepth` as the sensitive sentinel and `Int.max` as safe — so calling it at `coercerBaseDepth` produces the correct result. Only the view and save guards need updating.

### Resolution

Remove the depth guard entirely from both the view and the save path — the same conclusion Bug 57 reached for `ContactClassification`.

`isSensitive` returns true only for `visibleThroughDepth == currentDepth` (depth-relative read). `setVisibility` writes `visibleThroughDepth = currentDepth` (sensitive) or `Int.max` (safe) — correct at any depth. There is no cross-depth info leak and no mutation of contacts outside the current depth's scope. The guard added no protection; it only created a tell.

**`ContactFormV2.swift` — depth guard removed from view:**

```swift
// Before
if !self.security.isRestricted {
    FormSectionV2(header: "VISIBILITY") { ... }
}

// After
FormSectionV2(header: "VISIBILITY") { ... }
```

**`ContactFormV2.swift` — depth guard removed from save:**

```swift
// Before
if self.security.currentDepth == 0 {
    try? self.security.setVisibility(...)
}

// After
try? self.security.setVisibility(...)
```

---

## Bug 61 — Bug 58 fix writes wrong `coercerBaseDepth`; "Deactivate Protection" still absent after depth-1 activation, Bug 47 coercer path regressed

**Status:** Closed (Fixed)

### Severity: High (forensic tell + regression)

The Bug 58 fix writes `coercerBaseDepth = depth + 1` in `activateSecureMode`. The value must be `depth`. With the current code, the "Deactivate Protection" button never appears after activation from depth 1 — the exact symptom Bug 58 was meant to fix. Additionally, the write silently corrupts the value set by `reEnablePIN` for Bug 47's coercer scenario.

### Root Cause

The Bug 58 resolution document states: "Write `coercerBaseDepth = depth + 1` so that `currentDepth == coercerBaseDepth` (`1 == 1`) passes." The arithmetic is incorrect. When `depth = 1`, `depth + 1 = 2`. The condition evaluates as `currentDepth (1) == coercerBaseDepth (2)` → **false**. The parenthetical `(1 == 1)` in the documentation describes the intended outcome (`coercerBaseDepth = 1 = depth`), but the formula `depth + 1` implements a different value.

After activation from depth 1 with the current code:

- `coercerBaseDepth = 2`
- `currentDepth = 1`
- `state = .normal`
- "Deactivate Protection" guard: `(1 == 0 || 1 == 2)` → false → button absent ❌

With the corrected formula `coercerBaseDepth = depth`:

- `coercerBaseDepth = 1`
- "Deactivate Protection" guard: `(1 == 0 || 1 == 1)` → true → button shown ✓

### Bug 47 regression

Bug 47's `reEnablePIN` coercion-acceptance path writes `coercerBaseDepth = currentDepth + 1` before the coercer re-enters. After re-entry, `currentDepth = N+1` and `coercerBaseDepth = N+1` — the button correctly appears. When the coercer then activates from depth N+1 (`activateSecureMode(depth: N+1)`), the current Bug 58 code writes `coercerBaseDepth = N+2`, overwriting the `reEnablePIN` value. The button condition becomes `N+1 == N+2` → false → **Bug 47 is re-broken**.

With the corrected formula, the write is `coercerBaseDepth = N+1` — identical to the value `reEnablePIN` already wrote. The existing value is preserved and Bug 47 is unaffected.

### Resolution

In `Manager+Security.swift`, change the Bug 58 write from:

```swift
if depth > 0 {
    try? config.writeCoercerBaseDepth(depth + 1)
    self.state = .normal
}
```

to:

```swift
if depth > 0 {
    try? config.writeCoercerBaseDepth(depth)
    self.state = .normal
}
```

At depth 0 (real user activating the first layer): this branch is not taken, so `coercerBaseDepth` is unchanged (remains 0). The real user's "Deactivate Protection" is governed by `currentDepth == 0`, which is unaffected.

At depth 1 (real user entering their duress PIN and activating a second layer): `coercerBaseDepth = 1`. The button shows at `currentDepth = 1`. ✓

At depth N+1 (Bug 47 coercer after `reEnablePIN`): `coercerBaseDepth = N+1` — same value already written by `reEnablePIN`. No regression. ✓

---

## Bug 62 — `pinCollision` "Activation Failed" alert is a forensic tell; enables coercer PIN oracle at duress depth

**See also Bug 119, 2026-09-11:** Gap 2 (no rate-limit design survives a compliant-victim relock
cycle), the residual-risk section (accidental master-PIN collision), and Gap 3's own trigger
mechanism (the `masterPINCollision` signal a wipe would respond to) are all closed as a side effect if
`PASSPHRASE_LAYER_KEYS.md`'s passphrase-derived layer keys ship with genuinely high-entropy,
non-editable phrases — worth deciding alongside that proposal rather than solving these twice. Gap
3's own *deeper* structural problem (what happens once the real secret is known to be in a coercer's
hands) is not touched by any of this — see Gap 3's 2026-09-11 note below for why that part is
orthogonal to secret format.

**Status:** **Open — root scenario fixed, escalation gaps remain.** Re-examined 2026-08-26: the
bug's actual root — a single, accidental `pinCollision` during ordinary setup, revealing that
something is already configured to a coercer who was led to believe otherwise — is fully closed by
the Resolution's silent-dismiss + dummy-blob-write fix, on one occurrence, no repeated guessing
needed. What's left (Gaps 1a, 2, 3) all target a narrower, more deliberate escalation: a coercer who
already suspects collisions carry meaning and tries to exploit that on purpose. See *The root
scenario* below.

### Severity: High (forensic) — root scenario closed; remaining gaps are lower-likelihood escalations

`SummaryView` catches `pinCollision` in the generic `catch` block and shows an "Activation Failed" alert. A device with no Secure Mode active has no existing verifiers, so it can never produce a `pinCollision` during activation — any PIN the user proposes will succeed. A device with Secure Mode active can produce a collision when the proposed duress PIN matches an existing verifier. Seeing "Activation Failed" (as opposed to a wrong-entry-PIN error, which would have been caught earlier in the flow) confirms that protected verifiers already exist on the device. The alert directly reveals that Secure Mode is running.

Compare with `invalidStateTransition`, which is silently dismissed: that arm was added in Bug 24 precisely for tell-avoidance — the same principle must apply to `pinCollision`.

### The root scenario — clarified 2026-08-26

The bug's actual root is simpler than the oracle framing below makes it sound, and worth stating
plainly: **a coercer routed to a duress layer is shown a device that looks completely unprotected —
that's the whole point of a decoy layer. If they then decide to set up Secure Mode themselves,
believing they're configuring it for the first time, and the PIN they happen to propose collides
with an existing verifier anywhere in the real layer stack, `pinCollision` fires — on the first,
completely ordinary, non-adversarial attempt.** No deliberate guessing needed. Under the belief the
coercer was given (nothing is configured), a collision is logically impossible — there's nothing to
collide with. So the mere existence of a failure that can only happen when something already exists
is proof, in one interaction, that the device isn't what it appeared to be. That's the tell, and it
doesn't require the coercer to understand verifiers, oracles, or anything about how the app works —
just to notice that "set up fresh" unexpectedly failed.

**This is exactly what the Resolution below closes, fully, on a single occurrence** — not just for a
sequence of deliberate guesses. The silent-dismiss fix makes collision and success produce the
identical UI outcome; the dummy-blob-write fix (Gap 1) makes them identical at the disk level too.
So the root scenario is closed as of the Resolution landing, independent of everything below it.

### PIN oracle attack — an escalation on top of the root scenario, not the root scenario itself

Distinct from the above: a coercer who *already suspects*, through some channel other than the now-
silenced alert, that collisions carry meaning, and who deliberately exploits that by probing multiple
candidates on purpose. A coercer at depth 1 with `state = .duress` (no prior activation from this
depth) can attempt to use the collision as a binary oracle to identify the master PIN:

1. Open the activation flow, confirm their PIN ("1111"), propose candidate PIN X.
2. "Activation Failed" → X collides with an existing verifier. Because `sealedNormalVerifiers[0]` holds the master normal PIN, X = master PIN — found.
3. No alert (flow dismisses normally) → X is not in use. A new layer is created at depth 2.

Each successful probe creates a new layer and transitions `state` to `.normal` (Bug 58 fix), after which `invalidStateTransition` blocks further activation attempts from depth 1. Each colliding probe leaks whether the proposed PIN is the master PIN. With `pinCollision` silently dismissed the coercer receives no signal — successful activation and a collision are indistinguishable from the UI, so **this specific version of the attack no longer works at all** once the Resolution below lands; it's preserved here as the reasoning that motivated Gap 1, and because Gap 1a and Gap 2 both target residual, more speculative versions of a coercer trying to reconstruct this signal some other way.

### Root Cause

`SummaryView`'s catch hierarchy treats `invalidStateTransition` as a tell-avoidance case (silent dismiss) and every other error as a genuine failure (visible alert):

```swift
} catch Manager.Security.SecurityError.invalidStateTransition {
    self.isActivating = false
    self.onDone()         // silent dismiss
} catch {
    self.isActivating     = false
    self.activationFailed = true  // "Activation Failed" alert
}
```

`pinCollision` falls into the generic `catch` arm. There is no explicit arm for it. The tell-avoidance intent of Bug 24's fix was not extended to the collision case.

### Resolution (partial — bug remains open)

**Applied:** A dedicated `catch` arm for `pinCollision` was added in `SummaryView`, identical to the `invalidStateTransition` arm. Every activation attempt — collision, `invalidStateTransition`, or genuine success — now ends with the sheet dismissing without incident. The signal is removed.

**Not yet resolved — three remaining gaps, plus Gap 1a (a side effect of Gap 1's own fix, noted
later while tracing Bug 76):**

---

#### Gap 1 — The silent dismiss is itself a forensic tell

A real activation writes extensively: all contact rows are re-encrypted (new ciphertext, WAL activity), a blob is pushed to the layer store file, and `AppLayerConfig` gains new verifiers, a blob slot index, and a sequence number. A collision writes nothing — the DB is untouched, the WAL is idle, and the blob store is unchanged.

A forensic examiner comparing filesystem and DB state before and after a "successful" activation attempt can distinguish collision from success without decryption: file modification timestamps, WAL presence, and blob store contents all differ. The UI is indistinguishable; the disk is not.

**Applied:** on `pinCollision`, `pushDummyBlobSlot` writes a random-noise `LayerPayload` (empty contacts, random sequence number) to a non-excluded slot before the throw. `push()` pads all payloads to `slotPlaintextSize` before encrypting, so the ciphertext is the same fixed size as a real activation blob — indistinguishable by byte count. The contact DB and AppLayerConfig remain unmodified (no re-encryption, no new verifier), but the blob store — the most externally observable artefact — now shows a write on every collision.

##### Gap 1a — the dummy push trades a no-key tell for a with-key one

Noted while tracing Bug 76; not previously recorded here. The Gap 1 fix works as intended against
the threat model it targets, but it is a trade rather than a pure win, and the trade should be
explicit.

`pushDummyBlobSlot` records its slot index nowhere — no `writeBlobSlot` call accompanies it. The
dummy is therefore a permanent **orphan**: a real, decodable payload in the store that no
`sealedBlobSlots` entry points at. Consequences split by what the examiner holds:

- **Without keys — no tell, as designed.** Every `push` re-seals all 32 slots with fresh nonces
  and every slot is the same fixed ciphertext size, so a before/after diff shows all 32 changed
  whatever happened. The file is `.completeFileProtection` and `isExcludedFromBackup`, same as the
  DB. This is exactly the tell Gap 1 set out to close, and it is closed.

- **With the SE Secure Mode key — a new, faint signal.** That key never rotates, so an examiner who
  can derive it (compelled device, or code execution while unlocked) opens all 32 slots. Real
  payloads decode as `LayerPayload`; filler does not. Dummies decode with `contacts: []`, so
  counting empty payloads yields a rough count of **how many PIN collisions occurred** — that is,
  how many times someone proposed a PIN matching an existing verifier. That is adjacent to the very
  oracle this bug is about: it does not identify *which* PIN collided, but it does reveal that
  probing happened and roughly how much.

  Not conclusive on its own — a genuine activation where nothing was classified sensitive also
  produces `contacts: []` — so it is suggestive rather than proof.

Dummies accumulate for the life of the Secure Mode session. `push` decrypts all slots and re-seals
anything that decodes, so it actively carries them forward; they clear only when randomly
overwritten by a later activation's slot draw (~1 in 30 per activation) or wiped wholesale by
`rewrite()` at full deactivation, force-recovery, or the periodic rewrite once Secure Mode is off.

**Judgement:** probably an acceptable trade — the no-key threat model (filesystem image, seized
device, backup extraction) is far broader than the with-key one, which already implies an unlocked
device where the DB's own residual gap ([Manager+Security.swift:615-620](Occulta/Features/SecureMode/Manager+Security.swift:615))
exposes the contacts anyway. Recorded because it was implicit, not because it needs reversing.

**Cheap partial mitigation, if wanted:** Bug 76's proposed change to `push` — re-seal referenced
payloads, substitute fresh random for unreferenced ones — would clear accumulated dummies as a
side effect, capping the count at one per Secure Mode session rather than one per collision. It
does not remove the signal, only bounds it.

---

#### Gap 2 — Rate limit proposal is flawed, and re-examined 2026-08-26: it targets a narrower threat than it sounds like, and its own replacement has the same class of problem it was proposed to fix

**Scope, clarified first:** this gap does not defend the bug's root scenario (a single accidental
collision during ordinary setup) — that's fully closed by the Resolution above, on one occurrence,
with no attempt count involved. Gap 2 only matters for the PIN-oracle escalation: a coercer
deliberately trying many candidates on purpose, via some channel other than the now-silenced alert.
That's a narrower and more speculative population than the bug's main case.

The original Option A (N activations per 24-hour window) was inadequate on multiple dimensions:

- **Threat model mismatch.** A coercer has a bounded physical access window — typically hours, not days. A 24-hour counter resets before the next session and is useless.
- **Counter is observable.** An encrypted counter that increments after each probe is itself a forensic signal — an examiner who can observe the DB across time can infer that activation attempts were made.
- **Non-colliding probes create real state.** Each successful (non-colliding) probe creates a real new layer: new verifiers, new blob slot entry, new cryptographic artefacts that accumulate indefinitely. The rate limit constrains collision probes but not layer proliferation.
- **Clock manipulation.** iOS system time is controllable in some jailbreak or MDM-adjacent scenarios; a 24-hour window tied to wall time is not robust.

**Better framing, originally proposed:** a **session-scoped limit** (1–2 activation attempts per authenticated session at a given depth) is invisible to a legitimate user and makes brute-forcing impractical given the physical access requirement per session. This requires no persistent counter and is not vulnerable to clock manipulation.

**Re-examined 2026-08-26 — the session-scoped proposal assumes the wrong adversary.** "Requires a
fresh unlock to get another attempt" is a real cost against an attacker who has the *device* without
the *owner* — someone who stole or seized it and doesn't control re-authentication. That is not
Secure Mode's threat model. The threat model here is a coercer with the compliant owner physically
present, directing them to enter PINs on command — which is the entire premise of a duress PIN
existing at all. For that adversary, "lock it, unlock it again" costs nothing; a session-scoped limit
resets on exactly the thing a coercer can trivially compel for free.

**What it still buys, and what it doesn't.** Exhaustive brute force — cycling the full PIN space
(10⁴-10⁶ candidates) at 1-2 guesses per relock, even at a generous 10-15 seconds per cycle — adds up
to weeks or months of continuous relocking, genuinely impractical inside an hours-long coercion
window. But a small number of *targeted*, plausible guesses (birthdate, anniversary, repeated
digits) costs a compliant victim's coercer almost nothing to cycle through, ten or twenty relocks at
most. The doc's own acceptance-criteria section (below) already names targeted guessing as the more
realistic scenario, not exhaustive brute force — so the fix as proposed is strongest against the
attack that's least likely and weakest against the one already flagged as most likely.

**No replacement design yet.** A limit that survives a compliant-victim relock cycle needs to persist
across the session boundary — which walks straight back into the same "counter is observable"
objection that got the original 24-hour proposal rejected. Persistent-enough-to-survive-relock,
forensically invisible, and not itself the tell appear to pull against each other; no shape has been
found yet that satisfies all three. This is now a blocking design question, the same shape as Gap 3's
below, not an implementation task.

---

#### Gap 3 — Targeted wipe on master PIN collision

The original blanket wipe-on-any-collision was rejected (kill switch, false positives). A narrower variant is still under consideration: split `pinCollision` into two errors — `masterPINCollision` (hit `sealedNormalVerifiers[0]`) and `pinCollision` (hit any other verifier) — and wipe only on the former.

**Why the split is correct:** `sealedNormalVerifiers[0]` is exclusively the real user's depth-0 master PIN. Only a collision there means the coercer has found the key to the real layer. Collisions with routing aliases or duress verifiers at other depths do not expose depth 0 and warrant only a silent dismiss. The kill switch objection evaporates: a wipe can only be triggered by finding the master PIN, which is exactly the event worth responding to with destruction.

**Implementation shape:**
```swift
// Check master PIN first — collision here means wipe
guard !PINManager.checkVerifier(pin: duressPIN, label: Self.normalLabel,
                                 verifier: config.sealedNormalVerifiers[0], seKey: seKey)
else { throw SecurityError.masterPINCollision }

// Remaining normal verifiers (routing aliases) and all duress verifiers → silent dismiss
for v in config.sealedNormalVerifiers.dropFirst() { ... throw SecurityError.pinCollision }
for v in config.sealedDuressVerifiers            { ... throw SecurityError.pinCollision }
```

**Unresolved: what does the app look like after a wipe?**

This is the blocking design question. The wipe fires inside `SummaryView`'s catch block — the sheet dismisses normally and the coercer is back in Settings at their depth. They expect a working app.

If all verifiers are cleared: the coercer's current session survives (no re-check), but on next background → foreground their depth-1 PIN no longer exists. Lock screen appears, PIN fails — an obvious tell.

If only Secure Mode state is cleared but the coercer's depth-1 verifier is preserved: the app remains usable at depth 1, but the master PIN still exists in `sealedNormalVerifiers[0]`. The coercer found it and can still use it. Wiping Secure Mode state without wiping the master PIN verifier accomplishes nothing.

**The deeper structural problem:**

Sensitive contacts are not hard-deleted from the DB (Bug 13 resolution — they remain in SQLite, hidden by `visibleThroughDepth` filtering). Wiping the blob removes the deactivation restoration copy but leaves the sensitive contacts physically in the DB. If the coercer enters the master PIN after the wipe, they reach depth 0 and those contacts are still visible. A wipe that is actually effective at protecting the data requires hard-deleting sensitive contacts from the DB — which reinstates the Bug 13 functional conflict: the real user can no longer see their sensitive contacts after entering the normal PIN.

There is no currently available path that both protects the data on `masterPINCollision` and preserves the real user's access to it. This option remains open pending a design resolution for the hard-delete conflict.

**Re-examined 2026-09-11, against `PASSPHRASE_LAYER_KEYS.md`/Bug 119 — the pathway that *creates*
`masterPINCollision` goes away; the deeper structural problem does not.** The whole reason this
signal exists is that today's routing works by scanning a small array of stored verifiers — checking
a new PIN candidate against `sealedNormalVerifiers`/`sealedDuressVerifiers` at setup is what turns
"accidental collision" into a detectable event at all, and that only matters because a 6-digit PIN's
1-in-10⁶ accidental-collision odds are worth guarding against. Under `PASSPHRASE_LAYER_KEYS.md`'s
design, authentication is canary-decrypt-success per depth, not array comparison, and each depth
carries its own SE key — two independently-Diceware-generated 7-word phrases colliding is a ~1-in-2⁹⁰
event, not worth a setup-time check at all. No check, no `masterPINCollision`, no oracle to build a
wipe response around. Same mechanism that closes the root scenario and Gap 2.

**But strip away the collision-detection framing and what's actually left in this gap's own "Deeper
structural problem" section is untouched by any of that.** It was never really a guessing-difficulty
question: *if the app ever determines it's looking at the real depth-0 secret, entered by someone who
might be coerced, what should it do?* A higher-entropy secret makes it harder to *stumble onto*; it
does nothing to help the app tell voluntary entry from compelled entry once the real owner has been
directed to type their actual real passphrase and the app faithfully, correctly routes them to depth
0 — which is exactly what it's designed to do. The hard-delete-vs-Bug-13 dead end this section
describes is identical whether the secret is 6 digits or 7 words; it was never a guessing problem
underneath. See Bug 119 for the full accounting.

---

### Residual risk — accidental master PIN discovery

The silent dismiss closes the oracle signal, but does not eliminate a related residual risk: a coercer who accidentally proposes the master PIN as their duress PIN will later be routed to the real layer without realising it.

**What is stored on collision:** nothing. `pinCollision` is thrown before any writes occur. The config is unchanged. No new verifier, no new blob, no new layer.

**What happens on next authentication:** `verify()` scans `sealedNormalVerifiers` from index 0. The proposed PIN matches index 0 (the master PIN slot) and routes to `currentDepth = 0` — the real layer, with all real contacts visible.

The coercer does not know this happened. They entered what they believed was their duress PIN, saw a contact list, and have no mechanism to distinguish depth 0 from a decoy layer they think they created. Immediate deniability is not necessarily broken from the coercer's perspective. However, the real user's sensitive contacts are exposed to someone who stumbled onto the master PIN without realising it.

**Why the silent dismiss does not fully solve this:** the fix removes the signal that would have told the coercer they found something meaningful. It does not prevent the routing consequence. A coercer probing PINs against the oracle (with the alert present) would know when they hit the master PIN. A coercer probing with the alert removed would reach the real layer without realising it — a weaker but non-zero exposure.

**Acceptance criteria:** this risk is proportional to the probability of a 4–6 digit PIN collision by chance. For a 6-digit PIN that probability is 1-in-1,000,000 per attempt; for a 4-digit PIN, 1-in-10,000. In a targeted coercion scenario where the coercer is guessing plausible PINs (birthdays, repeated digits), the probability is higher but still bounded by the PIN space. The risk is accepted as low-probability given the session-scoped rate limit and dummy-blob-slot fixes are implemented.

---

## Bug 63 — Stale blob metadata after full deactivation; `clearBlobSlot(at: 0)` does not cover higher-depth activations

**Stale, 2026-09-11:** `clearBlobSlot` and the blob metadata arrays it describes no longer exist —
deleted whole by Removal Stages 0-4, 2026-09-10.

**Status:** Closed (Fixed)

### Severity: Low (stale metadata)

When the user activates Secure Mode from depth 0 and subsequently activates a second layer from depth 1, two blobs are written: `blobSlots[0]` and `blobSlots[1]`. Full deactivation (depth ≤ 1) called `clearBlobSlot(at: blobDepth)` where `blobDepth = 0`, leaving `blobSlots[1]` and `sequenceNumbers[1]` populated with stale metadata pointing at a file slot that `rewrite()` has already overwritten with random noise. On any future cascade deactivation that tried to pop slot 1, `readBlobSlot(at: 1)` would return the stale index, `pop()` would find random noise, and the graceful fallback would silently return an empty payload — harmless, but untidy.

The same hardcoding existed in `forceDeactivateForRecovery`, which also called `clearBlobSlot(at: 0)` only.

### Note on classification loss

Depth-1 sensitive contacts coming out of full deactivation with `visibleThroughDepth = nil` is **correct** behaviour. Bug 23's invariant — restoring sensitivity markings across deactivation cycles — only applies at depth 0, where only the real user can ever be. At depth 1, the duress PIN is known to the coercer; any classifications made there may be the coercer's. Automatically restoring depth-1 classifications would be restoring potentially-coercer-written data into the real user's next session. The Bug 23 invariant is intentionally not extended to depth > 0.

### Root Cause

`clearBlobSlot(at: blobDepth)` is a per-index clear. In the full deactivation path it was hardcoded to index 0, so any blobs written at higher depths were not cleared. The fix must be unconditional and index-free.

### Resolution

Added `clearAllBlobMetadata()` to `AppLayerConfig`:

```swift
func clearAllBlobMetadata() {
    self.sealedBlobSlots      = Self.randomFillerArray()
    self.layerSequenceNumbers = Self.randomFillerArray()
}
```

This replaces both arrays wholesale with fresh random filler — the same initialisation used at row creation. No indices, no hardcoding; handles any number of activated layers.

In `deactivateSecureMode`, the cleanup block was restructured so that `clearAllBlobMetadata()` is called in the `depth ≤ 1` (full deactivation) branch, while the per-index `clearBlobSlot` / `clearSequenceNumber` calls remain in the `depth ≥ 2` (cascade) branch:

```swift
if depth <= 1 {
    config.clearAllBlobMetadata()
    config.sealedDuressVerifier = nil
    try self.setState(0, config: config)
} else {
    config.clearBlobSlot(at: blobDepth)
    config.clearSequenceNumber(at: blobDepth)
    try self.setState(1, config: config)
}
```

`forceDeactivateForRecovery` updated to use `clearAllBlobMetadata()` in place of `clearBlobSlot(at: 0)` + `clearSequenceNumber(at: 0)`.

---

## Bug 64 — `PINEntry` phase 2 does not reject a duress PIN that matches the confirmed normal PIN

**Status:** Closed (Fixed)

### Severity: Medium (UX)

`PINEntry.submitSetPhase` receives the confirmed normal PIN as `confirmedPIN` and the proposed duress PIN as `pin`. It only checks that both entries of the new PIN match each other — it does not check `pin != confirmedPIN`. If the user enters the same digits for both PINs, `onComplete(normalPIN, pin)` is called with identical values, the flow advances through contact classification, and `activateSecureMode` ultimately throws `pinCollision` at the SummaryView step.

The result (post Bug 62 fix) is a silent dismiss: the sheet closes, Secure Mode is not activated, and the user receives no indication that anything went wrong. They would only discover the failure by noticing that "Deactivate Protection" is absent from Settings.

### Root Cause

`submitSetPhase` in `PINEntry.swift`:

```swift
private func submitSetPhase(pin: String, onComplete: @escaping (String, String) -> Void) {
    guard let normalPIN = self.confirmedPIN else { return }

    if let first = self.firstPIN {
        if pin == first {
            self.hapticResult(.success)
            onComplete(normalPIN, pin)   // no check: pin != normalPIN
        } else { ... }
    } else {
        self.firstPIN = pin
        ...
    }
}
```

Both entries of the duress PIN match, so the equality check passes. The duress-equals-normal case is not caught here.

### Resolution

On the second entry (confirmation pass), before calling `onComplete`, verify `pin != normalPIN`. If they match, reject the same way as a mismatch — clear digits, shake:

```swift
if let first = self.firstPIN {
    if pin == first && pin != normalPIN {
        self.hapticResult(.success)
        onComplete(normalPIN, pin)
    } else {
        self.firstPIN    = nil
        self.clearDigits()
        self.isVerifying = false
        self.shake()
    }
}
```

This catches the collision at the point of entry, where the user can immediately correct it, without reaching SummaryView. It does not cover collisions between the duress PIN and verifiers not visible to `PINEntry` (e.g., a stale duress verifier from a prior cycle), but those cases are forensically acceptable under the Bug 62 silent-dismiss rule — they are rare and the user receives no misleading signal.

---

## Bug 65 — Real-PIN unlock writes all contacts to share index while Secure Mode is active

**Status:** Closed (Fixed)

### Severity: Critical

After entering the real PIN at depth 0, `onAuthenticated` set `shareIndexAllowedIDs = nil` unconditionally, writing every contact — including those classified as sensitive — to `ShareIndex.sqlite`. The Share Extension is a separate process with no authentication gate; it reads the file directly. A coercer who obtained the unlocked device and invoked the share sheet from any app (Photos, Files, etc.) without opening Occulta would see the full real-layer contact list, including contacts the user had explicitly hidden from the duress view.

This is a regression relative to the intent of Bug 6's fix. Bug 6 addressed the `.inactive` / `.active` scene handlers but did not address `onAuthenticated` itself, which is the authoritative write point.

### Root Cause

`onAuthenticated` was written with the assumption that unrestricted access is correct after normal-PIN entry. It did not account for the invariant that the Share Extension is an ambient iOS surface reachable without re-entering Occulta, so the share index must always reflect the duress view when Secure Mode is active — regardless of which depth the main app is authenticated to.

### Resolution

`onAuthenticated` in `OccultaApp.swift` now evaluates `security.isSecureModeActive`:

```swift
self.contactManager.shareIndexAllowedIDs = self.security.isSecureModeActive
    ? self.security.safeContactIDs(atDepth: 1)
    : nil
self.contactManager.syncShareIndex()
```

When Secure Mode is active the share index is always restricted to the depth-1 (duress) view, regardless of the authenticated depth of the main app. When inactive all contacts are written as before.


**Retired by the removal of the share index, 2026-08-16.** The `ShareIndex.sqlite` mirror this entry constrains no longer exists — the recipient picker moved into the main app, behind the PIN gate (Bug 84). The fix described above was correct for the design it was written against; it is recorded here as history, not as live behaviour.
---

## Bug 66 — Scene phase handlers fight PIN-entry share index updates and use wrong depth

**Status:** Closed (Fixed)

### Severity: High

Two scene phase handlers in `OccultaApp` updated the share index redundantly and incorrectly:

**`.inactive` handler** — on every app-going-inactive transition, set `shareIndexAllowedIDs = safeContactIDs(atDepth: 1)` and called `syncShareIndex()`. This was intended as a last-resort pre-filter before the Share Extension became reachable, but it fires only when Occulta itself triggers the scene transition. A coercer who invokes the share sheet while Occulta is already backgrounded bypasses this handler entirely — the file already has whatever `onAuthenticated` last wrote. With Bug 65's fix in place, `onAuthenticated` always writes the correct restricted view, making this handler redundant.

**`.active` handler** — on every foreground return, applied hardcoded `atDepth: 1` for both the locked (`needsPINEntry = true`) and restricted (`isRestricted = true`) states, then called `syncShareIndex()`. Two problems:

1. **Wrong depth when `isRestricted`**: at `currentDepth = 2`, `safeContactIDs(atDepth: 1)` returns contacts with `visibleThroughDepth >= 1`, which includes contacts that were hidden at depth 2 (`visibleThroughDepth = 1`). These contacts leak into the share index.

2. **Conflicts with PIN entry**: `onAuthenticated` and `onDuress` set the correct state after authentication. The `.active` handler fired on every foreground return — including grace-period re-foregrounds — and overwrote the correct PIN-entry state with the hardcoded depth-1 result. At `currentDepth = 2`, `onDuress` correctly wrote `safeContactIDs(atDepth: 2)`; the next grace-period foreground overwrote it with `safeContactIDs(atDepth: 1)`, re-exposing depth-2-hidden contacts.

### Root Cause

The share index was treated as something to be corrected reactively at scene boundaries rather than maintained proactively at the points where security state actually changes (PIN entry, Secure Mode activation/deactivation). The scene handlers were a compensating patch for the missing updates in those canonical locations.

### Resolution

Both handlers' share index logic removed. The `.active` handler retains `cleanupPendingSessions()`, which genuinely belongs there. The `.inactive` handler is now empty. Share index correctness is owned entirely by `onAuthenticated`, `onDuress`, `activateSecureMode`, and `deactivateSecureMode`.


**Retired by the removal of the share index, 2026-08-16.** The `ShareIndex.sqlite` mirror this entry constrains no longer exists — the recipient picker moved into the main app, behind the PIN gate (Bug 84). The fix described above was correct for the design it was written against; it is recorded here as history, not as live behaviour.
---

## Bug 67 — `activateSecureMode` and `deactivateSecureMode` do not sync share index

**Status:** Closed (Fixed)

### Severity: High

Neither `activateSecureMode` nor `deactivateSecureMode` updated `shareIndexAllowedIDs` or called `syncShareIndex()` after completing. Two consequences:

**Activation mid-session**: user is at depth 0 with no Secure Mode. `onAuthenticated` wrote `shareIndexAllowedIDs = nil` (Bug 65). The user then activates Secure Mode and classifies contacts as sensitive. `activateSecureMode` completes successfully but does not update the share index. `shareIndexAllowedIDs` remains `nil`. Any subsequent contact mutation calls `syncShareIndex()` with `nil`, writing all contacts — including the newly-classified sensitive ones — to the file. The Share Extension shows the full contact list for the remainder of the session.

**Deactivation mid-session**: after `deactivateSecureMode` (full path, depth ≤ 1), the share index retained the depth-1 restricted view set by `onAuthenticated`. All contacts are restored to the DB and should be visible in the share sheet, but the stale restricted filter prevented newly-restored contacts from appearing.

### Root Cause

Both functions received `contactManager` as a parameter (for contact re-encryption) but did not use it to update the share index. The update responsibility was implicitly left to the scene phase handlers, which is insufficient for mid-session state changes.

### Resolution

Both functions call `contactManager.shareIndexAllowedIDs = ...` and `contactManager.syncShareIndex()` after their final `modelContext.save()`:

- `activateSecureMode`: `safeContactIDs(atDepth: max(self.currentDepth, 1))` — restricts to at least the depth-1 view immediately after activation.
- `deactivateSecureMode` (full path): corrected in Bug 68 below.


**Retired by the removal of the share index, 2026-08-16.** The `ShareIndex.sqlite` mirror this entry constrains no longer exists — the recipient picker moved into the main app, behind the PIN gate (Bug 84). The fix described above was correct for the design it was written against; it is recorded here as history, not as live behaviour.
---

## Bug 68 — `deactivateSecureMode` cascade path sets `shareIndexAllowedIDs = nil` while Secure Mode remains active

**Status:** Closed (Fixed)

### Severity: Critical

`deactivateSecureMode` always sets `contactManager.shareIndexAllowedIDs = nil` after completing, regardless of which deactivation path ran. The full-deactivation path (depth ≤ 1) produces `isSecureModeActive = false` and `currentDepth = 0` — `nil` is correct there. The cascade-deactivation path (depth ≥ 2) strips only the expendable top layer, leaving `isSecureModeActive = true` and landing at `currentDepth = 1`. Setting `nil` on this path writes all contacts to the share index, including contacts with `visibleThroughDepth = 0` that are hidden from the depth-1 view. The Share Extension immediately exposes those contacts.

### Example

User has three layers (real at depth 0, duress at depth 1, expendable at depth 2). Contact A has `visibleThroughDepth = 0` — hidden from the coercer. User authenticates at depth 2 and calls `deactivateSecureMode`. Cascade runs, lands at depth 1. Share index is written with `nil` → Contact A is now in the share extension. A coercer who opens any app's share sheet can see Contact A despite the duress layer being intact.

### Root Cause

The `nil` assignment was written as if deactivation always terminates Secure Mode. The two branches (`depth ≤ 1` / `depth ≥ 2`) were correctly distinguished for verifier cleanup and state transitions but not for the share index update.

### Resolution (pending)

Apply the same conditional used everywhere else:

```swift
contactManager.shareIndexAllowedIDs = self.isSecureModeActive
    ? self.safeContactIDs(atDepth: max(self.currentDepth, 1))
    : nil
contactManager.syncShareIndex()
```

After full deactivation: `isSecureModeActive = false` → `nil` ✓  
After cascade deactivation: `isSecureModeActive = true`, `currentDepth = 1` → `safeContactIDs(atDepth: 1)` ✓


**Retired by the removal of the share index, 2026-08-16.** The `ShareIndex.sqlite` mirror this entry constrains no longer exists — the recipient picker moved into the main app, behind the PIN gate (Bug 84). The fix described above was correct for the design it was written against; it is recorded here as history, not as live behaviour.
---

## Bug 69 — Cold launch with `pinEnabled = false, isSecureModeActive = true` leaves share index uninitialized

**Status:** Closed (Fixed)

### Severity: High

`disablePIN(at:confirmingPIN:)` sets `pinEnabled = false` while leaving `isSecureModeActive = true` and `currentDepth` unchanged — the intended coercion path where the PIN gate is lowered but depth-filtering remains active. On the next cold launch, `AppScreen.evaluate(coldLaunch: true)` checks `security.requiresPIN && security.pinEnabled`; with `pinEnabled = false` it skips the PIN gate and transitions directly to `.unlocked`. `onAuthenticated` never fires.

`shareIndexAllowedIDs` defaults to `nil` (in-memory) on every cold launch. Since no authentication event initialises it, it stays `nil`. The share index file on disk retains whatever was last written — correct from the previous session. However, the first contact mutation after this cold launch calls `syncShareIndex()` with `shareIndexAllowedIDs = nil`, overwriting the file with all contacts. Contacts hidden from the depth-1 view (`visibleThroughDepth = 0`) are written to the share index. A coercer who causes or waits for any contact mutation (background sync, incoming key rotation, any save) then opens the share sheet sees the full contact list.

### Root Cause

`onAuthenticated` is the only place that initialises `shareIndexAllowedIDs` based on security state. When it does not fire (no PIN gate), there is no fallback initialiser. The scene phase `.active` handler previously served as that fallback (and was the original motivation for the redundant sync identified in Bug 66), but it was removed as part of Bug 66's fix.

### Resolution (pending)

Add share index initialisation to the startup path taken when `pinEnabled = false`. The earliest safe point is inside `AppScreen.evaluate(coldLaunch:)` in the `guard security.requiresPIN, security.pinEnabled` early-return path, or equivalently in the `OccultaApp` observer of `appScreen.phase` transitioning to `.unlocked` without a PIN entry cycle. The initialisation logic is identical to `onAuthenticated`:

```swift
contactManager.shareIndexAllowedIDs = security.isSecureModeActive
    ? security.safeContactIDs(atDepth: max(security.currentDepth, 1))
    : nil
contactManager.syncShareIndex()
```

`currentDepth` is correctly restored from `AppLayerConfig.persistedDepth` in this path (per Bug 50's fix), so `safeContactIDs(atDepth:)` will produce the correct set.

### Resolution

Share index initialisation added to the no-PIN cold-launch path. When `AppScreen` transitions to `.unlocked` without a PIN entry cycle (`pinEnabled = false`), the observer in `OccultaApp` initialises `shareIndexAllowedIDs` using the same conditional as `onAuthenticated`:

```swift
contactManager.shareIndexAllowedIDs = security.isSecureModeActive
    ? security.safeContactIDs(atDepth: max(security.currentDepth, 1))
    : nil
contactManager.syncShareIndex()
```

`currentDepth` is correctly restored from `persistedDepth` at this point (Bug 50), so `safeContactIDs` produces the correct depth-filtered set before any contact mutation can trigger a sync.


**Retired by the removal of the share index, 2026-08-16.** The `ShareIndex.sqlite` mirror this entry constrains no longer exists — the recipient picker moved into the main app, behind the PIN gate (Bug 84). The fix described above was correct for the design it was written against; it is recorded here as history, not as live behaviour.
---

## Bug 70 — Lockout counter reset to zero via iTunes/Finder backup restore

**Stale, 2026-09-11:** Fix 2's `AppLayerConfig.reencrypt(from:to:)` no longer exists — deleted along
with all rotation, Removal Stages 0-4, 2026-09-10. Moot for a stronger reason than the entry states:
there is no rotation left to carry lockout fields through.

**Status:** **Fixed, re-examined and closed 2026-08-26.** Fix 2 (carry lockout fields through
rotation) is implemented and was independently unnecessary; see "Reconciled 2026-08-15" at the
bottom of this entry. **Fix 1 (backup exclusion) was already implemented** —
`RootView.excludeStoreFromBackup(url:)` has shipped since `a320e3b` (2026-06-09), called at init
and on every save, using `isExcludedFromBackup`, Apple's standard mechanism that covers both iCloud
and local iTunes/Finder backups; no separate entitlement needed. What was actually missing was
verification, not code: zero automated coverage existed. `OccultaTests/BackupExclusionTests.swift`
now covers it — the store file gets excluded, both `-wal`/`-shm` sidecars get excluded when present,
and a sidecar created *after* the first call still ends up covered once the function runs again
(the exact recovery `reapplyFileProtection()` depends on for SQLite-recreated sidecars). A real
iTunes/Finder backup-and-restore cycle is out-of-process and not exercisable from a unit test; these
tests pin the contract the fix actually relies on instead.

### Severity: High

An adversary with brief physical access to an unlocked trusted Mac can:

1. Back up the device via iTunes/Finder before any PIN attempts.
2. Begin brute-forcing the PIN until lockout fires.
3. Restore from the pre-attempt backup.
4. Repeat — the lockout counter is gone on every restore.

The 10⁶ keyspace of a 6-digit PIN is the only protection once this loop is available. At one attempt per restore cycle an adversary with sustained access over hours can exhaust a significant fraction of the space.

### Root Cause

`lockoutCountEncrypted` and `lockoutExpiryEncrypted` live in `AppLayerConfig`, which is stored in the SwiftData database. The database is included in iTunes/Finder backups. A restore replaces the entire database file, reverting the lockout fields to whatever state existed at backup time.

The SwiftData store is excluded from iCloud backup (`isExcludedFromBackup = true`) but **not** from local (wired) iTunes/Finder backups. `URLResourceValues.isExcludedFromBackup` excludes a file from both iCloud and local backups. The fix applied in commit `a320e3b` set this flag on the store and its WAL/SHM sidecars. If that flag is being applied correctly, this vector is already closed; if not (e.g. the flag is lost after iOS re-creates a sidecar), it remains open.

A second, independent path: key rotation in `activateSecureMode` and `deactivateSecureMode` re-encrypts contact and vault fields under the staged key but does not re-encrypt `lockoutCountEncrypted` or `lockoutExpiryEncrypted`. After rotation those fields are encrypted under the superseded canonical key and decode as `return 0` / `return nil` (see `AppLayerConfig+Model.swift` fallback). An in-progress lockout is silently reset by any activation or deactivation cycle. This angle is independent of backup and is documented in the repo audit as SEC-2.

> **Stale as of 2026-08-15 — do not act on this paragraph.** The rotation does re-encrypt both
> fields, the second field is not called `lockoutExpiryEncrypted`, and there is no in-progress
> lockout at rotation time to reset. See "Reconciled 2026-08-15" below. The backup path in the
> symptom above is unaffected and remains the live half of this bug.

### Resolution — both fixes done as of 2026-08-26

Two independent fixes were required; both are now in place.

**1. `isExcludedFromBackup` covers local backups — confirmed, not just assumed.** It's Apple's
standard resource value, documented to exclude a file from both iCloud and local (wired)
iTunes/Finder backups with no separate entitlement — so there was never a real ambiguity here to
resolve by API choice. `excludeStoreFromBackup(url:)` (`a320e3b`) applies it to the store and its
`-wal`/`-shm` sidecars, called at `RootView` init and on every `reapplyFileProtection()`. What had
never been done was writing it down as a verified contract: `OccultaTests/BackupExclusionTests.swift`
(2026-08-26) now asserts the flag actually lands on all three files, including the case where a
sidecar is created *after* the first call — matching why `reapplyFileProtection()` re-invokes this
on every save instead of once at launch.

**2. Carry lockout fields through key rotation — done, and shown unnecessary.** See "Reconciled
2026-08-15" below: `AppLayerConfig.reencrypt(from:to:)` already reseals both fields as a side effect
of the Bug 76 sweep, and it turns out no rotation can ever observe an in-progress lockout in the
first place, since `verify()` resets the counters on every match and blocks before any verifier scan
while a lockout delay is outstanding.

### Reconciled 2026-08-15 — fix 2 is done, was never needed, and named a field that no longer exists

Three separate documents disagreed about this half of the bug. Resolved by reading the code rather
than by picking between them; **fix 1 is the entire remaining scope of Bug 70.**

**Fix 2 is implemented.** `AppLayerConfig.reencrypt(from:to:)` reseals both lockout fields
(`AppLayerConfig+Model.swift:314-315`), so they are carried through every rotation. It arrived in
`182920b` on `release/v1.10.2` — the **Bug 76** fix — which re-keyed `AppLayerConfig` wholesale and
picked these up as part of that sweep. Nobody fixed Bug 70; Bug 76 covered it in passing, which is
why no document records it.

**Fix 2 was also unnecessary, and `SecurityReview2026-07-24` item #7 was right to retract it** —
though for a reason worth stating more precisely than the retraction did. Every rotation path is
gated behind a successful PIN verification, and `verify()` calls `resetCounters()` on every match
(`Manager+Security.swift:1135` normal, `:1145` duress). A lockout in progress cannot coexist with a
rotation either, because `verify()` returns `.locked(until:)` before reaching any verifier scan while
the delay is outstanding (`:1121-1124`). So at the moment any rotation runs, both fields are already
zero by construction. There has never been an in-progress lockout for a rotation to preserve.

**Both this entry and the retraction name `lockoutExpiryEncrypted`, which does not exist.** The field
is `lockoutAnchorUptimeEncrypted` — a boot-anchored monotonic value, not a wall-clock expiry. It was
renamed by the **SEC-1** fix (2026-08-05) that closed the clock-rollback bypass, which is the same
audit item this entry's own root cause section cites. A `grep` for the old name returns nothing,
which is the confusing way to discover this.

**What this did not touch, as of 2026-08-15 — since closed.** Rotation carrying the fields correctly
was always irrelevant to an adversary who replaces the whole database file with an earlier copy —
that's fix 1's territory, not fix 2's. At the time this was written fix 1 was implemented but had no
test confirming it; see *Resolution* above for the 2026-08-26 close.

---

## Bug 71 — Layer store file modification timestamp correlates with activation events

**Stale, 2026-09-11:** `LayerStore`/`.occbak` for Secure Mode no longer exist — the file-timestamp
correlation this bug describes has no current subject. Deleted whole by Removal Stages 0-4,
2026-09-10; re-examine if a similar mechanism is ever rebuilt.

**Status:** Open — **mitigation 2 (cadence jitter) implemented 2026-08-15**; mitigation 1
(opportunistic writes) still open. See "Implementation status" at the bottom.

### Severity: Low (forensic)

The layer store file (`<uuid>.occbak`) is rewritten on every `push()` and `pop()` call — activation, deactivation, and `maintain()`. Its filesystem modification timestamp therefore correlates with significant security state transitions. A forensic examiner who captures a filesystem image at two points in time can infer:

- Whether Secure Mode was activated or deactivated between the captures (timestamp changed unexpectedly relative to the 24-hour maintenance cadence).
- Approximately when the event occurred.

`maintain()` rewrites the file every 24 hours to provide cover: routine timestamps mask activation events that land within the same window. However, if the examiner's first capture predates an activation that occurred less than 24 hours before the second capture, the out-of-cadence timestamp is distinguishable from a normal maintenance write.

### Root Cause

AES-GCM re-sealing all 32 slots on every write is intentional (freshens nonces, prevents slot-position inference). A write cannot be avoided. The only variable is how distinguishable the write's timestamp is from background activity.

### Resolution (pending)

Two complementary mitigations:

**1. Opportunistic maintenance writes.** In addition to the 24-hour cadence, trigger a no-op `maintain()` write at unpredictable intervals during normal app use (e.g., on contact save, on app foreground after a random back-off). This increases background write density, making any single write less distinguishable.

**2. Jitter the 24-hour cadence.** Replace the fixed `86_400 s` threshold in `LayerStore.maxAge` with a randomised window (e.g., 18–30 hours) so the maintenance cadence itself is not fingerprintable.

Both mitigations reduce the signal strength; neither eliminates it. The residual risk — a write occurred, time unknown within the jitter window — is acceptable given that the file content is cryptographically opaque.

### Implementation status — 2026-08-15

**Mitigation 2 (jitter) is implemented.** `Manager.LayerStore.maxAge` is now
`.random(in: 18 * 3_600 ... 30 * 3_600)` instead of a fixed `86_400`
(`SecureMode+LayerStore.swift`). Covered by `LayerStoreMaintenanceTests` — window bounds,
in-process stability, and that `maintain()` honours the threshold in both directions.

**One design point worth recording, because the obvious implementation is wrong.** The draw is a
`static let`, evaluated **once per process**, not per `maintain()` call. `maintain()` runs on every
foreground, so a fresh draw each time would let the *lowest* draw win — with a handful of calls
between hour 18 and hour 30, the write lands near the 18 h floor almost every time and the jitter
window collapses to a point. Per-launch keeps the whole window in play.

**A deterministic derivation was considered and rejected.** Deriving the threshold from the file's
own mtime would make it stable across calls without any per-process state, which is tidier — but it
hands the examiner the threshold too, since they hold the mtime. They could then compute exactly when
the next maintenance write was due and flag anything early as an activation. That defeats the entire
purpose; the property needed is unpredictability *to the examiner*, not merely variation.

**Mitigation 1 (opportunistic writes) is not implemented**, so the residual is larger than the final
design intends: writes still cluster around the maintenance cadence rather than being buried in
general write density. The jitter widens the window an examiner must accept; it does not add cover
traffic.

---

## Bug 72 — `randomSlot(excluding:)` has negligible modular bias

**Stale, 2026-09-11:** Cites `SecureMode+LayerStore.swift`, which no longer exists — deleted whole by
Removal Stages 0-4, 2026-09-10.

**Status:** Open

### Severity: Negligible (informational)

`randomSlot(excluding:)` in `SecureMode+LayerStore.swift` selects a slot index using:

```swift
let value = Int(raw[0]) | (Int(raw[1]) << 8) | (Int(raw[2]) << 16) | (Int(raw[3]) << 24)
return pool[abs(value) % pool.count]
```

`value` is a 32-bit value drawn uniformly from `[0, 2^32)`. `abs(value) % pool.count` introduces modular bias when `pool.count` does not evenly divide `2^32`. For a pool of 30 slots (32 minus 2 excluded), the bias per slot is `(2^32 mod 30) / 2^32 = 16 / 4_294_967_296 ≈ 3.7 × 10⁻⁹`. This is cryptographically negligible.

### Root Cause

Modular reduction of a uniform random integer when the modulus does not divide the sample space.

### Resolution (optional)

Replace with a rejection-sampling loop to eliminate bias entirely:

```swift
func randomSlot(excluding excluded: Set<Int> = []) -> Int {
    var pool = Array(Set(0..<Self.slotCount).subtracting(excluded))
    pool.sort()
    var raw = [UInt8](repeating: 0, count: 4)
    repeat {
        _ = SecRandomCopyBytes(kSecRandomDefault, 4, &raw)
    } while UInt32(raw[0]) | (UInt32(raw[1]) << 8) | (UInt32(raw[2]) << 16) | (UInt32(raw[3]) << 24)
           >= UInt32.max - (UInt32.max % UInt32(pool.count))
    let value = Int(UInt32(raw[0]) | (UInt32(raw[1]) << 8) | (UInt32(raw[2]) << 16) | (UInt32(raw[3]) << 24))
    return pool[value % pool.count]
}
```

---

## Bug 73 — Group duress membership shared across all duress depths, breaking multi-layer decoys

**Status:** Closed (Fixed) — implemented and verified on `release/v1.9.1` (34/34 Group tests passing, including new regression coverage for depth-1/2/3 independence). ~~Not yet committed/pushed.~~ **Corrected 2026-08-15:** committed as `8924df6` and merged to `develop` via `aee66b9` (PR #64). The trailing sentence had been left as written at the time of the fix and read, months later, as though the work were still sitting uncommitted.

**Target:** v1.9.1

### Severity: Medium

`USER_GUIDE.md` documents multi-layer duress as a deliberate, user-facing feature: each duress
depth is meant to hold "a completely different set of fake contacts designed to convince someone
who knows what [the shallower layer] looks like." Individual contacts support this correctly —
`visibleThroughDepth` is a numeric depth, so a contact can be configured to appear at depth 0–1
and vanish at depth 2+.

Groups do not. `Group+Model.swift` stores membership in exactly two arrays, `realMemberSlots` and
`duressMemberSlots`, keyed by the two-case `RoutingDepth` enum (`.normal` / `.duress`). Both
`GroupDetailV3.swift` and `Group+FormV3.swift` resolve the active layer with:

```swift
switch self.security.currentDepth {
case 0:          return .normal
case let d where d > 0: return .duress
default:         return nil
}
```

Every duress depth — 1, 2, 3, however many the user has created — reads and writes the same
`duressMemberSlots` array. There is no per-depth storage for group membership the way there is
for contacts via `visibleThroughDepth`.

### Impact

A user who builds a Depth‑1 decoy group with members [A, B], is later coerced into Depth 2 (per
the guide's own multi-layer scenario), and edits that group's membership to the "completely
different" decoy set the guide instructs them to create — say [C, D] — does not create a second,
independent list. They overwrite the group's only duress array. The Depth‑1 decoy, previously
built to fool a first interrogator, now silently shows [C, D] the next time that depth is
entered. There is no warning anywhere in the UI that editing group membership at one duress depth
affects every other duress depth.

This is not a hypothetical: it directly breaks the multi-layer guarantee the app documents and
markets to users ("Depth 2 is a completely different set of fake contacts... designed to convince
someone who knows what Depth 1 looks like").

### Scope note

Out of scope for this fix: the `Group` model's dual real/duress array design (padding, shuffling,
per-slot AES-GCM sealing) does not itself need to change — it already mirrors the forensic
indistinguishability properties used elsewhere in Secure Mode. The fix is to key membership
storage by depth (N padded slots of member-lists, mirroring the pattern `AppLayerConfig` already
uses for `sealedDuressVerifiers` / `sealedBlobSlots`) instead of the binary `RoutingDepth` split,
and to update the two `switch self.security.currentDepth` call sites above to resolve the actual
depth rather than collapsing every depth > 0 into `.duress`.

Multi-device contacts (`Docs/Features/Multi-Device Contacts/FINDINGS.md`) is a separate,
unrelated piece of work targeting a later release — not a prerequisite or blocker for this fix.

### Root Cause

`RoutingDepth` (`AppLayerConfig+Model.swift:13`) was defined with only two cases before multi-layer
duress (arbitrary depth N) existed as a user-facing feature. `Group+Model.swift`'s member-storage
API was built against that two-case enum and never revisited when `AppLayerConfig` itself moved to
N-depth-aware storage (`sealedDuressVerifiers[N]`, `coercerBaseDepth`, per-contact
`visibleThroughDepth: Int`) for the coercer re-enable design (Bugs 37, 47, 48). The Secure Mode
72-bug audit predates the group real/duress split entirely — `scenarios.md` and `bugs.md` have no
prior mention of groups — so this interaction was never analyzed.

Given the negligible magnitude, this is low priority and can be deferred.

---

## Bug 74 — Eager `deeperMemberSlots` migration caused launch crash/freeze; reverted to lazy-only

**Status:** Closed (Reverted) — v1.9.1 shipped with the eager migration; a follow-up patch removes it. **Confirmed landed 2026-08-15:** `654aaba`, "Revert eager group deeper-slot migration — caused launch crash and freeze". Note this removed only the *eager migration*; `deeperMemberSlots` itself is intact and correct (`Group+Model.swift:50`), since it is the Bug 73 mechanism. Migration remains lazy-only, which is the state the Decision section below settled on.

**Target:** v1.9.2 (or next patch)

### Severity: High (crash), for affected users

### What happened

Bug 73's fix (depth-indexed group membership, `deeperMemberSlots` for duress depths 2+) included
an eager migration (`OccultaApp.migrateGroupDeeperSlots()`) that swept every stored `Group` at
launch and called `refreshCiphertext()` on each — re-encrypting all 32 depths x 32 slots per
group — so that a group nobody edits after upgrading wouldn't keep a distinguishable (unpadded)
row shape indefinitely (see the "Multi-Layer Membership" forensic note this was meant to close).

In production, this caused a real crash for any user with existing groups: `Manager.Crypto`'s
`.encrypt()`/`.decrypt()` re-derive the local DB key from scratch on every single call (multiple
Secure Enclave + Keychain round trips each, no caching — see `Key+Manager.swift:432`
`createHybridLocalEncryptionKey()`), and doing this for up to 1024 slots per group, synchronously
inside `OccultaApp.init()` (before the first frame is presented), exhausted iOS's ~20s
process-launch watchdog budget:

```
Termination Reason: FRONTBOARD ... 0x8BADF00D "process-launch watchdog transgression:
... exhausted real (wall clock) time allowance of 20.00 seconds"
```

Confirmed via a real device crash log, stack sitting in `migrateGroupDeeperSlots ->
Group.refreshCiphertext -> Data.decrypt -> SecItemCopyMatching`, blocked on `securityd` IPC.

### Fix attempts before reverting

1. Moved the migration out of `init()` into a `.task` on the root view, gated behind a
   one-time-completion `UserDefaults` flag. This stopped the crash but not a ~15s UI freeze right
   after launch, because SwiftUI runs a plain `.task { }` closure on the calling view's actor
   (main) — so the work was still on the main thread, just after first frame instead of before it.
2. Moved to a genuinely backgrounded `Task.detached`, with its own dedicated `ModelContext` (to
   avoid racing `ContactManager`'s shared context, which the UI also uses on the main thread).
   This still didn't fix the freeze: the Secure Enclave is a single physical resource. Regardless
   of which thread issues the requests, the migration's flood of SE/Keychain round trips queues up
   behind (or ahead of) the main thread's own decrypt calls (e.g. rendering the contact list),
   which need the same hardware. Threading the caller doesn't parallelize the chip.

### Decision

Reverted the eager migration entirely. `Group+Model.swift`'s actual Bug 73 fix (depth-indexed
storage, `ensureDeeperSlotsPadded()` running lazily on a group's first post-upgrade edit) is
unaffected and stays as the sole mechanism — this is the same lazy-only behavior the codebase
already used successfully for the analogous `AppLayerConfig.ensurePadded()` case.

The residual forensic gap (a pre-1.9.1 group nobody edits after upgrading keeps an empty,
distinguishable `deeperMemberSlots` until its first edit) is accepted for now: group messaging
only shipped in v1.9.0, one release prior, so very few users have groups at all yet, and fewer
still have groups that both predate 1.9.1 and go untouched afterward. Considered not worth a
launch-time performance/stability risk to close immediately.

### Revisit later if

- Group adoption grows enough that the residual gap's exposed population becomes meaningful.
- A cheap way to close it is found that doesn't require touching every group's full ciphertext
  eagerly — e.g. a lighter migration that only touches groups actually missing padding (accepting
  the narrower "which specific groups changed" tell that the full-touch design was avoiding), or
  spreading the sweep across many launches instead of one.

---

## Bug 75 — `Group` rows are never re-keyed during Secure Mode key rotation; all groups become permanently unreadable after activation

**Stale, 2026-09-11:** `Group.reencrypt(from:to:)` and the rotation call sites this bug's fix touched
no longer exist — deleted whole by Removal Stages 0-4, 2026-09-10. (Its repair path,
`ContactManager.purgeUnreadableGroups`, survives for unrelated reasons.)

**Status:** Fixed on `release/v1.10.2` (commit 182920b), pushed.

- **Root cause:** `Group.reencrypt(from:to:)` re-keys every field (ID, name, created-at, and all
  32 depths of member slots), called from both rotation paths — activation Step 8 after the draft
  pass, and a new deactivation Step 6b. 6 tests in `GroupKeyRotationTests.swift`, full
  `OccultaTests` target green.
- **Existing orphaned rows:** repaired. `ContactManager.purgeUnreadableGroups(using:)` deletes
  rows whose ID no longer decrypts, called from `RootView`'s `.task` at depth 0 only. Silent by
  design. 4 tests in `GroupOrphanPurgeTests.swift`.

**Target:** v1.10.2

### Severity: Critical — unrecoverable user data loss, plus a forensic tell

### Reported symptom

Device had 3 groups (2 empty, 1 containing 2 contacts classified sensitive). After activating
Secure Mode and re-entering with the **normal** PIN — i.e. at depth 0, the real layer, not under
duress — the Groups tab shows no group rows at all, only the footer label:

> `3 groups · encrypted at rest`

### Observed vs expected

| | Expected at depth 0 | Observed |
|---|---|---|
| Group rows | All 3 listed by name | None |
| Footer count | `3 groups` | `3 groups` |
| Group membership | Real-layer members visible | Unreachable |
| Recovery by deactivating Secure Mode | Groups return | Groups do **not** return |

The footer and the list disagree because they are computed from different things.
`ContactsListV2.sortedGroups` is **not** depth-filtered — it returns all 3 stored `Group` rows, so
`sorted.count` is 3 and the footer prints "3 groups"
([ContactsListV2.swift:86](Occulta/UI/Tabs/Contacts/v2/ContactsListV2.swift:86)). Each row,
however, is gated on a successful decrypt:

```swift
ForEach(sorted) { group in
    if let groupID = group.readID() {   // ContactsListV2.swift:77
        NavigationLink(value: groupID) { GroupRowV2(group: group) }
    }
}
```

`readID()` returns `nil` for every group, so `ForEach` emits zero rows. The count label is the only
surviving evidence that the groups exist. This is a precise match for the reported symptom, and it
explains why *all three* groups vanished including the two empty ones — the failure has nothing to
do with membership or with the sensitivity of the 2 contacts in the third group.

### Root Cause

`Group` stores every field under the **hybrid local DB key**: `encryptedID`, `encryptedName`,
`encryptedCreatedAt` via the bare `Data.encrypt()`/`.decrypt()` helpers
([Crypto+Manager.swift:53](Occulta/Services/Crypto+Manager.swift:53)), and all member slots
(`realMemberSlots`, `duressMemberSlots`, `deeperMemberSlots` — up to 32 depths × 32 slots) via
`Manager.Key().createHybridLocalEncryptionKey()`
([Group+Model.swift:162](Occulta/Data Models/Group+Model.swift:162)).

`activateSecureMode` rotates that key. Step 8 re-encrypts everything it knows about under the
staged key, and the enumeration is exhaustive — and does not include `Group`:

- `Contact.Profile` — `reencryptAllFields` / `reencryptKeyRecords`
  ([Manager+Security.swift:543-546](Occulta/Features/SecureMode/Manager+Security.swift:543))
- `VaultEntry.visibleThroughDepth`
  ([Manager+Security.swift:560](Occulta/Features/SecureMode/Manager+Security.swift:560))
- `Message.Draft` — `reKeyOrPurgeAll`
  ([Manager+Security.swift:577](Occulta/Features/SecureMode/Manager+Security.swift:577))

Step 9 then commits the staged key, and Step 11 calls `deleteSupersededLocalDBArtefacts()`
([Manager+Security.swift:604](Occulta/Features/SecureMode/Manager+Security.swift:604)), which
deletes **both** halves of the pre-rotation hybrid key — the superseded Secure Enclave private key
and its Keychain random component
([Key+Manager.swift:1112](Occulta/Services/Key+Manager.swift:1112)).

Every `Group` row is therefore left sealed under a key that no longer exists anywhere on the
device. Grep confirms the omission is total — there is no `Group` re-encryption anywhere in the
codebase. The only two `FetchDescriptor<Group>` sites inside `Manager+Security.swift` (lines 574
and 1130) merely *read* group IDs to feed `Message.Draft` purging; neither writes a group.

### Why this is permanent, and why deactivation does not fix it

`deactivateSecureMode` is a mirror of activation and has the identical omission: it re-encrypts
`Contact.Profile` ([:806](Occulta/Features/SecureMode/Manager+Security.swift:806)), restores blob
contacts ([:837](Occulta/Features/SecureMode/Manager+Security.swift:837)), re-encrypts
`VaultEntry.visibleThroughDepth` ([:853](Occulta/Features/SecureMode/Manager+Security.swift:853)),
then commits and deletes superseded artefacts
([:889](Occulta/Features/SecureMode/Manager+Security.swift:889)). `Group` is absent there too.

Deactivation also stages a **new** key rather than restoring the pre-activation one, so "reverse
rotation" is only reverse in the sense of unwinding the blob — it does not resurrect the deleted
key material. There is no recovery path: the ciphertext is intact in SQLite and cryptographically
unrecoverable. Group names, IDs, creation dates, and all real- and duress-layer membership for
every group created before the first activation are gone.

### The dead rows cannot be deleted through the UI

Every entry point to a group resolves it by `readID()`:

- `ContactsListV2.swift:77` — the `NavigationLink` (list has no `.onDelete`)
- `GroupDetailV3.swift:37` and `Group+FormV3.swift:45` — detail/edit lookups
- `ContactManager.group(withID:)`
  ([Contact+Manager+Groups.swift:96](Occulta/Services/Contact+Manager+Groups.swift:96)), which
  backs `deleteGroup(id:)` and so silently no-ops for an undecryptable group

Delete is only reachable from `Group.FormV3(mode: .edit(...))`, which is only reachable from
`GroupDetailV3`, which is only reachable from the `readID()`-gated `NavigationLink`. The user is
left with an un-openable, un-deletable, permanent "3 groups" label. Any fix must therefore include
a purge path for already-orphaned rows, not just the missing re-key.

### Secondary cascades

1. **Group drafts get purged on the next duress entry.** `purgeDraftsNotSafeAtCurrentDepth`
   ([Manager+Security.swift:1129](Occulta/Features/SecureMode/Manager+Security.swift:1129))
   builds `allGroupIdentifiers` from `readID()`, which now yields an empty set. In
   `Message.Draft.reKeyOrPurgeAll`, a draft survives only if its recipient is in
   `allGroupIdentifiers` or `safeContactIdentifiers`
   ([Message+Draft.swift:245](Occulta/Data Models/Message+Draft.swift:245)) — so every
   group-addressed draft is deleted.
2. **Membership is overwritten with empty slots on the next classification or contact deletion.**
   `cleanUpGroupDuressMembership`
   ([ContactManager+Classification.swift:208](Occulta/Services/ContactManager+Classification.swift:208))
   and `ContactManager`'s delete path
   ([Contact+Manager.swift:495](Occulta/Services/Contact+Manager.swift:495)) call
   `refreshCiphertext` / `purgeMember`, which re-source each depth's plaintext from
   `members(atDepth:usingKey:)`. That now returns `[]` for every depth, so
   `reencryptAllDepths` writes 32 depths of pure random filler under the **new** key — destroying
   the original ciphertext at the raw-SQLite level as well, which forecloses even a
   theoretical forensic recovery.
3. **Group messaging is dead.** `Crypto+Manager+GroupEncrypt` cannot resolve a group ID or its
   members, so no group bundle can be composed for any pre-existing group.

### Forensic-trace violation

Beyond the data loss, this is a tell that Secure Mode was used. A raw-SQLite examiner holding the
current canonical local DB key (i.e. anyone who has coerced the device open at any depth) sees
every `Contact.Profile`, `VaultEntry`, and `Message.Draft` decrypt cleanly while every `Group` row
fails authentication under the same key. Ciphertext that no live key can open, sitting alongside
ciphertext that opens fine, is direct evidence that a key rotation occurred — and in this app the
only thing that rotates the local DB key is Secure Mode activation. The whole design goal is that
an examiner cannot tell activation ever happened. Cascade 2 above eventually erases this specific
tell by overwriting the rows with new-key filler, but only after an unrelated classification or
contact deletion happens to run.

### Fix sketch (not implemented)

1. ~~Add a two-key re-encryption method to `Group`.~~ **Done** — `reencrypt(from:to:)`. Member
   slots route through the existing `reencryptAllDepths(usingKey:content:)`, whose `content`
   closure reads with the old key while the writes seal with the new one; that is safe because
   each depth's plaintext is read before that depth's slots are reassigned, the property
   `refreshCiphertext(usingKey:)` already relies on. No AAD change was needed —
   `encrypt(using:)`/`decrypt(using:)` use the same `EncryptionScheme.v2_hybridPQ.aad` as the bare
   variants, so re-sealed fields stay readable through `readName()`/`readID()`. Costs the two
   derivations the caller already holds, not two per slot (the Bug 74 constraint).

   An already-orphaned group is left byte-identical rather than re-sealed: it holds nothing
   recoverable, and rewriting it would make a dead row look freshly edited. Its ciphertext then
   stays static while live groups' changes — but an orphan is already the row that fails to
   decrypt under the current key, so this exposes nothing new.
2. ~~Call it from both rotation paths.~~ **Done** — activation Step 8 and a new deactivation
   Step 6b, both before `commitStagedLocalDBKey()` with a `save()` so writes reach the WAL.

   **Ordering in activation is load-bearing.** The group pass must run *after*
   `Message.Draft.reKeyOrPurgeAll`, never before. `readID()` decrypts with the canonical key,
   which is still the old key until Step 9 — so re-keying groups first would make `readID()` fail
   for every group, collapse `allGroupIdentifiers` to the empty set, and cause the draft pass to
   delete every group-addressed draft as an unknown recipient. That is cascade 1 below, triggered
   by the fix for the bug that causes it.
3. ~~Add a repair pass that hard-deletes `Group` rows whose `readID()` fails.~~ **Done** —
   `ContactManager.purgeUnreadableGroups(using:)`, called from `RootView`'s `.task`.

   Deleting is safe because the loss is provable, not merely current: the hybrid key needs both
   an SE private key and a Keychain random component, Step 11 destroys both, and the SE half is
   non-exportable — no backup on any device can restore it. So no repair path can ever exist and
   these rows are permanently unopenable, unmessageable, and undeletable through the UI.
   Removing them also closes the forensic tell of undecryptable rows sitting beside decryptable
   ones.

   Three design points worth keeping:
   - **The key is a parameter, not derived inside.** A nil key would make every row look
     stranded and empty the table; requiring it makes that unrepresentable rather than guarded,
     and the call site is where a failed derivation stops the sweep.
   - **No completion flag.** A `UserDefaults` key with any honest name would advertise that the
     app has an orphan concept, which points at key rotation, which points at Secure Mode. The
     sweep runs every launch instead — one decrypt per group, finding nothing once clean, and no
     named artefact left behind.
   - **Depth 0 only**, matching `cleanUpGroupDuressMembership`'s reasoning, so row deletions are
     never written to the WAL during a coerced session. Followed by an unconditional
     `checkpointStore()` so checkpoint timing does not itself become the signal.

   Silent, per product decision — the user already perceives these groups as missing, and any
   explanation would have to gesture at Secure Mode. Drafts addressed to a purged group are
   deliberately left alone; `reKeyOrPurgeAll` drops them at the next rotation anyway.
4. Audit the schema for any other model sealed under the rotating key and missing from both
   rotation paths. `AppLayerConfig` is the open question — see below.

### Related: `AppLayerConfig` has the same gap

`AppLayerConfig+Model.swift` seals eight fields with the same bare `.encrypt()`/`.decrypt()` local
DB key helpers, and none of them are re-encrypted during rotation either. Traced in full and split
out as **Bug 76** — the outcome is different enough from this bug to warrant its own entry: no
permanent data loss, but the Bug 46 blob-slot exclusion guarantee is silently voided.

### Test gap

No test covers group survival across a rotation. `OccultaTests/SecureMode/SecureModeActivationTests.swift`
never mentions `Group`, and `OccultaTests/Groups/*` never activates Secure Mode. Regression
coverage should assert that after activate (and after deactivate) a group's name, ID, and
depth-0 and depth-1 membership all still read back correctly. Note these tests need a physical
device: `Group` calls `Manager.Key()` directly rather than through an injectable
`KeyManagerProtocol`, so `TestKeyManager` cannot bypass the Secure Enclave — follow the
`secureEnclaveAvailable()` guard pattern already used in `GroupModelTests.swift`.

---

## Bug 76 — `AppLayerConfig` fields are never re-keyed during rotation; Bug 46's blob-slot exclusion silently stops protecting the real layer

**Stale, 2026-09-11:** `AppLayerConfig.reencrypt` and `blobMetadataKey` no longer exist — deleted
whole by Removal Stages 0-4, 2026-09-10.

**Status:** Fixed on `release/v1.10.2` (commit 182920b), pushed. Split out of Bug 75's audit item.

- **Blob metadata** (`sealedBlobSlots`, `layerSequenceNumbers`) now lives on a key derived from
  the non-rotating SE Secure Mode key — `AppLayerConfig.blobMetadataKey(from:)`, HKDF
  domain-separated from the layer store's own key. Rotation can no longer strand it, which
  removes Defects 1 and 2 by construction rather than by maintaining rotation machinery.
  `migrateBlobMetadata(fromLocalDBKey:toBlobKey:)` moves entries from the old scheme, driven from
  `Manager.Security.migrateBlobMetadataKeyIfNeeded()` at launch — without it a currently-reachable
  blob would be read as absent and silently orphaned.
- **The other six fields** (`persistedDepth`, `pinEnabled`, `pinEnabledPerDepth`,
  `coercerBaseDepth`, and the two lockout fields) stay on the local DB key and are re-keyed by
  `AppLayerConfig.reencrypt(from:to:)`, called from both rotation paths alongside `Group`. That
  closes Defect 3.
- 10 tests across `AppLayerConfigRotationTests.swift` and `BlobMetadataMigrationTests`, plus the
  6 exclusion tests in `ProtectedBlobSlotTests.swift` — now fully deterministic, since the key is
  an explicit parameter and no Secure Enclave is involved. Full `OccultaTests` target green.

- **Defect 1 (blob-slot exclusion):** downgraded to Low and **not** given behavioural changes — see
  the impact correction below. Two attempts to "fix" it were made and reverted (fail-closed throw,
  then a silent-dismiss catch arm); both were worse than the behaviour they replaced. What remains
  on `release/v1.10.2` is `Manager.Security.protectedBlobSlots(config:depth:)`, a deduplication of
  the expression that previously existed verbatim at two call sites, with the skip-unreadable
  behaviour unchanged and now documented and pinned by tests in `ProtectedBlobSlotTests.swift`.
  Full `OccultaTests` target green. Not committed/pushed.
- **Defects 2 and 3, and the root cause:** open. Awaiting the re-key work below.

**Decision taken:** blob metadata (`sealedBlobSlots`, `layerSequenceNumbers`) will move under the
**SE Secure Mode key** — the non-rotating key that already protects the verifiers — rather than
being re-keyed on every rotation. This removes Defects 1 and 2 by construction instead of adding
rotation machinery that must stay correct indefinitely, and costs nothing in exposure: the blob
*contents* are already sealed under `layerStore.deriveKey(from: seKey)`, so a slot index is
strictly less sensitive than the blob it points at, already under that same key. The remaining six
fields stay on the local DB key and get re-keyed alongside `Group` (Bug 75).

**Target:** v1.10.2

### Severity: Medium — no permanent data loss; blob redundancy and gate-down state are lost. See "What is *not* broken".

### Summary

`AppLayerConfig` seals eight fields under the rotating hybrid local DB key, and — exactly like
`Group` (Bug 75) — none of them are re-encrypted when `activateSecureMode` /
`deactivateSecureMode` rotate that key. Unlike Bug 75 the consequences are not catastrophic,
because every affected read has a fail-safe fallback and because the fields activation actually
depends on are rewritten post-commit. But two real defects fall out, one of them silently voiding
a guarantee an earlier bug was filed to establish.

### Field inventory

Under the rotating local DB key (bare `.encrypt()` / `.decrypt()`):

| Field | Rewritten post-commit by activation? |
|---|---|
| `sealedBlobSlots[depth]` | Yes — [:649](Occulta/Features/SecureMode/Manager+Security.swift:649) |
| `sealedBlobSlots[j ≠ depth]` | **No** |
| `layerSequenceNumbers[depth]` | Yes — [:650](Occulta/Features/SecureMode/Manager+Security.swift:650) |
| `layerSequenceNumbers[j ≠ depth]` | **No** |
| `coercerBaseDepth` | Only when `depth > 0` — [:665](Occulta/Features/SecureMode/Manager+Security.swift:665) |
| `persistedDepth` | **No** |
| `pinEnabledPerDepth[*]` | **No** |
| `lockoutCountEncrypted`, `lockoutAnchorUptimeEncrypted` | **No** |

**Not affected:** `sealedNormalVerifier(s)` and `sealedDuressVerifier(s)` are sealed by
`PINManager` under the dedicated SE Secure Mode key, which never rotates. PIN entry and layer
routing therefore keep working across any number of rotations — Secure Mode is not bricked by this.

`persistedDepth` and `pinEnabledPerDepth` are written *only* by `setState`
([:253](Occulta/Features/SecureMode/Manager+Security.swift:253)), and `activateSecureMode` never
calls `setState` — confirmed by grep, its only callers are the two deactivation paths and PIN
setup/disable. So both fields are stranded by every activation until some later `setState` runs.

### Defect 1 — Bug 46's exclusion guarantee is silently void (Low — see the impact correction)

Activation picks a blob slot at [:416-419](Occulta/Features/SecureMode/Manager+Security.swift:416):

```swift
let excludedSlots: Set<Int> = depth == 0
    ? []
    : Set((0..<min(depth, 2)).compactMap { config.readBlobSlot(at: $0) })
let slotIndex = self.layerStore.randomSlot(excluding: excludedSlots)
```

The stated invariant, three lines above it in the source, is that "the real layer (depth 0) and
the first duress layer (depth 1) are permanently excluded from all writes — they must never be
overwritten." That is Bug 46's fix.

The exclusion set is built by *decrypting* the stored slot indices, and this runs at line 416 —
before `createStagedLocalDBKey()` at line 426 — so it uses whatever the current canonical key is.
Walk two activations:

1. Activation at depth 0 rotates K0 → K1, then writes `sealedBlobSlots[0]` under **K1**.
2. Activation at depth 1 reads `readBlobSlot(at: 0)` under K1 — still fine, so slot 0 is correctly
   excluded. It then rotates K1 → K2 and writes `sealedBlobSlots[1]` under **K2**.
   `sealedBlobSlots[0]` is now stranded under K1, which Step 11 deleted.
3. Activation at depth 2 reads `readBlobSlot(at: 0)` under K2 → **nil**. `compactMap` silently
   drops it. `excludedSlots` contains only slot 1.

`randomSlot(excluding:)` then draws uniformly from the 31 remaining slots
([SecureMode+LayerStore.swift:236](Occulta/Features/SecureMode/SecureMode+LayerStore.swift:236)),
so it selects the real layer's blob slot with probability ~1/31, and `layerStore.push` overwrites
it. The depth-0 blob — the sealed copy of the real user's sensitive contacts — is destroyed, with
no error and no user-visible signal.

`compactMap` is what makes this silent: a decrypt failure and "no layer configured at this depth"
are the same nil, so the code cannot tell a stranded entry from an empty one.

#### Impact correction — this is not an independent defect

The mechanism above is real, but the harm was overstated when this entry was first written, and
the correction collapses Defect 1 into Defect 2.

The trigger for the narrowed exclusion set is `readBlobSlot(at: 0)` returning nil. That is the
*same call* `deactivateSecureMode` uses to locate the depth-0 blob to pop
([:722](Occulta/Features/SecureMode/Manager+Security.swift:722), with `blobDepth = max(0, depth-1)`).
And a stranded index never becomes readable again: the only writer is `writeBlobSlot(_:at:)` at
the activating depth, a depth-0 activation is blocked while Secure Mode is active
([:365](Occulta/Features/SecureMode/Manager+Security.swift:365)), and `clearBlobSlot` writes
random filler. Once nil, always nil.

So on exactly the configs where slot 0 drops out of the exclusion set, the depth-0 blob is
**already unreachable** — Defect 2. Overwriting it destroys a payload no code path can pop. Both
"defects" are one harm counted twice: the metadata is stranded, so the blob is orphaned.

And the orphaned blob is redundant even when reachable, for the reasons in "What is *not* broken"
below — the sensitive contacts it holds stay in the DB, re-keyed by every rotation and never
hard-deleted.

Residual value of protecting the slot is therefore thin but not zero: a `LayerPayload` carries its
own `slotIndex` and `sequenceNumber`, so a content scan of the store could recover an orphaned
blob without the stored index. That matters only if the DB copy is *also* damaged (which
`reencryptAllFields` can do — it clears fields it cannot decrypt) and only if such a repair path is
ever built. Not enough to justify failing an activation over. Severity dropped from High to Low.

`pushDummyBlobSlot` has an identical copy of this expression at
[:1405-1408](Occulta/Features/SecureMode/Manager+Security.swift:1405), so the PIN-collision path
can overwrite the real layer's blob the same way.

### Defect 2 — the final deactivation cannot pop the depth-0 blob (Medium)

`deactivateSecureMode` computes `blobDepth = max(0, depth - 1)` and reads the pop metadata at
[:722-723](Occulta/Features/SecureMode/Manager+Security.swift:722), before staging its own key —
so again under the current canonical key. After any second activation, index 0 is stranded, both
reads return nil, and control falls to the `else` at
[:732](Occulta/Features/SecureMode/Manager+Security.swift:732), which substitutes an empty payload.
Step 5's `restoreContact` loop then iterates over nothing.

The comment on that branch reads "No slot metadata — pre-upgrade install or config corruption",
which is now also silently covering the ordinary case of "this install activated a second layer."

### What is *not* broken (correcting the initial hypothesis)

Bug 75's audit note guessed this would leave the real layer's sensitive contacts unrecoverable.
Traced through, it does not:

- Sensitive contacts are never hard-deleted from the DB
  ([:606](Occulta/Features/SecureMode/Manager+Security.swift:606)).
- Every rotation re-keys **all** profiles including sensitive shells, while the old key is still
  canonical ([:543-546](Occulta/Features/SecureMode/Manager+Security.swift:543),
  [:806-807](Occulta/Features/SecureMode/Manager+Security.swift:806)), so the DB copy rides
  through any number of rotations intact.

  **This is a derived property, not a design invariant — do not build on it without checking.**
  It holds only because `reencryptAllFields` enumerates every encrypted field on the profile, and
  it was *false* for the first five days this mechanism existed. Until `70e1f77` (2026-05-31,
  "Centralise key-rotation re-encryption in Contact.Profile instance methods"), activation Step 8
  re-encrypted only `visibleThroughDepth`, `signedAttributes`, and key records; text fields were
  left under the old canonical key and were genuinely unreadable once Step 11 deleted it. That is
  what `a6adf74` ("Fix deactivation crash on sensitive shells") was fixing, and why
  `restoreContact` exists at all — back then the blob really was the only surviving copy of a
  sensitive contact's text fields.

  The live risk this leaves: a new encrypted field added to `Contact.Profile` but not added to
  `reencryptAllFields` strands silently on the next rotation — no error, since that method nils
  fields it cannot decrypt by design. The blob is not a backstop for it either, because
  `LayerContact` carries its own fixed field list that would need the same update. Two lists to
  keep in sync, nothing enforcing it, and both `globalTrusteeDepth` (`78c15f6`) and `originDepth`
  (`d0d75b5`) were added to `reencryptAllFields` only after the fact. A test asserting that every
  `Data?` property on `Contact.Profile` survives a rotation would close this.
- Deactivation Step 4 preserves each contact's real `visibleThroughDepth` independently of the
  blob ([:814](Occulta/Features/SecureMode/Manager+Security.swift:814)), and `restoreContact`
  would have written the same value it already holds.

So the DB copy is the primary and the blob is redundant here. What Defect 2 actually costs is the
redundancy: `reencryptAllFields` clears any field it cannot decrypt to nil by design
([Contact+Model+Reencrypt.swift:22](Occulta/Data Models/Contact+Model+Reencrypt.swift:22)), and the
blob is the only fallback when that happens. Defect 1 is the one that destroys data outright.

Two further fields were checked and found harmless:

- **Lockout counters.** Stranded → `readLockoutCount()` → 0 and `readLockoutAnchorUptime()` → nil
  ("not locked out"). But activation calls `resetCounters()`
  ([:670](Occulta/Features/SecureMode/Manager+Security.swift:670)) regardless, which is the
  intended behaviour. No impact, and unrelated to Bug 70 (backup restore).
- **`coercerBaseDepth`.** Rewritten post-commit whenever `depth > 0` — which is the entire Bug 47
  coercer flow — and reset to 0 by deactivation
  ([:931](Occulta/Features/SecureMode/Manager+Security.swift:931)). Reaching a stale read needs an
  activation at depth 0 with a non-zero `coercerBaseDepth` live, which the state guards at
  [:360-367](Occulta/Features/SecureMode/Manager+Security.swift:360) make unreachable.

### Defect 3 — a lowered PIN gate does not survive an activation (Medium, fails safe)

With `persistedDepth` and `pinEnabledPerDepth` stranded, `Manager.Security.init()` reads
`readPersistedDepth()` → 0 and `readPinEnabled(at: 0)` → true (both documented fallbacks). At
[:244-245](Occulta/Features/SecureMode/Manager+Security.swift:244):

```swift
self.pinEnabled = config.readPinEnabled(at: persistedDepth)
if !self.pinEnabled { self.currentDepth = persistedDepth }
```

`pinEnabled` is true, so the depth-restore branch never fires, the PIN gate presents, and
`verify()` + `applyVerifyState()` re-establish the correct depth from the PIN scan. **This fails
safe — it is not a Bug 50 regression**, and the real layer is not exposed.

The cost is behavioural: a user who lowered the PIN gate under coercion via
`disablePIN(at:confirmingPIN:)` finds the gate back up after the next activation, because the
`false` they wrote is now unreadable. In the coercion scenario that feature exists to serve, a gate
that silently re-arms is a tell.

### Fix sketch (not implemented)

1. Re-key `AppLayerConfig` alongside `Group` in both rotation paths (Bug 75, fix step 2). The eight
   fields are small and fixed-size — two 32-entry arrays plus six scalars — so a
   decrypt-with-old/re-seal-with-new pass costs one key derivation, nothing like the Bug 74
   workload. Do it before `commitStagedLocalDBKey()` and `save()` so the writes reach the WAL,
   same ordering invariant as everything else in Step 8.
2. **Do not make activation fail on an unreadable slot index.** Two attempts were made here and
   both were reverted; recorded so they are not tried a third time.

   *Attempt 1 — throw on an unreadable depth-0 index.* Added without checking where the error
   surfaces: `SecureModeSetupFlow` routes it into the generic `catch`, which sets
   `activationFailed` and shows the "Activation Failed" alert — precisely the arm Bugs 24 and 62
   exist to keep errors out of. `protectedBlobSlots` returns empty at depth 0, so that alert is
   *unreachable* on a device where Secure Mode has never been activated; its appearance proves
   depth ≥ 1. Unlike a `pinCollision` it is not probabilistic — on an affected config it fires on
   every activation attempt at depth ≥ 2 and a coercer can reproduce it at will. Not a PIN oracle
   (the condition depends on config state, not the candidate PIN), but a reproducible
   High-severity forensic tell traded for a Low-severity data risk.

   *Attempt 2 — keep the throw, add a silent-dismiss `catch` arm* matching `invalidStateTransition`
   and `pinCollision`. Removes the alert, but leaves activation silently no-opping: a user adding a
   third layer believes a decoy layer exists when it does not — dangerous in this threat model —
   and the refused path writes nothing to disk, which is Bug 62's Gap 1 in full.

   *Reverted to skip-unreadable-and-proceed*, which is what the original `compactMap` did. Per the
   impact correction above, a stranded index means the blob is already unreachable, so excluding
   its slot protects nothing while refusing to activate costs the user a real decoy layer. The
   helper is retained for the deduplication and to carry the rationale, and the behaviour is now
   pinned by tests.
3. **Exclusion should be content-based, not index-based.** Deriving the protected set from stored
   slot *indices* is what couples it to the rotating DB key at all. The layer key is already in
   hand at activation (`layerStore.deriveKey(from: seKey)`), so the store can be asked directly
   which slots hold a real payload.

   Checked, with one correction to the obvious approach: "does the slot authenticate" does **not**
   discriminate — `writeNoOpFile` and `push` seal filler with `sealRandom(using: layerKey)`, so
   all 32 slots authenticate under the layer key. What discriminates is JSON-decodability, which
   `decodeSlot` already relies on: a real payload decodes as a `LayerPayload`, uniform random
   filler does not.

   Open questions before adopting: this would exclude *every* occupied slot including the
   expendable depth-2+ blobs Bug 46 deliberately leaves writable (a pool-size cost, and a
   behaviour change), and dummy blobs pushed by `pushDummyBlobSlot` decode as valid payloads and
   would accumulate exclusions.
4. ~~Deduplicate the exclusion expression.~~ **Done** — one definition, called from
   `activateSecureMode` and `pushDummyBlobSlot`.

### Test gap

`ProtectedBlobSlotTests.swift` covers the exclusion helper directly: depth 0 returns empty;
unreadable entries are skipped rather than raised as an error (pinning the behaviour against a
third attempt to make activation fail here); a readable slot is still excluded when its neighbour
is not; both slots are excluded when both are readable; depth-2+ slots stay in the pool.
Simulator-safe, with the round-trip cases skipped where key derivation is unavailable.

Still missing, and only coverable once the re-key work lands: a test that activates **twice** and
asserts `readBlobSlot(at: 0)` still decrypts. That is the assertion that would have caught the
root cause rather than its symptom — the helper above only refuses to act on stranded metadata, it
does not stop the stranding. `SecureModeActivationTests.swift` covers single activations only.

---

## Bug 77 — `maxBundleVersion` and `deletionToken` missing from `reencryptAllFields`

**Stale, 2026-09-11:** `reencryptAllFields` no longer exists — deleted whole by Removal Stages 0-4,
2026-09-10. This bug's root cause (a field stranded by rotation) can no longer occur since there is
no rotation.

**Status:** Fixed on `release/v1.10.2` (commit d356eb8), pushed.

**Target:** v1.10.2

### Severity: High — silently disabled an authentication gate; the `deletionToken` half was a latent High

*Raised from Medium on 2026-08-12.* The original assessment ("silent capability loss") described
only the reported symptom — group ineligibility and downgraded send format. Reviewing this release
(`Docs/Audit/SecurityReview2026-08-12/README.md`, finding 1) showed the same stranded field also
switches off sender-ephemeral-signature enforcement. See "Security consequence" below.

Field-reported immediately after Bug 75's fix landed: contacts that had been group members
could no longer be added to a recreated group, with the UI saying they needed to update the app
or send a message. Their apps were current.

### Root cause

`Contact.Profile.maxBundleVersion` holds one encrypted byte — the highest wire format that
contact's app can decode — sealed under the local DB key. It was in neither `reencryptAllFields`
nor `reencryptKeyRecords`, so every rotation stranded it and Step 11 deleted the key.

`resolveTargetVersion` then fails the decrypt and falls back to `.v3fs`, which predates group
support (1.9.0), so `isGroupEligible` returns false. And because the field is non-nil — stranded
ciphertext, not absent — `groupIneligibilityReason` reports `.versionTooOld` ("they need to
update") rather than `.versionUnknown`. The check reads the field's presence correctly and its
contents not at all.

Not limited to groups: `resolveTargetVersion` also selects the wire format for sending, so
affected contacts silently receive `.v3fs` bundles — the backward-compatible floor. Messaging
keeps working; newer capabilities are lost on that path.

The blob is no backstop — `LayerContact` does not carry this field either.

This is the exact fragility recorded under Bug 76's "What is *not* broken" section one day
earlier. The class was described; nobody checked whether an instance already existed.

### Security consequence — enforcement of sender signatures is switched off

Found while reviewing this release, after the entry above was first written. `maxBundleVersion`
is not only a capability hint for sending; it is the gate on a **receive-side authentication
check** (`Contact+Manager.swift:1727`):

```swift
if isFSMode, recipientPayload.senderEphemeralSignature == nil,
   Self.resolveTargetVersion(for: sender, using: cryptoOps).isAtLeast(.senderSignatureCapable) {
    throw GroupDecryptError.missingSenderEphemeralSignature
}
```

A stranded field means `.v3fs`, `.v3fs` is not `senderSignatureCapable`, the branch is skipped,
and an unsigned forward-secret bundle is **accepted**. Per the `2026-07-24` review, that signature
is the only thing binding an FS-mode bundle to the sender's long-term identity — the session key
never involves it.

So the remediation applied on 2026-08-01 for that review's finding has been inert on every install
that ever activated Secure Mode. Fixing the cause here does not restore it: stranded values are
unrecoverable, and enforcement stays off per contact until that contact sends a bundle.

**The residual is tracked as Bug 80, which is still open** — this entry's *cause* is fixed, its
consequences are not. Two follow-ups there: whether affected users need something more active than
a release note, and whether `resolveTargetVersion` should fail closed. The second conflicts with
the fix in this entry — clearing undecryptable values to nil is
right for the group-eligibility message and wrong for the gate, because it destroys the evidence
distinguishing "never seen this contact" from "capability marker lost".

### `deletionToken` — the more dangerous half

Also absent from `reencryptAllFields`, and initially assessed as harmless because only its
nil/non-nil status is read. Adding it naively would have been destructive: the shared
`reencrypt(data:to:aad:)` helper clears unreadable fields to nil, and `fetchAllContacts` filters
on `deletionToken == nil`. Every contact soft-deleted before this field was covered carries a
stranded token, so a nil-on-failure re-key would have **un-deleted all of them** on the next
rotation.

Fixed with a new `reencryptPreserving(data:to:aad:)` helper that returns the original bytes when
they cannot be read — the `reencrypt(string:)` convention — for fields whose presence carries
meaning independently of their content.

`maxBundleVersion` **also** uses the preserving helper, as of 2026-08-12. It originally used
nil-on-failure, on the reasoning that nil reads as "version unknown" and produces the accurate
"send me a message" instead of the false "they need to update". That was the right message reached
the wrong way: this field also gates a receive-side authentication check (Bug 80), and repairing
that gate requires "present but unreadable" to stay distinguishable from "never seen". Clearing
collapses the two permanently, for exactly the installs that have the vulnerability. The message
is now fixed at the reading site — `ContactManager.hasReadableBundleVersion` — which replaced
three separate `maxBundleVersion == nil` checks (eligibility reason plus two in `Group+FormV3`)
that all got the answer wrong the same way.

### Recovery

No code needed for affected installs. `maxBundleVersion` is repopulated whenever a bundle is
received from that contact, under whatever key is current — so one message from each affected
contact restores group eligibility. Already-stranded values cannot be recovered any other way.

### Prevention

`EncryptedFieldCoverageTests.swift` adds two complementary guards:

- **Tripwires** — the set of stored property names on `Contact.Profile`, `Group` and
  `AppLayerConfig` must equal an explicit list. Adding any property fails the test with guidance
  on which re-encryption path to update and whether clearing on failure is safe. It cannot decide
  whether a new field needs re-keying; it forces the decision to be made, which is exactly what
  did not happen here. Verified to actually fail on a mismatch, not merely to pass.
- **Behavioural** — every encrypted field is populated, rotated, and asserted readable
  afterwards, plus the two `deletionToken` regressions (stranded stays non-nil, nil stays nil)
  and `maxBundleVersion` clearing to nil.

Note on mechanism: `Mirror` on a SwiftData `@Model` does enumerate every stored property, but
erases all types to `_SwiftDataNoType`. Filtering by "is this a `Data?`" is impossible, so the
tripwire keys on names and needs the human decision.

### The durable fix, not done here

Rotation only needs a field list because fields are sealed directly under the rotating key.
Envelope encryption — a per-row key sealed under the local DB key, with all fields encrypted
under the row key — removes the requirement entirely: rotation re-seals one wrapped key per row
and new fields are covered automatically, forever. It would also drop rotation from
O(rows × fields) to O(rows), the same cost problem behind Bug 74, and would isolate a compromised
row key to a single contact.

Not attempted here: it is invasive surgery on the most security-critical path, and its one-time
migration re-encrypts every field of every row — precisely the workload Bug 74 showed this
codebase handles badly. Worth its own design pass. The tests above are what make deferring it
safe.

---

## Bug 78 — Rotation commits and deletes the superseded key even when the re-encryption passes were skipped

**Stale, 2026-09-11:** `commitStagedLocalDBKey`, `deleteSupersededLocalDBArtefacts`, and the Step 8
re-encryption pass this bug's fix touched no longer exist — deleted whole by Removal Stages 0-4,
2026-09-10.

**Status:** Fixed on `release/v1.10.2`. Introduced by the Bug 75/76 fixes on the same branch.

Both sites now `guard let oldKey = … else { throw SecurityError.keyDerivationFailed }`. Regression
coverage in `SecureModeActivationTests.swift` (`SecureModeRotationKeyGuardTests`) drives the nil
through a real activation and a real deactivation via a new `TestKeyManager
.simulatesHybridKeyUnavailable` fault-injection hook, asserting both throw and that Secure Mode
state is unchanged — i.e. neither reached its commit. Full `OccultaTests` target green.

**Target:** v1.10.2

### Severity: Medium — silent, permanent data loss; recreates Bugs 75 and 76

Found by the review of this release (`Docs/Audit/SecurityReview2026-08-12/README.md`, finding 2).

### Root cause

Both rotation paths wrap the draft, `Group` and `AppLayerConfig` re-encryption in a conditional
binding with no `else` — `Manager+Security.swift:567` (activation) and `:912` (deactivation):

```swift
if let oldKey = try self.keyManager.createHybridLocalEncryptionKey() {
    // drafts, groups, config re-keyed here
}
```

If derivation returns nil, all three passes are skipped and control falls straight through to
`commitStagedLocalDBKey()` and then `deleteSupersededLocalDBArtefacts()`. Groups and the layer
config are left sealed under a key that is then destroyed.

That is precisely Bugs 75 and 76 — reached through the code written to fix them.

### Why this slipped in

The `if let` is older than the fix: it originally wrapped only `Message.Draft.reKeyOrPurgeAll`,
where skipping is survivable because drafts are regenerable. The Bug 75/76 work extended the same
block to cover groups and config, which are not, without revisiting the binding.

The codebase already states the correct rule elsewhere. `Group.requireKey()` throws
`GroupError.keyUnavailable` for this exact situation, documented as: *"Must abort the whole pass
rather than proceed with a missing key — silently skipping the mandatory ciphertext refresh would
itself be a forensic tell."*

### Impact

Not attacker-triggered. Any condition making the Secure Enclave or Keychain briefly unavailable
mid-activation causes the rotation to commit regardless, with no error and no user-visible signal.
Blast radius is every group plus the entire `AppLayerConfig` row.

### Fix

Both sites now `guard let oldKey = … else { throw SecurityError.keyDerivationFailed }`.

**Placement was the substance of the fix, and the first attempt got it wrong.** The guard initially
replaced the `if let` where it stood, inside Step 8's draft/group/config pass — which is after
`reencryptAllFields` has run over every contact and `modelContext.save()` has committed the result.
`reencrypt(data:)` returns nil for anything it cannot decrypt (deliberate: callers reinitialise on
next use), so on the very failure this guard exists to catch, every contact had already lost
`visibleThroughDepth`, `globalTrusteeDepth`, `originDepth`, `signedAttributes`,
`forwardSecrecyEncrypted` and both image fields — written to disk, and not restored by rolling the
staged key back. Losing `visibleThroughDepth` alone drops the Secure Mode visibility ceiling for
the entire address book. The guard prevented groups and `AppLayerConfig` from being stranded while
the contacts were already gone.

The derivation now happens before Step 1's PIN check in both functions, ahead of any staging,
blob push or row mutation, so the failure is genuinely inert: nothing to roll back, nothing
touched. It has no dependency on the intervening steps, so it moves freely.

`SecureModeRotationKeyGuardTests` covers both paths, and asserts the inertness directly — a contact
inserted with a known `visibleThroughDepth` must still hold it after the aborted rotation. That
assertion fails under the original placement, which is what makes it a regression test rather than
a restatement. `TestKeyManager.simulatesHybridKeyUnavailable` supplies the nil.

---

## Bug 79 — Blob-metadata migration checkpoints conditionally, against the stated differential-signal rule

**Stale, 2026-09-11:** `migrateBlobMetadataKeyIfNeeded` no longer exists — deleted whole by Removal
Stages 0-4, 2026-09-10.

**Status:** Fixed on `release/v1.10.2`. Introduced by the Bug 76 fix on the same branch.

`checkpointStore()` moved outside the `if moved` branch; the `save()` stays conditional.

**Target:** v1.10.2

### Severity: Low — forensic-trace inconsistency

Found by the review of this release (`Docs/Audit/SecurityReview2026-08-12/README.md`, finding 3).

### Root cause

`Manager.Security.migrateBlobMetadataKeyIfNeeded()` (`Manager+Security.swift:1224`) checkpoints
only when it actually moved an entry:

```swift
if moved {
    try? self.modelContext.save()
    self.checkpointStore()
}
```

`checkpointStore()`'s own documentation requires the opposite: *"Must run unconditionally, every
call, not only when a purge actually happened — a checkpoint that only fires when something was
purged would turn checkpoint timing itself into the exact kind of differential signal this exists
to remove."*

`ContactManager.purgeUnreadableGroups(using:)`, added in the same release, follows that rule. This
does not.

### Impact

Small. The migration runs at most once per install, and the config-row write it accompanies is a
louder signal than checkpoint timing. Recorded because forensic-trace cleanliness is a stated
project invariant and this contradicts a rule cited elsewhere in the same changeset — the kind of
inconsistency that erodes an invariant by precedent rather than by any single instance.

### Fix

Move `checkpointStore()` outside the `if moved` branch. The `save()` can stay conditional; there is
nothing to write when nothing moved.

---

## Bug 80 — Sender-signature enforcement stays disabled on installs whose `maxBundleVersion` was stranded

**Status:** Fixed on `release/v1.10.2` (gate fails closed, capability tier is now a high-water
mark). One operational item remains — see "Still open" at the end.

**⚠ The fix has a regression: see Bug 81.** The interop cost recorded below as "stays gated until
they update" is stated too mildly. Both paths that would let a pre-1.10.0 contact heal their marker
are closed — one by the gate running before `updateMaxVersion`, the other by the high-water mark
floor added here — so such a contact is blocked permanently rather than temporarily. Reported from
the field within a day of this landing.

**Target:** v1.10.2

### Severity: High — an authentication check is silently off on every affected install

Filed 2026-08-12 so this survives past the session that found it. Bug 77 reads *Fixed*, which is
true of its cause and misleading about its consequences; without this entry the residual is
recorded only in `Docs/Audit/SecurityReview2026-08-12/README.md` (finding 1).

### What is still wrong

`openGroup` rejects an unsigned forward-secret bundle only when the sender is known capable of
signing (`Contact+Manager.swift:1727`), and that capability is read from
`Contact.Profile.maxBundleVersion`. Where that field was stranded by a pre-1.10.2 key rotation,
`resolveTargetVersion` returns `.v3fs`, `.v3fs` is not `senderSignatureCapable`, the check is
skipped, and the bundle is accepted.

Per the `2026-07-24` review, that signature is the only thing binding an FS-mode bundle to the
sender's long-term identity — the session key never involves it. So on every install that ever
activated Secure Mode, the remediation applied on 2026-08-01 for that review's finding #2 is inert
for every contact.

Bug 77 adds the field to `reencryptAllFields`, so this cannot recur. It cannot repair what already
happened: the hybrid key needs a Secure Enclave half that was deleted and is non-exportable.
Enforcement returns per contact only when that contact next sends a bundle, which rewrites the
field under the current key.

### Fixed 2026-08-12 — two changes, both required

The original assessment here said no code change could undo this. That conflated *recovering the
lost version* (genuinely impossible) with *stopping the loss from disabling the gate* (entirely
possible). Only the first is unrecoverable.

**1. The gate fails closed on a stranded marker.** `openGroup` now distinguishes the three states
rather than letting `resolveTargetVersion` collapse two of them. Absence still accepts — a contact
we have genuinely never heard from cannot be assumed capable, and rejecting would break first
contact. Present-but-unreadable now rejects, because it means the sender's incapability cannot be
established and this check is the only identity binding FS mode has.

**2. The capability tier is a high-water mark.** Found while implementing (1), and without it (1)
is bypassable in two messages. `appVersion` arrives in the sealed payload, authenticated only by a
session key that in FS mode carries no sender identity — so whoever can build one FS bundle also
chooses this value. `updateMaxVersion` overwrote unconditionally, so an attacker could send a
signed bundle claiming an old build to lower the recorded tier, then send an unsigned one and walk
through the gate. The tier now only ever rises.

A stranded marker is treated as the top tier for that comparison too, not as unknown — otherwise
any low claim clears it and converts "cannot prove incapable" into a recorded "incapable",
reopening the gate by another route. The two rules are deliberately consistent so they cannot
disagree.

**Interop cost, accepted:** a contact who is genuinely pre-1.10.0 *and* whose marker was stranded
stays gated until they update. Their unsigned bundles are rejected. This is the trade named below
and it is now taken rather than deferred.

Coverage in `OccultaTests/Contacts/BundleVersionHighWaterMarkTests.swift` — raise, refuse to lower,
low claim cannot clear a stranded marker, top-tier claim heals one, first sighting records.

### Still open — the operational half

**How are affected users told?**
Exchanging one message per contact restores enforcement, and is the same action that restores group
eligibility. Open question: is a release note sufficient for a silently-disabled authentication
check, or does this warrant something in-app? An in-app prompt has its own cost here — anything
that names Secure Mode is a forensic tell, so the wording would have to carry the message without
referencing the feature.

**Superseded — the hardening is done.** What follows is kept as the record of how it was
unblocked, because the conflict was self-inflicted and worth not repeating.

**Unblocked 2026-08-12.** This previously conflicted with Bug 77's fix, which cleared
undecryptable values to `nil` and so destroyed the evidence the distinction depends on — and would
have done so on the next rotation of every affected install, making this permanently unfixable for
exactly the population that has the vulnerability. That conflict turned out to be self-inflicted:
the clearing existed only to make the group-eligibility message read correctly, and that message
belongs at the reading site. `maxBundleVersion` now uses the preserving helper, and
`ContactManager.hasReadableBundleVersion` supplies the three states everywhere they are read. The
evidence survives; the hardening is now a decision rather than an impossibility.

### Why this is not simply "fix it"

Failing closed on a genuinely-unknown version would reject bundles from any contact who has never
sent one, breaking first contact. Only the narrow "was known, now stranded" case can be failed
closed — and doing so still rejects legitimate unsigned bundles from any contact who is genuinely
pre-1.10.0 *and* whose marker was stranded, until they update. That interop cost against restoring
an authentication check is a product decision, which is why this is recorded rather than applied. That is the decision to take, and it should be taken deliberately rather
than folded into a patch.

---

## Bug 81 — Bug 80's fail-closed gate permanently blocks pre-1.10.0 contacts, with no healing path

**Status:** **Accepted limitation for v1.10.2 — shipping as-is, decided 2026-08-13.** Remedies
below are deferred, not rejected. Regression introduced by Bug 80's fix; found during development,
not in the field — a message from a contact running 1.9.0 failed to open with
`GroupDecryptError: 7` (`missingSenderEphemeralSignature`, index 7 of that enum) on a dev build.

**Target:** post-1.10.2, if the affected population turns out to matter.

**Priority reviewed 2026-08-16 — remains an accepted limitation, and is *not* a release blocker.**
It was briefly promoted to P0 in the open-limitations register when Bug 82a was re-rated out of that
slot; the promotion was made by elimination, without re-reading this entry, and is withdrawn. The
narrowing facts below all still hold — the band is exactly 1.9.x, the gate is per-contact, fallback
sends are unaffected, and one message from the contact after they reach 1.10.0+ repairs the marker
permanently. Severity per affected pair stays **High** (permanent, silent, unrepairable by the
recipient); priority is **P1**. The population that would justify more is the one this project has
no telemetry to measure, which is the same reasoning that re-rated 82a — applied consistently.

### The decision, and why it is defensible

Ship the fail-closed gate. Contacts on **1.9.0 ≤ version < 1.10.0** cannot have their forward-secret
group bundles opened by a recipient whose marker was stranded, until they update.

What makes that acceptable rather than reckless:

- **It closes something live.** On 1.10.0 and 1.10.1 — in the field right now — anyone who ever
  activated Secure Mode has sender-signature enforcement silently disabled for *every* contact.
  That is Bug 80's actual vulnerability, and this release is what closes it. Not shipping costs more
  than shipping.
- **The blast radius is a one-minor-version band, not "old clients".** Below 1.9.0 there is no group
  envelope, so those sends route through `decryptSealed` and are never gated. From 1.10.0 the sender
  signs. Only 1.9.x is both group-enveloped and unable to sign.
- **It is already per-contact.** The gate fires only on an unsigned FS-mode bundle. A recipient
  whose contacts are all on 1.10.0+ never sees a rejection — the gate is invisible to them. No
  additional scoping work was needed to achieve that.
- **Fallback-mode sends are unaffected.** `.longTermFallback` / `.longTermNoPQ` bundles are not
  gated, so a 1.9.x contact whose prekeys are exhausted still gets through.
- **The failure is now legible.** Affected messages say "Ask this contact to update Occulta" rather
  than surfacing an opaque error code (`f7c41f1`).

### Amended 2026-08-14 — the legibility argument above is partly reversed

The two rejection cases were given distinct user-visible strings so the UI could "say something
true about each". That reasoning stands on its own and was not wrong; what it missed is that the
pair is readable as a duress oracle.

`senderSignatureCapabilityUnknown` fires only on an unreadable marker, which exists only after a
local DB key rotation predating `maxBundleVersion` joining `reencryptAllFields` — i.e. only on an
install that used Secure Mode on 1.10.0 or 1.10.1. `missingSenderEphemeralSignature` fires when
the marker reads fine. So anyone able to deliver one unsigned forward-secret bundle could open the
file and read off whether this device had ever activated Secure Mode. Deactivating does not clear
it, because the stranded ciphertext is preserved deliberately (see Bug 80's amendment) — the tell
outlives the feature it exposes.

Both cases now produce a single string: *"Occulta couldn't confirm this message came from this
contact, so it wasn't opened."*

**What that costs, since it is not a clear win.** The actionable half of this bug's remedy is
gone. A user whose contact is genuinely on 1.9.x is no longer told so, and every benign refusal
now reads as a security event. Alarm fatigue is the mild cost; the sharp one is a user coming to
distrust a contact who did nothing wrong and withdrawing from a channel that was safe — a real
harm in this threat model, not a UX complaint.

Partly mitigated by where the advice still lives: the group-eligibility screen continues to say
"Needs to update Occulta" for exactly these contacts, and that screen is where a user goes to find
out why someone is unreachable. So the guidance moved rather than vanished — it is no longer
attached to the moment of failure, which is when it would have been most useful.

**Why this collapses toward the alarming string while the group form collapses toward the
innocuous one.** The two screens fail differently. On the group form, the alarming option
contradicts message history visible on the device, which is what makes it readable as a tell.
Here, the innocuous option tells the victim of an impersonation attempt that their friend needs a
software update — the attacker's cover story, repeated back by the app. Each side collapses away
from its own worse outcome, which is why they land on opposite answers to what looks like the same
question.

**Not closed by this.** `.unrecorded` still accepts an unsigned bundle rather than refusing it, so
open-versus-refuse is still observable. That distinguishes a contact this device has never heard
from — not one it is hiding — and such a contact holds no prekey of ours and cannot send
forward-secret traffic in the first place. No duress state falls out of it.

**Considered and declined, 2026-08-14: restoring the advice inside the single string.** The
collapse above removed the actionable half on the reasoning that mentioning updates was what
leaked. That was wrong — the leak was the two cases producing *different* text, and one string can
carry both meanings. The candidate was:

> "Occulta couldn't confirm this message came from this contact, so it wasn't opened. They may be
> using an older version — ask them to update, or verify them another way."

It leaks nothing, is true in both cases, and has a property neither previous wording had: the
advice is **diagnostic**. Followed in the benign case it ends the problem; followed against a
forgery it returns "I'm already on the latest version", which is information the user did not have
and arrives without the app accusing anyone. Both suggested actions also work against a 1.9.x
contact, since the identity challenge rides on `.v3fs`/`.longTermFallback`.

**Declined anyway, and the reason is the window rather than the wording.** A benign refusal
requires a sender on 1.9.x *and* a stranded marker on the receiving device. One message from that
contact once they reach 1.10.0+ repairs the marker permanently, so the affected population drains
by itself and the residual refusals are then genuine forgeries — where the current security-first
wording is the correct one and the missing advice costs nothing. Judged not worth changing
user-facing copy on a release branch for a self-limiting cost.

Revisit only if 1.9.x adoption turns out to be stickier than expected, or if users report
distrusting contacts over this.

### Shipped 2026-08-16 — the decline above is reversed

The candidate string is in the build (`OccultaApp.swift:666`), verbatim as written above. Nothing
in the analysis changed; only the cost side did.

**What the decline actually rested on** was *"not worth changing user-facing copy on a release
branch for a self-limiting cost"* — a statement about marginal cost on `release/v1.10.2`, not about
the wording, which the same section had already judged strictly better on three counts: it leaks
nothing, it is true in both cases, and its advice is diagnostic. That marginal cost is now lower:
1.10.3 is touching user-facing surfaces regardless, and the change is one appended sentence at one
call site with no test pinning the old text.

**The invariant is untouched, and that is the thing to check on any future edit.** The oracle came
from the two cases producing *different* text; both still resolve to a single string, emitted
identically whether the marker was unreadable or the signature was simply absent. Length is not the
leak. The `⚠️` comment at `OccultaApp.swift:626` still forbids splitting, and now also explains why
adding the advice back did not reopen anything.

**What this buys, restated because it is easy to read as cosmetic.** The population that sees this
message is overwhelmingly benign — contacts on 1.9.x, not attackers — and until now they were
being shown an unexplained security refusal about someone who had done nothing wrong. The sharp
harm named above was a user withdrawing from a safe channel on that basis. The restored sentence
also gives the user a cheap disambiguation the app deliberately refuses to perform itself: against
a forgery, *"ask them to update"* comes back *"I'm already on the latest version."*

The self-limiting argument still holds, and now cuts the other way as well — as the 1.9.x
population drains, the advice costs less and less, because there is progressively less benign
traffic for it to be wrong about.

### What was considered and not taken

A per-contact exemption for genuinely-old builds was explored and does not work by inference: it
requires distinguishing "this contact is old" from "this bundle is forged", and every signal
available at gate time is attacker-controlled — the bundle's own `appVersion` claim most obviously,
since an attacker forging an unsigned bundle simply claims 1.9.0. The marker that would settle it is
exactly what Bug 77 destroyed. Any inference-based exemption is fail-open wearing a per-contact
wrapper.

An exemption grounded in an *authenticated act* does work, which is what Remedy 2 below is. Deferred
rather than dismissed.

### Severity: High — blocks legitimate messages, silently and permanently

### What happens

Three conditions, each individually expected:

1. The recipient activated Secure Mode before 1.10.2, so **every** contact's `maxBundleVersion` is
   stranded (Bug 77).
2. The sender is genuinely on 1.9.0 and therefore cannot produce a `senderEphemeralSignature` —
   that shipped in 1.10.0.
3. Bug 80's gate treats a stranded marker as "cannot prove they are incapable" and rejects
   unsigned FS-mode bundles.

The gate does exactly what it was designed to do. The problem is what happens next.

### Both healing paths are closed, which Bug 80's write-up did not say

Bug 80 records this cost as a contact who "stays gated until they update", implying ordinary use
eventually repairs it. It does not.

**Group path — closed by ordering.** The gate is at `Contact+Manager.swift:1727`;
`updateMaxVersion` is at `:1760`. The throw happens first, so a group bundle can never record the
sender's version. The state that causes the rejection is the state the rejection prevents fixing.

**Single-recipient path — closed by the high-water mark.** `updateMaxVersion` treats a stranded
marker as `.senderSignatureCapable` for the floor. A 1.9.0 contact claims `.groupCapable`, which
fails `isAtLeast`, so the write is skipped and the marker stays stranded. That floor was added
deliberately — to stop an attacker clearing a stranded marker with a low claim — without noticing
it also blocks the legitimate case.

Net: a pre-1.10.0 contact with a stranded marker is **permanently** blocked from group messaging.
Nothing the recipient can do repairs it. The only escape is the sender upgrading to 1.10.0+, at
which point they clear the floor and sign anyway.

### What can be authenticated, which is what any fix must rest on

| Channel | Proves sender identity | Carries `appVersion` |
|---|---|---|
| FS-mode bundle | No — session key never involves the long-term key | Yes, but unauthenticated |
| `.longTermFallback` / `.longTermNoPQ` bundle | **Yes** — long-term key is in the ECDH | **Yes, authenticated** |
| Identity challenge | **Yes** (ECDSA verify, `IdentityChallenge+Manager.swift:377`) | No |

### Remedy 1 — accept a version claim carried in an identity-binding mode

Allow a stranded marker to be *lowered* by a claim arriving in `.longTermFallback` or
`.longTermNoPQ`. Producing one requires the sender's long-term private key, so the claim is
authenticated — exactly the property whose absence justifies distrusting FS-mode claims. Needs the
recipient mode plumbed into `updateMaxVersion`.

Free and automatic, but opportunistic: fallback mode occurs only when prekeys are exhausted or
unavailable, so it heals on no predictable schedule.

### Remedy 2 — reset the marker on a passed identity challenge

The challenge authenticates the contact but carries no version, so the right tier cannot be set
from it. It can, however, clear the stranded marker to `.unrecorded`. That restores first-contact
semantics: the gate accepts the next bundle, `updateMaxVersion` records the real tier (floor for
`.unrecorded` is `.v3fs`, so `.groupCapable` writes cleanly), and the contact works permanently
thereafter.

This is the reliable path — user-initiated, on demand, and it maps onto the existing trust-check
UX. Cost is a one-message window in which an unsigned bundle from that contact is accepted,
immediately after cryptographically verifying them. A reasoned trust decision rather than a hole.

Remedies 1 and 2 are complementary: automatic where fallback happens to occur, on demand where it
does not. Neither weakens the gate, because both require proof of the long-term key.

### Rejected — blanket amnesty for existing stranded markers on upgrade

The tempting move: since rotation now re-keys the field, no *new* stranding can occur, so every
stranded marker is a historical artifact of our own bug rather than anything an attacker created.
Therefore treat them all as `.unrecorded` at upgrade and restore compatibility in one step.

The premise is true and the conclusion does not follow. The attacker never needed to create
stranded markers — they exploit whichever ones exist. Amnesty restores the accept-unsigned state
for every pre-existing contact simultaneously, which is precisely the vulnerability Bug 80 closed.
It is fail-open with extra steps, and it reads as principled in a commit message. Recorded here
because it is the intuitive idea and it is wrong.

### If backward compatibility wins

The honest alternative is to fail open for stranded markers again and surface an "unverified
sender" indicator on affected messages. That restores every pre-1.10.0 contact immediately and
keeps the user informed rather than protected.

Whether that is right depends on how many real contacts are pre-1.10.0 — unknown here. If it is
most of them, a gate that blocks real messages to close an attack that still requires prekey
material issued to the impersonated contact may be the wrong trade for now. That is a product
decision, not a security one, and it should be taken with the population figure in hand.

### Regardless of which remedy is chosen

> **Stale as of 2026-08-16 — superseded twice over; do not act on this paragraph.** It was written
> before `f7c41f1` made the failure legible, and before the 2026-08-14 amendment collapsed the two
> strings into one to close a duress oracle. Both events are recorded at the top of this entry. The
> current behaviour is a single deliberate string at `OccultaApp.swift:664-666`, not an opaque error
> code. A reader reaching this section first — as happened on 2026-08-16, producing a wrong P0
> rating in the open-limitations register — will conclude there is unfixed work here. There is not;
> there is a *declined candidate*, recorded in the amendment above.

The failure is currently opaque: `GroupDecryptError: 7` in a log, with no user-facing explanation.
It should say what the group-eligibility screen already says — that this contact needs to update
Occulta, or can be verified to restore messaging. A silent, permanent message failure is worse
than the vulnerability it is guarding against, because the user cannot even see it happening.

---

## Bug 82 — A contact identity-key change makes earlier messages from that contact permanently undecryptable

**Status:** **Re-filed as a split, 2026-08-15**, after the original likelihood argument was
challenged and the stated trigger turned out to be wrong. The two halves have different
frequencies, different consequences, and very different fix costs, and bundling them produced
both an inflated likelihood claim and an over-large remedy.

- **82a — fallback-mode half.** Open. **Re-rated 2026-08-16 from High/P0 to Medium/P1** and
  re-scoped to the *unopened*-bundle case; the retained-archive justification did not survive
  challenge. See "Re-rated 2026-08-16" below. Needs no prekey work to fix.
- **82b — forward-secret half.** Accepted, deferred. This is the narrow unopened-message race
  the original entry described, and its fix is the expensive one.

Found 2026-08-13 while scoping the §2.2 prekey finding in
`Docs/Audit/SECURITY_CHECKLIST.md`. Pre-existing: the fallback half has been there for as long as
`resolveSenderPublicKey` has, and the signature half arrived with 1.10.0. Not introduced by that
release. The original entry is preserved in git history.

### Correction — the trigger this was filed under does not occur

The original entry said this "lands on ordinary use: a contact reinstalling the app and
re-exchanging keys is a normal thing to do, not an edge case." That is wrong, and it was the
load-bearing likelihood claim.

`Manager.Key.retrievePrivateKey()` (`Key+Manager.swift:163`) is retrieve-or-create: it returns
the existing Enclave key on `errSecSuccess` and only calls `create()` on `errSecItemNotFound`.
Keychain items survive app deletion on iOS, and `WhenUnlockedThisDeviceOnly` does not change
that. So a reinstall destroys the SwiftData store — the contact list is gone and the user must
re-exchange to rebuild it — but the **identity key is unchanged**, and peers receive the same
material.

That matters because `update(key:for:)` (`Contact+Manager.swift:525`) appends unconditionally and
computes `keyRotated` only to decide whether to emit `contactKeyRotated`. A re-exchange with
unchanged material appends a record holding identical bytes, so `last(where:)` returns the same
key and nothing breaks. **This bug requires the key material to actually change.**

⚠️ The keychain-survives-uninstall behaviour is the fact everything here rests on and has not been
confirmed on-device for this app. Confirm before relying on the frequency numbers below.

### What actually changes an identity key

Four events, all device-level rather than app-level:

| Cause | Frequency |
|---|---|
| New iPhone | The device-replacement cycle — D-19 prices it at every 2–3 years per relationship per side |
| Restore to new hardware from backup | Same; the SE key is non-migratable and `ThisDeviceOnly` is not in the backup |
| In-app Erase All Data — `Manager.Key().deleteAllKeys()` (`Manager+App.swift:28`) | Panic-wipe path only |
| Erase All Content and Settings | Rare |

Not reinstall, and not anything in ordinary use. So the event is **rarer than originally claimed
but certain** — every relationship reaches it, on a hardware cycle, from both sides.

**This is D-19's event.** Device replacement forces a new identity because identity *is* the
Enclave key, cross-device sync is intentionally absent, and the no-self-vouching rule requires a
new device's key to be established by physical exchange rather than vouched for by the old one.
D-19 is that moment's authenticity face — a legitimate "I replaced my phone" is indistinguishable
from an attacker saying it — and this bug is its availability face. They should be scoped
together, not separately.

### What happens

`ContactManager.resolveSenderPublicKey` resolves a sender to exactly one key:

```swift
sender.contactPublicKeys?.last(where: { $0.expiredOn == nil })
```

`Contact+Manager.swift:1633`. The newest non-expired record, and nothing else.

The model keeps the rest. `update(key:for:)` **appends** a new `Contact.Profile.Key` when a contact
re-exchanges (`Contact+Manager.swift:552`) and emits `contactKeyRotated` when the fingerprint
actually changed (`:561`). Nothing deletes the superseded record, and `expiredOn` is written only by
`reset(identity:)` (`:576`). So the full history is sitting in the store, and this line never
looks at it. **Corrected 2026-08-26: this function was never named `saveKey`** — that name doesn't
appear anywhere in this file's git history; it has always been `update(key:for:)`, matching the
reference two paragraphs up.

Any message sealed **before** the re-exchange was built against the old key. After the
re-exchange we resolve the new one, and every check that depends on the sender's identity
compares against a key that did not exist when the message was made.

### Why it costs more than a signature failure

That single value feeds three separate consumers on the inbound path, and all three break:

| Consumer | Where | Failure |
|---|---|---|
| Fallback-mode wrapping key — `ECDH(ourLongTermPriv, theirLongTermPub)` | `deriveInboundKey` → `deriveSessionKey(using:quantumMaterial:)` | Key cannot be derived, the slot never opens, `recipientSlotNotFound` |
| `verifySenderEphemeralSignature` | `Crypto+Manager+GroupDecrypt.swift:199`, throw site `:141-145` | `senderEphemeralSignatureMismatch` |
| `senderProof` HMAC over the sender's public key | `Contact+Manager.swift:1882-1885` | `senderProofMismatch` |

So this is not only "forward-secret messages fail to verify". **Fallback-mode messages become
undecryptable outright**, because the sender's identity key is load-bearing in that mode's key
derivation. The 1:1 path resolves the sender the same way (`:1564`) and fails identically.

There is no healing path. The resolution never widens, so re-opening the same file fails the
same way forever. The messages are lost, not delayed.

### Why the two halves are different bugs

The split is not administrative — the modes differ in whether a bundle can be opened twice, and
that changes both the exposure and the fix.

| | 82a — fallback (`.longTermFallback` / `.longTermNoPQ`) | 82b — forward-secret |
|---|---|---|
| Wrapping key | `ECDH(ourLongTermPriv, theirLongTermPub)` — deterministic, consumes nothing | Prekey ECDH — prekey consumed on open |
| Re-openable? | **Yes, indefinitely** | No. Single-use by design, independent of this bug |
| Exposure window | Every retained bundle, including ones already read | Only bundles sealed and never opened |
| Failure | Slot never opens — **undecryptable** | Opens, then `senderEphemeralSignatureMismatch` |
| When this mode is used | First message ever to a contact (no batch yet), and prekey exhaustion | Steady state once a batch exists |

**82a is the one the original likelihood argument missed.** Because fallback bundles re-open
forever and the app has no message history, re-opening the `.occ` is the only way to re-read
anything — and the README positions the bundle as the durable artifact ("share the bundle however
you want"). So when a contact replaces their phone, every fallback bundle they ever sent stops
opening, retroactively, including the first message of the relationship. That is not a race; it
is an archive break at a scheduled moment.

Unknown, and unknowable without telemetry this project has deliberately declined: how many
recipients actually retain `.occ` files rather than decrypting and saving the plaintext. The
"keep the encrypted container" habit is plausible for the legal/medical persona but is not
evidenced.

**82b is the race as originally described**, and the pushback on it is fair. Its window is
"sealed but never opened" — though note that with no inbox, a bundle sits in Mail or Files until
the recipient acts, and the re-exchange is triggered by something unrelated to the message, so
the window is measured in however long a file goes unopened rather than in transit time.

### Severity

Availability, not confidentiality — nothing is exposed, and a forged bundle is no more likely to
be accepted than before. Both halves are silent and permanent. 82a additionally reaches data the
user believes they already have.

### Re-rated 2026-08-16 — High/P0 → Medium/P1, and re-scoped to unopened bundles

Challenged by the release owner: *"I am still not convinced this is a bug. Are we worried that the
few bundles encrypted by our long-term identity key will no longer be readable? In a perfect
scenario, bundles are in forward secrecy mode."* The challenge largely holds, and the entry above
overstated the case.

**Measured, not assumed — how often fallback actually fires.** `defaultBatchSize = 15`; the UWB
exchange carries **no** prekeys (zero references in `Exchange+Manager.swift`); batches are generated
only on the receive side (`Contact+Manager.swift:1586`, `:1867`). So the long-term path is taken in
exactly two places: **the first message in each direction of a relationship**, and roughly **1 in 16**
during sustained one-way flow. A clear minority of traffic.

**What the challenge defeats — the retained-archive framing.** The headline claim was that a key
change breaks *"every fallback bundle they ever sent, retroactively."* True mechanically, but its
severity rests entirely on recipients keeping `.occ` files rather than decrypting and saving the
content — which this entry already conceded is *"unknown, and unknowable without telemetry this
project has deliberately declined."* An unevidenced habit cannot carry a P0.

**The sharper form of the objection, which is the one that matters.** Forward-secret bundles are
already single-use: the prekey is deleted on successful open, so an FS `.occ` cannot be re-opened at
all. That means the **only** re-openable archive in this app is the fallback bundles — and that
re-openability is an *artifact of the mode*, not a designed feature. 82a therefore destroys an
accidental archive, not a promised one, and paying for it has to be justified on something else.

**A note on the reasoning, since it will be re-derived.** "Forward secrecy" does not itself mean old
messages should be unreadable to their owner — it means a long-term key compromise does not expose
past session keys, a statement about an adversary's retrospective reach. Signal has forward secrecy
and a fully readable history. The conclusion happens to hold *here* for a different reason:
prekey-on-open deletion. Do not generalise the principle; cite the mechanism.

**What survives, and it is the whole remaining case: unopened bundles.** A recipient with unread
`.occ` files from a contact who then replaces their device loses those messages on the next open.
No retention habit is involved — this is content the user has never seen. It is narrow, needing a
device-replacement event to coincide with an unopened backlog, but it specifically includes the
**relationship-opening message in each direction**, which is always fallback and is exactly the kind
left sitting while two people arrange to meet.

**A live alternative: make fallback ephemeral on purpose.** The app's posture is currently
inconsistent — FS bundles single-use, fallback bundles permanent — and 82a is an inelegant accident
that makes them consistent. Deciding that retained `.occ` re-openability was never a promise is a
defensible product position, and it would mean **not** fixing 82a for the archive case at all. It
does not cover the unopened case, which is wrong under either posture.

**Consequence for the fix, which the challenge sharpens rather than removes.** The remedy accepts
superseded keys in `deriveInboundKey`, and that weakens rotation as a revocation lever. With the
benefit now scoped to unopened bundles rather than whole archives, the `expiredOn` /
merely-superseded distinction below stops being a nicety and becomes the condition on which the fix
is worth shipping at all. Do not implement the candidate walk-back without it.

**Net:** still a real defect, still worth the small fix, no longer a release blocker. Bugs 81 and
81-b take the P0 slots — they block legitimate messages permanently with no device-replacement
precondition.

### Remedy — 82a

Resolve a candidate **set** rather than a single key, in `deriveInboundKey` only. Try the current
key first, exactly as today, and walk back through the older unexpired records only when it fails,
so the common path keeps its present cost.

This half needs **no prekey work**: fallback slots consume nothing, so a failed candidate leaves
no state behind and the §2.2 `defer` is never armed. It touches neither
`findAndOpenRecipientSlot`'s exit contract nor the signature path.

The one constraint that still applies: whichever candidate opens the slot must be the key
`senderProof` is checked against at `Contact+Manager.swift:1882-1885`, or the mismatch just moves from
derivation to proof. So the winning key has to be returned upward, not discarded.

Bound the candidate count — fallback derivation costs an SE ECDH per candidate per slot, and Bug
74 is the standing reminder that Enclave round trips have a ceiling.

### Remedy — 82b, and why it is deferred

The naive fix is wrong in a way worth recording, because it is the obvious one: looping over
candidates by *re-calling* `findAndOpenRecipientSlot` cannot work in FS mode.

FS mode's wrapping key never involves the sender's long-term identity (finding #8,
`SecurityReview2026-07-24`), so the slot opens on the **first** attempt regardless of which
candidate key is passed. `usedPrekey` is set, the signature check fails, and §2.2's `defer`
consumes the prekey on the way out. The second attempt then finds no prekey, opens nothing, and
returns `recipientSlotNotFound`. The retry is dead, and the first attempt destroyed the key the
legitimate message was sealed to.

A correct fix therefore has to try the candidates **at the signature check**, inside
`findAndOpenRecipientSlot`, before either returning or throwing — modifying the function whose
exit contract was rewritten for §2.2 in 1.10.2, to guard the less likely half. That cost against
that likelihood is why it is deferred.

### Interaction with the §2.2 prekey finding — the honest cost of deferring 82b

The FS half is one of the three throw sites §2.2 addressed, and the **only** one reachable
without an attacker. §2.2 shipped in 1.10.2 by consuming the prekey the moment the slot opens,
accepted on the reasoning that rejections are attacker-driven.

Deferring 82b leaves that reasoning incomplete: when a contact replaces their device, an unopened
FS bundle both fails *and* burns its prekey, with no attacker involved. The blast radius is a lost
message plus a destroyed key rather than a lost message alone. That is still the fail-secure
direction — the message was unrecoverable either way, and the key is gone rather than exposed —
but the original claim that fixing this "confines that cost to genuinely forged bundles" does not
hold while 82b is open. Fixing 82a does **not** address this; only 82b does.

### The tradeoff this makes, which is the real decision

Accepting signatures from superseded keys weakens rotation as a **revocation** mechanism. If a
contact rotates precisely because their old key was compromised, anyone holding that old key can
keep impersonating them for as long as we accept it.

Both properties are available, because the model already encodes the difference and the code
currently ignores it:

- A key explicitly expired through `reset(identity:)` carries a timestamp in `expiredOn`. **Never
  accept it** — that keeps `reset` a real revocation lever.
- A key merely *superseded* — a newer record appended, no expiry written — is the ordinary
  re-exchange case, and is safe to accept.

Today `resolveSenderPublicKey` treats the two identically by looking at neither.

`reset(identity:)` is user-reachable — `TrustCheckV2.swift:182` and the v1 contact form — so the
revocation lever exists in the UI. What is not established is whether a user who rotates *because
of* a compromise knows to reach for it rather than simply re-exchanging. That is a copy question,
and it is what makes accepting superseded keys safe or unsafe in practice.

---

## Bug 83 — A contact who downgrades below 1.10.2 permanently stops receiving our forward-secret group messages

**Status:** **Open — accepted for v1.10.2, still unfixed and still absent from `release/v1.10.3`.**
Introduced by 1.10.2, alongside the `.prefixedSenderSignatureCapable` tier (§3.6 of
`Docs/Audit/SECURITY_CHECKLIST.md`). Filed 2026-08-13. Deferred on likelihood, not on cost: the App
Store does not offer downgrades, so this needs TestFlight or a device restore onto an older build.

**Target: not 1.10.2 or 1.10.3 — a later release, same as Bug 82a.** "Post-1.10.2" was accurate when
written but is now ambiguous: the branch once bound for 1.11.0 was re-cut and shipped as the 1.10.3
patch (`b34277f`, 2026-08-16) without this fix, so the deferral has already outlived one full
release. `updateMaxVersion`'s own code comment still cites this bug live — *"See also Bug 83:
monotonicity is safe for capability decisions but not for decisions that change what we put on the
wire"* — confirming the deferral, not a fix, is still the current state.

### What happens

1.10.2 signs `senderEphemeralSignature` over a domain-separated payload for recipients at
`.prefixedSenderSignatureCapable`, and over the bare ephemeral public key for everyone below.
The tier comes from `Contact.Profile.maxBundleVersion`, which is a **high-water mark**:
`updateMaxVersion` writes only when the claimed tier clears the recorded one
(`Contact+Manager.swift:1722-1724`), so the marker rises and never falls.

If a contact recorded at `0x08` moves back to 1.10.0 or 1.10.1, nothing walks that marker down —
their subsequent bundles claim 1.10.0, `.senderSignatureCapable.isAtLeast(.prefixedSenderSignatureCapable)`
is false, and the write is skipped. We keep prefixing. Their build verifies only the bare form,
so every forward-secret slot we seal for them fails with `senderEphemeralSignatureMismatch`.

### It is intermittent rather than flat, which is worse to diagnose

Only FS-mode slots carry a real signature; fallback slots carry random filler and are never
checked. So the failure tracks our stock of *their* prekeys: we pop one per send until the batch
of `PrekeyManager.defaultBatchSize` (15) is exhausted, then fall back to long-term ECDH, which
arrives normally. That fallback message prompts them to issue a fresh batch, we go forward-secret
again, and the cycle repeats.

The observable pattern is roughly fifteen lost messages, then one that lands, then fifteen more —
not a clean outage, and from their side indistinguishable from an unreliable transport.

### Why this class of mistake is new

The high-water mark was safe while it only gated **capabilities** — send groups, send shard
content, require a signature. Over-estimating a contact there was either harmless or fail-closed,
and under-estimating was the only direction that cost anything, which is exactly what the
monotonicity was protecting against (see Bug 80: a low claim must not walk the tier down and
disable the signature requirement).

This tier is the first one that changes **what bytes we sign**. Over-estimating is now a
delivery failure rather than a conservative default, and monotonicity makes it permanent.

### Remedy

Key the prefix decision off the contact's **last claimed** version rather than the high-water
mark, and leave the signature *requirement* on the high-water mark where it belongs.

The asymmetry is the point: a downgrade attack on the *requirement* reopens Bug 80, so that must
never be walked down. A downgrade on the *prefix choice* only means we sign bare — which is what
every 1.10.0 and 1.10.1 build already does and what our own receivers still accept — so it costs
nothing to let it fall. Storing last-claimed alongside the high-water mark is one more encrypted
field on `Contact.Profile`, and both would need adding to `reencryptAllFields` (see Bug 77 for
what happens when a field is missed there).

Cheaper alternative if the extra field is unwelcome: drop the tier entirely and prefix
unconditionally once 1.10.0 and 1.10.1 are out of circulation, retiring the bare arm in
`verifySenderEphemeralSignature` at the same time. That is the end state either way.

---

## Bug 84 — Share-extension handoff runs the whole outbound encryption before the PIN, and its transport sheet presents over the PIN gate

**Status:** **Closed (Fixed)** 2026-08-16, by candidate 2 below — the picker moved into the app.
Filed 2026-08-15 from a report against `release/v1.10.3` (named `release/v1.11.0` at the time).

### Severity: High

Reported symptom: with the PIN enabled and Secure Mode inactive, encrypting a photo through the
Share Extension puts the transport-channel sheet **on top of** the PIN entry view. The reporter's
reading — that the PIN must come first, and arguably before the contact is chosen at all — is
correct, and the visible z-order is the smaller half of it.

Two independent defects stack here. Either one alone produces a wrong flow.

---

#### Part A — `case "share"` has no lock gate (original omission, not a regression)

`handleOpenURL` treats the two `occulta://` hosts differently:

- `case "inbound"` falls through to the gate at `OccultaApp.swift:557` — while
  `appScreen.phase != .unlocked` the raw bytes are parked in `pendingFileData` and drained by the
  `.onChange(of: appScreen.phase)` handler after any unlock.
- `case "share"` (`OccultaApp.swift:506`) calls `processShareSession(sessionID:)` **immediately,
  with no phase check**.

So the entire outbound pipeline runs pre-authentication: manifest decrypt, EXIF strip,
`buildShardOperations`, `encryptBundle`, `.occ` write, and finally `self.shareResult = …`, which
raises the `UIActivityViewController` sheet.

This is not a read-only path. `encryptBundle` calls `configureForwardSecrecy()`, pops a prekey via
`popOldestPrekeyData()`, and commits with `try self.modelContext.save()`
(`Contact+Manager.swift:1041-1053`, `:1090`). Someone holding the device — with iOS unlocked but
Occulta gated — can burn real-layer prekeys, advance forward-secrecy state, produce an `.occ`
genuinely signed by the owner's identity key, and send it anywhere the share sheet reaches, without
ever entering a PIN.

**Under Secure Mode it is worse.** `currentDepth` is only set by `verify()`; with `pinEnabled` true
it stays 0 until a PIN is entered (`Manager+Security.swift:245` restores `persistedDepth` only when
the gate is down). A pre-PIN share session therefore encrypts on the **real** layer no matter which
PIN is entered afterwards, and the prekey/FS mutation it commits is a depth-0 write with no
authentication behind it.

The recipient list itself is not newly exposed — the picker reads `ShareIndex.sqlite`, which Bugs 6
and 65 already constrain to the depth-1 view whenever the app is locked.

Never gated: this path dates to `0e4042f`, the commit that introduced the extension.

**Also in this class:** the `.occbak` branch at `OccultaApp.swift:549` calls
`vaultManager.storePendingRestore(data)` before the same gate.

---

#### Part B — the PIN gate is underlappable again (regression of Bug 1, Incident A)

Bug 1's first fix replaced the `.overlay` with a `.fullScreenCover` precisely so iOS modal
presentations could not render above the gate. Commit `8b95ee5` ("Refactor screen lifecycle into
AppScreen — fixes Bug 56") removed that cover and made `PINEntry` an ordinary in-tree branch of
`phaseContent` (`OccultaApp.swift:396-423`). The comment it deleted stated the invariant that is now
broken:

> `fullScreenCover` rather than overlay: a UIKit modal presentation stacks above any existing
> sheets, so it cannot be underlapped by conversation or identity-challenge sheets triggered while
> locked.

Six root-level presentations hang off the same view that renders `PINEntry` — `openedFileContents`,
`shareResult`, the three identity-challenge sheets (`OccultaApp.swift:274-322`) — plus the error
`.alert`. Any of them set while `phase == .pinRequired` presents over the gate. `shareResult` is the
one Part A reaches today; `processShareSession`'s failure path is the alert equivalent, putting
"Failed to encrypt shared content" over the PIN screen.

A straight revert is not available: the `fullScreenCover`'s async presentation window is what caused
Bug 56. The invariant has to be re-established without it.

---

### Why the fix cannot live in the extension

The reporter's stronger proposal — show the PIN *before* the contact picker — is the right ordering,
but the extension is the wrong process for it. Verifiers live in `AppLayerConfig` inside the main
SwiftData store, sealed with `Manager.Key`'s local DB key; the lockout counter and wipe threshold
live there too. `ShareViewController`'s header names the boundary: the extension links no
`Manager.Key`, `Manager.Crypto`, or `ContactManager`, and carries only `ShareIndexKeyManager`.
Prompting for a PIN there means duplicating verifier and lockout logic across that boundary — a
worse trade than the bug.

### Candidate fixes (not yet chosen)

1. **Gate the session, keep the picker where it is.** Queue the share `sessionID` the way
   `pendingFileData` is queued and drain it on `.unlocked`. Contact choice stays pre-PIN but reads
   an index Bug 6 already restricts; no crypto, no prekey burn, and no transport sheet until the PIN
   is in. The drain must run identically at every depth, for the reason `pendingFileData`'s own
   comment gives.
2. **Move the picker into the main app.** Extension collects attachments and hands off; the app does
   PIN → picker → encrypt → transport. This is the reporter's ordering, and it retires
   `ShareIndex.sqlite` along with the shared root of Bugs 6, 65, 66, 67, 68, and 69. Costs a context
   switch into Occulta before the recipient is chosen.
3. **Re-establish the z-order invariant** — required under either of the above. Suppressing the
   sheet/alert items while `phase != .unlocked` keeps Bug 56 fixed and Bug 1 fixed at the same time.

---

### Resolution

**Part B first.** All six sheets and the error alert moved inside the `.unlocked` branch of
`phaseContent`, which is where they belong — every one is a view onto unlocked content. The
`fullScreenCover` was *not* restored; its async presentation window is what caused Bug 56. Leaving
`.unlocked` now tears the branch down and dismisses whatever is on screen, so the phase handler also
clears `openedFileContents` and `shareResult` — their state outlives the branch, and a warm return
past the grace period would otherwise re-present a finished sheet over freshly re-authenticated
content. One deliberate consequence: an error raised while locked no longer alerts over the PIN
screen. `showError` survives and fires once unlocked, which is what Bug 24's rule requires.

**Part A by removing the entry point, not by gating it.** `case "share"` records the session id and
returns. The picker sheet hangs off `.unlocked`, so a session that arrives at the PIN gate waits
there with nothing decrypted and no key material touched. `pendingShareSession` is deliberately
*not* cleared on re-lock — it is queued intent, the same shape as `pendingFileData`, and clearing it
would discard a share the user staged.

Recipient choice is now `ShareRecipientPicker`, composed from the contacts tab's own
`ContactRowV2`, `GroupRowV2`, `SectionHeaderV2`, and a new `ContactListFilter` holding the filtering
and sort order lifted out of `ContactsV2`. Groups are selectable for the first time; the picker
hides those whose membership is empty at the current depth so it cannot offer a recipient
`encryptGroupBundle` would reject.

`ShareIndex.sqlite`, `ShareableContact`, and `syncShareIndex()` with all five call sites are gone,
and `ShareSession.removeLegacyContactIndex` sweeps the file out of the App Group on every
foreground. See the notes appended to Bugs 6, 65, 66, 67, 68, and 69.

### What the new coverage found on its way in

`ShareSession` exists so this path can be tested at all — the lifecycle used to be a private method
on a SwiftUI `View`, and a path no test can reach is a path where a missing PIN gate survives
review. The first EXIF test written against it failed, and not because of the fixture:

`stripEXIF` passed an empty properties dictionary to `CGImageDestinationAddImageFromSource`. That
argument is a set of **overrides** onto the metadata the source already carries, so an empty
dictionary means *override nothing* — every byte of EXIF and GPS was copied into the output
untouched. Every photo shared through the extension since the feature landed carried its capture
location and time to the recipient, while `SHARE_EXTENSION_PLAN` invariant 7 and the security
checklist both recorded the strip as done. Removal requires naming each dictionary with `kCFNull`,
which it now does for Exif, ExifAux, GPS, IPTC, TIFF, and MakerApple; orientation is carried over
explicitly, since dropping the TIFF dictionary wholesale lays portrait photos on their side.

Already-sent bundles cannot be recalled. This is worth a release note rather than a silent fix.

The general lesson is the one this entry opened with: a function named for a security property is
not evidence the property holds, and neither is a checklist line citing the function.

---

## Bug 85 — `visibleThroughDepth` ciphertext length partitions safe from sensitive contacts, with no key

**Status:** **Fixed 2026-08-19, device-verified.** Filed 2026-08-16 while scoping rotation-coverage
step 3, from a question about whether the field is ever nil. Found by measurement, not by reading —
the doc comment on the field asserts the opposite and is why it survived. This entry's status label
sat stale as "Open" for several sessions after the fix actually shipped and was confirmed on a live
device (all depth fields one length) — caught during a release-readiness check, corrected 2026-08-24.
`DepthCodec.encode`/`.decode` (`DepthCodec.swift`) is now the sole write path for
`visibleThroughDepth`, `.globalTrusteeDepth` and `.originDepth` across `Manager+Security.swift`,
`Contact+Manager.swift`, `ContactManager+Classification.swift` and `PQmigration.swift` — fixed-width
two-byte plaintext, sealed length constant regardless of value. `DepthCodecTests` covers the codec
directly; `DeletedDepthStampScrubTests` and the migration tests cover the rows it reaches.

**Target:** — (closed).

### Severity: Critical (forensic)

The first **passive, keyless, row-level** distinguisher found in this codebase. Every other tracked
tell is weaker: Bug 71's is a timestamp correlation, Bug 62's Gap 1a gives a *count* to an examiner
who already holds the SE key. This one names individual rows to anyone holding the database file.

### What happens

`Contact.Profile.visibleThroughDepth` stores `try JSONEncoder().encode(depthValue).encrypt()`.
`JSONEncoder` is variable-length and AES-GCM is length-preserving — `.combined` is
nonce(12) ∥ ciphertext(plaintext length) ∥ tag(16), so ciphertext length is plaintext + 28.

Measured (`xcrun swift`, 2026-08-16):

| Value written | Meaning | Plaintext | Ciphertext |
|---|---|---|---|
| `Int.max` | always visible — **safe** | **19 bytes** | **47 bytes** |
| `0`–`9` | hidden at that duress depth — **sensitive** | 1 byte | **29 bytes** |
| `10`–`31` | hidden at depth ≥ 10 | 2 bytes | 30 bytes |

`Int.max` is not an edge case: it is the default for every new contact
(`Contact+Manager.swift:194, :381`), the value written for every contact marked safe
(`ContactManager+Classification.swift:142, :171`), and the legacy backfill
(`PQmigration.swift:85`, `Manager+Security.swift:524`).

So the column length is a two-value classifier over exactly the safe/sensitive partition. No
clamping exists at any write site: `saveClassification` writes
`safeIDs.contains(contact.identifier) ? Int.max : depth` and `setVisibility` writes
`isSensitive ? depth : Int.max`, both encoded raw.

### Reproduction

Against the store file, with no key, no PIN, no Secure Enclave and no decryption. Column and table
names follow Core Data's convention, which SwiftData inherits:

```sql
SELECT length(ZVISIBLETHROUGHDEPTH) AS n, COUNT(*) FROM ZPROFILE GROUP BY n;
```

`n = 47` are safe contacts. `n = 29` (or 30) are hidden ones. The principle does not depend on the
exact column name — any inspection of that BLOB's length works.

### What it leaks

Both of the things the feature exists to hide:

1. **That Secure Mode is configured.** An install that never classified anyone is uniformly 47
   bytes, because every contact carries the `Int.max` default. Mixed lengths arise only once
   contacts are classified, which happens only through the activation flow. Uniformity is the
   innocent baseline, and the deviation from it is the tell.
2. **Which specific contacts are hidden**, row by row, by name of row rather than in aggregate.

### Why this contradicts a stated invariant

`forensic-trace-avoidance.md` S5 — *"Sensitive contacts remain in DB; page slack covered by S1 +
S2"* — rests entirely on the row being indistinguishable at the SQLite layer. Hard deletion was
removed (Bug 13) on the strength of that premise. This defeats it directly rather than degrading it.

### Root cause, and why it survived

Variable-length plaintext under a length-preserving cipher, with a sentinel (`Int.max`) whose JSON
form is 19× the size of an ordinary depth.

It survived multiple audits because the field's own doc comment states the opposite
(`Contact+Model.swift:81`):

> All values are AES-GCM of a 1-byte JSON integer → identical ciphertext size.

That is true for `0`–`9` and false for `Int.max`, which is the commonest value in the table. Anyone
checking this property read the comment and moved on. **The comment is a security claim the code
does not implement, and it should be corrected immediately and separately from the format fix** —
whatever is decided about the format, nothing should keep asserting a property that is not there.

### Scope — one field

Checked the siblings; none has the same shape:

| Field | Values written | Uniform? |
|---|---|---|
| `Contact.Profile.globalTrusteeDepth` | `-1` sentinel (2 bytes), small ints | Near-uniform; no `Int.max` |
| `Contact.Profile.originDepth` | small depths only | Uniform |
| `VaultEntry.visibleThroughDepth` | `currentDepth`, `encode(0)` | Uniform |

Only `Contact.Profile.visibleThroughDepth` carries a large sentinel, and only there does the length
split map exactly onto safe-versus-sensitive.

**Second-order, minor:** depths ≥ 10 are 2 bytes, so a 30-byte row is hidden at depth 10 or deeper.
Negligible beside the main partition, but it is the same defect and any fix should cover it.

### Why this is not a one-line fix

The obvious change — a fixed-width encoding, e.g. one byte with `0xFF` for always-visible — is a
**wire-format change to an encrypted field at rest**, which is the exact shape that produced Bugs
75, 76 and 77. It needs a read path accepting both formats, a normalisation pass so existing rows
converge, and assurance the pass cannot strand values.

**Partial normalisation reintroduces the leak in a new form.** `saveClassification` skips contacts
already hidden (`guard contact.isVisible(atDepth: depth) else { continue }`), so it does not rewrite
every row. A mix of 47-byte legacy, 29-byte legacy and fixed-width new rows is still a partition,
just a three-way one.

Rotation *does* touch every contact's `visibleThroughDepth`, so an activation is the natural
normalisation point. But that means the leak persists until the user next activates — on exactly
the devices that already have it, and with no way to prompt them without itself being a tell.

### Remedies to weigh

1. **Fixed-width plaintext.** One byte, `0xFF` = always visible, `0…31` = depth ceiling. Uniform 29
   bytes for every row, and it also closes the depth ≥ 10 variance. Needs the dual-format read and
   the normalisation pass above.
2. **Pad before sealing.** Keep the JSON, pad the plaintext to a fixed length, strip on read. Less
   elegant, same migration problem, but a smaller diff at the write sites.
3. **Normalise inside the rotation.** Fold the format change into `reencryptAllFields` so it happens
   wherever rotation already runs. Attractive — that path already rewrites the field — but it means
   a format migration riding the code path with the worst failure history in the project, and it
   still leaves never-activated devices untouched.

Whichever is chosen, the guard is a test asserting **every** row's ciphertext length is identical
regardless of visibility — a check no existing test makes, and the one that would have caught this.

---

## Bug 86 — `AppLayerConfig`'s padded arrays name the occupied depths by element length, with no key

**Stale, 2026-09-11:** The fields and apparatus this fix built (`sealedBlobSlots`,
`layerSequenceNumbers`, `LayerArrayCodec`, `writeBlobSlot`, `readBlobSlot`) no longer exist in
production — deleted whole by Removal Stages 0-4, 2026-09-10. They survive only in the now-orphaned
`OccultaTests/SecureMode/LayerArrayUniformityTests.swift`.

**Status:** **Fixed 2026-08-19.** Filed 2026-08-18 while checking whether Bug 85's codec could be
reused for the other depth-shaped fields.

Both arrays now use `LayerArrayCodec` — tag byte plus a 4-byte big-endian `UInt32`, 33 bytes sealed
for every value either holds — and `fillerSize` is `LayerArrayCodec.sealedSize` rather than a
literal, which is what makes the drift unrepeatable. `pinEnabledPerDepth` was severed from that
constant first, in its own commit, because moving `fillerSize` would otherwise have widened its
fallback outlier from 1 byte to 4 as a side effect.

The conversion runs in `Manager.Security.init` rather than `DatabaseMigration`: that context owns
the `AppLayerConfig` row, so no second context's cached copy can overwrite the result. It derives the
SE key once and aborts entirely if that fails, uses only the in-memory key for all 64 elements, and
saves exactly once — the three properties recorded under "The migration hazard".

The SE key is now seeded at first launch (`bd0160b`), so deriving it in the pass cannot mint a key as
a side effect. That removed the branch this fix was otherwise going to need, and the tell that made
the branch necessary.

All four Phase 0 reproductions flipped from recording expected failures to passing, and their
`withKnownIssue` wrappers were removed. Suite: 844 passed, 0 failed, 0 expected failures. Found by measurement, and the fix is materially riskier than Bug 85's —
see "Why this one can lose user data". **Amended the same day** — a third array turned out to have a
narrower version of the same defect on one path, plus a functional failure alongside it; see
"Amendment" below. The scope table's `pinEnabledPerDepth` row was corrected accordingly.

**The amendment is fixed** (2026-08-19); the two array defects this entry was opened for are not. The
amendment was separable because it needed neither a format change, a `fillerSize` change, nor a
migration — see the note at the end of that section. Remaining scope is therefore **two** arrays, not
three: `sealedBlobSlots` and `layerSequenceNumbers`. The design for them is settled — see "Settled
design" — and the reason the third is excluded is recorded with it.

**Target:** unset. Sequenced after Bug 85's format decision, since both want the same fixed-width
treatment and the same migration point.

### Severity: Critical (forensic)

Stronger than Bug 85 in the way that matters most: Bug 85 says nothing until at least one contact has
been classified, whereas this marks an occupied depth from the moment a layer is created, names
*which* depth, and does so whether or not the address book was ever touched.

Weaker in one respect: extraction is not Bug 85's single SQL function. It needs the column's archive
parsed — a dozen lines of stdlib Python, still passive, still keyless. See "Reproduction".

### What happens

`ensurePadded()` (`AppLayerConfig+Model.swift:373`) pads three arrays to 32 entries so that, in the
field's own words (`:45`), *"array length is forensically constant"*. Filler is `fillerSize = 30`
random bytes (`:369`).

Two of the three arrays store values whose sealed length is not 30.

**`layerSequenceNumbers[depth]`** holds `JSONEncoder().encode(seqNum).encrypt(using: blobKey)`, and
`randomSequenceNumber()` (`Manager+Security.swift`) returns `Int(UInt32)` — the full 32-bit range.
AES-GCM is length-preserving, so sealed length is decimal digits + 28.

Measured (`xcrun swift`, 2026-08-18) over 2,000,000 uniform `UInt32` draws:

| Sealed length | Share of real entries |
|---|---|
| 32–36 bytes | 2.3% |
| 37 bytes | 21.0% |
| **38 bytes** | **76.7%** |
| **30 bytes — collides with filler** | **0.0000021%** |

A real entry is indistinguishable from filler only when its sequence number happens to have exactly
two digits: 90 values out of 2³², about 1 in 48 million. Every other occupied depth is identifiable
from element length alone.

**`sealedBlobSlots[depth]`** holds `encode(slot).encrypt(...)` where `randomSlot()` returns 0–31 —
29 bytes for slots 0–9, 30 for 10–31. A 29-byte element proves a layer exists at that depth, which
happens for 10 of 32 slots (~31%). One-sided and weaker, but the same defect.

### Reproduction

A `[Data]` property is not a child table. Verified 2026-08-18 against a minimal SwiftData model: the
column is a single `BLOB` holding an `NSKeyedArchiver` binary plist with element order preserved.

```python
import plistlib
d    = plistlib.load(open('blob.bin', 'rb'))
objs = d['$objects']
root = objs[d['$top']['root'].data]
print([len(objs[u.data]) for u in root['NS.objects']])
```

Against a store seeded with one 38-byte entry at index 7 among 31 fillers, this returned
`[30]*7 + [38] + [30]*24` — the occupied depth named by its index. No key, no PIN, no Enclave, no
decryption.

### What it leaks

1. **That Secure Mode is configured**, without needing any contact to have been classified. Writing
   a layer at any depth stamps both arrays.
2. **Which depths are occupied**, by array index — the nesting structure of the duress layers.

As in Bug 85, uniformity is the innocent baseline: a never-activated install has all 32 entries at
exactly 30 bytes, and the deviation is the signal.

### Why this contradicts a stated invariant

`:45` claims the padding makes the array *forensically constant*. Constant array **length** was
achieved. Constant **element** length was not, and element length is what carries the information.

### Root cause, and why it survived

One constant, `fillerSize = 30`, serving two arrays whose real entries are not 30 bytes. It reads
like it was derived from a two-digit value — correct for slots 10–31, wrong for slots 0–9, and wrong
for essentially every sequence number.

It survived because the reasoning that would have caught it is written down in the same file, on the
array that gets it right (`:50`–`:55`):

> A forensic examiner could identify the disabled slot by size alone — without the SE key and
> without decryption.

That is the comment explaining why `pinEnabledPerDepth` encodes `UInt8` rather than `Bool`. The
hazard was understood, documented, and then not applied to the two sibling arrays padded by the same
function three lines away.

### Scope — two of five padded arrays

| Array | Real entry | Filler | Uniform? |
|---|---|---|---|
| `sealedBlobSlots` | 29 or 30 | 30 | **No** — 29 proves occupancy |
| `layerSequenceNumbers` | 29–38; ~98% are 37–38 | 30 | **No** — essentially always distinguishable |
| `pinEnabledPerDepth` | 29 (`UInt8`) | 29 (encrypted `1`) | Yes — one path was not, now fixed |
| `sealedNormalVerifiers` | 53 (`PINManager.verifierSize` = 12 + sentinel + 16) | 53 | Yes, by design |
| `sealedDuressVerifiers` | 53 | 53 | Yes, by design |

The verifier arrays are correct by explicit construction, which is what makes the two broken ones an
inconsistency rather than an oversight of the whole design.

### Amendment (2026-08-18): the third array has one path that breaks it too

`pinEnabledPerDepth` was credited above as correct by design, and its steady-state writer is —
`writePinEnabled` encodes `UInt8(1)`/`UInt8(0)`, one byte either way. But the legacy-upgrade path in
`Manager+Security.swift:227` writes a **`Bool`** into the same array:

```swift
if !config.readPinEnabledLegacy(), persistedDepth < array.count,
   let encrypted = try? JSONEncoder().encode(false).encrypt() {
    array[persistedDepth] = encrypted
}
```

Measured (`xcrun swift`, 2026-08-18):

| Written | JSON | Plaintext | Sealed |
|---|---|---|---|
| `UInt8(1)` / `UInt8(0)` — normal writer | `1` / `0` | 1 byte | **29 bytes** |
| `false` — this path | `false` | 5 bytes | **33 bytes** |
| random filler fallback | — | — | 30 bytes |

So a 33-byte entry is unique in the array and marks both that the PIN gate was disabled and the
depth at which it was. This is the exact hazard the array's own doc comment exists to prevent, quoted
word for word:

> A `Bool` encoding would produce `"true"` (4 bytes) vs `"false"` (5 bytes); AES-GCM does not pad, so
> the sealed box sizes would differ by one byte. A forensic examiner could identify the disabled slot
> by size alone — without the SE key and without decryption.

The comment is on `pinEnabledPerDepth`. The violation is a `Bool` written into `pinEnabledPerDepth`.

**And the write does not work either.** `readPinEnabled(at:)` decodes `UInt8.self`; decoding the
plaintext `false` as `UInt8` returns nil, so the guard falls through to `else { return true }`.
Measured: `try? JSONDecoder().decode(UInt8.self, from: encode(false))` → `nil`.

The block's own comment states the intent — *"if the old scalar was `false`, record that at the
persisted depth so the gate stays down after the upgrade"* — and the gate does not stay down. It
comes back up on every read, because the value is unreadable by the only reader.

Note the functional direction is the safe one: an unreadable entry falls back to "PIN required", so
this costs a user their disabled-gate preference rather than dropping a gate that should be up. The
forensic direction is not safe: the 33-byte entry announces exactly the state the failed write was
trying to record.

Reachable only on installs predating per-layer PIN tracking whose legacy scalar was `false` — but
those are precisely the installs an upgrade release exists to carry forward.

**Fixed 2026-08-19.** The path now routes through `writePinEnabled` instead of hand-rolling the
encode, which corrects the size and makes the value readable in one change — `writePinEnabled`
encodes `UInt8` like every other writer, so the disabled entry is 29 bytes like its neighbours and
`readPinEnabled` can parse it.

This landed ahead of the rest of the entry because it is genuinely separable: no format change, no
`fillerSize` change, no migration, and it touches neither array that sits under the SE Secure Mode
key. None of the hazards in "The migration hazard" apply to it.

`LayerArrayUniformityTests.legacyPinGateUpgradeIsUniformAndReadable` was written as a reproduction —
driving `Manager.Security.init` with a pre-upgrade row rather than replicating the write, so the
defect was confirmed reachable through the real path — and now passes with its `withKnownIssue`
wrapper removed. It stays as the regression guard. The other three tests in that file still record
expected failures, which is the accurate picture: one of the four defects is closed.

**Still open in this array, separately:** `pinEnabledFillerArray()` falls back to `randomFiller()`
(30 bytes) if `encrypt()` fails, against 29-byte real entries. That only arises when key derivation
is unavailable, in which case little else works either, so it is noted rather than rated.

**Also variable, separately:** the scalars `persistedDepth` (`:450`) and `coercerBaseDepth` (`:503`)
encode a raw depth, so they are 29 bytes below depth 10 and 30 at or above it. Single-valued, so they
partition nothing — they only distinguish depth ≥ 10. Minor, same defect, worth folding into the
same fix.

### Why this one can lose user data

`layerSequenceNumbers` is not inert metadata. It is validated on pop
(`SecureMode+LayerStore.swift`, `Error.sequenceNumberMismatch`), and a mismatch is caught in
`deactivateSecureMode` with the payload replaced by an empty one. The existing comment there
(`Manager+Security.swift:776`) states the consequence plainly:

> Blob corrupted, overwritten by `maintain()`, or seqnum mismatch. Sensitive contacts unrecoverable;
> safe contacts in DB are intact.

So a format change to this array that fails to round-trip an existing value does not degrade a
privacy property — it **permanently destroys every sensitive contact sealed in that layer**. This
raises the bar well above Bug 85's: the dual-format read is not a nicety here, it is the difference
between a fix and data loss, and it needs a test that pops a layer written in the old format.

### Settled design (2026-08-19)

**Scope: two arrays.** `sealedBlobSlots` and `layerSequenceNumbers`. `pinEnabledPerDepth` is
deliberately *excluded* now that its one defect is fixed — see "Why the third array is not in scope".

**One codec at one width**, sized by the widest value any of the two holds:

| Array | Values | Needs |
|---|---|---|
| `sealedBlobSlots` | slot index 0–31 | 1 byte |
| `layerSequenceNumbers` | `Int(UInt32)`, full 32-bit | **4 bytes** |

```
byte 0     0xFF                format tag
bytes 1–4  UInt32 big-endian   payload
```

Five plaintext bytes → **33 sealed**. `fillerSize` becomes `LayerArrayCodec.sealedSize`, computed as
`1 + payloadWidth + 28`, never a literal.

**Why one width rather than one per array.** This bug *is* a drift between a format and a filler
constant. Two widths means two constants and two chances to drift again. The cost is 3 wasted bytes
per slot entry — 96 bytes across the whole array — against removing the failure mode entirely.

**Why a tag byte.** The read path must accept legacy JSON for as long as un-migrated rows exist, and
a legacy sequence-number plaintext can be any length from 1 to 10 bytes, so length alone cannot
separate the formats. Legacy plaintexts are JSON integers, hence ASCII, hence they begin with `-`
(0x2D) or a digit (0x30–0x39); `0xFF` cannot begin one. Same discriminator as `DepthCodec`, for the
same reason.

**`DepthCodec` stays separate at 2 bytes.** Unifying would mean re-migrating the seven depth fields
already converted and correct, which is churn and risk on working code. Cross-field uniformity
between a column and an array element buys nothing — nobody compares them.

### Why the third array is not in scope

`pinEnabledPerDepth` was the third broken array; its `Bool` path is fixed and every writer now
encodes `UInt8` (`writePinEnabled`, `reencrypt`'s fallback, `ensurePadded`, `pinEnabledFillerArray`).
Three reasons to leave it alone rather than fold it into the new codec:

1. It is correct. Touching it is churn on working code.
2. It is under the **local DB key**, while the two in scope are under the **SE Secure Mode key**, so
   they cannot share a migration pass anyway — the tidiness of one shared constant does not buy a
   shared pass.
3. **It already implements the principle this fix is trying to establish.** Its filler is not a
   hardcoded size; it is literally `encode(UInt8(1)).encrypt()`, so the filler *is* the encoding and
   the two cannot drift apart. That is exactly why it is correct, and exactly what `fillerSize = 30`
   fails to do for the other two.

**The two in scope cannot copy that trick, and the reason is semantic rather than technical.** For
`pinEnabledPerDepth`, "no entry" is not a state — every depth has a gate, defaulting to `true` — so
encrypting `1` as filler is honest. For the blob arrays, "no layer at this depth" *is* the state
filler represents, and it must be indistinguishable from a real entry to someone without the key. Any
real encryption would decode to some slot index. So those two need **random** filler, sized from the
codec.

**Still open in `pinEnabledPerDepth`, separately:** `pinEnabledFillerArray()` falls back to
`randomFiller()` (30 bytes) against 29-byte real entries when `encrypt()` fails. Only reachable when
key derivation is unavailable, in which case little else works either.

The guard remains a test asserting that **every element of every padded array has identical length**,
evaluated after a real write at some depth, since all five arrays are trivially uniform before one.

### The migration hazard: no key means "everything looks like filler"

**This is the most dangerous part of the fix and it is not the format change.**

Two facts combine badly.

**First, the three arrays are under two different keys.** `pinEnabledPerDepth` is sealed with the
ambient local DB key. `sealedBlobSlots` and `layerSequenceNumbers` are sealed under
`AppLayerConfig.blobMetadataKey(from: seKey)`, derived from the **SE Secure Mode key** — which is why
`RotationRegistry` records that blob metadata *"must stay out"* of the rotation. So the conversion is
two passes with different key requirements, not one uniform sweep.

**Second, filler and an unreadable real entry are indistinguishable.** That is by design: it is
exactly how `readBlobSlot(at:)` tells "no layer here" from "layer here" — it attempts decryption and
treats failure as absence. There is no marker to inspect.

Those two together mean the pass *cannot* use Bug 85's skip-on-undecryptable rule. Filler is
precisely what has to change size, so undecryptable elements must be rewritten as fresh filler.

That is safe when the key is good: an element that will not decrypt under a known-good key is either
filler or a layer that is already lost, since `readBlobSlot` returning nil already sends
`deactivateSecureMode` down its empty-payload path. Overwriting it destroys nothing that still worked.

**It is catastrophic when the key is absent.** If `deriveSecureModeKey()` fails and the pass runs
anyway, every element in both arrays looks undecryptable, all 32 entries of each are replaced with
filler, and every layer's blob slot and sequence number are gone at once. Deactivation can then pop
no blob at any depth: sensitive contacts unrecoverable, for every layer, on a device where nothing
was wrong a moment earlier.

**The guard is structural, not a value check.** Derive the SE key up front and abort the entire pass
if it fails — nothing staged, nothing written, no partial rewrite. This is the same shape as Bug 78's
fix, which moved a key derivation to the top of activation precisely so that a key failure would be
inert rather than half-applied, and the reasoning transfers verbatim.

#### What actually guarantees the key is there — and what does not

Checked rather than assumed, 2026-08-19, because the guard above rests entirely on it.

**Nothing caches.** `createHybridLocalEncryptionKey()` performs an SE ECDH plus two Keychain reads on
*every call*; `deriveSecureModeKey()` performs a Keychain read plus an SE key exchange on every call.
Every item involved is stored `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — **not**
`AfterFirstUnlock`. So each call requires the device to be unlocked *at that moment*, not merely
unlocked once since boot.

**Launch time is protected by configuration, not by design.** No `UIBackgroundModes` is declared in
any Info.plist, so iOS will not background-launch the app; `App.init()` — where `migrate()` runs —
is reached from a user tap, which implies an unlocked device. The Share extension neither builds a
`ModelContainer` nor calls `DatabaseMigration`. That holds today, and nothing asserts it: declaring
a background mode in a later release would silently remove this protection with no test failing.

**The gap this leaves is a device lock *during* the pass**, which auto-lock makes ordinary rather
than exotic. Because every `.encrypt()`/`.decrypt()` re-derives from the Keychain, calls made after
the lock fail while earlier ones succeeded — a partially-applied pass, which for these two arrays is
the wipe described above.

So "derive up front and abort" is necessary but **not sufficient**, and the stronger rule is:

> Derive the SE key once, then use that in-memory `SymmetricKey` for **every** element read and
> write. Never call ambient `.encrypt()`/`.decrypt()` inside the loop.

An in-memory `SymmetricKey` survives a device lock; a Keychain read does not. The array API already
supports this — `writeBlobSlot(_:at:using:)` and `writeSequenceNumber(_:at:using:)` take the key
explicitly, so this costs nothing to honour.

**But holding the key is only half of it, and not the half that carries the guarantee.** A device
lock takes away two things, not one. The SQLite store, WAL and SHM files are stamped
`FileProtectionType.complete` at init and re-stamped after every save (`OccultaApp.swift:73`, S3 in
`forensic-trace-avoidance.md`). `NSFileProtectionComplete` means the OS encrypts those files while
the device is locked — inaccessible **to the app itself**, not merely to an examiner. So an
in-memory key keeps the crypto working right up to the moment the pass tries to persist, and then
the write fails anyway.

Which is survivable, and the reason is the shape of the write rather than the key:

> Mutate every element in memory, then call `save()` **exactly once**, at the end. Never per element.
> And suspend `autosaveEnabled` for the duration, or the first half of that sentence is not true.

SQLite transactions are atomic, so the pass either commits in full or not at all. A lock mid-pass
means the save fails, nothing is persisted, and the next launch retries from the original bytes. The
in-memory key is what makes a *complete* result available at that single save; the single save is
what makes a partial result impossible. Saving per element would defeat it entirely — holding the
key would not help, and the result would be a half-converted array with mismatched element sizes,
which is this bug again in a new shape.

So the full requirement is four things, of which the key is only the first:

1. Derive the SE key **once**, into an in-memory `SymmetricKey`.
2. Fetch the config and materialise the arrays into locals early, so nothing lazy-faults from a file
   that may since have become unreadable. (Belt-and-braces — SwiftData's faulting behaviour here has
   not been verified in detail.)
3. Do all 32 elements' crypto in memory, with the held key.
4. Assign back and `save()` exactly once, with `autosaveEnabled = false` for the pass.

**On (4), corrected 2026-08-20.** The autosave half was missing when this was first written, and
without it the rest does not hold: a RunLoop- or backgrounding-triggered autosave can commit a
partially-applied pass before the function decides whether to, so "one save at the end" is a property
of the code only while autosave is suspended. Three other multi-step sequences here already suspend
it for exactly this reason — `activateSecureMode`, `deactivateSecureMode`, and `Message.Draft`'s
purge — and all three restore it with `defer`, which is what marks `true` as the normal state.

`pinEnabledPerDepth` is exempt from (1) and does not need it: its writer and filler both go through
ambient `encrypt()`, and a per-element failure there is benign — an unreadable entry reads back as
`true` (gate up), which is its documented fallback. It is **not** exempt from (4).

Bug 85's shipped pass already satisfies (4) — `migrateDepthFieldsToFixedWidth` accumulates into
`didChange` and saves once at the end. That was written for idempotence, not for lock-safety, and
gets lock-safety for free.

**For contrast, the Bug 85 pass is already safe under this.** `migrateDepthFieldsToFixedWidth` uses
ambient calls, so a mid-pass lock makes them return nil, `fixedWidthRewrite` skips the row, and the
pass simply converts fewer rows and retries on the next launch. It costs progress, not data. That is
the skip-on-undecryptable rule covering a case it was not written for.

Note what this means for verification: a test can prove the guard works once it exists, but it cannot
prove the guard is present on every path that reaches the rewrite, nor that no future background mode
undermines the launch-time assumption. Those want a review of the code's shape, not another assertion.

### Test plan

Phase 0 is committed ahead of any fix, in `LayerArrayUniformityTests.swift`, wrapped in
`withKnownIssue` so the suite stays green while this is open and each test flips to failing the day
it is fixed. All four record an expected failure today, which is the executable reproduction:

- blob-slot elements are not one length (29 against 30-byte filler)
- sequence-number elements are not one length (37–38 against 30)
- `fillerSize` does not match what either writer produces
- the `pinEnabledPerDepth` upgrade path writes an oversized entry *and* one `readPinEnabled` cannot
  parse — confirmed reachable by driving `Manager.Security.init`, not merely by reading the code

The first three need no Secure Enclave: `writeBlobSlot` and `writeSequenceNumber` take their key
explicitly, so they run on CI runners.

Phase 1, with the codec: round-trip across the `UInt32` range including boundaries, legacy JSON still
decoding, and `fillerSize == codec.sealedSize` — trivially true once derived, and there to fail the
day someone re-hardcodes it, which is how this bug happened.

Phase 2, with the migration, in rising order of what they protect:

1. **No SE key → the pass is a complete no-op.** The guard above.
2. Filler resizes and real entries survive: a written slot and sequence number read back identically,
   and all 32 elements end one length.
3. **The blob still pops after migration** — activate, migrate, deactivate, assert the sensitive
   contacts come back. Everything else checks bytes; this checks that what the bytes are *for* still
   works, and it is the direct guard on "sensitive contacts unrecoverable".

---

## Bug 87 — A stranded `visibleThroughDepth` is un-hidden by rotation, in both directions

**Stale, 2026-09-11:** This fix's own mechanism (`reencryptPreserving`, used inside
activation/deactivation) no longer exists — deleted whole by Removal Stages 0-4, 2026-09-10.

**Status:** **Fixed 2026-08-19.** Filed 2026-08-18 while writing Bug 85's migration guards. Found by
asking what a normalisation pass must do with a row it cannot decrypt, then discovering the shipped
rotation paths already answer that question wrongly.

Both halves were fixed as remedy 1. Activation's three depth fields moved to `reencryptPreserving`,
so a stranded ceiling is no longer nil-ed into "visible everywhere". Deactivation now separates
*absent* from *undecryptable*: absent still resolves to `Int.max` (never classified, per S6), while
undecryptable resolves to `0` — hidden at every duress depth, still visible to the real user at depth
0, which is the fail-safe S7 already states for vault entries.

Guarded by `StrandedCeilingRotationTests`, verified non-vacuous by stashing the fix and confirming
both reproductions fail without it, with a third test asserting a readable ceiling is untouched by
the new fallback.

**Target:** unset, but this is separable from Bug 85 and much smaller — the fix is a fallback change
in two places, with no wire-format implications.

### Severity: High (security, not forensic)

Different in kind from Bugs 85 and 86. Those are passive distinguishers that leak *metadata* about
hidden contacts. This one makes a contact the user marked sensitive **visible to a coercer at every
duress depth** — not a leak about the protection, but the protection itself failing open.

Rated High rather than Critical only because it needs a precondition: the contact's
`visibleThroughDepth` ciphertext must already be unreadable. Bugs 85 and 86 need no precondition at
all. If stranded ciphertext turns out to be common rather than exceptional, this is Critical.

### What happens

`isVisible(atDepth:)` fails **closed** — a non-nil ceiling that will not decrypt excludes the
contact, per its own comment: *"non-nil field that won't decrypt = sensitive shell; exclude"*
(`Contact+Model.swift:212`). So while a contact's ceiling is stranded, it is correctly hidden.

Both halves of a rotation cycle destroy that state, by different mechanisms, and both land on
*visible everywhere*.

**Deactivation** (`Manager+Security.swift:838`) resolves an unreadable ceiling to `Int.max` and then
persists it:

```swift
let contactDepth: Int = {
    guard let data = profile.visibleThroughDepth,
          let plain = data.decrypt(),
          let value = DepthCodec.decode(plain)
    else { return Int.max }          // ← unreadable → "safe"
    return value
}()
…
profile.visibleThroughDepth = try AES.GCM.seal(DepthCodec.encode(contactDepth), …)
```

The comment above it reads *"undecryptable or absent → Int.max (safe / never classified)"*, which is
the defect stated out loud: **absent** means genuinely never classified, **undecryptable** means the
value is unknown. Collapsing the two resolves an unknown to the most permissive value available.

**Activation** (Step 8, `Manager+Security.swift:556`) reaches the same outcome through
`reencryptAllFields`, whose `reencrypt(data:)` helper returns nil for anything it cannot decrypt —
deliberately, so callers reinitialise. And `isVisible` treats nil as *visible*:

```swift
guard let data = self.visibleThroughDepth else { return true }
```

So activation nils the stranded ceiling and the contact becomes visible at every depth. The nil does
not even persist as nil: `migrateSafeContactVisibilityBackfill` re-stamps it to `Int.max` on the next
launch, cementing the same end state deactivation reaches directly.

### Why this is the one pattern the file already guards against elsewhere

`reencryptAllFields` has a second helper, `reencryptPreserving`, for exactly this hazard. It is used
on precisely two fields, and the reasoning on one of them is a sentence-for-sentence match for
`visibleThroughDepth`'s situation (`Contact+Model+Reencrypt.swift:70`):

> Clearing an unreadable token would therefore un-delete the contact: every row soft-deleted before
> this field was re-keyed carries a stranded token, and they would all silently reappear on the next
> rotation.

Substitute *un-hide* for *un-delete* and it describes this bug. `deletionToken` gets
`reencryptPreserving` because clearing it un-deletes; `maxBundleVersion` gets it because of Bug 80.
`visibleThroughDepth` gets the nil-ing helper, one line below, even though clearing it un-hides.

The consequence was also already known. Bug 78's fix comment (`Manager+Security.swift:385`) says:

> Losing `visibleThroughDepth` alone drops the Secure Mode visibility ceiling for the whole address
> book.

Bug 78 addressed the *whole-key outage* case by deriving the key up front so nothing is touched. It
did not address a *single field* that fails to decrypt while the key is perfectly healthy, which is
the case here.

### Why the vault gets this right and contacts do not

`forensic-trace-avoidance.md` S7 handles the identical situation for `VaultEntry`, and states the
principle:

> **Non-nil, unreadable** (Bug 27 — corrupt or wrong-key ciphertext) — treated as `encode(0)` under
> staged key. Fail-safe to hidden: an entry that is invisible in duress mode is a UX inconvenience;
> one that is visible is a security failure.

Vault entries fail closed. Contacts fail open. Only the vault side has the reasoning written down,
and it is the correct reasoning for both.

### Reproduction

1. Classify a contact as sensitive at depth 0 (`visibleThroughDepth = encode(0)`).
2. Corrupt its `visibleThroughDepth` ciphertext, or strand it under a key no longer canonical.
3. Confirm it is hidden: `isVisible(atDepth:)` returns false at every depth.
4. Activate, then deactivate Secure Mode.
5. `visibleThroughDepth` now decodes to `Int.max`. The contact is visible at every duress depth.

### Remedies to weigh

1. **Fail closed in both paths.** Deactivation's fallback becomes the current depth (hidden at the
   next layer) rather than `Int.max`; activation switches `visibleThroughDepth` — and, for the same
   reason, `globalTrusteeDepth` and `originDepth` — to `reencryptPreserving`. Matches S7 and matches
   `deletionToken`. Smallest diff, and the fallback direction stops contradicting `isVisible`.
2. **Preserve rather than resolve.** Leave stranded bytes byte-identical everywhere, so the state
   stays exactly what `isVisible` already interprets correctly, and no path invents a value. Cleanest
   semantically; needs a check that a permanently stranded field cannot wedge a later rotation.
3. **Make nil unreachable and fail closed on it.** Reverse `isVisible`'s nil branch to return false.
   Rejected as stated: nil is the documented never-classified default (S6) and reversing it would
   hide every contact on a pre-backfill install.

The guard is a test that a contact with an unreadable ceiling is still hidden **after** a full
activate/deactivate cycle — the property `unreadableCeilingFailsClosed` in `DepthCodecTests` asserts
only before one. Note this bug is why Bug 85's normalisation pass must skip rows it cannot decrypt:
the same fail-open default, written into a migration, would do this to every stranded row at once
instead of only on rotation.

## Bug 88 — Vault backup ignores `visibleThroughDepth` in both directions

**Status:** **Fixed 2026-08-25, both halves, per remedy 4.** Filed 2026-08-19 while confirming, on
request, how vault export/import behave under Secure Mode. Found by tracing
`exportBackup`/`importBackup` for any reference to depth or Secure Mode and finding none.
**Export half — fixed 2026-08-24.** `exportBackup(currentDepth:)` now filters to
`visibleThroughDepth == currentDepth`, no default parameter, no wire format change — matching
remedy 4 exactly as designed. Staleness metadata moved to a 32-slot fixed-width array (one per
depth) as part of the same work, guarded by a dedicated cross-depth-isolation test. The export
education screen's "all your vault entries" / "your entire vault" wording was also corrected — it
overclaimed once export became depth-scoped. **Import half — fixed 2026-08-25**, once Bug 93's
deferral (also fixed 2026-08-25) made "stamp with the current depth" safe on the automatic
restore-on-unlock path. `importBackup(_:currentDepth:)` now stamps every restored entry the same
way `addEntry` does. `importRestoresDepthCeiling` (`VaultBackupRoundTripTests.swift`) asserts the
restored ceiling decodes to the exact depth imported at; its `withKnownIssue` wrapper is gone.

**Target:** unset.

### Severity: Critical (security)

No precondition at all — unlike Bug 87, which needs stranded ciphertext first. Any export performed
while at a duress depth dumps the entire real vault, decrypted, into the resulting file. This is the
same class of failure as Bug 87 (the depth-visibility protection failing open rather than leaking
metadata about it), but reachable by ordinary use of a shipped, user-facing feature rather than by a
corruption precondition, and it hands the coercer a portable, permanent copy rather than a
transient on-screen view.

### What happens, as originally found — both halves fixed (export 2026-08-24, import 2026-08-25)

**Export ignored depth entirely.** `exportBackup()` called `fetchAllEntries()`
(`Vault+Manager.swift:270`), an unfiltered fetch with no `visibleThroughDepth`
predicate and no reference to `currentDepth`. It decrypted and serialized every entry — this code
no longer exists; `exportBackup(currentDepth:)` (`Vault+Manager+Backup.swift:176`) now filters via
`entriesVisible(atDepth:)` instead, per remedy 4 below. Kept here as the original finding:

```swift
let entries = try self.fetchAllEntries()
…
for entry in entries {
    let labelPayload = try self.decryptLabelPayload(for: entry)
    let content      = try self.decryptContent(for: entry)
    backupEntries.append(VaultBackupEntry(…))   // Vault+Manager+Backup.swift:178-193
}
```

The depth gate that exists — `Manager.Security.isEntryVisible(_:)` — is consulted by exactly one
call site in the whole codebase, the vault list's `visibleEntries` (`Vault+Tab.swift:199-201`):

```swift
private var visibleEntries: [VaultEntry] {
    return self.entries.filter { self.security.isEntryVisible($0) }
}
```

`exportBackup` and `importBackup` never call it, and a repo-wide search for `secureMode` /
`isSecureModeEnabled` under `Features/Vault` and `UI/Tabs/Vault` returns zero matches. `addEntry`
stamps every entry with an encrypted depth ceiling specifically so it can be hidden
(`Vault+Manager.swift:211-213`, *"Depth 0 entries get encrypt(0): real-layer items hidden from all
duress views"*) — the export path simply never asks.

`VaultBackupEntry` (`Vault+Manager+Backup.swift:56-62`) doesn't even have a field for it, so the
classification isn't just unfiltered, it's unrepresentable in the backup format.

**Import erased depth classification on the way back in — fixed 2026-08-25.**
`importBackup(_ data: Data)` (as it was) built a fresh `VaultEntry` per restored row and set `id`
and `createdAt` from the backup, but never touched `visibleThroughDepth`:

```swift
let entry = VaultEntry(encryptedLabel: Data(), encryptedContent: Data())
entry.id        = backupEntry.id
entry.createdAt = backupEntry.createdAt
// visibleThroughDepth left at its model default
```

The model default is `nil` (`Vault+Model.swift:194`), and `isEntryVisible` treats `nil` as *always
visible* (`Manager+Security.swift:1515`). So a restored entry — even one that was created and hidden
at real depth 0 — became visible at every depth, including any duress depth, until the user
manually re-classified it. `VAULT_BACKUP_GUIDE.md`'s description of import behaving "exactly as if
the entries were created new" was inaccurate here: `addEntry` always stamps a concrete depth
(`Vault+Manager.swift:213`, "always encrypted, never nil"); `importBackup` used to stamp nothing.
Now `importBackup(_ data: Data, currentDepth: Int)` (`Vault+Manager+Backup.swift:268-354`) stamps
`entry.visibleThroughDepth = try DepthCodec.encode(currentDepth).encrypt()` right after
`createdAt`, mirroring `addEntry` exactly — see *The import fix itself* below.

### Reproduction (as originally filed — neither step reproduces after the 2026-08-25 fix)

1. At real depth 0, create a vault entry (`visibleThroughDepth = encode(0)`).
2. Enter the duress PIN to reach a decoy depth > 0. Confirm the entry is absent from the vault list.
3. From that duress depth, tap Export backup. The resulting `.occbak` file, once decrypted with the
   BEK, contains the depth-0 entry's plaintext label and content.
4. Separately: import any `.occbak` file on a fresh device. Every restored entry is visible at every
   depth, including duress ones, regardless of the depth it was hidden at when exported.

### Correction: vault entries are exact-match, not a ceiling

Worth stating before the remedies, because it is easy to design the wrong fix from the wrong model.
`isEntryVisible` is `value == currentDepth`, **not** `value >= currentDepth`, and the doc comment
says why: a ceiling let an entry created at a duress depth leak upward into every shallower depth
including the real one (`Vault-Entries-Created-At-A-Duress-Depth-Leak-Into-The-Real-Vault.md`).

So vault depths are *partitioned*, not nested. There is no "layers below" for a vault entry — each
depth is an island. Contacts use a ceiling and do nest; vault entries do not, and reasoning about one
from the other produces a design that enforces a hierarchy which does not exist.

### Remedy 4 — one file per layer, and no format change at all *(preferred)*

Falls out of exact-match, and is simpler than the three below.

- **Export at depth N** writes only `{entries with depth == N}` — which at any depth is exactly "what
  is visible here". Rebased to 0, though see below: there is nothing to rebase.
- **Import at depth M** stamps every restored entry with M.

Because every entry in a file comes from one layer, **the file never needs to record depth**, and
`VaultBackupEntry` does not change. No `version: 1 → 2`, no migration story for existing `.occbak`
files — an old file has no depth to restore, and stamping it with the current depth is the correct
reading of that.

Both halves close at once, and by construction rather than by a rule someone must keep honouring: an
export cannot leak another layer because it never read one, and an import cannot produce an
always-visible entry because it always stamps.

**Full restore is one file per layer, imported at each layer.** That sounds like a cost and mostly is
not: re-establishing the layers on a restored device is manual anyway — Secure Mode has to be
configured and each duress PIN set before those layers exist — so importing that layer's file while
already standing in it is one extra step, not a separate chore.

**The one real cost, and it needs UI rather than code.** Today export at depth 0 writes everything;
under this rule it writes the depth-0 layer only. A user with layered entries would back up less than
they think, silently. The export screen should say what it captured — "12 entries from this layer" —
rather than letting "backup" be read as "everything".

**The import half is live, and its caller is not the UI.** Checked 2026-08-22. `importBackup` has one
production caller — `attemptBEKRestore(currentDepth:)` (`Vault+Manager+Backup.swift:712`) — reached
from `unlock(context:currentDepth:)` (`Vault+Manager.swift:167`) and from
`acceptReturnedShard(_:currentDepth:)` (`Vault+Manager+ReturnBuffer.swift:38`). So the import defect
is not latent behind an unshipped screen: it runs **automatically on every vault unlock** once shard
recovery reaches threshold, which is the primary way entries come back after a lost device.

That broke the "stamp with M" rule for this path, because nobody chose M — it was whatever depth the
unlock happened to land in. **Bug 93 covered it, and is now fixed (2026-08-25, all four harms):**
`attemptBEKRestore` defers completion to depth 0 and never fires with any other value, so "stamp
with the current depth" is now safe on the automatic path — the gate this paragraph describes is
lifted; see the Status line above. The export half was done independently, as planned here; the
import half is what's left.

**The import fix itself — built 2026-08-25.** One line, mirroring what `addEntry` already does
(`Vault+Manager.swift:223`) — `entry.visibleThroughDepth =
try DepthCodec.encode(currentDepth).encrypt()`, added right after `entry.createdAt` is set inside
`importBackup`'s per-entry loop. `importBackup` gained a required `currentDepth: Int` parameter, no
default; its one call site (`attemptBEKRestore`, above) already had `currentDepth == 0` in scope by
the time it got there, asserted two lines earlier by its own guard, so the call site change was a
one-line addition. `importRestoresDepthCeiling` now asserts the restored ceiling decodes to the
exact depth imported at (not just non-nil), and its `withKnownIssue` wrapper is gone. All six
`importBackup` call sites across production and tests updated; full affected-suite run green.

**Rejected while designing this:** a single depth-0 export carrying every layer with its depth, so a
full restore is one pass. It restores layer structure in one go, but the file then describes every
layer, needs the format bump, and adds asymmetric export behaviour to reason about. The restore
convenience it buys is small once you account for the layers having to be re-created manually
regardless.

### Remedies originally weighed

1. **Filter export by `isEntryVisible` at the current depth**, matching the vault list. Simplest, but
   changes what "backup" means — a duress-depth export would silently produce a partial (decoy-only)
   file rather than failing or warning, which could itself read as suspicious to a coercer, or could
   surprise a legitimate user who only ever uses depth 0 but layers entries.
2. **Block export outright while `currentDepth > 0`.** Removes the leak with a hard rule instead of a
   filter, at the cost of a duress-depth session being unable to produce even a decoy backup — which
   Secure Mode elsewhere goes out of its way to make behaviorally normal.
3. **Carry `visibleThroughDepth` in `VaultBackupEntry` and gate export the same way**, so a full
   export still contains every entry (matching current behavior for legitimate depth-0 backup/
   restore use) but only ever from a `currentDepth == 0` session, and import restores the original
   ceiling instead of defaulting to always-visible. Closest to preserving today's real-depth backup
   utility while closing both the export leak and the import regression in one change; needs a wire
   format bump (`version: 1` → `2`) and a migration note for existing `.occbak` files, which have no
   ceiling field to restore from.

No test exercised `exportBackup` or `importBackup` at all when this was filed — a repo-wide search
for both names under `OccultaTests/` returned zero matches. **`VaultBackupRoundTripTests.swift` now
covers both, as real assertions**: `exportExcludesHiddenEntries` guards the export half;
`importRestoresDepthCeiling` guards the import half, `withKnownIssue` wrapper removed once the
import fix landed.


---

## Bug 89 — Bug 85's fix does not reach soft-deleted rows, leaving its classifier alive there

**Status:** **Fixed 2026-08-20**, then **superseded by Bug 89a on 2026-08-26** — the fix described
below never fired on a readable row, and its "no deletion-time hook" conclusion was wrong. Read this
entry for the length leak and Bug 89a for the value leak and the shipped behaviour. Found 2026-08-19
on a live device, in the `⚠️` line Bug 85's own DEBUG diagnostic prints. Not a regression from that
fix — an area it did not cover.

`migrateScrubDeletedDepthStamps` writes `Data.randomBytes(DepthCodec.sealedSize)` into any depth
stamp of a soft-deleted row that is not already that length — no key, no decryption, idempotent by
length. `DepthCodec` gained `sealedSize` so the length comes from the format rather than from a
number observed in a log, which is the lesson of `fillerSize = 30`.

One pass, no deletion-time hook: see the remedy for why prevention is unnecessary here.

Guarded by `DeletedDepthStampScrubTests`, including the property the bug is actually about — after
the pass, live and soft-deleted rows are one length. `DepthCodecTests` asserts that for live rows
only, which is why this survived Bug 85's fix.

**Target:** unset. Small and independent of Bugs 86 and 87.

### Severity: Medium (forensic)

Lower than Bug 85 on two counts. It cannot name *which* contact is hidden, only that classification
happened at all; and it is confined to rows whose content is already cryptographically erased.

It is still a deniability break, because "was Secure Mode ever configured" is exactly the question
the feature exists to leave unanswerable.

### What happens

Activation's Step 8 re-encrypts `allProfiles = try contactManager.fetchAllContacts()`, and that
fetch filters `deletionToken == nil`. **Soft-deleted rows are never re-keyed.** Once the old key is
deleted at the end of a rotation their fields are permanently unreadable — which is S1 working as
designed: the row survives for forensic uniformity (hard deletion was removed in Bug 13), the content
does not.

`migrateDepthFieldsToFixedWidth` then correctly refuses to touch them, because a row it cannot
decrypt is left byte-identical (Bug 87). So live rows converge on the fixed-width 30 bytes and
soft-deleted rows keep whatever legacy length they had when they were last written.

Measured on a device, 14 rows, 7 live and 7 soft-deleted:

```
Contact.visibleThroughDepth outcomes: UNDECRYPTABLE=7 alreadyFixedWidth=7
Contact.visibleThroughDepth   [29, 30, 47] over 14 rows
Contact.originDepth           [29, 30] over 14 rows
```

`originDepth` shows no 47 while `visibleThroughDepth` does, which is what the two fields' ranges
predict — `originDepth` never holds `Int.max`. The split is real, not an artifact of the logging.

### What it leaks

Legacy length still encodes the classification a row carried when last written: 47 is `Int.max`
(safe or never classified), 29 is a small depth. A 29-byte stranded row can only have been produced
by one of two writes, and **both imply Secure Mode was configured** — a classification
(`saveClassification`/`setVisibility`), or creation while already at a duress depth
(`Contact+Manager.swift:193`, `currentDepth == 0 ? Int.max : currentDepth`).

So mixed lengths *among the stranded rows* are evidence the feature was used. An install that never
classified anything has uniform 47s there.

### What it does NOT leak, and why the first analysis was wrong

The first reading of this was that it made **soft-deleted rows distinguishable from live ones**,
since live rows now converge on 30. That was wrong, and worth recording because the mistake is an
easy one to repeat.

`deletionToken` is a nullable column whose nil/non-nil status is directly observable with no key —
that is not incidental, it is how the app itself partitions the table (`fetchAllContacts` filters on
`deletionToken == nil`, evaluated against a NULL column), and the field's own doc says only its
nil/non-nil status is meaningful at the query layer. A coercer can already run
`WHERE ZDELETIONTOKEN IS NULL` and get the live count exactly.

Ciphertext length adds nothing to a partition that a NULL check already gives away. The argument had
been built on an ambiguity that does not exist. The lesson: before rating a length as a
distinguisher, check whether the same partition is already available through a plainer channel.

### Remedy — a one-time repair, and nothing else

**This is a purely historical defect. There is no prevention half, and adding one would be churn.**

A row becomes a length outlier only if it has legacy-format stamps *and* is stranded so the
fixed-width pass cannot convert them. The first condition is now unreachable: every write path
produces fixed-width — creation, classification, the three backfills, rotation, blob restore. So a
contact deleted from now on already carries 30-byte stamps *before* anything can strand it, and when
a later rotation skips it, it is already uniform.

Only rows written in legacy format and stranded before the fixed-width migration ran are affected.
Repair those and the class is closed permanently.

Worth recording because it is an easy mistake to make twice: an earlier draft of this remedy added a
scrub to `deleteContact`, on the reasoning that fixing a state where it is created beats repairing it
later. That reasoning is sound in general and wrong here — at deletion the stamps are *already* 30
bytes, so the scrub replaced good bytes with random ones of the same length and achieved nothing.
Without this paragraph the one-time pass reads as incomplete and someone adds the hook back.

**The repair:** a launch pass over rows where `deletionToken != nil`, writing
`Data.randomBytes(DepthCodec.sealedSize)` into any depth stamp not already at that length.

The `deletionToken` test is what makes this safe, and it is the whole design:

- **Soft-deleted row** — content is already erased by rotation, by design. There is nothing left to
  preserve, so overwriting loses nothing. The app has no undelete path: soft-deleted rows are never
  shown in any view, and the 50-row cap hard-deletes to make room.
- **Live row** — an unreadable ceiling still means something: `isVisible` fails closed and treats it
  as hidden. Overwriting it is Bug 87 exactly, and must not happen.

Same rule the rest of this work follows — never resolve an unknown that still carries meaning — with
the observation that for an erased row the unknown no longer carries any.

**Random, not a fresh encryption — and this reverses an earlier recommendation.** The first version
of this remedy proposed writing a real `encrypt(Int.max)`, reasoning by analogy with
`pinEnabledPerDepth`, whose filler is deliberately real ciphertext, *"indistinguishable from a real
entry where the gate is up"*. The analogy was applied without checking which way the population ran.

Filler has to blend into its neighbours. In `pinEnabledPerDepth` the neighbours are live entries that
all decrypt, so real ciphertext blends and random would stand out. On a stranded soft-deleted row the
neighbours are fields that **all fail to decrypt**, so a field that decrypts cleanly is the outlier —
and worse, it tells an incoherent story. A fully stranded row reads as "rotation erased this". A row
whose name will not decrypt but whose depth field will says something wrote here *after* the erasure,
which points at the normalisation itself.

Random keeps the story coherent, and drops the key requirement entirely: nothing is encrypted, and
decryptability never has to be tested, so the pass cannot be blocked by an unavailable key. That is
the hazard Bug 86's array migration has to manage, avoided here rather than handled.

**Out of scope: live stranded rows.** A live row with an unreadable ceiling also keeps its legacy
length — your device has two — but they are not this bug's to fix. `isVisible` fails closed on such a
ceiling, so it still means *hidden*, and overwriting it is Bug 87 exactly. They resolve on the next
activate/deactivate instead: deactivation resolves an unreadable ceiling to `0` and re-seals it at
the uniform length, which is Bug 87's fix already shipped.

**It also normalises the mixed rows.** The three backfills
(`migrateSafeContactVisibilityBackfill` and its siblings) do **not** filter `deletionToken`, so a
soft-deleted row whose field was nil got it stamped under the current key while its other fields
stayed stranded. Those rows are already half-readable today, which is the same incoherence described
above, arrived at accidentally. Overwriting all three fields makes them uniformly unreadable.

**On the write itself being a trace.** Considered and rejected as a reason not to do this.
`Contact.Profile` declares no `Date` field, and SQLite keeps no per-row or per-field modification
time, so there is no timestamp to recover. The only per-row trace is Core Data's `Z_OPT`, an
optimistic-locking counter rather than a clock; after the pass every soft-deleted row has been
scrubbed, so their counters move together and there is no scrubbed-versus-unscrubbed split to read.
Whatever it suggests, it suggests about rows `deletionToken` already flags. Set against that,
declining to act leaves a 29-byte value that says a contact was classified as sensitive — a concrete
inference about the feature, traded away for a hypothetical one with no channel.

**Note the interaction with the 50-row cap.** Soft-deleted rows are capped at 50, with one
hard-deleted to make room when full, so the affected population is bounded and churns. That limits
the exposure but does not remove it: a device that classified contacts and then deleted some will
carry the signal until those rows age out.

### Guard

A test asserting that after the migration **every** row's depth fields are one length, including
soft-deleted rows — the current assertion only holds for live ones, which is why this survived. The
device diagnostic already reports it; the suite does not.

---

## Bug 89a — Bug 89's scrub never fires on the rows that leak, and leaves the depth value itself readable

**Status:** **Fixed 2026-08-26.** Found the same day by a security review of `release/v1.10.3`, in
the code Bug 89 shipped. A defect in that fix, not an area it did not cover — the distinction Bug 89
itself was careful to draw about Bug 85.

**Target:** `release/v1.10.3`. Blocks the release: this is a live deniability break, not a residue.

### Severity: High (forensic)

Higher than Bug 89, which it supersedes in scope. Bug 89 leaked a *length*, and from it the
inference "classification happened at all". This leaks the **value**: `originDepth` names the duress
layer a contact was created in and `visibleThroughDepth` says it was deliberately hidden from every
cover story. That is not "was Secure Mode configured" but "here is the depth of a layer you have not
admitted exists", recovered from a row the user believes they deleted.

### What happens

Three faults compose, and each one alone would have been enough to keep the true value on disk.

**1. The predicate is inverted.** `scrubbedStamp` skipped any field already at
`DepthCodec.sealedSize`:

```swift
guard field?.count != DepthCodec.sealedSize else { return nil }
```

`sealedSize` is 30, which is by construction the length of *every* stamp the current codec writes.
So a readable stamp — the only kind that leaks a value — was always skipped, and only legacy-width
stranded ones (29/47), which leak nothing but their length, were ever rewritten. The guard was
written as an idempotency check ("already scrubbed") and silently doubles as "already sealed",
because random filler and real ciphertext are the same length by design. Length cannot separate
those two states, so it cannot be the predicate for either.

**2. The pass that runs first removes the remaining evidence.**
`migrateDepthFieldsToFixedWidth` fetched `FetchDescriptor<Contact.Profile>()` with no
`deletionToken` filter, and runs at `OccultaApp.swift:168`, before the scrub at `:178` — an ordering
the comment there states deliberately. Any legacy-width stamp on a soft-deleted row it *could* read
was converted to 30 bytes one pass earlier, and then skipped permanently by fault 1.

**3. The deletion-time half was never built.** Bug 89's entry says *"One pass, no deletion-time
hook: see the remedy for why prevention is unnecessary here"*, and the shipped doc comment on
`migrateScrubDeletedDepthStamps` went further, asserting `deleteContact` *"scrubs these at deletion
time from now on, so this exists only for rows deleted before that shipped"*. It never did.
`deleteContact` set `deletionToken`, purged drafts, prekeys and group membership, and left all three
depth stamps untouched. So the affected population was never historical — **it grew with every
deletion.**

### Why the "random, not a fresh encryption" reasoning was wrong

Bug 89's remedy reversed an earlier proposal to write a real `encrypt(Int.max)`, on the grounds that
*"on a stranded soft-deleted row the neighbours are fields that all fail to decrypt, so a field that
decrypts cleanly is the outlier"*. That argument is correct, and it is the right instinct — filler
has to blend into its neighbours. It was applied to the wrong population.

**Soft-deleted and stranded are not the same set.** A row is stranded only once a rotation has
happened *since* its deletion, because rotation is what abandons the key its fields were sealed
under. A row deleted since the last rotation is soft-deleted and fully readable: its name, its
`deletionToken`, everything. On that row the neighbours all decrypt, so random bytes are the outlier
— and they tell the same incoherent story in reverse, one the earlier analysis named precisely
without noticing it cuts both ways. Three fields that will not decrypt on a row whose every other
field will does not read as erasure. It reads as *deliberate destruction*, which points at the
scrub itself and is a worse trace than the value it was hiding.

The lesson generalises past this bug: **the tell is never the value in the field, it is a field
whose readability disagrees with the row it sits on.** Neither "always random" nor "always sealed"
can be right, because the target state is a property of the row, not of the format.

### Remedy

**Scrub at deletion time, and make the migration a pure repair pass.** `deleteContact` now seals the
benign triple before marking the row deleted, under the same key the rest of the row already uses:

| Field | Value | Why |
| --- | --- | --- |
| `visibleThroughDepth` | `Int.max` | Visible at every duress depth — an ordinary contact. Also the backfill's own default, so it is the modal value on any install |
| `globalTrusteeDepth` | `-1` | The codec's dedicated "not a trustee" sentinel |
| `originDepth` | `0` | Born in the real session; `isVisible` only branches on `origin > 0` |

Written unconditionally, so there is no branch on secret state. Note **not** `visibleThroughDepth =
0`: that is the incriminating value, the one that marks a contact hidden from every cover story, and
it is also what Bug 87's fail-closed reading resolves an unreadable ceiling *to*. The benign value
and the fail-closed value point in opposite directions here, which is worth stating because the two
are easy to conflate.

Doing this at deletion time rather than in a migration also means there is never a window in which
the true value sits on disk on an already-deleted row.

**The migration keys on the row, not on length.** `scrubbedStamp` now takes the benign value and a
`rowIsReadable` flag: readable rows get the sealed benign value, stranded rows keep the key-free
random-bytes path, and a stamp already sealed under a superseded key is left byte-identical because
it is *already* consistent with its neighbours. Idempotent in both branches, and the readable branch
requires fixed width as well as a benign value — a legacy-format stamp can already decode to
`Int.max` while still leaking through its length (Bug 85).

**`deletionToken` is the readability oracle.** It is the right one on three counts: it is set on
exactly this population, it is always encrypted, and its plaintext is the known constant `Data([1])`
— so it confirms a *correct* decrypt rather than a merely non-throwing one. It also tracks the row's
bulk state rather than a stray field, which matters for the Bug 97 population, where one stamp can
be current-key while the names are stranded. Probing an individual stamp would misread those rows
and re-seal all three into readability against stranded neighbours.

**`migrateDepthFieldsToFixedWidth` fetches live rows only**, so it stops feeding fault 1.

**On losing the key-free property.** Bug 89 valued that the pass *"cannot be blocked by an
unavailable key"*. The readable branch necessarily gives that up — it exists to write values that
decrypt. It degrades rather than breaking: with no key, `deletionToken` will not decrypt, every row
reads as stranded, and the pass falls back to exactly the old key-free length normalisation.

**Page hygiene needed no new work.** `PRAGMA secure_delete = ON` (`OccultaApp.swift:210`) zeroes the
freed page holding the pre-scrub ciphertext rather than leaving it in the freelist, and
`deleteContact` already calls `checkpointStore()` after its save, so the WAL frame is flushed. The
scrub is placed before that save and is covered by both.

### Residual, accepted

Every scrubbed row now reads identically. An examiner holding the key and comparing the live
population against the deleted one has a weak distributional signal: live contacts vary across
depths, deleted ones are uniformly ordinary. Accepted rather than closed. Sampling the benign value
from the live distribution would flatten it and would risk writing a value that names a real layer,
which is a strictly worse trade. The values chosen are also what an install that never activated
Secure Mode holds, so the population blends into the innocent baseline rather than into itself.

### Guard

`ScrubMatchesRowReadabilityTests` covers both branches: a readable row's stamps decode to the benign
triple and still decrypt afterwards, a stranded row's do neither, the readable branch is idempotent,
and a readable legacy-width stamp is rewritten even when its value is already benign.
`FixedWidthPassExcludesDeletedRowsTests` pins the fetch filter in both directions.
`DeleteContactScrubsStampsTests` covers the deletion-time control — the one that keeps the
population from growing. All three fail against the pre-fix code.

Bug 89's own suite is unchanged and still passes: its fixtures use a `deletionToken` that does not
decrypt, so those rows take the stranded branch, which is the behaviour it was written to assert.

---

## Bug 90 — One unmigratable contact permanently blocks every v1 contact after it, and can leave a half-migrated row behind

**Status:** **Fixed 2026-08-20.** Found 2026-08-19 on a live device reporting
`Migration error: authenticationFailure` on every launch alongside seven contacts whose fields no
longer decrypt.

All three parts landed together, because the first two are unsafe apart: isolating per contact
without discarding the partial mutation would have made the corruption reliable rather than
incidental. Per-contact `do/catch` with `modelContext.rollback()`, failures left at `v1` so they are
retried; resume, so a field already converted by an earlier partial run is left untouched instead of
throwing; and `autosaveEnabled = false` across the migrations (`c5c32d3`) so the rollback has
something to roll back.

Guarded by `MigrateToV2ResilienceTests`, which asserts through a **fresh** `ModelContext` rather than
the in-memory object — `rollback()` discards the context's pending changes, but an already
materialised reference can still hold the mutated value, and only what reached disk matters.

**Target:** unset. Independent of Bugs 85–88; this is the v1→v2 scheme migration, not the depth work.

### Severity: High (data availability, and a corruption path)

The blocking half is certain and permanent. The corruption half needs a partial mutation to reach
disk, which the current call sequence makes possible rather than hypothetical — see "The second
defect".

### The first defect: one bad row stops the rest, forever

`migrateToV2` fetches every contact still marked `v1_identityDerived` and migrates them in a loop:

```swift
for contact in contacts {
    if contact.deletionToken == nil {
        try self.migrateContact(contact, legacyCrypto: legacyCrypto, newCrypto: newCrypto)
    }
    contact.encryptionScheme = EncryptionScheme.v2_hybridPQ.rawValue
    try modelContext.save()
}
```

`try` propagates out of the loop, so the **first** contact whose legacy ciphertext will not
authenticate ends the whole pass. Three consequences compound:

1. Every v1 contact *after* it is never processed — however many that is, and however recoverable
   they individually were.
2. The scheme marker is advanced *after* the migrate call, so the failing row stays `v1` and is
   retried on the next launch, where it fails identically. The block is permanent, not transient.
3. The fetch has no `sortBy`, so which contacts end up stranded depends on SwiftData's return order
   — arbitrary, and not necessarily stable between launches.

`OccultaApp.migrate()` catches and logs, so the app carries on and the failure is invisible outside a
DEBUG build. Contacts left at v1 have their fields read with v2 crypto, fail to decrypt, and are then
excluded from every view because `isVisible` fails closed — so they read as "gone" rather than as
"broken".

**One unrecoverable row strands an unbounded number of recoverable ones.** That is the defect; the
first row's own data may well be genuinely unreadable, and nothing can fix that.

### The second defect: the partial row can be committed by a later migration

`migrateContact` assigns field by field — fourteen scalar strings, then images, then the forward
secrecy blob, then relationships — mutating the model object in place as it goes. A throw on, say,
`jobTitle` leaves the preceding fields already re-encrypted to v2 **on the live object**.

That alone would be harmless, because the failing contact's `save()` is never reached. But
`OccultaApp.migrate()` creates **one** `ModelContext` and passes it to every migration in sequence:

```swift
let context = ModelContext(self.sharedModelContainer)
do { try DatabaseMigration.migrateToV2(modelContext: context, …) } catch { … }
do { try DatabaseMigration.migrateSafeContactVisibilityBackfill(modelContext: context) } catch { … }
…
```

The backfills and the fixed-width pass all call `save()` on that same context. So the partially
mutated contact — dirty, and still holding v2 ciphertext in some fields and v1 in others — is
committed by the next migration that saves anything.

The row then has mixed-scheme fields with `encryptionScheme` still reading `v1`, and nothing records
which fields are which. The next launch tries the legacy key against all of them, fails on the first
already-converted field, and throws again.

### Remedy

1. **Isolate per contact.** Wrap the `migrateContact` call in its own `do/catch`, count failures, and
   continue. Leave a failed row at `v1` rather than advancing its marker — collapsing "not yet
   migrated" into "migrated" would destroy the only evidence that a retry is possible, the same
   reasoning as Bug 80's `reencryptPreserving`.
2. **Do not let a partial mutation escape.** Either give `migrateToV2` its own `ModelContext` so a
   discarded context discards the partial row, or build the new values locally and assign them only
   once every field has succeeded. The second is better: it makes atomicity a property of the
   function rather than of how the caller happens to sequence contexts.
3. **Report counts**, not just the first error. The current log gives one `authenticationFailure` and
   no indication of how many rows are affected or whether the rest would have succeeded.

### Adjacent, not part of this bug

`migrateToV2` decrypts and logs a contact's given name under `#if DEBUG`
(`let debugName = contact.givenName.decrypt()`). DEBUG-only, but it is a contact name in the console,
which is the one thing the rest of this subsystem's logging is careful never to emit.

### Guard

No test exercises `migrateToV2` with a contact that fails to decrypt. The two properties to pin are
that a failing row does not stop the ones after it, and that a failing row leaves **no** field
changed — asserted after a subsequent migration has saved on the same context, since that is the
path that commits it.

---

## Bug 91 — Three rules govern what `Contact.Draft` may carry, and none is written down or enforced

**Stale, 2026-09-11:** Rule 1's entire premise (`LayerContact`, `restoreContact`) no longer exists —
deleted whole by Removal Stages 0-4, 2026-09-10. Deactivation no longer restores contacts from a blob
at all. Only rule 3 (`Contact.Draft` as a wire-format leak) still has real footing.

**Status:** **Open.** Noticed 2026-08-19 while weighing whether `Contact.Draft` could serve as the
carrier type for Bug 90's atomicity refactor. **Substantially rewritten 2026-08-20** — the first
version framed this as "`Draft` should mirror `Contact.Profile` and does not", which is wrong, and
wrong in a direction that would cause harm if acted on. See "Why mirroring would be a bug".

**Target:** unset.

### Severity: Low, and the risk is future rather than present

Every field that must be carried today **is** carried. Nothing is currently lost. What is missing is
any statement of the rules, and anything that fails when they are broken — and the field list was
arrived at by patching three times after the fact, once after data had already been lost (Bug 23).

### The three rules

`Contact.Draft` sits at the intersection of three paths with different requirements. Each field it
omits is omitted for one of these reasons, and the reasons are not interchangeable:

| Rule | Applies to | Why |
|---|---|---|
| **Carry on `LayerContact`** | anything deactivation *overwrites* | the value must be captured at activation or the restore writes a fallback over it |
| **Set fresh at creation** | anything the import path should re-derive | a newly created contact has no history to preserve |
| **Never on `Draft`** | anything that must not leave the device | `Draft` is a wire format, not just a model carrier |

**The first rule is narrower than it looks.** A field needs a source in the blob only if
`restoreContact` writes it. It writes exactly six things: everything `save(contact: record.draft)`
assigns, plus `visibleThroughDepth`, `globalTrusteeDepth`, `originDepth` and `signedAttributes`.
Everything else survives untouched on the row, because a blob-sealed row is never deleted and
`save`'s update branch only assigns what `Draft` carries. That is why `forwardSecrecyEncrypted` and
`maxBundleVersion` are safely absent — nothing overwrites them.

That also explains the three fields bolted onto `LayerContact`. They are not there because `Draft` is
deficient; they are there because deactivation rewrites them and needs the captured value. Bug 23 was
exactly that: without the captured ceiling, restore wrote its `?? 0` fallback over a real
classification.

### Why mirroring would be a bug

`Contact.Draft` is the **shared-contacts wire format**. `Import+View.swift:292` filters received
basket files for `format == .contacts` and decodes `[Contact.Draft]` out of them, so a `Draft` is
something that arrives from another person's device.

Putting the depth stamps on `Draft` to "complete the mirror" would therefore put them in every
shared-contacts file. `visibleThroughDepth` would tell the recipient **which of your contacts you
marked sensitive** — the exact secret Secure Mode exists to protect, handed to someone else in a file
you deliberately sent them. `signedAttributes` and `globalTrusteeDepth` are private in the same way,
and `deletionToken` on `Draft` would let an import resurrect a deleted contact while
`encryptionScheme` would let it claim a scheme it is not in.

So `Draft`'s omissions are load-bearing. The first version of this entry recommended removing them.

### The exposure is latent, not live

Checked 2026-08-20: **nothing in production writes a `.contacts` file.** `format: .contacts` is
constructed only inside `#Preview` blocks. The app can receive shared-contacts files and never sends
one — the read side, the `Format` case in `Transfers.swift` (now `OccultaCore`'s `Basket.swift`) and the whole import UI exist, but the
write side was never implemented.

That is why this is filed rather than fixed, and why it is worth filing at all: the rule needs to be
written down **before** someone builds the send side. Whatever `Draft` carries on the day that lands
is what leaves the device.

### `originDepth` is the model

It is absent from both `Draft` and `LayerContact` *deliberately*, with a comment explaining that a
duress-origin contact is exempt from blob-sealing entirely and so can never reach the struct. That is
what a considered omission looks like. The others are correct, but they do not look like that, and
nothing distinguishes "correct by reasoning" from "not yet noticed".

### Remedy

1. **Write the three rules down**, on `Contact.Draft` itself. They are currently distributed across
   `restoreContact`'s assignments, `save(contact:)`'s create branch, and an unstated assumption about
   what a wire format may carry.
2. **Make them enforced rather than remembered.** The project already has the pattern:
   `EncryptedFieldCoverageTests` drives `Contact.Profile`'s coverage from a probe table with an
   `unprobedFields` tripwire, so a newly added stored property fails a test until someone classifies
   it. The same shape here would require every `Profile` property to be classified against the three
   rules above, with a reason.

The tripwire matters most for the third rule. Violating the first is a data-loss hazard that a blob
round-trip test would catch; violating the third is a privacy leak into a file the user hands to
someone else, and nothing would catch it at all.

### Not a carrier for Bug 90

Recorded because it was the question that surfaced this. `Draft` cannot serve as the compute-phase
carrier for Bug 90's two-phase refactor: it lacks `forwardSecrecyEncrypted`, its `identifier` and
`status` are `let` so it cannot be mutated in place, and its relationship children are value types
while `Profile`'s are `@Model` classes — so applying them back still requires pairing by identity,
which is the part of that refactor where a mistake would hide.

---

## Bug 92 — An exported backup file opens for anyone holding its backup key: the opt-in export passphrase isn't built

*Originally filed as "A backup file is readable from any layer, because the BEK is not layered".
Re-scoped 2026-09-24; see "Split, 2026-09-24" below.*

**Status:** **Open, re-scoped 2026-09-24 to the exported-file half.** The on-device half (the stored
backup key opens under the one vault key, so extracting it reads every depth's backup key) is
subsumed into Bug 119. Earlier: **Open — re-examined 2026-08-26, scenario narrower than originally filed.** Separated out
of Bug 88's design discussion, 2026-08-20, on noticing that fixing the export leak does not stop a
coerced session reading a backup file it *finds*. **That specific in-app scenario no longer reaches**
— see *Re-examined* below, added after Bugs 93 and 94 (both filed and fixed after this one) turned
out to close the only code path that ever calls `importBackup`. The remaining exposure is real but
different: raw key extraction outside the app, not a coerced PIN entry inside it. Severity re-rated
accordingly.

**Target:** unset. Independent of Bug 88 — that one needs no format change and should not wait for
this.

### Severity: Low (security) — re-rated 2026-09-24 from Medium; Medium since 2026-08-26, High before that

**2026-09-24:** what remains needs the file *and* the backup key obtained elsewhere: from k trustees
colluding, or by extracting it from the device, which is Bug 119's case. The in-app route is closed
(see "Split, 2026-09-24"), and k colluding trustees can already recover the owner's vault by design.
The export passphrase adds a factor on top of that trust model, which is why it is still worth building.

**Original reasoning, preserved:** Bug 88 needs someone to tap Export. This needs a backup file to
exist and be reachable — on the device, in Files, in iCloud. Weaker, but ordinary: backups are made
to be kept somewhere. **That comparison was about reachability, not about what a coercer can do once
they've reached it** — the second half turned out to be much narrower than assumed; see below.

### What happens, as originally found

The vault key comes from `deriveVaultKey(context:)` — a dedicated SE key gated on biometrics, with
**no depth input** — and nothing in the backup path references depth at all. So there is one BEK per
device, identical at every layer. That part is still true and is the whole reason a fix is still
worth building — see *Re-examined* just below for what it does and doesn't currently let a coercer
do about it.

A backup file is sealed with it. A duress session has it. Therefore a coerced session can decrypt any
backup file it can reach, including one exported from the real layer, and read entries the vault UI
would never show it because `isEntryVisible` filters them.

Bug 88's remedy stops an export from *containing* other layers. It does not stop this: the file is a
depth-bypassing artifact wherever it is stored.

### Re-examined 2026-08-26 — the in-app path this severity was rated on doesn't reach

Asked directly: how would a coercer actually get the app to decrypt a *found* file using the
device's own BEK? Traced every caller of `importBackup` — there is exactly one, inside
`attemptBEKRestore`'s shard-reconstruction branch (`Vault+Manager+Backup.swift:721-753`). Two things
built after this bug was filed, for unrelated reasons, close that path off for the population that
matters:

- **A device that already has a BEK** — the realistic target, someone who actually finished setting
  up backup — never reaches `importBackup` at all. `storePendingRestore` (Bug 93's own two-signal
  check) refuses to arm a newly-found file outright whenever `alreadyHasBEK` is true, before writing
  anything. Dead end at every depth, immediately.
- **A device with no BEK yet** can arm a found file, but completion still requires genuine trustee
  shards reaching threshold, and `attemptBEKRestore` only ever completes at depth 0 (Bug 93's
  deferral). So even here, a coercer sitting in a duress session watching this happen never sees the
  result — the decrypted entries only surface later, to the real owner, at their own next real
  unlock. "A coerced session can decrypt any backup file it can reach" does not hold even in this
  narrower case: nothing is ever displayed to the coerced session at all.

So the scenario this bug's High rating was based on — sit in duress, open a found file, read what
comes back — isn't reachable through the shipped UI today. **That doesn't make the underlying defect
harmless, it changes what kind of attacker can reach it:**

1. **Raw BEK extraction outside the app, then offline decryption** — device forensics, a jailbreak, a
   memory-dump exploit, or any other compromise that gets the BEK bytes directly rather than through
   the app's gated flows. None of the in-app guards above are barriers once the key is out, because
   none of that code is being run. This is what the PIN-combined derivation actually defends
   against: a leaked or forensically-extracted BEK alone still isn't sufficient, because the PIN —
   knowledge, not stored material — isn't part of what was extracted.
2. **A found file plus genuinely cooperating trustees, landing at the real owner's own later
   depth-0 unlock.** Not really coercion-shaped — closer to "someone else's old backup, someone
   else's real trustees, enough time" — and the result reaches the real layer for the real owner,
   never a coercer's view.

Neither of these is a duress-specific, PIN-coercion attack. The layering fix is still worth building
— the BEK genuinely is layer-blind, and that's a real design gap for anything that *does* get raw key
access — but the urgency is that of a device-compromise defense-in-depth measure, not a PIN-coercion
mitigation, which is why the severity below is re-rated rather than left at High.

### Why the obvious keys do not work

- **The BEK alone** is what we have — layer-blind by construction.
- **A layer key derived from the SE Secure Mode key** does not help: a duress session holds that key,
  so it could derive every layer's key.
- **A layer key derived from PIN *verifiers*** does not help either, for the same reason — the
  verifiers live in `AppLayerConfig`'s arrays under that same SE key.

### The one input a coerced session does not hold

**The PIN itself.** It is knowledge, not stored material. Verifiers let a candidate be checked; they
do not yield the PIN. A coercer at depth N knows the PIN they forced — correct, that layer is the
decoy — and does not know the real PIN.

That makes it the first input in this subsystem a coerced session genuinely cannot derive, and the
basis for the fix:

```
stretched = slowKDF(PIN, perFileSalt, high cost)
fileKey   = HKDF(ikm: BEK ‖ stretched, salt: perFileSalt, info: "occulta.backup.v2")
```

**Combined, not substituted.** The BEK alone is layer-blind; the PIN alone is six digits. Together an
attacker needs BEK access *and* PIN knowledge, which come from different places — the device or the
shards for one, the user's memory for the other.

### The number this turns on

`PINEntry.swift:70` sets `pinLength = 6`, so the space is 10⁶. **A repo-wide search finds no slow
KDF** — only HKDF, which is fast by design and correct for high-entropy inputs. Deriving a file key
from a 6-digit PIN with HKDF gives an attacker holding the device a few minutes of work.

So this fix has a hard dependency that does not exist in the codebase yet: a deliberately expensive
KDF for the PIN. **Skipping it produces a design that looks layered and is not**, which is worse than
not doing it, because the file would then be treated as protected.

### File format

The salt must be readable before the key can be derived, so it cannot live inside the sealed JSON.
Today the layout is:

```
OCBK | nonce(12) | ciphertext | tag(16)
└─plaintext─┘ └──────── AES-GCM sealed ────────┘
```

It becomes `OCBK | version(1) | salt(N) | nonce(12) | ciphertext | tag(16)`. **No `Codable` struct
changes** — `VaultBackup` and `VaultBackupEntry` are untouched.

**Note the trap this exposes.** `VaultBackup.version` lives *inside* the encrypted JSON, so reading
it requires decrypting, which requires already knowing the scheme and salt. It therefore cannot
version anything that affects decryption — which is precisely this change. The discriminator has to
be in the plaintext envelope. Keeping the magic and adding a version byte is preferred over a second
magic string: a reader can then say "this is an Occulta backup, but a newer one" rather than "unknown
file", and it leaves room for a third scheme.

### Two costs to decide before building

**Recovery gains a second factor.** The shard system exists so a lost device does not lose the vault.
Under this, shards alone stop being sufficient — the PIN is needed too. Defensible for a PIN the user
knows, but it is a new way to permanently lose a backup and belongs in the recovery UI rather than
being discovered.

**PIN rotation orphans old files.** A file sealed under the old PIN needs the old PIN forever.
Storing a wrapped key to avoid that would put the material back on the device and undo the benefit,
so the honest answer is that rotation means re-exporting — which the existing staleness tracking
already has somewhere to say so.

### Rejected: invalidating old files on re-activation

Considered folding an activation-scoped nonce into the derivation so that re-activating with the same
PIN makes old files unreadable, forcing a re-export. Rejected.

A backup exists for the case where everything else has gone wrong; tying its readability to an
unrelated later event means a user can re-activate, lose the device, and find the backup
cryptographically dead with every shard intact and the right PIN in hand. It buys no confidentiality
either — a leaked file is already out, and re-keying afterwards does not reach it.

The goal underneath it is freshness, and `refreshBackupStaleness()` / `BackupStalenessReport` already
serve that. *"This file is stale, re-export"* is recoverable; *"this file is dead"* is not.

### Reconciled with Bug 102, 2026-08-28 — not a duplicate, and each needs the other

Both entries open with the same sentence: the BEK is not layered. They diverge immediately, and
neither subsumes the other.

| | Bug 92 (this) | Bug 102 |
| --- | --- | --- |
| Harm | A backup *file* decrypts at any layer | In-app operations at a duress depth act on the *real* key |
| Attacker | Holds raw BEK bytes, obtained outside the app | Uses the app normally, in a duress session |
| Fix | Derive the file key from BEK ‖ slow-KDF(PIN) | Give each layer its own BEK |
| Blocker | No slow KDF exists in the codebase | ~~Storage-format change, staged~~ — **built, 2026-09-11** |

**Stale, 2026-09-11: the right column's blocker shipped.** Per-depth BEK storage landed
(`VAULT_KEY_LAYERING.md` §8 item 14) — Bug 102 is now closed, reclassified as subsumed into Bug 99;
see that entry's own reclassification note for the accounting. Everything else in this reconciliation
still holds unchanged: per-depth storage still does nothing for *this* bug, because `encryptedPayload`
stays sealed under the plain vault key (not depth-derived) regardless of which table holds the row —
someone holding raw extracted key material still gets every depth's payload. This bug's own remedy
(PIN-combined file key) is still blocked on the same missing slow KDF, unaffected by any of this.

**Per-depth BEKs do not fix this bug**, and the reason is already stated above under *Why the obvious
keys do not work*. Bug 102's slots would all be sealed under the vault key, which is not
depth-derived — so an attacker who extracts key material gets every slot, exactly as they get the one
BEK today. Layering the storage changes what the *app* will act on; it changes nothing about what
falls out of a device dump.

**And the converse: this bug supplies an input Bug 102's design is missing.** That design separates
its per-depth slots by code discipline for the BEK field — only convention stops a duress session
decrypting slot 0, because it holds the vault key. Its own §2.1 concedes this and calls the asymmetry
out. The PIN is the only input in this subsystem a coerced session does not hold, so a
PIN-combined derivation is what would make that separation cryptographic rather than conventional.
Whether to adopt it there, or to accept convention and say so plainly, is a decision the refactor has
to make rather than inherit.

**Bug 105 may have restored the in-app route this entry's severity was re-rated away from.** The
2026-08-26 re-rating turned on there being no way for a coercer to make the app decrypt a found file.
Bug 105 does not do that — but it hands a coercer threshold shares of the real BEK through ordinary
UI at a duress depth, from which the BEK reconstructs offline, after which any real-layer `.occbak`
he obtains (Bugs 100 and 101 supply the routes) decrypts. That is this bug's harm reached without a
jailbreak, forensic extraction or a memory dump — the three things the re-rating rested on.
**Re-rate deliberately after Bug 105 is settled**, rather than leaving Medium standing on reasoning
that predates it.

### Split, 2026-09-24

Re-examined against the current code, as the "Bug 105 may have restored the in-app route" note above
asked once Bug 105 settled (it closed 2026-09-10).

**The in-app route is closed.** Only two places touch a backup file's contents: `exportBackup`, which
seals it, and `restoreBackup`, which opens it only with a key rebuilt from returned shards and checked
against the file's GCM tag (`verifiedKey`). No code opens a file with a stored backup key. Every depth
has its own backup key (`VAULT_KEY_LAYERING.md` §7 stages 1-2), so a duress layer's export and shard
distribution act on its own key (Bug 105). A restore refuses at a depth that already has a backup key,
and counts only shards from contacts visible at the current depth (§9.4). The one way in is the owner's
real trustees left visible in the duress layer, having handed back their shards: that is the residual
Bug 99 and §9.4 already accept, not a separate one.

**The on-device half is Bug 119.** Per-depth backup keys are sealed under the one vault key, which is
not derived per depth, so extracting it yields every depth's backup key and opens any real `.occbak`.
The same attacker reads every depth's entries straight from the database anyway. The fix is Bug 119's,
`PASSPHRASE_LAYER_KEYS.md`, which already names the backup key's cross-depth scan among the things it
must handle. Subsumed there; see Bug 119's note of the same date.

**The exported-file half stays here.** `VAULT_KEY_LAYERING.md` §8 item 4 (decided 2026-09-06, not built)
replaced this entry's PIN-combined file key with an **opt-in, 6-word passphrase per export**: EFF
wordlist via `Manager.PassphraseGenerator`, about 77.5 bits, generated fresh for each export and shown
once. It isn't the app PIN, so changing the PIN never orphans a file, and at that entropy plain HKDF is
enough, so the missing slow KDF (see "The number this turns on") no longer blocks anything. Its scope,
as decided: it protects a file obtained without the owner's cooperation (from `Documents/Inbox`, Bug 101;
a device backup; or k trustees colluding), and nothing against a coercer holding the owner. Layer keys
don't cover this: they protect the stored key on the device, not the file against someone holding the
key from elsewhere.

**Superseded in this entry:** the PIN-combined derivation, the "Two costs" section (both costs belonged
to the PIN design; recovery from shards alone stays the default, since the passphrase is opt-in), and
that Bug 105 severity caveat. The file-format section still applies: the passphrase salt and a scheme
version have to sit in the plaintext envelope.

### Guard

`VaultBackupRoundTripTests` already pins that a backup carries no plaintext label or content, and
that entries survive a round trip — both of which must hold across the envelope change. What it
cannot yet assert is the property this bug is about: **a file exported at one layer must not decrypt
at another.** That test is the fix's acceptance criterion.

Note that criterion is satisfiable two ways, and only one of them is real. Per-depth BEKs make it
pass for a caller going through the app; only the PIN-combined derivation makes it pass for someone
holding the storage. A test written against the app's own API cannot tell those apart, so it should
assert on raw key material rather than on a decrypt call.



**2026-09-24:** the cross-layer criterion above now belongs to Bug 119. For this entry's re-scoped half
the acceptance criterion is: a file exported with a passphrase does not open from the backup key alone
(shards or stored key), and does open with the key plus the passphrase; a file exported without one
still restores from shards alone.
---

## Bug 93 — Vault recovery is depth-blind: a coerced session sees the pending restore, and the restore runs into whatever layer it is standing in

**Stale, 2026-09-11:** The Guard section cites `attemptBEKRestore`/`fetchDecodedBEK` — renamed to
`attemptBackupRestore`/`fetchDecoded` by this session's BEK storage refactor
(`VAULT_KEY_LAYERING.md` §8 item 14).

**Status:** **Fixed 2026-08-25, all four harms.** Filed 2026-08-22 while checking, for Bug 88's fix
plan, whether `pendingRestoreActive` is depth-aware. It was not, and neither was anything else in the
recovery path. Built in five parts, each committed separately: **A** — `currentDepth` threaded
through `unlock(context:)` and the `OccultaApp.swift → ShardCustodyManager.handleInbound →
handleHandback` / `acceptReturnedShard` chain. **B** — `refreshPendingRestoreState` and
`attemptBEKRestore` both force published state false/defer above depth 0; `isRestorePending` added
as the always-truthful signal for the two functional consumers (`acceptReturnedShard`,
`handleHandback`) that must keep absorbing shards and relaxing signature checks regardless of depth.
**C** — a distinct `showBackupNotice` alert for `alreadyProcessed`, separate from the generic
`showError`, so a legitimate user sees a neutral acknowledgment rather than an "Error" dialog. **D**
— the on-disk filenames renamed from `pending-restore.occbak` / `pending-restore-shards.dat` to
`backup-import-cache.occbak` / `backup-import-cache-shards.dat`, closing harm 3 independent of the
other four parts. **E** — dedicated tests for all three `storePendingRestore` outcomes, which
surfaced and fixed a real ordering bug: the pending-file branch wrote a second file's bytes to disk
*before* checking whether one was already pending, so a different `.occbak` could silently replace a
genuine in-flight restore while the caller still saw the same reassuring `alreadyProcessed`. **A
fourth harm, found the same day in review** (a coercer could distinguish the three
`storePendingRestore` outcomes by which duress response they got, without ever seeing depth 0) **was
fixed same-day too** — see *Harm 4, found after the fix* below. See *The design, settled* below for
the shape all five parts implement, and *Guard* for what covers it now.

**Target:** met. **Bug 88's import-side remedy depended on this** — see *Relationship to Bug 88*;
that remedy can now proceed.

### Severity: High (security), with the same shape of precondition as Bug 92

Needs a pending restore to exist: a `.occbak` awaiting shard recovery. That is not an edge case — it
is the ordinary state of a device being rebuilt after loss, which is the exact situation the shard
system exists for, and the exact situation a user is most likely to be carrying a partly-configured
device around in.

**"No BEK yet" is not only the lost-device case.** Checked 2026-08-25:
`Manager.Key.retrievePrivateKey()` (`Key+Manager.swift:163`) does `SecItemCopyMatching` against a
fixed, hardcoded tag before ever calling `create()`, and keychain items survive an app delete on the
same device by default — nothing here deletes them first. So the identity key persists across a plain
uninstall/reinstall; only the SwiftData database (Application Support) is wiped. That means "no BEK
yet" covers three distinct starting states, not one: a genuinely new device, the same device erased
("Erase All Content and Settings"), or the same device with the app merely reinstalled. **This bug's
exposure is identical across all three** — it has nothing to do with whether the identity key
happens to have rotated, only with there being a pending restore and no depth awareness anywhere in
the path. The distinction matters for Bug 94's remedy, not this one; noted here so the precondition
isn't misread as narrower than it is.

### What happens

`refreshPendingRestoreState()` (`Vault+Manager+Backup.swift:546`) sets the published state from a
file's existence and a shard count. No depth input:

```swift
func refreshPendingRestoreState() {
    self.pendingRestoreActive = FileManager.default.fileExists(atPath: Self.pendingRestoreURL.path)
    self.pendingRestoreShardCount = self.pendingRestoreActive
        ? ((try? self.loadRestoreShards())?.count ?? 0)
        : 0
}
```

`Vault+Tab.swift:238` renders it unconditionally — no `isSecureModeActive` check, no `currentDepth`
check:

```swift
if self.vault.pendingRestoreActive {
    …
    Text("Restoring your vault")
    Text("\(self.vault.pendingRestoreShardCount) recovery pieces collected")
}
```

And `attemptBEKRestore()` (`Vault+Manager+Backup.swift:589`) guards on `isUnlocked` and
`pendingRestoreActive` and nothing else, then calls `importBackup`:

```swift
guard self.isUnlocked, self.pendingRestoreActive else { return }
```

It is reached from `unlock(context:)` (`Vault+Manager.swift:175`) — **every unlock, at every depth** —
and from `acceptReturnedShard` (`Vault+Manager+ReturnBuffer.swift:85`) whenever a shard arrives.

So the whole depth-blind surface is:

| Surface | Depth-aware? |
|---|---|
| `refreshPendingRestoreState()` | No — file existence only |
| `pendingRestoreActive` / `pendingRestoreShardCount` | No |
| "Restoring your vault" banner, `Vault+Tab.swift:238` | No |
| `attemptBEKRestore()` on unlock and on shard arrival | No |
| `postRestoreActionNeeded` → `VaultPostRestoreSheet`, `Vault+Tab.swift:142` | No |

### Three harms, and they are not the same one

**1. Disclosure to a coerced session.** A coercer holding the phone at a duress depth reads
*"Restoring your vault — 3 recovery pieces collected"*, watches the counter climb as trustees hand
shards back, and is then shown a post-restore sheet offering to set up backup. The duress layer is
supposed to be a complete, boring, plausible device; instead it volunteers that a vault exists, that
trustees exist, that recovery is inbound, and roughly how close it is. It also gives the coercer a
reason to wait rather than give up.

**2. The restore completes into the duress layer.** Combined with Bug 88's import half —
`importBackup` never sets `visibleThroughDepth`, and `isEntryVisible` reads nil as visible at every
depth — the recovered entries become visible immediately in the coercer's view. **A coerced session
watches the real vault arrive.** Neither bug alone does that: Bug 88 needs someone to reach an
import, and this is what reaches it, automatically, unprompted.

**3. The filenames are self-describing, with no live session required at all.** Checked 2026-08-25.
`Vault+Manager+Backup.swift:586-591` writes the two restore files as literally
`pending-restore.occbak` and `pending-restore-shards.dat`, unobfuscated, sitting in Application
Support. Harms 1 and 2 both need a live coerced session at the *duress* depth. This one needs
neither a coercer nor any depth at all — a forensic examiner, a border search, or anyone else with
filesystem access to a seized or extracted device reads the filenames without decrypting anything and
learns a recovery is in progress, purely from `ls`. Compare `backup-export-meta.dat`
(`Vault+Manager+Backup.swift:813`, already noted in Bug 96 item 4's "self-describing artifacts") —
that name at least has a plausible cover story, since exports are ordinary. These two name the
*mechanism* directly: not "this app made a backup," but "this device is mid-recovery, right now."
Any fix that only addresses the live-UI banner (harms 1 and 2) leaves this open — it needs the
restore files themselves to stop naming what they are, independent of whatever the deferral design
ends up being.

### What is *not* wrong with it today

Worth stating so the fix is not misjudged. The banner is **not currently a duress oracle**. It shows
the same thing at every depth, so a coercer cannot compare it against a real-layer view they never
see, and its presence is fully explained by facts they can already observe. The defect today is
disclosure and misdelivery, not a tell.

### Relationship to Bug 88

Bug 88's import remedy is *"import at depth M stamps every restored entry with M"*. That is correct
for a user-initiated import — the user chose the moment and the layer. It is wrong for this path,
because **nobody chose the moment**: the restore fires on whatever unlock happens to complete the
shard threshold. Stamping current depth would file a recovered real-layer backup into whichever
duress layer the user happened to unlock into, silently and unrecoverably in place.

The fix is to defer: `attemptBEKRestore` no-ops above depth 0 the way it already no-ops while
locked, and completes on the next depth-0 unlock. Shards continue to be collected and stored
meanwhile — storage is silent and `storeRestoreShard` already works while locked — so nothing is
lost, only postponed.

**But a deferral alone converts harm 1 into a genuine oracle.** A coercer who can see
*"5 recovery pieces collected"* and then watches the threshold pass with nothing happening has found
a view that contradicts itself, and self-contradiction inside a single view is exactly what an
observer can catch. The requirement is not that the duress view match the real one — the coercer
never sees the real one — but that **the duress view be internally coherent**. So the deferral and
the surface-hiding are one change, not two: above depth 0 the recovery machinery must both decline to
run *and* decline to announce itself, leaving a layer that looks like a device with nothing pending.

### The design, settled and built 2026-08-25

Neither shape originally proposed was quite right. Accept-silently-always leaves a real gap for the
"already armed, still pending" case (below). Per-layer state solves it but needs new storage the
problem doesn't actually require. The answer that fell out of walking concrete scenarios end to end:

**Depth has to reach three places it doesn't today.** `unlock(context:)` gains a required
`currentDepth: Int` parameter — its three call sites (`Vault+Tab.swift`, `VaultRecoverySettings.swift`,
`VaultShardHealth.swift`) all pass `security.currentDepth`; the last of the three doesn't have
`Manager.Security` in its environment yet and needs it added. The `acceptReturnedShard` path is
reached from `OccultaApp.swift`'s inbound-bundle handling, which already holds `self.security`
directly (confirmed before assuming it) — depth threads down through `ShardCustodyManager.handleInbound`
into `acceptReturnedShard` from there.

**`refreshPendingRestoreState` and `attemptBEKRestore` both gain the same guard.** Above depth 0, the
published state is forced to `false`/`0` regardless of what's actually on disk — not "hidden if
something's pending," genuinely false, so a coercer watching across multiple unlocks sees the same
nothing every time. `attemptBEKRestore` additionally refuses to complete above depth 0, matching the
"defer and hide together" requirement above — deferral alone (without the state-forcing) is what
turns harm 1 into a self-contradicting oracle; this is why they ship as one change.

**`storePendingRestore` gets a new check, and it resolves the open question.** Not "is this exact
file already known" — "does any restore state already exist," pending or completed:

```
pending file already exists (recovery armed, not yet complete)  →  true
        OR
a BEK already exists (recovery already completed)               →  true
```

Both halves reuse state that's already there — the pending file's mere presence, and remedy 1's
existing `fetchDecodedBEK` check — so this needs **no new persisted history**. If either is true: at
depth 0, show the real, specific truth ("still restoring" or "already set up"); above depth 0, show
a single flat acknowledgment — *"this backup file has already been processed"* — true in either
sub-case, since it doesn't claim which one. If neither is true (genuinely nothing has happened yet):
depth 0 starts the live progress UI as it does today; above depth 0, silent accept, file written,
nothing shown.

**Why "any restore state" rather than "this exact file" is the right framing, not a shortcut.** It
means the message is never a lie — a *different* `.occbak` shown while one is already pending or
done gets the same honest "already processed," rather than needing file-identity tracking (hashing,
persisted history) to stay truthful. It also matches the constraint that already existed
independently: accepting a second, conflicting restore target mid-flight is its own hazard, so
refusing it is correct behavior regardless of the forensic question.

**The first implementation of that refusal only half-honored it, and Part E's tests caught the
other half.** `storePendingRestore`'s pending-file branch wrote the incoming file's bytes to disk
*before* checking whether one was already pending, throwing `alreadyProcessed` only afterward — so
a second, different `.occbak` silently replaced a genuine in-flight restore, while the caller saw
the identical reassuring message either way. Writing the dedicated "already pending" test surfaced
it directly: assert the throw, then assert the bytes on disk are still the *first* file's, and the
original code failed that second assertion. Fixed to check-then-refuse, symmetric with the
BEK-exists branch beside it, which already refused before writing. This is the same "other
population" Bug 94 still flags open (no BEK exists yet, so remedy 1's overwrite refusal never
applied here) — worth the cross-reference since it's the same shape of hazard, one layer earlier.

**Two pieces flagged as unresolved, both since closed:**

1. The message's display surface reuses the existing `showError`/`errorMessage` pattern in
   `OccultaApp.swift`, rather than needing new UI: a second `@State` pair (`showBackupNotice` /
   `backupNoticeMessage`) and a second `.alert`, placed the same way inside the `.unlocked` branch
   for the same Bug 84/56 reason, wired via a `catch VaultManager.BackupError.alreadyProcessed`
   clause ahead of the generic `catch`.
2. Checked directly: `BackupError` has no `LocalizedError` conformance, so
   `error.localizedDescription` on `.invalidFormat` already produces Swift's generic, non-revealing
   fallback string — identical at every depth, via the same generic `showError` alert. No fourth
   case; the malformed-file path was already depth-safe before this work started.

**Why the legitimate user isn't burdened by any of this.** A real recovery, done by the actual owner,
has no reason to be initiated from a duress PIN in the first place — she would naturally do her own
recovery at her real depth, which is exactly the path that shows her everything. The constraint only
becomes visible in the adversarial case: a coercer forcing the duress PIN and trying the file anyway,
which is precisely where "tell them nothing true or false" is the correct behavior.

### Harm 4, found after the fix, 2026-08-25 — fixed same day

Found while walking a proposal to relax the depth-0 completion gate (rejected — see below). The
proposal's justification ("silence in duress reads as a tell") turned out to be correct, just not for
the reason it was raised for.

**Duress's response to opening a `.occbak` was not uniform across the two-signal check's three
states.** A genuinely new file (nothing pending, no BEK) was accepted silently — no alert of any kind.
A file opened while one was already pending, or while a BEK already existed, showed the flat
`alreadyProcessed` acknowledgment (Part C). Those were two different observable outcomes, and the
difference between them **leaks which of the three states is true, without ever needing to compare
against depth 0** — a coercer who tries more than one `.occbak` against the same duress session sees
some produce an alert and some produce nothing, which is the two-signal distinction read straight off
the UI. And even with a single file: an adversary specifically probing for a decoy layer doesn't need
to see the victim's real depth at all — they can install the same shipped app, test it themselves with
no coercion involved, learn independently that opening a `.occbak` is *supposed* to produce some
acknowledgment, and then notice its absence on the victim's device. "The coercer never sees depth 0"
is not the same claim as "the coercer has no way to know what normal behavior looks like," and the
original design conflated the two.

**This was narrower than it first looked, and doesn't reopen harms 1 or 2.** There are two different
surfaces bundled under "what does duress show," and only one of them was fixable this way:

- **The one-time file-open acknowledgment** (this harm) — whether *anything at all* is shown the
  moment a `.occbak` is opened. **Fixed:** `OccultaApp.swift`'s `.occbak` handling now shows the same
  "Backup file received" acknowledgment above depth 0 for all three states — fresh accept, already
  pending, already done — via a local `do`/`catch` around `storePendingRestore` rather than the
  now-removed outer `catch VaultManager.BackupError.alreadyProcessed` clause. The wording is
  deliberately vague: it has to stay true whichever of the three actually happened, so it can't imply
  completion or duplication. Depth 0 keeps its differentiated, truthful behavior unchanged — silent +
  live banner for fresh, the existing "already been processed" wording for pending/done — since this
  constraint is about duress's internal consistency, not about matching depth 0.

  **Superseded 2026-08-27, and both halves of this bullet were rebuilt.** The acknowledgment is
  gone entirely and the banner below is now depth-uniform. The paragraph above scoped depth 0 out
  rather than clearing it, and the distinction was lost afterwards — the divergence got cited later
  as a settled decision when it had only ever been declared out of scope.

  **The comparison this fix ran was duress-against-duress:** can someone read the device's state by
  trying several files in one duress session? No. The comparison nobody ran was
  duress-against-real, which is the one a coercer can actually make. They open any `.occbak` —
  their own will do — and read which session they are in off the reply: depth 0 said "already been
  processed" on any device with a vault, or stayed silent on one without, where duress said
  "Backup file received". The repo is public, so the baseline needed to interpret that is too.

  **It could not be closed from the duress side.** Depth 0 varied its reply on whether a BEK
  exists, and duress is deliberately blind to that, because surfacing real-layer state is a worse
  leak than this one. Removing the message from duress alone — the obvious move — inverts the tell
  rather than removing it: silence-versus-speech is legible at a glance, where a wording difference
  at least needs prior knowledge. That is also roughly where this design started, before this harm
  replaced it.

  **So the acknowledgment was removed rather than harmonised.** The confirmation the user already
  tapped (Bug 94 remedy 3) is the receipt for a fresh accept, and the banner is the durable signal.
  A malformed file still errors at both depths; that branch turns on the file's own bytes, not on
  vault state or depth.

  **Cost, accepted:** on a device that already has a backup configured, opening another one now
  does nothing visible at all, where it used to say why. That is the price of the uniformity.

  **And that price is conditional on the architecture, not permanent — see Bug 102.** Depth 0 had to
  vary its reply on whether a BEK exists, and duress could not, only because there is one BEK for the
  whole device. With a per-layer recovery subsystem each layer answers truthfully about its own state,
  and that answer is identical to what a real session in that layer would give. The acknowledgment
  should come back if that lands. Recorded here so this reads as "correct for the current design"
  rather than as a settled conclusion about what the user is allowed to be told.

  **Redirect, not correction, 2026-09-12: Bug 102 no longer exists to point at, but the dependency
  itself is still live and still unmet.** `VAULT_KEY_LAYERING.md` §8 item 14 already gave the BEK
  its per-layer storage this paragraph was waiting for — checked directly, `storePendingRestore`
  (`Vault+Manager+Backup.swift:434`) still hard-codes its `alreadyHasBEK` check to depth 0 regardless
  of which depth is actually arming, so "depth 0 had to vary its reply... duress could not" remains
  true today for the *reply* even though the *storage* it's about is no longer device-wide. What
  this paragraph is actually waiting for is `RECOVERY_BUFFER_LAYERING.md`'s own Stage 4 (arming
  state made genuinely per-depth) — tracked forward under Bug 99, not Bug 102, per that bug's own
  2026-09-11 reclassification.

- **The ongoing progress banner** — was the persistent, updating shard count in the vault tab.
  Originally judged un-unifiable: showing it in duress was harm 1 outright (direct disclosure that a
  recovery is inbound), and fabricating a plausible, consistently-timed counter that tracks nothing
  real is a harder and riskier build than the problem it solves — wrong timing or an inconsistency
  across repeat checks is itself a tell, and a worse one.

  **Revised 2026-08-27: the banner is now shown at every depth, and the count is gone.** That
  reasoning was sound but attached to the wrong part. What could not be shown in duress was the
  *number* — a live tally is a report on real depth-0 activity, and it would visibly climb during a
  duress session, since shard collection is depth-independent (`storeRestoreShard`) even though
  reconstruction is not. Dropping it leaves "Recovery in progress…", which claims no progress, so it
  cannot contradict itself across repeated unlocks and reads the same as a real recovery still
  waiting on trustees it has not met.

  **"Depth-independent" is now imprecise, corrected 2026-09-12 — the fix's conclusion is unaffected.**
  `RECOVERY_BUFFER_LAYERING.md` §2.1's Stage 3 gate now drops an inbound shard op (`.handback`
  included) when its sender isn't visible at the current depth, before `storeRestoreShard` ever runs
  — collection is no longer *unconditionally* depth-independent. This narrows, doesn't reopen, the
  concern above: a real depth-0 trustee typically isn't visible at a duress depth, so their handback
  now gets dropped and retried rather than silently banked during a duress session — the exact
  cross-depth accumulation this paragraph worried about. The static "Recovery in progress…" text
  remains the right choice regardless (a duress-depth-visible sender, per Bug 99's attack, still
  accumulates freely), just no longer the *only* thing standing between duress and a climbing count.

  Neither horn of the original objection applies to the static form: it is real state rather than a
  fabrication, so there is no timing to get wrong, and it is identical in both layers, so there is
  nothing to compare. What it does concede is that duress advertises an event whose result only ever
  lands at depth 0 — accepted, because a recovery that visibly never finishes is an ordinary thing
  for one to do, and because the alternative was leaving a divergence a coercer can read in one move.

  This reverses half of "defer and hide together". **Deferral is what makes it safe and stays
  load-bearing:** `attemptBEKRestore` still refuses above depth 0, now pinned by
  `pendingRestoreNeverCompletesAboveDepthZero`. `refreshPendingRestoreState` no longer takes a depth
  at all, and the test that required it to publish false above depth 0 is inverted to require
  uniformity.

**The rejected proposal, for the record.** Allowing `attemptBEKRestore` to complete above depth 0
when no BEK exists yet was suggested on the theory that a coercer would need cooperating trustees to
reach threshold, so there was no real risk. Traced through `handleHandback`
(`ShardCustody+Manager.swift:201-219`): once `isRestorePending` is true, signature verification on
incoming shard attributes is skipped entirely — deliberate, for the rotated-key new-device case — so
nothing checks that a shard came from a real, previously-established trustee at all. A coercer with
physical access to the victim's phone (no-BEK state only — Bug 94's still-open "other population")
can set up their own vault on their own device, export their own `.occbak`, deliver it and their own
self-authored shard attributes through the same file/bundle-open channel used for everything else, and
reach threshold using entirely self-supplied material — no real trustees needed. Today the depth-0
completion gate stops this cold: nothing completes while the coercer is watching. Relaxing it for the
no-BEK case would make this exact attack succeed live, in front of them, instead. Kept as built.

### Guard

Updated 2026-08-25, Part E: `VaultRestoreDepthGatingTests` (`VaultRestoreTrustTests.swift`) covers
the depth surface directly — `genuineRestoreCompletesAtDepthZero`, `genuineRestoreDoesNotComplete
AboveDepthZero`, `shardsStillAccumulateAboveDepthZero`, `publishedStateIsForcedFalseAboveDepthZero`.
`VaultRestoreTrustTests` covers all three `storePendingRestore` outcomes by name —
`storePendingRestoreAcceptsAGenuinelyNewFile`, `storePendingRestoreRefusesWhenBEKAlreadyExists`,
`storePendingRestoreRefusesWithoutOverwritingWhenAlreadyPending` — the last of which is what caught
the write-ordering bug above. Filenames are asserted directly in `VaultRestoreTrustTests.swift`'s
own path constants (`backup-import-cache.occbak` / `-shards.dat`), which fail to compile-match if
production and test ever drift.

**Harm 4's fix has no automated coverage.** `storePendingRestore` itself is unchanged by that fix —
it still throws `alreadyProcessed` for two of the three states and returns normally for the third,
exactly as `VaultRestoreTrustTests`' three outcome tests already assert, and those tests remain
correct descriptions of the underlying function. What changed is `OccultaApp.swift`'s UI wiring
around that call, which none of the `VaultManager`-level tests reach at all — they call
`storePendingRestore` directly, not through the app's file-open handling. Verified by reading the
resulting code path for all three states rather than by a test; a SwiftUI-level test that opens a
`.occbak` through the app and asserts on `showBackupNotice`/`backupNoticeMessage` would close this
gap if one is added later.

Acceptance criteria, matching *The design, settled*:

- ✅ A restore reaching threshold at depth > 0 must leave `pendingRestoreActive` false to the UI, must
  not insert entries, and must complete on the next depth-0 unlock with the entries stamped 0.
- ✅ A genuinely new `.occbak`, no prior restore state, opened above depth 0: silent write to the
  pending-restore file, `pendingRestoreActive` stays false. Superseded in spirit by Harm 4's fix below
  (the file-open response is no longer silent), but the underlying storage behavior this criterion was
  really about — no live count, no state change visible above depth 0 — still holds.
- ✅ A `.occbak` opened above depth 0 while a restore is already pending *or* already completed (BEK
  exists): the flat acknowledgment shown, never the live count, and identical whichever of the two
  underlying states is true.
- ✅ The same two cases at depth 0 show the real, specific state — this is not a security requirement,
  it is the difference between the depth-0 and duress paths that makes the whole design coherent.
- ✅ Harm 3 needs its own criterion, independent of any UI behavior: the on-disk filenames must not
  name the mechanism, regardless of the above.
- ✅ **Harm 4:** all three `storePendingRestore` outcomes produce the same one-time acknowledgment
  above depth 0 — never silence for one and an alert for the others — so trying multiple files against
  the same duress session never produces a distinguishable pattern. No automated test; see *Guard*.

### Noted in passing, not filed

`handleHandback` (`ShardCustody+Manager.swift:207`) relaxes shard signature verification whenever
`pendingRestoreActive` — deliberate, for the rotated-key new-device case, and documented as such.
It is not depth-related, but it is a second behaviour that changes based on this same unguarded flag,
and it should be re-read once the flag becomes depth-aware.


---

## Bug 94 — A hostile `.occbak` destroys the real BEK and injects vault entries, because the restore path lets attacker-supplied material authenticate itself

**Stale, 2026-09-11:** Cites `reconstructBEK`/`attemptBEKRestore`/`persistBEKPayload`/
`fetchDecodedBEK`/`setupBEK()`/`distributeBEKShards`/`prepareBEKShards` throughout — all renamed by
this session's BEK storage refactor. The `Vault+Manager+Backup.swift:721` citation for
`attemptBEKRestore` now points at unrelated legacy-array-migration code.

**Status:** **All three remedies in as of 2026-08-26.** Remedy 1 fixed 2026-08-24; remedy 2 (trustee
attestation) built and tested 2026-08-26; **remedy 3 (explicit confirmation) built 2026-08-26**, when
a security review of `release/v1.10.3` established that it is not the optional third of three but the
only control that actually gates this attack — see *Remedy 3, and why the threshold cannot be
enforced* below. Filed 2026-08-22 during a critical read of the
export/import mechanism, requested after Bug 93. Found by asking what `ownerIdentity: nil` actually
gives up. **Remedy 1 (overwrite refusal) is in** — `reconstructBEK` now refuses before touching
Shamir, GCM, or `persistBEKPayload` whenever a BEK row already exists, closing the *destructive* half
unconditionally. **Remedy 2 closes "the other population" below** — the no-BEK-yet population, most
users most of the time, is no longer able to have a fully attacker-controlled vault silently planted
by any known contact. **Remedy 2's first-pass design had a critical gap** — a naive implementation let
a single attacker self-attest a full threshold's worth of forged shares, reintroducing this bug's
exact severity through the new mechanism — found and closed before any code was written; see
*Implementation, worked out and stress-tested* below for the corrected design, now built exactly as
specified there and covered by `ShardHandbackAttestationTests.swift` (9 tests, including the specific
single-attacker case the review caught). **Remedy 3 (explicit confirmation before an automatic import
mutates the vault) is the only piece of the original three-part remedy still open** — kept as
defense-in-depth on top of remedy 2, not load-bearing on its own; see *Remedy* below.

**A consequence of remedy 1, found and closed the same day.** Every group `reconstructBEK` sees
on an existing-BEK device now fails immediately via `bekAlreadyPresent` — so the "success" branch
in `attemptBEKRestore` that clears `pendingRestoreActive` and deletes the restore files can never
run. Without a further change, one hostile `.occbak` would leave the device stuck in "restoring"
state permanently: the banner never clears (Bug 93's surface), and every future shard arrival
keeps appending to a file nothing can ever read successfully again (Bug 96's growth item).
`attemptBEKRestore` now checks for an existing BEK *before* touching the shard file at all, and
if one exists, clears `pendingRestoreActive` and deletes both restore files immediately rather
than letting every group fail one at a time. Because `acceptReturnedShard` calls
`attemptBEKRestore()` synchronously right after every `storeRestoreShard()`, this bounds growth
on an existing-BEK device to roughly one shard per arming cycle in real usage — see Bug 96's
entry for what this does and does not resolve there.

**Target:** unset. **Independent of Bugs 88, 92 and 93** — those are about depth. This one survives
all three being fixed.

### Severity: Critical (security)

Preconditions are two, and both are ordinary: the user opens one attacker-supplied `.occbak`, and the
attacker is an established contact able to send `.occ` bundles. No confirmation prompt exists
anywhere in the flow to interrupt either half.

### The circular argument

`attemptBEKRestore` (`Vault+Manager+Backup.swift:721`) reconstructs with signature verification
switched off:

```swift
try self.reconstructBEK(shards: group, backupData: backupData, ownerIdentity: nil)
```

`reconstructBEK`'s doc comment states the substitute: *"Pass nil on new-device path (old key
non-migratable); GCM tag substitutes."* And the GCM tag does prove something — that the reconstructed
BEK opens `backupData`.

**But on this path the attacker supplies both.** They generate a BEK, seal their own `VaultBackup`
JSON under it, Shamir-split it, and send the shares. The tag then proves their shards match their
file, which is true and worthless. The ECDSA check against the owner's identity is the only thing on
this path that binds the material to *this device*, and it is the thing being skipped.

### The chain, end to end

**1 — The file is armed with no confirmation, and above the Secure Mode gate.**
`OccultaApp.swift:645-660` routes any `.occbak` into `storePendingRestore`, which validates four
magic bytes and — since Bug 93 — the two-signal check (refuses if a BEK already exists or a restore
is already pending) and nothing else about the file's actual contents or provenance:

```swift
if fileLocation.pathExtension == "occbak" {
    let currentDepth = self.security.currentDepth
    do {
        try self.vaultManager.storePendingRestore(data, currentDepth: currentDepth)
        …
    } catch VaultManager.BackupError.alreadyProcessed { … }
    return
}

// Secure Mode gate: if the app is locked, queue raw bytes without any processing.
if self.appScreen.phase != .unlocked { … }
```

The `return` is still *above* the lock check, so a `.occbak` arms a pending restore while the app is
locked — unlike every other inbound file type, which is queued unprocessed. Bug 93's additions
(depth threading, the two-signal check, the acknowledgment UI) changed what gets displayed and when
completion is allowed to run; they did not add any check on the file's contents, so this step is
otherwise unchanged from when this bug was filed.

**2 — Forged shards are accepted, twice over.** `handleHandback`
(`ShardCustody+Manager.swift:201`) hard-rejects a bad signature *except* during a pending restore:

```swift
guard vaultManager.isRestorePending else { throw CustodyError.signatureRejected }
```

**Renamed from `pendingRestoreActive` by Bug 93 (2026-08-25), same behavior.** Bug 93 needed
`pendingRestoreActive` to start lying above depth 0 for display, and split off `isRestorePending` as
an always-truthful twin specifically so this gate — a functional check, not a display one — would
keep working exactly as before. Confirmed against the actual diff: `isRestorePending` reads identically
to how `pendingRestoreActive` behaved pre-Bug-93, at every depth. **This bug's exploitability is
unchanged; only the name in this quote was stale.**

Then `acceptReturnedShard` (`Vault+Manager+ReturnBuffer.swift:38`) performs what its own
documentation calls *"Best-effort signature verification"* — it logs under `#if DEBUG` and continues
regardless. Step 1 of its documented steps enforces nothing in any build. It validates
`category == .shard` and a non-nil `entryID`, and **never checks that `entryID` names a distribution
this device ever created.**

`.handback` is also the only `ShardOperation.Kind` whose handler receives neither `senderPublicKey`
nor `senderIdentifier` — `handleDistribute` and `handleReplace` both take them.

**3 — Reconstruction "validates."** Shamir returns the attacker's BEK; `AES.GCM.open` on the
attacker's file succeeds; the guard passes.

**4 — The real BEK is deleted.** `persistBEKPayload` (`Vault+Manager+Backup.swift:1005-1008`) is
delete-and-replace:

```swift
let existing = try self.modelContext.fetch(FetchDescriptor<BackupEncryptionKey>())
for row in existing { self.modelContext.delete(row) }
self.modelContext.insert(BackupEncryptionKey(id: rowID, encryptedPayload: combined))
```

Every genuine backup file sealed under the old BEK becomes permanently unrestorable, and the
trustees' real shards now reconstruct a key that matches nothing on the device.

**5 — Entries are inserted.** `importBackup` writes the attacker's rows into the user's vault.

**Nothing guards on the device already having a BEK.** `attemptBEKRestore`'s only preconditions are
`isUnlocked` and `pendingRestoreActive`. An established device with a healthy vault runs all five
steps.

### The other population: no BEK yet, and remedy 1 does not reach it

Checked 2026-08-22, asking whether "refuse to overwrite an existing BEK" (remedy 1, below) is a
complete fix. It is not — it protects exactly the population that already has something to lose, and
does nothing for the population that doesn't yet, which given `setupBEK()`'s single opt-in caller
(`Vault+ShardSetup.swift:553`, `.backup` mode only) is most users most of the time, and permanently
for anyone who never turns the feature on.

Steps 1, 2, 3 and 5 above do not depend on step 4 (the overwrite) at all. On a device with no BEK row,
`fetchDecodedBEK` returns `nil`, step 3's reconstruction still "validates" against the attacker's own
file, and step 5 still inserts. **Nothing is destroyed, because nothing existed — but a working,
plausible, attacker-controlled vault is planted where none was, silently, with no anomaly for the
user to ever notice.** That is arguably worse than the overwrite case: overwriting at least breaks
something a user might go looking for; planting creates something they have no reason to.

**The attacker does not need to be a trustee.** `handleHandback` checks a signature (skippable, see
above) and nothing else — there is no `ShardRecord` to check the sender against, because none exists
until a BEK does. And `ShamirSecretSharing.reconstruct` only requires `shares.count >= 2`
(`ShamirSecretSharing.swift:137`). So the minimal attack is: any existing contact — not specifically
someone the victim ever entrusted with recovery — sends one hostile `.occbak` (sealed under a BEK of
their choosing) plus two forged `SignedAttribute` `.handback` ops forming a valid 2-of-2 split of
that same BEK, sharing one `entryID`. `identifyOwner(for:)` (`Contact+Manager.swift:1501`) does still
require the sender to be a *known* contact — an unrelated stranger's bundle never decrypts — but nothing
requires that contact to be a trustee.

**Remedy 1 does not cover this population, by construction — only remedy 2 does**, since it is the
only mechanism capable of asking "is this genuinely the owner's own material" rather than "does
something already exist to protect." Any acceptance criterion for this bug that stops at "an existing
BEK cannot be overwritten" is incomplete.

### Remedy

Three changes, smallest first. The first closes the *overwrite* sub-case only — see above for the
sub-case it leaves fully open.

1. **Refuse to overwrite an existing BEK row during restore.** A device that already holds a BEK is
   not a fresh restore target. Kills step 4 with no format change and no new state. Does not help a
   device with no BEK — see above.
2. **Verify against the owner's current identity when possible; accept a trustee's attestation when
   it isn't — never an unconditional skip.** See below; this is not a looser version of the ECDSA
   check, it is a second, different mechanism for the one case the check structurally cannot cover.
3. **Require explicit confirmation before an automatic import mutates the vault.** Bug 93 already
   establishes that this path runs unprompted on unlock.

### Why remedy 2 can't just be "verify more strictly"

Worth spelling out, because the natural first read of remedy 2 — check the signature whenever
possible — undersells what the rotated branch actually needs.

**A single shard cannot be authenticated in isolation, on either path.** `SignedAttribute.signature`
is the *owner's* signature over the shard, made at `prepareBEKShards` time by whatever SE identity key
existed on the device that split the BEK. Checking it needs that same key's public half. On an
unrotated device, `retrieveIdentity()` returns it — the check is real and remedy 2's first half
applies directly. **On a genuinely new device it does not, structurally, because SE keys are
non-exportable and die with the device they were created on.** There is no looser version of an
ECDSA check that recovers a public key which no longer exists anywhere reachable — tightening the
check cannot help a device that has nothing to check against.

**"Unrotated" is broader than "never lost the device," and this matters for scope, not just for
wording.** Checked 2026-08-25 against `Manager.Key.retrievePrivateKey()` (`Key+Manager.swift:163`):
it looks the identity key up under a fixed, hardcoded keychain tag before ever creating one, and
keychain items survive a plain app delete on the same device — only the SwiftData database gets
wiped on uninstall. So the same-device-reinstall population — no BEK, but the identity key intact —
is `retrieveIdentity()`-unrotated in every sense that matters here, and Branch A authenticates its
returning shards correctly with zero new mechanism. **Attestation is load-bearing only for the
remaining two starting states: a genuinely new physical device, or the same device deliberately
erased.** Both are real and both need it — but the population this remedy has to cover is narrower
than "any recovery with no BEK yet" (Bug 93's precondition) suggests on its own.

The other candidate oracle doesn't help either. The GCM tag on the backup file is the only signal
that survives rotation, but it operates on a **reconstructed group**, not a single share — Shamir
shares are information-theoretically indistinguishable from random individually, which is what makes
secret sharing work at all. So there is no per-shard test available on the new-device path, only a
post-hoc one on the whole group (see Bug 95, which is what a forged share does to that group).

**The rotated case needs a different kind of trust anchor, not a weaker version of the same one.**
Not a new one, either — Occulta already has what's needed, just not applied here. **The trustee is
the anchor.** `Contact.Profile.Key` is append-only (`Contact+Manager.swift:552`, `update(key:for:)`):
when Bob re-pairs with the owner's new device over UWB — which has to happen anyway, or none of his
bundles decrypt on that device at all — his contact record for the owner gains a new key without
deleting the old one. He still holds the exact public key that originally signed his `CustodyShard`,
long after the owner's own device has lost the ability to verify against it. **Bob can perform the
check the owner's device structurally cannot, using data that was never his to lose.**

So the fix is not a new channel for the shard to travel over. It already travels over an ordinary
bundle, authenticated the ordinary way, to a contact the owner's new device re-paired with over UWB
regardless. The fix is what the trustee attaches to it: a fresh signature, made with *his own current*
identity key, attesting that he checked the share's original signature against his own retained copy
of the owner's old key before sending it. The owner's device cannot check the old signature. It can
check this one — the same way it already checks anything else from a contact it has UWB-established.

### The design: trustee attestation

Two other designs were considered and rejected before this one, recorded so they are not
re-proposed without re-deriving why they were wrong.

**Rejected: a dedicated live exchange session for the shard specifically.** The instinct was to reuse
`ExchangeManager`'s `NISession`/`MCSession` machinery (`Exchange+Manager.swift:30`) as a new, separate
ceremony for handing back a shard. Redundant: the proximity anchor it would provide already exists,
upstream, in the ordinary re-pairing required for Bob's bundle to decrypt on the owner's new device at
all. A second session would re-prove something already proven.

**Rejected: asking the owner to enumerate her trustees at recovery time.** The instinct was that since
the device has no local record of who held what (`shardMetadata: nil` on reconstruction — Gap 2
below), only the owner's own memory could supply it. Wrong premise: the record was never the owner's
alone to lose. The trustee's own contact history survives exactly where the owner's identity does not,
and an owner-supplied list adds nothing an honest trustee's attestation doesn't already prove, while
adding a step a coerced or careless owner could get wrong.

**What attestation actually closes.** It is self-limiting to genuine trustees by construction — to
attest, Bob needs both a real `CustodyShard` and a matching historical key for the owner, neither of
which an arbitrary contact (the population identified above, in "The other population") was ever
given. There is nothing to fake possessing. This closes that population's attack categorically, not by
raising the cost of it.

**What it does not close, and why that is not a gap in this design.** Nothing cryptographically forces
a trustee to have actually performed the check before signing an attestation — it is a claim, not a
proof the claim's process ran. A single dishonest or compromised trustee could sign an attestation
over fabricated bytes. But one fabricated share, mixed with k−1 genuine ones, simply fails to
reconstruct anything that opens the target file — Shamir does not degrade gracefully. Defeating this
needs k or more trustees dishonest *and* colluding, which is the same assumption every k-of-n
threshold scheme already rests on. Attestation is not required to improve on that baseline; nothing
built on top of Shamir sharing is.

**Kept as cheap defense-in-depth: do not silently auto-arm the file.** Attestation closes the shard
side outright, which means the file side matters less than it did — but a colluding-majority attacker
who also controls what `.occbak` gets tested against is a strictly worse position for the owner than
one who does not. Moving `storePendingRestore`'s trigger behind a deliberate "restore my vault, pick
your backup file" action, instead of the current silent handler on any inbound file, costs little and
narrows that residual case further. Not load-bearing on its own — see "The other population" above for
why a confirmation step alone cannot stop an attacker who supplies both sides.

### Implementation, worked out and stress-tested 2026-08-26

**"Defeating this needs k or more trustees dishonest and colluding," above, is not automatic from
attestation existing — it is a property of one specific mechanism, and a first-pass design of that
mechanism didn't actually have it.** Recorded in full because the failure mode is exactly the kind
this bug is about: a check that looks like it closes the population but doesn't.

**The flaw a naive Branch B has.** The obvious shape — accept a shard whenever its signature fails
direct verification but an attestation from a known contact vouches for it — only checks that *some*
known contact signed *something*. It never independently verifies the original `attribute.signature`
against anything. Nothing stops the attester and the "original signer" from being the same party: a
single known contact (not a trustee, never given a real share) can invent their own fake
`SignedAttribute` with an observable target `entryID`, sign an attestation over it with their own
current key, and have it verify cleanly — because it genuinely is their own signature over their own
fabricated data. Nothing stops them minting `threshold`-many distinct fake `SignedAttribute.id`s this
way, all sharing the target `entryID`. `ShamirSecretSharing.reconstruct` only checks
`shares.count >= threshold` and distinct x-coordinates — it does not check who sent them. One attacker,
alone, reconstructs a key of their choosing. That is Bug 94's original severity, relocated into the new
code path, not the "k colluding trustees" bound this design is supposed to provide.

**The fix: enforce distinct senders, not just distinct share IDs, toward any threshold.**

1. The attestation is a `SignedAttribute` with a new `.attestation` category, signed by the trustee's
   current identity key over `SHA256(attribute.signingPayload())` — a hash, not the raw payload, so the
   attestation doesn't carry a second copy of the raw shard bytes (`signingPayload()` includes `value`,
   the actual GF(2^8) shard material) alongside the original in the same message.
2. `handleHandback` accepts via **Branch A** (`attribute.verify(against: ownKey)` — can only ever be
   genuine; forging it means breaking ECDSA or stealing the SE key, so no dedup is needed for this
   branch) or **Branch B** (`attestation.verify(against: senderPublicKey)`, the hash matches, `entryID`
   matches).
3. Every stored share — both the per-entry `ReconstructShard` buffer and the BEK-restore shard file —
   carries `senderIdentifier` alongside the attribute and attestation. Storage keeps **at most one
   share per `(entryID, senderIdentifier)`**, replacing rather than accumulating on a repeat from the
   same sender. Reconstruction then structurally requires `threshold` *distinct senders*, because
   that's what the stored count now actually reflects — restoring the bound the design always claimed.
4. **Dedup key is `senderIdentifier` (the contact record), not `senderPublicKey`'s fingerprint.**
   Stress-tested this choice rather than assuming it: keying on the raw public key would let a single
   hostile trustee reinstall the app or use a second device, generate a fresh identity key, re-pair with
   the owner as "the same contact" (`Contact.Profile.Key`'s history is append-only — nothing marks an
   old key as the *only* valid one), and hold two fingerprints that both count — a cheaper Sybil than
   establishing a second contact relationship. `senderIdentifier` stays stable across a trustee's own
   legitimate key rotation, correctly counting them once.
5. **`senderIdentifier` is receiver-derived, not sender-asserted — checked directly, not assumed.**
   Traced both call sites (`OccultaApp.swift:835-864` group path, `:885-909` 1:1 path): `ownerID` comes
   from the *receiving* device's own `contactManager.openGroup(...)`, and `senderPublicKey` is looked up
   *from* that resolved `ownerID` via `currentPublicKey(forIdentifier:)` — the lookup runs
   identifier-on-file → key, not key → sender-claimed-identifier. An attacker can't assert a different
   name across bundles; whichever contact the decrypting key actually resolves to on the receiver's own
   records is what `senderIdentifier` will be, every time. This is what makes step 3's dedup sound —
   had this gone the other way, the whole mechanism would need a different anchor.
6. **BEK-shard and per-entry-PEK-shard storage need different gates, not one flag loosened
   uniformly.** A per-entry share can be gated precisely: the device already knows locally which
   entries have an outstanding distribution (`VaultEntry.shardDistributionEncrypted != nil`), so gate
   on that rather than the old global flag — more precise *and* safer than today, where the buffer
   insert is otherwise ungated on anything but `category == .shard`. A BEK share can't be gated that
   precisely: a fresh device doesn't know the expected `distributionID` before reconstruction succeeds
   (it lives inside the encrypted BEK payload), so `isRestorePending` has to stay as that gate — an
   earlier pass proposed dropping it everywhere, which was wrong for this branch specifically. Gap 1's
   bootstrap-window removal still holds for the per-entry case, where a precise gate now exists to
   replace it.

**What stays explicitly out of scope, on purpose:** a genuinely-established, otherwise-legitimate
trustee still overwriting their own stored share with poisoned material — remedy 2 authenticates
provenance, not correctness, and error-correction against a bad-but-genuinely-sent share is Bug 95's
territory, not this one's. Sybil identities via *separate* contact relationships (distinct from the
same-trustee-multiple-keys case step 4 closes) — the app already treats an established contact,
however recently added, as its baseline trust unit everywhere else; closing that boundary isn't this
fix's job.

**Built and tested 2026-08-26**, exactly as specified above — `SignedAttribute.Category.attestation`,
`AttestedShard`, `OccultaBundle.ShardOperation.attestation`, `handleHandback`'s Branch A/B, the
per-`(entryID, senderIdentifier)` storage cap in both `acceptReturnedShard` and `storeRestoreShard`,
and the trustee-side `attestation(for:)` builder. `ShardHandbackAttestationTests.swift` covers both
directions: the owner-side accept/reject logic (including the single-attacker-cannot-reach-threshold
case this review caught) and the trustee-side building path end to end, including the
no-matching-retained-key fallback to no-attestation-at-all rather than a fabricated one. Full
affected-suite regression passes clean.

### The gate is too narrow even for the mechanism it already has

Traced 2026-08-22, prompted by asking whether an owner-identity rotation could be closed out
afterward by re-signing what trustees already hold. It can't be done in place — that would move the
raw share value between devices again — but the trustee side already contains most of what a clean
reissue needs, and two separate gaps stop it from finishing.

**The trustee side already self-triggers on rotation.** `buildShardOperations` calls
`mismatchHandbackOps(for:currentFP:)` with whatever fingerprint the trustee currently has on file for
the owner. The moment a trustee re-pairs with the owner's new device — updating their own contact
record — their *next ordinary outbound bundle* compares that fresh fingerprint against
`CustodyShard.payload.ownerKeyFingerprint` (captured at original distribution), finds a mismatch, and
offers the stale shard back as `.handback`, unprompted. This is not hypothetical machinery to build —
it already runs.

**Gap 1 — `handleHandback` only accepts a mismatch during an active restore.** Its guard is
`vaultManager.isRestorePending` (renamed from `pendingRestoreActive` by Bug 93, 2026-08-25 — same
behavior, see *The chain, end to end* above). Once the owner has already recovered, that check is
false, so any *later* mismatch-handback — from a trustee who re-pairs after the fact, which is the
ordinary case, since not every trustee is available at the moment of bootstrap — is hard-rejected
with `CustodyError.signatureRejected`. There is no accept-and-reconcile path for a trustee returning
a stale shard as routine hygiene outside the bootstrap window.

**Gap 2 — re-examined 2026-08-26, and the claim as originally written doesn't hold.** The reasoning
up to the redistribution decision is still right: `reconstructBEK` clears `shardMetadata: nil` on
success, so a freshly-recovered owner has no record of who held what, `distributeBEKShards`'s
existing-vs-new-trustee split reads every trustee as new off that empty map, and redistribution
issues plain `.distribute`. **But the conclusion — that `.distribute`'s handler never cleans up the
stale shard — is wrong.** Checked directly: `handleDistribute`
(`ShardCustody+Manager.swift:116-144`) calls `deleteMismatchShards(for:newFingerprint:)` at line 142,
unconditionally, on every accepted `.distribute`, using the fingerprint of whoever just signed the
incoming shard. `git log` traces this call to `0f5392a` (2026-05-04, the original manifest-based
reconciliation protocol) — nearly four months before this bug was filed, so this was never a
regression introduced alongside the rest of Bug 94's finding; the doc's claim was incorrect from the
moment it was written, not something that changed later. **So a post-recovery `.distribute` to a
trustee already holding a stale shard for that owner does get cleaned up**, the same way `.replace`
does — Gap 2 does not need its own fix.

**Net effect on Gap 1 alone: a trustee's stale shard is only orphaned between recovery and their
next re-pairing** — not permanently, as originally written, since redistribution's `.distribute`
already cleans it up once it arrives. In that window, offering it back gets hard-rejected; a repeating
rejected-handshake pattern between the same two identities in that window is still worth weighing
against this project's forensic-trace standard, the same way B4 is, but it is bounded, not indefinite.

**Gap 1 resolves as a side effect of remedy 2's design, not as a separate fix.** Once
`handleHandback`'s acceptance condition is "verifies directly (Branch A) or carries a valid trustee
attestation" rather than "verifies directly or `isRestorePending` is true," there is no global flag
left to scope in the first place. The attestation check is safe to run on *any* incoming handback,
bootstrap or routine hygiene alike, because it is self-limiting to genuine trustees regardless of
when it arrives. The tension with remedy 3 that an earlier version of this entry raised here doesn't
apply once the accept condition stops being a flag at all.

**Constraint on any fix touching the `.occbak` handler.** The extension is shared with the Secure
Mode layer store by design — `forensic-trace-avoidance.md` **B4**, *"Vault backups use the same
`.occbak` extension and are indistinguishable at the filesystem level"* — and the OCBK magic check in
`storePendingRestore` is what keeps a blob out of the restore path. All three remedies above route
through that handler. None may make the two formats distinguishable to an examiner, and none may
surface a user-visible response to a file that fails the magic check.

### Why this shape recurred

The rationale for `ownerIdentity: nil` is genuine — a new device's SE identity key has rotated, so
old shards cannot verify against it, and no amount of stricter checking recovers a key that no longer
exists. But the fix routed *around* the problem instead of solving the rotated case on its own terms:
the check was removed for every device on the path, including those whose key never rotated, rather
than being paired with a mechanism that actually covers rotation. **The unrotated case needs the
existing check enforced; the rotated case needs a different anchor — the trustee's own attestation —
not a skipped one.** This is the same failure mode as Bug 80's stranded `maxBundleVersion` and Bug
81's fail-closed gate: an exception written for one state applied unconditionally instead of being
scoped to it.

### Guard

`VaultBackupRoundTripTests` covers the honest round trip; `VaultRestoreTrustTests` covers remedy 1
(overwrite refusal). `ShardHandbackAttestationTests.swift` (2026-08-26, 9 tests) covers remedy 2
directly — this is the suite that actually exercises the population remedy 1's own tests don't reach.

Acceptance criteria, and which test covers each:

- ✅ A device holding a BEK must reject a restore that would replace it —
  `foreignShardsCannotReplaceExistingBEK` (`VaultRestoreTrustTests`, pre-existing).
- ✅ A device with no BEK must reject reconstruction from shards that carry neither a valid direct
  signature nor a valid trustee attestation — `noAttestationRejected`.
- ✅ A rotated-identity share must be accepted on its attestation, never on the direct signature or
  the GCM tag alone — `branchBAttestationAccepted`, `attestationWrongSenderRejected`,
  `attestationHashMismatchRejected`.
- ✅ A contact who was never given a real share must be unable to produce an accepted attestation
  under any circumstance — `noMatchingRetainedKeyProducesNoAttestation` (no retained key → no
  attestation, not a fabricated one) combined with `singleSenderCannotReachThresholdAlone` (even a
  self-consistent fabricated attribute+attestation pair from one identity cannot single-handedly
  reach threshold).
- ✅ **The specific vulnerability this review caught**: a lone attacker must not be able to
  self-attest a full threshold's worth of forged shares — `singleSenderCannotReachThresholdAlone`
  directly, `sameSenderReplacesNotAccumulates` for the underlying storage mechanism.
- ✅ The trustee-side builder must produce a working attestation when it genuinely can, and decline
  cleanly when it can't — `trusteeBuildsAttestationOnFingerprintMismatch`,
  `noMatchingRetainedKeyProducesNoAttestation`.
- ✅ None of the above may produce a crash or a silent insert — implicit in every test above asserting
  an exact `reconstructShardCount`, not just "no crash."
- ✅ A mismatch-handback arriving after recovery has already completed must be reconcilable on the
  same attestation check, not rejected for arriving outside a bootstrap window — resolved by
  construction: `handleHandback`'s accept condition is no longer a flag (`isRestorePending`/
  `pendingRestoreActive`) at all, so there is no bootstrap window left to fall outside of. No
  dedicated test beyond the Branch A/B tests above, since there is no separate code path left to
  test differently.

Explicitly out of scope for this bug's guard, and inherent to any k-of-n scheme rather than a defect
in this one: k or more genuinely-held trustee shards being dishonest and colluding.

### Remedy 3, and why the threshold cannot be enforced

Added 2026-08-26, from a security review of `release/v1.10.3`. Remedy 3 was carried as the soft third
of three — nice to have once the cryptographic remedies were in. That reading was wrong, and the
reason matters more than the remedy.

**What remedy 2 actually delivers is a floor of two distinct senders, not `threshold`.** The one-row-
per-`senderIdentifier` rule is real and does what it says: one identity cannot self-attest a group.
But nothing on the BEK path checks the *count* against the owner's chosen `k`. `attemptBEKRestore`
groups by `entryID` and hands the group to `reconstructBEK` with `ownerIdentity: nil`, so the only
floor left is `ShamirSecretSharing.reconstruct`'s own `shares.count >= 2`. An attacker authors the
`.occbak`, generates its BEK, and splits that BEK with `k = 2` — so two paired identities suffice
regardless of what the victim's real distribution used. Two devices, or one enrolled twice.

**And the check cannot be added, which is the part worth recording.** Enforcing a threshold requires
knowing the owner's `k` on a device that has no BEK — a fresh install or a new phone, which is
precisely the population remedy 2 exists for. That value survives in exactly three places, and none
of them is available there:

| Where `k` lives | Why it does not help |
| --- | --- |
| The BEK payload's `ShardDistributionMetadata` | The restoring device has no BEK. That is the precondition for being on this path at all |
| The `.occbak` file | Authored by the attacker. Reading `k` from it is reading the constraint from the party it constrains |
| The trustees | `prepareBEKShards` records `threshold` in the *owner's* payload. A trustee is given a share and never learns `k` |

So a threshold check here would be theatre: either unenforceable or self-asserted. Recording this so
the "just enforce the threshold" fix is not re-proposed — it looks obviously correct until you ask
where the number comes from.

**What actually gates the attack is the victim opening and accepting the file**, which is remedy 3.
There was previously no confirmation at all — `storePendingRestore` armed on the strength of opening
a file, and arming is not inert: it makes the device accept BEK shards from contacts and, once enough
arrive, import the file's entries into the real-layer vault with no further prompt. A confirmation
now precedes arming.

**At every depth, and the first attempt at this got it wrong.** The prompt was initially scoped to
depth 0, reasoning that a confirmation above it would be the distinguishable response Bug 93 harm 4
exists to prevent. That misreads which half of the interaction harm 4 constrains. The
*acknowledgment* has to vary with the outcome — fresh accept, already pending, already done — and is
therefore the thing that must be flattened above depth 0. The *prompt* is raised before
`storePendingRestore` runs and cannot vary with the outcome at all: same text, same buttons, same
order, in all three cases. Making it uniform across depths satisfies harm 4 completely.

Scoping it to depth 0 also introduced a leak of its own, in the opposite direction to the one being
avoided. Its **absence** would tell whoever is holding the phone that they are not at depth 0 — that
they are in a duress layer. The app is open source, so the baseline behaviour that comparison needs is
public. A control that only fires in the real session is a depth oracle for anyone who knows the app.

The acknowledgment split is unchanged and still lives where it belongs, now in `armPendingRestore`:
uniform "Backup file received." above depth 0, differentiated and truthful at depth 0.

**The staged file carries the depth it was opened at**, rather than re-reading `currentDepth` when
the user confirms, so a depth change while the prompt is up cannot arm a file against a depth it was
never offered for.

The three doc comments that asserted the stronger property — `AttestedShard`, `storeRestoreShard`,
`ReconstructShard.Payload` — now state the real one and why it cannot be stronger. `ReconstructShard`
also notes the contrast worth keeping straight: the *per-entry* path does reach the entry's real
threshold, because that entry is one this device split itself, so its distribution is on hand and
every shard is verified against the owner identity. Only the BEK path is limited this way.

**Not covered by a test.** The confirmation is view state in `OccultaApp`. Needs a manual device
check: open a `.occbak` at depth 0 and again at a duress depth, confirm the prompt is identical in
both — text, buttons, order — and that declining leaves nothing armed at either. Same standing
limitation as Bug 93 harm 4's acknowledgment.

**Addendum, 2026-09-14 — Bug 124 finds remedy 2's actual protection narrower than assumed here.**
Branch B (attestation) never verifies the underlying share value is genuine, only that a currently-
recognized identity vouches for it. Bug 124 traces the revoked-trustee half of that; Bug 125
(2026-09-19) goes further and finds attestation's own signature redundant with transport-level sender
authentication regardless of revocation status — `handleHandback` already knows who sent this, one
layer up, before it ever looks at `op.attestation`. See Bug 125 for the current, complete word on
whether Branch B (as a mechanism, not just its size) is needed at all.

---

## Bug 94a — Remedy 2's attestation field is not padded, so slot size names the trustee who is mid-recovery

**Status:** **Fixed 2026-08-26**, same day as the code it reports on. Found by a security review of
`release/v1.10.3`, in remedy 2 itself.

**Target:** `release/v1.10.3`.

### Severity: Medium (forensic)

No key material is exposed and nothing is forged. What leaks is the shape of a relationship: which
member of a group send is genuinely holding shards for the sender, and that the sender's identity key
has rotated — i.e. that they are mid-device-recovery. In a duress-depth send, where the member list
is deliberately populated with contacts visible at that depth, this separates real trustees from
cover members by file size alone.

### What happens

Remedy 2 added `ShardOperation.attestation` and populated it in `mismatchHandbackOps`.
`ContactManager.fillerShardOperation` was not touched, so filler went out with `attestation: nil` —
and `SignedAttribute` uses synthesized `Codable`, which omits a nil optional's key entirely rather
than writing null. A populated attestation is roughly 260 bytes of JSON. Filler also carried
`entryID: nil` where every real `.shard` attribute binds one, worth about 50 more.

`ShardPadding` equalises the op **count** per recipient. Nothing equalises their encoded size. Each
recipient's `RecipientPayload` is JSON-encoded and sealed with AES-GCM, which is length-preserving,
and `GroupEnvelope`/`Recipient.wrappedPayload` travel as a cleartext JSON TLV block — so per-recipient
byte lengths are readable straight out of a `.occ` with no key. That is not an inference; it is what
`ShardPadding`'s own doc comment says the scheme exists to prevent.

`fillerShardOperation`'s doc comment meanwhile still asserted the invariant it no longer held:
*"filler and real entries aren't distinguishable by size within the array."*

### Why the existing test did not catch it

`GroupShardGatingTests.mixedGroupSendsToAllWithUniformSlotSize` asserts exactly the right property —
both recipients' `wrappedPayload` within a tight tolerance — and passed throughout. It sends a
`.distribute` op, and `attestation` is only ever set on `.handback`. The invariant was guarded on the
one op kind that could not exhibit the defect.

Its fixture had a second problem in the same direction: `makeSignedShardAttr` built `.shard`
attributes with `entryID: nil`, which production never produces (`prepareBEKShards` binds the
distributionID; per-entry splits bind the entry id). The fixture was ~50 bytes smaller than anything
real, so it also could not have caught the `entryID` half.

### Remedy

**Fill the field, do not omit it** — the pattern this codebase already uses for exactly this class.
`wrapRecipient` gives fallback-mode recipients a random `senderEphemeralSignature` of the right size
for the same reason, and its comment names the same failure: *"otherwise this field's mere
presence/size would let a mixed-mode group send distinguish FS from fallback recipients by
RecipientPayload size alone."* Same shape as `verifierFillerArray`, `pinEnabledFillerArray`, and tier
padding itself.

So every outbound op now ships an attestation: real where one exists, `attestationFiller` otherwise —
on `.distribute`, on `.replace`, on a `.handback` whose `attestation(for:)` returned nil, and on
padding filler. Filler matches the real thing field for field: 32-byte value, 72-byte DER-shaped
signature, same label, non-nil `entryID`.

Behaviour is unchanged on receive. `handleDistribute`/`handleReplace` never read the field. A filler
attestation fails Branch B exactly as a nil did, so a shard that needed a real one is still rejected;
`noMatchingRetainedKeyProducesNoAttestation` now asserts that directly rather than asserting nil.
`handleHandback` carries forward only a Branch B-*verified* attestation, so filler never reaches the
recovery buffer.

**Two residuals, both documented at the call site and neither scaling with content.** `kind`'s
spelling — `.unsupported` (11 bytes) against `.handback` (8) — cannot be normalised without breaking
the receiver's skip. And a real `.replace` carries an `attributeID` no other op has; giving filler one
would make filler the outlier against the far more common `.distribute`, so the more common shape
wins.

### Guard

`ShardOperationPaddingTests` encodes filler against a real attested handback and bounds the delta,
sampled over 200 encodes rather than measured once — `Date` encodes as a variable-length `Double` and
each op carries two, which is the same jitter that made the neighbouring test fail one run in three
before its bound was widened. A second test pins the specific omissions (`attestation` non-nil,
`attribute.entryID` non-nil, matching entryIDs) so they cannot return via a tidied nil default.

**Moot as of 2026-09-19 — `bugs.md` Bug 125 removed `attestation` from the wire format entirely.**
This entry's fix (pad the field so its presence/absence can't be a tell) was correct for as long as
the field existed; once there's no `attestation` field on `ShardOperation` at all, there is nothing
left to pad unevenly. `ShardOperationPaddingTests` was updated accordingly — it now compares a filler
op against a plain `.handback`, with no attestation on either side. Left as historical record of a
real bug, not rewritten to pretend the field it was about never existed.

`fillerShardOperation` is no longer `private`, solely so the first test can reach it. The general
lesson is in its doc comment: **every optional member a real op can carry has to be filled here**,
because tier padding equalises count and nothing equalises size.

---

## Bug 95 — One poisoned shard permanently blocks legitimate vault recovery

**Stale, 2026-09-11:** Cites `reconstructBEK` as the live call site — renamed to `Backup.reconstruct`
by this session's BEK storage refactor.

**Status:** **Fixed 2026-09-23**, on `v1.11.0/vault-key-layering`: `verifiedKey` searches subsets of
the shards against the backup file's GCM tag (see "Fix, as built" below). Of the three remedies below,
only the second was buildable by then. Filed 2026-08-22 alongside Bug 94, from the same read. **Re-verified
2026-08-26** against Bug 93's depth-gating: `attemptBEKRestore` now guards `currentDepth == 0` before
the grouping/reconstruction loop this bug lives in (`Vault+Manager+Backup.swift:723`) — not a fix,
just confirmation that the vulnerable code only ever runs at the one depth recovery was always meant
to complete at, same reachability as before.

**Re-verified again 2026-09-02, against Bug 94 remedy 2 — does not close this, and Bug 94's own entry
already says so** (`"remedy 2 authenticates provenance, not correctness, and error-correction against
a bad-but-genuinely-sent share is Bug 95's territory, not this one's"`), but this entry never recorded
the cross-reference even though both landed the same day. Traced `handleHandback`
(`ShardCustody+Manager.swift:219-255`) directly rather than relying on that note: Branch A/B
authentication plus per-`(entryID, senderIdentifier)` dedup closes Bug 94's actual scenario — one
unauthenticated party unilaterally minting `threshold`-many fake shares to reconstruct a key of their
choosing. It narrows this bug's population (a share must now come from a sender who can pass Branch A
or B, and dedup caps any one sender to a single stored share) but does not touch the mechanism this
bug is about: `ShamirSecretSharing.reconstruct` still does no subset search, so one fabricated-but-
properly-authenticated share mixed with k−1 genuine ones still poisons the whole group, and there is
still no UI path to discard a wedged restore. Same defect, narrower population, unchanged remedy.

**Target:** `v1.11.0`.

### Severity: High (availability)

Needs a pending restore and knowledge of the `distributionID`. **Any trustee has the latter** — it is
the `entryID` on the shard they hold — so the attacker set is exactly the people the user chose to
trust with recovery, which is the set this system already assumes may be partly hostile. Post-remedy-2,
narrow this to: a trustee (or any contact able to construct a Branch A/B credential) submitting one
fabricated share during a pending restore — still that same population, since knowledge of the
`distributionID` was already effectively trustee-scoped before remedy 2 shipped.

### What happens

`ShamirSecretSharing.reconstruct` (`ShamirSecretSharing.swift:136`) interpolates over **every share
passed to it**. There is no subset search and no try-all-k-combinations:

```swift
let xCoords = shares.map { $0[0] }
for byteIdx in 0..<32 {
    let yCoords = shares.map { $0[byteIdx + 1] }
    secret[byteIdx] = Self.lagrange(xCoords: xCoords, yCoords: yCoords)
}
```

`attemptBEKRestore` groups by `entryID` and hands the whole group in:

```swift
groups[eid, default: []].append(shard)
…
try self.reconstructBEK(shards: group, backupData: backupData, ownerIdentity: nil)
```

So one bogus 33-byte share carrying the real `distributionID` and a fresh x-coordinate merges with
the legitimate shares. Lagrange returns garbage, the GCM open fails, `continue`. The poisoned shard
is persisted in `pending-restore-shards.dat`, **no UI can clear it**, and every subsequent unlock
retries the same doomed group. Recovery is permanently dead.

Bug 94's signature bypass widens the attacker set beyond trustees to anyone who learns a
`distributionID`.

### What is already right

Worth recording so the fix is not misaimed at the arithmetic. `reconstruct` **does** close the
obvious attacks:

```swift
guard !xCoords.contains(0)                else { throw Error.invalidShareFormat }
guard Set(xCoords).count == xCoords.count else { throw Error.duplicateXCoordinate }
```

x = 0 is the secret itself, and a duplicate x would corrupt interpolation. Both are rejected. The gap
is not a flaw in the field arithmetic — it is that a well-formed share with a fresh x is
indistinguishable from a genuine one **once signature verification has been skipped**, and that
`attemptBEKRestore` treats a group as all-or-nothing.

### Remedy

- **Verify shard signatures** (Bug 94, remedy 2). A forged share never enters the group. This is the
  real fix; the two below are defence in depth.
- **Try k-subsets rather than the whole group** when the full group fails, bounded by a sane cap.
  `reconstruct` already rejects malformed input cheaply, and the GCM tag is a clean oracle for which
  subset is right. Cost is combinatorial — cap it, and prefer the signature fix.
- **Give the user a way to discard a pending restore.** There is currently no path to delete
  `pending-restore.occbak` or `pending-restore-shards.dat` from the UI, so any wedged restore is
  permanent regardless of cause. This is worth doing on its own.

### Where it stood by 2026-09-23

§9.4 (`RECOVERY_BUFFER_LAYERING.md`) removed the held file, so nothing stayed stuck on disk any more.
The poisoned share did, though: it sits in its sender's `PendingShamirSecretRestore` slot, and every
attempt combined every visible shard, so every attempt failed. Only that sender sending a good share
would clear it, and a hostile trustee won't.

How it arrives: after the owner re-pairs in person on a new phone, each trustee's next message carries a
`.handback`. A trustee running a modified app sends a 33-byte share with the real `distributionID`
(it's on the share they hold), any x that isn't 0 or another sender's, random values, and any
signature. `handleHandback` accepts it on trust (Branch A always fails once the owner's key has
rotated), and `absorbShard` banks it. The stock app can't produce one by accident: a damaged custody row
fails to decrypt and isn't sent, and a share from an older round carries a different `distributionID`.

Remedies 1 and 3 no longer applied:
- **Remedy 1, signature verification, can't work on the path that matters.** The key that signed the
  shares was on the lost phone, which is why `restoreBackup` passes `ownerIdentity: nil`. Bug 125
  removed Branch B, and nothing can replace it.
- **Remedy 3, a discard-restore UI, would now cause harm.** There's no pending restore left to
  discard, only banked shard rows, which are depth-blind. A discard in a duress layer would let a
  coercer delete the real restore's shards, and the control itself is a surface to spot.

The one way out before the fix was blind: deleting the hostile trustee's contact drops their share from
`visibleContactIdentifiers`, but nothing tells the owner which contact to delete.

### Fix, as built (2026-09-23)

- **Subset search** (`VaultManager.Backup.verifiedKey`). It tries every shard first. If that fails, it
  retries with shards left out, fewest first, and stops at the first candidate that opens the file.
  Extra honest shards never change the result, so the first subset that works is the full set minus the
  bad ones, and the GCM tag is an exact check for it. The threshold is unknown on the restoring device,
  so the search runs down to pairs; a subset below k just yields a wrong key. Every wrong candidate is
  zeroed. A hostile trustee can now do no more than withhold their share.
- **Cap: 1,024 tries per distribution** (`maxReconstructionAttempts`). One bad share needs at most n + 1
  tries, and n ≤ 255, so the cap never binds for one hostile trustee. It binds only for several at once:
  two bad shares among up to 44, and three among up to 18, always fit.
- **`ShamirSecretSharing.reconstruct` computes the Lagrange weights once per call** instead of once per
  byte. They depend only on the x-coordinates, so the output is identical. Before this, a 20-share
  reconstruction took about 0.64 ms in an optimized build, and 0.44 s with 255 shares, which put the
  search at up to about 2 minutes in that extreme.
- **The successful candidate's decrypted backup is zeroed.** The old check threw it away without zeroing
  it, a gap left over from Bug 96 item 3.

Not chosen: accepting it as a limitation, trustees cross-vouching for each other's shares, a Merkle root
in the `.occbak`, and Berlekamp–Welch decoding. `decisions.md`, "Recover past poisoned shares by subset
search against the GCM tag", records why.

**Measured** on the iPhone 17 Pro simulator on an Apple Silicon Mac, optimized build, before the Lagrange
change (a device will be somewhat slower):

| Backup | 10 honest | 10 honest + 1 bad | 16 honest + 4 bad (cap reached, fails) |
|---|---|---|---|
| 10 entries, 4 KB file | 61 ms | 57 ms | 592 ms |
| 200 entries of 5 KB, 1.4 MB file | 842 ms | 823 ms | 870 ms |

One bad share adds almost nothing, and for a large backup most of a successful restore's time is
inserting entries. The Lagrange change then cut `PoisonedShardTests.capBoundsTheSearch` from 114 s to
3 s in the unoptimized test build. The optimized build wasn't re-measured.

Timing: the search runs only on shards from contacts visible at the current depth, so the same inputs
take the same time at every depth. The field arithmetic's own data-dependent timing is Bug 131.

### Guard

`PoisonedShardTests` (`VaultRestoreTrustTests.swift`), all through `restoreBackup` on a fresh device:
- one poisoned share with a fresh x among enough honest ones restores the owner's key and entries;
- a poisoned share reusing an honest share's x restores (the full set fails on a duplicate coordinate,
  not the tag);
- two poisoned shares restore;
- too few honest shares plus a poisoned one restores nothing and writes nothing;
- the cap from both sides, whatever order shares arrive in: three poisoned among 18 restores (at most
  988 tries), four among 20 fails (at least 1,352).

`SSSVectorTests.matchesPerByteLagrange` (`ShamirTests.swift`) pins `reconstruct` against the per-byte
formula it replaced, on arbitrary points for 2 to 255 shares.

A wrong-length share needs no test here: `SignedAttributeCodec.encode` refuses any value that isn't 33
bytes, so one can never be banked.

---

## Bug 96 — Restore-path robustness: two traps on decoded content, unbounded growth, and vault plaintext left unzeroed

**Stale, 2026-09-11:** Items 3-4 cite `setupBEK`/`rotateBEK`/`prepareBEKShards`/`reconstructBEK`/
`bekSetupState`/`bekShardMetadata` — all renamed by this session's BEK storage refactor. Item 4's
file-naming note (`pending-restore.occbak`/`pending-restore-shards.dat`) also describes a problem
already fixed elsewhere (Bug 93 harm 3, renamed to `backup-import-cache*`) without ever
cross-referencing back here.

**Status:** **Partially fixed 2026-08-24.** Filed 2026-08-22 alongside Bugs 94 and 95. Grouped
because all four are robustness rather than access-control defects, and none is worth its own
entry. **Item 1 (the two traps) is fixed** — `importBackup` now range-checks `entryType` and
`createdAt` before either reaches the conversion that used to crash the process. **Items 2
(unbounded shard file) and 3 (unzeroed export plaintext) remain open.** Item 3 fixed 2026-09-23, see
below.

**Item 2 has a structural fix rather than a cap, 2026-08-27.** The shard *file* no longer exists —
Bug 100 remedy 2 made restore shards `ReconstructShard` rows — so item 2 is now unbounded *rows*
rather than an unbounded file. The count is still uncapped and the dedup scan still decrypts every
buffered row on each arrival, so nothing here is fixed. But the cap this item asks for falls out of
Bug 102's fixed-slot design for free: fixed width means a bounded shard count by construction rather
than a numeric limit bolted on. Worth waiting for that rather than adding a cap now, *unless* Bug 102
slips — the guard test `restoreShardBufferIsBounded` is already written as a `withKnownIssue` and will
flip to a real assertion on its own when a bound appears.

**One caution carried from that design work.** A cap plus a *shared* buffer would be a cross-layer
denial channel — junk shards evicting real ones. Bug 102's per-depth arrangement is what makes a cap
safe, which is another reason not to add one to the shared buffer first.

**Doubly stale, corrected 2026-09-12 — the thing this item is waiting for no longer exists in the
shape it was waiting for.** Bug 102 was reclassified Closed, subsumed into Bug 99, 2026-09-11 — its
own fixed-slot design is preserved there for the record but was never built. Its successor,
`RECOVERY_BUFFER_LAYERING.md` §6 item 9 (proposed the same day, 2026-09-11), does **not** provide the
free hard cap this item is counting on: item 9 is rows with an eager-*filler* baseline, explicitly
"uncapped beyond" that baseline, mirroring `BackupEncryptionKey`'s own deliberately-uncapped design
— it closes the *row-count-as-forensic-signal* problem, a different axis from the
*resource-exhaustion-via-unbounded-growth* problem this item is actually about. Item 9's own text
lists filler-baseline sizing as still open and doesn't mention a cap anywhere. **So: waiting is no
longer the right call — there is nothing left upstream that closes this "for free."** Whoever builds
item 9 needs to separately decide a real cap for the shard buffer specifically (item 9's "One
caution" above about caps-plus-shared-buffers being a denial channel still applies and still needs
its own per-depth-safety argument, independent of whichever container shape wins). The guard test's
actual name is `restoreShardFileIsBounded` (`VaultRestoreTrustTests.swift:587`) — a naming leftover
from the file era, not `restoreShardBufferIsBounded` as cited above — confirmed still present, still
an active `withKnownIssue`, not yet flipped.

**Target:** unset.

### Severity: Medium, rising to High in combination with Bug 94

Two of these need the BEK to reach. Bug 94 hands an attacker the BEK, so they should be read as
amplifiers of it rather than as independently gated.

### 1 — Two traps reachable from decoded backup content — **fixed 2026-08-24**

`importBackup` (`Vault+Manager+Backup.swift:268`, this trapping form no longer present — the fixed
guards live at `:295` and `:308`):

```swift
let entryType = VaultEntryType(rawValue: UInt8(backupEntry.entryType)) ?? .note
```

`backupEntry.entryType` is `Int` from JSON. `VaultEntryType` is `UInt8`-backed with three cases. The
`?? .note` guards the `rawValue:` lookup — but `UInt8(300)` or `UInt8(-1)` **traps before it is
reached**. The nil-coalescing is on the wrong conversion.

`VaultEntry.aad(for:)` (`Vault+Model.swift:227`):

```swift
var ts = UInt64(self.createdAt.timeIntervalSince1970).bigEndian
```

`UInt64` of a negative `Double` traps. Any `createdAt` before 1970 in a backup crashes the app.

**Why this is not merely a robustness nit.** `attemptBEKRestore` runs on every unlock, and the
pending-restore file is deleted *only after* `importBackup` returns. A trap is not an `Error`, so the
`catch … continue` does not catch it. Under Bug 94 an attacker who can craft a file can therefore
choose a **permanent crash on every vault unlock** in place of the entry injection.

Fix: validate the `Int` range before converting, and reject a non-representable `createdAt` at
import rather than at AAD construction.

### 2 — Unbounded shard file and unbounded group count — **narrowed 2026-08-24, and downgraded to nice-to-have**

`storeRestoreShard` deduplicates by `SignedAttribute.id` only, and the attacker picks fresh UUIDs:

```swift
guard !shards.contains(where: { $0.id == attribute.id }) else { return }
```

The file grows without limit, is fully read, GCM-opened and JSON-decoded on every unlock, and each
distinct attacker-chosen `entryID` creates another group to run Shamir plus GCM against.
`storePendingRestore` likewise accepts a file of any size and writes it to Application Support.

**Resolved for the existing-BEK population, as a side effect of Bug 94's remedy 1.** Every group on
that population now fails immediately via `bekAlreadyPresent`, and `attemptBEKRestore` checks for
that up front rather than letting the shard file grow while every group fails one at a time — see
Bug 94's entry. Because `acceptReturnedShard` calls `attemptBEKRestore()` synchronously right after
`storeRestoreShard()`, real-world growth on that population is now bounded to roughly one shard per
arming cycle, not a numeric cap.

**Still open for the no-BEK population**, which has no equivalent early-out — there is no BEK to
detect, and that device may legitimately need shards trickling in from real trustees over time, so
there is no way to distinguish "not enough shards yet" from "never going to get enough" the way the
existing-BEK case can. A count cap remains the only cheap defense there until Bug 94 remedy 2
(trustee attestation) lands.

**Downgraded from "fix" to "nice to have," on reconsideration of actual cost.** The original framing
overstated urgency: reaching a size that meaningfully hurts (multi-second stalls, real memory
pressure) needs several orders of magnitude beyond what one reproduction test showed (300 forged
shards ≈ 1 second to store) — and getting there requires the attacker to deliver that many *distinct
inbound bundles* through the ordinary messaging pipeline, which has its own cost on both ends and is
a pre-existing, general flood surface this fix would not touch regardless of what the bundles
contain. A cap here still costs nothing to add and is still worth doing, but it is not the
same order of urgency as the trap fixes were, and should not be prioritized as if it were.

`storePendingRestore` accepting a file of unbounded size is unaffected by any of the above and
remains open — a separate concern from the shard-count question.

**Decided permanently unbounded, 2026-09-13 — `RECOVERY_BUFFER_LAYERING.md` §6 item 9.3, `bugs.md` Bug
122.** Generalizing this population past BEK (`PendingShamirSecretRestore`, keyed by the secret's own
identity rather than by depth) made a cap unsafe to add at all: capping live rows without restoring
per-depth isolation turned into a counting oracle letting a coercer learn whether a genuine restore is
active anywhere on the device, without any key (Bug 122). A depth-scoped cap would have closed that, but
was rejected — not for a security reason, but because it needs its own UX for what happens at the boundary,
judged not worth building for a concern this item's own 2026-08-24 reconsideration already downgraded to
"nice to have." So: no cap, ever, on this population — cost is now materially higher than when this item
was last sized (~112 KB per unbounded row under the new model, not a few hundred bytes), but still an
accepted trade against the alternative, not an oversight.

### 3 — The entire vault plaintext is left in freed heap on export

The file header states the discipline (`Vault+Manager+Backup.swift:8-9`):

> *"BEK bytes only exist in memory during an active operation and are zeroed via defer where they
> appear as raw `[UInt8]` or `Data` buffers."*

It is honoured precisely for 32-byte keys in `setupBEK`, `rotateBEK`, `prepareBEKShards` and
`reconstructBEK`. Meanwhile `exportBackup` builds `backupEntries` — every label and every content
blob in the vault, decrypted — and then `JSONEncoder().encode(backup)`. **Neither is zeroed.**

Guarding the key while leaving what the key protects is the wrong way round. `JSONEncoder`'s internal
buffers cannot be reached, which limits how complete any fix can be, but the two named buffers can
be — and the discipline as written promises more than it delivers.

**Fixed, 2026-09-23, on both export and restore.** The restore side had the same defect in mirror
image (`decodedBackup`'s decrypted JSON and decoded entries), so both are covered:
- `VaultBackupEntry.label`/`.content` and `VaultBackup.entries` are now `var`, so they can be zeroed in
  place. `VaultManager.zeroPlaintext(_:)` zeroes every label and content.
- `exportBackup` zeroes its entries and its JSON by `defer`. The `VaultBackup` is built inside the
  encode call, so no second reference outlives it.
- `decodedBackup` zeroes the decrypted JSON on return, and the decoded entries if a check fails.
  `restoreBackup` zeroes them when the attempt ends, successful or not. The per-entry checks moved out
  of a loop over the entries, because the loop's own reference to the array would have made the
  zeroing hit a copy.

In-place zeroing only works while each buffer has one owner; a second reference makes Swift copy on
write and zero the copy. `BackupPlaintextZeroingTests` pins that property (it checks the buffers'
addresses are unchanged), and it fails if a second reference is introduced. **Not covered, and can't
be:** `JSONEncoder`/`JSONDecoder` internals, labels while they pass through Swift `String`s
(`decryptLabelPayload` returns one), and CryptoKit's own buffers.

**Follow-up, 2026-09-26 (branch code review):** per-entry key reconstruction had the same gap.
`reconstructEntry` (`Vault+Manager+Reconstruction.swift`) opened the entry's content to check the GCM tag
and dropped the decrypted secret unzeroed. It now zeroes it at once, as `Backup.keyOpening` does. Not
covered by a test, like the other zeroing points: a leftover copy in freed memory isn't observable from one.

### 4 — Minor, recorded so they are not rediscovered

- **`VaultBackup.version` is decorative.** It is decoded and never read; `importBackup` accepts any
  value. Same root cause as Bug 92's note — it lives inside the ciphertext, so it cannot gate
  anything about decryption.
- **`bekSetupState` reports `.notSetup` after a successful restore.** `reconstructBEK` sets
  `shardMetadata: nil`, so `bekShardMetadata()` returns nil and the state collapses to `.notSetup`
  while a BEK plainly exists. Intentional per the comment (*"redistribution prompt handles
  rebuild"*), but the state asserts something false and `exportBackup` then throws `belowThreshold`
  without explaining why.
- **Self-describing artifacts.** `pending-restore.occbak`, `pending-restore-shards.dat`,
  `backup-export-meta.dat`, and the `vault.postRestoreActionNeeded` `UserDefaults` key. Contents are
  sealed; names and existence are not. `backup-export-meta.dat`'s mere presence proves an export was
  performed on this device.


---

## Bug 97 — Depth-field backfills stamp deleted rows with current-key material, the exact pattern rejected elsewhere in this file

**Status:** **Fixed 2026-08-24.** Filed 2026-08-22, confirming a note carried since Bug 89 rather than
acting on it unverified. Re-checked against current code before filing. All three predicates now
carry `&& $0.deletionToken == nil`, matching the remedy exactly. `scrubbedStamp`'s doc comment
(`PQmigration.swift:467`) — the one this entry quoted as evidence — is updated to record the gap as
historical rather than live. `DeletedRowBackfillExclusionTests` covers the exclusion, the still-works
case for live rows, and composition with Bug 89's scrub.

**Target:** unset. Sibling to Bug 89 (closed) — that fixed the *classifier* left behind by legacy
lengths; this is a *live* backfill still writing fresh stamps onto deleted rows on every launch.

### Severity: Medium (forensic trace)

No user action needed — the three backfills below run unconditionally on every launch, per their
own doc comments (`PQmigration.swift:95-116`).

### What happens

`migrateSafeContactVisibilityBackfill`, `migrateGlobalTrusteeDepthBackfill`, and the sibling for
`originDepth` (`PQmigration.swift:105`, `:126`, `:147`) each match purely on the field being `nil`:

```swift
let descriptor = FetchDescriptor<Contact.Profile>(
    predicate: #Predicate { $0.visibleThroughDepth == nil }
)
…
for contact in contacts {
    contact.visibleThroughDepth = try DepthCodec.encode(Int.max).encrypt()
}
```

No `deletionToken == nil` filter. A soft-deleted row whose depth field happens to be `nil` — plausible
for anything deleted before the "never nil" creation-time invariant existed — gets sealed with a
**fresh value under the current key** by ordinary backfill logic, indistinguishable from a live
contact's stamp being written.

`migrateScrubDeletedDepthStamps`'s own doc comment already names this precisely
(`PQmigration.swift:458`): *"a deleted row can legitimately have one stamp readable and the others
stranded, because the backfills do not filter `deletionToken`"* — the fix for Bug 89 was written
knowing this, and scoped around it rather than closing it, because the scrub only touches rows *after*
this has already happened, once. It does not stop it happening again on the next contact deleted with
a `nil` stamp.

### Why this is the pattern already rejected here

Directly contradicts a design decision made earlier in this same file, for the same class of field:
*"I don't like the idea of encrypting any field with current key of profiles that have been
stranded. It smells like a tell"* — the reasoning behind Bug 88's keyless-filler remedy. A deleted
row's neighbours (its other fields) don't decrypt under the current key; a fresh current-key stamp on
one field of that row is exactly the asymmetry that reasoning was written to avoid. The backfills
predate that design conversation and were never revisited against it.

### Remedy

Add `deletionToken == nil` to each of the three predicates. A deleted row with a `nil` depth field
should be left for `migrateScrubDeletedDepthStamps` to handle — keyless random bytes at the uniform
length, which is already the correct answer for exactly this state, per Bug 89's fix.

### Guard

None of `DepthCodecTests`, `DeletedDepthStampScrubTests`, or `MigrateToV2ResilienceTests` construct a
deleted row with a nil depth field ahead of the backfill pass — the gap has no reproduction yet.

---

## Bug 98 — The field-coverage tripwire is two different strengths, and the class of bug it exists to catch has no coverage at all

**Status:** **Closed — moot, 2026-09-11.** Filed 2026-08-22, **Open** until now, confirming a note
carried since the Bug 76/77 tripwire work rather than acting on it unverified.

**Target:** unset.

### Reclassified 2026-09-11 — the machinery this entry's tripwire protected no longer exists

**Everything below describes `EncryptedFieldCoverageTests.swift`'s `groupPropertiesReviewed`,
`messageDraftPropertiesReviewed`, and the `probes`/`unprobedFields` table form built for
`Contact.Profile`/`AppLayerConfig` — a tripwire against a stored property silently escaping the
Secure Mode key-rotation machinery.** That whole machinery — `reencryptAllFields`, `Group.reencrypt`,
`AppLayerConfig.reencrypt`, `Message.Draft.reKeyOrPurgeAll`, `RotationRegistry`, and the staged-key
protocol — was deleted outright by "Removal Stage 3: delete the rotation machinery" (`2b00f09`,
2026-09-10), the day before this bug was last touched and never reconciled since. Confirmed directly:
`EncryptedFieldCoverageTests.swift`'s own header now states exactly this — *"That machinery... was
removed along with key rotation itself (Removal Stage 3, `plan.md`)"* — and the file itself was
trimmed to one surviving, unrelated test (`readabilitySeparatesStrandedFromAbsent`, about
`maxBundleVersion`'s stranded-vs-never-seen read, not rotation coverage). Grepped the whole repo for
`RotationRegistry`/`groupPropertiesReviewed`/`storedPropertyNames`/`tripwireGuidance`: zero matches
anywhere, source or tests.

There is no longer a rotation-classification tripwire to be "two different strengths" of, and nothing
for `Group`, `Message.Draft`, or `VaultEntry` to be ported into — the remedy below is not a
description of unfinished work, it's a description of a system that stopped existing. Closed rather
than left open describing a mechanism the codebase no longer has, matching the "Closed — moot"
disposition already used for Bugs 106-109, the other casualties of the same Removal sequence.

**Same root cause as Bug 102's own reclassification** (2026-09-11, same day) — a bug filed against a
subsystem that a later Removal stage deleted, never revisited after. `VAULT_KEY_LAYERING.md` §7/§8
separately cited "`RotationRegistryTests` passes as-is"/"forces an explicit rotation classification"
as Stage 1 verification evidence (2026-09-08, one day before the deletion) — corrected alongside this.

### Original entry, preserved below for the reasoning trail

### Severity: Low (process gap — nothing is exploitable, a future addition could ship unreviewed)

### What happens

`EncryptedFieldCoverageTests.swift` documents its own history at the top of the file: *"previously
the tripwire was silenced by adding a name to a list… now an entry must carry a key path and a probe
value, so silencing the tripwire is the same [cost as fixing it]."* That upgrade — from a bare name
list to the `probes`/`unprobedFields` table — was applied to `Contact.Profile` and `AppLayerConfig`
— `7e811b5` for `Contact.Profile` (2026-08-17), `4dc6e9d` for `AppLayerConfig` (2026-08-18). It was
not applied everywhere the file has a tripwire.

**`Group`'s tripwire is still the old form** (`:409-416`):

```swift
@Test("Group has no unreviewed stored properties", .enabled(if: secureEnclaveAvailable()))
func groupPropertiesReviewed() throws {
    let expected: Set<String> = [
        "encryptedID", "encryptedName", "encryptedCreatedAt",
        "realMemberSlots", "duressMemberSlots", "deeperMemberSlots",
    ]
    #expect(storedPropertyNames(of: try Group(name: "probe")) == expected, "\(tripwireGuidance)")
}
```

A new stored property is caught, but the fix the test invites is adding its name to `expected` — no
proof that the field was actually classified for rotation, unlike the table-driven form.

**`Message.Draft`'s tripwire is the same weaker form** (`:424-436`, doc comment at `:419-421`), and its own doc comment already
names the limit: *"Its fields were never stranded by a field omission — the whole model was skipped
by one of the two rotation paths — so this tripwire would not have caught that bug."* Correct, and
also true of `Group`'s: a name-list tripwire catches an added field, not a field routed to the wrong
handling.

**`VaultEntry` has no coverage test in this file at all.** No `vaultEntryPropertiesReviewed`, no
name list, nothing — confirmed by absence, not by a weaker form. This is the model where the
consequence is most concrete: `visibleThroughDepth` on `Contact.Profile` is exactly the field family
Bugs 85, 87 and 89 were about, and `VaultEntry.visibleThroughDepth` (`Vault+Model.swift:194`) is the
same hazard on the sibling model. Bug 87's fix added rotation-composition tests for the existing
field; nothing would flag a *new* `VaultEntry` stored property that needs the same scrutiny.

`Contact.Draft`'s absence is already recorded — Bug 91's remedy proposes the table-driven form for
it specifically. This entry is about the three gaps Bug 91 does not cover: `Group`, `Message.Draft`,
and `VaultEntry`.

### Remedy

1. Port `Group` and `Message.Draft` to the `probes`/`unprobedFields` table form, matching
   `Contact.Profile` and `AppLayerConfig`.
2. Add the same coverage for `VaultEntry`.

Not a design question — the pattern exists twice already; this is applying it to what it was left
off of.

### Checked and not filed alongside this

Three functions named `randomBytes` exist (`AppLayerConfig+Model.swift:431`,
`IdentityChallenge+Manager.swift:520`, `Passphrase+Manager.swift:93`). Read side by side, they are
not the same function under three names: one is deliberately non-throwing
(`SystemRandomNumberGenerator`, with a comment explaining why the call site cannot cascade a throw),
one throws on `SecRandomCopyBytes` failure, and one falls back to `SystemRandomNumberGenerator`
silently rather than throwing. Three different failure-handling contracts for three different call
sites — consolidating them would be a behavioural decision, not a naming cleanup, so this is not
filed as a bug.

---

## Bug 99 — A coercer who supplies his own trustees can test whether the phone is in duress, because a restore completes in one layer and not the other

**See also [`RECOVERY_BUFFER_LAYERING.md`](RECOVERY_BUFFER_LAYERING.md), cross-referenced
2026-09-11 — this bug isn't blocked on an unsolved design question, only on unbuilt implementation
of one that already exists.** That document's §2 (sender-visibility gate on inbound shard
attribution), §4 (Stage 4: per-depth arming/restore state), and §6 item 5 (that state's actual
sizing — *"Arming/state: small — timestamp, state enum. Generously, ~64 bytes"*) is the full design
this entry's own Requirements section below gestures at without landing on. Its own §7 bugs table
already tracks this entry: *"open — subsumed here except the pending-file tag."* Confirmed directly
against code, not just the document's own "design, not built" label: `identifyOwner`
(`Contact+Manager.swift:1550`) still resolves senders via unfiltered `fetchAllContacts()`, and
`storePendingRestore` (`Vault+Manager+Backup.swift:434`) still has no depth parameter at all — every
piece this design depends on remains genuinely unbuilt.

**Addendum, 2026-09-21 — a real, narrow interim widening, accepted deliberately, not silently.**
Replacing `ReconstructShard` with `PendingShamirSecretRestore` (the plan at
`Vault+Manager+ReturnBuffer.swift`, RECOVERY_BUFFER_LAYERING.md §9.3) moves BEK-restore shard
collection from depth-partitioned to depth-blind *before* this bug's own fix (binding completion to
the depth a restore was attempted at) lands — the two were originally meant to ship together, but the
storage swap alone is worth doing now, and building the depth-blind shape twice (once temporarily
scoped, once final) to avoid the gap costs more than the gap is worth. Today's `ReconstructShard`-based
collection is depth-partitioned: a shard delivered while depth 2 is showing is invisible to a depth-0
restore attempt. Depth-blind collection removes that. Traced with `attemptBackupRestore`'s
`currentDepth == 0` completion guard still unconditionally in place (unchanged until this bug's own
fix lands): the widening is narrow, not the core attack this entry describes — a shard collected at
duress depth 2 becoming usable at depth 0 requires the same attacker to *also* later get access to
depth 0, **and** depth 0 to have no real BEK configured yet (`alreadyHasBEK`, Bug 94 remedy 1, already
blocks it otherwise). Closes the moment this bug's own remedy ships, not before. Tracked here so it
isn't lost between the two changes landing separately.

**Status:** **Fixed, 2026-09-23, with an accepted residual.** `RECOVERY_BUFFER_LAYERING.md` §9.4 is built: a restore
completes at the depth its file is opened at, counting only shards from contacts visible there. The
residual (trustees left visible in a duress layer still count there) is described in the 2026-09-23
addendum below. Full suite: 881 tests, 875 passed, 0 failed, 6 skipped (the `KeychainMigrationSETests` baseline).

Filed 2026-08-27, during the review that produced Bugs 89a and 94a. Found by
asking what an attacker who owns the trustee set can do, rather than what one who does not can.

**Target:** `release/v1.10.3`.

### Severity: High (deniability break)

Not a disclosure of vault contents. It answers the one question the whole layering system exists to
leave unanswerable — *am I being shown the real phone?* — on demand, repeatably, with equipment the
attacker already has.

### The attack

The victim is coerced, gives the duress PIN, and no restore is pending. The coercer has two phones.

1. Pair both with the victim's phone over UWB. He is already holding it, so this is free.
2. Author a `.occbak` on his own device, generate its BEK, and Shamir-split it at **k = 2** across
   his two phones. He chooses `k`, so two is the entire cost.
3. Open the file on the victim's phone and accept the confirmation. It arms, and the banner appears
   — identical in both layers since Bug 93's follow-up, so nothing is learned yet.
4. Both phones hand back their shards immediately. `handleHandback` takes them through Branch B: the
   attestation verifies against `senderPublicKey`, and he controls the shard and the attestation
   alike. `storeRestoreShard` banks them, because shard collection is depth-independent by design.
5. **Wait.**

**"Depth-independent by design" is now imprecise, corrected 2026-09-12 — the attack itself is
unaffected.** `RECOVERY_BUFFER_LAYERING.md` §2.1's Stage 3 gate (built after this bug was filed)
drops an inbound shard op when its sender isn't visible at the current depth. Checked directly
against this attack: step 1 pairs the attacker's own two phones with the victim's device *at the
coerced depth itself*, so those contacts are visible at exactly the depth step 4's handback later
arrives at — Stage 3's gate is satisfied by construction, not bypassed by an oversight. The attack
proceeds exactly as described; only the phrase "depth-independent by design" overstates it now,
since collection is conditionally depth-independent (on sender visibility), not unconditionally.

At depth 0 `attemptBEKRestore` fires on the next unlock, reconstructs his BEK, imports his entries,
and clears the banner. Above depth 0 nothing happens, ever.

**The signal he reads does not depend on comparing two devices — he has certainty, not inference.**
He authored the whole distribution himself: he chose `k`, split his own genuine BEK across exactly
`k` of his own phones, and confirmed both handbacks were accepted. Whether reconstruction *can*
succeed is therefore not something he is estimating — he supplied precisely what his own scheme
requires, and everything downstream of that is deterministic (Shamir combine, then a GCM tag check
against his own file). So when nothing happens, there is exactly one explanation available to him,
not a most-likely one among several: the depth he is looking at is not depth 0. Running the same
sequence once on his own, undeceived phone first (the "baseline" this entry originally leaned on)
only confirms the *mechanism* works end to end before he relies on it — pairing, handback, the
unlock-triggered retry — it is not what makes the result on the victim's phone legible. Once he
trusts the mechanism, silence in the face of a self-authored, self-sufficient share set is already a
direct readout, not a comparison he has to draw.

### Why the standing reasoning does not cover this

Two arguments in this file assume the attacker cannot make shards arrive.

**"A duress session is short and shard handback needs UWB proximity with a trustee."** True of the
victim's trustees. Irrelevant here — **he is the trustee**, standing next to the phone, delivering on
demand. The premise fails exactly when the attacker supplies the trustee set, which costs him one
extra handset.

**"Deferral is what makes showing the banner in duress safe."** It is what stops a *completion* in
duress, and that is still worth having. But deferral is itself the observable: completing in one
layer and not the other is the signal. The control that protects the vault is the same control that
answers his question.

Bug 93's follow-up did not create this — before it, duress showed no banner at all, which was a
cheaper version of the same tell requiring no shard delivery. It raised the price from "arm and
glance" to "arm, pair two phones, deliver a full shard set, wait." That is a real increase and not a
close.

### Remedy: complete at the depth the file was armed at

Not "complete in either layer" — that has a hole. A *genuine* backup armed at depth 0 contains
depth-0 entries; if it completed at duress depth 2, `importBackup` would stamp them 2 and the real
vault would materialise in the layer the coercer is reading. Worse than the oracle, because it hands
over the data instead of revealing the lie.

Binding completion to the arming depth removes the conditional behaviour instead:

- The attacker arms in duress, so it completes in duress. His entries appear, exactly as his baseline
  predicts.
- A backup armed at depth 0 still only completes at depth 0, so a duress session can never finish it.

Both layers then read the same from an observer's seat — *arm here, deliver shards, it completes
here* — because the condition is "same depth as arming", which is symmetric rather than
depth-privileged.

**The edge case is symmetric too.** If a restore is already pending when he arms, his file is refused
(`alreadyProcessed`) and his shards cannot reconstruct a BEK he did not split. His test returns "no
completion" — which is equally what depth 0 returns in that state, so it distinguishes nothing.

### This is better than deferral for containment, not merely equal

Vault entries are **exact-match** partitioned, not nested like contacts — `isEntryVisible` and
`entriesVisible(atDepth:)` both compare `value == depth`. So an entry imported at duress depth 2 is
visible **only** at depth 2.

That inverts the intuition. Deferral does not prevent his injection; it delays it and then delivers
it into the *real* layer at the next depth-0 unlock. Completing where the file was armed quarantines
it in the duress layer, where it is his own data sitting in his own cover story.

Recorded because the analysis leading here got this backwards first, by applying the contact rule
(`value >= depth`) to vault entries. The exact-match property is what makes the remedy work, and it
is the thing easiest to misremember, since the two models sit side by side under one name.

### What it does not change

`BackupEncryptionKey` is not depth-scoped — one row per device. His BEK becomes the device's BEK
whichever layer completes, so a later export at depth 0 is readable by him. Unchanged by this
remedy, and already confined by Bug 94 remedy 1 to devices that have no BEK yet, which is also the
only case where his restore can proceed at all.

**Stale as of 2026-09-08, corrected 2026-09-11 — never updated when it happened.** This paragraph
describes a device-wide, unlayered BEK. That stopped being true at Stage 2 (2026-09-08, `VAULT_KEY_LAYERING.md`
§7), which routed the BEK array itself by depth, and is even less true now: BEK storage moved off
the array onto per-depth `BackupEncryptionKey` rows (§8 item 14, 2026-09-11). Installing a BEK at
duress depth N now only ever touches depth N's own row — depth 0's key, trustees, and `shardMetadata`
are structurally untouched, confirmed directly by `BackupKeyOrphaningTests.shallowerBackupKeySurvivesCascade`.
**What is still true, unchanged:** `attemptBackupRestore` (renamed from `attemptBEKRestore`) still
hard-guards `currentDepth == 0` before completing (`Vault+Manager+Backup.swift:482`) — restore
completion itself remains pinned to depth 0, not routed per-depth. So this entry's actual oracle (arm
in duress, wait, nothing ever completes there) is unaffected by either storage change; only the
"his key becomes *the device's* key" framing above is what's gone stale — see Bug 102's own
correction note for the fuller accounting, since that bug's entire scope turned on the same premise.

### Requirements

**The arming depth has to be persisted, and sealed.** It must go through `DepthCodec` under the
recovery buffer key like every other depth stamp. A plaintext integer naming a layer is precisely
what Bug 93 harm 3 took out of those filenames, and storing one raw would put it straight back.
Fixed-width matters for the same reason it does everywhere else: a JSON `Int` is one byte at depth 0
and three at 253, and AES-GCM preserves that difference.

**Where it lives falls out of Bug 100.** The first two designs considered here — a sealed sidecar
file, then a header folded into the shard file — were both working around the shard file's existence.
It should not exist: `ReconstructShard` is already a SwiftData model doing this exact job for
per-entry recovery, sealed under the same recovery buffer key with a per-row AAD, and
`acceptReturnedShard` writes rows for one path and a file for the other with no stated reason for the
split. Once BEK restore shards are a model too (Bug 100 remedy 2), the arming depth is simply a field
on that model.

That removes the cleanup-parity hazard this entry would otherwise carry. A sidecar can go stale
independently of the file it describes, and a stale one silently mis-gates the next restore; one row
has one lifecycle and cannot drift from itself. **Build Bug 100 remedy 2 first** — this remedy is
smaller and safer on the other side of it.

**Corrected 2026-09-11 — Bug 100 remedy 2 already shipped and already corrected this paragraph's own
"simply a field on that model" framing; this entry never incorporated that correction, and neither
entry actually lands on an answer.** Bug 100's own remedy-2 write-up says plainly: *"the arming depth
is **not** simply a field on that model, as first assumed: at arming time no shard rows exist yet...
See Bug 99's build plan for where it actually has to live"* — pointing back here, where nothing was
ever added. The real answer already exists, in `RECOVERY_BUFFER_LAYERING.md` §6 item 5, cited at the
top of this entry: the arming depth needs no dedicated field at all. Once the whole container is
genuinely one-slot-per-depth (that document's Stage 4), arming state (*"timestamp, state enum"*) is
just one more small field living in *that depth's own slot* — the depth is implicit in which slot
holds it, sealed the same AAD-bound-to-slot-index way everything else in this design is, not tagged
onto a row that may not exist yet at arming time. Bug 100 remedy 2 (rows, not a file) is still a
correct and necessary prerequisite — just not, on its own, where the arming depth ends up living.

**The deferral guard changes shape rather than disappearing.**
`pendingRestoreNeverCompletesAboveDepthZero` becomes "does not complete at a depth other than the one
it was armed at". Something still has to stop a duress session finishing a depth-0-armed restore —
that is the assertion that protects the genuine backup.

**Superseded outright, 2026-09-23 — not "in part by Bug 102" (which no longer exists, see Bug 100's
own 2026-09-12 redirect), but by the reordering `RECOVERY_BUFFER_LAYERING.md` §9.3 already settled and
this entry's own 2026-09-21 addendum already names.** Everything in this "Requirements" section — the
sealed arming-depth field, where it lives, the sidecar-vs-row debate — was solving for a design with
two depth-sensitive moments: arm, then complete later, needing something to remember which depth arming
happened at so completion could look it up. §9.3 removed the first moment entirely. Shards are collected
depth-blind, unconditionally, before any `.occbak` file exists (`PendingShamirSecretRestore`, shipped
Stage 4, 2026-09-21) — there is no "arming" event left to timestamp. The only depth-sensitive moment
remaining is the file being opened — provided the file is used only at that moment and never held
(next paragraph). Full design: `RECOVERY_BUFFER_LAYERING.md` §9.4.

**The `.occbak` is never held: opening it is the only completion attempt.** Today `storePendingRestore`
writes the file to the sandbox and waits for a later `attemptBackupRestore` (the next unlock or shard
arrival) to try it. Once completion is allowed at any depth, a held file breaks two ways. It completes at
whatever depth the *next* attempt happens at, not the depth it was opened at, so a coercer's file opened
in duress lands in depth 0 at the owner's next real unlock (this entry's own "deferral delivers it into
the real layer"). And one depth's held file blocks every other depth's restore through `alreadyProcessed`.
Per-depth pending files would fix both only by re-creating arming state (which depth owns which file),
the thing §9.3 removed. A fallback of "attempt first, persist the file only if that fails", proposed
earlier the same day, has the same two problems and was dropped. The settled shape: attempt reconstruction
against the in-memory bytes at the depth the file is opened at; success imports there; failure stores
nothing, and the user opens the file again once more shares have arrived. The attempt iterates over banked
shard sets (one `PendingShamirSecretRestore` row per `distributionID`) against the one file in hand, and
the GCM tag picks the match. It never iterates over files.

The code change that follows is still small, but larger than deleting one guard:
- delete `attemptBackupRestore`'s `guard currentDepth == 0 else { return }`
  ([Vault+Manager+Backup.swift:496](Occulta/Features/Vault/Vault+Manager+Backup.swift:496));
- thread a real `currentDepth` through `Backup.reconstruct`, which hardcodes depth 0 twice (its
  `bekAlreadyPresent` check and its `persist` call), and through `storePendingRestore` and its caller,
  `OccultaApp.armPendingRestore()`;
- remove `pendingRestoreURL`, `pendingRestoreActive`, `pendingRestoreShardCount`,
  `refreshPendingRestoreState`, the "Recovery in progress" section, and the unlock and shard-arrival
  triggers of `attemptBackupRestore`, since there is no held file left for them to act on.

Bug 126 becomes moot with that state. Bug 100 remedy 3 and the `.occbak` half of remedy 1 become moot
outright: the file never touches the sandbox. No new field, no `DepthCodec`-sealed arming depth, no
sidecar-vs-row question.

**Requirement: import succeeds at any depth, the same way.** A depth-privileged success or failure is
itself a forensic trace. Once `Backup.reconstruct` takes the real depth, the core path satisfies this;
`importBackup` already stamps entries with its caller's depth. One existing piece violates it: on
success, `attemptBackupRestore` sets a device-wide `UserDefaults` flag,
`vault.postRestoreActionNeeded` ([Vault+Manager+Backup.swift:541](Occulta/Features/Vault/Vault+Manager+Backup.swift:541)),
which `Vault+Tab` reads through `@AppStorage` to open the post-restore sheet on *any* unlock at *any*
depth. That was harmless while completion was pinned to depth 0. Once an import can happen in duress,
the owner's next depth-0 unlock would show "set up your backup", announcing a restore that happened in
another layer. Under the settled shape the prompt belongs at file-open, at the importing depth, with no
persisted global flag.

**Open hole: "nothing to bind together" was too strong.** This entry's Remedy opens with the warning:
"Not 'complete in either layer' — that has a hole." A genuine depth-0 backup completing at a duress depth
imports the real vault into the layer the coercer is reading. The stateless file-open doesn't cause this,
but it doesn't close it either; depth-blind collection plus completion at any depth re-opens it:
1. During a genuine recovery, the real trustees' shards are banked depth-blind.
2. A coercer holding the phone at a duress depth opens the real `.occbak`, for example from the phone's
   own Files app, which isn't depth-scoped.
3. If that depth has no backup key of its own, reconstruction succeeds and the real depth-0 entries are
   imported into his layer.

It is bounded: it needs a genuine recovery in progress with its shards banked and not yet consumed, and
success consumes them (`orphanShards`), so it works once. Once is enough to disclose the real vault.
`VAULT_KEY_LAYERING.md` §8 item 9's "nothing left to protect by blocking it" assumed per-depth shard
buffers, which §9.3 later abandoned. The regression rule "deferral must not be silently dropped"
(`RECOVERY_BUFFER_LAYERING.md`, *Regressions*) is why this had to be decided before the guard comes
out, not after.

**Decided, 2026-09-23: filter by trustee visibility at completion.** A restore at depth d uses only banked
shards whose sender (`senderIdentifier`, already stored in each slot) is a contact visible at d at the
moment of the attempt. No new stored state. The coercer's own trustees, paired in his layer, get
`originDepth` = d and are visible there, so his file still completes and Bug 99 stays closed. They are
not visible at depth 0 (`depth >= origin` fails), so his shards can't complete anything in the real
layer either. Considered and not chosen:
- Accepting the window, because the real vault goes to exactly the coercer who meets the preconditions
  (one who took the old phone knows a recovery is coming).
- Binding each shard to the depth current when it arrived, which needed a `ShardsCodec` v2 and a
  migration.

**What this leaves open, stated so it isn't mistaken for a full close:** a contact with no
`visibleThroughDepth` is visible at every depth (`Contact+Model.swift`, `isVisible(atDepth:)`). Unless
the owner hid their trustees from the duress layer, the real trustees pass the filter there, and the
hole is open exactly as described above. The protection holds only for trustees the owner has hidden,
and nothing currently prompts the owner to hide them. The arrival-depth binding would have closed the
default case too; it stays available if this proves insufficient.

**Guard, once built:**
- A full share set banked first, then the file opened at a duress depth: entries land there (this
  entry's "quarantine, not deferral" property), and nothing is ever written to the sandbox.
- The same at depth 0.
- Too few shares: the attempt fails, no pending state exists afterward, and opening the same file again
  once enough shares have arrived completes.
- The post-restore prompt appears only at the importing depth.
- Shards from trustees hidden at the duress depth don't count there: the owner's real file, opened in
  duress against a full set of their shards, doesn't complete.
- The coercer's own trustees, paired at his depth, can't complete a restore at depth 0.
- A test pinning the residual, so it can't pass unnoticed: trustees left visible at the duress depth
  *do* count there.

### Superseded in part by Bug 102's wider framing

**Amended 2026-08-27.** The arming-depth binding is the right fix *within the current architecture*,
and remains worth building as an interim: it closes the oracle and contains the injection better than
deferral does. But it is a binding bolted onto a device-wide subsystem.

Bug 102, restated, layers the recovery subsystem itself. There the oracle closes because arming and
completing are genuinely one per-layer operation rather than a masked depth-0 privilege, and shards
self-route by `distributionID` with no depth binding at all. What survives of this entry in that world
is only the tag on the pending `.occbak`, which stays a file and so still needs to say which layer
armed it.

Build order if both are wanted: this one now, Bug 102 when a minor release can carry it.

### Supersedes

- "Defer and hide together" (Bug 93) — hiding is already gone; this replaces deferral's depth-0
  privilege with an arming-depth binding.
- The "unlikely to receive shards during a duress window" reasoning, wherever it appears. It holds
  only for an attacker who does not bring his own trustees.

### The limit this puts on the guarantee, stated plainly

Even with the remedy, recovery-related deniability holds against a coercer who cannot supply his own
trustees. It is worth writing down that this was ever in question, because it bounds what the
surrounding fixes buy: they close the cheap tells, and the expensive one is closed by the arming-depth
binding rather than by anything about the UI.

---

## Bug 100 — The pending-restore files are a keyless progress counter and a vault-size estimate, and they leave the device in backups

**Status, 2026-09-23: remedy 3 moot; remedy 1's pending-`.occbak` half moot.** `RECOVERY_BUFFER_LAYERING.md`
§9.4 is built: the `.occbak` is never written to the sandbox, so there is no file to pad or exclude.
Remedy 1 still applies to `backup-export-meta.dat`. Earlier status, unchanged below.

**Status:** **Remedies 1 and 2 fixed 2026-08-27; remedy 3 open.** Remedy 2 shipped as part of this
branch — BEK restore shards are `ReconstructShard` rows and the shard file is gone, so the progress
counter it leaked is gone with it. Remedy 1 shipped too — both remaining Application Support files
are now marked `isExcludedFromBackup` at each write, guarded by a test that rewrites the file rather
than checking it once. **It does not stand alone: Bug 101 found the same content, unsealed, in
`Documents/Inbox`, and that copy is still there.** Remedy 3 (`.occbak` padding) remains and is moot
if Bug 102 slots the backup contents. See also Bug 102: rows remove the length channel but still leave a row count, so
fixed slots supersede them. Filed 2026-08-27, while enumerating what a restore leaves on disk. Not found by
reading the restore code — found by asking what an examiner sees, after the *same* number had just
been removed from the UI for being too revealing.

**Redirect, 2026-09-12: Bug 102 no longer exists, and its successor isn't "fixed slots."**
`RECOVERY_BUFFER_LAYERING.md` §6 item 9 (2026-09-11) proposes replacing `backup-import-cache.occbak`
with a per-depth *row* holding a padded `encryptedSnapshot` field, not a fixed-slot array. The
conclusion above still holds — the standalone file disappears either way, so remedy 3 (padding a
file that no longer exists) stays moot — just via item 9, not "Bug 102"/fixed slots.

**Superseding update, 2026-09-21: item 9 itself moved past "a row holding the file's contents" —
remedy 3 is still open today, not yet moot.** §9.3 (2026-09-13) dropped `encryptedSnapshot` entirely
rather than moving it into a row: the settled design collects shards first, depth-blind, and only
opens the `.occbak` file at the very end, synchronously, once a matching set already exists —
`RECOVERY_BUFFER_LAYERING.md`'s own Stage 3 ("start shard return"). Stages 4-5 of that build (the
storage-mechanism swap, `PendingShamirSecretRestore` replacing `ReconstructShard`) shipped
2026-09-21; Stage 3 — the reordering that actually removes the file's held-window and would make
remedy 3 genuinely moot — has not. Until it does, `storePendingRestore` still writes the file
immediately on open and holds it for the full waiting window exactly as this entry originally
described. Do not mark remedy 3 moot before Stage 3 ships.

**Update, 2026-09-23: once built, the reordering removes the file entirely, not just shortens how long
it's held.** Bug 99's 2026-09-23 addendum settles that the `.occbak` is never written to the sandbox:
opening it is a one-shot reconstruction attempt against the in-memory bytes, and a failed attempt stores
nothing. So when that ships, remedy 3 (pad the file) and the pending-`.occbak` half of remedy 1 (exclude
it from backup) both become moot outright. `backup-export-meta.dat`'s exclusion is unaffected, and so
is Bug 101, since the `Documents/Inbox` copy is made by the OS, not by this code. Still not built: the
same "do not mark moot early" rule applies.

**Target:** unset. Independent of Bug 99, though both concern the same two files.

### Severity: Medium (forensic)

No contents are exposed. Both payloads stay sealed — the `.occbak` under the BEK, the shard file
under the SE-derived recovery buffer key — and neither opens off-device. What leaks is metadata about
a recovery: that one is under way, roughly how large, and how far along.

### What leaks, and from where

Two files in Application Support, both `.completeFileProtection`, both length-preserving because
AES-GCM is:

**`backup-import-cache-shards.dat` is a shard counter.** It holds `[AttestedShard]` JSON, appended to
as each shard arrives. Every element adds a near-constant chunk — a `SignedAttribute` with a
fixed-size share and signature, plus a sender identifier — so `ls -l` divides out to *n*. That is the
count of recovery pieces collected, available without a key.

There is a second-order channel in the same number. `handleHandback` carries forward only a Branch
B-verified attestation, so an element is roughly 260 bytes larger when the shard arrived by the
rotated-identity path. The file length therefore also weakly counts how many shards came in that way
— i.e. indicates that the owner's identity key rotated, which means a device recovery rather than a
routine one.

**`backup-import-cache.occbak` is a vault-size estimate.** It is stored as delivered, so its length
tracks the size of the vault it was exported from. Presence plus length says a recovery of roughly
this magnitude is in progress. Since `exportBackup` is depth-scoped, for a genuine file that size
reflects one specific depth's entry count.

### Why this is filed now rather than accepted quietly

The shard count is the exact number removed from the vault tab in Bug 93's follow-up, on the grounds
that a live tally is a report on real depth-0 activity that would visibly climb during a duress
session. That reasoning was accepted for the banner. It applies unchanged to the file, and the file
was never looked at — the UI stopped showing the number while the filesystem kept publishing it, more
durably and to a wider audience.

Worth recording as a pattern rather than an incident: a value can be removed from a screen and remain
fully readable in the artifact behind it. The banner fix is not wrong, it is just incomplete in a way
that is invisible from the UI layer.

### The escalation: these are not excluded from backup

`RootView.excludeStoreFromBackup` covers the SQLite store and its `-wal`/`-shm` sidecars only. None of
the Application Support files written by this subsystem is marked `isExcludedFromBackup`.

**As filed that was three files. Since remedy 2 shipped it is two** — the pending `.occbak` and
`backup-export-meta.dat`. The shard file is gone, and its replacement rows sit inside the SQLite
store, which the existing exclusion already covers. Remedy 2 therefore closed this half for shards as
a side effect, which is one more reason it was the right shape. A legacy shard file may still exist
transiently on a device upgrading mid-restore; the import path deletes it on first read or write.

So they are copied into iTunes/Finder/iCloud device backups. The sealed contents remain unreadable
off-device (the recovery buffer key is Secure Enclave-derived and device-bound), but existence and
length are not sealed and travel with the copy. A device backup is a far softer target than the device
itself: it can be obtained without the passcode prompt that `.completeFileProtection` depends on, held
indefinitely, and examined at leisure.

This is the half worth fixing first. It is one line per file and needs no format change.

### Remedy

1. **Exclude the remaining two from backup** — the pending `.occbak` and `backup-export-meta.dat`.
   Cheap, no format change, and it removes the off-device copy that makes the rest of this worth
   attacking.

   **Apply it at every write, not once at launch.** `isExcludedFromBackup` is a `URLResourceValues`
   attribute on the *file*, not on the path, so it does not survive the file being replaced — and
   `storePendingRestore` writes a fresh file each time it arms, as does each export-metadata update.
   Setting it during bootstrap would look correct, verify correct on the device it was tested on, and
   silently lapse the first time either file is rewritten.

   This is the same trap `excludeStoreFromBackup` already documents for a different reason: it is
   re-called on every `reapplyFileProtection` because "sidecar files may be recreated by SQLite". Same
   attribute, same lifetime problem, different files.

   **Do not ship this alone — see Bug 101.** Excluding these two while an unmanaged, backed-up copy of
   the same content accumulates in `Documents/Inbox` addresses the measurement and leaves the content.
   One device session verifies both.
2. **Move the BEK restore shards into the store, rather than padding the file.** Padding to a fixed
   32-slot array was the first answer here — the house pattern exists three times over
   (`verifierFillerArray`, `pinEnabledPerDepth`, and this file's own neighbour
   `backup-export-meta.dat`). It is the wrong one, because the file should not exist.

   `ReconstructShard` is already a SwiftData `@Model` doing this precise job for per-entry recovery:
   a sealed `SignedAttribute` plus sender identifier, under `deriveRecoveryBufferKey()`, with AAD
   bound to the row id. `acceptReturnedShard` writes rows in step 1 and a file in step 3 — the same
   data, the same key, the same lifecycle, through two mechanisms. No comment anywhere gives a reason
   for the split; `storeRestoreShard`'s "safe while locked" note is about which key it uses, not
   where it writes, and applies equally to a row.

   A sibling model gets four things at once: the length channel and its Branch B sub-channel
   disappear rather than being padded around; remedy 1 covers it for free, since the store is already
   excluded from backup; deletion goes through `PRAGMA secure_delete` page zeroing instead of a plain
   unlink; and `RotationRegistryTests` forces an explicit rotation classification, because it asserts
   every model in `OccultaApp.schema` is classified.

   **What it does not do, stated so the claim is not oversold:** an examiner who opens the store can
   still count rows. What changes is the bar — from `ls -l` on a file whose length divides cleanly by
   a near-constant element size, to opening SQLite and querying a store shared by eighteen models
   plus freelist and WAL, whose own size decomposes into nothing. A reduction, not an elimination.

   Bug 99 depends on this. Note the arming depth is *not* simply a field on that model, as first
   assumed: at arming time no shard rows exist yet, and a depth written onto a shard row as it
   arrives is the arrival depth, not the arming depth. See Bug 99's build plan for where it actually
   has to live. **Corrected 2026-09-11: Bug 99's own entry never actually landed on that answer —
   it's `RECOVERY_BUFFER_LAYERING.md` §6 item 5, cited at the top of that entry.** Arming state
   ends up as a small field (*"timestamp, state enum"*) in that depth's own shared-pool slot, once
   Stage 4 there is built — not tagged onto a `ReconstructShard` row at all.

   **Required under Bug 102's per-layer design too, not just this one.** Restore shards belong in
   rows whether or not recovery is layered — and under layering they need no depth field at all,
   because a shard already self-identifies by `distributionID`.
3. **Pad the `.occbak` cache to a coarse tier.** `ShardPadding.tier(for:)`'s doubling ladder is the
   existing idiom. Bounded at 2× worst case, so the disk cost is understood rather than open-ended.
   Lower priority than the first two: the magnitude signal is weaker than the progress signal, and for
   an attacker-supplied file it describes the attacker's own file rather than the victim's vault.

   **This one stays a file, and that is not inconsistency with remedy 2.** A `.occbak` can be large —
   photo and video attachments — and is memory-mapped deliberately (`.mappedIfSafe`, citing the
   unbounded inbound-read finding in SecurityReview2026-07-24). A multi-megabyte attacker-supplied
   blob does not belong in SQLite: it bloats the store, and the store's residue handling is tuned for
   small rows. The distinction is size and access pattern, not principle.

### Already correct, for contrast

`backup-export-meta.dat` is 32 fixed-width slots with random filler, so its length is constant
whatever the export history holds. The pattern this entry asks for is not new — it is applied one
file over and was not carried across.

---

## Bug 101 — Every file opened through "Open in Occulta" is likely still sitting in `Documents/Inbox`, unsealed and backed up

**Status:** **Fixed 2026-09-25, on `v1.11.0/vault-key-layering`, and verified in the simulator the same
day.** New copies are deleted after the read (step 1 below), and every Inbox, with copies left by
earlier versions, is cleared when the app goes to the background (step 3). Share-sheet and AirDrop
deliveries on a device are still unchecked.
~~Open, one fact unverified — see Confirm first.~~ Filed 2026-08-27, found while scoping
Bug 100's backup exclusion. Not found by reading the restore code: found by asking which copy of an
opened file the exclusion would actually cover, and discovering there is one more copy than the code
accounts for.

**Target:** `v1.11.0`.

### Fix, 2026-09-25 — delete the copy after reading, wherever iOS put it

**The location was probably wrong.** A device upgraded from v1.10.3 had no `Documents/Inbox` at all.
Occulta is a scene-based SwiftUI app, and for those iOS usually copies an opened file into
`tmp/<bundle-id>-Inbox/`, not `Documents/Inbox/`. That is unconfirmed: the device had not
necessarily opened a file through "Open in Occulta". If it holds, the harm is far smaller: `tmp/` is
not backed up, and `clearTemporaryDirectory()` empties it on launch. The fix below does not depend on
which location is right.

**Built:**
1. `handleOpenURL` (`OccultaApp.swift`) deletes the opened file after reading it whenever
   `FileManager.isInsideAppContainer` places it inside the app's container, the same `defer` that
   already deleted the share extension's App Group handoff. That covers both Inbox locations. A
   file outside the container is the user's original, opened in place from Files, and is never
   touched. Deleting after the read is safe for a staged `.occbak`: the bytes are memory-mapped,
   and unlinking a mapped file leaves the mapping valid.
2. `clearTemporaryDirectory()` now skips `*-Inbox` folders (`clearContents(of:)`). On a cold launch
   iOS has put the incoming copy there before the app starts, and the detached sweep raced
   `handleOpenURL` for it, so a file that launched the app could be deleted unread.

3. **Added the same day, after the simulator run below:** `FileManager.clearInboxes()`, called from
   `RootView`'s `scenePhase` handler on `.background`, deletes `Documents/Inbox/` and every
   `tmp/*-Inbox/`, folders included. By then every delivered file has been read, since iOS brings the
   app to the foreground to hand one over and `handleOpenURL` reads it at once, so this can't race an
   incoming file the way a launch sweep does. It removes what step 1 can't reach: copies left by
   versions before the fix, and one stranded by a crash between delivery and read. Removing the folder
   leaves no sign a file was ever opened into the app; iOS recreates it for the next delivery.

**Not built: remedy 1 (`LSSupportsOpeningDocumentsInPlace`)** — changes the opening contract, and a
share-sheet delivery is copied regardless, so step 1 is needed either way. **Not built: a launch sweep
of `Documents/Inbox`.** If iOS does deliver there, the sweep races the incoming file exactly like the
`tmp/` one did; and no such folder was found on the one upgraded device checked. *(Superseded the same
day: iOS 26 does deliver there, and copies from earlier versions need removing. Step 3 does it at
backgrounding instead, which has no race.)*

**Residual:** ~~a crash between delivery and the read leaves that one copy in `tmp/…-Inbox`, now
skipped by the launch sweep, until iOS purges `tmp/`. Not backed up.~~ *Closed by step 3: that copy
goes at the next backgrounding.* Remaining: a copy delivered and never followed by a backgrounding (the
app is killed while in the foreground) waits for the next one.

**Tests:** `OpenInPlaceCopyTests` — the inside/outside predicate (both Inbox locations, the container
root, a `<home>X` sibling, `..` escape, a symlink pointing out), the sweep keeping `*-Inbox`, and
`clearInboxes` removing both Inbox folders with their copies and nothing else, and doing nothing when
there are none.
`handleOpenURL` itself is on `OccultaApp` and can't be constructed in a test.

**Device check still wanted:** open a `.occbak` from Files and from a share sheet, cold and warm
launch; each must open, and a downloaded container must show no copy left afterwards.

### Verified in the simulator, 2026-09-25

iPhone 17 Pro simulator, iOS 26.2, Debug build of `46868e5`. Each `.occbak` was a dummy (`OCBK` plus
random bytes) opened with `xcrun simctl openurl`, which hands the file to the app the way "Open in"
does; the app container was watched every 20 ms. A control build, identical except that the `defer`
deleted only share-extension handoffs, was run the same way.

| | Fixed build | Control build |
|---|---|---|
| Where iOS put the copy | `Documents/Inbox/`, cold and warm | `Documents/Inbox/`, cold and warm |
| Copy after a cold launch | deleted after the read; the "Restore from this backup?" prompt showed | left in place |
| Copy after a warm launch | deleted within 20 ms | left in place |
| The original outside the container | untouched | untouched |

What this settles and what it changes:
- **The location guess above was wrong, at least here:** the copy goes to `Documents/Inbox/`, which is
  in device backups, not `tmp/<bundle-id>-Inbox/`. So the harm is the one this entry was filed for, and
  **the premise is confirmed:** without the fix every copy stays.
- **The fix works for new files,** on both launch paths, and reads before deleting.
- **Copies left by earlier versions are never removed.** The control build's two copies survived the
  fixed build's launches and opens. Every user of v1.10.3 or earlier who opened a file this way still
  has those copies, in backups. The "no launch sweep" decision above rested on the `tmp/` location and
  on one device that had no `Documents/Inbox`.
- **A date-based launch sweep can't fix that safely:** iOS keeps the original's creation and
  modification dates on the copy (a file dated 2020 arrived dated 2020), so "delete anything old" would
  delete a just-delivered old file unread.
- **An empty `Documents/Inbox` folder remains** after the fix deletes a copy. Its existence and
  modification date say a file was once opened into the app, and when.

**Step 3, verified the same way:** with the control build's two copies still in `Documents/Inbox/`, the
fixed build launched and sent to the background (by opening Settings) removed both copies and the
folder. A new file opened afterwards: iOS recreated `Inbox`, the app read the file and showed the
prompt, the copy was deleted, and the next backgrounding removed the folder again.

Not covered: share-sheet ("Copy to Occulta") and AirDrop deliveries, and a real device. Both still
want the device check above.

### Severity: High if confirmed (contents, not metadata)

Bug 100 is about a file's *length* revealing progress. This is the file itself. If confirmed, every
`.occbak` and `.occ` ever handed to the app this way is retained indefinitely in the backed-up
directory, as delivered.

Note the `.occ`/`.occbak` payloads are themselves sealed, so this is not plaintext exposure. What
leaks is the same class Bug 100 covers — existence, count, size, timestamps, one artifact per file
ever received — except accumulated forever and copied off-device, rather than transient and confined
to a pending restore.

### Confirm first

Two facts are established from the tree. The third is inferred and decides the severity.

**Established.** `LSSupportsOpeningDocumentsInPlace` is not declared in `Occulta/Info.plist`. Absent,
it defaults to `NO`, and the system hands a document-opening app a copy in `Documents/Inbox/` rather
than the original in place.

**Established.** The string `Inbox` appears in zero Swift files. Nothing enumerates that directory and
nothing deletes from it. `FileManager.clearTemporaryDirectory()` clears `tmp/`, which is a different
directory and not backed up in the first place. The cleanup at `OccultaApp.swift`'s `handleOpenURL`
runs only when `openedThroughShareExtension` is true — the App Group `.occ` handoff — so a `.occbak`
arriving by any other route has nothing remove anything.

**Inferred, and the thing to check on device.** Which entry points actually produce that copy. The
code calls `startAccessingSecurityScopedResource()`, which implies at least one path delivers a
security-scoped original rather than a copy, so the two mechanisms plainly coexist here. Open a
`.occbak` from the Files app and again from another app's share sheet, then list `Documents/Inbox`.
Everything below is conditional on that listing being non-empty.

### Why this was missed

The three files Bug 100 enumerates are all ones this code writes deliberately, so reading the backup
path finds them. This copy is made by the system, on the app's behalf, because of a key that is not
in the plist — it is invisible from the Swift sources, and the only trace of the decision is an
absence. Worth recording as a search pattern: an artifact created by a missing declaration cannot be
found by reading the code that would have created it.

### Remedy

1. **Declare `LSSupportsOpeningDocumentsInPlace`.** The preferred fix: no copy is made at all, and
   the existing `startAccessingSecurityScopedResource()` handling in `handleOpenURL` is already
   written for exactly that. Verify both entry points still open afterwards — in-place opening is a
   different contract, not just a flag.
2. **Sweep `Documents/Inbox` on launch**, and delete the copy after reading it on the paths that
   still produce one. Needed regardless of (1): existing installs have whatever has already
   accumulated, and (1) changes future behaviour only.
3. **Then apply Bug 100 remedy 1** to the Application Support files. Excluding those from backup while
   an unmanaged, backed-up copy of the same content sits in `Documents/` is a half-measure — which is
   how this was found.

### Relationship to Bug 100

Independent, and this one ranks higher. Bug 100 is metadata about a restore in flight, cleaned when it
completes. This is retained content, accumulating across every file ever opened, in the directory iOS
backs up by default. Same investigation, unrelated remedies.

---

## Bug 102 — The BEK has no layer concept, so a restore completing in duress hands the coercer the device's real backup key

**Status:** **Closed — subsumed into Bug 99, 2026-09-11.** Filed 2026-08-27, **Open** until now. Found
originally by asking whether Bug 99's arming-depth remedy also contains the *key* a restore installs,
not just the entries it imports — it did not, at the time.

**Target:** unset. Larger than the entries it sits beside — see Remedy.

### Reclassified 2026-09-11 — the premise this entire entry rests on no longer holds

**Everything below this note describes a device-wide, unlayered `BackupEncryptionKey` — "exactly two
fields, `id` and `encryptedPayload`... no depth stamp," fetched via `.first` with no predicate. That
was accurate when filed and stayed accurate through Stage 1. It stopped being true at Stage 2
(2026-09-08, `VAULT_KEY_LAYERING.md` §7), which routed the then-shipping BEK array by depth, and is
further from true now that BEK storage moved off the array onto per-depth `BackupEncryptionKey` rows
(§8 item 14, 2026-09-11).** Left below unedited as the reasoning trail — the design work in *Remedy*
is what this refactor actually built, in a rows-shaped form rather than the array this entry proposed,
so it's the accurate record of why, not a stale description to correct line by line.

**What this closes, concretely.** The three consequences section below ("his key becomes the device's
key," "real trustees are stranded," "the vault lists his phones as trustees") described a *device-wide*
row — install anywhere, own everywhere. That's now structurally impossible: installing a BEK at duress
depth N only ever touches depth N's own row via `Backup.persist`/`claimFillerRow`, confirmed directly
by `BackupKeyOrphaningTests.shallowerBackupKeySurvivesCascade` (a shallower, still-live depth's BEK is
byte-for-byte untouched by an unrelated deeper deactivation) — the identical property this entry's
*Remedy* section asked for, under "What it subsumes." Row/file-count leaking layer count (the entry's
own "What it does not remove" caveat) is likewise addressed the way item 14 settled it: a 32-row
eager-filler baseline, not the fixed 32-slot array this entry pictured, but the same row-count-hiding
property up to that baseline.

**What is genuinely still open, and where it now lives: Bug 99, not here.** `attemptBackupRestore`
(renamed from `attemptBEKRestore`) still hard-guards `currentDepth == 0` before completing
(`Vault+Manager+Backup.swift:482`, confirmed directly) — restore *completion* remains pinned to depth
0, unchanged by either storage refactor, blocked on `RECOVERY_BUFFER_LAYERING.md`'s own not-yet-built
per-depth restore state (`VAULT_KEY_LAYERING.md` §8 item 9). That's exactly Bug 99's oracle — arm in
duress, wait, nothing ever completes there — not a separate harm anymore. Before this refactor, Bug
102 was the wider bug (it installs the *wrong* key device-wide) and Bug 99 the narrower one it
partially subsumed (it never installs at all, which at least isn't wrong). Now that installing is
correctly per-depth by construction, there is only the narrower harm left, and Bug 99 already tracks
it in full — including the exact remedy (complete at the arming depth) that closes it. Nothing is lost
by folding this entry into that one; there is no remaining piece of this bug that Bug 99 doesn't
already cover.

### Original entry, preserved below for the reasoning trail

### Severity: High

Not a deniability break on its own. It is a durable compromise of the real layer reached from a
duress session, and it survives the coercion.

### What is not depth-scoped

`BackupEncryptionKey` declares exactly two fields, `id` and `encryptedPayload`. There is no depth
stamp. `fetchDecodedBEK` reads `fetch(FetchDescriptor<BackupEncryptionKey>()).first` — no predicate,
no filter, take the single row. It is sealed under the vault key, which is one key for every depth;
vault *entries* carry individual depth stamps, the key they are sealed under does not.

So there is one BEK per device, readable and writable from any layer.

This is genuinely surprising in a codebase where contacts, vault entries, group membership, PIN gates
and layer arrays are all depth-partitioned, and nothing anywhere states it. Recorded plainly for that
reason: the next reader is likely to assume it is layered, and the reader after that is likely to
"fix" it into a per-depth form without knowing what that breaks (see Remedy).

### Why Bug 99's remedy does not cover it

That remedy binds completion to the depth the file was armed at, and `importBackup` stamps every
restored entry with that depth. Entries are therefore contained — an attacker's rows land in his own
cover story and never reach depth 0, which is a genuine improvement on deferral.

The BEK is a different object. `reconstructBEK` persists it through `persistBEKPayload`, whose
`Payload` carries `bekBytes`, `distributionID` and `shardMetadata` — and no depth. There is no field
for the arming depth to stamp, so the binding has nothing to bind. **Bug 99 contains the contents and
not the key that came with them.**

### Three consequences, all on the no-BEK device

The population is exactly the one Bug 94 remedy 1 does not cover: a device with no BEK yet, which is
a fresh install or a new phone — and also the only population where a restore can proceed at all.

1. **His key becomes the device's key.** Every backup exported afterwards, from any depth, is sealed
   under a key he generated. Latent rather than immediate: it pays off only when a file crosses his
   path — a device backup, iCloud Drive, mail, a shared computer. Bug 101 is one such path.
2. **Real trustees are stranded.** They still hold shards for the BEK that this one replaced. If they
   were ever needed they would reconstruct a key matching nothing on the device. This is precisely
   the harm Bug 94 remedy 1 exists to prevent, arriving through the gap that remedy leaves open by
   design.
3. **The vault lists his phones as trustees.** `shardMetadata` rides inside the BEK payload, so
   `bekShardMetadata()` returns his distribution. Shard health, trustee counts and `bekSetupState`
   all describe his set, and `exportBackup` permits an export because his metadata reports the
   threshold met. The user has a backup they believe is protected and recoverable, whose recovery
   depends entirely on the attacker's handsets.

### Remedy: layer the recovery subsystem, of which the BEK is one part

**Restated 2026-08-27, wider than first filed.** This entry began as "give the BEK a depth." The
better framing came out of asking why the afternoon's UI work had been necessary at all, and it
reframes Bugs 99, 100 and part of 93 as symptoms of one cause.

**The cause: recovery is device-wide in an app that is layered everywhere else.** One BEK, one pending
file, one shard buffer, plus a depth-0 privilege bolted on so the real layer wins. The two layers
therefore genuinely behave differently, and every fix so far has flattened a *symptom* of that —
uniform confirmation, uniform banner, deleted acknowledgment. Each makes the UI misrepresent the
asymmetry slightly less. None removes it.

Make recovery per-layer and the asymmetry stops existing, so the symptoms go with it rather than being
suppressed one at a time.

**The routing is already in the data.** A shard carries `entryID = distributionID`, and each depth's
BEK would carry its own `distributionID` — so an arriving shard *self-identifies* which layer it
belongs to. No depth field on the shard, and no arming-depth binding needed for shards at all.

**What it subsumes**

- **Bug 102** as originally scoped. A restore in duress installs the duress layer's BEK. Depth 0's key
  is untouched, real trustees are not stranded, the vault does not list the attacker's phones.
- **Bug 99's oracle.** He arms in duress, it completes in duress — indistinguishable from real,
  because it is the same operation rather than a masked one.
- **Part of Bug 93's follow-up, by reverting it.** With per-layer state, each layer can answer
  truthfully about *its own* BEK, and that answer is exactly what a real session in that layer would
  give. The file-open acknowledgment deleted on 2026-08-27 can come back. What was recorded there as
  the accepted cost of uniformity was only a cost because the state was shared.

**What it does not remove**

- **Row and file counts still leak layer count.** N BEK rows, or N pending files, says N layers have
  backups configured — countable without decrypting. Needs the fixed-slot padded-array treatment of
  `pinEnabledPerDepth` and `verifierFillerArray`, not a naive one-row-per-depth table.
- **Bug 99's binding survives in reduced form**, for the pending `.occbak` alone. That file is bulk
  data and stays a file (Bug 100), so unless it is slotted per depth too it still needs a depth tag
  saying which layer armed it.
- **Bug 100 remedy 2 is superseded rather than required.** Rows were the right answer against the
  file, and the file-to-rows migration still earns its keep for devices upgrading now. But rows leave
  a count — an examiner who opens the store can still `SELECT count(*)` — where a fixed-slot array
  leaves nothing to count. Rows are the interim; slots are where this lands.

### The shape: one array, not several

**One fixed-width array of fixed-count slots, one slot per depth.** Each slot carries, as separately
sealed fields:

| Field | Sealed under | Why not shared |
| --- | --- | --- |
| BEK record | vault key | it protects backup contents |
| Collected restore shards | recovery buffer key | shards arrive during inbound processing, which happens while the vault is locked |
| Arming depth (Bug 99) | recovery buffer key | written at arming, read at completion |

**Two keys do not force two containers.** Preserving a sealed blob never requires its key: a shard
arriving at a locked vault rewrites its slot's shard field and copies the BEK field's ciphertext
through untouched. One array is also better than two — one artifact of constant size rather than two
to pad, clean up and explain.

**Every sealed field's AAD must bind its slot index.** Without it, lifting slot 2's ciphertext into
slot 0 moves a duress layer's BEK into the real one. Same discipline `reconstructRowAAD` applies to
row ids and the export-metadata file applies to its depth slots.

**Bug 96 closes for free.** Fixed width means a cap on shards per depth, which is exactly what that
entry's unbounded-growth `withKnownIssue` asks for. A cap is inherent to the shape rather than bolted
on.

### Where it lives: `AppLayerConfig`, and the constraint that settles it

`AppLayerConfig` already holds fixed-width padded per-depth arrays — `pinEnabledPerDepth`, the
verifier arrays, the blob metadata arrays — is already classified in `RotationRegistry`, and **already
exists on every install**. `Manager.Security`'s constructor seeds the row at first launch for the
reason this design has to respect anyway:

> its absence would be a forensic tell that the feature was never used

**An earlier draft of this entry ruled `AppLayerConfig` out**, on the grounds that a device which
never configured Secure Mode has no row and that this is the main restore population. That was wrong,
and wrong twice — the same claim was used to reject it as a home for Bug 99's arming depth. It came
from reading `requireConfig()`'s `.notConfigured` throw as evidence the row can be absent, when that
throw guards a case the bootstrap makes unreachable. Recorded because the mistake is repeatable:
where a state is *handled* says nothing about whether it *occurs*.

**Eager creation is a constraint on this design, not a detail.** The same constructor applies it twice
— to the config row, and to the Secure Mode SE key, where the argument is sharper still, since
keychain items carry `kSecAttrCreationDate` and lazy creation leaks not just whether a PIN was ever
configured but when. Any per-depth BEK structure must therefore exist from first launch, fully padded,
on every install — including ones that never configure Secure Mode and never run a restore. A
structure that appears when backup is first set up would reintroduce exactly the tell the surrounding
code went to trouble to remove.

**Cost, stated honestly.** This is a large change to a security-critical subsystem, and it is not a
patch-release change. It also means part of what shipped on `release/v1.10.3` is correct for the
current architecture and would be undone by the better one — specifically the deleted acknowledgment.
That is recorded rather than left to be discovered.

### The original remedy, for reference

Narrower: give the BEK a depth and stop there.

The direction is right and more consistent than what exists — `exportBackup(currentDepth:)` is already
depth-scoped, so a per-depth key is the shape the rest of the feature implies. It is not small:

- **Shard distribution becomes per-depth.** Either each layer carries its own trustee set, or there
  is an explicit, written decision that layers share one and what that means when a duress layer
  distributes.
- **Row count would leak layer count.** One row says nothing; N rows says N layers have backups
  configured, readable by counting without decrypting anything. This needs the fixed-slot padded-array
  treatment already used by `pinEnabledPerDepth` and `verifierFillerArray`, not a naive one-row-per-
  depth table.

### Two rejected fixes, recorded because both look correct

**"Don't persist a BEK when the restore completes above depth 0."** Tidy, small, and wrong. After the
identical action the vault would report *backup ready* in one layer and *not set up* in the other —
`bekSetupState` is read straight into the vault tab. That is a new depth oracle bought to close a
different problem, the same trade the depth-0-only restore confirmation made before it was corrected.

**"Stamp the BEK row with the arming depth and filter `fetchDecodedBEK`."** Closer, but it is
per-depth BEK with the hard parts omitted: it still leaves one row, so whichever layer wrote last owns
the device's only key, and the filter turns a missing row into "no backup configured" for every other
layer — reintroducing the same observable as the first rejected fix.

### Reconciled with Bug 92, 2026-08-28

Bug 92 shares this entry's premise — the BEK is not layered — and is not a duplicate of it. It
addresses the *offline* consequence (a file decrypts at any layer for someone holding extracted key
material); this addresses the *in-app* one (duress-depth operations act on the real key).

**Neither fix covers the other's harm.** Per-depth slots would still all be sealed under the vault
key, which is not depth-derived, so a device dump yields every slot — this entry's remedy does
nothing for Bug 92. And a PIN-combined file key does not stop a duress session installing or
distributing the real BEK, so Bug 92's remedy does nothing for this one.

**Bug 92 does supply something this design needs.** §2.1 of `BEK_LAYERING_REFACTOR.md` concedes that
the BEK field's slot separation is code discipline rather than cryptography, because the vault key
opens every slot. Bug 92's insight — the PIN is the only input in this subsystem a coerced session
does not hold — is the available answer. Adopting it here, or accepting convention and documenting
that plainly, is an open decision for this refactor rather than something to inherit silently. It
carries Bug 92's hard dependency with it: no slow KDF exists in the codebase, and a PIN-derived key
without one is a design that looks layered and is not.

### Relationship to the entries around it

Bug 94 remedy 1 refuses to overwrite an existing BEK and explicitly does not cover the no-BEK device.
Bug 99 contains what a restore imports. This is the third piece of the same seam: what a restore
*installs*. All three are the no-BEK population, and none of the others closes this one.

---

## Bug 103 — An inbound message from a contact hidden at the current depth renders that contact's name, phone and email

**Status:** **Not a bug — duplicate of an accepted, documented limitation. Closed 2026-08-28.**

Filed 2026-08-27 as High severity. It is a re-discovery of the residual recorded in
`Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md`, whose 2026-08-13
inbound-path trace found this exact leak, evaluated five handlings of it, and closed the question:
*"The flow is left exactly as it is… an accepted, documented limitation, not an oversight and not a
deferred fix."* That decision is the authority; this entry is kept only because the trace below is
accurate and the reasoning about why it cannot be fixed is worth having in two places.

**Severity, corrected: none — no change is warranted, and the obvious fix is harmful.** The original
"High (deniability break)" rating is left visible in the history rather than quietly edited, because
the misjudgement is the useful part: the leak is real and the rating was defensible in isolation, but
the fix it implies makes the product strictly worse. See "Why the remedy was wrong" below.

**Do not re-file this.** It has now been raised twice in two weeks (2026-08-13 and 2026-08-27) by
tracing the inbound path without reading the oracle document. If a third trace finds it again, the
answer is still no.

### The leak, traced end to end — this part was and is correct

The chain below was verified independently and matches the 2026-08-13 trace. Nothing here is
disputed; what was wrong was the conclusion drawn from it.

### The chain, verified end to end

1. **Inbound processing has no depth filter.** `ContactManager.identifyOwner` resolves the sender
   through `fetchAllContacts()`, which predicates on `deletionToken == nil` and nothing else. No
   `isVisible(atDepth:)` appears anywhere in the inbound path; `currentDepth` is threaded only into
   `ShardCustodyManager.handleInbound`, where it gates restore completion rather than filtering.
2. **A duress unlock drains queued files, deliberately.** A file arriving while the app is locked is
   queued as raw bytes and drained on *any* unlock (`OccultaApp.swift`, the `pendingFileData` drain).
   Discarding it in duress was itself a detection oracle and was removed in `2958593`.
3. **The reader renders the sender.** `processInboundFile` sets `openedFileContents`, the sheet
   presents `ComposableMessage.Conversation(mode: .read(messageOwner:))`, and that view's body opens
   with `Contact.Info(identifier: owner)`.
4. **`Contact.Info` filters on nothing.** Its `init(identifier:)` replaces the type's default
   `@Query(Contact.Profile.descriptor)` with a bare identifier predicate — no depth, and not even
   `deletionToken` — then renders `givenName.decrypt()`, the first phone number and the first email.

No step requires anything of an attacker. A contact sends a message, the phone is locked when it
arrives, the user is coerced into a duress unlock, the queue drains and the sheet opens.

### Why the remedy was wrong

The filing proposed giving `Contact.Info` a depth check so a hidden sender renders its `"Anonymous"`
fallback. It was amended on 2026-08-28 to note the check cannot be a SwiftData `#Predicate` —
`isVisible(atDepth:)` decrypts `originDepth` and `visibleThroughDepth` and runs `DepthCodec.decode`
over the plaintext, so it has to be a post-fetch guard. That amendment was correct about the
mechanism and beside the point about the substance. **The remedy should not be implemented at all.**

It was implemented on 2026-08-28, reverted the same day, and never committed. The oracle document had
already proposed, examined and rejected the identical change on 2026-08-13, for two reasons:

**1. "Anonymous" is the same tell wearing a different label.** The fallback fires only when no contact
matches the identifier, and `identifyOwner` requires a match to succeed — so it is currently
*unreachable* on this path at any depth. Adding the guard would make it reachable **only** at a duress
depth. The signal moves from "this name is not in my contact list" to "the word Anonymous is on
screen"; it does not go away. The implementation made this concrete and worse: it also added
`deletionToken == nil` to the predicate, manufacturing a second way to reach a string that otherwise
never appears.

**2. The identity was already disclosed by the transport, before Occulta ran.** Bundles arrive out of
band — a messaging app, AirDrop, email — and that channel named the sender on the delivery screen
before anyone tapped the file. In-app anonymisation conceals nothing an observer does not already
have. The oracle document's word for it is theatre: it costs the legitimate user the sender's identity
and buys no confidentiality.

### Why refusing the bundle is worse, not better

The obvious next instinct — refuse the bundle outright, accepting a tell in exchange for keeping the
content unread — is the original `passSecurityControl` behaviour that the oracle document exists to
remove (`b1f9045`). The asymmetry that decision turns on:

- **Refusal is adversary-controlled.** Key exchange is proximity-only, so a coercer with physical
  control can force-pair a device and probe on demand. One rejection from a provably-paired identity
  is close to conclusive; a second removes essentially all doubt. Repeatable, at a moment of the
  coercer's choosing.
- **The render leak is not adversary-controlled.** It requires a real, unaware third party to send
  during the coercion window. Timing-bounded, chance-dependent, not repeatable on demand.

Trading a chance leak for an on-demand one is the wrong direction even though refusal also hides the
body. Refusal additionally identifies *which* contact is hidden, where the current behaviour does not
single anyone out.

### The exposure follows from an invariant, not an implementation choice

Key exchange is proximity-only, so **openable ⟹ the sender is a known contact**. The duress view's
purpose is to hide some known contacts. A message from one of them forces an inconsistency that has
to surface somewhere, and the oracle document tabulates every handling: render the real name (sender
absent from the list), render "Anonymous" (a string unreachable at depth 0), reject (the original
oracle), silently queue until depth 0 ("nothing happens on tap" is itself duress-only), or fabricate
an identity (still absent from the list, and now the app lies to its owner). All five leak.

Closing it would require depth 0 to produce the same observable — messages from contacts not in the
list, or files that sometimes do nothing when tapped — which contradicts the invariant. The app has no
concept of a stranger, because it cannot decrypt anything from one.

### What is actually still open

Not this. The oracle document's closing paragraph separates two things this entry conflated:

> And *content* confidentiality is separable from the identity leak — checking visibility before
> decrypting would keep the message body unread even where "a message arrived, from someone" is
> inferable. That option is not taken here, since the flow is unchanged, but it remains available and
> is a different question from this one.

Silent queueing is noted there as the least-bad alternative — it satisfies C1 properly, since
visibility can be checked after `identifyOwner` and before decryption, and a coercer-paired contact
would not trigger it because a contact created at depth N has `originDepth = N` and is visible there.
It was not adopted, because it still trades a strong signal for a weaker one rather than removing one.
That is the live question. It is about the body, not the name, and it should be raised against the
oracle document rather than re-filed here.

### Scope: sweep completed 2026-08-28

The filing called for a sweep rather than a point fix, on the grounds that `Contact.Info` is a shared
component and only the `.occ` reader had been traced. The sweep was run. Results:

**`Contact.Info` has two call sites, one of them dead.** `ComposableMessage.swift:209` is the live
one traced above. `Import+View.swift:284` renders the same three fields for a basket owner, but
`struct Import`'s only reference is its own `#Preview` — it has no production presenter. Dead, and
noted here because reviving that view would inherit the leak.

**A second instance of the same accepted limitation.** The inbound identity-challenge path renders
the sender's name with no query involved at all. Filed as **Bug 104**, and closed the same day for
the same reason as this entry — it is the same residual in a second subsystem, not a second bug.

**Unfiltered, and correctly so.** `Contact.DetailsV2` (`ContactDetailV2.swift:16` and `:347`),
`KeyExchange` (`KeyExchange.swift:18`) and `ComposableMessage`'s own write-mode query (`:16`) all
replace the descriptor with a bare identifier predicate and decrypt `givenName`. `KeyExchange` is
structurally identical to `Contact.Info`, down to the `?? "Anonymous"` fallback. All three are reached
only through `ContactsListV2`'s `navigationDestination`, fed by rows that are already depth-filtered,
and nothing appends to that path programmatically. The filing called these "latent"; they are not.
A view that can only be entered with a visible contact's identifier needs no depth check of its own,
and adding one would create the same duress-only observable described above. Left alone deliberately.

**Dead, so unfiltered but unreachable.** The entire v1 contacts tree — `Contacts`, `Contact.Details`,
v1 `Contact.Form`, `BusinessCardContactsView` — plus `ContactDetailV3` and `Import`. The live tab is
`ContactsV2` (`OccultaApp.swift:526`).

**Already correct.** `ContactsListV2`, `GroupDetailV3`, `Group+FormV3`, `Vault+Tab`,
`ContactClassification`, `ShareRecipientPicker`, and both vault trustee screens via
`mlkemEligibleContacts`. `SecureModeSetupFlow`'s `sensitiveCount` counts only currently-visible
contacts and renders no identity.

**The "pattern" is the design, not a defect.** The filing generalised this to "views render contacts
without a depth predicate," and the 2026-08-28 amendment widened it further to "any identifier
arriving from an inbound path reaches an identity render with no depth check." That statement is
factually accurate and its implied conclusion is backwards: on the inbound path, the absence of a
depth check *is* the decision — it is what keeps duress and depth-0 behaviour identical. The place
depth filtering belongs is the lists a user picks from, and every one of those already has it.

Note also that `Contact.Info`'s query does not filter `deletionToken`, so a soft-deleted contact
renders the same way, and `fetchContact(by:)` (`Contact+Manager.swift:413`) omits it too. Recorded as
an observation, not a defect: adding the filter is what makes the `"Anonymous"` fallback reachable,
which is the harm described above. If a reason ever emerges to filter soft-deleted senders, it has to
answer that first.

---

## Bug 104 — An inbound identity challenge from a contact hidden at the current depth renders that contact's name

**Status:** **Not a bug — same accepted limitation as Bug 103, in a second subsystem. Filed and
closed 2026-08-28.**

Filed as High severity by the sweep Bug 103 asked for, hours before that sweep's premise was found to
be wrong. It is the same residual: an inbound bundle from a contact hidden at the current depth
renders that contact's name. The authority is the same —
`Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md`, decision of
2026-08-13. Both of that decision's reasons apply here unchanged: suppressing the name creates a
string reachable only under duress, and the transport that delivered the `.occ` already named the
sender before the app ran.

**Severity, corrected: none.** Kept because the trace is accurate and because this path differs from
Bug 103's in a way worth recording — see "Why this one is shaped differently" below, which was
written as an argument for a separate fix and reads better now as an argument for why no fix belongs
in either place.

### The chain

1. **The inbound `.occ` pipeline resolves the sender with no filter.** Both identity-challenge
   branches in `buildOwnedBasket` — `OccultaApp.swift:884` (group envelope) and `:925` (1:1
   `decryptSealed`) — call `contactManager.fetchContact(by: ownerID)`. That predicates on the
   identifier alone: no depth, and unlike `fetchAllContacts()` not even `deletionToken`
   (`Contact+Manager.swift:413`).
2. **A duress unlock drains queued files.** Identical to Bug 103 step 2 — the identity-challenge
   branches sit inside `buildOwnedBasket`, which `processInboundFile` calls on the drain.
3. **The coordinator decrypts the name into state.** `handleInboundChallenge` takes the resolved
   `Contact.Profile` and computes `senderName` from `sender.givenName.decrypt()`
   (`IdentityChallenge+Coordinator.swift:167`), storing it in `incomingChallenge` (via
   `PendingApproval.challengerName`) or `verificationOutcome.contactName`.
4. **Two sheets render it.** `IdentityChallenge+View.swift:223` prints
   "`<name>` is verifying your identity"; `:294`–`:295` prints it twice more in the verification
   result. Both are presented from `OccultaApp.swift:502` and `:513`.

### Why this one is shaped differently

Bug 103's proposed remedy was a post-fetch guard inside `Contact.Info` — a view that owns a query.
There is no query here. The name is decrypted in the coordinator at inbound-processing time and
stored as a plain `String` in observable state; by the time a view sees it, the plaintext has been
captured and the `Contact.Profile` is gone. Any gate would have to sit at step 1 or 3 — the two
`fetchContact(by:)` call sites, or once inside `handleInboundChallenge`.

That difference was the original argument for filing this separately. It survives; the conclusion
drawn from it does not. A gate in the coordinator produces exactly what a gate in the view produces:
a rendered string that can only appear at a duress depth.

### The claim this entry originally made, and why it was wrong

The filing asserted, under the heading "Not an oracle":

> Suppressing the *name* is a display change; it does not alter whether the bundle is processed,
> whether a response is signed, or anything the sender can observe.

That is the error, and it is worth leaving visible because it is an easy one to make twice. It
reasons about what the *sender* can observe. The threat model here is a coercer **holding the
device**, reading the screen. For that observer the display *is* the observable, and a display that
differs by depth is a depth oracle regardless of whether any protocol behaviour changed.

The supporting argument was wrong on its own terms too. The filing claimed `"Unknown"` is "a value the
UI already produces for ordinary reasons," pointing at `senderName`'s empty-name fallback at `:167`.
That fallback fires only for a contact with a blank given name — rare, and unrelated to depth. Gating
on visibility would make `"Unknown"` a routine, duress-only outcome. Same mistake as Bug 103's
`"Anonymous"`: a fallback that is nearly unreachable in practice is not cover, and making it reachable
only under duress manufactures the signal it was meant to hide.

### Also unchanged: `contextNote`

`contextNote` is attacker-supplied free text carried in the challenge and rendered directly beneath
the name (`IdentityChallenge+View.swift:227`, and `:299` in the outcome sheet). It was recorded as an
open trade alongside Bug 103's message body. It stays open in the same sense and for the same reason:
it is a *content* question, separable from the identity one, and it belongs to the thread the oracle
document leaves available — checking visibility before decrypting — not to a display gate.

### Note on `.response`

The `.response` branch also writes `verifiedAt[senderID]` before rendering
(`IdentityChallenge+Coordinator.swift:194`). That is in-memory state keyed by identifier, not a
render, and is out of scope here — but any future UI reading `verifiedAt` inherits the same question.

---

## Bug 105 — A duress layer can distribute shares of the real BEK, through ordinary UI

**Stale, 2026-09-11:** The Guard section cites `BEKArrayTests`, deleted outright by this session's
BEK storage refactor — the slot-isolation property it proved is presumably now covered by
`BackupEncryptionKeyStorageTests.swift`, but the citation itself is a dead end.

**Status:** **Closed (Fixed), verified 2026-09-10.** Filed 2026-08-28, found while scoping
`BEK_LAYERING_REFACTOR.md` — by asking whether shard *distribution* is depth-gated, having already
established that restore is not. Fixed by `VAULT_KEY_LAYERING.md` §7 Stages 1-2 (built 2026-09-08,
per that document's own status — not previously reflected here, verified directly against shipped
code rather than taken on the doc's word). Distribution only — restore/reconstruction completing
per-depth is a separate, still-open concern, `VAULT_KEY_LAYERING.md` item 9, blocked on
`RECOVERY_BUFFER_LAYERING.md`'s own Stage 4. Not to be conflated with this closure.

**Target:** Fixed. (Originally `release/v1.10.3` — that release shipped without this fix, per
`VAULT_KEY_LAYERING.md` §9's own correction; landed instead on `v1.11.0/vault-key-layering`.)

### Severity: High

A durable compromise of the real layer, reached from a duress session, that survives the coercion. The
same class as Bug 102 and arrived at more cheaply — every step is legitimate app behaviour.

### What happens

`prepareBEKShards` has no depth gate. It reads the one device-wide BEK through
`fetchDecodedBEK(vaultKey:)` and splits *that* key, whatever depth the caller is at.
`Vault+ShardSetup.swift` contains **zero** references to `currentDepth` or `isVisible`.

So at a duress depth a coercer opens the backup shard setup, picks trustees, and distributes. The
shares he receives are shares of the owner's **real** backup key.

### Why it is easy to miss

**The trustee picker is correctly depth-filtered.** `mlkemEligibleContacts` applies
`isVisible(atDepth: security.currentDepth)`, so a duress session offers only that layer's contacts —
which reads as the flow being depth-aware. It is filtering the wrong axis. The contacts are per-layer;
the key they are handed shares of is not.

That is the entire thesis of Bug 102 in one screen: everything *around* recovery is layered, and
recovery is not.

### Two harms

1. **He holds threshold shares of the real BEK.** Latent rather than immediate — it pays off when he
   obtains any `.occbak`, via a device backup, iCloud, or Bug 101's `Documents/Inbox` copy. Note
   `exportBackup` at a duress depth exports only that depth's entries, so the file he can make himself
   is not the one he wants; he needs one of the owner's.
2. **The owner's trustee list is replaced, immediately.** `prepareBEKShards` reuses the existing
   `distributionID` and **overwrites** `shardMetadata` with the new distribution. Genuine trustees
   still hold valid shares — same key, same distributionID — but the device's record of who holds what
   is gone. `bekSetupState`, shard health and trustee counts all report his set. The owner's real
   recovery now appears to depend on the attacker's handsets.

### Reconciled with Bug 92, 2026-08-28

Bug 92 shares this entry's premise — the BEK is not layered — and is not a duplicate of it. It
addresses the *offline* consequence (a file decrypts at any layer for someone holding extracted key
material); this addresses the *in-app* one (duress-depth operations act on the real key).

**Neither fix covers the other's harm.** Per-depth slots would still all be sealed under the vault
key, which is not depth-derived, so a device dump yields every slot — this entry's remedy does
nothing for Bug 92. And a PIN-combined file key does not stop a duress session installing or
distributing the real BEK, so Bug 92's remedy does nothing for this one.

**Bug 92 does supply something this design needs.** §2.1 of `BEK_LAYERING_REFACTOR.md` concedes that
the BEK field's slot separation is code discipline rather than cryptography, because the vault key
opens every slot. Bug 92's insight — the PIN is the only input in this subsystem a coerced session
does not hold — is the available answer. Adopting it here, or accepting convention and documenting
that plainly, is an open decision for this refactor rather than something to inherit silently. It
carries Bug 92's hard dependency with it: no slow KDF exists in the codebase, and a PIN-derived key
without one is a design that looks layered and is not. (This decision itself is `VAULT_KEY_LAYERING.md`
item 7: settled as accepted code-discipline separation, not the PIN-derived per-slot key — see that
item and the *Fix* note below for why.)

### Fix

`VAULT_KEY_LAYERING.md` §7 Stages 1-2: the single device-wide `BackupEncryptionKey` row became a
32-slot array, one slot per depth, each slot holding an independently-generated key. Verified directly
against shipped code, not assumed from the design doc:

- **`Backup.setup(vaultKey:currentDepth:)`** (`Vault+Manager+Backup.swift:888`) generates a fresh
  `SecRandomCopyBytes` 256-bit key and persists it to `currentDepth`'s own slot — no derivation from,
  or connection to, any other depth's key. A duress-depth setup cannot produce the real depth-0 key by
  construction, not by convention.
- **The full call chain genuinely routes by depth**, checked hop by hop:
  `prepareBackupShards(currentDepth:)` → `Backup.prepareShards(currentDepth:)` →
  `fetchDecoded(currentDepth:)` → `LayerStore.read(slotIndex: currentDepth, ...)`. `currentDepth` is
  the slot index, not a decorative parameter.
- **`Vault+ShardSetup.swift`** — the file this entry's own "What happens" section named as having zero
  references to `currentDepth` — now passes `currentDepth: self.security.currentDepth` into
  `backupShardMetadata`, `setupBackup`, and the shard-preparation call.
- **Both named harms are closed as a structural consequence, not patched individually.** Harm 1 (a
  coercer holds shares of the real BEK): impossible, since a duress-depth distribution splits that
  depth's own independently-random key. Harm 2 (the owner's trustee list replaced): `shardMetadata`
  lives inside each slot's own payload now, so a duress-depth distribution can only overwrite *that
  depth's own* metadata — depth 0's is a separate record, never touched.
- **The item 7 accepted-tradeoff decision, cross-referenced above:** slots are not additionally
  cryptographically isolated by a PIN-derived per-slot key (the direction "Bug 92 does supply
  something this design needs," above, gestures at) — that was designed (`slotKey(depth)`,
  fold-the-PIN-into-`info`), then found to conflict with a *different* property this design also wants
  (hiding which depth was last active across snapshot diffs, by full-array reseal on every write) and
  deliberately dropped in favor of the snapshot protection. A coercer holding the vault key can still
  decrypt every depth's slot content directly — that risk is accepted as code-discipline separation,
  the same posture this codebase's contact storage used to document before its own mechanism was
  removed (Removal Stage 2, `plan.md`) — not a residual version of *this* bug, a different, named,
  still-accepted tradeoff.

### Guard

No dedicated regression test asserts the literal `depth0Key.bytes != depth2Key.bytes` — worth naming
as a real, if narrow, gap rather than glossing over it. What's covered: `BEKArrayTests`
("writing to one slot preserves a previously-written different slot's content" et al.) proves
storage-level slot isolation; `VaultBackupRoundTripTests.shardConfirmationAppliesToOwningDepthOnly`
sets up independent BEKs and `shardMetadata` at depths 0 and 2 and proves they're tracked as fully
separate records, never cross-contaminating. Combined with `Backup.setup`'s fresh-CSPRNG-per-call
construction (verified above, not test-covered directly), this is strong but not airtight evidence —
a direct "two depths' keys are provably different values" test would close the remaining gap and is
worth adding if this area is touched again.


### Relationship to the entries around it

- **Bug 102** — same root cause, and this is the sharpest demonstration of it. Harm 2 here is Bug 102's
  consequence 3, reached without any restore. It also settles that entry's open design question
  empirically: *may a duress layer distribute?* It can today, and it distributes the real key.
- **Bug 94 remedy 1** refuses to overwrite an existing BEK during a restore, precisely so a stranger's
  material cannot strand the owner's trustees. This reaches the same end through distribution instead,
  which that remedy does not cover.
- **Bugs 100 and 101** supply the missing half of harm 1 — a copy of a real-layer `.occbak` that leaves
  the device.
- **Bugs 103 and 104** are the same omission at the view layer rather than the key layer: a depth
  dimension that exists in the data model and was not applied at the boundary being written.

### Remedy

**Short term, and independent of the refactor:** gate distribution on depth. The narrow form is to
refuse `prepareBEKShards` above depth 0 — but that is depth-conditional behaviour a coercer can
observe (the setup flow works in one layer and not another), which is the trap two fixes already fell
into this week. See Bug 93's follow-up and Bug 94 remedy 3.

The honest short-term options are therefore both unattractive, and the choice should be made
deliberately rather than by picking the smaller diff:

- **Refuse above depth 0** — closes the harm, adds an observable difference between layers.
- **Allow it, but distribute the layer's own key** — which requires the layer to *have* one, i.e. the
  refactor.

**Structurally:** `BEK_LAYERING_REFACTOR.md`. Once each layer holds its own BEK, distributing at a
duress depth distributes that layer's key to that layer's contacts, and the operation is correct
rather than merely permitted. That is the only version where the flow works identically in every layer
because it *is* the same flow, not a suppressed one.

### Guard

No test covers distribution at a non-zero depth. `Vault+ShardSetup.swift` has no depth-aware tests at
all, which is consistent with the code having no depth awareness to test.

## Bug 106 — The contact `LayerStore` has no cryptographic cross-depth isolation, the same gap Bug 92 names for the BEK

**Status:** **Closed — moot, 2026-09-10.** `Manager.LayerStore` and the entire blob mechanism this
entry is about were deleted whole (Removal Stage 2, `plan.md`) — Secure Mode no longer seals
sensitive contacts into any blob, so there is no `layerKey`, no shared-key cross-depth exposure, and
no slot to bind an AAD to. The severity question this entry left open (a confident High/Low rating
for the shared-key gap) is now moot rather than answered; nothing is asking it any more. Left below
verbatim as a historical record — including the *Partial fix* (`LayerStore.SlotAAD`), which was
deleted along with the rest of `SecureMode+LayerStore.swift`.

**Original status (superseded):** **Open for the headline issue (shared key, accepted tradeoff, not
being fixed); the separable AAD/slot-binding half is fixed, 2026-09-09 — see *Partial fix* below.**
Filed 2026-09-07, found while working through
`VAULT_KEY_LAYERING.md` item 7 (a duress-depth-detection risk in the new BEK slot array) and asking
why the *existing* contact `LayerStore` can safely reseal all 32 slots with fresh nonces on every
write without hitting the same problem. The answer — it has no per-depth key isolation to begin with
— is a real, previously unnamed consequence of an intentional design choice, not a newly introduced
defect. No reachability trace has been done yet; this entry records the structural fact, following
Bug 92's own precedent of separating "this is real" from "here is exactly what a coercer can do about
it today."

**Target:** unset. No fix proposed or decided. `VAULT_KEY_LAYERING.md` item 7 considers the analogous
trade-off for the BEK array and is itself open — this entry is supporting context for that decision,
not a request to resolve this one first. **A second reason to eventually fix this, found 2026-09-09:**
item 13 there proposes unifying `Manager.LayerStore`'s crypto/logic layer with `BEKArray`'s (both
already share the identical raw-I/O shape) — but only after this bug is fixed, since unifying first
would either dilute `BEKArray`'s AAD protection to match this store's absence of any, or require the
AAD fix to happen unreviewed, folded inside an unrelated refactor. Still no commitment to fix this on
any timeline — item 13 is itself unconfirmed — but it's now two independent reasons pointing at the
same missing AAD, not one.

### Severity: not yet rated — see *Why this isn't a confident "High" or "Low"* below

### What happens

`LayerStore.md`'s own "Cryptography" section documents `layerKey = HKDF-SHA256(IKM: seKey, info:
"layer-store-key")` — no depth or PIN input — and states plainly that "all 32 slots use the same
`layerKey`," calling this out as the property that *enables* full-array regeneration (the store can
trial-decrypt every slot and tell real payloads from padding by which ones authenticate). Confirmed
directly against `Key+Manager.swift:889-913`'s `deriveSecureModeKey()`: no `depth` or `pin` parameter
anywhere in the derivation. Every session, at every depth, computes the identical key.

So there is no cryptographic barrier that prevents a session at depth 2 from opening or resealing
depth 0's contact slot — the exact shape of gap Bug 92 names for the BEK (*"the vault key... opens
every slot... code discipline rather than cryptography"*), except here it was never framed as a gap at
all — `LayerStore.md` presents the shared key as a feature, because it is one, for the property it
was built to enable. The consequence just never got named as a corresponding cost until asked.

### Why this isn't a confident "High" or "Low"

**Not established: any concrete in-app path.** Unlike Bug 105 (traced to a specific, ordinary-UI-
reachable function with zero special access needed), no equivalent trace has been done here for
`LayerStore.pop()`/`push()`'s actual call sites — whether the app's own code ever calls either with an
explicit depth other than `currentDepth` is unconfirmed, not ruled out. `pop()`'s `slotIndexMismatch`
check happens *after* decryption, on the plaintext, matching Bug 92's own "code discipline, not
cryptography" framing — but code discipline having no known counterexample today is different from
having been verified to have none.

**Not established: what an offline/extracted-key scenario actually requires.** `layerKey` derives from
an SE-backed key gated `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (`Key+Manager.swift:936-941`) —
device-unlock state, not a per-use biometric prompt. Whether that access-control tier is meaningfully
weaker than the vault key's biometric gate, for this specific class of attacker, hasn't been assessed
here — Bug 92 went through exactly this kind of re-examination (rated High, then re-rated Medium once
the actual reachable path was traced) before its severity was trusted; this entry hasn't done that
work yet.

### Relationship to the entries around it

- **Bug 92** is the same underlying issue — a device-wide key with no depth input, protection resting
  on the app's own code discipline — for the BEK instead of contacts. Its "Re-examined" section is the
  template for how this entry's severity should eventually be settled: trace actual reachable call
  sites before rating, not from the structural fact alone.
- **`VAULT_KEY_LAYERING.md` item 7** is where this was found. That item is weighing whether the new BEK
  slot array should get item 4's cryptographic depth isolation (at the cost of the write-pattern leak
  item 7 describes) or accept the same posture `LayerStore` already has, live, in shipped code. This
  entry is what makes "accept the same posture" a documented, precedented choice rather than an
  unexamined one.

### Partial fix, 2026-09-09 — closes a narrower, separable gap this entry's own text raised but never
cleanly split out from the headline issue. **The headline issue — the shared `layerKey` itself, no
depth input, the same accepted tradeoff `VAULT_KEY_LAYERING.md` item 7 settled for the BEK array — is
unfixed and, per that precedent, not going to be fixed.** Full-array reseal needs one shared key to
resurface 31 slots it didn't write; that's still true here exactly as it is for BEK.

What this section already flagged, without naming it as its own gap: *"`pop()`'s `slotIndexMismatch`
check happens after decryption, on the plaintext... code discipline, not cryptography."* That's a
second, separable property from the shared key — whether a slot's ciphertext is bound to its own
position in the file at all, checked at the AEAD-authentication layer rather than by a caller
remembering to compare a decoded field afterward. `BEKArray` already has this, via `BEKSlotAAD`, kept
even after item 7 superseded the *other* half of item 4 (the live-slot key) — the two properties were
already separable there. `LayerStore` had neither.

**Fixed:** `LayerStore.SlotAAD` (nested in `SecureMode+LayerStore.swift`, private — same shape as
`BEKSlotAAD`, own domain string) binds every slot to its position. A slot opened without it falls back
to the pre-fix (no-AAD) scheme, so existing files keep reading; every slot gets re-sealed under the new
scheme on the very next `push()`/`pop()`, which already reseal all 32 slots unconditionally — no
separate migration pass needed. `LayerStoreSlotAADFixTests.swift` proves: a legacy slot still opens via
the fallback; popping a legacy file upgrades even the untouched filler slots, not just the popped one;
and a slot's ciphertext relocated to a different position (the actual attack this AAD stops) is now
discarded as fresh filler by the preserve path instead of being silently carried forward with the
wrong identity, which is what happened before — checked directly, not assumed, since the first version
of that test asserted the wrong resulting error type. **This closes the plaintext-only, "code
discipline, not cryptography" half named above; the shared-key half is the part Bug 92/item 7 already
decided is not being closed.**

### Guard

`LayerStoreSlotAADFixTests.swift` (2026-09-09) covers the AAD/migration fix above — legacy fallback,
migration-on-write, and slot relocation. **Still none for the headline issue**: no test asserts that a
session at one depth cannot open another depth's contact slot with the shared key, or documents that
no such test exists because the property isn't claimed — the same absence Bug 105's own Guard section
notes for BEK distribution, and the same accepted-tradeoff shape item 7 already documents there.

## Bug 107 — `Manager.LayerStore.push()`/`pop()` silently replace an unreadable slot with fresh
random filler, indistinguishable from a slot that was always empty

**Status:** **Closed — moot, 2026-09-10.** `Manager.LayerStore.push()`/`pop()` and the whole blob
mechanism were deleted (Removal Stage 2, `plan.md`) — there is no slot, no filler, and no
unreadable-slot-replacement path left to silently lose anything. The severity question this entry
left open (how often a slot actually becomes unreadable in practice) is moot rather than answered.
Left below verbatim as a historical record.

**Original status (superseded):** **Open, severity not fully assessed — mechanism confirmed,
likelihood not yet traced.**
Filed 2026-09-08, found while designing the new BEK slot array's own write algorithm and comparing it
against `Manager.LayerStore`'s existing pattern as precedent. A near-identical bug was caught and fixed
in the BEK design before any of that code was written (`VAULT_KEY_LAYERING.md` §8 item 8, third
finding) — checking the precedent it was modeled on afterward found the same conflation already live.

**Target:** unset. No fix proposed or decided.

### Severity: impact is high if triggered (silent, irreversible loss of real sensitive contact data);
likelihood — how often a slot actually becomes unreadable in practice — has not been traced. Rating
deliberately withheld rather than guessed, matching Bug 92's own precedent of re-examining reachability
before trusting a severity number.

### What happens

`decryptedPlaintexts(using:)` (`SecureMode+LayerStore.swift:333-345`), used by `push()` to preserve
every slot other than the one being newly written:

```swift
guard let box   = try? AES.GCM.SealedBox(combined: cipher),
      let plain = try? AES.GCM.open(box, using: key)
else { return nil }
```

Every slot in this store — real or filler — is sealed under the exact same `layerKey`
(`deriveKey(from:)`, no depth input, no per-slot AAD). Filler is genuinely-sealed random plaintext,
not a structurally-distinguishable "empty" marker — there is no separate decode-validity step the way
`BEKPayloadCodec` (the new design) has. That means `AES.GCM.open` succeeding is **not** conditional on
whether a slot holds real content; it should succeed for every slot this store has ever written,
period. A `nil` here can only mean the ciphertext failed to authenticate under the one key that opens
everything — disk corruption, a partial write, or a bug. It cannot mean "this slot was always empty."

`push()` doesn't draw that distinction. `nil` from `decryptedPlaintexts` and "this slot is genuinely
unused" are treated identically — `SecureMode+LayerStore.swift:187-192`:

```swift
} else if let plain = existing[i], let combined = try? AES.GCM.seal(plain, using: key).combined {
    file.append(combined)
} else {
    file.append(try self.sealRandom(using: key))   // ← real-but-unreadable and never-written land here alike
}
```

`pop()` has the identical shape inline (`:224-233`) rather than going through `decryptedPlaintexts`,
same conflation, same consequence.

### The harm

A slot that held a real, sensitive contact and became transiently unreadable — the concrete path being
a crash mid-write, since `AppGroupLayerStoreBackend.write()` (`SecureMode+LayerStoreBackend.swift:37-53`)
does not use `.atomic`, only `.completeFileProtection` (a Data Protection class, not a write-atomicity
guarantee) — gets silently overwritten with fresh random garbage on the very next `push()` or `pop()`.
No error, no signal, nothing recoverable. `push()`/`pop()` run on every Secure Mode activation and
deactivation, not a rare code path, and every one of the 32 slots is subject to this on every call, not
just the one actively being read or written.

### Relationship to `OPEN_LIMITATIONS.md` C1

C1 ("Decryption failure is not representable") names this exact failure shape — *"wrong-key ciphertext
... indistinguishable from an empty field ... the direct reason Bugs 75, 76, 77, 78 and 80 were silent
permanent data loss"* — but C1's own count is specifically `String.decrypt()`/`Data.decrypt()`'s `try?`
pattern across 88 call sites. `push()`/`pop()` call `AES.GCM.SealedBox`/`AES.GCM.open` directly, not
those functions — this is a separate, previously uncounted instance of the same underlying problem, not
one of the already-tracked 88.

### Proposed fix, 2026-09-08 — designed and reviewed against actual call sites, not yet applied

Simpler than first expected: `LayerStore` doesn't need BEK's two-way "open fails vs. decode fails"
split at all, since every slot here — real or padding — is sealed under the same key with no separate
structural-validity check. There is no legitimate case where `open` fails; it should succeed for every
slot this store has ever written, full stop. The fix is just: stop treating an open failure as if it
were one.

`decryptedPlaintexts(using:)` changes from returning `[Data?]` (silent `nil` per slot) to
`throws -> [Data]?` — `nil` only for "no existing file to preserve from" (a real, different, non-error
case), and a thrown `Error.decryptionFailed` for any individual slot that fails to open once the file
is confirmed present at the correct size:

```swift
private func decryptedPlaintexts(using key: SymmetricKey) throws -> [Data]? {
    guard let fileData = try? self.backend.read(),
          fileData.count == Self.slotCount * Self.slotCiphertextSize
    else { return nil }
    return try (0..<Self.slotCount).map { i in
        let offset = i * Self.slotCiphertextSize
        let cipher = fileData[offset..<(offset + Self.slotCiphertextSize)]
        guard let box = try? AES.GCM.SealedBox(combined: cipher),
              let plain = try? AES.GCM.open(box, using: key)
        else { throw Error.decryptionFailed }
        return plain
    }
}
```

`push()` propagates the throw and its per-slot loop drops the silent-filler fallback for a real
failure; `pop()` gets the identical treatment inline. Neither writes anything until the whole loop
succeeds, so a thrown error mid-loop leaves the on-disk file completely untouched — not a partial
write.

**Checked against real call sites before proposing this, not just made to compile:**
- `Manager+Security.swift:643` (activation, `push`) — already `try`, propagates normally.
- `Manager+Security.swift:884` (deactivation, `pop`) — already `do/catch` with an existing, sensible
  fallback ("blob corrupted... sensitive contacts unrecoverable, safe contacts intact"). Strictly
  better than today: a corrupt *other* slot currently gets silently destroyed with zero signal; with
  the fix, `pop()` throws into a path that already degrades gracefully instead of losing data quietly.

**Found while checking call sites — a real complication, not resolved:** `Manager+Security.swift:1720`,
`pushDummyBlobSlot`, writes a decoy `push()` right before throwing a PIN-collision error, specifically
so a collision produces the *same filesystem footprint as a real activation* — same anti-oracle family
as Bug 99. It calls `push()` with `try?`, deliberately swallowing errors, because the write's own
success has never mattered to that caller. But the fix changes what a swallowed failure now *means*: if
some unrelated slot happens to be corrupted exactly when a PIN collision fires, the fixed `push()`
throws before writing anything at all — the decoy write silently doesn't happen, and a collision would
leave a different, no-write footprint versus a real activation, which always writes. Today's bug
accidentally avoids this (it always writes *something*, even when it shouldn't). Not resolved: likely
needs a decoy-path variant of `push` that skips other-slot integrity checking entirely, since it never
needed to preserve anything real — genuinely separate design work, not a default to pick silently.

### Not yet done

No reachability trace of how often the underlying corruption actually fires in practice (matching the
discipline Bug 92 was held to before its severity was trusted). Fix designed and reviewed, not applied.
The `pushDummyBlobSlot` interaction above needs its own resolution before the fix ships.

### Guard

None yet. No test exercises a corrupted or unreadable slot during `push()`/`pop()` and asserts the real
content survives rather than being silently replaced.

## Bug 108 — Design B has no mechanism to persist a mid-session edit, once the DB row it would edit is
a dead shell

**Status:** **Closed — moot, 2026-09-10.** Design B (the four-named-steps content-shelling design
this entry is about) was never built and is not going to be: the whole blob/classification/rotation
machinery it would have extended — `Manager.LayerStore`, `inMemorySensitiveContacts`,
`resyncSensitiveContactsBlob()`, `ContactManager.restoreContact`/`hasUnreadableKeys` (the narrower
item-1/3 pair that *did* ship, 2026-09-10, and is described below) — was deleted in full (Removal
Stages 0-4, `plan.md`). Secure Mode now does UI-only depth filtering; there is no DB shell, no blob
snapshot, and so no mid-session-edit gap to have. `forensic-trace-avoidance.md §S5`'s Design
A/Design B discussion is updated separately to reflect the same decision. Left below verbatim as a
historical record of why the four-step design was rejected even before this removal, which is
itself part of why the removal happened.

**Original status (superseded):** **Not a live bug — Design A ships today for contact *content* (text
fields), and is unaffected; the four-named-steps Design B this bug is about (full text-field
shelling, `inMemorySensitiveContacts`, merged view) is still deferred, not built.** Filed 2026-09-09
as a design
gap, found before Design B is built rather than after, while checking whether `VAULT_KEY_LAYERING.md`'s
S8 could safely reuse Design B's four named steps as-is for vault entries. It couldn't, because the four
steps have this hole regardless of which content they're applied to. **The missing fifth step's
mechanism is built, same day — see *Not yet done* below — but not wired to anything, since the steps
that would populate `inMemorySensitiveContacts` (1, 3, 4) don't exist yet. Its co-requisite (a validated
non-destructive read for step 2) is built and tested too.**

**2026-09-10 — a narrower, related pair shipped: `plan.md`'s "What Design B requires" items 1 and 3
(key records only, not the four-named-steps content-shelling this bug is about).** Activation now
skips re-encrypting a sensitive contact's key records (left under the old key, genuinely unreadable
once deleted); deactivation's `restoreContact` rebuilds them from the blob. This closes the worse,
immediate-term risk this bug's own discovery flagged — item 1 without a rebuild would have caused
silent, permanent key-material loss on literally the first activation, before this bug's own
mid-session-edit gap ever mattered. That gap itself is **not fixed** by this change — a key rotation
received for a sensitive contact while the session is unlocked is still discarded, because the rebuild
only knows about the activation-time blob snapshot — now pinned as an explicit regression test
(`restoreContact_discardsMidSessionKeyRotation`, `SensitiveContactKeyRecordTests`,
`SecureModeActivationTests.swift`) so it stays visible rather than being fixed silently or
reappearing as a surprise later. Text-field shelling and the rest of Design B remain untouched.

**Target:** unset. Blocks Design B (`forensic-trace-avoidance.md` S5) and, downstream, S8
(`VAULT_KEY_LAYERING.md` item 12) — neither should be built against the four steps as currently
specified.

### Severity: would be High (silent, permanent loss of the user's own data) if Design B shipped with
only the four described steps; not yet triggerable, since nothing runs this path today

### What happens

Design B's four named steps (`forensic-trace-avoidance.md` S5, `plan.md`'s "Design B considered and
deferred"): (1) sensitive contacts' DB rows become unreadable shells at activation — fields
re-encrypted under the deleted old key; (2) `inMemorySensitiveContacts` loaded from the blob into
memory on normal unlock; (3) that array wiped on lock; (4) DB + in-memory merged for the contact list
view. None of the four says what happens to an edit made to a sensitive contact *between* steps 2 and
3 — while the session is unlocked and the in-memory array is the only thing holding it.

Checked directly against the actual code, not assumed: `Manager.LayerStore.push()` — the only function
that writes real content into the blob — has exactly two call sites in the whole codebase. Activation's
one-time snapshot (`Manager+Security.swift:643`), and `pushDummyBlobSlot`, an empty decoy write fired
on PIN collision (`Manager+Security.swift:1709-1720`) so a collision produces the same filesystem
footprint as a real activation. Neither fires in response to an edit. `rewrite()` (called at
deactivation and force-recovery) doesn't preserve content either — `writeNoOpFile()` overwrites all 32
slots with fresh random junk, a wipe, not a reseal of real content.

### The harm

Harmless under Design A, shipped today: the DB row stays the live, authoritative, editable copy for
the whole session, and the blob is just a periodic snapshot taken once per activation — its staleness
relative to later DB edits doesn't matter, because deactivation restores from the blob only to recover
what activation *hid*, not to recover edits made while active.

Once Design B ships, the DB row cannot hold anything readable from the moment of activation onward, so
an edit made mid-session exists only in the wiped-on-lock, killed-on-termination in-memory array. If
the app backgrounds ordinarily — not a deliberate, explicit lock action — or is killed by the OS or the
user before any (currently nonexistent) blob-resync step runs, the edit is lost permanently: no error,
no signal, no recovery path. The same silent, permanent-loss shape Bug 107 documents for corruption,
except triggered by ordinary use rather than corruption.

### Relationship to S8 (`VAULT_KEY_LAYERING.md`)

S8's release-owner decision (`VAULT_KEY_LAYERING.md`, "Vault entries and contacts (S5/S8)") has vault
entries reuse Design B's lifecycle "once built once on the cheaper case" — the same four steps, applied
to vault entries instead of contacts. Copying them as specified would copy this exact gap, and vault
entries are edited far more often than sensitive contacts (add/edit/delete vs. an occasional
classification change), so the exposure window is proportionally worse wherever it lands second.
Tracked as item 12 there.

### Not yet done

**Fifth step designed 2026-09-09 — `plan.md`'s "What Design B requires" list, item 5.** Reuses `push()`
itself: any mutation to `inMemorySensitiveContacts` resyncs the blob synchronously, before the caller
can treat the edit as saved, using the depth's already-on-record `slotIndex` and `sequenceNumber`
(`AppLayerConfig.readBlobSlot`/`readSequenceNumber`) rather than regenerating either. Checking that
directly against `pop()`'s validation caught a real trap: a fresh random sequence number per edit — the
naive version of "just push again" — would make the first edit-triggered resync silently break every
later `pop()` at deactivation with `sequenceNumberMismatch`, losing every edited contact. Same
full-array-reseal cost `Manager.LayerStore` already pays for classification changes today, not a new
category — contact edits are occasional, not the "constantly" frequency `VAULT_KEY_LAYERING.md` item 11
weighed for vault entries. Surfaced a co-requisite gap in step 2, not this bug's own scope: the only
non-destructive read, `readPayload(key:slotIndex:)`, was commented "for diagnostics and tests" only,
and — checked directly, not just its comment — ran neither of `pop()`'s integrity checks, so promoting
it as-is would have silently accepted a stale blob. **That co-requisite is now fixed** (2026-09-09):
`readPayload` takes a required `expectedSequenceNumber` and runs both `pop()` checks non-destructively;
`LayerStoreReadPayloadTests.swift` covers the round trip and both rejection paths.

**The step 5 mechanism itself is built, same day — `resyncSensitiveContactsBlob()` and
`inMemorySensitiveContacts`, `Manager+Security.swift`.** Added `SecurityError.blobMetadataMissing`
for the "no slot/sequence number on record" branches — the original design reused
`invalidStateTransition`, flagged as a poor fit (a state-machine error for a missing-metadata
condition) and fixed before writing this in. **Not wired to anything, and not independently
meaningfully testable yet:** `inMemorySensitiveContacts` is `private(set)` with no writer, since steps
1, 3, and 4 (which would shell the DB, load the array on unlock, and populate it from edits) don't
exist. Blocks Design B and, by extension, S8 (item 12) from being safely built as currently specified —
steps 1, 3, and 4 are what's left.

### Guard

None. Design B is not built, so nothing exercises this path yet — this entry exists so the fifth step
gets designed deliberately when Design B is implemented, rather than discovered as data loss after it
ships.

## Bug 109 — Skipping a sensitive contact's key-record re-encryption leaves an authentication-failure
tell, not silence

**Status:** **Closed — moot, 2026-09-10, same day it was filed.** This entry's own discovery — that
Design B's item 1 (activation skipping `reencryptKeyRecords` for a sensitive contact) trades a
content leak for a proof-of-concealment leak — became part of the argument for removing the
skip-and-rebuild mechanism (item 1/3) entirely rather than fixing it with the proposed remedy below.
Activation no longer touches `Contact.Profile`/`Contact.Profile.Key` fields at all (Removal Stages
0-4, `plan.md`) — no key-record skip, no Step 8, no `reencryptKeyRecords`, so no field that
authenticates differently from its neighbors. The proposed remedy (resealing as filler under the
current key) was never built; it's moot along with the mechanism it would have patched. Left below
verbatim as a historical record — including the severity analysis, which was part of the reasoning
that led to this removal in the first place.

**Original status (superseded):** Open. Live in shipped code (`Manager+Security.swift` Step 8,
commit `3b7baa9`, 2026-09-10) — `plan.md`'s Design B item 1. Found the same day, while defending that
change against a direct question about what an AFU-capable adversary — one who can derive the
current canonical key, which needs no biometric (see this feature's own key-derivation discussion) —
would actually observe, not discovered independently.

**Target:** unset.

### Severity: would be High under actual coercion — proves concealment occurred, which can be worse
than exposing the content it was meant to hide

### What happens

Item 1 has activation's Step 8 skip `reencryptKeyRecords` for a sensitive contact's `contactPublicKeys`,
deliberately, so those bytes stay sealed under the canonical key Step 11 deletes moments later. Text
fields (`reencryptAllFields`) are untouched by this skip and continue to be re-encrypted normally, same
as every other contact.

The result: a sensitive contact's row, examined under the *current* canonical key, decrypts almost
entirely — name, phone, notes, everything `reencryptAllFields` touches — except
`contactPublicKeys[*].material`/`owner`/`acquiredAt`/`quantumKeyMaterialEncrypted`, which fail
`AES.GCM.open` with `.authenticationFailure`, every time, for as long as that layer exists.

### The harm

Not a quiet gap — a loud, structural one. A forensic examiner does not need to suspect this specific
mechanism: attempting to decrypt every field of every row and noting where authentication fails is
routine practice, not a targeted attack. A row where the overwhelming majority of fields open cleanly
and one specific field category consistently, reproducibly does not is unambiguous evidence of
deliberate content removal — not corruption (corruption is rare and inconsistent across rows; this is
systematic, isolated to exactly the fields item 1 targets, and correlates with `visibleThroughDepth`
once combined with app-logic knowledge that's not even required to notice the pattern).

Compare to Design A's own accepted gap (`forensic-trace-avoidance.md` S5): Design A exposes a sensitive
contact's *content* to anyone holding the canonical key, but every field decrypts uniformly — nothing
about ciphertext shape reveals that concealment was attempted. Item 1, as shipped, trades a content
leak for a *proof-of-concealment* leak. Under coercion, "they can demonstrate I deliberately hid
something from them" invites exactly the follow-up pressure — what, from whom, why — that a deniability
mechanism exists to avoid. That can be a worse position than uniform exposure, not a strictly better
one, depending on what the coercer does with "I know you hid something" versus simply reading it.

### Proposed remedy — not built

Mirror `Manager.LayerStore`'s own established pattern for unused slots (`sealRandom`): a slot holding no
real content is never left unsealed or under a mismatched key — it's resealed with fresh random
plaintext under the *current* key, so it opens cleanly and only fails on content inspection, never on
authentication. Applied here:

- Activation's Step 8, for a sensitive contact's key records, would reseal `material`/`owner`/
  `acquiredAt`/`quantumKeyMaterialEncrypted` with random bytes under the **staged** (new,
  about-to-be-canonical) key, instead of leaving the old ciphertext untouched. Decrypts fine under the
  current key; decodes to nothing meaningful — no `AES.GCM.open` failure anywhere in the row.
- `ContactManager.restoreContact` would no longer need `hasUnreadableKeys` (a decrypt-and-check
  heuristic) at all — it is only ever called for contacts that came out of the blob, i.e. were
  classified sensitive during that same activation, so it can unconditionally rebuild
  `contactPublicKeys` from `record.draft.contactPublicKeys` on every call instead of conditionally.
- Cost: trades away "genuinely destroyed, not just hidden" for that field specifically — the content
  becomes real-key-recoverable if an adversary already captured the *old* key before its deletion (a
  different, prior-compromise scenario this design never protected against any differently — an
  AFU-capable adversary who compromises the device *before* a rotation gets everything live at that
  moment regardless). What it buys back is removing the authentication-failure tell: the field becomes
  indistinguishable, by shape, from any other key record, the same way `LayerStore`'s filler slots are
  indistinguishable from real ones without the key.

### Guard

None yet. `SensitiveContactKeyRecordTests` (`SecureModeActivationTests.swift`) asserts the key material
is left *unchanged* by activation — proving item 1 works exactly as specified, which is also exactly
the shape of this bug. A test for the remedy above would assert the opposite: after activation, a
sensitive contact's key-record material decrypts successfully under the current canonical key (no
`.authenticationFailure`) but decodes to something other than the original plaintext.

---

## Bug 110 — A vault entry's duress-depth stamp is never reset, so it can resurface in a later, unrelated duress session at the same depth number

**See `decisions.md`** (`Docs/General/`) for the short version of the orphan-in-place decision this
bug's fix establishes — later extended to `BackupEncryptionKey` (Bug 118) and considered, declined,
for `Contact.Profile` (Bug 112).

**Regression, 2026-09-24:** the fix shipped no migration for entries created before `deletionToken`
existed, so upgrading from v1.10.3 hid all of them. See Bug 133.

**Status:** Closed (Fixed), 2026-09-10. Filed the same day, found while updating
`forensic-trace-avoidance.md`'s S7 to describe the current (post-removal) behavior — not a
pre-existing entry being revisited, a fresh regression from Removal Stage 1. Fixed the same day, after
a design discussion — see *Fix* below.

**Target:** Fixed.

### Severity: Low — stale-state confusion, not a confidentiality leak

**What this is not:** content leaking to a more-trusted viewer than it was meant for. `VaultEntry`'s
exact-match depth design (`Vault+Model.swift:267`'s own doc comment, citing
`Docs/Bugs/v1.10.0/Vault-Entries-Created-At-A-Duress-Depth-Leak-Into-The-Real-Vault.md`) exists
specifically to stop a duress-created entry leaking *upward* into a less-restricted view — including
the real depth-0 vault. That protection is untouched by this bug. Everything below is about a
*different* direction: reappearing in a later view at the *same* restriction level, not a safer one.

### What happens

`VaultEntry.visibleThroughDepth` is stamped once, at creation, with whatever `currentDepth` is at
that moment (`Vault+Manager.swift:253`, `Vault+Manager+Backup.swift:280`) and compared by exact match
(`value == depth`, `Vault+Model.swift:267`). Nothing else ever writes it — confirmed by grep, exactly
two writers, both creation-time.

Duress depth *numbers* are reused across unrelated sessions: `deactivateSecureMode` always returns to
depth 0 or 1, and a fresh `activateSecureMode` → duress-PIN verification always walks back up through
1, 2, 3... the same way every time (`Manager+Security.swift`). Depth 1 is not tied to *which* duress
PIN produced it — it is simply "the first duress layer," and any new, unrelated duress PIN configured
after a full deactivate/reactivate cycle becomes depth 1 again.

Before Removal Stage 1, this was covered by two things working together: activation's old Step 8
re-stamped every vault entry on each activation, and deactivation's old Step 6 unconditionally reset
every entry's stamp to nil. Between them, a stale depth-N stamp from a past session could never
survive into a new one. Stage 1 removed both, per the Stage 0 design decision that activation/
deactivation touch no application data at all — and nothing replaced the reset. Concretely: create a
vault entry during duress session A (reaches depth 1) → deactivate → later configure an unrelated
duress session B (also reaches depth 1) → the entry from session A is visible again in session B,
because `entry.visibleThroughDepth == 1 == currentDepth` for both, with no way to tell the sessions
apart.

### Why this is Low, not High

Anything stamped at a duress depth was, by construction, already shown to whoever reached that depth
— it is not real-vault content. A stale duress-session entry resurfacing in a later duress session
exposes it to someone at the *same* restriction level it was already exposed to, not a safer or more-
trusted one. The worst case is confusing, unexpected old content appearing in a new coercion episode —
not the real user's protected data crossing into a view it was never meant to reach. `originDepth` on
`Contact.Profile` looks superficially similar (also a creation-time `currentDepth` stamp) but is not
the same class of bug: its floor semantics (`depth >= origin`) are a deliberate policy about depth
*severity levels*, meant to generalize across future duress sessions by design (see its own doc
comment) — not an accidental byproduct with no policy intent behind the specific number, which is
what makes `VaultEntry`'s case different.

### Fix

Rejected the first design considered (a sentinel value written into `visibleThroughDepth` itself,
e.g. `-1`, chosen so it could never exact-match a real depth): it would have conflated "which depth
this entry belongs to" with "is this entry still live," and — found only after tracing the actual
shard-custody call chain — a sentinel there does nothing for the shard side of this bug at all, since
`shardRecordsForTrustee` doesn't look at `visibleThroughDepth`.

**Shipped design:** a new `VaultEntry.deletionToken` field (`Vault+Model.swift`), initially mirroring
`Contact.Profile.deletionToken` exactly — encrypted, nil/non-nil meaningful at the query layer,
content a fixed sentinel when present — physically kept rather than hard-deleted (same reasoning
Bug 13 already established for contacts: a row count that drops in step with a duress-layer teardown
is itself a forensic signal), capped at 50 with oldest-first eviction. `visibleThroughDepth` is left
untouched — a historical record of the depth the entry was actually created at, now moot for every
functional purpose since exclusion makes it unreachable.

**Refined the same day, before this shipped to anyone:** nil/non-nil is itself a free,
zero-decryption signal — SQLite tracks column nullability structurally, independent of any
encryption applied to the value, so `SELECT COUNT(*) WHERE deletionToken IS NOT NULL` would still
answer "how many are orphaned" without the key. `deletionToken` is now **always populated** —
`VaultEntry.liveToken`/`orphanedToken` are two fixed-width, one-byte sentinels (`Data([0])`/
`Data([1])`) that encrypt to the same ciphertext length, the identical "no plaintext boolean flags"
principle `AppLayerConfig.pinEnabledPerDepth` already uses (Bug 51) — nothing about the sealed bytes
reveals which one is inside without decrypting. `VaultEntry.isOrphaned(usingKey:)` replaces every
`== nil`/`!= nil` check; it fails safe (nil, undecryptable, or an unrecognized value all count as
orphaned). Stamped live at creation by both `addEntry` and the backup-restore path, mirroring how
`visibleThroughDepth` is already stamped by its callers rather than defaulted in `init`. This raises
the bar from "zero-effort" to "requires knowing this app's schema convention and running one
decryption" — not a guarantee against an examiner already decrypting the database wholesale (who
gains nothing new to defend against here), but a real improvement against a quick, no-decryption
pass. `Contact.Profile.deletionToken` was deliberately left on the nil/non-nil pattern: it's shipped,
its migration cost is real (a production backfill, not a lightweight default), and
`PQmigration.swift`'s `migrateScrubDeletedDepthStamps` already uses its nil/non-nil status as a
readability oracle for stranded rows — changing it would mean redesigning that oracle, not just the
predicate, for the same marginal benefit this fix already delivers where it was cheap.

`VaultManager.fetchAllEntries()` — the single central read every consumer (shard custody, backup
export, the return buffer, the UI list) goes through — now fetches every row unconditionally and
filters on `isOrphaned(usingKey:)` in Swift, deriving the local-DB key once and reusing it across
every row. This is the one real structural cost of the refinement: the old `deletionToken == nil`
predicate pushed down to SQLite for free; decrypting a column can't be expressed as a SQL `WHERE`
clause, so filtering moved from the database to the app. Acceptable at the row counts a personal
vault realistically has. Caught in the same pass: `deleteAllEntries()` (panic wipe) was routing
through `fetchAllEntries()` too and would have silently stopped erasing orphaned rows — fixed to
fetch unfiltered, matching how `ContactManager.deleteAllContacts()` already hard-deletes soft-deleted
contacts during a wipe.

`Manager.Security.orphanVaultEntries(freedFrom:)` runs from both `deactivateSecureMode` and
`forceDeactivateForRecovery`, right where verifiers for the freed depth(s) are cleared — decodes each
entry's `visibleThroughDepth` once with a single derived key (not one Secure Enclave round trip per
row) and orphans anything `>= clearFrom`, the exact depth threshold the deactivation just freed.

**The shard-custody side resolves for free, no new machinery needed** — traced end to end, not
assumed: `ShardCustodyManager.buildExpectedShards` → `VaultManager.shardRecordsForTrustee` reads
through `fetchAllEntries()` (`Vault+Manager+Shards.swift:428`), so an orphaned entry's `ShardRecord`s
simply stop appearing in the `expectedShards` list sent in the next bundle to that trustee. The
trustee's own `processExpectedShards` (`ShardCustody+Manager.swift:322`) already deletes any
`CustodyShard` absent from that list — a real, physical deletion on the trustee's device, riding the
protocol's existing implicit-revoke mechanism (`SHARD_PROTOCOL_CASES.md`). The one honest caveat,
not new to this fix: revocation only fires the next time the owner sends that specific trustee
anything — the same eventual-consistency property `deleteEntry`'s existing hard-delete path already
has, since both ride the identical mechanism.

### Guard

Three tests in `VaultEntryOrphaningTests` (`SecureModeActivationTests.swift`), updated in place when
`deletionToken` moved to the always-populated scheme (same tests, assertions now go through
`isOrphaned(usingKey:)` instead of `== nil`/`!= nil`): `staleSessionEntryDoesNotResurface` (the core
regression — an entry from one duress session must not reappear in a later, unrelated session
reaching the same depth, and the row must survive physically, marked orphaned, not hard-deleted),
`shallowerEntrySurvivesCascade` (an entry at a shallower, still-live depth must be untouched by an
unrelated deeper cascade deactivation), and `orphanCapEvictsOldest` (51 entries orphaned in one call
caps at 50, with the single oldest hard-deleted — this test also caught a real ordering bug in the
first implementation pass, where `toOrphan` wasn't sorted before processing, so eviction inside a
single multi-entry batch wasn't reliably oldest-first).
Full suite: 0 failures, 6 skips (baseline), confirmed after the original fix and again after the
always-populated refinement.

---

## Bug 111 — `deactivateSecureMode` collapsed a cascade deactivation straight to depth 1 instead of popping one layer at a time

**Status:** Closed (Fixed), 2026-09-10. Found and fixed the same day, during a user conversation about
what `activateSecureMode`/`deactivateSecureMode` do post-removal — not related to Bug 110 or anything
found during the removal effort itself; this is a pre-existing state-machine defect that predates
Removal Stage 0 and was simply never exercised by a test deep enough to catch it.

**Target:** Fixed.

### Severity: felt wrong / broke the intended mental model — nested duress layers are meant to behave
as a stack (LIFO): activating pushes one layer at a time, so deactivating should pop one layer at a
time. It didn't.

### What happened

For any cascade deactivation (calling `deactivateSecureMode` from `currentDepth >= 2`), the function
unconditionally set `currentDepth = 1` regardless of how deep the stack actually was — confirmed via
`git log -S`, this exact behavior dates to the very first multi-layer commit (`22762fb`, 2026-06-03),
not a later regression. Deactivating from depth 3 (in a 0→1→2→3 stack) jumped straight to depth 1,
silently skipping past depth 2 as a landing state, even though depth 2's own verifiers were never
touched by the clear (`clearVerifiers(from: clearFrom)` already only removed the popped layer and
anything nested deeper — the verifier-clearing scope was already correctly LIFO, only the landing
depth wasn't).

**Why nothing caught it:** the only existing multi-layer test coverage
(`SecurityMultiLayerTests.deactivation_fromDepth2_goesToDepth1`) used exactly a 2-layer stack, where
`depth - 1 == 1` regardless — mathematically unable to distinguish "always land at depth 1" from a
genuine one-level LIFO pop. A 3-layer stack is the minimum needed to tell the two apart, and nothing
in the suite built one.

A second, coupled defect: `coercerBaseDepth` was unconditionally reset to `0` on every deactivation,
including cascades. Combined with `Settings.swift`'s `isAtSecureModeHomeDepth` gate
(`currentDepth == 0 || currentDepth == coercerBaseDepth`), this meant "Deactivate Protection" was
never visible immediately after any cascade pop — even in the pre-fix single-hop-to-depth-1 behavior,
landing at depth 1 left `state == .duress`, not `.normal` (confirmed directly: the pre-fix test
asserted this itself). The operator would have needed to leave and re-verify a PIN to regain the
button, rather than being able to pop a multi-layer stack down in one sitting.

### Fix

`Manager+Security.swift`'s `deactivateSecureMode`:
- `newDepth = max(0, depth - 1)` replaces the old `depth <= 1 ? 0 : 1` branch — lands exactly one
  depth shallower than the layer just removed, for every starting depth, not just a hardcoded floor.
- `coercerBaseDepth` is now written as `newDepth` (mirroring exactly how `activateSecureMode` already
  writes `coercerBaseDepth = depth` when creating a layer — Bug 58/61's own precedent) instead of
  unconditionally `0`. "Deactivate Protection" is now reachable at every intermediate depth
  immediately after each pop, letting a multi-layer stack be torn down one button-press at a time
  without a re-verify between steps.

Both changes are additive in scope for a 2-layer stack — `deactivation_fromDepth2_goesToDepth1`
(renamed `deactivation_fromDepth2_popsOneLevelToDepth1`) still lands at depth 1 for that case, only
its `state` assertion flipped from `.duress` to `.normal` to match the `coercerBaseDepth` fix.

### Guard

Two new tests in `SecurityMultiLayerTests` (`PINManagerTests.swift`), both requiring a 3-layer stack
to be meaningful: `deactivation_fromDepth3_popsOneLevelToDepth2` (a single pop lands at depth 2 exactly,
not depth 1; the un-popped depth-1 layer's own verifier is independently confirmed still
cold-start-routable) and `deactivation_threeLayerStack_popsOneLevelPerCall` (three sequential
deactivations, asserting `currentDepth`/`isSecureModeActive` after each one: 3→2→1→0). Full suite
green, 0 failures, 6 skips (baseline), confirmed after the fix.

---

## Bug 112 — `Contact.Profile.deletionToken`'s nil/non-nil status is a free, zero-decryption signal — scoped, deliberately not fixed

**Status:** Open, low severity, declined for now. Filed 2026-09-10, found immediately after Bug 110's
fix shipped for `VaultEntry.deletionToken` and the same question was asked of its sibling field on
`Contact.Profile`. Scoped in full before deciding; the scope is why this is declined rather than
fixed, not a severity judgment alone.

**Target:** unset — not planned.

### Severity: Low — same class of gap as Bug 110 before its fix, same reasoning for why it's low

SQLite tracks column nullability structurally, independent of any encryption applied to the value —
`SELECT COUNT(*) WHERE deletionToken IS NOT NULL` answers "how many contacts are soft-deleted" with no
key at all. Exactly the gap Bug 110 closed for `VaultEntry.deletionToken` by making that field always
non-nil, content carrying the meaning instead of presence. Low for the same reason Bug 110 was: this
raises the bar for a quick, no-decryption pass, not a guarantee against an examiner already decrypting
the database wholesale, who gains nothing new here either way.

### Why it's declined, not just deferred — the real scope, checked before deciding

**The blocking finding: SwiftUI's `@Query` cannot decrypt-and-filter.** `Contact.Profile.descriptor` —
the fetch descriptor carrying `deletionToken == nil` — is consumed via `@Query` in **18 sites across 14
files**: every contact list (v1/v2/v3), contact detail screens, group forms, the vault tab's contact
lookup, key exchange, the share recipient picker, both Secure Mode flows. `@Query`'s predicate must be
translatable straight to SQL by SwiftData; there is no way to express "and this AES-GCM blob decrypts
to sentinel X" in a `#Predicate`. Making `deletionToken` always non-nil breaks every one of those 18
sites' ability to exclude soft-deleted contacts *at the query level* — each would need re-architecting
to fetch unfiltered and filter reactively elsewhere (a view-model layer deriving the key and decrypting
per row on every render, or a maintained published "visible contacts" cache). That is not a predicate
swap; it is a different architecture for the Contacts UI's primary rendering path.

**Beyond the UI, the service/migration layer alone would be a wider version of `VaultEntry`'s fix, same
shape:** `Contact+Manager.swift` (`fetchAllContacts`, `deleteContact`'s write, `fetchSoftDeletedContacts`
driving the existing 50-row cap, one more lookup), `ContactManager+Classification.swift` (four
`identifier == X && deletionToken == nil` lookups), `Manager+Security.swift`'s
`purgeDraftsNotSafeAtCurrentDepth`.

**`PQmigration.swift` adds a third kind of complexity beyond either of those — an actual oracle, not
just a filter.** Three backfills (`migrateSafeContactVisibilityBackfill`, `migrateGlobalTrusteeDepthBackfill`,
`migrateOriginDepthBackfill`) each gate on `someField == nil && deletionToken == nil` (Bug 97) so a
backfill never stamps a fresh value under the current key onto a row whose other fields are
deliberately left under a stale one. `migrateDepthFieldsToFixedWidth` excludes soft-deleted rows the
same way, for the same reason. `migrateScrubDeletedDepthStamps` is the real oracle: it fetches only
`deletionToken != nil` rows, then uses `deletionToken?.decrypt() == Data([1])` itself to distinguish
"deleted and still readable under the current key" from "deleted but stranded by a since-superseded key
rotation," feeding a per-field repair decision. Worth naming precisely: since Removal Stages 0-6 deleted
key rotation entirely, a contact soft-deleted from now on can never become stranded — that branch is
permanently historical, relevant only to rows already stranded by a rotation that happened before this
removal shipped. The oracle's *logic* doesn't need to change, only its entry predicate — but losing the
SQL-level `!= nil` filter means fetching every contact just to find the (now permanently non-growing)
deleted population, on every launch, forever, for something that used to be free. A dedicated test
suite, `DeletedDepthStampScrubTests.swift`, is built entirely around this oracle and would need
updating in step with it.

**Unlike `VaultEntry.deletionToken`, this field is shipped.** Changing its semantics needs a real
migration — backfill every existing nil row to encrypted-`0`, re-stamp every existing non-nil row to
encrypted-`1` — not a lightweight default on an unreleased field.

### Conclusion

The service/migration layer cost alone would be proportionate to the benefit — the same trade Bug 110
made for `VaultEntry`. The `@Query` architecture problem is not: it is a different, larger project (a
new data-fetching pattern for the Contacts UI generally) with its own design questions, not a follow-on
to this bug. Declined for now on that basis. If the Contacts UI's `@Query` pattern is ever revisited for
an unrelated reason, this fix becomes cheap to fold in at the same time — tracked here so that
opportunity isn't missed.

### Guard

None — not fixed.

## Bug 113 — The vault entry list reads a raw `@Query`, not `VaultManager.fetchAllEntries()` — the depth-0 duress leak and Bug 110's orphan filter both bypass the UI

**Status:** Closed (Fixed), verified 2026-09-10. Filed 2026-09-10, found while verifying that
vault entries are depth-aware end-to-end, prompted by re-checking whether the exact-depth-match fix
(`Docs/Bugs/v1.10.0/Vault-Entries-Created-At-A-Duress-Depth-Leak-Into-The-Real-Vault.md`) and Bug 110's
orphaning both actually reach the screen. Neither did, for the same root cause.

**Target:** `v1.11.0/vault-key-layering`.

### Severity: Medium

Two independent harms, from one cause. Neither exposes new plaintext to a coercer beyond what a
correctly-filtered screen would already withhold from the *other* depth — the damage is a UI showing
content it has no business showing at the depth it's showing it at, not a new decryption path.

### The cause

[Vault+Tab.swift:215-218](Occulta/UI/Tabs/Vault/Vault+Tab.swift:215):

```swift
private var visibleEntries: [VaultEntry] {
    guard self.security.isRestricted else { return self.entries }
    return self.entries.filter { self.security.isEntryVisible($0) }
}
```

`self.entries` ([Vault+Tab.swift:81](Occulta/UI/Tabs/Vault/Vault+Tab.swift:81)) is a plain
`@Query(sort: \VaultEntry.createdAt, order: .reverse)` straight on `VaultEntry` — every row in the
table, unfiltered by SwiftData itself. `visibleEntries` is the only place that narrows it, and it is
the sole source for the list, the count text, and the attention section
(`Occulta/UI/Tabs/Vault/Vault+Tab.swift:221-225`). Nothing else in the file touches orphan status or
depth.

### Harm 1 — the depth-0 duress leak this branch believed was already fixed

`isRestricted` is `currentDepth > 0`. At depth 0 the guard's `else` branch never runs, so
`isEntryVisible` — the function `Fix vault entries leaking into the real view with a one-line change,
not a new schema` (`2392653`) corrected to an exact match — is never called at all. An entry stamped
`visibleThroughDepth == 2` is returned by `visibleEntries` at depth 0 exactly as it was before that
fix.

**Confirmed by git history, not assumed:**
- `git log -L 210,220:Occulta/UI/Tabs/Vault/Vault+Tab.swift` shows the guard was introduced in `5f20dac`
  ("[step3] Complete Step 3: depth stamping, share index, grace period, file protection"), May 21 2026 —
  three months before the exact-match fix.
- `git show --stat 2392653` — the exact-match fix — touched only `Manager+Security.swift`,
  `Vault+Model.swift`, the bug doc, and `VaultTests.swift`. `Vault+Tab.swift` is absent from that list.
  The guard was never revisited.
- The fix's own regression test,
  `isEntryVisible_stampedDepthN_onlyVisibleAtN_hiddenElsewhere` (`VaultTests.swift:349-363`), asserts
  `security.isEntryVisible(entry)` directly at depth 0 and correctly gets `false` — proving the
  *function* is right. It never calls `visibleEntries`, the property that actually gates the screen, so
  it cannot see that the screen bypasses the function it's testing.

Net effect: an entry created at a duress depth — willingly, by rehearsal, or under live coercion — is
not confined to that depth. It resurfaces in the real depth-0 list, indistinguishable from anything
created intentionally, with only a `createdAt` timestamp as a passive tell — the exact risk
`Vault-Entries-Created-At-A-Duress-Depth-Leak-Into-The-Real-Vault.md` describes, reopened at the one
call site its fix never reached.

### Harm 2 — Bug 110's orphan filter never reaches the screen

`VaultManager.fetchAllEntries()` ([Vault+Manager.swift:314-321](Occulta/Features/Vault/Vault+Manager.swift:314))
derives the vault key once and filters out every `isOrphaned(usingKey:)` row — the mechanism this
branch built specifically so an orphaned entry is "genuinely inert everywhere at once, not just hidden
from the list" (that function's own doc comment, lines 310-313). Checked by grep across
`Occulta/Features/Vault/`: `Vault+Manager+ReturnBuffer.swift`, `Vault+Manager+Backup.swift`, and
`Vault+Manager+Shards.swift` all call it and inherit the filter correctly. `Vault+Tab.swift` is not on
that list — its `@Query` reads `VaultEntry` directly, so `fetchAllEntries()`'s doc comment claiming "the
UI list" is one of its consumers is itself wrong, not just the code.

Concretely: `Manager.Security.orphanVaultEntries` runs on Secure Mode deactivation
(`Manager+Security.swift:461,509`) to retire entries at a depth being freed — Bug 110/111's entire
point. Those rows are not hard-deleted, by design, for the deletion-count cover Bug 110 exists to
provide. But because `Vault+Tab.swift` never checks `isOrphaned`, a just-orphaned entry keeps appearing
in the list at whatever depth is current, fully readable, until something else removes the row —
undoing the "inert" half of Bug 110's fix at the only place a person actually looks.

**Not the same path as user-initiated deletion.** `VaultManager.deleteEntry(id:)`
(`Vault+Manager.swift:405`) calls `modelContext.delete(entry)` — a real hard delete — so a swipe-deleted
entry disappears correctly, via SwiftData's own change notification, without touching this bug. This
entry is specifically about rows `orphanVaultEntries` retires, not ordinary deletion.

### Why this wasn't caught earlier

Both regressions are invisible to the existing test suites because both suites test the correct
function in isolation (`isEntryVisible`, `isOrphaned(usingKey:)`) rather than the SwiftUI computed
property that actually decides what renders. `Vault+Tab.swift` has no test coverage of `visibleEntries`
itself — confirmed by grep, no test file references it. This is the same class of gap this branch's own
work has hit before: a unit-tested primitive with no test proving its one production call site
actually uses it.

### Fix

Replaced `Manager.Security.isEntryVisible(_:)` with `visibleVaultEntries(from: [VaultEntry])`
(`Manager+Security.swift`), which folds both harms into one call over an already-fetched array —
`Vault+Tab.swift`'s `@Query` results:

```swift
func visibleVaultEntries(from entries: [VaultEntry]) -> [VaultEntry] {
    guard let key = try? Manager.Key().createHybridLocalEncryptionKey() else { return [] }
    let depth = self.currentDepth
    return entries.filter {
        !$0.isOrphaned(usingKey: key) &&
        $0.isVisible(atDepth: depth, whenUnclassified: depth == 0, usingKey: key)
    }
}
```

`Vault+Tab.swift`'s `visibleEntries` is now a one-line call to this, at every depth — no
`isRestricted` shortcut. Two design points worth recording:

- **`whenUnclassified: depth == 0`, not a constant.** A legacy nil-`visibleThroughDepth` entry
  (pre-dating the field) is a real, persistent state — not swept away by anything (confirmed by grep
  and by `PQmigration.migrateDepthFieldsToFixedWidth`'s own doc comment, "a legitimate steady state").
  It must stay visible at the real depth 0 (matching ordinary pre-feature usage) and hidden at every
  duress depth. A single fixed value for `whenUnclassified` cannot get both right — `true` leaks a
  real entry into duress; `false` hides legacy entries from their own owner.
- **Key derived once, reused across every row** — matching `fetchAllEntries()`/`entriesVisible(atDepth:)`'s
  existing pattern, not the ambient per-row `.decrypt()` that would re-derive it once per entry per
  SwiftUI render.

The doc comments this bug's investigation showed were stale — the "Step 8 stamps every nil entry"
claim in `Vault+Model.swift` and the old `isEntryVisible` — have been corrected in place, and
`Docs/Bugs/v1.10.3/Backup-Export-Silently-Drops-Legacy-Nil-Depth-Vault-Entries.md` has been marked
partially superseded. See Bug 114 for the related, still-open finding: `entriesVisible(atDepth:)`
(backup export) has the same unconditional `whenUnclassified: true`, at whatever depth its caller is
at, including a duress depth — not fixed here, scoped separately.

### Guard

`VaultEntryDepthVisibilityTests` (`VaultTests.swift`) rewritten to call `visibleVaultEntries(from:)`
directly instead of the deleted `isEntryVisible(_:)` — this is what closes the actual gap this bug
was about: the old tests exercised a correct function that the real UI call site never invoked. Two
new cases added: `visibleVaultEntries_excludesOrphanedEntries` (an orphaned entry stays hidden even
at the depth its untouched `visibleThroughDepth` still names) and
`visibleVaultEntries_legacyNilVisibleThroughDepth_visibleAtRealDepth0` (the new depth-0 nil-entry
case this fix adds, mirroring the pre-existing hidden-at-restricted-depth case). Full local suite
run on a host with Secure Enclave access, per `CLAUDE.md`'s Testing Gate: 842 passed, 0 failed, 6
skipped (`KeychainMigrationSETests`, the one expected device-only skip), 849 total — clean.

## Bug 114 — A legacy nil-`visibleThroughDepth` `VaultEntry` is swept into a backup exported from a duress depth

**Status:** Closed (Fixed), verified 2026-09-10. Found while checking whether Bug 113's fix for
the display path had a counterpart on the export path. Filed and fixed the same day.

**Target:** `v1.11.0/vault-key-layering`.

### Severity: High

Real vault content — by construction, since a nil-stamped entry can only be one that predates duress
depths existing on the device at all — ends up inside a `.occbak` file sealed under a duress depth's
own backup key. Unlike Bug 113 (a UI display glitch, self-correcting once you're looking at the right
depth), this produces a durable artifact: a file a coercer who controls that depth's backup key
custody can decrypt and read, containing content the owner never intended to expose at that layer.

### What happens

`VaultManager.entriesVisible(atDepth:)` ([Vault+Manager+Backup.swift:207](Occulta/Features/Vault/Vault+Manager+Backup.swift:207)):

```swift
private func entriesVisible(atDepth depth: Int) throws -> [VaultEntry] {
    guard let key = try Manager.Key().createHybridLocalEncryptionKey() else {
        throw VaultError.keyDerivationFailed
    }
    return try self.fetchAllEntries().filter {
        $0.isVisible(atDepth: depth, whenUnclassified: true, usingKey: key)
    }
}
```

`whenUnclassified: true` is unconditional — it does not vary with `depth`. Its one caller,
`exportBackup(currentDepth:)` ([Vault+Manager+Backup.swift:130](Occulta/Features/Vault/Vault+Manager+Backup.swift:130)),
passes whatever depth it's called with straight through: `let entries = try self.entriesVisible(atDepth: currentDepth)`
at line 148, with `currentDepth` supplied by the caller — there is no depth-0-only gate anywhere in
this path. So a legacy nil entry is included in the export at *every* depth, duress ones included.

### Why `whenUnclassified: true` was believed safe here, and why that no longer holds

This exact question was investigated once already, thoroughly, in
`Docs/Bugs/v1.10.3/Backup-Export-Silently-Drops-Legacy-Nil-Depth-Vault-Entries.md`. Its answer,
verified correct *at the time*: a nil entry cannot exist at an active duress depth, because
`activateSecureMode`'s Step 8 unconditionally re-stamped every entry — nil ones included — to a
hidden sentinel before that depth became reachable, backed by an `assert` and a dedicated regression
test, `activation_nilDepthVaultEntry_getsStampedHidden`.

**Both are gone.** `ef9c1f4` ("Removal Stage 1: shrink activate/deactivateSecureMode to PIN-only"),
on this same branch, deleted `activateSecureMode`'s entire re-encryption/stamping sweep — Step 8
included — along with its `assert` and that regression test, as part of retiring the old blob-based
activation design. Confirmed three ways:

- `grep -rn "stamps every\|stamp every" Occulta/Features/SecureMode/ Occulta/Features/Vault/` finds
  nothing — no code anywhere stamps an existing nil entry to a concrete depth.
- The current `activateSecureMode` ([Manager+Security.swift:337-414](Occulta/Features/SecureMode/Manager+Security.swift:337))
  read in full: PIN verification and verifier-slot writes only. No loop over `VaultEntry`, no
  `assert`, no reference to `visibleThroughDepth`.
- `grep -n "activation_nilDepthVaultEntry_getsStampedHidden" OccultaTests/SecureMode/SecureModeActivationTests.swift`
  — no match. That file was fully rewritten by this branch's own "Removal Stage 4" commit (`15404b1`).

**Confirmed the opposite is now explicitly true, not just unenforced.** `PQmigration.swift`'s own doc
comment on `migrateDepthFieldsToFixedWidth` (line 192): *"For `VaultEntry` nil is a legitimate steady
state rather than a gap... inventing a value there would change what the user sees."* Nil is not an
unlikely edge case that happens to be unreachable today — it's a documented, permanent population
this codebase deliberately never touches. Combined with Removal Stage 1 deleting the only thing that
ever moved a nil entry out of a duress depth's reach, the population this bug affects is real,
persists indefinitely, and is now reachable at any depth.

### Relationship to Bug 113

Same underlying cause — the Removal effort deleted machinery an unrelated function's safety argument
depended on, without that function or its doc comments being revisited. Bug 113's fix
(`Manager.Security.visibleVaultEntries(from:)`) already handled this correctly for the display path
by conditioning on `depth == 0`; this entry applies the identical fix to the export path.

### Fix

One-line change to `entriesVisible(atDepth:)` ([Vault+Manager+Backup.swift:210](Occulta/Features/Vault/Vault+Manager+Backup.swift:210)):
`whenUnclassified: true` → `whenUnclassified: depth == 0`. Both of its callers benefit with no fork
needed — `exportBackup(currentDepth:)` (the `.occbak` builder) and `refreshBackupStaleness(currentDepth:)`
(which was, as a side effect, counting a legacy entry toward a duress depth's "current" entry count
even though — pre-fix — it could never actually have been exported there; the fix also resolves that
inconsistency for free). `Vault+Model.swift`'s shared doc comment on `isVisible(atDepth:whenUnclassified:)`
updated to describe both callers now agreeing on `depth == 0`, rather than the two-different-answers
framing that was accurate before this fix.

### Guard

Two new tests in `VaultBackupRoundTripTests.swift`, mirroring `exportExcludesHiddenEntries`'s existing
full export→wipe→import round-trip pattern: `exportExcludesLegacyNilDepthEntryAtDuressDepth` (a legacy
nil-depth entry is not present after a round trip through an export taken at depth 2) and
`exportIncludesLegacyNilDepthEntryAtRealDepth0` (the same entry survives a round trip through an
export taken at depth 0 — the behavior this fix must not regress, and the original subject of
`Docs/Bugs/v1.10.3/Backup-Export-Silently-Drops-Legacy-Nil-Depth-Vault-Entries.md`).

Constructing the legacy entry surfaced a real test-harness trap, worth recording since it could bite
again: mutating the `VaultEntry` object `VaultManager.addEntry` returns, in place, without saving
through `VaultManager`'s own `ModelContext`, leaves that context's identity map holding a "dirty"
tracked instance. A later external wipe (a separate `ModelContext` on the same container, the
established pattern in this file for resetting state before import) deletes and saves the row at the
persistent-store level, but `VaultManager`'s own context — used internally by `importBackup`'s
`fetchEntry(by:)` dedup check — can still resolve the stale in-memory instance for that id, so the
check reads "already exists" and silently skips re-importing it. Nothing to do with depth filtering;
pure test-setup hazard, caught by adding a diagnostic `isVisible`/`isOrphaned` check and a byte-count
check on the exported file, both of which showed the export side was already correct while the
round-tripped count still came back wrong. Fixed by adding `makeLegacyEntry(via:in:)`, which mutates
and saves through its own freshly-opened `ModelContext`, matching the `wipe` context's own pattern,
so `VaultManager`'s context never carries an unsaved edit into the dedup check.

Full local suite run on a host with Secure Enclave access: 844 passed, 0 failed, 6 skipped
(`KeychainMigrationSETests` only), 851 total — clean, and consistent with Bug 113's own verified run.

## Bug 115 — `VaultShardHealth` reads a raw, unfiltered `@Query` and renders decrypted entry labels from every depth

**Status:** Closed (Fixed), verified 2026-09-11. **Moot since 2026-09-27:** `VaultShardHealth` was deleted
with per-entry splitting (`Docs/General/decisions.md`, "Retire per-entry splitting"). Filed and fixed the same day, found while
answering "what's left to complete the vault entry refactor" — checked every remaining
`@Query`/`FetchDescriptor<VaultEntry>` site in the UI against the pattern Bug 113 fixed for
`Vault+Tab.swift`, since that fix was scoped to one file and never claimed to be exhaustive.

### Severity: High — worse than Bug 113, not just the same class

Bug 113 leaked *visibility* (an entry showing up when it shouldn't). This leaks *content*: the actual,
decrypted entry label — the thing a seed phrase or password's own descriptive name would be — rendered
directly on screen for entries at every depth, real and duress alike, and for orphaned entries too.

### What happens

[VaultShardHealth.swift:18](Occulta/UI/Tabs/Settings/VaultShardHealth.swift:18):

```swift
@Query private var entries: [VaultEntry]
```

No predicate, no depth check, no orphan check — every row in the table, exactly the pattern
`Vault+Tab.swift` had before Bug 113. `Manager.Security` is imported (`VaultShardHealth.swift:17`) but
never referenced anywhere in the file — the depth-awareness the import implies was never wired in.

```swift
private var entriesWithShards: [VaultEntry] {
    entries.filter { $0.shardDistributionEncrypted != nil }
}

private var decoded: [(entry: VaultEntry, meta: ShardDistributionMetadata, label: String, type: VaultEntryType)] {
    guard vault.isUnlocked else { return [] }
    return entriesWithShards.compactMap { entry in
        guard let meta = try? vault.shardDistributionMetadata(for: entry.id) else { return nil }
        let payload = try? vault.decryptLabelPayload(for: entry)
        return (entry, meta, payload?.label ?? "–", payload?.type ?? .note)
    }
}
```

`decryptLabelPayload` is called unconditionally for every entry that has shard distribution set up —
at any depth, orphaned or not — and the resulting plaintext `label` is carried straight into the
row model. `healthSection`'s `ForEach(decoded, id: \.entry.id) { entry, meta, label, type in ... }`
(`VaultShardHealth.swift:147`) renders it.

**Reachable from any depth.** Settings → Vault Recovery → Shard Health, `NavigationLink`-accessible
from `VaultRecoverySettings.swift`'s `pekSummaryRow` (see Bug 116) at any depth, real or duress — the
screen itself has no depth gate of its own to prevent navigating to it in the first place.

### Two harms, mirroring Bug 113's two but with label content instead of just presence

1. **A coercer at a duress depth sees the real depth-0 vault's entry labels** — not just that entries
   exist (Bug 113's harm), but what they're called: "Recovery seed," "Bank PIN," whatever descriptive
   name the owner gave it, for any depth-0 entry that has shards set up.
2. **The real owner, back at depth 0, sees duress-depth decoy entries' labels too** — and orphaned
   entries' labels (Bug 110's entire point was making an orphaned entry inert everywhere; this screen
   doesn't check `isOrphaned` at all, so a decommissioned entry's label still renders here indefinitely).

### Why this wasn't caught by Bug 113's fix

Bug 113 fixed `Vault+Tab.swift`'s `visibleEntries` specifically — the file the bug was filed against.
It never claimed to audit every other `VaultEntry` consumer in the UI. This file has its own,
independent `@Query`, never routed through the fix. Confirmed by grep: no test file references
`VaultShardHealth`'s `entries`/`decoded`/`entriesWithShards` properties at all — zero test coverage of
this screen's filtering, the same "unit-tested primitive, untested call site" gap Bug 113 named.

### Fix

One-line change to `entriesWithShards`, the single upstream property everything else in the file
derives from ([VaultShardHealth.swift:22-25](Occulta/UI/Tabs/Settings/VaultShardHealth.swift:22)):

```swift
private var entriesWithShards: [VaultEntry] {
    self.security.visibleVaultEntries(from: self.entries).filter { $0.shardDistributionEncrypted != nil }
}
```

Routes through `Manager.Security.visibleVaultEntries(from:)` — the same function Bug 113 introduced —
before the shard-distribution filter runs. `decoded`, `atRiskCount`, `atRiskBanner`, and `healthSection`
all consume `entriesWithShards`, so every downstream computation and every rendered row is now
depth-and-orphan-correct with the one change. `self.security` (`Manager.Security`) was already an
`@Environment` property on this view — imported, per the bug's own write-up, but never used until now.

### Guard

No new test written: `visibleVaultEntries(from:)` itself is already fully covered by
`VaultEntryDepthVisibilityTests` (Bug 113) — exact-depth match, orphan exclusion, the depth-0
nil-entry case — and this fix introduces no new logic, only a new caller of that same, already-tested
function. Neither this file nor `Vault+Tab.swift` has its own test suite (no SwiftUI view in this
codebase does; view-level logic delegates to tested `Manager`/`VaultManager` functions, confirmed by
grep — consistent architecture, not a gap specific to this fix). Full local suite run, combined with
Bug 116's fix: 844 passed, 0 failed, 6 skipped (`KeychainMigrationSETests` only), 851 total — clean.

## Bug 116 — `VaultRecoverySettings`'s PEK summary reads `recoveryHealth.affected` unfiltered, leaking a cross-depth count

**Status:** Closed (Fixed), verified 2026-09-11. **Moot since 2026-09-27:** the PEK summary and
`recoveryHealth` were deleted with per-entry splitting (`Docs/General/decisions.md`, "Retire per-entry splitting"). Filed and fixed the same day, found alongside
Bug 115.

### Severity: Medium — a count leak, not a content leak

No entry labels are shown here, only aggregate numbers ("3 entries critical," "1 entry degraded"), but
those numbers are computed across every depth's entries, not just the current one.

### What happens

[VaultRecoverySettings.swift:108](Occulta/UI/Tabs/Settings/VaultRecoverySettings.swift:108):

```swift
private var pekSummaryRow: some View {
    let affected = vault.recoveryHealth?.affected ?? []
    let critical = affected.filter { $0.status == .critical }.count
    let degraded = affected.filter { $0.status == .degraded }.count
    ...
}
```

`vault.recoveryHealth` is computed by `VaultManager.recomputeRecoveryHealth()`
(`Vault+Manager+Shards.swift:341`), which reads `fetchAllEntries()` — orphan-filtered, but not
depth-filtered — and builds `affected: [RecoveryHealthSummary.AffectedEntry]` (which does carry each
entry's decrypted `label`, per its own struct) across every depth at once. `Vault+Tab.swift` reads this
same published property but filters it first: `(self.vault.recoveryHealth?.affected ?? []).filter {
visibleIDs.contains($0.entryID) }` (`Vault+Tab.swift:223`). `VaultRecoverySettings.swift` does not —
the count badge on this screen aggregates every depth's critical/degraded entries into one number,
displayed at whichever depth the viewer is currently at.

**Not a label leak in this file** — `pekSummaryRow` only reads `.status` to build counts, never
`.label`. But `VaultRecoverySettings.swift`'s own `NavigationLink` from this row goes to
`VaultShardHealth()` (Bug 115), so the practical path from "the count looks off" to "the actual labels
are visible" is one tap, not a separate vulnerability chain to build.

### Fix

Added the same `@Query`/filter pair `Vault+Tab.swift` already carries, then applied it to
`pekSummaryRow` ([VaultRecoverySettings.swift](Occulta/UI/Tabs/Settings/VaultRecoverySettings.swift)):

```swift
@Query private var entries: [VaultEntry]

private var visibleEntryIDs: Set<UUID> {
    Set(self.security.visibleVaultEntries(from: self.entries).map(\.id))
}
```

```swift
private var pekSummaryRow: some View {
    let affected = (vault.recoveryHealth?.affected ?? []).filter { self.visibleEntryIDs.contains($0.entryID) }
    ...
}
```

This view had no `@Query` on `VaultEntry` before — `SwiftData` added as an import. Deliberately local to
this view rather than a new shared helper on `Manager.Security`: `Vault+Tab.swift` already computes its
own `visibleIDs` the same inline way, so this matches the existing pattern rather than introducing a
second one.

### Guard

Same reasoning as Bug 115's Guard: no new logic, only a new caller of the already-tested
`visibleVaultEntries(from:)`; neither this view nor `Vault+Tab.swift` carries its own test suite. Full
local suite run, combined with Bug 115's fix: 844 passed, 0 failed, 6 skipped
(`KeychainMigrationSETests` only), 851 total — clean.

## Bug 117 — `deleteContact`'s 50-row eviction has no defined order, and `Contact.Profile` has no field that could give it one

**Status:** Open, not fixed. Filed 2026-09-11, found while explaining the 50-row soft-delete/orphan
cap's eviction logic and being asked to verify "oldest evicted first" actually holds for both
`Contact.Profile` and `VaultEntry`.

### Severity: Low — a correctness/intent gap, not a leak

The 50-cap itself is a practical bound on unbounded dead-row growth, not a security mechanism (see
the "why cap it, and why 50" discussion this entry's investigation grew out of — no evidence the
number or the policy was derived from a threat calculation). Evicting the *wrong* soft-deleted row
doesn't expose anything a correctly-chosen eviction wouldn't: both the evicted row and every row that
stays are already soft-deleted, already excluded from every functional read, already indistinguishable
from live rows without the key. Unlike Bugs 113-116, nothing here crosses a depth boundary or reveals
content. Filed because the code's own shape (mirrored from `VaultEntry`, which *does* implement
oldest-first correctly) implies a guarantee that doesn't actually hold for contacts, and because fixing
it properly needs a model decision, not just a one-line patch.

### What happens

[Contact+Manager.swift:524-529](Occulta/Services/Contact+Manager.swift:524), `fetchSoftDeletedContacts`:

```swift
private func fetchSoftDeletedContacts() throws -> [Contact.Profile] {
    let predicate = #Predicate<Contact.Profile> { $0.deletionToken != nil }
    let descriptor = FetchDescriptor<Contact.Profile>(predicate: predicate)
    return try self.modelContext.fetch(descriptor)
}
```

No `sortBy` at all. [Contact+Manager.swift:467-470](Occulta/Services/Contact+Manager.swift:467),
`deleteContact`, evicts whichever row this unordered fetch happens to return first:

```swift
let softDeleted = try self.fetchSoftDeletedContacts()
if softDeleted.count >= 50, let victim = softDeleted.first {
    self.modelContext.delete(victim)
}
```

`.first` on an unordered `FetchDescriptor` is whatever SwiftData/SQLite's query planner happens to
return for a plain predicate scan — in practice, likely rowid/insertion order for a table that's
never reordered, but that's implementation behavior, not a documented guarantee, and nothing in this
code asserts or depends on it deliberately.

**Contrast: `VaultEntry`'s equivalent (`Manager+Security.swift:562-563`, `orphanVaultEntries`) sorts
explicitly before evicting:**

```swift
alreadyOrphaned.sort { $0.createdAt < $1.createdAt }
toOrphan.sort { $0.createdAt < $1.createdAt }
```

Bug 110's own doc comment states the vault-entry cap "mirrors `Contact.Profile.deletionToken`'s own
cap" — but only the *cap number* was carried over. The oldest-first *ordering* that comment implies
was never actually present on the contacts side to mirror, or existed and was dropped; either way, the
two implementations have diverged silently.

**Worth being precise about even on the `VaultEntry` side, since "oldest first" undersells what's
actually being sorted: `createdAt` is when the entry was originally created, not when it was
orphaned.** There is no separate "orphaned-at" timestamp — `orphanVaultEntries` has nothing else to
sort by, so creation date stands in as a proxy for "how long has this been orphaned." The two usually
track closely in practice (orphaning only happens on deactivation, and an entry can't be orphaned
before it's created), but they're not the same thing, and an entry created long ago but orphaned only
recently would be evicted ahead of one created recently but orphaned earlier — the reverse of what
"evict whichever has been dead longest" would actually mean. `VaultEntry` is still strictly better off
than `Contact.Profile` here (it has *a* defined, deliberate order; contacts have none), but neither
implementation evicts by true orphaned-duration, and no field exists to make that possible without the
same new-field, does-it-leak-timing tradeoff named above for contacts.

### Why this can't be fixed with just a `sortBy`

Checked directly: `Contact.Profile` (`Contact+Model.swift`) has **no creation-date field at all** — no
`createdAt`, `addedDate`, or equivalent, confirmed by grep across the model. `VaultEntry.createdAt`
exists and is what `orphanVaultEntries` sorts on. Even a correctly-written `sortBy` on
`fetchSoftDeletedContacts()` would have nothing meaningful to sort *by* — adding real "oldest first"
behavior needs a new field on the model, not a query fix.

**That new field is its own design question, not a free addition.** It would need the same scrutiny
this session already gave `deletionToken` itself when asked whether it should carry a timestamp: a
literal creation-date field, even sealed, is a new place for timing information to live, and this
codebase has repeatedly chosen not to add exactly that kind of field elsewhere for that reason (see
the `deletionToken`-has-no-date discussion this bug grew out of). Whether "oldest first" is worth that
cost for a mechanism whose own stakes are already low (see Severity above) is the actual open question
here — not resolved by this filing.

### Two remedies, neither chosen

1. **Add a creation-date-equivalent field to `Contact.Profile`**, sealed under the same key discipline
   the rest of the model uses, enabling genuine oldest-first eviction — brings contacts to parity with
   `VaultEntry`, at the cost of a new field and a migration for existing rows.
2. **Leave eviction order unspecified, but say so** — drop the implied "oldest first" framing (the
   `VaultEntry` mirror comment, and this function's own resemblance to that one) and document
   `deleteContact`'s eviction as "evicts an arbitrary soft-deleted row when the cap is reached," matching
   what the code actually does today. Cheapest fix, but a real behavior downgrade from what a reader
   would currently assume this does.

### Guard

None — not fixed. No test currently asserts eviction order for `deleteContact` at all (unlike
`VaultEntry`'s orphaning, which per Bug 110's own write-up caught a real ordering bug in an earlier
draft via a dedicated test) — worth adding regardless of which remedy above is chosen, so the actual
behavior (ordered or not) is pinned down and visible rather than implied by resemblance to a sibling
function.

---

## Bug 118 — `deactivateSecureMode` never orphans the freed depth's BEK, so a later, unrelated duress session inherits the old session's backup key and trustee list

**Status:** Closed (Fixed), verified 2026-09-11. Filed and fixed the same day, found while scoping the
BEK-storage-off-the-array refactor (`VAULT_KEY_LAYERING.md`) — this is the exact BEK-side analog of Bug
110, one container over, and closing it is what motivated moving BEK storage onto `BackupEncryptionKey`
SwiftData rows rather than being a separate follow-on patch. Full suite: 841 passed, 0 failed, 6 skips
(`KeychainMigrationSETests` baseline only), 847 total.

### Severity: Medium — stale-state confusion with a real trustee-facing consequence, not a confidentiality leak

**What this is not:** content leaking to a more-trusted viewer than it was meant for. A depth's BEK,
like its vault entries, was always visible to whoever reached that depth in the session that created
it. This bug is about the *same* restriction level inheriting a *different, unrelated* session's key
and trustee list — not a safer view gaining access to a more-restricted one.

**Why this is worse than Bug 110's own severity, not just the same shape.** Bug 110's stale entry is
inert content — confusing, but nothing acts on it. A stale BEK is live key material with a live
consequence: `backupSetupState`/`currentBackupKey` for the reused depth report "already configured,"
`shardMetadata` lists the *previous* session's trustees as this session's own, and `exportBackup` at
that depth would seal new content under a key whose distributed shares are held by people the current
session's owner never chose and may not know about.

### What happens

Before this fix, `deactivateSecureMode` and `forceDeactivateForRecovery` (`Manager+Security.swift`)
cleared verifiers and called `orphanVaultEntries(freedFrom:)` for the freed depth(s), but never touched
that depth's `BackupEncryptionKey` row at all — confirmed by reading both functions' full bodies, not
assumed from the vault-entry precedent. Depth *numbers* are reused across unrelated future duress
sessions, exactly as Bug 110 found for vault entries: `deactivateSecureMode` always returns to depth 0
or 1, and a fresh `activateSecureMode` → duress-PIN verification walks back up through 1, 2, 3... the
same way every time. Concretely: set up backup at duress depth 1 during session A (real trustees, real
key) → deactivate → later configure an unrelated duress PIN, also reaching depth 1 in session B — session
B's `backupSetupState(currentDepth: 1)` reports the depth already configured, `currentBackupKey`
returns session A's key unchanged, and `backupShardMetadata` lists session A's trustees as though the
new session's owner had chosen them.

### Fix

Folded into the BEK-storage refactor rather than patched as a standalone fix, since the refactor moved
BEK storage onto the same `deletionToken`-orphaning shape `VaultEntry` already uses (Bug 110) — the
mechanism this bug needed already existed one container over, just not wired to a BEK-aware version of
it.

**`BackupEncryptionKey` gained the same three-state shape `VaultEntry` has:** `depth`/`deletionToken`
fields (sealed under the local DB key, not the vault key — forced, since orphaning has to run from
`deactivateSecureMode`/`forceDeactivateForRecovery`, neither of which derives the vault key),
`liveToken`/`orphanedToken` fixed-width one-byte sentinels mirroring `VaultEntry.liveToken`/
`orphanedToken` exactly, `isOrphaned(usingKey:)` failing safe the same direction. One row per claimed
depth, drawn from a 32-row filler baseline eagerly created at first launch (see
`VAULT_KEY_LAYERING.md` for the full storage-migration design this bug's fix rode in on) — uncapped
beyond 32, since BEK rows are only ever created by an explicit "set up backup at this depth" action,
not everyday use, so the 50-row cap-and-evict shape `VaultEntry`/`Contact.Profile` use for their much
higher-frequency writes wasn't judged necessary here.

**`Manager.Security.orphanBackupKeys(freedFrom:)`** (`Manager+Security.swift`), added right after
`orphanVaultEntries` in both `deactivateSecureMode` and `forceDeactivateForRecovery`, inside the same
`autosaveEnabled = false` window and committed by the same trailing `save()` — mirrors
`orphanVaultEntries(freedFrom:)`'s own shape exactly: fetch every `BackupEncryptionKey` row, decrypt
each `depth` with the local key, skip anything already orphaned or still filler, mark every live match
`>= clearFrom` as orphaned. No cap, no eviction, matching the row-creation-frequency reasoning above.

### Guard

`BackupKeyOrphaningTests` (`BackupEncryptionKeyStorageTests.swift`), mirroring `VaultEntryOrphaningTests`
one container over: `staleSessionBackupKeyDoesNotResurface` (the core regression — a BEK set up in one
duress session must not resurface in a later, unrelated session reaching the same depth; the row must
survive physically, marked orphaned, not deleted; a fresh `setupBackup` in the new session must produce
a genuinely different key, not read the old one back), `shallowerBackupKeySurvivesCascade` (a BEK at a
shallower, still-live depth must be untouched by an unrelated deeper cascade deactivation — exact same
key, not a fresh one), and `updateShardStatusIgnoresOrphanedRow` (a shard-confirmation call targeting an
orphaned row's own `attributeID` must be a silent no-op — the row's `encryptedPayload` byte-for-byte
unchanged — since the row is excluded from the live-row scan `updateShardStatus` searches). All three
pass; full suite re-run clean after (841/0/6/847).

---

## Bug 119 — The vault key's access control is device-level, not Occulta-level — AFU forensic extraction (Cellebrite/GrayKey-class) derives it via code execution alone, no coercion needed, and one key opens every depth

**Status:** Open. Filed 2026-09-11, during a design conversation about whether replacing the 6-digit
duress PIN with a longer passphrase would close Bug 62's open gaps. It doesn't, on its own — but
tracing *why* led to the actual key-derivation code, which confirmed a gap this codebase already has a
proposed remedy for, filed against a future release and not yet cross-referenced from anywhere a
reader chasing Bug 62 would find it: **[`PASSPHRASE_LAYER_KEYS.md`](PASSPHRASE_LAYER_KEYS.md)**
(`Occulta/Features/SecureMode/`, proposed 2026-09-10). This entry exists to make that connection
findable, record today's confirmation against the current shipped code, and note that the design
doc's own sequencing precondition has now landed.

### Severity: High — forensic-extraction exposure, not a coercion-scenario bug

Distinct from almost everything else in this file: every other duress/depth bug assumes an attacker
using the app normally, through its own UI, with or without a compliant owner. This one assumes an
attacker who has gotten code execution on the device (the realistic AFU — After First Unlock —
capability class Cellebrite/GrayKey-style tooling targets) and asks: does Occulta's own app-level PIN,
duress-PIN, or depth logic stand between that attacker and the vault key at all? Traced directly
against shipped code rather than assumed — it does not.

### What happens, confirmed directly against `Occulta/Services/Key+Manager.swift`

[`createVaultSEKey()`](Occulta/Services/Key+Manager.swift:641) sets the vault SE key's access control
to `[.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode]` — the **device's own** Face
ID/Touch ID or iOS system passcode. [`deriveVaultKey(context:)`](Occulta/Services/Key+Manager.swift:707)
computes `HKDF(ikm: ECDH-shared-secret, salt: vaultPublicKeyBytes, info: kVaultKeyInfo)` — no Occulta
PIN, duress PIN, or passphrase is an input anywhere in that derivation. Occulta's own depth/duress
logic never participates in the SE's actual release decision; it's app-level routing sitting entirely
on top of a key the SE will hand to *any* caller who satisfies the *device's* authentication, because
that's the only condition the access control actually encodes.

**Practical consequence:** once a device is in AFU state (its system passcode has been entered once
since boot — compelled from the owner, or reached via an exploit that doesn't trigger the
erase-after-10-attempts limit), a code-execution exploit can call the identical Keychain/SE API
Occulta itself uses, with a validly-authenticated `LAContext`, and receive the same vault key —
regardless of which depth, if any, Occulta's own app believes is active, because that belief was never
part of the key's release condition.

**And it is one key for every depth, confirmed against `VAULT_KEY_LAYERING.md` §4:** *"vault entries
carry individual depth stamps, the key they are sealed under does not."* A single successful
extraction yields the one shared vault key, and every depth's rows — real and every duress layer
alike — are still physically present (`visibleThroughDepth`/`deletionToken` is UI filtering, not
cryptographic separation, per Bugs 110-118) and decrypt under it. The duress/depth system was built to
survive a coercer using the app normally; it was never designed to resist code-execution-class
extraction, and nothing in its design claims otherwise — this entry is naming that boundary
explicitly, not reporting a regression.

### The proposed remedy already exists — `PASSPHRASE_LAYER_KEYS.md`

Filed 2026-09-10, one day before this entry, from what its own header describes as the same
conversation thread ("the 'how does the second attacker get the key' and 'is it impossible if we pair
ECDH with diceware' exchanges that motivated this doc"). Core mechanism: `layerKey_D = HKDF(ikm:
Argon2id/PBKDF2(passphrase_D) ‖ ECDH(depth_D_SE_privkey, G), ...)` — a human-only secret that never
touches the device, combined with the existing per-device SE binding. Extraction alone yields half an
input, not a usable key.

**That document's §2 already found, independently, the exact structural problem this entry's own
design conversation re-derived from scratch:** making each depth's content genuinely
cryptographically distinct (not just UI-filtered) means a row belonging to depth 2, decrypted with
depth 1's key, must fail *silently* rather than with a loud authentication error — otherwise the mere
existence of an auth failure is itself the tell Bug 109 already named for a sibling mechanism. Its
proposed fix is `Manager.LayerStore`'s own retired filler-slot pattern, generalized: every row seals
cleanly under every depth's key, real content under the depths it belongs to, random filler
everywhere else. This is flagged there as the actual complexity cost of the whole proposal — "not the
simple version of Design B" — and remains the open, unresolved design question blocking it, not
anything raised fresh today.

**What today's conversation adds, not already in that document:**

- **Grounded §0's "why now" framing against the literal current code**, rather than describing the
  gap abstractly — the `Key+Manager.swift` citations above are new; the document's own text describes
  the mechanism without line-level citations.
- **The sequencing precondition has landed.** §5 states this work "depends on the current
  removal-stages plan (`plan.md`) landing first." Removal Stages 0-4 shipped 2026-09-10 (confirmed
  repeatedly this session — `Manager.LayerStore`, the staged-key protocol, and `RotationRegistry` are
  all gone). The blocker named in that document's own sequencing section no longer holds; §2's open
  structural question is the next real design work, per that section's own words, and nothing is
  waiting on this session's own BEK/vault-entry refactor either — the two are independent.
- **A concrete example of what §2's "every consumer needs re-auditing" cost actually touches:**
  `VaultManager.Backup.updateShardStatus` (`Vault+Manager+Backup.swift:1407`) loops over every depth's
  BEK row searching for a matching `attributeID`, using the one shared vault key, because today one
  key opens all of them. Under per-depth keys it has nothing to decrypt other depths' rows *with* — it
  would need to stop being a decrypt-and-check scan and route by something self-identifying instead
  (the shard's own `distributionID`, already noted as available in Bug 102's own remedy text before
  its reclassification). This is one concrete instance of the "real, nontrivial" cost §2 names in the
  abstract; there are likely others among the vault-key domain's other consumers, not yet enumerated.
- **Cross-reference to Bug 62.** That entry's Gap 2 (no design exists for a rate limit that survives a
  compliant-victim relock cycle without becoming its own forensic tell) and its residual-risk section
  (accidental master-PIN collision, bounded by PIN-space size) are both closed as a side effect if
  `PASSPHRASE_LAYER_KEYS.md` ships with genuinely high-entropy, non-user-editable phrases — a 7-word
  Diceware phrase (~90.5 bits against the EFF large wordlist) makes both exhaustive brute force and
  the targeted, human-plausible guessing Gap 2 actually worries about equally infeasible. Not a reason
  to build this instead of fixing Gap 2 directly — a reason the two should be decided together rather
  than Bug 62 acquiring its own separate rate-limit design that this proposal would make moot.
  **Re-examined 2026-09-11: Gap 3's trigger mechanism closes the same way.** `masterPINCollision`
  only exists because today's routing scans a small array of stored verifiers, comparing a new
  candidate against existing ones — that comparison is what turns a rare accidental match into a
  detectable, nameable event. Canary-based per-depth authentication at ~90 bits doesn't need that
  setup-time check at all (accidental collision odds go from 1-in-10⁶ to ~1-in-2⁹⁰), so there's no
  error to throw and no oracle to build a wipe response around. **Gap 3's own "deeper structural
  problem" is not closed by this, and can't be by any secret-format change** — it was never a
  guessing-difficulty question. Once the real depth-0 secret is known to be in a coercer's hands (via
  direct compulsion, not probing), the app still has no way to tell that apart from the real owner's
  own legitimate entry, and the Bug 13 hard-delete conflict Gap 3 names is unaffected by whether the
  secret was 6 digits or 7 words.
- **§4's PBKDF2-vs-Argon2id tradeoff is lower-stakes than it reads, not resolved.** At ~90 bits of
  input entropy (7 words), even PBKDF2's weaker resistance to parallel/GPU attack leaves brute force
  well outside feasibility — the KDF choice stops being what stands between an attacker and the phrase.
  It still matters for defense-in-depth against a future entropy-reducing mistake (a shorter phrase, a
  user-edited one), so this doesn't remove the decision, just lowers what's riding on it.

### Absorbs Bug 92's on-device half, 2026-09-24

Per-depth backup keys (`BackupEncryptionKey` rows) are sealed under the same vault key as everything
else, so this entry's extraction also yields every depth's backup key, and with it any real `.occbak`
the attacker finds. Bug 92 carried that case separately; it is folded in here, because the fix is the
same: `PASSPHRASE_LAYER_KEYS.md`'s per-layer keys, sealing the real layer's backup key under the real
layer's key. Bug 92 stays open for the exported file itself (an opt-in export passphrase).

One thing the backup file adds beyond the entries in the database: it lives off the device (iCloud,
Files, AirDrop) and can hold entries later deleted from the phone. And the backup key is deliberately
reused across trustee changes (`decisions.md`, "Reuse the same BEK across trustee-set changes"), so a
key extracted once opens that depth's earlier and later exports until it is rotated. Rotation has no
UX or caller yet: Bug 121.

### Absorbs Bug 123, 2026-09-26

The small local-key fields (`VaultEntry.visibleThroughDepth`/`.deletionToken`, `BackupEncryptionKey.depth`/
`.deletionToken`, `Contact.Profile`'s three depth fields, `PendingShamirSecretRestore.attributeID`/
`.deletionToken`) all seal with one fixed AAD, so their ciphertext can be moved between rows. That only
matters to an attacker who can write the store but can't use the local key, and on an unlocked phone
anyone who can write the store can use it (no prompt on that key). So it is folded in here: **when this
entry's remedy re-seals these fields under layer keys, the same migration must bind each to its row and
field** (an AAD built from the row's `id` and a field tag, as `VaultEntry.aad(for:)` already does for the
content fields). Recorded as a requirement in `PASSPHRASE_LAYER_KEYS.md` §2.

### Threat review, 2026-09-29

Sizing the remedy against a state-level attacker added four requirements to `PASSPHRASE_LAYER_KEYS.md`:
- **§1:** as drafted, the SE half is a constant (`ECDH(SE_priv, G)`), so AFU extracts it once and guessing
  moves off-device. The stretched phrase has to go into the SE operation, so every guess needs this phone's SE.
- **§3:** every depth's phrase is the same length, and phrases are app-generated, not editable. Shorter duress
  phrases can be cracked offline, and the one that survives is the real one.
- **§4:** 7 words with PBKDF2, or 6 words with Argon2id. 6 words with PBKDF2 falls within years to
  SHA-256 hardware on the scale of the Bitcoin network.
- **§4:** entry must not go through the ordinary keyboard. The keyboard's learned-words cache is a forensic
  artifact that would hold the phrase and show that something is hidden.

This also records how exposed the current PIN is: `deriveSecureModeKey()` is a constant under AFU, so the
6-digit verifiers fall in under a second and reveal how many depths exist, whatever the lockout says.

### Guard

None — not built. Tracked as `PASSPHRASE_LAYER_KEYS.md`'s own §2, unresolved. This entry's job is
findability (a reader starting from Bug 62 or from this file's Cellebrite/AFU-adjacent entries has no
path to the document that already designed the fix) and confirmation against current code, not new
design work.

---

## Bug 120 — Modifying one depth's stored data never touches a sibling depth's bytes, so write frequency across snapshots reveals which depth is used most — likely identifying the real one

**Status:** Open. Filed 2026-09-12, found while designing `RECOVERY_BUFFER_LAYERING.md` Stage 4's
shard-buffer cap and generalizing the question to the rest of the app's per-depth storage.

**Target:** None — cross-cutting, affects every per-depth container currently shipped, not a single
release's scope.

### Severity: Medium (forensic — reveals which depth is real, not vault contents)

Exposes no content. Answers a narrower but still load-bearing question: given two or more on-disk
snapshots taken over time, with no key at all, which depth is used the most? Ordinary daily use happens
overwhelmingly more often at the real depth than at any duress depth, which exists only for the rare
coercion window — so the depth showing the most write activity across snapshots is very likely the real
one, independent of whether any content is ever actually decrypted.

### What happens, confirmed directly against current code, 2026-09-12

Checked every per-depth-keyed object currently shipped:

- `BackupEncryptionKey` rows — `Backup.persist`/`seal` write only the one row being claimed or updated
  (`Vault+Manager+Backup.swift`).
- `AppLayerConfig.sealedNormalVerifiers`/`.sealedDuressVerifiers` — `writeNormalVerifier`/
  `writeDuressVerifier` assign exactly one array index (`AppLayerConfig+Model.swift:138,146`).
- `AppLayerConfig.pinEnabledPerDepth` — same shape, one-index assignment
  (`AppLayerConfig+Model.swift:281`).
- `VaultEntry.visibleThroughDepth`/`.deletionToken` — per-row field assignment
  (`Vault+Manager.swift:259,262`).
- `Contact.Profile`'s depth fields (`visibleThroughDepth`/`originDepth`/`globalTrusteeDepth`/
  `deletionToken`) — per-row field assignment (`Contact+Manager.swift:194-201`).
- `CustodyShard`, `ReconstructShard`, `PendingShardDistribute` rows — same per-row shape.

In every one of these, writing depth N's data leaves every other depth's stored bytes byte-for-byte
identical to before. Exactly one thing currently shipped does the opposite: `backup-export-meta.dat`
(`ExportMetaSlotCodec`/`writeBackupExportMetadata`, `Vault+Manager+Backup.swift:930`) loads all 32 slots'
plaintext, updates one, re-encodes all 32 into one buffer, and seals that whole buffer under one fresh
nonce — every byte of the output changes on every write, regardless of which slot's plaintext actually
moved. That is the only currently-live precedent for closing this; everything else leaks.

### Why this is not the same thing as row-count camouflage

Bug 110/118's fixed-filler-baseline work (and this session's shard-buffer design) defends against "how
many rows exist" being informative — an examiner with a single snapshot can't tell real content from
padding. This is a different axis: **which** row or slot changes across **multiple** snapshots taken over
time. Row-count camouflage says nothing about it — a fully padded row set can still show exactly one
entry's ciphertext changing between two captures, which is enough to mark that entry, and by extension
whichever depth it belongs to, as "active," with no decryption needed at all.

### This was an accepted, narrow trade-off for BEK specifically — it is not narrow once generalized

`VAULT_KEY_LAYERING.md` item 7 (superseded by item 14) explicitly accepted losing "which slot changed"
undiffability when BEK moved off its old full-reseal array onto rows, reasoning that the realistic
threat — physical re-imaging of the same device at two points in custody, given the array was already
backup-excluded — was narrow enough to accept. That reasoning was scoped to BEK alone. It was never
re-examined against every *other* per-depth object in the app also lacking this property, or against the
specific, high-value signal of "which depth is used more often" as opposed to "was any write made at all
to this one field." Generalized across every per-depth container in the app, and weighted by how starkly
real-depth activity outpaces duress-depth activity in ordinary use, this is a considerably stronger signal
than the narrow one item 7 weighed.

### Cross-reference

Also flagged in [`PASSPHRASE_LAYER_KEYS.md`](PASSPHRASE_LAYER_KEYS.md) §2, 2026-09-12 — that document's
proposed per-depth-key storage mechanism ("structurally close to what the blob array already did for
contacts") would need to deliberately re-adopt the old array's full-reseal behavior to avoid inheriting
this leak, and currently doesn't specify that it does.

### Guard

None — not built, and not yet designed. Whoever picks this up needs to decide, for each affected
container, either: (a) reseal every sibling slot/row on every write (the old array's actual mechanism, at
whatever storage-churn cost that implies — worse for containers written to often, like the shard buffer,
than for ones written rarely, like BEK), or (b) some other mechanism that hides write-frequency-by-depth
without paying that cost everywhere. Not resolved by anything currently in this file or in either design
document.

---

## Bug 121 — Backup key rotation has no UX, and no caller at all — `Backup.rotate()` is unreachable dead code

**Status:** Open. Filed 2026-09-12, found while explaining what rotating a BEK actually looks like to a
user and confirming directly against code that nothing calls it.

**Partly overtaken, 2026-09-26:** Bug 141's decision generates a new backup key whenever a trustee is removed,
so that path reaches a key change with its own confirmation and re-export prompt. A deliberate "rotate now"
without changing trustees is still missing.

**Target:** v2.0.0 — not urgent for the current release. Nothing depends on rotation existing today;
`decisions.md`'s "reuse the same BEK across trustee-set changes" entry treats rotation as the rare,
deliberate escape hatch, not something routine use ever needs.

### Severity: Low (missing feature, not a security regression)

Nothing is less safe because of this — `Backup.rotate()` being unreachable doesn't expose anything or
weaken any existing guarantee. It means the one deliberate mechanism this design's own reasoning relies on
("a genuine rotation is the only path that invalidates old backups, and it's explicit") doesn't actually
work: a user who concludes a share may have leaked and wants to kill the old key has no way to do it.

### What's missing, confirmed directly against code

- `Backup.rotate(vaultKey:currentDepth:modelContext:)` (`Vault+Manager+Backup.swift:1367`) exists and is
  presumably correct, but has zero callers anywhere — confirmed by grep across `Occulta/` and
  `OccultaTests/`: no `VaultManager` wrapper (unlike `setupBackup`/`prepareBackupShards`/`currentBackupKey`,
  which all have one), no UI button or flow, not even a direct unit test.
- The only UI surface touching rotation at all is reactive, not a trigger: `VaultRecoverySettings.swift:160`
  shows a "BEK rotated" staleness warning when `backupStaleness.bekRotated` is true, comparing the
  `distributionID` recorded at the last export against the current one. That reports a rotation that
  already happened by some other means; nothing in the app is that means.

### Remedy

Add a `VaultManager` wrapper mirroring `setupBackup`'s shape (derive `vaultKey`, call through to
`self.backup.rotate`), then a UI entry point calling it — most naturally in `VaultRecoverySettings` next to
the staleness warning it currently only reports on. Needs its own confirmation UX too: rotating
deliberately invalidates every existing `.occbak` (per `decisions.md`'s entry), so the user needs to
understand that cost before triggering it, the same way `storePendingRestore`'s `.alreadyProcessed`
refusal already treats an irreversible state change as something to confirm rather than fire silently.

### Guard

None — not built.

---

## Bug 122 — A cap on `PendingShamirSecretRestore` would let a coercer count how many restores are live, without any key

**Status:** Closed, 2026-09-13 — resolved by deciding never to cap this container at all, rather than by
fixing the cap. Filed the same day, while sizing a cap for `RECOVERY_BUFFER_LAYERING.md` §6 item 9.3's
`PendingShamirSecretRestore` model. **Was never exploitable and never will be:** `PendingShamirSecretRestore`
has no working implementation at all — no cap, no read/write logic, nothing beyond the bare model
definition in `Vault+Model.swift` — and per the resolution below, it never gains one. This entry exists so
the reasoning behind "no cap, ever" on this container is findable, not to report something that happened.

**Target:** None — blocks adopting any cap on this container, whenever that's attempted; not tied to a
release.

### Severity: High, if a cap is ever added the naive way (deniability break, same class as Bug 99)

Doesn't expose vault contents. Answers the same question Bug 99 already named as the one thing this whole
layering effort exists to keep unanswerable: *is a restore genuinely in progress on this device right now?*
Unlike Bug 99, this would need no shard delivery at all to test — just a row count. Stated as a
conditional (*if* a cap is added without resolving the isolation question below) because that's exactly
what it is right now — a condition that hasn't occurred, on a mechanism that hasn't been built.

### What happens

§6 item 9.3 generalized BEK-restore tracking past depth-indexing: `PendingShamirSecretRestore` is now keyed
by the secret's own identity (`attributeID`) rather than by which of 32 depths it belongs to, so a
per-entry PEK restore (keyed by `VaultEntry.id`) can be tracked the same way a BEK restore is. That
generalization is real progress, but it removed something the depth-indexed design provided for free:
per-depth isolation, the exact precondition `RECOVERY_BUFFER_LAYERING.md` §3 already requires before any
cap on this kind of container is safe (*"a cap on a shared buffer is a cross-layer denial channel... safe
only once the buffer is per-depth"*).

Suppose a cap of N live rows exists, to bound Bug 96 item 2's resource-exhaustion problem. Suppose one
genuine restore is already live, anywhere on the device, at any depth. A coercer holding the phone:

1. Re-pairs N distinct identities with the victim's phone at their own duress depth — free, they're already
   holding it (Bug 99's own step 1, reused here).
2. Sends N `.handback` shard operations, each carrying a different, never-seen-before `attributeID`
   (garbage `SignedAttribute`s work fine — see the earlier finding on Branch B attestation requiring no
   real prior distribution).
3. Extracts the device (physical custody is already assumed) and counts `PendingShamirSecretRestore` rows
   directly from the raw SQLite file. No key needed — row count is always plaintext.

If fewer than N new rows exist, a live row already occupied one of the N slots before the coercer started
— meaning a restore is genuinely in progress somewhere on this device. If exactly N new rows exist, no
prior restore was live. Either answer is the thing this design exists to keep the coercer from ever
learning.

### Why this is sharper than the denial-channel framing §3 already names

§3's own concern was an attacker *destroying* a real recovery's collected shares by flooding the shared
buffer — a denial attack. This doesn't destroy anything and needs the victim's restore to survive intact;
it only *counts*. A coercer never needs to identify which row is the real one, decrypt anything, or prevent
the real restore from completing — they only need to know whether it exists at all, which the cap's own
admission behavior answers for free.

### Remedy — resolved: no cap at all, permanently

Two ways to close this were on the table. **Restoring per-depth isolation** — a local-key-sealed `depth`
field recording where a row's first shard arrived, capping per-depth instead of globally — was technically
sound (it does restore the isolation §3 requires, and `attributeID`/`depth` answer genuinely different
questions, so nothing about generalizing past BEK required giving it up). It was rejected anyway, for a
reason worth recording precisely since it isn't a security objection: enforcing any cap needs a decision
about what happens at the boundary — reject silently, surface an error, something a person eventually has
to design UX for — and that scope was judged not worth taking on for what Bug 96 item 2 already called a
"nice-to-have, not urgent" resource-exhaustion concern.

So: **no cap, adopted permanently, not as a placeholder.** This closes the counting oracle by removing its
precondition outright — there is no cap boundary to fill, so there is nothing for a coercer to learn by
filling one. `PendingShamirSecretRestore` rows are deliberately, permanently unbounded. See Bug 96 item 2
for the resource-exhaustion trade-off this decision accepts, in full and without a future revisit implied.

### Guard

None needed — closed by removing the mechanism (a cap) rather than by guarding it. Tracked as
`RECOVERY_BUFFER_LAYERING.md` §6 item 9.3's own closing decision, now final.

---

## Bug 123 — `depth`/`deletionToken`/`visibleThroughDepth` share one fixed AAD across every row and field, so their ciphertext is splice-able without the key

**Closed, subsumed into Bug 119, 2026-09-26.** See "Closed as subsumed" below. Earlier: **Status:** Open. Found 2026-09-13 during a security review of `RECOVERY_BUFFER_LAYERING.md` §6 item 9.3's
`PendingShamirSecretRestore` model, before it gains any read/write logic — its `attributeID`/`deletionToken`
fields are specified to inherit this exact pattern from `BackupEncryptionKey`. Pre-existing, not introduced
by that work: `BackupEncryptionKey.depth`/`.deletionToken` and `VaultEntry.deletionToken`/
`.visibleThroughDepth` already ship this way.

**Target:** None — not planned. Needs a deliberate decision, not a quick patch; see Remedy for why.

### Severity: Moderate — an integrity bypass, not a confidentiality leak, and it needs a stronger attacker than this codebase's usual threat model

Every field sealed through the generic `Data.encrypt(using:)`/`decrypt(using:)` helper
([Crypto+Manager.swift:242-250](Occulta/Services/Crypto+Manager.swift:242), routing to
`Manager.Crypto.encrypt(data:using:)`/`decrypt(data:using:)`,
[Crypto+Manager.swift:93-110](Occulta/Services/Crypto+Manager.swift:93)) authenticates under
`EncryptionScheme.v2_hybridPQ.aad` — one fixed byte (`0x02`), identical for every call, regardless of which
model, which row, or which field. Contrast the "big" fields (`VaultEntry.encryptedLabel`/`.encryptedContent`,
`BackupEncryptionKey.encryptedPayload`, `CustodyShard.encryptedPayload`), which seal directly via
`AES.GCM.seal(..., authenticating: row.aad())`, binding the ciphertext to that row's own `id` (and, for
`VaultEntry`, a field tag and timestamp too). The small "local key" fields never get that binding.

GCM authentication only proves "sealed under this key with this exact AAD" — nothing about which row or
field it was originally for, when the AAD never encoded that. An attacker with **write access to the raw
on-device database** (not the key — just the bytes) can copy one row's `deletionToken` ciphertext (say, a
live row's, decrypting to `liveToken`) onto a different row's `deletionToken` column. Same key, same AAD:
it authenticates and decrypts cleanly, just to the wrong row's truth. That's a genuine bypass, not something
the existing fail-safe defaults catch — `isOrphaned`'s fail-safe direction only protects *ambiguous*
ciphertext (nil, garbled, wrong key) by defaulting to "hidden." This attack produces a perfectly valid
decrypt; it's just borrowed from elsewhere. Concretely, it undoes exactly what Bugs 110/118 exist to
prevent — a stale depth's old `BackupEncryptionKey`/`VaultEntry` state resurfacing — via ciphertext splicing
instead of via "nobody bothered to orphan it."

Called Moderate, not High, because it needs write access to the raw SQLite file without the key — a
stronger attacker than this codebase's primary concern throughout (a coercer who gets the device unlocked
and reads through the UI or a full decrypt pass). Realistic for forensic tooling that can extract, modify,
and reflash a device image, or jailbreak-level access — not for a coercer standing over the user's shoulder.

### Why the fixed AAD exists as the default — not why a fix would need to touch `Group`

This same file's `Group` re-encryption entry already relies on this AAD staying identical across a field's
entire lifetime: `reencrypt(from:to:)` reseals `Group` member slots under a new key but the *same* AAD,
specifically so `readName()`/`readID()` keep working through a key rotation with no AAD bookkeeping. That
explains why the helper defaults to one fixed byte today — it does **not** mean a fix has to touch `Group`.
Checked while scoping the remedy below: `Group`'s calls never need to pass anything but the default, so an
additive change (a new optional parameter, current behavior when omitted) leaves `Group` — and any other
untouched caller — byte-for-byte unaffected. The earlier draft of this entry claimed the fix would need to
be "app-wide or not at all" and specifically need `Group`'s rotation path reviewed first; that overstated
it, corrected here.

### Remedy — not attempted; scope is narrower than first filed

Add an optional `aad:` parameter to the shared helper (`Data.encrypt(using:)`/`decrypt(using:)` and
`Manager.Crypto.encrypt(data:using:)`/`decrypt(data:using:)`), defaulting to today's fixed byte so every
existing, unmodified call site — `Group` included — keeps working exactly as it does now. Then bind only
the fields that actually need it, each via a small per-model field-discriminator mirroring `VaultEntry`'s
existing `VaultField` enum:

- `BackupEncryptionKey.depth`/`.deletionToken` (2 fields)
- `VaultEntry.deletionToken`/`.visibleThroughDepth` (2 fields — `VaultField` would need extending; it
  currently only tags the `encryptedPayload`-style fields, not these two)
- `Contact.Profile.originDepth`/`.visibleThroughDepth`/`.globalTrusteeDepth` (3 fields — `Contact.Profile
  .deletionToken` is not in scope here; it's a plain `#Predicate { $0.deletionToken == nil }` check, Bug
  112's mechanism, not this one)

Three models, seven already-shipped fields, roughly 15-20 read/write call sites across
`BackupEncryptionKey+Model.swift`, `Vault+Manager+Backup.swift`, `Manager+Security.swift` (both orphan
functions), `Contact+Model.swift`, `Contact+Manager.swift`, and `ContactManager+Classification.swift`. The
real cost is a one-time migration per model — decrypt every existing row's ciphertext under the old fixed
AAD, re-seal under the new row-bound one, crash-safe and idempotent, same shape as
`migrateLegacyBackupStorageIfNeeded` — plus a splice-attempt test per field proving GCM now rejects
ciphertext copied from a different row or field, since nothing currently tests for that. `Group` needs no
change and no new test. `PendingShamirSecretRestore.attributeID`/`.deletionToken` cost nothing extra either
way — nothing has shipped for them yet, so building them bound from the start carries no migration debt.

### Closed as subsumed into Bug 119, 2026-09-26

Re-examined against who can actually splice. Two facts from the code:
- **The store is only readable while the phone is unlocked:** it carries `FileProtectionType.complete`
  (`OccultaApp.swift`), so rewriting it needs an unlocked phone and write access to the app container.
- **The key these fields are sealed under needs no user prompt:** the local database SE key is created with
  `[.privateKeyUsage]` only and `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (`Key+Manager.swift`), so
  any code running as the app on an unlocked phone can use it.

An attacker able to rewrite the database is therefore, in practice, running code on the phone, and can
use the local key to decrypt and re-seal these fields with any value at all. Row binding wouldn't stop
that; they don't need to splice. That is Bug 119's attacker, who also gets the vault key. The only
attacker binding stops is one who can write a modified container back without running code that uses
the app's SE keys, a narrow capability.

So binding pays only once these fields are sealed under a key hostile code can't just use, which is what
Bug 119's remedy (`PASSPHRASE_LAYER_KEYS.md`) would bring, and that design already lists these fields.
The requirement moves there: when these fields are re-sealed under layer keys, the same migration binds
each to its row and field. Fixing it now would mean a migration now and another then, against an attacker
who can forge the values outright.

Fields carried into that requirement: `VaultEntry.visibleThroughDepth`/`.deletionToken`,
`BackupEncryptionKey.depth`/`.deletionToken`, `Contact.Profile.originDepth`/`.visibleThroughDepth`/
`.globalTrusteeDepth`, and `PendingShamirSecretRestore.attributeID`/`.deletionToken` (built unbound on
this branch, against this entry's earlier advice; consistent with this closure).

### Guard

None. Filed so the tradeoff is visible and decided on purpose the next time a model — `PendingShamirSecretRestore`
included — reaches for `Data.encrypt(using:)` for a field where row-identity binding might matter.

---

## Bug 124 — A removed trustee's shard stays valid forever; neither branch checks current trustee status

**Status:** Closed, 2026-09-19 — BEK fixed and tested 2026-09-14, PEK fixed and tested 2026-09-19 (see
Guard). Found 2026-09-14, while working out whether Bug 94 remedy 2's
attestation actually distinguishes a legitimate trustee from anyone else. It doesn't, on its own — tracing
the acceptance path directly turned up a broader, pre-existing gap that has nothing to do with attestation
specifically.

**Target:** unset.

### Severity: High (availability, same class as Bug 95) — and the attacker population is larger than Bug 95's own text assumed

Bug 95's severity section reads: *"the attacker set is exactly the people the user chose to trust with
recovery."* That's too narrow. It's exactly the people the user **ever** chose to trust, at any point in
that secret's history, including everyone since removed. Trustee-set changes don't shrink this population —
they only add to it.

### What happens

Neither `handleHandback` ([ShardCustody+Manager.swift:219-247](Occulta/Features/Vault/ShardCustody+Manager.swift:219))
nor `acceptReturnedShard` ([Vault+Manager+ReturnBuffer.swift:44-77](Occulta/Features/Vault/Vault+Manager+ReturnBuffer.swift:44))
ever checks whether the sender is a *current* trustee for the entry in question. `ShardRecord.status` models
exactly this (`.revoked` is a real case), but it's only ever consulted on the outbound side — building the
manifest of what Alice still expects trustees to hold. The inbound handback path never reads it.

**This does not need identity rotation, and does not need Branch B at all.** Branch A alone is enough:
`attribute.verify(against: ownKey)` only checks "did my key sign this" — it says nothing about whether the
signer is still someone I trust. A trustee Alice removed months ago, who kept their original, genuinely-
Alice-signed share from before removal, passes Branch A exactly as well as a current trustee does, because
nothing about their credential expires when they're removed from the list.

**Root cause: neither the BEK's `distributionID` nor a `VaultEntry`'s `entryID` changes when the trustee
list changes without a full secret rotation.** `prepareShards`/`distributeShards` re-split the *same*
underlying secret (`bekBytes`, or the PEK) under the *same* id every time trustees are added, removed, or
replaced — confirmed directly: BEK's `prepareShards` reads `decoded.payload.distributionID` rather than
minting a new one ([Vault+Manager+Backup.swift:1170](Occulta/Features/Vault/Vault+Manager+Backup.swift:1170)),
and PEK's shard-signing payload binds to `entryID` = `VaultEntry.id` ([Vault+Manager+Shards.swift:84-91](Occulta/Features/Vault/Vault+Manager+Shards.swift:84)),
which never changes for the entry's life. The doc comment there claims `entryID` "binds this shard to the
specific key generation" — it doesn't; there is no separate notion of "generation" anywhere in the model,
only the entry's own permanent identity. So a removed trustee's old credential remains bound to the exact
same id a current restore attempt is grouped by, forever.

### A real precondition — Marla needs a fresh key exchange with Alice's new device first — that turns out not to matter

Raised directly and checked rather than assumed: bundle encryption requires the *sender's own* local record
of the recipient's current key (`resolveKeyMaterial`, [Contact+Manager.swift:1418-1425](Occulta/Services/Contact+Manager.swift:1418)).
If a removed trustee hasn't re-paired with the owner's new device, anything they send encrypts to the
owner's *old* key and the new device can't decrypt it at all — not a signature failure, a transport one. So
a removed trustee genuinely cannot submit anything until they've done a fresh exchange with the new device.

That looks like a mitigation until you trace *why* that exchange happens. There's already a real, working
self-cleaning mechanism for the adjacent case: `deleteMismatchShards`
([ShardCustody+Manager.swift:183-189](Occulta/Features/Vault/ShardCustody+Manager.swift:183)) wipes a
trustee's stale, pre-rotation `CustodyShard` copy automatically — but only as a side effect of that trustee
receiving a fresh `.distribute`/`.replace` from the owner. A *continuing* trustee gets this for free the
next time they're redistributed to. A *removed* trustee never receives another `.distribute`/`.replace` at
all, so this never fires for them — confirmed, not assumed, by reading both handlers directly.

And the re-exchange that lets a removed trustee send anything in the first place doesn't require anything
vault-related — it's the same routine key exchange that happens whenever two people who message each other
normally both get new phones. Nothing about that moment involves the vault, signals anything to Alice, or
triggers `deleteMismatchShards` (which only fires on `.distribute`/`.replace`, never on a plain key
exchange). So the precondition is real, but it's satisfied by ordinary, unrelated contact maintenance, not
by anything that would make Alice think twice — it raises the bar from "passive, no action needed" to
"needs one ordinary interaction that isn't unusual on its own," not from "exploitable" to "safe."

The one thing that *would* structurally close it: Alice deleting Marla as a contact entirely, not just as a
trustee — then `senderPublicKey` resolution on Alice's side has nothing to find, and nothing from Marla can
authenticate at all. Not a realistic mitigation to depend on; it's a far bigger, more disruptive action than
ordinary trustee-list management, and isn't what removing someone as a *trustee* should require.

### Bounded the same way Bug 95 already is, but that's not a reason to leave it

A revoked trustee resubmitting a stale share can't complete a fraudulent recovery — the final GCM check
against the real backup file (or, for PEK, against the real vault content) is still the actual arbiter, and
a wrong contribution poisons the interpolation rather than succeeding with fabricated content. What it *can*
do is deny a legitimate recovery indefinitely, on a secret they were explicitly and deliberately removed
from — which is exactly the harm Bug 95 already tracks, just from a population nobody scoped correctly
until now.

### Remedy — both built and shipped

Regenerate the SSS distribution identity on every trustee-set mutation, not just on an explicit full
rotation. The two secret kinds split differently, because only one has an external-artifact cost:

- **BEK: regenerate `distributionID` only, never `bekBytes`. Done, 2026-09-14** — `prepareShards`
  ([Vault+Manager+Backup.swift:1163](Occulta/Features/Vault/Vault+Manager+Backup.swift:1163)) now mints
  `UUID()` on every call instead of reusing `decoded.payload.distributionID`. This does not conflict with
  `decisions.md`'s "reuse the same BEK across trustee-set changes" decision — that decision is specifically
  about the *key bytes*, made to avoid orphaning every `.occbak` already exported (sealed under `bekBytes`
  alone, confirmed directly: `VaultManager.backupFileAAD` is a fixed constant, never `distributionID`-
  dependent). Rotating just the id costs nothing there. A removed trustee's old share now groups under an
  id nothing currently tracks — it never reaches the live reconstruction pool at all, rather than being
  merged in and poisoning it. Full suite green (844/0/6) after the change; regression tests added the
  same day (`BackupTrusteeRotationTests.swift`) — see Guard.
- **PEK: regenerate the actual PEK value. Done, 2026-09-19** — a new `rotatePEK(for:vaultKey:)`
  ([Vault+Manager+Shards.swift](Occulta/Features/Vault/Vault+Manager+Shards.swift)), called as step 0 of
  every `prepareShards`: decrypts the entry's current label/content, generates a fresh key, re-seals both
  under it, re-seals the new key under the vault key. Nothing external ever depends on a `VaultEntry`'s PEK
  bytes the way exported `.occbak` files depend on `bekBytes` — it's an internal field, re-encryptable at
  will — so the fuller fix (that BEK can't afford) was available and simpler here: no new id field needed,
  `entry.id` never changes, only the key does. A removed trustee's old share now reconstructs a PEK that
  decrypts nothing, even in the case where it somehow still got admitted. Full suite green (846/0/6) after
  the change — no regressions in the many existing tests that already exercise `prepareShards` for PEK.
  Dedicated regression test added the same day (`PEKTrusteeRotationTests.swift`) — see Guard.

Either way, this is also the more direct fix for the underlying problem than a trustee-list-membership check
on the receiving side would be on its own — regenerating the id/value makes a stale credential inert by
construction, rather than requiring every acceptance path to remember to check status correctly forever.

### BEK chain traced end to end, 2026-09-14 — only one line actually changes

Walked every step distribution touches, to make sure the fix doesn't need to be bigger than it looks:

- **`Backup.setup`/`Backup.rotate()`** already mint a fresh `distributionID` — no change.
- **`prepareShards`** ([Vault+Manager+Backup.swift:1163](Occulta/Features/Vault/Vault+Manager+Backup.swift:1163))
  is the one line: stop reading `decoded.payload.distributionID`, mint `UUID()` instead.
- **`distributeShards`'s `oldAttrIDs` capture** (decides `.replace` vs `.distribute` per recipient) is keyed
  by `contactIdentifier`, never by `distributionID` — unaffected, keeps producing the right op per trustee.
- **`updateShardStatus`** matches purely by `attributeID`, a fresh UUID every split regardless of
  `distributionID` — a stale confirmation for a superseded `attributeID` already finds no match and falls
  through silently. Unaffected.
- **`handleReplace`** on the trustee's own device (`ShardCustody+Manager.swift:149`) deletes the old shard by
  `op.attributeID`, also independent of `entryID`. Unaffected.
- **`attemptBackupRestore`**'s grouping ([Vault+Manager+Backup.swift:516-520](Occulta/Features/Vault/Vault+Manager+Backup.swift:516))
  already buckets every collected shard **by `entryID`** before attempting reconstruction — built for Bug 95,
  isolating a poisoned group from a clean one. It's the exact mechanism this fix needs on the receiving end,
  and it needs nothing added: once distribution actually produces two different ids, a removed trustee's
  stale submission lands in its own group, never reaches threshold, and never touches the live one. No
  restore-side change at all — it was already built to isolate by id, it just never had two different ids to
  isolate before.

**One adjacent, pre-existing discrepancy found while tracing this, not part of the fix.**
`storeRestoreShard`'s dedup ([Vault+Manager+ReturnBuffer.swift:346](Occulta/Features/Vault/Vault+Manager+ReturnBuffer.swift:346))
matches only on `senderIdentifier` — its own doc comment claims `(entryID, senderIdentifier)`, but the code
never checks `entryID`. Doesn't undermine this fix (Marla and a current trustee are different senders
regardless), and doesn't need to block it, but the doc comment is wrong about what the code actually checks
and should eventually be corrected to match one or the other.

### A consequence worth stating, and a correction to an earlier version of this same section

Traced what attestation (Branch B) actually proves, end to end, to answer a direct question about whether
it protects against anything: it doesn't verify that the underlying share value is genuine — the attester
controls both the fabricated `attribute` *and* the attestation hashed over it, so a dishonest attester can
self-consistently vouch for anything. What Branch B actually reduces to is "this signature comes from an
identity I currently recognize."

**An earlier version of this entry claimed that once both regeneration fixes shipped, Branch B would stop
doing anything a plain membership check wouldn't do better — that overreached, corrected here rather than
left standing.** Branch B exists for a scenario this bug has nothing to do with: a *current*, never-removed
trustee whose share still verifies fine against the old key, but whose signature Alice's device can no
longer check directly because *her* identity rotated (Bug 94's original motivation). A membership check
alone doesn't solve that — it would need to be layered on top of some form of Branch A/B, not instead of
it, since membership alone verifies nothing cryptographically. Both regeneration fixes closing means a
*revoked* trustee's stale credential is now inert regardless of which branch they'd otherwise pass — that
is real and worth having — but it does nothing to remove Branch B's actual, ongoing job.

**Superseded again, same day, by a sharper and independent finding — `bugs.md` Bug 125.** "Branch B stays"
above is still right about the *job* (letting a rotated-identity trustee's genuine share through) — it was
wrong to assume attestation, as a mechanism, is what has to keep doing that job. Bug 125 traces the actual
transport layer and finds sender identity is already proven, cryptographically, one level up, before
`handleHandback` ever looks at `op.attestation` — making attestation's own signature redundant for reasons
that have nothing to do with revocation. See that entry for the full reasoning; it's the current word on
whether attestation (in any form, not just its size) is needed at all.

**Foundation half acted on 2026-09-14; the shipped half followed on 2026-09-19, as Bug 125's remedy, not
this bug's.** `PendingRestoreShardSlot.attestation` and its half of `ShardsCodec`'s per-slot layout were
removed (`Vault+Model.swift`, cutting the slot from 862 to 449 bytes and the per-row cost from ≈215 KB to
≈112 KB) — safe to do outright since nothing called that codec yet, and, per Bug 125, correct for a reason
beyond just being safe: there was nothing to restore there, not even a presence flag. The *shipped, tested*
Branch B mechanism (`ShardCustody+Manager.swift`'s Branch A/B split, `ShardHandbackAttestationTests`,
originally 2026-08-26) has since been collapsed too — see Bug 125's own Remedy for the full account of what
changed there.

### Guard

BEK covered, 2026-09-14 — `BackupTrusteeRotationTests.swift`. `redistributionMintsNewDistributionID`
is the load-bearing one (verified it actually fails if the fix is reverted, not just that it passes);
`cleanRestoreStillSucceedsAfterRedistribution` confirms the fix didn't break a legitimate restore.
**Deliberately doesn't assert that mixing a stale share into a live reconstruction throws** — checked
`ShamirSecretSharing.lagrange()` directly, it uses every supplied point unconditionally with no
error-correction, so that mix fails the GCM check regardless of whether `distributionID` changed
between rounds. Grouping-by-`entryID` is what actually keeps the mix from being attempted at all in
production (`attemptBackupRestore`), and that's what the first test already covers.

PEK covered, 2026-09-19 — `PEKTrusteeRotationTests.swift`. Unlike BEK, `entryID` (=
`VaultEntry.id`) never changes between rounds, so there's no second id for a stale round to be isolated
by — the discriminating property here is that a stale round's shares reconstruct a PEK that no longer
opens the entry's own content. `redistributionInvalidatesStalePEKShares` is the load-bearing one
(verified it fails if `rotatePEK`'s call in `prepareShards` is commented out, reverting to reading the
entry's unrotated PEK — confirmed directly, not just assumed); `cleanRestoreStillSucceedsAfterRedistribution`
confirms a legitimate restore using the current round's shares still recovers the real content
afterward. No Secure Enclave dependency — `rotatePEK` only touches the vault key and
`SecRandomCopyBytes`, unlike `Backup.persist`'s ambient `Manager.Key()` path.

---

## Bug 125 — Branch B's attestation signature is redundant with transport-level sender authentication it never needed to duplicate

**Status:** Fixed, 2026-09-19 — found and built the same day. A design finding about shipped, tested code
(`ShardCustody+Manager.swift`'s Branch A/B split, `ShardHandbackAttestationTests`), acted on the same day
it was recorded rather than left for a separate decision. Never a vulnerability in the traditional sense:
nothing got *less* secure while attestation was still in place. The finding was that it carried real cost
(bytes, complexity, a second signing/verification path) for a security property already established
elsewhere, for free — and that cost is why it was worth removing outright rather than just documenting.

**Target:** unset.

### Severity: N/A as a vulnerability — this is a simplification finding

Current behavior isn't insecure; it's redundant. Severity classification doesn't really apply the way it
does to the rest of this file's entries.

### What happens — the redundancy, traced precisely

Two separate claims get conflated by attestation's current shape, and only one of them is actually true
once you check the surrounding transport:

1. **Content authenticity — "is this value genuinely what Alice signed."** This is what Branch A's own
   signature (`attribute.verify(against: ownKey)`) proves, and transport authentication cannot substitute
   for it: knowing *who sent a message* says nothing about whether its *content* is truthful. Branch A
   stays exactly as it is — real, non-redundant, unrotated case only.
2. **Sender authenticity — "who actually sent this."** This is all attestation's own signature
   (`attestation.verify(against: senderPublicKey)`) ever proved. Checked whether the transport layer
   already proves the same thing, rather than assuming: `shardOperations` (carrying both `attribute` and
   `attestation`) is a field inside `OccultaBundle.SealedPayload`
   ([OccultaBundle.swift:395-428](OccultaCore/Sources/OccultaCore/OccultaBundle.swift:395)), sealed as one
   GCM-authenticated blob. `senderProof`'s own doc comment states plainly what that buys: *"only the
   actual sender can produce this value."* For a 1:1 exchange — which handback always is, trustee to
   owner, never a group — the session key itself is derivable only by the two parties involved, so a
   successful decrypt already proves who sent the content, before `handleHandback` ever inspects
   `op.attestation`.

Once (2) is established, attestation's signature isn't adding a second, independent proof — it's
re-proving the exact same fact, more weakly (an ECDSA signature nobody downstream ever independently
re-verifies against anything, versus a transport layer already checked as a precondition to reaching this
code at all). Confirmed nothing re-checks it later either: `Backup.reconstruct`'s own `ownerIdentity`
verification only ever re-checks `attribute`, never `attestation` — its entire job is done, once, at the
moment `handleHandback` accepts or rejects, inside the same session it arrived in. Unlike the original
`.shard` attribute (created once at distribution, consumed possibly months later over a completely
different transport session, which is exactly why *that* signature has to be independently, transport-
independently verifiable), attestation is created and consumed within one interaction — it never needs to
outlive the transport session that already authenticated it.

**Once you subtract what Branch A already provides (content authenticity, unrotated) and what transport
already provides (sender authenticity, always), there's nothing left for attestation to add — signature,
hash-binding, or even a bare presence flag.** Content authenticity is not recoverable after identity
rotation, with or without attestation; that was never fixable by this mechanism, and isn't the gap
attestation was ever capable of closing. Branch B's actual logic collapses to: *if Branch A fails, accept
`attribute` anyway* — because sender identity was already established one layer up, and that was always
the only thing Branch B was checking.

### Why this doesn't reopen Bug 94

`attribute.entryID` matching a real, live distribution is what limits the population to people who were
actually sent a share — that check is untouched, still runs, still does the actual work of keeping this
scoped to trustees. Removing attestation removes a redundant second signature, not the binding to a real
distribution.

**Corrected 2026-09-26 (branch security review): the check the paragraph above relies on doesn't exist.**
Nothing verifies that `attribute.entryID` names a real, live distribution. `acceptReturnedShard` and
`absorbShard` bank a shard under any `entryID`, and `bekRestoreDistributionIDs` enumerates every row. For a
backup-key restore it couldn't be checked anyway: the restoring phone is usually new, and the record of
what was distributed was on the lost one. The conclusion still holds, for other reasons:
- one slot per `(entryID, sender)`, with the sender resolved from the transport, so no single contact can
  supply a threshold alone (Bug 94 remedy 2);
- `restoreBackup` counts only senders visible at the current depth, and refuses a depth that already has
  a backup key (Bug 94 remedy 1);
- a reconstructed key counts only if it opens the `.occbak` the owner chose to open;
- a per-entry key is only finalised for an entry this device split, checked against its own ciphertext.

What remains is the case Bug 94 already accepts: two or more contacts visible at a depth with no backup
key, plus the owner choosing to open their file. The stray rows a non-trustee can create are Bug 96
item 2's accepted unbounded growth. `ShardCustody+Manager.swift`'s `handleHandback` comment, which
repeated the claim, is corrected to match.

### Remedy — both surfaces done

- **Foundation model:** settled the question `bugs.md` Bug 124 paused and then answered incompletely —
  `PendingRestoreShardSlot` needs no attestation field of any kind, not a `SignedAttribute`, not a trimmed
  104-byte version, not a presence flag. Already the current shape as of Bug 124's own foundation-half
  edit; this entry is why that shape is correct, not merely safe.
- **Shipped mechanism, done 2026-09-19:** `handleHandback`'s Branch A/B split
  ([ShardCustody+Manager.swift:219-267](Occulta/Features/Vault/ShardCustody+Manager.swift:219)) now runs
  Branch A for the real, non-redundant thing it proves when it succeeds (content authenticity) but no
  longer gates on it — failure falls straight through to acceptance instead of trying a second check.
  Removed `op.attestation` from `OccultaBundle.ShardOperation` (a real wire-format change — old builds
  simply never see the key, matching this codebase's established "unknown fields are silently ignored"
  tolerance), `attestationFiller`, `attestation(for:retainedKeysByFingerprint:)`, and
  `retainedKeysByFingerprint(forOwner:)`. `ShardHandbackAttestationTests.swift` kept its name (cosmetic
  rename, not done) but lost every test that only made sense with Branch B — attestation construction,
  attestation-signature/hash mismatch rejection — and kept/reworked the ones that don't: Branch A
  acceptance, unconditional acceptance on Branch A failure, and distinct-sender enforcement, which is the
  property actually doing security work now. `Vault+Manager+ReturnBuffer.swift`, `ReconstructShard+Model
  .swift`, `SignedAttribute.swift`'s `AttestedShard` (now in its own `AttestedShard.swift`), and `Contact+Manager.swift`'s
  `fillerShardOperation`/tier-padding all lost their `attestation` parameter or field to match.
  `GroupShardGatingTests.swift`'s padding-parity suite (`ShardOperationPaddingTests`) updated to compare a
  filler op against a plain `.handback` instead of an attested one — see Bug 94a's own moot-as-of-today
  note.

### Guard

Covered by the reworked `ShardHandbackAttestationTests.swift` (Branch A acceptance, rotated-identity
acceptance with no signature at all, distinct-sender enforcement, trustee-side handback still fires on
fingerprint mismatch) and `GroupShardGatingTests.swift`'s updated padding-parity suite. Full suite run
after the change — see the commit this note lands with for the pass/fail/skip counts.

---

## Bug 126 — `pendingRestoreActive`/`pendingRestoreShardCount` are hand-synced at five separate sites instead of queried from the data that already answers them

**Status:** **Closed — moot, 2026-09-23.** Bug 99's remedy removed `pendingRestoreActive`,
`pendingRestoreShardCount` and `refreshPendingRestoreState` along with the held file. See the note at the end
of this entry. Filed 2026-09-22, **Open** until then. Found while designing the fix for `storePendingRestore` not
immediately re-attempting reconstruction against already-collected shards (`decisions.md`'s "Don't
auto-arm shard collection on first vault-tab visit," the gap it surfaced). No code changed — this
entry documents the finding so the simplification is tracked, not lost, while that other fix proceeds
first.

**Target:** unset — a design/maintainability finding, not tied to a release.

### Severity: Low as a vulnerability, real as a correctness risk in a codebase that treats UI-state honesty as security-relevant

Nothing here decrypts anything or crosses a depth boundary. But `pendingRestoreActive` is exactly the
kind of published state Bug 93 spent real design effort making depth-uniform and honest — "duress
advertises an event whose result it will never show" only holds if the flag is reliably correct. Five
independent hand-written assignment sites is exactly the shape that produces the "missed-consumer"
bugs this codebase has already hit more than once for a structurally similar reason (Bug 110/113/115/116,
all "a functional read forgot to apply a filter the model itself requires").

### What happens

`pendingRestoreActive: Bool` and `pendingRestoreShardCount: Int`
([Vault+Manager.swift:81,85](Occulta/Features/Vault/Vault+Manager.swift:81)) are plain `@Observable`
properties on `VaultManager` — not computed, not re-derived on read. SwiftUI's `@Observable` only
tracks "did this stored value change since the view last read it"; it gives no help recomputing a
stale value, so whatever last assigned it is the only thing keeping it honest. Both are entirely
derivable on demand: `pendingRestoreActive` from `FileManager.default.fileExists(atPath:
pendingRestoreURL.path)`, `pendingRestoreShardCount` from `bekRestoreShardCount()` — which already
queries `PendingShamirSecretRestore` rows directly, the actual source of truth. Nothing about either
value requires caching.

Despite that, the same two-line formula is written out by hand in five places:

1. **`refreshPendingRestoreState(currentDepth:)`**
   ([Vault+Manager+Backup.swift:415-420](Occulta/Features/Vault/Vault+Manager+Backup.swift:415)) — the
   one function that's actually named for this job: `active = fileExists(...)`, `count = active ?
   bekRestoreShardCount() : 0`.
2. **`storePendingRestore`**
   ([Vault+Manager+Backup.swift:459-460](Occulta/Features/Vault/Vault+Manager+Backup.swift:459)) —
   re-derives the same two fields by hand, with `active` hardcoded `true` instead of calling
   `fileExists` (reasoned to be equivalent at that point, but that reasoning lives only in a
   comment, not in the code).
3. **`attemptBackupRestore`'s early "already has BEK" cleanup branch**
   ([Vault+Manager+Backup.swift:505-506](Occulta/Features/Vault/Vault+Manager+Backup.swift:505)) —
   hand-sets `active = false`, `count = 0`.
4. **`attemptBackupRestore`'s pre-loop recompute**
   ([Vault+Manager+Backup.swift:514](Occulta/Features/Vault/Vault+Manager+Backup.swift:514)) —
   hand-sets `count` alone, a third independent copy of half the formula.
5. **`attemptBackupRestore`'s success branch**
   ([Vault+Manager+Backup.swift:538-539](Occulta/Features/Vault/Vault+Manager+Backup.swift:538)) —
   hand-sets `active = false`, `count = 0` again.

Concrete evidence this already causes friction, not just a hypothetical: the fix under discussion for
the `storePendingRestore` gap was to append a call to `attemptBackupRestore(currentDepth: 0)`
immediately after site 2's two hand-set lines. If that call reaches site 5, it silently overwrites the
values site 2 just set, three lines earlier, in the same function — correct in that instance only
because both sites happen to compute a value that's consistent, not because anything enforces it.  A
future edit to either site has no compiler help catching a mismatch, and only a careful read (like the
one that surfaced this) catches it by inspection.

### Remedy — proposed, not built

Collapse to one source of truth. Two shapes were discussed, neither implemented yet:

- **Computed properties**, replacing the two stored `var`s outright: `var pendingRestoreActive: Bool {
  FileManager.default.fileExists(...) }`, `var pendingRestoreShardCount: Int { pendingRestoreActive ?
  ((try? bekRestoreShardCount()) ?? 0) : 0 }`. Removes all five hand-sync sites at once — every reader
  gets the current on-disk/on-database truth by construction, and there is nothing left to drift.
  Trade-off to weigh: `bekRestoreShardCount()` decrypts each `PendingShamirSecretRestore` row's
  `shards` field to count slots, and a computed property re-runs on every SwiftUI access, not just at
  the five points that used to assign it — needs checking whether that cost is acceptable on
  `Vault+Tab.swift`'s render path, or whether it needs its own cheap count-only path (e.g. counting
  rows without decrypting slot contents).
- **If the decrypt cost turns out to matter**, keep a cache but reduce it to one writer: only
  `refreshPendingRestoreState` ever assigns the two stored fields, and every other site
  (`storePendingRestore`, both `attemptBackupRestore` branches) calls it instead of hand-rolling the
  formula. Keeps the caching, removes the duplication.

Whichever shape is chosen, the fix for the `storePendingRestore` immediate-recheck gap (still open,
see `decisions.md`) should land on top of it, not before it — building the new call site on the
current five-way duplication just adds a sixth.

### Guard

None yet — not fixed.

### Superseded, 2026-09-23: the state itself goes away

Bug 99's 2026-09-23 addendum settles that the `.occbak` is never held: opening it is a one-shot
reconstruction attempt, and a failed attempt stores nothing. Without a held file, there is nothing for
`pendingRestoreActive` to mirror and no "Recovery in progress" section for `pendingRestoreShardCount`
to feed, so both are removed along with `refreshPendingRestoreState` and all five assignment sites
above. The "immediate-recheck" fix this entry was sequenced ahead of no longer exists either. Until that
change ships, the five sites stay exactly as described. Two findings from the review, kept for the
record:

- **The computed form already existed.** `isRestorePending`
  ([Vault+Manager+Backup.swift:380](Occulta/Features/Vault/Vault+Manager+Backup.swift:380)) is a
  computed `fileExists` check, used by functional callers. `pendingRestoreActive` was a hand-synced
  cached copy of a value the type already computed.
- **The computed-properties remedy above wouldn't have worked on its own.** `VaultManager` is
  `@Observable`, which invalidates views on writes to *stored* properties. A computed property that reads
  the filesystem or SwiftData gives it nothing to observe. Making `pendingRestoreActive` computed would
  have kept the banner updating only because `pendingRestoreShardCount`, still stored, happens to be
  written at the same moments. Making both computed would have left nothing to trigger a redraw.

Closed as moot, 2026-09-23, when Bug 99's remedy shipped.

---

## Bug 127 — v1.10.3's restore-file rename left files from v1.10.2 and earlier orphaned on disk, named for the mechanism and included in device backups

**Status:** **Fixed, 2026-09-23.** `VaultManager.deleteLegacyRestoreState()` deletes both names on every
unlock (test: `unlockDeletesLegacyRestoreState`). Filed the same day, while listing what legacy restore state
`RECOVERY_BUFFER_LAYERING.md` §9.4's migration has to handle.

**Target:** unset. The fix belongs in §9.4's legacy migration (being decided).

### Severity: Medium (forensic), plus a silently lost restore

It affects only devices that were mid-restore when they upgraded from v1.10.2 or earlier to v1.10.3 or later.

### What happens

Bug 93 Part D (`0e35dd6`, 2026-08-25, shipped in v1.10.3) renamed `pending-restore.occbak` →
`backup-import-cache.occbak` and `pending-restore-shards.dat` → `backup-import-cache-shards.dat`. Its commit
message says "filesystem paths only", and it included no migration. Nothing in current code references the
old names (`grep` for `pending-restore.occbak` finds only history). So on an upgraded device:

- **The old files are never read and never deleted.** Their names state what they are, the exact tell Part
  D existed to remove, readable with `ls` and no key. The `.occbak`'s length estimates the vault's size
  (Bug 100).
- **They are in device backups.** Bug 100 remedy 1 (`f9aeaca`, 2026-08-28) sets `isExcludedFromBackup` only
  on files it writes, under the new names. Old-name files were written before it existed, so they never
  got the attribute.
- **The in-flight restore silently died.** `pendingRestoreActive` and `isRestorePending` check the new path
  only, so the banner vanished and nothing ever attempted the old file again.
  `migrateLegacyRestoreShardFile` reads only `backup-import-cache-shards.dat`, which no release ever wrote:
  shards moved into rows (remedy 2) in the same release as the rename.

### Remedy

Fold into §9.4's legacy migration. **Decided 2026-09-23** (`RECOVERY_BUFFER_LAYERING.md` §8): at the first
unlock at any depth, delete `pending-restore.occbak`, `pending-restore-shards.dat` and
`backup-import-cache.occbak`, without a final restore attempt. The old shard file is deleted, not salvaged,
because the restore it belonged to already died at the v1.10.3 upgrade.

### Guard

A migration test seeding both old-name files and asserting neither survives the first unlock after upgrade.

---

## Bug 128 — "Erase all data" leaves the backup and restore files in Application Support

**Status:** **Fixed, 2026-09-23.** `deleteAllData()` now deletes the legacy restore files and
`backup-export-meta.dat` (test: `wipeDeletesBackupFiles`). The `Documents/Inbox` copies remain Bug 101's.
Filed the same day, while drafting the §9.4 changes.

**Target:** unset.

### Severity: Medium (forensic), a trace that survives the wipe

### What happens

`Manager.App.eraseAllData()` deletes prekeys, contacts, the vault's SwiftData rows
(`VaultManager.deleteAllData()`), and then the Secure Enclave keys. It deletes no files. Nothing in the
erase path removes:
- `backup-import-cache.occbak`, the held restore file (and its v1.10.2-and-earlier name,
  `pending-restore.occbak`, plus `pending-restore-shards.dat`; see Bug 127);
- `backup-export-meta.dat`, written by every backup export.

Once the keys are gone, the contents can't be decrypted. The files' existence, length and timestamps still
say that this device exported a vault backup and was mid-restore, and the held `.occbak`'s length estimates
the vault's size (Bug 100). An old-name file states the mechanism outright. A wiped device is supposed to
carry none of this. The OS copies in `Documents/Inbox` (Bug 101) survive a wipe too.

### Remedy

Have the erase path delete these files. §9.4's legacy-cleanup function already deletes the three restore
files, so the wipe can call it and also remove `backup-export-meta.dat`. The Inbox copies belong with
Bug 101's fix.

**Follow-up, 2026-09-26 (branch code review):** the wipe also deleted the `Vault` singleton and every
`BackupEncryptionKey` row, including the 32-row filler baseline, and only `VaultManager.init` recreated
them. Erase all data doesn't relaunch the app, so until the next launch `absorbShard` threw
`vaultNotFound` (returned pieces dropped), and a backup set up in that session sat without its filler, the
row count revealing it. `deleteAllData()` now ends with `ensureBackupKeyFillerRows()` and
`ensureVaultExists()`; `VaultBackupRoundTripTests.wipeRestoresFreshShape` pins it (fails without the fix).

### Guard

Seed every file, run `eraseAllData()`, and assert none remain.

---

## Bug 129 — A restore whose entry import fails after the key is saved leaves that depth stuck: key installed, entries missing, every retry refused

**Status:** **Fixed, 2026-09-23.** `restoreBackup` checks everything, then writes once with rollback. `importBackup`,
`reconstructBackup` and `Backup.reconstruct` were deleted, since no production code called them any more;
their tests now go through `restoreBackup`. Found while drafting §9.4's `restoreBackup`. Present in shipped code
(`attemptBackupRestore`), and the new function keeps the same shape.

**Target:** unset.

### Severity: Medium

A genuine owner can lose the ability to restore. A crafted file can install its author's backup key in a
layer without importing anything.

### What happens

Completion runs two steps in order: `Backup.reconstruct` (Shamir combine, GCM check against the file, then
`persist` the reconstructed key for the depth), then `importBackup` (decrypt, decode `VaultBackup`, insert
the entries). `importBackup` can still throw after `persist` has run:
- the JSON doesn't decode;
- an entry's `entryType` doesn't fit a `UInt8`;
- an entry's `createdAt` is out of range;
- sealing an entry or saving the context fails.

The catch block moves on to the next distribution, but the key is already saved. Every later attempt at
that depth is then refused by the "this depth already has a backup key" check (Bug 94 remedy 1), so the
same file can never be restored there again. The entry loop can also throw partway, after inserting some
entries.

- **Genuine owner:** an import error at depth 0 leaves the real key in place with some or none of the
  entries, and no way to retry.
- **Crafted file:** a file that passes the GCM check but fails decoding installs its author's key as this
  layer's backup key with nothing imported. Later exports from that layer are then readable by the file's
  author.

**A second failure in the same path, found 2026-09-23 while deciding the fix.** `importBackup` inserts
entries one at a time and saves once at the end. If an entry fails validation partway (an out-of-range
`entryType` or `createdAt`), the entries inserted before it stay in `VaultManager`'s shared `modelContext`
unsaved, and the next `save()` anywhere commits them. So a failed import can leave a partial import behind
later, even when no key was saved.

### Remedy — decided and built 2026-09-23

**Check everything first, then write once.**
- Split `Backup.reconstruct` into a step that verifies the key against the file and writes nothing, and
  the existing `persist`.
- Split `importBackup` into decrypt, decode and validate every entry, and insert without saving.
- `restoreBackup` runs all the checks before any write, stages the key and the entries, and commits them
  in one `modelContext.save()`. On any failure, `modelContext.rollback()` discards the staged changes.
- A failed attempt leaves nothing behind, and the layer can still be restored from a good copy of the
  file. `importBackup` and `reconstructBackup` are rebuilt from the same pieces and also roll back.

**Shards after a file that verifies but won't decode are kept, not consumed.** They reconstructed the
file's key, so they're genuine; only this copy of the file is bad, and a good copy can still complete. The
owner sees the usual neutral message.

Not chosen:
- **Undo afterwards** (revert the saved key row): it would have to become indistinguishable from a
  filler row again, and inserted entries would still need cleanup.
- **SwiftData `transaction { }`:** how the inner `save()` calls behave inside a transaction isn't
  documented.

`rollback()` discards every unsaved change in the shared context, not only this attempt's. That's
acceptable because every other `VaultManager` operation saves before returning, but it is worth knowing.

### Guard

- A file that passes the GCM check but fails decoding: after the attempt, that depth has no backup key and
  no new entries, the banked shards are still there, and a valid file can still restore there.
- A file whose second entry is invalid: no entries are inserted, including the first, and a later `save()`
  elsewhere commits nothing from it.

---

## Bug 130 — Three of the four custody-shard deletions leave every other row byte-identical, so a snapshot diff shows exactly which row was removed

**Status:** Fixed 2026-09-23, on `v1.11.0/vault-key-layering`. Filed the same day, found while answering
whether `CustodyShard` has a `deletionToken` (it doesn't; its rows are hard-deleted), after closing
`RECOVERY_BUFFER_LAYERING.md` §6 item 7.

**Target:** unset.

### Severity: Low (forensic)

Needs two snapshots of the trustee's database, which means extracting the device twice (the store is
excluded from device backups). Without a key, the diff can't tell whose shard was removed.

### What happens

`CustodyShard` rows (shards this device holds for other people) are hard-deleted in four places in
`ShardCustody+Manager.swift`:
- `handleReplace`: the old shard, when the owner sends a replacement;
- `deleteMismatchShards`: shards tied to the owner's old key, when the owner redistributes under a new one;
- `processExpectedShards`: a shard the owner no longer lists (implicit revoke);
- `purgeCustody`: everything held for an owner, when that contact is deleted.

Only `purgeCustody` re-seals the surviving rows with a fresh nonce
(`decoded.row.encryptedPayload = try self.sealRow(...)`). Its own doc comment gives the reason: without
it, "a raw-DB examiner comparing two snapshots across a deletion would see exactly which rows
disappeared and find every surviving row byte-for-byte identical". The other three paths skip that
step, so the comparison it closes is still open after every replace, re-key and revoke. It shows that
one custody relationship changed, and when.

Hard deletion itself isn't the problem: custody rows don't belong to a depth, so this is not the case the
"orphan rows in place" decision covers (`decisions.md`). The changing row count is the same accepted class
recorded when item 7 was closed.

### Remedy (built)

The three paths now delete through one helper, `deleteCustodyShards(using:where:)`. It deletes the
rows matching a predicate and re-seals every other readable row with a fresh nonce and the same content.
`handleReplace`'s two deletions (the replaced shard, and the owner's old-key shards) became one
predicate, so survivors are re-sealed once rather than twice.

Two differences from the proposal:
- **Re-seal only when something is deleted.** The row count already shows whether a deletion
  happened, so re-sealing on a no-op leaks nothing less. It would also rewrite every custody row on
  every inbound bundle, since `processExpectedShards` runs on each one.
- **`purgeCustody` keeps its own loop.** It re-seals on every purge, even one that deletes nothing,
  and `ShardCustodyPurgeTests` pins that. Routing it through the helper would have quietly dropped the
  unconditional re-seal, so it wasn't moved. The helper's doc comment names the exception.

### Guard

`CustodyDeletionResealTests` (`ShardCustodyTests.swift`) covers `.distribute` under a new owner key,
`.replace` and `processExpectedShards`. Each snapshots every row's bytes and decrypted attribute ID,
runs the operation, and asserts the deleted row is gone and every survivor has new bytes and the same
content. All three fail on the pre-fix code. A fourth test pins that a `processExpectedShards` which
revokes nothing leaves every row's bytes unchanged, so moving to always re-sealing has to be deliberate.

---

## Bug 131 — `gfMul` branches on its inputs, so Shamir split and reconstruct take data-dependent time

**Status:** Fixed 2026-09-23, on `v1.11.0/vault-key-layering`. Filed the same day, found while
reviewing Bug 95's change to `ShamirSecretSharing.reconstruct`, which computes the Lagrange weights
once per reconstruction instead of once per byte.

**Less live than filed.** Checking the compiled output while fixing it showed that shipped builds
never branched here: at `-O` the compiler turned both `if`s into conditional selects (`csel`, 7 in the
specialized `gfMul`), and ARM treats `csel` as a data-independent-timing instruction. Only unoptimized
builds branched, and those don't ship. The exposure was that nothing in the source guaranteed the
optimizer's choice.

**Target:** `v1.11.0`.

### Severity: Low (side channel)

The only realistic observer is code on the same device measuring CPU or cache timing, which iOS
sandboxing makes hard. Restore and split are local and offline, so there is no network observer. A
coercer holding the phone sees only how long a whole restore takes, which is milliseconds to seconds
dominated by the GCM check, SwiftData and Enclave calls. A nanosecond-scale difference is lost in that.

### What happens

`gfMul` (`ShamirSecretSharing.swift`) multiplies two bytes bit by bit, and two of its steps are
conditional:

```swift
if b & 1 != 0 { p ^= a }      // runs only when b's low bit is 1
...
if carry { a ^= 0x1B }        // runs only when a's high bit was 1
```

So a multiplication's running time depends on the bits of `a` and `b`. Unoptimized builds certainly
branch here. Optimized builds may compile these to branch-free instructions (`csel` on ARM), but Swift
doesn't guarantee it, and nobody has checked the compiled output.

Secret data reaches `gfMul` in two places, both in the `a` slot, where the `carry` step depends on it:

| Where | Secret input | Public input |
|---|---|---|
| `split` (owner's phone, at distribution), `eval`'s `gfMul(acc, x)` | `acc`, built from the key byte and random coefficients | the share's x |
| `reconstruct`, `gfMul(yᵢ, wᵢ)` once per share per byte | the share's value `yᵢ` | the Lagrange weight `wᵢ`, from x-coordinates only |

`gfInv` runs only on values derived from x-coordinates, which are public (byte 0 of every share), and
its loop runs over the fixed exponent 254, so it leaks nothing.

Bug 95's change doesn't make this worse. Before it, each share's value went through n
secret-dependent multiplications per byte; now it goes through one. Its subset search does repeat
reconstruction, up to 1,024 times over the same shares in one failing restore. Repetition helps an
attacker average out noise, so it adds a little exposure, and only for the same on-device observer.

`VAULT_SSS_GUIDE.md` has called this "acceptable for SSS" since the guide was written.
`RUST_PACKAGES_SPEC.md` already specifies constant-time GF(2⁸) for its planned `shamir.rs`.

### Remedy (built)

Replace the two conditionals with masks. This is the standard constant-time form and returns the same
result:

```swift
static func gfMul(_ a: UInt8, _ b: UInt8) -> UInt8 {
    var p: UInt8 = 0
    var a = a
    var b = b
    for _ in 0..<8 {
        p ^= a & (0 &- (b & 1))          // all-ones mask when b's low bit is set
        let carry = 0 &- (a >> 7)        // all-ones mask when a's high bit is set
        a = (a << 1) ^ (0x1B & carry)
        b >>= 1
    }
    return p
}
```

Every step runs whatever the inputs. The speed should be about the same. Log/exp lookup tables are not
an alternative: indexing a table by a secret leaks through the cache, which is worse than the branches
here.

### Guard

Timing can't be asserted reliably in a unit test, so the guard is equivalence plus inspection:
- `GFArithmeticTests.mulMatchesBranchingForm` compares the new `gfMul` with the branching form it
  replaced on all 65,536 input pairs;
- the existing GF tests, including the exhaustive `a · a⁻¹ == 1`;
- a manual check of the compiled output, recorded below.

**Compiled output, checked 2026-09-23** (Apple Swift 6.2.3, `swiftc -emit-assembly`,
`-target arm64-apple-ios18.6`, on `ShamirSecretSharing.swift` itself):

| Build | Old `gfMul` | New `gfMul` |
|---|---|---|
| `-O` | 0 conditional branches, 7 `csel` | 0 conditional branches, 0 `csel` |
| `-Onone` | 3 conditional branches: the loop's end check and both `if`s | 1: the loop's end check |

At `-O`, `reconstruct` calls the specialized `gfMul` rather than inlining it, and has no bit-test
branches of its own. `split`'s six bit-test branches are the same before and after, and are all
copy-on-write uniqueness checks (`swift_isUniquelyReferenced`), not secret values. Re-check after a
Swift toolchain upgrade if this ever matters more; the source no longer depends on the optimizer's
choice, but the check is cheap.

---

## Bug 132 — `migrateLegacyRestoreShardFile` migrates a file no release ever wrote

**Status:** Fixed 2026-09-24, on `v1.11.0/vault-key-layering`: the function and its call are deleted.
Filed the same day, found while listing what was left in the vault refactor: the
function looked like a gap, since it runs only when a shard arrives (not on unlock) and "Erase all
data" doesn't delete its file. Checking which builds wrote the file showed there is no population for
either concern.

**Target:** unset.

### Severity: Low (dead code, with a doc comment that says otherwise)

No user device can hold the file. The only cost is code that runs for nothing and describes a
population that doesn't exist.

### What happens

`acceptReturnedShard` calls `migrateLegacyRestoreShardFile()` on every shard delivery
(`Vault+Manager+ReturnBuffer.swift`). It checks for `backup-import-cache-shards.dat` in Application
Support and, if present, decrypts it, absorbs its shards into `PendingShamirSecretRestore` rows and
deletes it. Its doc comment says it exists for "devices upgrading mid-restore, from a build old enough
to predate Bug 100's move off this file entirely", and that dropping the file "would strand a genuine
recovery".

No such device exists:
- `backup-import-cache-shards.dat` was introduced by `0e35dd6` (2026-08-25, Bug 93 Part D, renaming
  `pending-restore-shards.dat`), and writing it stopped with `284e145` (2026-08-27, Bug 100 remedy 2,
  shards into `ReconstructShard` rows).
- The only release tag containing either commit is `v1.10.3`, which contains both. Checked in the
  released trees: `v1.10.2` writes `pending-restore-shards.dat`. `v1.10.3` (released; tag `92e3e6e`,
  2026-09-02) names `backup-import-cache-shards.dat` only in this migration, which reads it, and in a
  comment, and writes shards as `ReconstructShard` rows. No shipped build wrote the file.
- So the migration shipped in `v1.10.3` never fired on a real device. It looked for the new name while
  `v1.10.2` devices mid-restore held the old one, which is how their restores died at the upgrade
  (Bug 127).
- Bug 127 already recorded this ("reads only `backup-import-cache-shards.dat`, which no release ever
  wrote"). Its remedy deletes `pending-restore-shards.dat` on unlock and wipe without salvaging it,
  because the restore it belonged to died at the v1.10.3 upgrade, and left this function alone.

So the file can exist only on a development device that ran a build from 2026-08-25 to 2026-08-27.

### Remedy (built)

Delete `migrateLegacyRestoreShardFile`, its two constants (`legacyRestoreShardsURL`,
`legacyRestoreShardsAAD`), its call in `acceptReturnedShard`, and the reference to it in
`ReconstructShard+Model.swift`'s header comment. Don't add the name to `deleteLegacyRestoreState`'s
list: no user has the file, and a development device can be reinstalled.

### Guard

None beyond the build: no test references the function. After the change, searching the source for
`backup-import-cache-shards` should find nothing outside `bugs.md`. Checked 2026-09-24: nothing in
`Occulta/` or `OccultaTests/`. (`Docs/Bugs/v1.10.3/` still names the function, as a record of that
release.)

---

## Bug 133 — Upgrading from v1.10.3 hides every existing vault entry: they have no `deletionToken`, which reads as orphaned

**Status:** Fixed 2026-09-24, on `v1.11.0/vault-key-layering`, and confirmed on the device that found it.
Found testing on a device: an entry created before the update was gone from the Vault tab.

**Target:** `v1.11.0`. **Release blocker.**

### Severity: High (data availability)

No data is destroyed by the upgrade itself, but every pre-update entry disappears from every read, and
two follow-on paths can make the loss real (below). It hits every user who upgrades with a non-empty
vault.

### What happens

Bug 110's fix (2026-09-10) added `VaultEntry.deletionToken`, a sealed live/orphaned sentinel. `addEntry`
writes a live token for every new entry. v1.10.3's `VaultEntry` had no such field, so every entry it
created has `deletionToken == nil` after the lightweight schema migration, and no migration ever filled
it in.

`VaultEntry.isOrphaned(usingKey:)` fails closed on a missing token (`guard let data =
self.deletionToken ... else { return true }`). Its doc comment claimed a nil row "cannot happen on this
branch", which holds for a fresh install and not for an upgrade. So every pre-update entry reads as
orphaned, and is excluded by:
- the Vault tab's filter, `Manager.Security.visibleVaultEntries` (v1.10.3's tab applied no such filter,
  which is why the entry showed before the update);
- `VaultManager.fetchAllEntries()`, the central read behind backup export, shard custody
  (`shardRecordsForTrustee`) and the return buffer.

**How the loss can become real:**
- **Export writes an incomplete backup.** `exportBackup` reads through `fetchAllEntries()`, so a new
  `.occbak` omits every pre-update entry. Worst if it replaces an older, complete backup.
- **The orphan cap can hard-delete them.** `Manager.Security.orphanVaultEntries` counts rows that
  already read as orphaned toward a cap of 50 and hard-deletes the oldest when orphaning more on
  deactivation. Pre-update entries count, and are the oldest. Needs 50 or more such rows, so unlikely
  on one device, but it is a real deletion path.
- Trustees holding shards of these entries' keys also stop seeing them in `expectedShards`, which reads
  as an implicit revoke (per `deletionToken`'s own doc comment), so they delete their copies.

Checked for the same mistake elsewhere: `BackupEncryptionKey`'s legacy row is carried forward explicitly
(`migrateLegacyBackupRowIfNeeded`), `PendingShamirSecretRestore` is new on this branch, and
`Contact.Profile.deletionToken` uses nil for live. Only vault entries are affected. The local key the
token is sealed under is derived the same way as in v1.10.3, and this branch no longer rotates it, so a
missing token is the only cause.

### Fix, as built

- **`DatabaseMigration.migrateVaultEntryDeletionTokens`** (`PQmigration.swift`), run from
  `OccultaApp.migrate()` at every launch. It gives every `VaultEntry` whose `deletionToken` is nil a live
  token, sealed per row under the local key exactly as `addEntry` does, and saves once. Idempotent.
- **Live is the correct value, not a guess:** every path that orphans an entry writes a sealed token, so
  nil can only mean the row predates the field. Undecryptable tokens are left alone and still read as
  orphaned, so the fail-closed design stands.
- **No trace:** every pre-field row is rewritten in the same pass, so the change says nothing about any
  one entry.
- The wrong claim in `isOrphaned`'s doc comment is corrected.

**Confirmed on a device, 2026-09-24:** on the phone that found it, installing the fixed build over the
existing one (not a reinstall) brought the hidden entry back.

### Guard

`VaultEntryDeletionTokenMigrationTests` (Enclave-gated):
- a pre-field entry is hidden from `fetchAllEntries()` before the migration, and live and returned after
  it; two such entries get different ciphertexts;
- entries that already have a token, live or orphaned, are left byte-identical;
- a second run changes nothing.

**What let it through:** no test ever built a `VaultEntry` the way v1.10.3 left it. Every test creates
entries through `addEntry`, which writes the token. The same gap applies to any field added with a
fail-closed reading of nil.

---

## Bug 134 — After the vault locks, the backup setup screen keeps showing its trustees and threshold, and Export fails silently

**Status:** Fixed 2026-09-25, on `v1.11.0/vault-key-layering` (`7e977f8`); not yet checked on a
device. Found checking which pushed vault screens react to a lock, after the restore screen's picker
case (`decisions.md`, "Restore discoverability", 2026-09-25 note).

**Changed 2026-09-29 (Bug 150):** the screen no longer navigates back on lock. It clears everything
seeded from the vault and shows a locked state with Unlock Vault in place; navigating back could be
ignored while the education sheet was up, and the screen could also be opened already locked.

**Target:** `v1.11.0`.

### Severity: Low (vault-key data visible after lock; a silent failure)

### What happens

The Vault tab swaps its root view for the lock screen when the vault locks, but screens already pushed
onto its navigation stack stay. `VaultEntryDetail` closes itself on lock; two others didn't.

- **`VaultShardSetup`** (reached from 7 places: the Vault tab, an entry's detail, the post-restore
  prompt and two Settings screens) keeps the trustee checkmarks and threshold it seeded from the
  distribution metadata, which is sealed under the vault key, in its own state. After a lock they stay
  on screen, while the status chips vanish on the next redraw (`fetchDistributionMeta()` reads with
  `try?`), so it reads as "nothing distributed" with the selection still showing. Distributing then
  fails with "Vault locked — unlock and try again", revoking with a generic "Revoke failed".
  The global trustee list is readable without the vault key anyway (contact records); this
  distribution's selection, threshold and status are not.
- **`BackupExportEducationView`** shows only fixed text, but "I understand — Export" after a lock calls
  `startExport()`, `exportBackup` throws `locked`, and the error is swallowed by an unfinished
  `// TODO: surface export error`.

The inactivity timer only resets when the vault key is used, so five minutes on either screen is
enough, as is leaving the app.

### Fix, as built

- **`VaultShardSetup` closes on lock,** clearing the seeded selection, threshold and pending revoke
  first: the same `onChange(of: vault.isUnlocked)` → `dismiss()` as `VaultEntryDetail`. One change covers
  all 7 entry points. It opens no system picker, so the concern that ruled closing-on-lock out for the
  restore screen doesn't apply. Unsaved selection changes are lost once the vault locks.
- **Export goes through `VaultManager.whenUnlocked`:** a lock since the screen opened means Face ID, then
  the export, as the restore paths do.

Not changed: other export failures are still silent (the existing TODO); choosing their message is a
separate decision.

### Guard

None automated: these are SwiftUI views with no test harness here, and the simulator can't unlock the
vault. Device check: open Backup Recovery (and an entry's Shard Distribution), wait five minutes or
leave the app, and confirm the screen has closed; open Export Backup, wait, tap Export, and confirm
Face ID appears and the export sheet follows.

**Related:** `VaultNewEntrySheet` had no lock handling either; filed and fixed as Bug 135.

---

## Bug 135 — A vault entry being typed stays on screen after the vault locks, and Save can't unlock

**Status:** Fixed 2026-09-25, on `v1.11.0/vault-key-layering`; not yet checked on a device. Found as the
related case noted under Bug 134.

**Target:** `v1.11.0`.

### Severity: Low (the secret being entered stays visible over a locked vault)

### What happens

`VaultNewEntrySheet` is a sheet on the Vault tab, presented independently of the lock, so it stayed
open when the vault locked. Two things lock it: the five-minute inactivity timer, which only counts
use of the vault key, so typing never reset it and a slowly typed seed phrase could outlast it; and
leaving the app (`willResignActive`). After that:
- **the label and content stayed on screen,** including the secret. `privacySensitive` only redacts
  system snapshots, not the live view;
- **Save failed with "Vault locked — unlock and try again",** but the sheet has no way to unlock. The
  only way out was Cancel, which discarded the entry.

### Fix, as built

- **Typing counts as vault activity in this sheet.** `VaultManager.extendSession()` resets the inactivity
  timer, only while unlocked, and the sheet calls it on every change to the label or content. The
  vault now locks only after five minutes without typing, or on leaving the app. Everywhere else only
  use of the vault key counts (`decisions.md`, "Typing in the new-entry sheet counts as vault activity").
  *(Superseded 2026-09-25 by Bug 136's fix: key use no longer counts anywhere; typing here is one of
  the deliberate actions that do.)*
- **On lock, the sheet clears the label and content and closes,** as `VaultEntryDetail` and
  `VaultShardSetup` do. Nothing typed is kept, in memory or anywhere else; the user unlocks and starts
  again. Chosen over hiding the fields and keeping the draft until Face ID. The cost, accepted: anything
  that briefly takes the app out of focus (a call, Control Center, a notification banner, switching
  apps to copy words) also discards the entry.

### Guard

`VaultManagerLifecycleTests` (`VaultTests.swift`): `extendSession` moves the inactivity deadline later
on an unlocked vault, and on a locked one leaves it locked with no timer. Both read the timer's deadline
(`VaultManager.inactivityDeadline`, internal for tests) rather than timing the lock: a first,
real-time version failed in full-suite runs both ways, kept unlocked by other tests' saves (Bug 136)
and locked early by main-thread contention, while passing on its own. The sheet is a SwiftUI view with
no test harness here. Device check: type for more than five minutes and confirm the vault stays
unlocked; stop typing for five minutes, or leave the app, and confirm the sheet has closed and is empty
when reopened.

---

## Bug 136 — Any save anywhere in the app resets the vault's inactivity timer

**Status:** Fixed 2026-09-25, on `v1.11.0/vault-key-layering`; not yet checked on a device. Filed the
same day, found when Bug 135's `extendSession` test failed in full-suite runs only: other tests' saves
kept its vault unlocked. **The scope turned out wider than saves; see "Wider than filed" below.**

**Target:** `v1.11.0`.

### Severity: Medium (weakens the inactivity lock)

### What happens

`VaultManager.init` subscribes to every `ModelContext.didSave`, from any context, and while the vault is
unlocked calls `recomputeRecoveryHealth()` (`Vault+Manager.swift`). That calls `currentKey()`
(`Vault+Manager+Shards.swift`), and `currentKey()` resets the inactivity timer on every success. The
hook's comment calls the extra recomputes "harmless"; each one extends the vault session.

So using any other part of the app that saves (sending a message, editing a contact, opening a file)
keeps the vault unlocked, not just using the vault. Nothing in the app was found to save on a timer
while idle (the only repeating timers are UI ones: the PIN countdown, the identity challenge's 30-second
tick), so an idle app still locks after five minutes. The rule the inactivity lock is built on, that
only use of the vault counts, doesn't hold.

### Wider than filed

It wasn't the save hook alone: `currentKey()` reset the timer on every success, so every automatic use
of the vault key extended the session:

| Use of the key | Triggered by |
|---|---|
| `recomputeRecoveryHealth()` | any save anywhere, through the `ModelContext.didSave` hook |
| `shardRecordsForTrustee(_:)` | building each outgoing message to a trustee (`expectedShards`), the lost-shard check |
| `markShardsLost(forContact:)` | a contact's key changing on an incoming message, or deleting a contact |
| `tryFinalizeReconstruction(entryID:)` | a returned shard arriving |
| `updateShardStatus(...)` from `ShardCustody+Manager.swift` | an incoming manifest confirming shards |
| `decryptLabelPayload` for the entry list | redrawing the Vault tab when data changes |

A first proposal, rejected in review: a `currentKey(extendingSession:)` parameter passed `false` by the
automatic callers. Deriving the key isn't activity at all, and a per-caller flag would drift as callers
are added.

### Fix, as built

- **`currentKey()` only derives the key;** its timer reset is removed. Lock condition 5 (lock on a
  derivation failure) is unchanged.
- **The session is extended only by `unlock` and `extendSession()`,** and the vault screens call
  `extendSession()` for the person's deliberate actions, 21 events in all (`decisions.md`, "Vault
  activity is the person's deliberate actions, not key use"): opening any vault screen, switching to the
  Vault tab, hold-to-reveal (once, when the hold starts), Copy, Delete, typing and choosing a type and
  Save in a new entry, choosing and picking a restore file, confirming export, ticking trustees and
  changing the threshold, distributing, revoking, and the post-restore prompt.
- **The save hook's comment** no longer calls the recomputes harmless for the session.

Behaviour change: the vault locks five minutes after the last deliberate action in it, whatever the
app does meanwhile. Reading a revealed entry without touching anything for five minutes locks it, and
using other tabs no longer keeps it open.

### Guard

`VaultManagerLifecycleTests` (`VaultTests.swift`), reading `VaultManager.inactivityDeadline`:
- `currentKey()` leaves the deadline unchanged;
- a save on an unrelated context leaves it unchanged once the hook has run (the filed case);
- `unlock` sets it one timeout from now; `extendSession` moves it later, and does nothing while locked.

The first two fail with the old reset put back into `currentKey()`. `locksAfterInactivity`, which
failed once in a full run for this bug, now waits 1 s rather than 150 ms past a 50 ms timeout, so a
busy main thread can't beat the timer. The UI calls have no test harness here; the event list in
`decisions.md` is what reviews check against. Device check: keep tapping in the vault past five
minutes and it stays unlocked; stay idle on a vault screen, or use other tabs, for five minutes and it
locks.

---

## Bug 137 — Upgrading from v1.10.3 deletes every banked recovery piece: the migration derives the key under a renamed HKDF info string

**Status:** Fixed 2026-09-26, on `v1.11.0/vault-key-layering`. Filed the same day, found by the branch
security review against `develop`, then confirmed against the `v1.10.3` tree.

**Target:** `v1.11.0`. **Release blocker.**

### Severity: High (data loss on upgrade)

Silent and permanent for anyone upgrading mid-recovery. Recovering needs every trustee to send their
piece again, in person-paired messages, and nothing tells the owner the pieces were lost.

### What happens

v1.10.3 banks returned recovery pieces in `ReconstructShard` rows: both backup-key restore pieces and
per-entry key reconstruction pieces. Each row's payload is sealed under
`deriveRecoveryBufferKey()`: ECDH with the shard-custody SE key, then HKDF with salt = that key's public
bytes and **info = `SaltInfo.kRecoveryBufferKeyInfo` = `"Occulta-v1-recovery-buffer-2026"`**.

`44c983e` ("Rename deriveRecoveryBufferKey to deriveRestoreVaultKey…") renamed the function and, with
it, the info string: `deriveRestoreVaultKey()` uses the same SE key and salt but
**`SaltInfo.kRestoreVaultKeyInfo` = `"Occulta-v1-restore-vault-2026"`** (`Key+Manager.swift:49`). A
different info string derives a different key.

`migrateReconstructShardsIfNeeded()` (`Vault+Manager+ReturnBuffer.swift`), run on every unlock, opens
each legacy row with `deriveRestoreVaultKey()`. No v1.10.3 row authenticates under it, and the function's
own rule is to delete a row it can't read (`defer { self.modelContext.delete(row) }`, then `continue`).
So the first unlock after upgrading deletes every banked piece without absorbing any of them.

The payload format is not the obstacle: v1.10.3's `Payload` has an `attestation` field and no `depth`;
the current one drops `attestation` and adds an optional `depth`. `JSONDecoder` ignores the unknown key
and reads the missing optional as `nil`, so a v1.10.3 payload would decode once decrypted.

**Why tests missed it:** `ReconstructShardMigrationTests` builds its legacy rows with
`km.deriveRestoreVaultKey()` while describing them as "sealed exactly as the retired mechanism used to
seal it". They are sealed with the new key, so the migration reads them. The same gap as Bug 133: no
test builds data the way the last release actually wrote it.

### Fix, as built

**`SaltInfo.kRestoreVaultKeyInfo` is back to `"Occulta-v1-recovery-buffer-2026"`,** v1.10.3's value. Same
SE key, same salt, same info: `deriveRestoreVaultKey()` produces v1.10.3's key again, and the migration
opens and absorbs every legacy row unchanged. The constant's doc comment says the value must never
change, and why the name and the string no longer match. Domain separation from the custody key is
unaffected (`distinctFromCustodyKey` still passes).

Rejected: keeping the new string and adding a legacy constant for the migration to try as well. The
rename had no security reason to change the key; HKDF info strings are protocol constants (as
`RUST_PACKAGES_SPEC.md` already states), and a second key would have been carried only to undo the
change.

**Cost, development phones only:** `PendingShamirSecretRestore` rows banked by this branch's builds were
sealed under the other string and no longer decrypt. `decodedSlots` reads such a row as empty, and the
next piece to arrive is saved into it under the reverted key, so collection carries on; the pieces
banked before the revert are lost. No release ever had that model.

### Guard

- `ReconstructShardMigrationTests` now seals its legacy rows under v1.10.3's derivation, with the info
  string written out literally (`TestKeyManager.deriveCustodySEKey(info:)`, made internal for this),
  not through the current constant. Against the renamed string, 5 of its 7 tests failed, reproducing
  this bug; all pass after the revert.
- `RecoveryBufferKeyTests.infoStringIsV1_10_3s` pins the constant's exact bytes and checks the derived
  key equals the literal-string derivation, so a future rename can't pass silently.

---

## Bug 138 — The v1.10.3 backup-key migration destroys the only copy of the key before the replacement is saved

**Status:** Fixed 2026-09-26, on `v1.11.0/vault-key-layering`. Filed the same day, found by the branch
code review against `develop`.

**Target:** `v1.11.0`.

### Severity: Medium (catastrophic loss, narrow trigger)

Nothing is lost on the ordinary path: the upgrade from v1.10.3 was checked on a device (`6242b9c`) and the
backup key survived. But on any failure between the two saves, or if the process dies between them, the
device's backup key is gone for good: every `.occbak` ever exported can no longer be restored, and the
pieces trustees hold rebuild a key nothing is sealed under. Nothing reports it.

### What happens

`VaultManager.unlock` runs `migrateLegacyBackupStorageIfNeeded` inside `try?`, which calls
`migrateLegacyBackupRowIfNeeded` (`Vault+Manager+Backup.swift`) for v1.10.3's single `BackupEncryptionKey`
row (`depth == nil && deletionToken == nil`). It:
1. decrypts and decodes the payload into memory (`try?`, so a failure gives `nil`);
2. **folds the legacy row into filler** (`foldLegacyRowIntoFiller`: random bytes over `encryptedPayload`,
   `depth` and `deletionToken`) **and saves**;
3. only then, `guard let legacyPayload else { return }`, and `backup.persist(...)` writes the key into a
   depth-0 row and saves.

So the only durable copy is destroyed at step 2, before the replacement exists on disk:
- **if decoding failed,** step 3 returns early and the key is simply gone;
- **if `persist` throws** (`localKey()` or sealing the depth stamp fails, `PayloadCodec.encode` throws, the
  seal or the save fails), the error vanishes into `unlock`'s `try?` and the key is gone;
- **if the process dies** between the two saves, the next unlock finds no legacy row and no depth-0 row.

The code contradicts its own documentation: `migrateLegacyBackupStorageIfNeeded`'s doc comment says a row
that decrypts but fails to decode "simply stays un-migrated and the next unlock tries again — safe, not
silent data loss". The fold-first order was chosen so `persist`'s filler-claiming can't pick the legacy
row by chance (`isUnclaimed` is true for a nil `depth`); that concern is real, but it doesn't need the
fold to be saved first.

The array path next to it (`migrateBackupArrayIfNeeded`) doesn't have this problem: it persists each slot
first and deletes the file only after every slot is committed.

### Remedy (built)

Make the migration all-or-nothing and leave the legacy row alone whenever the key can't be carried over:
- **Decode first; on failure, touch nothing.** Return without folding, so the next unlock retries, as the
  doc comment promises.
- **Stage the new row, fold the legacy row, then save once.** Use `Backup.stage` (it doesn't save), making
  sure it doesn't claim the legacy row itself (claim with the legacy row excluded, or if it does claim it,
  skip the fold, since sealing the new payload into that row already replaces its content). Then fold and
  call `save()` once. On any error, `modelContext.rollback()`, which restores the legacy row.

As built: after `stage`, the legacy row is folded only if its `depth` is still nil, meaning `stage` claimed
a different row. The decrypted plaintext is zeroed after decoding. `migrateLegacyBackupStorageIfNeeded`'s
"stays un-migrated … the next unlock tries again" promise now holds, and says since when.

Behaviour change, accepted: a legacy row that can never decode (for example, sealed under a vault key that
no longer exists) used to be folded into filler as a side effect. It now stays in its nil/nil state, and
each unlock tries it again cheaply. That row is only a leftover of the pre-refactor format; keeping it
rules out ever destroying a key that could have been recovered.

### Guard

`BackupKeyLegacyStorageMigrationTests` (`BackupEncryptionKeyStorageTests.swift`), rows built the way
v1.10.3 left them (depth and token nil, payload JSON-encoded, sealed under the vault key with `row.aad()`):
- `undecodableLegacyRowIsUntouched`: a payload that decrypts but won't decode leaves the row
  byte-identical, still nil/nil, and no depth-0 key;
- `failureAfterStagingRollsBack`: 256 shard records decode from JSON but make `PayloadCodec.encode` throw
  `tooManyShards` inside `stage`, after a depth-0 row is claimed; the error surfaces, the legacy row is
  byte-identical, and there's no depth-0 key. No seam needed;
- the existing `migratesLegacyRowOnly` stays green on both versions.

Both new tests fail against the pre-fix migration.

---

## Bug 139 — Keys left by an interrupted v1.10.3 key rotation are never deleted, not even by "Erase all data"

**Status:** Fixed 2026-09-26 for the wipe, on `v1.11.0/vault-key-layering`; the optional launch clean-up
is not built. Filed the same day, found by the branch code review against `develop`.

**Target:** `v1.11.0`.

### Severity: Low (forensic trace that survives a panic wipe; narrow trigger)

Needs a v1.10.3 activation or deactivation of Secure Mode that was interrupted (app killed, crash, a
failed keychain call) partway through its key rotation. Where it happened, the leftover items outlive
every later wipe, and their names say what they were for.

### What happens

v1.10.3 rotated the local database key on every Secure Mode activation and deactivation, using three
items besides the canonical ones (`Key+Manager.swift` in `v1.10.3`):
- SE key `local.db.se.key.occulta.staged` and keychain item `local.db.random.key.occulta.staged`,
  created by `createStagedLocalDBKey()`;
- SE key `local.db.se.key.occulta.superseded`, the old canonical key, renamed by
  `commitStagedLocalDBKey()`.

On success, step 11 called `deleteSupersededLocalDBArtefacts()`; on failure, `rollbackStagedLocalDBKey()`.
An interruption between those points left items behind, and v1.10.3 had two things that removed them
later: `createStagedLocalDBKey()` rolls back leftover staged items before starting, and
`Manager.Key.deleteAllKeys()` swept all three on "Erase all data".

This branch removed key rotation (Removal Stages 0-3, `plan.md`), and with it both clean-ups. `plan.md`
records dropping the wipe's sweep on the grounds that "nothing rotates any more, so there is never a
transient artefact to sweep". That holds for new installs, not for a device upgraded from v1.10.3 that
already has leftovers. Nothing on this branch reads or deletes those three names (confirmed by search).
So on such a device they stay forever, including after "Erase all data", and a keychain dump shows
items named `…staged` / `…superseded`: evidence that Secure Mode was activated, surviving the very
wipe meant to leave nothing. The same class as Bug 133 and Bug 137: an upgrade path from what v1.10.3
actually left on disk.

They grant nothing: the old random component is overwritten at commit, and the wipe deletes the
canonical SE key, so no leftover can re-derive a key that decrypts anything.

### Remedy

- **Built: the wipe deletes the three legacy names again.** `Manager.Key.deleteLegacyRotationArtefacts()`
  deletes the two SE keys and the keychain item under private constants that nothing else uses, and
  `deleteAllKeys()` calls it; missing items count as deleted, so a device that never had leftovers still
  wipes cleanly. Keep them as private constants used only for
  deletion, and delete them in `deleteAllKeys()`. Always safe there: after a wipe there is no data left
  that any of them could be needed for.
- **Not built: optionally, clean up once at launch, but only in unambiguous states.** A blind delete is not safe:
  if a v1.10.3 commit stopped between sub-step A (canonical → `.superseded`) and sub-step B (`.staged` →
  canonical), the key the data is sealed under sits at `.superseded`, and nothing holds the canonical
  name. Delete leftovers only when the canonical key demonstrably opens existing data (for example a
  `VaultEntry.deletionToken` or an `AppLayerConfig` field); otherwise leave them.

Out of scope, pre-existing: an interrupted v1.10.3 rotation could already leave data sealed under a key
the canonical name no longer holds (v1.10.3 had no launch-time recovery either). Recovering that is a
separate problem; the launch rule above only has to avoid making it permanent.

### Guard

`LegacyRotationArtefactTests` (`OccultaTests/SecureMode/`): creates the two SE keys and the keychain item
under the names written out as v1.10.3 used them, calls `deleteLegacyRotationArtefacts()`, and asserts all
three are gone; and with nothing there, deletion still reports success. Both are Enclave-gated: without one,
deleting an SE-token key reports neither success nor not-found (the second was ungated until CI on PR #76
failed it, 2026-09-29). It tests the
helper rather than `deleteAllKeys()`, which would delete the canonical keys other tests in the process
use. If the launch clean-up is built: a test per state (post-commit leftovers deleted; staged-only
leftovers deleted; canonical missing with `.superseded` present, left untouched).

---

## Bug 140 — Session state outlives the session: nothing clears it at a new unlock or an in-place depth change

**Status:** Fixed 2026-09-26, on `v1.11.0/vault-key-layering`; not yet walked through on a device or in
the simulator. Found by the branch code review against `develop` as a pending restore prompt surviving the
PIN screen; rewritten the same day around the invariant that case breaks.

**Target:** `v1.11.0`.

### Severity: Medium (state from one session, at one depth, reaches the next, possibly a coercer's)

### The invariant

Everything the app holds in memory is one of two kinds:
1. **Input queued before anyone authenticated.** A file or share that arrives while the PIN screen is up
   (`pendingFileData`, `pendingShareSession`, a `.occbak` opened at the PIN screen) is kept on purpose and
   delivered after whichever PIN is entered, the same at every depth; treating it differently by depth
   would itself be a tell.
2. **State created during an authenticated session, at one depth.** Presented screens and sheets,
   decrypted content, unanswered decisions (a pending prompt, a draft, a trustee selection), values
   computed for "this depth", and an unlocked vault. This must end when the session or the depth changes:
   the next session may be someone else, in another layer.

The code has no single boundary where kind 2 ends.

### Two ways the session changes, and what each clears today

1. **Leaving `.unlocked`** (the PIN screen after the grace period). `AppScreen` switches to
   `.pinRequired`, which tears down the unlocked view tree, so state *inside* it goes. State held *above*
   it, on `RootView` or in the managers, survives unless cleared by hand. `RootView`'s
   `onChange(of: appScreen.phase)` clears a hand-picked list, `openedFileContents` and `shareResult`,
   because "their item state outlives the branch … otherwise the next unlock re-presents a sheet the user
   already finished with". The restore prompt added on this branch (`pendingRestoreFile`,
   `showRestoreConfirmation`) isn't on the list: the same manual-sync weakness as Bug 126.
2. **Depth changing while the app stays unlocked.** `Manager.Security.deactivateSecureMode` moves
   `currentDepth` from N to N−1 in place, called from `SecureModeDeactivateFlow` in Settings; no PIN screen,
   nothing torn down, nothing cleared. (`forceDeactivateForRecovery`, which moves to 0 the same way, has no
   caller in the app today.)

### What survives, and into which session

| State | Held by | After the PIN screen | After an in-place depth change |
|---|---|---|---|
| Pending restore prompt and the `.occbak` bytes | `RootView` | **survives** | **survives** |
| An opened message, a share result | `RootView` | cleared | **survives** |
| The vault's unlocked session (`authContext`) | `VaultManager` | locked (the app resigned active) | **survives: the new depth has an unlocked vault with no Face ID of its own** |
| Post-restore prompt, recovery health, backup erosion, staleness | `VaultManager` | cleared on lock | **survives, computed for the old depth until a view refreshes it** |
| Pushed vault screens (an entry's detail, backup setup) and their cached `@State` | the Vault tab's navigation stack | torn down | **survives: switch to Settings, deactivate, come back, and the old depth's screen is still open** |

The case that surfaced this: the owner opens their real `.occbak` and leaves without answering. Past the
grace period a coercer enters the duress PIN; the unlocked tree is rebuilt around the same `RootView`
state, the owner's file bytes are still held, and the "Restore from this backup?" prompt can be offered
in the duress layer. That both tells the coercer a restore was in progress and lets Accept run the
owner's restore there, completing whenever the owner's trustees are visible in that layer (the case Bug 99
and §9.4 accept), without the coercer ever holding the file. Whether the prompt itself reappears depends
on SwiftUI writing `false` back to `showRestoreConfirmation` when its host is torn down; the bytes stay
either way.

### Remedy: one session boundary (as proposed; see "Built" below for where it differs)

- **A session identifier** owned by `Manager.Security`, changed on every successful unlock and every
  in-place depth change.
- **The unlocked view tree keyed by it** (`.id(session)` on the `.unlocked` branch). A change rebuilds the
  whole tree, discarding every pushed screen, sheet and cached `@State` at once, with no list to keep.
- **State above the tree resets through one hook** on the same change: `RootView` clears its
  session presentations (replacing the hand-picked clearing in the phase handler), and `VaultManager`
  locks and drops its depth-scoped values, so a new depth needs its own Face ID.
- **Queued input is exempt by an explicit, documented list** kept outside the session scope on purpose:
  `pendingFileData`, `pendingShareSession`, and a `.occbak` staged while `.pinRequired`.

### Built

- **`Manager.Security.sessionID`** changes in `setState` whenever the depth actually changes, which is the
  in-place case (`deactivateSecureMode`). It does **not** change at a PIN unlock, unlike the proposal:
  `applyVerifyState` and the phase flip run in one synchronous block, so their two `onChange` handlers
  would fire in one SwiftUI update in no guaranteed order, and a reset there could race the delivery of a
  file queued at the PIN screen. The PIN path doesn't need it: the PIN screen tears the unlocked tree down,
  and the reset runs on leaving `.unlocked`.
- **`RootView.endSession()`** is the one reset: it clears `openedFileContents`, `shareResult`,
  `pendingRestoreFile`, `showRestoreConfirmation`, `showNothingRestored`, `showError`, the identity
  challenge's three presentations (`outboundShare`, `incomingChallenge`, `verificationOutcome`, also held
  above the tree), and calls `vaultManager.lock()`. It runs when the phase changes *from* `.unlocked` (not
  on a cold launch's `.covered` → `.pinRequired`, which may already have staged the file that launched the
  app), and on every `sessionID` change. It replaces the phase handler's hand-picked clearing.
- **`.id(self.security.sessionID)`** on the `.unlocked` branch rebuilds the whole tree on an in-place
  depth change. The selected tab moved up into `RootView` (`selectedTab`, bound to the `TabView`) so it
  survives; it isn't sensitive.
- **`VaultManager.lock()`** now also clears `backupStaleness`, the one depth-scoped value it missed.
- **The exempt list** is one comment above `RootView`'s session state: `pendingFileData`,
  `pendingShareSession`, and a `.occbak` staged while `.pinRequired`. No separate queued slot was needed:
  such a file is staged after the reset, so it reaches the prompt after the PIN.

Accepted edge: a `.occbak` whose read finishes before a warm return's phase change to `.pinRequired` is
cleared with the session; the owner reopens it. The read is asynchronous, so the file normally lands after.

Out of scope, worth its own look: which depth `deactivateSecureMode` lands on when used from a duress
depth. The boundary makes any in-place change safe to leave behind; whether that transition should be
allowed is a separate question.

### Guard

- `SessionIdentifierTests` (`SecureModeActivationTests.swift`): the identifier changes when
  `deactivateSecureMode` moves the depth (2 → 1), and stays the same through PIN setup, activation, a wrong
  PIN and a same-depth verify.
- `VaultManagerLifecycleTests.lockClearsStaleness`: `lock()` clears `backupStaleness`, recovery health,
  erosion and the post-restore prompt.
- `RootView` and the view tree can't be built in a unit test. Device or simulator check (needs a PIN):
  open a `.occbak`, leave without answering, return past the grace period, enter a PIN, and confirm no
  prompt; open an entry, switch to Settings, deactivate, return to the Vault tab, and confirm the entry is
  closed and the vault asks for Face ID; open a `.occbak` while the PIN screen is up and confirm the prompt
  appears after the PIN.

---

## Bug 141 — Messaging a trustee with the vault unlocked makes them delete their backup-key piece: `expectedShards` never lists backup-key pieces

**Status:** Fixed 2026-09-27 (`ba57be1`, see "Built" below); filed and reproduced 2026-09-26,
remedy decided the same day. Found while inventorying per-entry shard splitting for retirement.
**Shipped:** `v1.10.3` builds the list the same way.

**Target:** `v1.11.0`. **Release blocker, and a blocker for retiring per-entry splitting.**

### Severity: High (silent loss of backup recoverability)

A restore needs k trustees' backup-key pieces. Ordinary messaging destroys them, the owner's app keeps
showing the backup as healthy, and the loss surfaces only when a restore fails, after the phone is gone.

### What happens

Every outgoing bundle from the owner to a contact carries `expectedShards`, "the IDs the owner expects
this trustee to hold", built by `ShardCustodyManager.buildExpectedShards` from
`VaultManager.shardRecordsForTrustee`. That function reads **only per-entry distribution records**
(`VaultEntry.shardDistributionEncrypted`); backup-key pieces, recorded in the `BackupEncryptionKey`
payload's `ShardDistributionMetadata`, are never included. Senders:
- `ComposeViewModel` (1:1 messages) and `RootView`'s share flow (`OccultaApp.swift`): `try?`, so the field is
  `nil` when the vault is locked and the list, possibly empty, when it is unlocked;
- `ContactManager`'s group path: per recipient, `[]` on failure with `shardMetadataAttempted` false.

`[]` is encoded (`encodeIfPresent` omits only `nil`), and the bundle's own doc comment defines it as "holds
nothing". On the trustee, `handleInbound` → `processExpectedShards` deletes every custody piece from that
owner, under the owner's current fingerprint, that isn't listed. It doesn't distinguish backup-key pieces
(`"vault-bek-shard"`) from per-entry ones.

So whenever the owner sends a trustee anything with the vault unlocked:
- **owner who split no entry:** the list is `[]`, and the trustee deletes all of that owner's pieces;
- **owner who split entries:** the list holds those entries' piece IDs only, and the trustee still deletes
  the backup-key piece.

When the vault is locked the list isn't sent, so nothing is deleted; that may be why the device upgrade
check (`6242b9c`) saw a healthy backup.

### Reproduction

Alice (`TestKeyManager`) sets up a backup at depth 0 and splits it for Bob and Carol
(`prepareBackupShards`); Bob's `ShardCustodyManager` receives his piece (`handleInbound`, `.distribute`).
With Alice's vault unlocked, `buildExpectedShards(for: bob, vaultManager: alice)` returns `[]`; Bob
processes a bundle carrying it. Bob's custody pieces: **1 before, 0 after.**

### The owner never finds out

- The status Alice sees is her own record (`confirmed`), not the trustee's state.
- Absence detection can't see it either: when Bob's `custodyManifest` later omits the piece,
  `drainPotentiallyLostShards` checks the missing ID against `shardRecordsForTrustee`, which knows only
  per-entry records, so a backup-key piece is never marked `.lost`. `markShardsLost` (a contact's key
  change) is per-entry only too.
- So "Backup Recovery" and `backupErosion` keep reporting a healthy backup.

**Why tests missed it:** every `expectedShards` test uses per-entry pieces (`makeShardAttr`, label
`"vault-shard"`); none sends a backup-key piece through `buildExpectedShards` to a trustee.

### Remedy: needs a decision (depth)

Backup keys are per depth, and one trustee can hold the owner's pieces from several depths. What a message
sent at depth *d* should say about backup-key pieces isn't obvious:
1. **List only depth *d*'s backup-key pieces:** the trustee deletes the owner's pieces from every other depth
   it holds, so using the app at one layer destroys another layer's backup.
2. **List every depth's backup-key pieces:** the owner's device, at any depth, enumerates other depths'
   backup keys to build a bundle, and a trustee comparing lists from different sessions can see there are
   pieces the current layer doesn't account for.
3. **Take backup-key pieces out of implicit revoke:** the trustee never deletes a `"vault-bek-shard"` piece
   because of `expectedShards`; those are replaced or removed only by `.replace`, a new-fingerprint
   `.distribute`, or `purgeCustody`. Depth-neutral and simple. The cost: a trustee dropped from a
   redistribution keeps their old piece, and because the backup key is reused across trustee changes
   (`decisions.md`, "Reuse the same BEK across trustee-set changes"), k such dropped trustees colluding could
   still rebuild it.

Whichever is chosen, `drainPotentiallyLostShards` and `markShardsLost` need backup-key records so a lost
piece shows up in the owner's backup health.

A fourth option was added in discussion: **generate a new backup key whenever a trustee is removed.** Option 2
was rejected because the owner's device would read other depths' backup keys to build a bundle, and v2.0.0
derives each depth's keys from its own passphrase (`PASSPHRASE_LAYER_KEYS.md`), so no depth can read another's.
Every part of the remedy has to work from the current depth's own data.

### Decision, 2026-09-26

**Option 3 + option 4, plus automatic re-sending.** Recorded in `decisions.md`, "Rotate the backup key when
a trustee is removed; re-send automatically otherwise".

1. **Implicit revoke and the `expectedShards` field are removed (option 3, widened 2026-09-27).**
   - The field goes from every payload that carries it (`WireHandle`'s 1:1 payload, `SealedPayload`, the
     group recipient payload with `expectedShardsCount`), with its three builders, `buildExpectedShards`,
     `handleInbound`'s parameter and `processExpectedShards`.
   - Old bundles still decode: every payload reads the field with `decodeIfPresent` from a keyed container,
     which ignores keys it doesn't know, so a `v1.10.3` owner's `[]` is dropped unread. A `v1.10.3` trustee
     decodes a missing 1:1 field as `nil` and deletes nothing.
   - **Groups always send `shardMetadataAttempted = false`.** A `v1.10.3` member reads a group recipient's
     list as `attempted ? prefix(expectedShardsCount) : nil`, and a missing list decodes as `[]` with count 0,
     so `attempted = true` would tell it to delete every piece it holds from us. The flag also gates the
     manifest, so our group messages carry no manifest; the block building both for group recipients goes.
     Manifests still travel in 1:1 messages and the share flow, and a `v1.10.3` sender's group manifest is
     still read. Re-enabling group manifests for new members (a capability bit plus version gating) was
     rejected: it only speeds up absence detection.

   First decided as an exemption for backup-key pieces only, checked by `label != "vault-bek-shard"`, with the
   owner sending `nil`. Changed the same weekend, first to ignoring the field, then to removing it: the label is the only field that tells the two kinds apart (`category`, value
   size and `entryID` are the same shape for both), it isn't covered by the signature, and no code had ever
   read it. With the owner no longer sending the list, the only lists left come from `v1.10.3` owners, and
   the one thing lost is such an owner removing a per-entry piece by omission; per-entry splitting is being
   retired, and `.replace` still removes pieces.
2. **Removing a trustee generates a new backup key (option 4).** A distribution that drops any trustee
   splits a freshly generated key instead of the current one, in the same save. Only a new secret makes the
   removed trustee's piece useless: the distribution ID is a label for grouping on restore, and any k pieces
   of the old split still rebuild the old key whatever they are labelled. Every `.occbak` exported before
   the change stops being restorable, so the owner confirms the removal knowing that, and the backup status
   asks for a new export. Adding a trustee, or re-sending, keeps the key.
3. **A piece the trustee no longer has is re-sent automatically; the owner does nothing.** Two triggers,
   both depth-local:
   - the trustee's identity key changes (only possible through the in-person key exchange,
     `KeyExchange.swift`), handled at the current depth at once;
   - a confirmed piece is missing from the trustee's `custodyManifest`, handled by each depth at its own
     next vault unlock. This also catches a key change for the depths that weren't current: the trustee's
     new phone reports holding nothing.

   Re-sending re-splits the **same** key for the same trustees and threshold, and queues `.replace` for
   each; the owner doesn't keep the old split's coefficients, so a single piece can't be re-created. Until
   k trustees have the new split, restore relies on the old split's pieces, which are no longer revoked.
4. **Lost** is kept for what a re-send can't fix: a trustee whose contact was deleted. That shows through the
   existing backup erosion warning, and the owner removes them, which is step 2.
5. **Bug 142's queue fix:** before queuing a new split, the depth deletes the queued rows, and the watch rows
   below, of its previous split, found by its own previous `distributionID`.

### Found while designing the fix, 2026-09-26

Three defects the decision depends on, fixed with it:
- **Absence detection works once per piece.** `processInboundManifest` inserts a `PotentiallyLostShard` watch
  row only when a queued piece is first confirmed, and `drainPotentiallyLostShards` deletes **every** row at
  every vault unlock. After one unlock nothing watches the piece, so a later disappearance is never seen.
  Watch rows become persistent: removed only when their split is replaced or their contact deleted, and
  created at unlock for any confirmed backup-key piece that lacks one.
- **Backup-key status updates read every depth's backup key.** `Backup.updateShardStatus` tries each live
  `BackupEncryptionKey` row until one holds the ID (reached from `processInboundManifest`,
  `drainPendingShardStatusUpdates` and `markForDistribution`), which the decision above rules out. Backup-key
  status is instead reconciled by the current depth against the watch rows: at vault unlock, and when a
  manifest arrives while the vault is unlocked.
- **Every redistribution reports "BEK rotated — Existing backup file is permanently unrestorable".**
  `refreshBackupStaleness` detects rotation by comparing `distributionID`s, and since Bug 124 every
  redistribution mints a new one. The export record stores a key identifier derived from the backup key
  instead (HKDF, 16 bytes, in the same field). An existing record still matches if it holds the current
  `distributionID`, so an upgrade doesn't show a false warning.

**Related, filed 2026-09-26:** Bug 142. Redistributing never removes the previous split's queued pieces,
so a trustee removed before delivery still receives theirs. That part is a queue fix; a removed trustee
whose piece was already delivered is this entry's decision.

### Guard

A test through the real paths: owner sets up a backup and distributes; a trustee receives a piece; the owner,
unlocked, builds `expectedShards` for that trustee (with no entries split, and with one split); the trustee
processes it; the backup-key piece is still there. Plus: a piece missing from a later manifest is marked
`.lost` in the backup-key metadata.

**Revised with the decision, 2026-09-26.** The guards become:
- a bundle from a `v1.10.3` owner carrying `expectedShards: []` decodes, and the trustee keeps every piece;
- our group recipient payloads always have `shardMetadataAttempted == false`;
- dropping a trustee changes the backup key, and an old `.occbak` no longer opens; adding one doesn't;
- a trustee's key change re-queues a piece for every current trustee, at the current depth only;
- a confirmed piece missing from a manifest is re-sent at that depth's next unlock, and still after an
  earlier unlock (the watch row persists); another depth's pieces are untouched;
- a redistribution without a key change doesn't report "BEK rotated"; a rotation does.

### Built, 2026-09-27

- **Wire:** `expectedShards` removed from `SealedPayload`, `WireHandle`'s metadata, the group
  `RecipientPayload` (with `expectedShardsCount`) and `GroupRecipient`; the group path always sends
  `shardMetadataAttempted: false` and no manifest (`GroupRecipient` no longer carries one, and
  `encryptGroupBundle` lost its `vaultManager` parameter, as did `ComposeViewModel.encrypt` and its four
  callers). `processExpectedShards` and `buildExpectedShards` are deleted.
- **Rotation:** `Backup.prepareShards(newKey:)` splits a fresh key in the same save.
  `ShardCustodyManager.distributeBackup` re-splits, deletes the previous split's queued and watch rows, and
  queues `.replace`/`.distribute`. `VaultShardSetup` in backup mode asks "Remove trustee?" when the selection
  drops a current trustee, then splits a new key; its per-trustee "Revoke Shard" menu is entry-mode only.
- **Reconcile:** `ShardCustodyManager.reconcileBackupPieces`, from `RootView` at vault unlock, after every
  inbound bundle, and on `contactKeyRotated`. `Backup.updateShardStatus` (the all-depths scan) is replaced
  by the depth-local `setShardStatuses`; `VaultManager.updateShardStatus` is per-entry only.
  `drainPotentiallyLostShards` keeps backup-key watch rows.
- **Staleness:** the export record stores `backupKeyIdentifier(for:)` (`keyID`). Settings' Vault Recovery screen now
  words the warning as the Vault tab does ("Backup can't be restored" / "Backup key changed — export a new
  backup", was "BEK rotated"), and drops "BEK" from its other strings; the "not set up" row pointed to
  Export, which fails without a key, and now points to Backup Key Trustees, where the key is created.
- **Tests:** `BackupPieceReconcileTests.swift` (12), three staleness/rotation tests in
  `VaultBackupRoundTripTests`, group-payload tests in `GroupEncryptTests`; the implicit-revoke tests in
  `ShardManifestTests` and `ShardCustodyTests` are deleted, and backup-key tests confirm pieces through
  `setBackupShardStatuses`.
- **Not handled:** per-entry revoke (the context menu, `.revokePending`) no longer reaches trustees. Resolved
  2026-09-27: per-entry splitting was retired (`Docs/General/decisions.md`, "Retire per-entry splitting"). `Backup.distributeShards` has no callers (pre-existing).
- **Full suite:** 928 tests, 922 passed, 0 failed, 6 skipped (the `KeychainMigrationSETests` baseline).
  Not walked through on a device: the "Remove trustee?" prompt, and a re-send reaching a real trustee.

---

## Bug 142 — Redistributing leaves the superseded split's pieces queued: a removed trustee still gets one, and kept trustees get old and new together

**Status:** Fixed 2026-09-27 with Bug 141 (step 5, `ba57be1`); remedy decided 2026-09-26. Found while verifying how backup-key pieces reach trustees after a trustee-list change, for Bug 141's
decision; reproduced with a throwaway test.

**Target:** `v1.11.0`.

### Severity: Medium (revocation fails before delivery; stale pieces kept)

### What happens

Distributing pieces queues one `PendingShardDistribute` row per trustee (`ShardCustodyManager.queueDistribute`,
from `VaultShardSetup.markForDistribution`). Every outgoing message to that contact carries all of its queued
rows (`buildShardOperations` → `pendingDistributeOps`, on the 1:1, share-flow and group paths) until the
trustee's manifest lists the piece and `processInboundManifest` drops the row. That part works: after a
change, added trustees get `.distribute` and kept trustees `.replace` with their next message.

What nothing does is remove the **previous split's** queued rows when the depth redistributes.
`markForDistribution` marks removed trustees' pieces `.revoked` and queues the new split, but never touches
the queue, and `queueDistribute` only deduplicates identical pieces. Reproduced with trustees A, B, C, then
the list changed to A, B, D before anything was delivered:

```
backup key regenerated on mutation: false
A (kept):    distribute(round1), replace(round2, replaces)
B (kept):    distribute(round1), replace(round2, replaces)
C (removed): distribute(round1)
D (added):   distribute(round2)
C's record in current metadata: nil
```

- **A removed trustee still receives their piece.** C's next message delivers the round-1 piece although C
  was dropped. C's record is also gone from the backup's metadata (`prepareShards` writes the new recipient
  list only), so the owner has no trace that C holds anything. Because the backup key is reused across
  trustee changes, that piece works together with any other round-1 piece.
- **Kept trustees receive the stale piece and its replacement in the same message.** The two rows go out in
  fetch order, which isn't guaranteed. If `.replace` is processed first it deletes nothing (the old piece
  hasn't arrived yet), then `.distribute` stores the round-1 piece, and the trustee ends up holding both. The
  stale one never goes away: implicit revoke can't remove backup-key pieces correctly (Bug 141).

The per-entry split path has the same shape; it is being retired.

### Remedy (proposed, not built)

When a depth redistributes its backup key, delete the queued rows of the split it replaces before queuing
the new one: rows whose piece carries the depth's previous `distributionID` (the attribute's `entryID`).
The depth reads only its own `BackupEncryptionKey` row to find that ID, so it stays depth-local, as Bug 141
requires. A removed trustee whose piece was **already delivered** is a revocation, and falls to Bug 141's
decision; if that is option 4 (a new backup key whenever a trustee is removed), such pieces become harmless.

### Guard

A test through the queue: distribute to A, B, C; change to A, B, D before delivery; then C's next message
carries no piece, A's and B's carry only the round-2 piece, and D's carries its round-2 piece. Also: a piece
already confirmed by C is outside this fix (Bug 141).

**Decided 2026-09-26:** Bug 141 chose option 4, so dropping C also generates a new backup key; a piece C
already holds then opens nothing exported afterwards.

---

## Bug 143 — A trustee who only messages the owner in groups never confirms their backup-key piece, so export stays blocked

**Status:** Accepted limitation, decided 2026-09-28 (option B below); the wording is built.
Found by the branch code review of 2026-09-28, as a consequence of Bug 141's fix.

**Target:** `v1.11.0` (the wording change only).

### Severity: Low (export delayed, nothing exposed)

### What happens

Bug 141's fix sends `shardMetadataAttempted = false` to every group recipient: a `v1.10.3` member reads `true`
with no expected-shards list as "delete every piece you hold from me". The same flag gates the custody
manifest, so a trustee's group messages carry no manifest; only 1:1 messages and the share flow do. A piece
is confirmed only when a manifest lists it (`reconcileBackupPieces`), so:

- a trustee who writes to the owner only in groups never confirms, however many group messages they send;
- the queued piece rides along in every group message the owner sends them (pieces still go out in groups);
- `backupSetupState` stays `waitingForConfirmations`, and `exportBackup` refuses below the threshold.

It ends as soon as the trustee sends the owner a 1:1 message.

### Options considered

- **A. Group manifests again for members on this version:** a capability case derived from `appVersion`,
  `shardMetadataAttempted = true` and a real manifest only for members at or above it, manifest padding
  restored across the membership. About 30 lines. Not chosen.
- **B. Accept it, and say so where the owner waits:** the "awaiting confirmations" status says that
  confirmations arrive with a trustee's next direct message. **Chosen, 2026-09-28.**

### Guard

None beyond the wording; `shardMetadataAttempted == false` for group recipients is pinned by
`GroupEncryptFallbackTests`.

---

## Bug 144 — A trustee left out of a redistribution without being deselected keeps a valid backup-key piece: hidden, ineligible and deleted trustees don't trigger a new key

**Status:** Fixed 2026-09-28 (see "Built" below). Filed the same day, found by the branch code
review of 2026-09-28 (findings 1 and 2).

**Target:** `v1.11.0`. Undoes part of Bug 141's guarantee.

### Severity: Medium (a removed trustee keeps a working piece)

### What happens

Bug 141 made a distribution that drops a trustee split a new key. What counts as "dropped" misses three cases:

- **Hidden or no longer ML-KEM-capable.** `VaultShardSetup.commitDistribution` splits to
  `mlkemContacts ∩ selectedIDs`, but `droppedBackupTrustees()` compares the record with `selectedIDs`.
  `seedInitialState` puts every current trustee in `selectedIDs`, including one now hidden at this depth or
  without quantum material, who isn't listed on screen. Changing only the threshold re-splits without them,
  with no prompt and no new key.
- **Deleted.** A deleted trustee's piece is marked `.lost`, and `droppedBackupTrustees()` counts only
  `.pending`/`.confirmed` records, so leaving them out never rotates.
- **Automatic re-send.** When another piece goes missing, `reconcileBackupPieces` re-splits the **same** key for
  the live trustees, leaving the deleted one out.

In each case the left-out trustee still holds a piece of the current key, which rebuilds it with k−1 others of
the same split, against every backup exported afterwards. Deleting a contact is the owner dropping them.

### Remedy (built 2026-09-28)

One rule, owned by `ShardCustodyManager`: a distribution splits a new key whenever anyone in the depth's
current record, of any status, is missing from the real recipient list
(`distributionDropsTrustee(recipients:currentDepth:vaultManager:)`). `distributeBackup` applies it itself and
stops taking `newKey`; the setup screen asks it, with the real recipients, whether to prompt; reconcile skips
the automatic re-send while any trustee is lost, leaving the erosion warning for the owner, since a re-send
would have to rotate and rotating silently breaks exported backups.

### Guard

Dropping a pending, confirmed or lost trustee rotates; adding one or changing only the threshold keeps the key;
reconcile doesn't re-send while a trustee is lost.

### Built, 2026-09-28

- `ShardCustodyManager.distributionDropsTrustee(recipients:currentDepth:vaultManager:)` is the rule;
  `distributeBackup(threshold:recipients:currentDepth:vaultManager:)` applies it and no longer takes `newKey`.
- `VaultShardSetup` asks it with `recipientIDs` (selected ∩ `mlkemContacts`), the list it distributes to;
  `droppedBackupTrustees()` is gone.
- `reconcileBackupPieces` re-sends only when every trustee in the record is active and still a contact, and then
  to the whole record.
- Same pass, from the same review:
  - `distributeBackup` deletes the previous split's rows first, then persists, then queues in one save, so a
    failure leaves pending pieces with nothing queued, which reconcile re-sends (finding 4);
  - `RootView` reconciles after an inbound bundle only when it carried a manifest (finding 5);
  - `ContactManager.contactDeleted`, observed by `RootView`, reconciles on deletion so a deleted trustee's
    piece shows as lost at once (finding 6);
  - `Backup.distributeShards`, dead and bypassing the queue and the rule, is deleted (finding 7);
  - Bug 143's wording: Vault Recovery's waiting row and the setup screen's export note say trustees confirm
    with their next direct message.
- Tests: `BackupDropRuleTests` (pending, lost, threshold-only, the rule itself), `noResendWhileLost`,
  `deleteContact_announcesTheDeletion`. The failure ordering has no direct test.
- Full suite: 919 tests, 913 passed, 0 failed, 6 skipped (the `KeychainMigrationSETests` baseline).

---

## Bug 145 — Distributing the backup key fails for every real trustee: the stored record assumes contact identifiers are UUIDs

**Status:** Fixed 2026-09-28 (see "Built" below). Found testing the backup flow on a device:
"Queue for Distribution" showed no result. Traced in code the same day.

**Target:** `v1.11.0`. **Release blocker.**

### Severity: High (the backup key can't be distributed at all)

### What happens

`BackupEncryptionKey.Payload`'s fixed-width codec (`Backup.PayloadCodec`, this branch) stores each trustee record's
`contactIdentifier` as 16 raw UUID bytes; `encodeShard` throws `invalidContactIdentifier` when it isn't a UUID
string (`Vault+Manager+Backup.swift`, `guard let contactID = UUID(uuidString: shard.contactIdentifier)`).

A real `Contact.Profile.identifier` is not a UUID: since SecurityReview 2026-07-24 finding #11 it is encrypted before
it is first stored (`ContactManager`, `encryptedIdentifier` in `createContacts` and the new-contact branch), the
base64 of the ciphertext, far longer than 36 characters.

So `VaultShardSetup.commitDistribution` → `distributeBackup` → `prepareBackupShards` → `persist` →
`PayloadCodec.encode` throws for any real trustee. Nothing is written or queued; the button stays "Review".

**Why it looked like nothing happened:** `commitDistribution` catches the error into `self.error`, rendered inside
the scroll view after the trustee list and both notes, below the fold with a few trustees. The bottom bar doesn't
change.

**Why tests missed it:** every backup-key test passes `UUID().uuidString` as a trustee identifier. `ShardRecord`'s
doc comment states the wrong premise ("a stable SwiftData UUID").

### Remedy

Built 2026-09-28, with Bugs 146 and 147 (same premise): records store a fixed-width tag derived from the
identifier instead of the identifier.

### Built, 2026-09-28

- `TrusteeTag` (`Vault+Model.swift`): the first 16 bytes of SHA-256 over `TrusteeTag.domainLabel`
  (`"occulta-trustee-tag"`) and the stored identifier. Depends on the whole identifier, needs no key, reveals
  nothing on its own. Decrypting the identifier instead was considered and rejected: the raw value isn't a UUID
  either (`CNContact` identifiers carry a `:ABPerson` suffix), every comparison would need a decryption on both
  sides, and it would put raw Contacts identifiers back into the restore buffer, which opens without Face ID
  (what finding #11 removed).
- `ShardRecord.contactIdentifier` → `trustee: TrusteeTag`, with `isHeld(by:)`; its JSON decoding still reads
  v1.10.3's `contactIdentifier` and tags it. `PayloadCodec` format 2 stores the tag in the same 16 bytes; format
  1 decodes its UUID to that UUID string's tag. `invalidContactIdentifier` is gone.
- `PendingRestoreShardSlot`/`AttestedShard` carry `sender: TrusteeTag`; `ShardsCodec` format 2 stores the tag
  plus 20 random bytes in the same 36-byte field. `absorbShard` de-duplicates by tag; `restoreBackup` counts a
  piece when its sender's tag is among the visible contacts' tags.
- `ShardCustodyManager` compares by tag and maps tags back to identifiers through the contacts it already has.
- Setup screen: records matched with `isHeld(by:)`; the selection, when seeded and after a successful queue, is
  the listed contacts holding an active piece, so the screen reads up to date and "Pieces queued for delivery."
  shows; first-time seeding keeps only Global Trustees who can receive a piece here; errors show in the bottom
  bar; a success haptic plays.
- Tests: `realFormatContactIdentifier()` (base64 of 64 random bytes) replaces UUID strings and short labels in
  every backup-key and restore suite; codec tests for real-format identifiers, format 1 decoding, the v1.10.3
  JSON record and `TrusteeTag`; `distributedLegacyKeyMigrates` (Bug 146); `longSendersStayDistinct` (Bug 147).
- Full suite: 923 tests, 917 passed, 0 failed, 6 skipped (the `KeychainMigrationSETests` baseline).

---

## Bug 146 — Upgrading from v1.10.3 with a distributed backup key: the key never migrates, and opening Backup Recovery can overwrite it

**Status:** Fixed 2026-09-28 by Bug 145's remedy. Filed the same day, found tracing Bug 145.

**Target:** `v1.11.0`. **Release blocker.**

### Severity: Critical (the only copy of a v1.10.3 backup key can be destroyed)

### What happens

`migrateLegacyBackupRowIfNeeded` decodes v1.10.3's JSON payload, whose trustee records hold real contact
identifiers, and stages it through the same codec (Bug 145). `encode` throws; the migration rolls back and is
retried at every unlock, never succeeding. Depth 0 then has no live backup-key row:

- the Vault tab and Vault Recovery show the backup as not set up;
- opening Backup Recovery runs `seedInitialState` → `setupBackup(currentDepth: 0)`, which finds no depth-0 key and
  generates a new one, sealed into `claimFillerRow`'s first unclaimed row. The legacy row (`depth` and
  `deletionToken` nil) counts as unclaimed, and as the oldest row it is likely first: the new key overwrites the
  v1.10.3 key, the only copy. Bug 138's loss, by a different route.
- if another row is claimed instead, the legacy row survives but is never migrated (the guard sees a depth-0 key
  and returns), staying behind as a distinguishable nil/nil row.

Either way every `.occbak` exported under v1.10.3 can no longer be opened from this phone's key, and trustees'
pieces are for the old key.

An owner who never distributed in v1.10.3 has no records and migrates fine.

### Remedy

Fixed by Bug 145's remedy: the legacy JSON records decode into the new record form, so staging succeeds. Devices
that already ran a build of this branch after upgrading (test devices only; nothing has shipped) may already have
lost or stranded the key; not repaired.

### Guard

A v1.10.3 legacy row with records holding real-format identifiers migrates on unlock, and `setupBackup` afterwards
keeps the migrated key.

---

## Bug 147 — A restore never completes on a real device: banked pieces keep only the first 36 bytes of the sender's identifier

**Status:** Fixed 2026-09-28 by Bug 145's remedy. Filed the same day, found tracing Bug 145.

**Target:** `v1.11.0`. **Release blocker.**

### Severity: High (recovery from a lost phone doesn't work)

### What happens

`PendingShamirSecretRestore.ShardsCodec` writes each banked piece's `senderIdentifier` into 36 bytes
(`fixedWidthUTF8(senderIdentifier, count: 36)`), assuming a UUID string; a real identifier is longer (Bug 145) and
is silently cut. `restoreBackup` counts only pieces whose sender is in `visibleContactIdentifiers`, which holds full
identifiers, so no banked piece ever matches and every restore attempt finds nothing. The per-sender
de-duplication in `absorbShard` also compares the cut form.

Tests use `"trustee-0"`, `"alice"` and the like, which fit.

### Remedy

Same as Bug 145: the slot stores a fixed-width tag of the sender's identifier, and both comparisons use tags.

### Guard

A restore end to end with real-format sender identifiers completes; a second piece from the same sender replaces
the first.


---

## Bug 148 — A message opened from outside the app shows before the PIN screen on a warm return past the grace period

**Status:** Fixed 2026-09-28, on `v1.11.0/vault-key-layering`; not yet walked through on a device. Reported the
same day from a device: Secure Mode and PIN on, a `.occ` opened from another app, the message visible before the
PIN screen came up. Regression of Bug 1 Incident A, through a gap the Bug 84 Part B fix left open.

**Target:** `v1.11.0`. **Release blocker.**

### Severity: High (message content shown without a PIN, and the inbound pipeline run before one)

### What happens

`AppScreen.phase` keeps its last value, `.unlocked`, for the whole time the app is in the background. The grace
period is evaluated only in `sceneDidBecomeActive`. On a warm return UIKit calls `sceneWillEnterForeground`,
then delivers the URL (`onOpenURL`), then `sceneDidBecomeActive`. So `handleOpenURL` runs while the phase still
reads `.unlocked` from the session that expired, and its gate (`if self.appScreen.phase != .unlocked { queue }`)
passes. Two outcomes, depending on which runs first on the main actor:

1. **The decryption finishes first.** `openedFileContents` is set, the `.sheet` in the `.unlocked` branch
   presents, and UIKit adds its container view to the window above the snapshot cover (the cover is a plain
   window subview installed earlier). `sceneDidBecomeActive` then sets `.pinRequired`, which tears the branch
   down and dismisses the sheet with its animation. The message is on screen from the sheet appearing until it
   has finished sliding away. This is the reported case.
2. **The phase flips first, after the gate has passed.** The decryption keeps going and sets
   `openedFileContents` while `.pinRequired`. `endSession()` already ran on the `.unlocked → .pinRequired`
   transition, so nothing clears it, and the sheet presents after the next PIN, whichever it is. That is not a
   leak of its own: a message nobody has seen yet is equivalent to queued input, and showing it after either
   PIN looks the same as the designed queued flow (a file opened, a PIN entered, the message shown). It only
   happens by timing, though, and loses the message in the gap before `endSession()` runs.

In both cases the whole inbound pipeline ran before any PIN: prekey consumption, shard ops, manifest
reconciliation and their saves, at the expired session's depth (the shape Bug 84 Part A removed for shares).

A `.occbak` takes the same path without the phase check: its prompt can show over the cover, and `endSession()`
then drops the staged file.

### Why now

The race has existed since `8b95ee5` moved the lock decision into `sceneDidBecomeActive`. It was probably hidden
by the read before the gate: until `7edef05` (2026-08-01) that was `URLSession.shared.data(from:)`, slow enough
that `sceneDidBecomeActive` usually won; the memory-mapped read returns in microseconds. Not yet confirmed on a
device with the old read.

### Resolution

Lock as early as possible, unlock as late as possible.

1. **`AppScreen.lockIfGracePeriodExpired`**, called first in `sceneWillEnterForeground`, sets `.pinRequired`
   when a PIN is configured, the gate is up, and the time in the background exceeds the grace period, so the
   phase is right before UIKit can deliver the URL and `handleOpenURL` queues the file as designed. The unlock
   decision stays in `sceneDidBecomeActive`, which already leaves `.pinRequired` alone.
2. **A result that finishes after its session ended is dropped.** `endSession()` advances a `sessionEpoch`;
   `RootView.processInboundFile` captures it before decrypting and, if the session ended (or the phase isn't
   `.unlocked`) by the time decryption finishes, presents nothing, neither the basket nor an error.

   The gate can't come up *during* decryption: identifying the sender, opening the bundle, burning the prekey,
   the shard ops and the save run as one synchronous block on the main actor, and the lock is itself a
   main-thread scene callback. Only the step after, writing decrypted attachments to temp files, can straddle
   it, and by then the prekey is gone, so the bytes cannot be re-queued. Holding the result and showing it
   after the next PIN would have been safe too (see outcome 2). **Dropping was chosen by the owner,
   2026-09-29:** a message is lost only if the user leaves before it finishes decrypting and stays away past
   the grace period, which is acceptable; the sender can resend.

Not covered by (2): an identity-challenge sheet, set inside `buildOwnedBasket` before its first suspension, so
it cannot outlive a session change that (1) now prevents from happening first.

### Guard

`AppScreenLockTests` (6 tests; the 4 that configure a PIN are Enclave-gated, since `configurePIN` seals
`AppLayerConfig` fields with the ambient local key — found when CI on PR #76 failed them, 2026-09-29): past
the grace period the phase is `.pinRequired` before
activation; within it, with no background entry, with no PIN, with the gate lowered, and before `wire`, nothing
changes. `sceneWillEnterForeground` needs a live `UIScene`, so the call from it is covered by reading, not a test;
`processInboundFile` lives on a SwiftUI `View` and is untested, like the rest of that type.

Still to do on a device: background for more than 5 minutes, open a `.occ` from Files or Messages; expect the PIN
screen with no sheet before it, and the message after the PIN.

---

## Bug 149 — A contact marked as a Global Trustee carries the depth it was marked at, readable without Face ID

**Renumbered 2026-09-29:** filed as Bug 148 by mistake, colliding with the warm-return lock entry above
(`d88ba22`); commit `1e8d949`'s message cites the old number.

**Status:** Fixed 2026-09-29 by retiring Global Trustees (`decisions.md`, "Backup recovery
lives only in the Vault tab; Global Trustees retired"). Found while costing that retirement.

**Target:** `v1.11.0`.

### Severity: Medium (a duress depth's existence readable without coercion)

### What happens

`Contact.Profile.globalTrusteeDepth` held `-1` for "not a trustee", or the depth a contact was marked a Global
Trustee at (`saveGlobalTrusteeDepth` stamped the current depth). It is sealed under the local key, which opens
without Face ID, so anyone running code as the app could read a contact marked at depth 2 and learn that a
depth 2 exists, and who its trustees are. `migrateGlobalShardConfigToPerContact` also stamped `0` on contacts
from the old depth-0 list.

### Fix

- The feature is gone: `VaultGlobalTrustees`, `saveGlobalTrusteeDepth`, `isGlobalTrustee`,
  `globalTrusteeIdentifiers`, and the setup screen's pre-selection and GLOBAL badge.
- `DatabaseMigration.migrateRetireGlobalTrustees` (replacing the nil backfill, every launch) resets every live
  contact's stamp to a sealed, fixed-width `-1` through `scrubbedStamp`; a row already there is left
  byte-identical. Soft-deleted rows were already scrubbed to `-1` (`migrateScrubDeletedDepthStamps`).
- `migrateDeleteGlobalShardConfig` (was `migrateGlobalShardConfigToPerContact`) only deletes old rows.
- The field keeps being written as `-1` at creation and deletion so every row stays alike, and leaves the schema
  next release with `shardDistributionEncrypted` and `PendingShardStatusUpdate`.

### Guard

`GlobalTrusteeRetirementTests`: stamps of 0, 2, legacy JSON and nil all read a sealed `-1`; a `-1` row is left
byte-identical and a second run rewrites nothing; soft-deleted rows are left to their own scrub; the old list is
deleted without re-marking anyone.

Full suite after the change: 919 tests, 913 passed, 0 failed, 6 skipped (the `KeychainMigrationSETests` baseline).

**Review follow-up, 2026-09-29:** the retire pass first rewrote every live stamp as if readable, so a stamp that
doesn't decrypt would have become a readable -1 among unreadable fields (Bug 97's pattern). It now leaves an
undecryptable stamp alone, as the fixed-width pass does, and derives the local key once for the pass instead of
once per contact. Guard: `leavesUndecryptableStampAlone`. Full suite: 924 tests, 918 passed, 0 failed, 6 skipped.

---

## Bug 150 — Backup Recovery opens on a locked vault from Settings; queueing fails with "Vault locked", and a locked vault reads as "no distribution"

**Renumbered 2026-09-29:** filed as Bug 149, shifted when the Global Trustees entry moved to 149; commit
`1e8d949`'s message cites the old number.

**Status:** Fixed 2026-09-29. Found testing the backup flow on a device.

**Target:** `v1.11.0`.

### Severity: Medium (the backup can't be set up from that path; an existing distribution looks absent)

### What happens

Settings › Vault Recovery's "Backup Key Trustees" link wasn't gated on the vault being unlocked, unlike the Vault
tab, which shows its lock screen. On a locked vault the setup screen:

- skipped `setupBackup` silently (`try?`);
- listed trustees anyway (contacts need no vault key);
- read `fetchDistributionMeta()`'s `nil` (a `try?` over a locked vault) as "no distribution yet", so the button
  read "Review" and the education sheet opened even when a distribution existed;
- failed at "Queue for Distribution": `currentKey()` threw `VaultError.locked`, shown as "Vault locked — unlock and
  try again" with nothing to unlock with;
- never closed itself: Bug 134's handler reacts to the vault *becoming* locked.

A lock while the education sheet was open could also leave the screen in place, since dismissing the screen and
the sheet at once could be ignored.

### Fix

- The Settings path is gone (`VaultRecoverySettings` deleted); the setup screen is reached only from the unlocked
  Vault tab.
- The screen shows its content only while the vault is unlocked, otherwise a locked state with Unlock Vault
  (`vault.whenUnlocked`). Seeding, the Review/education decision and queueing run only while unlocked; a lock
  clears the seeded state and closes the sheet and alert, in place (Bug 134's navigate-back is replaced).

### Guard

The button's decision is `VaultShardSetup.nextStep`, which checks the lock before reading the distribution or
the recipients (`DistributionStepTests`, added in the review follow-up of 2026-09-29). The rest is view code: a device
check (open the screen, lock the phone or wait out the timeout with the education sheet open, unlock again).

## Bug 151 — The Backup Recovery row reads "0 of 2 trustees confirmed" for three trustees with a threshold of two

**Status:** Fixed 2026-09-29. Found testing the backup flow on a device.

**Target:** `v1.11.0`.

### Severity: Low (misleading wording; no data or security effect)

### What happens

`Backup.setupState` returned `.waitingForConfirmations(confirmed:threshold:)`, and the Vault tab's `VaultBackupRow`
rendered it as "`confirmed` of `threshold` trustees confirmed". The denominator is the number of confirmations export
needs, not the number of trustees, so a split among three trustees with a threshold of two read as if two trustees
had been chosen.

### Fix

`waitingForConfirmations` carries `total` as well: the pieces still `.pending` or `.confirmed`, the same set the setup
screen treats as active. A lost piece can't confirm, so it leaves the total. The row reads
"`confirmed` of `total` trustees confirmed · `threshold` needed", for example "0 of 3 trustees confirmed · 2 needed".

No leak: the row shows only while the vault is unlocked, at the current depth, and the setup screen already shows
the trustee count and threshold there.

### Guard

`BackupSetupStateTests` (`BackupPieceReconcileTests.swift`): three trustees, threshold two, counts 0 and 1 confirmed
of 3, then `.ready` at 2; a lost piece drops the total to 2.

## Bug 152 — A trustee who has used up the owner's prekeys never confirms a backup-key piece

**Status:** Fixed 2026-09-29. Found testing the backup flow on a device with a trustee on v1.10.3: the Backup
Recovery row stayed at "0 of 3 trustees confirmed" through several exchanges, and the trustee's messages showed
standard encryption.

**Target:** `v1.11.0`. The rule dates from `5aabc01` (2026-05-06), so v1.10.3 has it too; it is not a v1.10.3
compatibility problem, and a trustee on v1.11.0 hits it the same way.

### Severity: High (backup-key distribution can stall permanently; export never becomes available)

### What happens

1. `ContactManager.encryptBundle` attached the pending prekey batch only when the bundle carried no piece
   (`if !isCarryingShard`), a rule from when a piece travelled in its own shard-only bundle and ordinary messages
   carried the batch.
2. A queued piece now rides every direct message to its trustee until a manifest confirms it, so none of those
   messages carries the batch.
3. Each trustee reply uses one of the owner's prekeys (15 per batch). Once they run out, replies use the long-term
   fallback. The owner's device answers a fallback by storing a fresh pending batch, which step 1 keeps from
   leaving.
4. On the fallback path the trustee's manifest is dropped with the other shard content (forward secrecy is required
   for it, in v1.10.3 and v1.11.0), so the piece is never confirmed and stays queued — back to step 2.

The owner's direction still works (the trustee's replies keep delivering their batches), so the owner's app shows
forward secrecy on while the trustee's shows standard encryption.

### Fix

`encryptBundle` attaches the pending batch whenever it pops a prekey, with or without a piece. Contacts below 1.9.0
are unchanged: `needsPrekey` is false when a piece is carried, so that path never loads a batch. A batch holds
public prekeys only, and ordinary messages already vary in whether they carry one, so a piece-carrying message
doesn't stand out.

v1.10.3 trustees need no update: their `openGroup` stores a recipient's batch whatever else the bundle carries
(`storeInboundBatch`). No migration: the stalled owner already holds the pending batch, so the next message
delivers it, the trustee's next reply is forward-secret and carries the manifest, and the piece confirms at the
owner's next reconcile.

### Guard

`PieceCarriesPrekeyBatchTests` (`ShardFallbackGatingTests.swift`, Enclave-gated): a bundle carrying a piece
carries the pending batch in the recipient's slot; and end to end, a trustee store holding none of the owner's
prekeys has the full batch after opening a piece-carrying bundle. Both fail with the old rule restored.

Still to do on a device: the stalled owner sends one more message; the trustee's next reply should show forward
secrecy and the piece should confirm.

## Bug 153 — Every key exchange leaves its particle canvas running at 60 Hz after the screen closes

**Status:** Fixed 2026-10-01. Found reusing `ParticleCanvas` behind the redesigned onboarding (`decisions.md`,
"Onboarding redesign").

**Target:** `v2.0.0`.

### Severity: Low (CPU and battery; nothing exposed)

### What happens

`ParticleCanvas` created its `CADisplayLink` in `init` and invalidated it only in `deinit`. A display link retains
its target, so `deinit` never ran: each key exchange left its canvas alive, updating 80 particles every frame, until
the app was terminated. Each exchange added one more.

### Fix

The link runs only while the canvas is in a window (`didMoveToWindow`): created on entering one, invalidated on
leaving it, which releases the canvas. The `deinit` is gone, having nothing left to do.

### Guard

`ParticleCanvasTests`: a canvas removed from its window, and one never put in a window, are both released. Both fail
with the old `init` and `deinit` restored.

## Bug 154 — Six internal design docs ship inside `Occulta.app`, regressing the 1.10.2 bundle-contents fix

**Status:** Fixed 2026-10-01, the day it was found, in a Release archive of `develop` at `3319fd7`. Full record:
`Docs/Bugs/v1.11.1/Internal-Design-Docs-Shipped-In-App-Bundle.md`. Audit: `Docs/Audit/SECURITY_CHECKLIST.md` §6.

**Target:** `v2.0.0`.

**Shipped in:** `v1.11.1` and `v1.11.0` (all six); `v1.10.3` (`BEK_LAYERING_REFACTOR.md` only, then the full 26 KB
design).

### Severity: High (forensic: the app hands an examiner its at-rest layering and duress-depth key design)

### What happens

`Occulta/` is a file-system-synchronized root group, so every non-source file under it is copied into the bundle
unless it is listed in the Occulta target's `membershipExceptions`. Six docs added between 2026-08-28 and
2026-09-10 were never listed: `SecureMode/AT_REST_LAYERING.md` and `SecureMode/PASSPHRASE_LAYER_KEYS.md`, plus
`Vault/BEK_LAYERING_REFACTOR.md`, `Vault/RECOVERY_BUFFER_LAYERING.md`, `Vault/STORAGE_LAYERING.md` and
`Vault/VAULT_KEY_LAYERING.md`. The bundle is the same on every install, so the files reveal nothing about this
user's configuration. They do reveal the design.

### Fix

All six are added to the exception set. A sweep found no other `.md`/`.html` under `Occulta/` missing from it.

### Guard

`BundleContentsTests` (`OccultaTests/BundleContentsTests.swift`, no Enclave needed). It runs hosted in `Occulta.app`,
fails on any `.md` or `.html` in the bundle or its appexes, and checks that the host is the app with both appexes
embedded. With the exclusions reverted it fails and names exactly the six.

## Bug 155 — An identity challenge makes each side generate a fresh prekey batch while the other still has keys

**Status:** Open. Found 2026-10-06 reviewing the prekey batch lifecycle (Bugs 155–160 come from that review).

**Target:** `v2.0.0`. Present since the identity challenge shipped (`b63b5daa`, 2026-04-15).

### Severity: Medium (the main source of Bug 156's leftover Enclave keys)

### What happens

1. A batch is requested implicitly: when a bundle opens on the long-term path, `decryptSealed` and `openGroup`
   read that as "the sender has used up my prekeys" and, if no batch is pending, call
   `generateAndStoreFreshBatch` (15 new Enclave keys).
2. `IdentityChallenge.Manager.sealIdentityBundle` always seals with `.longTermFallback`, whatever prekeys the
   challenger holds, and `OccultaApp` opens it through `decryptSealed`. The challenge and the response each
   trigger step 1 on the receiving side.
3. The new batch rides the receiver's next message. `syncInboundPrekeys` accepts it (newer `generatedAt`) and
   **replaces** the stored keys, discarding the unused part of the previous batch.
4. The private halves of the discarded keys stay in the Enclave with nothing left to consume them (Bug 156).
   Up to 15 per side, per challenge.

Old-path shard sends to contacts below 1.9.0 do the same: `encryptBundle` skips the prekey pop when a piece is
carried (`needsPrekey`), so those bundles are long-term even with prekeys available.

### Fix (proposed)

Only a bundle that could have been forward-secret should request a batch. Candidates: skip generation in
`decryptSealed` when the payload carries `identityChallenge` (it is decoded after generation today, see
Bug 159, so the order has to change first); or have the challenge use a prekey when one is available. Either
way, the receiver must still treat the bundle the same on the wire, since identity-challenge traffic is meant
to be indistinguishable from an ordinary fallback message.

### Guard

None yet. Needed: open an identity-challenge bundle through `decryptSealed` for a sender with no pending batch
and assert none is created.

## Bug 156 — Unused prekeys are never removed from the Secure Enclave

**Status:** Open — fix decided 2026-10-06, not yet built: delete retired keys 30 days after retirement.

**Target:** `v2.0.0`. Pruning existed (`d16ec10c`, 2026-03-18) and was removed in `efb0b199` (2026-03-29);
every release with forward secrecy is affected.

### Severity: Medium (open-ended forward-secrecy window for unopened messages; key count grows with history)

### What happens

A prekey private key leaves the Enclave in only two ways: `PrekeyManager.consume` when a message using it is
opened, and `deleteAllKeys(for:)` when the contact is removed. Keys the contact will never use stay for good.
They come from:

- a batch replaced before it was used up (Bugs 155 and 157);
- messages sealed to a key and never opened — lost in transit, or deleted unread;
- batches generated and never saved (Bug 159).

Two consequences:

- **Forward secrecy.** A message sealed to a key that is never consumed can be opened by anyone who later has the
  `.occ` file and the unlocked device, with no time limit. The rest of the design assumes that window closes.
- **Forensic.** The number of `prekey.<contactID>.*` keys per contact only grows. It reflects how many batches
  were replaced and how many messages were lost, which is more history than the design needs to keep.

`remainingCount(for:)` counts these keys too, so it overstates how many prekeys the contact really holds. It
has no production caller today, nor does `needsReplenishment`, which is built on it; wiring either up as-is
would misfire.

The comment in `PrekeyManager.generateBatch` ("A partial batch would prune old SE keys and increment the
sequence") still describes the removed mechanism.

### Fix — decided 2026-10-06

The retirement rule in `Docs/Features/Prekey Continuity/DESIGN.md` §3.1 (its decision D1). A batch retires when
the contact first uses a key from a newer batch; its remaining keys are deleted **30 days after retirement**.

By time rather than by message count: a count leaves a contact who goes quiet holding old keys indefinitely,
and their unopened files are where the risk is. The two options considered were:

- **On the next generation, keeping one older batch** for in-flight messages. Bounded storage, but no bound
  in time for a quiet contact. Not chosen.
- **After a fixed age.** Bounds the forward-secrecy window in time; fails messages delivered late. Chosen.

A leftover key at retirement always belongs to a message that was sealed and not opened here, so a file opened
more than 30 days after its batch retired can't be opened. It fails with the generic error. The rule needs the
batch a key belongs to recorded at generation, and a migration that treats the keys existing installs already
hold as one retired-on-first-use batch (design §8, stage 1).

### Guard

None yet.

## Bug 157 — Using any of our prekeys clears the pending batch, even one from an older batch

**Status:** Open.

**Target:** `v2.0.0`. Present since the pending batch was introduced (`8ec81d8a`, 2026-03-23).

### Severity: Low (one extra fallback round; adds to Bug 156)

### What happens

`decryptSealed` and `openGroup` call `clearPendingBatch()` whenever a bundle opens with a prekey, as "proof the
contact received our batch". It proves they received *a* batch, not the pending one. With messages arriving out
of order:

1. The contact seals m15 with our last key from batch 1, then m16 on the long-term path.
2. m16 arrives first; we generate batch 2 and store it as pending.
3. m15 arrives; its batch-1 key clears batch 2 before batch 2 has gone anywhere.

The contact stays on the long-term path, the next fallback generates batch 3, and batch 2's keys stay in the
Enclave (Bug 156).

### Fix (proposed)

Clear only when the consumed prekey's id is in the pending batch. The pending batch is stored with its ids, so
no format change is needed.

### Guard

None yet. Needed: the sequence above through `decryptSealed`, asserting batch 2 is still pending after m15.

## Bug 158 — A sender whose clock moves backwards can lose forward secrecy with a contact indefinitely

**Status:** Open — fix needs a decision.

**Target:** `v2.0.0`. Present since `latestPrekeysGeneratedAt` was introduced (`efb0b199`, 2026-03-29).

### Severity: Medium (forward secrecy silently off for a pair; neither side can restore it)

### What happens

`syncInboundPrekeys` accepts a batch only if its `generatedAt` is later than the last one accepted. That date
comes from the **sender's** clock. If the sender's clock moves back past their previous batch's date (manual
time setting, or a device restored with a wrong clock):

1. Their new batch is older than the stored date, so we drop it without saying anything.
2. We never use a key from it, so the sender never clears it (`clearPendingBatch` needs a used key).
3. While a batch is pending, the sender doesn't generate another (`!hasPendingBatch`).

Every message from us to that contact goes out on the long-term path until the sender's clock passes the old
date. Nothing on either side shows why.

### Fix — open, needs a decision

`Docs/Features/Prekey Continuity/DESIGN.md` §3.3 proposes the first option below, with a batch `id` added as an
optional field and the date rule kept for batches without one.

The date check exists for a real reason: an old copy of the current batch can arrive after we have used some of
its keys, and accepting it would bring back keys the contact has already deleted, making the messages sealed to
them unopenable. Any replacement has to keep rejecting that copy. Options:

- Dedupe on batch identity (its prekey ids) instead of time: reject a batch we have already accepted, accept any
  other. Needs the ids of past batches kept, or a batch id added to `PrekeySyncBatch` (a wire change, which the
  interop vectors pin).
- Keep the date, and also accept an older-dated batch when our store for that contact is empty and the batch is
  one we have not seen.

### Guard

None yet.

## Bug 159 — A fresh prekey batch is generated before the bundle has passed every check

**Status:** Open.

**Target:** `v2.0.0`. `decryptSealed` has had this order since forward secrecy was introduced; `openGroup` since
`87d3a21f` (2026-06-25).

### Severity: Low (leftover Enclave keys; no message is accepted that shouldn't be)

### What happens

`decryptSealed` calls `generateAndStoreFreshBatch` before `decodePayload`; `openGroup` calls it before the
`senderProof` check. Both bundles have already been authenticated by AES-GCM at that point, so nothing forged
gets through. But if a later step throws, the 15 Enclave keys already exist while the pending batch is never
saved (the explicit `modelContext.save()` is not reached). Every retry of the same file makes 15 more (Bug 156).

### Fix (proposed)

Move the generation after the last check that can throw, just before the save. This is also what Bug 155's fix
needs, since it must see the decoded payload first.

### Guard

None yet.

## Bug 160 — No test exercises the real prekey replenishment trigger

**Status:** Open.

**Target:** `v2.0.0`.

### Severity: Medium (process: the mechanism that restores forward secrecy has no regression guard)

### What happens

`ExhaustionScenarioTests` (`ForwardSecrecyIntegrationTests.swift`) re-implements the orchestration inside the
tests instead of calling it. `exhaustion_hasPendingBatch_blocksSecondGeneration`, for example, contains its own
`if !contact.hasPendingBatch { … }`, and `exhaustion_pendingBatchCleared_onFSReceipt` calls `consume` and
`clearPendingBatch` directly. They would all still pass with the trigger deleted from `ContactManager`.

The only test on the real path is `PieceCarriesPrekeyBatchTests.trusteeStoresBatch` (Bug 152), which checks that
a batch is delivered and stored, not that a long-term bundle generates one or that a used key clears it.

Not covered by anything: a long-term bundle stores a pending batch; a forward-secret bundle clears it; the full
cycle (keys used up → fallback → batch generated → batch rides the reply → next message is forward-secret), on
both `decryptSealed` and `openGroup`.

The doc comment on `ContactManager.encryptGroupBundle` says a batch is attached when the member's "stock for this
sender is below the replenishment threshold". It is attached whenever one is pending; the threshold
(`PrekeyManager.replenishThreshold`) is not used anywhere in production.

### Fix (proposed)

End-to-end tests through `decryptSealed` and `openGroup` for each item above. They create prekeys through
`PrekeyManager`, so they need `.enabled(if: secureEnclaveAvailable())`, not the ambient trait. Correct the
`encryptGroupBundle` comment.

### Guard

This entry is the guard's absence.

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

---

## Bug 7 — Hard-delete inside staged key rollback scope causes irrecoverable data loss

**Status:** Closed (Fixed)

### Severity: High
In `activateSecureMode`, `hardDeleteContact` was called after all safe contacts were re-encrypted with the staged key and persisted to the DB — but still inside the `do { } catch { rollbackStagedLocalDBKey() }` block. If `hardDeleteContact` threw, the catch block deleted the staged key, but the DB already contained data encrypted exclusively with it. The canonical key could no longer decrypt any of those records. All contact data was permanently unrecoverable.

### Root Cause
The hard-delete loop sat after the Step 8 re-encryption writes but before `commitStagedLocalDBKey()` (Step 10). Any error in this window triggered a rollback that invalidated the only key capable of reading the already-written DB rows.

### Resolution
Moved the `hardDeleteContact` loop to after `commitStagedLocalDBKey()` (Step 10, the point of no return). Each call uses `try?` — a delete failure is silently absorbed and does not re-throw into the outer `catch`. After commit the staged key is the canonical key, so a delete failure leaves sensitive contacts in the DB encrypted under the canonical key. The user can retry activation; no rollback is triggered and no data is lost.

---

## Bug 8 — Vault PEKs unnecessarily stored in the blob

**Status:** Closed (Fixed)

### Severity: Medium
`activateSecureMode` Step 6 unwrapped every vault entry's per-entry key (PEK) and stored the raw 32-byte key bytes inside `BlobPayload`. The vault key is derived from a dedicated SE key entirely independent of the local DB key rotation — vault entries never need re-keying during activation or deactivation.

`payload.vaultPEKs` was unsealed in `deactivateSecureMode` and silently ignored, confirming the data served no purpose. Meanwhile, storing raw PEK bytes in the blob unnecessarily widened the attack surface: a blob compromise (requiring only the SE Secure Mode key, no biometrics) also yielded the symmetric keys for all vault entry content, bypassing the biometric gate that normally protects them.

### Resolution
Removed `VaultPEKRecord` struct and the `vaultPEKs` field from `BlobPayload`. Removed Step 6 (vault PEK collection) from `activateSecureMode`. The vault's `visibleThroughDepth` re-encryption (Step 8) is the only vault-related work the key rotation requires.

---

## Bug 9 — `findBlob` returns an arbitrary file when multiple `.occbak` files exist

**Status:** Closed (Fixed)

### Severity: Low
`findBlob` requested `contentModificationDateKey` from the filesystem but never used it for sorting. `files?.first { $0.pathExtension == "occbak" }` returned whichever file appeared first in the enumeration order, which is unspecified on APFS. If two `.occbak` files were present — e.g. a stale file from a prior interrupted `seal()` — the wrong blob could be returned, causing deactivation to fail with `BlobError.decryptionFailed` or to silently unseal stale data.

### Root Cause
The sort step was omitted when the resource key was added. `FileManager.contentsOfDirectory` does not guarantee ordering.

### Resolution
`findBlob` now filters to `.occbak` files, sorts by `contentModificationDateKey` descending (falling back to `.distantPast` on read failure), and returns `first`. The most recently written file is always selected.

---

## Bug 10 — `reEncryptKeyRecords` after INSERT in deactivation

**Status:** Closed (Invalid — proposed fix causes data loss)

### Severity: N/A
The original diagnosis claimed the `reEncryptKeyRecords` call after INSERT in `deactivateSecureMode` Step 5 is a no-op because `save(contact:using:stagedCrypto)` already encrypts `contactPublicKeys` via `stagedCrypto`.

This is incorrect. The INSERT path in `ContactManager.save` handles key records via `self.update(key:for:)`, which uses `self.cryptoManager` (the canonical key), not the `crypto` parameter. After INSERT, key records are canonical-key encrypted. `reEncryptKeyRecords` correctly decrypts them with the canonical key and re-encrypts with the staged key.

Removing the call — as the original resolution proposed — would leave key records for every restored contact encrypted with the deactivation-era canonical key. After `commitStagedLocalDBKey()` that key is superseded and deleted, making every restored contact's public key material permanently unreadable.

### Resolution
No code change. The call is correct and must stay.

---

## Bug 11 — `maintainNoOpBlob` destroys the real blob after 24 hours, breaking deactivation

**Status:** Closed (Fixed)

### Severity: Critical
`maintainNoOpBlob()` is called unconditionally from `OccultaApp.init()` on every launch. It calls `isStale()` on the existing `.occbak` file — the same function used for no-op blobs, which considers any file older than 24 hours stale. When Secure Mode is active, the blob holds a real payload (sensitive contact data, not random bytes). If the user activates Secure Mode and returns more than 24 hours later, `maintainNoOpBlob` deletes the real blob and writes a fresh random-byte no-op in its place. The blob key decrypts the no-op successfully (same SE-derived key), but the plaintext is random garbage. `JSONDecoder` fails immediately, surfacing as `"Unexpected character '\u{0C}' around line 1"`. Deactivation is permanently blocked until the blob is manually removed — but doing so also destroys all sensitive contact data.

### Root Cause
`maintainNoOpBlob` was designed for no-op blob maintenance and has no awareness of whether the current blob is a real payload. The 24-hour staleness check was intended to keep Last-Modified timestamps from being correlated with meaningful events — it was never meant to apply to real payloads.

### Resolution
In `OccultaApp.init()`, read `AppLayerConfig` from the already-initialized `ModelContainer` (no SE key required) and check whether a duress verifier is present before calling `maintainNoOpBlob`. A duress verifier indicates Secure Mode is active and the blob holds real data. If active, skip `maintainNoOpBlob` entirely. After deactivation, `rewriteNoOpBlob()` is called explicitly to install a fresh no-op, so the next launch will not see a stale real blob.

---

## Bug 12 — `visibleThroughDepth` watermark survives deactivation

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

**Status:** Open

### Severity: High (forensic)

`SummaryView` catches `pinCollision` in the generic `catch` block and shows an "Activation Failed" alert. A device with no Secure Mode active has no existing verifiers, so it can never produce a `pinCollision` during activation — any PIN the user proposes will succeed. A device with Secure Mode active can produce a collision when the proposed duress PIN matches an existing verifier. Seeing "Activation Failed" (as opposed to a wrong-entry-PIN error, which would have been caught earlier in the flow) confirms that protected verifiers already exist on the device. The alert directly reveals that Secure Mode is running.

Compare with `invalidStateTransition`, which is silently dismissed: that arm was added in Bug 24 precisely for tell-avoidance — the same principle must apply to `pinCollision`.

### PIN oracle attack

A coercer at depth 1 with `state = .duress` (no prior activation from this depth) can exploit the collision signal as a binary oracle to identify the master PIN:

1. Open the activation flow, confirm their PIN ("1111"), propose candidate PIN X.
2. "Activation Failed" → X collides with an existing verifier. Because `sealedNormalVerifiers[0]` holds the master normal PIN, X = master PIN — found.
3. No alert (flow dismisses normally) → X is not in use. A new layer is created at depth 2.

Each successful probe creates a new layer and transitions `state` to `.normal` (Bug 58 fix), after which `invalidStateTransition` blocks further activation attempts from depth 1. Each colliding probe leaks whether the proposed PIN is the master PIN. With `pinCollision` silently dismissed the coercer receives no signal — successful activation and a collision are indistinguishable from the UI.

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

**Not yet resolved — three remaining gaps:**

---

#### Gap 1 — The silent dismiss is itself a forensic tell

A real activation writes extensively: all contact rows are re-encrypted (new ciphertext, WAL activity), a blob is pushed to the layer store file, and `AppLayerConfig` gains new verifiers, a blob slot index, and a sequence number. A collision writes nothing — the DB is untouched, the WAL is idle, and the blob store is unchanged.

A forensic examiner comparing filesystem and DB state before and after a "successful" activation attempt can distinguish collision from success without decryption: file modification timestamps, WAL presence, and blob store contents all differ. The UI is indistinguishable; the disk is not.

**Applied:** on `pinCollision`, `pushDummyBlobSlot` writes a random-noise `LayerPayload` (empty contacts, random sequence number) to a non-excluded slot before the throw. `push()` pads all payloads to `slotPlaintextSize` before encrypting, so the ciphertext is the same fixed size as a real activation blob — indistinguishable by byte count. The contact DB and AppLayerConfig remain unmodified (no re-encryption, no new verifier), but the blob store — the most externally observable artefact — now shows a write on every collision.

---

#### Gap 2 — Rate limit proposal is flawed

The original Option A (N activations per 24-hour window) was inadequate on multiple dimensions:

- **Threat model mismatch.** A coercer has a bounded physical access window — typically hours, not days. A 24-hour counter resets before the next session and is useless.
- **Counter is observable.** An encrypted counter that increments after each probe is itself a forensic signal — an examiner who can observe the DB across time can infer that activation attempts were made.
- **Non-colliding probes create real state.** Each successful (non-colliding) probe creates a real new layer: new verifiers, new blob slot entry, new cryptographic artefacts that accumulate indefinitely. The rate limit constrains collision probes but not layer proliferation.
- **Clock manipulation.** iOS system time is controllable in some jailbreak or MDM-adjacent scenarios; a 24-hour window tied to wall time is not robust.

**Better framing:** a **session-scoped limit** (1–2 activation attempts per authenticated session at a given depth) is invisible to a legitimate user and makes brute-forcing impractical given the physical access requirement per session. This requires no persistent counter and is not vulnerable to clock manipulation.

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

---

## Bug 70 — Lockout counter reset to zero via iTunes/Finder backup restore

**Status:** Open

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

### Resolution (pending)

Two independent fixes required:

**1. Verify `isExcludedFromBackup` covers local backups.** Confirm that `excludeStoreFromBackup(url:)` (added in `a320e3b`) prevents the database from appearing in a wired iTunes/Finder backup, not just iCloud. If local backup exclusion requires a different entitlement or API call, apply it.

**2. Carry lockout fields through key rotation.** In the re-encryption loops of `activateSecureMode` and `deactivateSecureMode`, re-encrypt `lockoutCountEncrypted` and `lockoutExpiryEncrypted` under the staged key alongside the other `AppLayerConfig` fields. A test asserting that a lockout in progress at activation time is still active and unexpired after deactivation should be added.

---

## Bug 71 — Layer store file modification timestamp correlates with activation events

**Status:** Open

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

---

## Bug 72 — `randomSlot(excluding:)` has negligible modular bias

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

**Status:** Closed (Fixed) — implemented and verified on `release/v1.9.1` (34/34 Group tests passing, including new regression coverage for depth-1/2/3 independence). Not yet committed/pushed.

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

# Bug Tracker

---

## Bug 1 — Messages visible over PIN lock

**Status:** Closed (Fixed)

### Severity: High
An authenticated attacker with brief physical access to an unlocked device can open a sheet (e.g. via a notification tap or an in-app action) and read message content without ever entering the PIN. The PIN layer is present but rendered below sheets in the SwiftUI hierarchy, making it visually and interactively bypassable.

A secondary issue exists independently of the z-order problem: if the app is locked and a message notification is tapped, `buildOwnedBasket` runs inside the `onOpenURL` Task before any PIN is entered. If the basket is from a safe contact and `openedFileContents` is set at that point, entering the duress PIN afterward would still present the sheet — because `openedFileContents` was populated while the security state had not yet been determined by PIN entry.

### Root Cause
`PINEntry` was applied as an `.overlay` on `TabView`. SwiftUI overlays are layout primitives — iOS modal presentations (`.sheet`, `.fullScreenCover`) are UIKit-level operations that attach to the window's root view controller, completely outside the SwiftUI view tree. They render above any overlay regardless of z-order.

The content gate gap is a timing issue: `openedFileContents` is set inside an async Task that can run while the app is locked, before the user's PIN determines the security depth.

### Resolution
Two fixes applied together:

**1. z-order fix** — replaced `.overlay { if self.isLocked { ... } }` with `.fullScreenCover(isPresented: self.$isLocked)`. A `fullScreenCover` is itself a UIKit modal presentation; iOS stacks it above any existing sheets so it cannot be underlapped.

**2. Content gate** — two check points added:
- *At set-time* (app already unlocked in restricted mode): after `buildOwnedBasket` returns, if `security.isRestricted` and the sender is not a safe contact, suppress the basket and show the standard "not addressed to you" error instead of setting `openedFileContents`.
- *After duress unlock* (message queued while locked, duress PIN entered after): in the `onDuress` callback, before clearing `isLocked`, check any pending `openedFileContents` against `isSafeContact`. If the sender is not visible at duress depth, clear the basket and surface the error. Sensitive contacts are absent from the DB in Secure Mode, so `isSafeContact` returns `false` for them naturally.

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

**Status:** Open

### Severity: High
When `Manager.Security.verify()` returns `.wipe` (wrong PIN limit reached, or duress consecutive-entry threshold exceeded), `PINEntry` calls `onWipe()`. The lock-screen `PINEntry` in `OccultaApp` passes `onWipe: {}`. No data is erased. The user stays on the PIN screen and can continue guessing indefinitely, defeating the entire wipe-threshold feature.

### Root Cause
`onWipe` was left unimplemented as a placeholder.

### Resolution
Pending. `onWipe` should call `appManager.eraseAllData()` (the same path used by Settings → Manage Contacts → Delete) and transition `Manager.Security` to `.noPIN` by deleting the `AppLayerConfig` row.

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
Pending investigation. The trustee picker's data source must apply the same depth filter used by the contact list: contacts with `visibleThroughDepth` encoding a depth less than `security.currentDepth` must be excluded from the eligible-trustee list when `security.isRestricted`.

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

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

**Status:** Open

### Severity: Medium
Double prompting is a UX defect on its own, but in a coercion scenario it is worse: the unexpected second prompt is a behavioural tell that the device is in a special state. A coerced user asked to "turn off the PIN" would visibly hesitate or fail on the second prompt, signalling to an observer that something unusual is happening.

### Root Cause
`Settings.SecuritySettings` uses `PINEntry(mode: .setup)` for the `.active`/`.duress` disable path and `PINEntry(mode: .verifyNormal)` for the `.pinOnly` path. `.setup` is a two-phase flow (enter, then confirm); `.verifyNormal` is single-entry. The asymmetry is a UI artifact — `disablePINFromCurrentDepth` itself performs exactly one check internally.

### Proposed Resolution
Introduce a `PINEntry.Mode.verifySilent` case: single-entry, calls `checkCurrentLayerPIN` (no counter mutation), delivers the PIN to a caller-supplied closure on match. Replace `.setup` with `.verifySilent` in the `.active`/`.duress` branch of `Settings.SecuritySettings`. Both `.pinOnly` and `.active`/`.duress` then present a single-entry prompt, eliminating the tell.

---

## Bug 5 — App stays in grace period after Secure Mode activation; PIN does not show on scene change for ~5 minutes

**Status:** Open

### Severity: High
Immediately after Secure Mode is activated, the window during which the app can be backgrounded and foregrounded without triggering a PIN prompt is ~5 minutes. An adversary who witnesses activation (or checks the device shortly after) can access the app without a PIN during this window, defeating the purpose of activating Secure Mode in the first place.

### Root Cause
`activateSecureMode` does not clear `lastUnlockDate`. The field retains the timestamp from the most recent `recordUnlock()` call (the PIN entry that unlocked the app before the user started the setup flow). `isWithinGracePeriod` in `OccultaApp` returns `true` until that timestamp is more than 5 minutes old, so background → foreground transitions skip the PIN prompt for the remainder of that window.

### Proposed Resolution
Set `self.lastUnlockDate = nil` at the end of `activateSecureMode`, before the state transition to `.active`. `lastUnlockDate` is `private(set)` but writable from within the class. Setting it to `nil` is sufficient — `isWithinGracePeriod` already returns `false` when `lastUnlockDate` is `nil`.

---

## Bug 6 — Share Extension shows all contacts when selecting encryption recipients while PIN / Secure Mode is active

**Status:** Open

### Severity: Critical
The Share Extension's recipient picker exposes the full, unfiltered contact list regardless of lock state or Secure Mode depth. In a duress scenario an adversary can force the user to "encrypt a file via Share" and use the picker to enumerate every contact — including those intentionally hidden at the current depth. This directly breaks the coercion-resistance guarantee of Secure Mode and leaks the existence of hidden contacts.

### Root Cause
The Share Extension runs as a separate process with its own `ModelContext`. It instantiates `ContactManager` directly without going through `Manager.Security`, so depth-aware filtering is never applied. All SwiftData contacts are returned in the raw fetch, bypassing every security boundary the main app enforces.

### Proposed Resolution
1. At extension launch, read `AppLayerConfig` from the shared SwiftData store and derive the current depth using the same logic as `Manager.Security.init()` — check which verifiers are present, read `persistedDepth`.
2. Apply `isVisible(_:atDepth:)` before populating the picker. Never display contacts until this step completes.
3. If the security state cannot be determined (SE key unreachable, decryption fails), show zero contacts and surface an error — never fail open.
4. Extract the filtering and depth-resolution logic into a shared file both the main app and extension link against, so the filter cannot drift out of sync.

---

## Bug 7 — Hard-delete inside staged key rollback scope causes irrecoverable data loss

**Status:** Open

### Severity: High
In `activateSecureMode`, `hardDeleteContact` is called after all safe contacts have been re-encrypted with the staged key and persisted to the DB — but still inside the `do { } catch { rollbackStagedLocalDBKey() }` block. If `hardDeleteContact` throws, the catch block deletes the staged key, but the DB already contains data encrypted exclusively with it. The canonical key can no longer decrypt any of those records. All contact data is permanently unrecoverable.

### Root Cause
The hard-delete loop sits after the Step 8 re-encryption writes but before `commitStagedLocalDBKey()` (Step 10). Any error in this window triggers a rollback that invalidates the only key capable of reading the already-written DB rows.

### Proposed Resolution
Move the `hardDeleteContact` loop to after `commitStagedLocalDBKey()` (after the point of no return), with its own non-rollback error handling. At that point a delete failure is recoverable: sensitive contacts remain in the DB encrypted under the canonical key; the user can retry activation. No rollback is triggered and no data is lost.

---

## Bug 8 — Vault PEKs unnecessarily stored in the blob

**Status:** Open

### Severity: Medium
`activateSecureMode` Step 6 unwraps every vault entry's per-entry key (PEK) and stores the raw 32-byte key bytes inside `BlobPayload`. The vault key is derived from a dedicated SE key entirely independent of the local DB key rotation — vault entries never need re-keying during activation or deactivation.

`payload.vaultPEKs` is unsealed in `deactivateSecureMode` and silently ignored, confirming the data serves no purpose. Meanwhile, storing raw PEK bytes in the blob unnecessarily widens the attack surface: a blob compromise (requiring only the SE Secure Mode key, no biometrics) now also yields the symmetric keys for all vault entry content, bypassing the biometric gate that normally protects them.

### Proposed Resolution
Remove vault PEK collection from Step 6 of `activateSecureMode` and remove `VaultPEKRecord` and the `vaultPEKs` field from `BlobPayload`. The vault's `visibleThroughDepth` re-encryption (already handled in Step 8) is the only vault-related work the key rotation requires.

---

## Bug 9 — `findBlob` returns an arbitrary file when multiple `.occbak` files exist

**Status:** Open

### Severity: Low
`findBlob` requests `contentModificationDateKey` from the filesystem but never uses it for sorting. `files?.first { $0.pathExtension == "occbak" }` returns whichever file appears first in the enumeration order, which is unspecified on APFS. If two `.occbak` files are present — e.g. a stale file from a prior interrupted `seal()` — the wrong blob may be returned, causing deactivation to fail with `BlobError.decryptionFailed` or to silently unseal stale data.

### Root Cause
The sort step was omitted when the resource key was added. `FileManager.contentsOfDirectory` does not guarantee ordering.

### Proposed Resolution
Sort the result by `contentModificationDateKey` descending before taking `first`, so the most recently written file is always selected.

---

## Bug 10 — `reEncryptKeyRecords` after INSERT in deactivation

**Status:** Closed (Invalid — proposed fix causes data loss)

### Severity: N/A
The original diagnosis claimed the `reEncryptKeyRecords` call after INSERT in `deactivateSecureMode` Step 5 is a no-op because `save(contact:using:stagedCrypto)` already encrypts `contactPublicKeys` via `stagedCrypto`.

This is incorrect. The INSERT path in `ContactManager.save` handles key records via `self.update(key:for:)`, which uses `self.cryptoManager` (the canonical key), not the `crypto` parameter. After INSERT, key records are canonical-key encrypted. `reEncryptKeyRecords` correctly decrypts them with the canonical key and re-encrypts with the staged key.

Removing the call — as the original resolution proposed — would leave key records for every restored contact encrypted with the deactivation-era canonical key. After `commitStagedLocalDBKey()` that key is superseded and deleted, making every restored contact's public key material permanently unreadable.

### Resolution
No code change. The call is correct and must stay.

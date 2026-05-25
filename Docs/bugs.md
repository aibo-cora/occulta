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

## Bug 13 — Hard-delete of sensitive contacts fails silently after WAL checkpoint

**Status:** Open

### Severity: High
After `activateSecureMode` completes, sensitive contacts (those with `visibleThroughDepth < 1`) are supposed to be removed from the SQLite database — their data is sealed in the blob, and the DB hard-delete is the forensic protection that prevents a duress-mode examiner from finding them at the SQLite layer. In practice the hard-delete silently fails: sensitive contacts remain in the DB after activation, meaning the forensic protection does not apply even though depth filtering correctly hides them from the UI in duress mode.

The hard-delete failure was confirmed empirically: with the blob destroyed (Bug 11, now fixed) and a missing-blob fallback that returns `BlobPayload(contacts: [])`, sensitive contacts should be unrecoverable if the delete had succeeded — yet they remain visible in the app after activation, proving they were never removed from the database.

### Root Cause
Step 9 of `activateSecureMode` calls `walCheckpoint(at:)`, which opens a *second* SQLite connection to the same database file and runs `PRAGMA wal_checkpoint(TRUNCATE)`. This external write-level operation disturbs the SwiftData persistent store coordinator's internal state: SwiftData detects an external change to the database and can invalidate or re-merge the in-memory context, wiping the pending deletion marks that a subsequent `modelContext.delete(profile)` would rely on. The `try?` wrapping the hard-delete loop in Step 11 silently swallows the resulting error, leaving sensitive contacts in the database encrypted under the new canonical key.

Note: depth filtering (`isVisible(contact, atDepth:)`) is unaffected — the contacts remain correctly hidden in duress mode at the *UI* layer. The failure is forensic: a raw SQLite examination during duress exposure would reveal the sensitive contact rows.

### Resolution
Pending. Two viable approaches:
- **Option A (simpler):** Move the WAL checkpoint from Step 9 to *after* the hard-delete loop (Step 11). The hard-delete runs while the SwiftData context is still coherent, before the external SQLite connection disturbs it. The hard-delete still happens after `commitStagedLocalDBKey()`, preserving Bug 7's invariant.
- **Option B:** Replace the SwiftData hard-delete with a direct SQLite `DELETE` via a dedicated connection (same pattern as `walCheckpoint`). Bypasses context state entirely; requires manual cascade handling for related records (`PhoneNumber`, `EmailAddress`, `PostalAddress`, `URLAddress`, `Key`).

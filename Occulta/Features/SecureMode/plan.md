# Secure Mode — Implementation Plan

## Step 1 — PIN Infrastructure

- [ ] Convert `Tags` in `Manager.Key` from static-let namespace to `enum Tags: String, CaseIterable` — adding `secureModePin = "secure.mode.pin"`. Any tag added to the enum is automatically included in `deleteAllKeys()` by construction.
- [ ] Simplify `deleteAllKeys()` to iterate `Tags.allCases` — remove the four individual private delete functions. One explicit special case remains: the localDB Keychain random component.
- [ ] Add `kSecureModeKeyInfo` to `SaltInfo`. Add `deriveSecureModeKey()` to `Manager.Key` following the same `ECDH(seKey, G)` → HKDF pattern as vault and shardCustody keys. No biometric gate.
- [ ] Add `deriveSecureModeKey() throws -> SymmetricKey?` to `KeyManagerProtocol`. Add in-memory key pair for it in `TestKeyManager`.
- [ ] Create `SecureModeConfig` SwiftData model:
  - `sealedNormalVerifier: Data` — `AES-GCM(seKey, sentinelBox_normal)`
  - `sealedDuressVerifier: Data` — `AES-GCM(seKey, sentinelBox_duress)`
  - `salt: Data` — 32-byte PBKDF2 salt, stored plaintext
  - `wipeThreshold: Int`
  - Where each `sentinelBox = AES-GCM(HKDF(PBKDF2(pin, salt), label), knownConstant)`
- [ ] Add `SecureModeConfig.self` to the schema in `OccultaApp.swift`. Add `try deleteAll(SecureModeConfig.self)` to `VaultManager.deleteAllData()`.
- [ ] Implement PBKDF2-SHA256 via `CommonCrypto` (`CCKeyDerivationPBKDF`, 600k iterations) — no external dependencies.
- [ ] Implement `PINManager` (`Manager.PINManager`):
  - `configure(normalPIN:duressPIN:wipeThreshold:in:)` — builds and stores sentinels
  - `verify(_ pin: in:) -> PINVerifyResult` — returns `.normal / .duress / .wrong / .wipe`
  - `.wipe` returned when wrong-PIN counter hits 3 OR consecutive-duress counter hits N
  - Wrong PIN: resets duress counter, increments wrong counter
  - Duress PIN: resets wrong counter, increments duress counter
  - Normal PIN: resets both counters
  - All counters in-memory only — never persisted
- [ ] Unit tests via `KeyManagerProtocol` + in-memory `ModelContainer`

---

## Step 2 — PIN Entry UI

- [ ] `PINEntry` SwiftUI view — neutral appearance, no branding that reveals mode
- [ ] Single code path for all three outcomes — identical animations, haptics, and timing regardless of `.normal / .duress / .wrong` result
- [ ] Fixed-duration gate (≥ 500 ms) applied to all outcomes before the result is acted on. `.wrong` runs a synthetic PBKDF2 round to consume the same wall time as the SE operations in `.duress` / `.normal`. Measurable latency difference between paths would be an oracle.
- [ ] Route on result: `.normal` → full app, `.duress` → decoy view, `.wrong` → increment counter, `.wipe` → trigger full panic wipe then present clean state
- [ ] Sit behind debug flag — not wired into app launch yet

---

## Step 3 — Contact Classification + Decoy View

- [ ] Add `isSafe: Bool` to contact SwiftData model — default `false` (sensitive). Existing contacts migrate as sensitive; new contacts created after activation also default to sensitive.
- [ ] Classification UI — pre-populated from stored `isSafe` flag on subsequent activations. User only reclassifies if their situation changed.
- [ ] `SecureModeManager` (`@Observable`):
  - `isActive: Bool`
  - `isDuressActive: Bool`
  - State machine: `.inactive / .active / .duress`
- [ ] Decoy view: filter contact list to `isSafe == true` contacts only
- [ ] Vault tab remains visible in decoy view — shows as empty (all entries deleted from SwiftData during activation; restored on deactivation via blob)
- [ ] Safe contacts remain fully operational in decoy view (send, receive, decrypt `.occ`)
- [ ] No special handling needed for inbound `.occ` from sensitive contacts — contact record absent from SwiftData → fingerprint lookup fails → same unknown sender behavior as any unrecognized file

---

## Step 4 — Blob (Activation / Deactivation)

- [ ] `SecureMode+Blob` — serializes:
  - Sensitive contact SwiftData rows (already ciphertext)
  - Sensitive contact public keys
  - Vault entries with PEKs re-wrapped under a blob key (see encryption below)
- [ ] Blob encryption — two distinct formats depending on storage destination:
  - **On-device** (App Group container): outer = `AES-GCM(seKey, ...)`, inner = `AES-GCM(HKDF(PBKDF2(normalPIN, salt, 600k), "blob-key"), content)`. SE binding prevents offline attacks; PIN provides a second factor.
  - **Exported** (AirDrop / Files / vault backup): passphrase-derived key only — `AES-GCM(HKDF(PBKDF2(passphrase, salt, 600k), "blob-key"), content)`. No SE binding; offline resistance comes from passphrase strength. Reuses `PassphraseManager` — same pattern as existing contact export. The vault backup feature should use this same format.
- [ ] Continuous background blob maintenance — triggered by `ModelContext.didSave` (same notification used by `VaultManager`), incremental updates only. Blob exists with natural timestamps long before activation.
- [ ] Activation sequence (blob already written and current):
  1. Flip active flag
  2. Delete sensitive contact rows + their public keys from SwiftData
  3. Delete all vault entries from SwiftData (blob holds the serialized copy)
  4. Delete vault SE key
  5. Delete prekeys for sensitive contacts from SE
- [ ] Deactivation sequence (normal PIN entry):
  1. Decrypt blob
  2. Restore sensitive contact rows to SwiftData
  3. Generate new vault SE key
  4. Re-wrap all vault PEKs under new vault key
  5. Delete blob
- [ ] `SecureModeOperation` SwiftData record — tracks activation/deactivation intent and current stage. Written before operation begins, deleted on clean completion. On next launch, incomplete record → resume or rollback automatically.
- [ ] Enable `PRAGMA secure_delete = ON` on the SwiftData SQLite store before activation. This overwrites freed pages with zeroes in-place, eliminates plaintext traces without compacting the file. Do **not** `VACUUM` — a sudden large-scale file rewrite after activation is a forensic "cleaned crime scene" signature and resets file metadata timestamps.
- [ ] Blob stored as UUID-named `.occbak` file in the App Group container (`group.com.occulta.shared`) — indistinguishable from routine vault backup. Note: the container is deleted with the app (extensions share the same bundle), so app deletion while active is a permanent wipe.
- [ ] Blob stored with `.completeFileProtection`
- [ ] Random padding appended before encryption — file size must not leak number of sensitive contacts or vault entries
- [ ] Optional: offer manual blob export (AirDrop / Files) as the last step before activation. If the app is deleted while active, the on-device blob is gone; an off-device copy is the only recovery path. Exported blob uses passphrase-based encryption (see above). **Note:** this overlaps directly with the planned vault backup feature — both use passphrase-derived encryption via `PassphraseManager`. Design them together; the export UI and file format should be shared.

---

## Step 5 — App Integration + Panic Trigger Accessibility

- [ ] Wire `PINEntry` as app entry point when `SecureModeManager.isActive`
- [ ] `onOpenURL` handler respects Secure Mode state
- [ ] `scenePhase` changes respect Secure Mode state
- [ ] Surface existing panic wipe (prekeys → contacts → vault → SE keys) via accessible trigger — back tap or shake — reachable outside of Settings → Manage Contacts

---

## Known Limitations

- WAL files and SQLite free pages retain partial forensic traces of deleted rows even after `VACUUM` — SQLite does not provide secure erase
- The blob file, while UUID-named and naturally timestamped via continuous maintenance, is a distinct encrypted container whose existence proves something is protected
- Activation artifacts (deleted prekeys, new vault SE key creation) remain detectable by a sophisticated examiner with full filesystem access
- App deletion while Secure Mode is active is unrecoverable. The App Group container is deleted with the app (all extensions ship in the same bundle, so no app remains to claim the group). The blob is gone; even if the SE key survives app deletion, there is nothing left to decrypt. Users must be warned before activation that app deletion is equivalent to a permanent wipe of sensitive data.
- Secure Mode substantially raises the bar against coercion and mid-tier adversaries. It is not state-actor proof.
- Users in high-risk environments should power off the device and enable Lockdown Mode before anticipated encounters, carry minimal sensitive data, and treat Secure Mode as one layer in a broader operational security posture.

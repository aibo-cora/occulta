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

- [ ] Add `isSafe: Bool` to contact SwiftData model
- [ ] Classification UI — mark each contact as safe or sensitive before activation
- [ ] `SecureModeManager` (`@Observable`):
  - `isActive: Bool`
  - `isDuressActive: Bool`
  - State machine: `.inactive / .active / .duress`
- [ ] Decoy view: filter contact list to `isSafe == true` contacts only
- [ ] Decoy view: hide vault tab
- [ ] Safe contacts remain fully operational in decoy view (send, receive, decrypt `.occ`)
- [ ] No special handling needed for inbound `.occ` from sensitive contacts — contact record absent from SwiftData → fingerprint lookup fails → same unknown sender behavior as any unrecognized file

---

## Step 4 — Blob (Activation / Deactivation)

- [ ] `SecureMode+Blob` — serializes:
  - Sensitive contact SwiftData rows (already ciphertext)
  - Sensitive contact public keys
  - Vault entries with PEKs re-wrapped under `HKDF(PBKDF2(normalPIN, salt, 600k iterations), "blob-key")`
- [ ] Continuous background blob maintenance — triggered by `ModelContext.didSave` (same notification used by `VaultManager`), incremental updates only. Blob exists with natural timestamps long before activation.
- [ ] Activation sequence (blob already written and current):
  1. Flip active flag
  2. Delete sensitive contact rows + their public keys from SwiftData
  3. Delete vault SE key
  4. Delete prekeys for sensitive contacts from SE
- [ ] Deactivation sequence (normal PIN entry):
  1. Decrypt blob
  2. Restore sensitive contact rows to SwiftData
  3. Generate new vault SE key
  4. Re-wrap all vault PEKs under new vault key
  5. Delete blob
- [ ] `SecureModeOperation` SwiftData record — tracks activation/deactivation intent and current stage. Written before operation begins, deleted on clean completion. On next launch, incomplete record → resume or rollback automatically.
- [ ] Enable `PRAGMA secure_delete = ON` on the SwiftData SQLite store before activation. This overwrites freed pages with zeroes in-place, eliminates plaintext traces without compacting the file. Do **not** `VACUUM` — a sudden large-scale file rewrite after activation is a forensic "cleaned crime scene" signature and resets file metadata timestamps.
- [ ] Blob stored as UUID-named `.occbak` file in vault backup location — no dedicated directory, indistinguishable from routine vault backup
- [ ] Blob stored with `.completeFileProtection`
- [ ] Random padding appended before encryption — file size must not leak number of sensitive contacts or vault entries

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
- Secure Mode substantially raises the bar against coercion and mid-tier adversaries. It is not state-actor proof.
- Users in high-risk environments should power off the device and enable Lockdown Mode before anticipated encounters, carry minimal sensitive data, and treat Secure Mode as one layer in a broader operational security posture.

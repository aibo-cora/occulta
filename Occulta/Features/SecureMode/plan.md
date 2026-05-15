# Secure Mode — Implementation Plan

## Implementation Order

**Phase 1 (ship-ready): Single-layer flat duress.** Steps 1–5 implement a fully functional duress PIN → decoy view with blob backup/restore and panic wipe. The plausible deniability stack (arbitrary-depth nesting) is designed but not built in Phase 1. The single-layer path covers 80% of the value and is the foundation everything else rests on; it must be rock-solid before stacking is added.

**Phase 2 (post-ship): Multi-layer stacking.** The `sealedCurrentNormal/Duress` verifier pair and the append-only blob stack are additive changes that build on Phase 1 without modifying its core flows. Phase 2 begins after Phase 1 has been tested end-to-end under adversarial conditions.

---

## Step 1 — PIN Infrastructure

- [ ] Convert `Tags` in `Manager.Key` from static-let namespace to `enum Tags: String, CaseIterable` — adding `secureModePin = "secure.mode.pin"`. Any tag added to the enum is automatically included in `deleteAllKeys()` by construction.
- [ ] Simplify `deleteAllKeys()` to iterate `Tags.allCases` — remove the four individual private delete functions. One explicit special case remains: the localDB Keychain random component.
- [ ] Add `kSecureModeKeyInfo` to `SaltInfo`. Add `deriveSecureModeKey()` to `Manager.Key` following the same `ECDH(seKey, G)` → HKDF pattern as vault and shardCustody keys. No biometric gate.
- [ ] Add `deriveSecureModeKey() throws -> SymmetricKey?` to `KeyManagerProtocol`. Add in-memory key pair for it in `TestKeyManager`.
- [ ] Create `SecureModeConfig` SwiftData model:
  - `sealedNormalVerifier: Data` — Layer 1 normal PIN verifier, **permanent master unwind key**
  - `sealedDuressVerifier: Data` — Layer 1 duress PIN verifier, permanent
  - `sealedCurrentNormalVerifier: Data?` — current layer's normal PIN verifier (nil = Layer 1)
  - `sealedCurrentDuressVerifier: Data?` — current layer's duress PIN verifier (nil = Layer 1)
  - `salt: Data` — 32-byte PBKDF2 salt, stored plaintext, shared across all layers
  - `wipeThreshold: Int`
  - **No `stackDepth` field.** Storing depth as a plaintext integer is a forensic artifact — an examiner reading the SwiftData store would immediately know how many hidden layers exist. Stack depth is implicit in the blob structure (count the payloads); no separate field is needed.
  - Where each `sentinelBox = AES-GCM(HKDF(PBKDF2(pin, salt), label), knownConstant)`; `label` encodes the layer role (e.g., `"secure-mode-normal-l1"`, `"secure-mode-duress-l1"`, `"secure-mode-normal-current"`, …)
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

- [x] Safe contact IDs stored as `safeContactIDsEncrypted: Data?` on `SecureModeConfig` — encrypted JSON `[String]`, never plaintext. Default: all contacts are sensitive (absent from the safe list). Existing contacts and new contacts created after activation default to sensitive.
- [x] Classification UI — pre-populated by decrypting `safeContactIDsEncrypted` on appear; re-encrypted on save. Each push can reclassify within the currently-visible safe set.
- [ ] `SecureModeManager` (`@Observable`):
  - `isActive: Bool`
  - `isDuressActive: Bool`
  - State machine: `.inactive / .active / .duress`
- [ ] Decoy view: filter contact list to contacts that **decrypt successfully with the current SE key**. Safe contacts were re-encrypted with the new key during activation; sensitive contacts were not — their rows remain in SwiftData but decryption returns nil. No explicit safe-list lookup is needed at runtime; the key state is the filter.
- [ ] Vault tab remains visible in decoy view — shows as empty. Vault rows remain in SwiftData but are locked (encrypted with the deleted vault SE key); all decryption attempts return nil.
- [ ] Safe contacts remain fully operational in decoy view (send, receive, decrypt `.occ`)
- [ ] **Inbound `.occ` from hidden contacts suppressed in duress mode.** In normal mode, a file from an unrecognized sender surfaces an "unknown sender" prompt. In duress mode, this prompt must not appear — a coercer who sees unknown sender activity may probe it. Inbound `.occ` files that fail fingerprint resolution in duress mode are silently queued without surfacing any UI. On return to normal mode (full unwind), the queue is processed normally. The queue itself is stored encrypted; its existence is not surfaced anywhere in duress mode.
- [ ] **Soft-delete (forensic hardening, no UI).** When a user deletes a contact, mark the row with `isDeleted: Data?` (encrypted, non-nil = deleted) rather than removing it from SwiftData. Never shown in any view. No recovery path. Cap at 50 soft-deleted rows; when full and a new contact is deleted, hard-delete any one existing soft-deleted row — one DELETE per user-initiated action at capacity, no sorting required. This ships for all users regardless of Secure Mode.

  Soft-deleted rows exist in two natural states depending on key history:
  - **Decryptable:** contact was deleted after the most recent key rotation — encrypted with the current DB key, `isDeleted` non-nil, content readable if the SE key is present.
  - **Locked:** contact was deleted before a key rotation — encrypted with an old (gone) DB key, `isDeleted` non-nil (visible), content unreadable. Indistinguishable from Secure Mode locked rows to a forensic examiner, but distinguishable by the non-nil `isDeleted` marker.

  During Secure Mode activation, soft-deleted contacts require **no special handling**. They are not re-encrypted (they are already deleted — no reason to maintain them). They lock naturally alongside sensitive contacts when the old SE key is deleted. An examiner who sees locked rows with `isDeleted != nil` has a complete innocent explanation: deleted contacts that predate a key rotation were never re-encrypted because there was no functional reason to do so.

  **Future hardening — routine key rotation:** on first launch after each app version increment, and annually on first launch if no update has occurred in 12 months, perform a background DB key rotation for all users: generate a new SE key, re-encrypt all active contact fields under the new DB key, delete the old SE key. Soft-deleted rows are skipped (same as Secure Mode activation — they lock naturally). Cost per rotation: one SE ECDH operation + O(n) AES-GCM re-encryptions, runs in seconds in the background on first launch after update. Result: every user's Keychain history contains rotation timestamps spanning multiple app versions and calendar dates. A rotation timestamp at any given moment becomes statistically indistinguishable from routine maintenance. Do not rotate during active use — background only, on launch.
- [ ] **Decryption-failure contract — enforced at `ContactManager`.** `ContactManager` is the single abstraction between SwiftData and all UI and business logic. The contract is enforced there: `ContactManager` never returns a contact whose fields fail to decrypt. Any view or service that routes through `ContactManager` gets the contract for free. The audit question becomes "does every data path go through `ContactManager`?" rather than "does every call site handle nil correctly?" Paths that bypass `ContactManager` and read SwiftData directly are the audit target. Requirements at every path: no distinctive error logs, no crashes, no UI strings that reveal a failure, no timing differences between a locked record and a never-existing one. Audit scope: contact list rendering, search, Share Index sync, inbound bundle fingerprint resolution, notification payloads, autocomplete/recents, and any share extension path that touches contact identity.

---

## Plausible Deniability Stack — Architecture *(Phase 2)*

### Threat model

A coercer demands access at PIN-point. The goal is that no matter how many PIN entries are coerced, the app behaves identically to an ordinary contacts app at every depth. The coercer can never determine how many layers exist, whether they have reached the bottom, or whether any protected data has been withheld.

### Stack invariants

1. **Arbitrary depth.** There is no cap on the number of layers. Capping at 2 (as VeraCrypt does) is a smoking gun: a coercer who tries to activate another layer and finds it unavailable immediately knows hidden layers exist. Every layer must present an identical "Activate Secure Mode" option.
2. **PIN entry on every foreground.** `PINEntry` is presented on every launch and every `scenePhase` `.active` transition. The screen is indistinguishable regardless of depth.
3. **Deactivation only via PIN screen.** There is no "Deactivate" button in Settings. The only way to unwind a layer is to enter the correct normal PIN at the PIN screen. This prevents accidental data restoration under coercion.
4. **Settings button is 3-state but appears 2-state.** `.inactive` → "Activate Secure Mode". `.active` → "Deactivate Secure Mode". `.duress` → **"Activate Secure Mode"** (identical to `.inactive`, never reveals that a layer is already active). Tapping Activate in duress mode runs the normal activation flow, pushing a new layer.

### Data model changes to `SecureModeConfig`

Two verifier pairs are stored:

| Field | Purpose | Mutability |
|---|---|---|
| `sealedNormalVerifier` | Layer 1 normal PIN — **master unwind key** | Permanent; never overwritten |
| `sealedDuressVerifier` | Layer 1 duress PIN | Permanent; never overwritten |
| `sealedCurrentNormalVerifier: Data?` | Current layer's normal PIN (nil = Layer 1) | Replaced on each push |
| `sealedCurrentDuressVerifier: Data?` | Current layer's duress PIN (nil = Layer 1) | Replaced on each push |
| ~~`stackDepth: Int`~~ | **Removed** — plaintext forensic artifact; depth is implicit in blob payload count | — |

### PIN verification logic (any depth)

Try in this order:

1. PIN matches `sealedNormalVerifier` (Layer 1 original) → **full unwind**: pop ALL stack layers, restore all data, reset to `.active`.
2. PIN matches `sealedCurrentNormalVerifier` (current layer, non-nil) → **pop one layer**: restore current layer's blob payload, install previous layer's verifiers as current, transition to `.active` (or `.duress` if the previous layer was itself in duress).
3. PIN matches `sealedCurrentDuressVerifier` (current layer, non-nil) OR `sealedDuressVerifier` (Layer 1) → **enter duress**: transition to `.duress`, hide sensitive contacts for this layer.
4. Otherwise → **wrong**: increment wrong-PIN counter, apply gate delay.

Note: a PIN collision between Layer 1 normal and a deeper normal PIN is the user's responsibility to avoid. Step 1 always wins.

### Push sequence (Activate from any depth)

1. Collect new normal PIN + duress PIN for the new layer.
2. Build verifiers for the new PIN pair using the existing salt (one salt per device, reused across layers — the PBKDF2 label differentiates layers from one another).
3. Run the key-rotation activation sequence: serialize sensitive contacts + vault into a new blob payload; re-encrypt safe contacts under a new SE key; delete the old SE key. No rows are deleted.
4. Append encrypted payload to the stack blob file.
5. Write new verifiers to `sealedCurrentNormalVerifier` / `sealedCurrentDuressVerifier`.

### Pop sequence (Normal PIN entry at depth N > 1)

1. Decrypt the outermost blob payload.
2. For each (persistentModelID, data): UPDATE the existing locked SwiftData row with re-encrypted data under the new DB key.
3. Restore vault entries; generate fresh prekeys for restored contacts.
4. Remove outermost payload from the stack blob.
5. If one layer above Layer 1: clear `sealedCurrentNormalVerifier` / `sealedCurrentDuressVerifier` to nil.
6. Else: install the previous layer's verifiers as current.

### Full unwind (Layer 1 normal PIN at any depth)

Same as repeated pop N times but in a single atomic pass: decrypt all stack payloads, UPDATE all locked rows, restore everything, delete the blob file, clear verifiers, transition to `.active`.

### What Occulta adopts from VeraCrypt — and what it rejects

| Concept | Decision |
|---|---|
| No magic bytes in blob | **Adopted** — blob has no identifying header; looks like random data |
| Fixed bucket sizes (pad to next bucket boundary) | **Adopted** — prevents contact-count leakage from file size |
| No-metadata blob format | **Adopted** — no creation date, layer count, or version field in blob content |
| Two-layer cap | **Rejected** — arbitrary depth required; any cap is a smoking gun |
| Outer/inner volume sharing physical space | **Not applicable** — Occulta uses an append-only stack in a dedicated file, not nested free-space sharing |

---

## Step 4 — Blob (Activation / Deactivation)

- [ ] `SecureMode+Blob` — each stack payload serializes:
  - For each sensitive contact: its **SwiftData persistent model ID** + plaintext field data (re-encrypted under the blob key). The persistent ID is the restoration handle — it allows UPDATE of the existing locked row on deactivation without a DELETE+INSERT cycle.
  - Sensitive contact identity public keys
  - **Vault PEKs only — not vault file data.** Each vault entry has a Per-Entry Key (PEK, 32 bytes) that is normally wrapped under the vault SE key. The blob contains those unwrapped PEKs re-wrapped under the blob key, plus vault entry metadata (IDs, labels). Vault files themselves remain on disk encrypted with their PEKs. When the vault SE key is deleted during activation, the PEKs cannot be unwrapped — vault files are computationally locked in-place without moving a single byte of file data. On restore, PEKs from the blob are re-wrapped under the new vault SE key; vault files become accessible again. Blob size is therefore independent of vault storage size regardless of how many images or files the vault contains.
  - **Prekeys are not serialized.** Prekey rows for sensitive contacts are locked in-place alongside their contact rows — encrypted with the deleted DB key, unreadable, indistinguishable from any other locked row. On restore, fresh prekeys are generated; old prekey material is unrecoverable and has no value.
- [ ] **Blob is a stack of independently-encrypted payloads in a single file.** Push appends a new payload; pop removes the outermost. Each payload is independently encrypted — a partial-read attack on the file reveals nothing about other layers.
- [ ] Blob encryption — two distinct formats depending on storage destination:
  - **On-device** (App Group container): outer = `AES-GCM(seKey, ...)`, inner = `AES-GCM(HKDF(PBKDF2(normalPIN, salt, 600k), "blob-key"), content)`. SE binding prevents offline attacks; PIN provides a second factor.
  - **Exported** (AirDrop / Files / vault backup): passphrase-derived key only — `AES-GCM(HKDF(PBKDF2(passphrase, salt, 600k), "blob-key"), content)`. No SE binding; offline resistance comes from passphrase strength. Reuses `PassphraseManager` — same pattern as existing contact export. The vault backup feature should use this same format.
- [ ] Each payload is padded to the nearest fixed bucket boundary before encryption. Bucket sizes are powers of 2 (e.g., 64 KB, 128 KB, 256 KB). File size reveals only the bucket tier, not the exact contact or vault entry count.
- [ ] Blob file has no header, no magic bytes, no version field, no layer count. The file name is a UUID with `.occbak` extension — indistinguishable from routine vault backup.
- [ ] Continuous background blob maintenance — triggered by `ModelContext.didSave` (same notification used by `VaultManager`), incremental updates only. Blob exists with natural timestamps long before activation. **Debounced:** coalesce writes within a 30-second window — one blob write per burst of saves, not one per save. Mass contact edits must not produce a burst of blob rewrites.
- [ ] **No-op blob writes on a schedule.** In addition to data-driven updates, rewrite the blob with fresh random padding on a periodic schedule (e.g., every 24 hours of active app use) even when no sensitive data has changed. This decouples the blob's Last Modified timestamp from any meaningful event. A blob last written 3 minutes before device seizure is a signal; a blob written on a rolling daily schedule is not.
- [ ] **Activation sequence — key rotation, no row deletion:**
  1. Generate a new SE key for this layer
  2. Read `safeContactIDsEncrypted` while the old SE key is still live → get the safe contact ID set
  3. Serialize each sensitive contact (not in safe set, `isDeleted = nil`): persistent model ID + plaintext fields → blob payload. Soft-deleted contacts (`isDeleted != nil`) are skipped — they are not re-encrypted and lock naturally in step 7 alongside sensitive contacts.
  4. Serialize vault entries → blob payload (vault rows remain in SwiftData but will be locked)
  5. Re-encrypt each safe contact's fields under the new DB key (derived from the new SE key)
  6. Re-encrypt `safeContactIDsEncrypted` under the new DB key (needed if a second layer is ever activated)
  7. Delete the old SE key — sensitive contact rows, vault rows, and all data encrypted under the old DB key become locked ciphertext in-place. **No rows are deleted. No WAL deletion event occurs.**
  8. Build new layer's verifiers and update `SecureModeConfig`

- [ ] **Deactivation sequence (normal PIN, any depth):**
  1. Decrypt blob payload
  2. For each (persistentModelID, contactData) in blob: fetch the existing SwiftData row by ID and **UPDATE** its fields with data re-encrypted under the new DB key. WAL shows UPDATE operations, indistinguishable from normal contact sync.
  3. Generate new vault SE key; restore vault entries to SwiftData via UPDATE
  4. Generate fresh prekeys for restored contacts
  5. Remove blob payload; update `SecureModeConfig` verifiers

- [ ] **Full unwind (Layer 1 normal PIN from any depth):** same as above but processes all stack payloads in a single atomic pass before clearing verifiers and deleting the blob file.

- [ ] `SecureModeOperation` SwiftData record — tracks activation/deactivation intent and current stage. Written before operation begins, deleted on clean completion. On next launch, incomplete record → resume or rollback automatically. **Design constraints:** all fields must be encrypted (consistent with the rest of the data model); the record's existence must not reveal the operation type — it should be structurally indistinguishable from a routine maintenance task record. An interrupted activation that leaves this record visible should not confirm to a forensic examiner that Secure Mode was being activated.
- [ ] Blob stored in the App Group container (`group.com.occulta.shared`) with `.completeFileProtection`.
- [ ] Optional: offer manual blob export (AirDrop / Files) as the last step before activation. If the app is deleted while active, the on-device blob is gone; an off-device copy is the only recovery path. Exported blob uses passphrase-based encryption (see above). **Note:** this overlaps directly with the planned vault backup feature — both use passphrase-derived encryption via `PassphraseManager`. Design them together; the export UI and file format should be shared.

---

## Step 5 — App Integration + Panic Trigger Accessibility

- [ ] Wire `PINEntry` as app entry point when `SecureModeManager.isActive` (any depth, any state)
- [ ] Present `PINEntry` on **every** `scenePhase` `.active` transition — not just launch. The screen is indistinguishable at every depth.
- [ ] `onOpenURL` handler respects Secure Mode state — inbound `.occ` files are queued until PIN is entered; fingerprint lookup for contacts hidden at the current depth returns "unknown sender"
- [ ] **Decryption-failure audit.** Before shipping, audit every query path in the app against the contract defined in Step 3: `decryptOrNil() == nil` is "does not exist," never "error." Specific paths to verify: `ContactManager` fetch and search, `ExchangeManager` fingerprint resolution, `IdentityChallenge` sender lookup, Share Extension contact index sync, notification content (no contact name or fingerprint leaks for locked records), and any SwiftUI view that accesses contact fields directly. Write a test that activates Secure Mode in-memory, hides a contact, and asserts that every query path returns the same result as if the contact had never been created.
- [ ] Settings Secure Mode button follows the 3-state logic: `.inactive` → "Activate Secure Mode"; `.active` → "Deactivate Secure Mode" (leads to full-unwind PIN confirmation); `.duress` → "Activate Secure Mode" (indistinguishable from inactive — pushes a new layer)
- [ ] "Deactivate" in Settings presents a PIN entry confirming Layer 1 normal PIN before unwinding — prevents accidental deactivation under observation
- [ ] Surface existing panic wipe (prekeys → contacts → vault → SE keys) via accessible trigger — back tap or shake — reachable outside of Settings → Manage Contacts
- [ ] **Forward constraint — notifications.** Occulta does not currently use `UNUserNotificationCenter`. If notifications are added in any future feature, they must respect Secure Mode state: never surface contact names, fingerprints, file activity, or any derivable identifier for contacts that fail to decrypt. This constraint applies to notification titles, bodies, subtitles, and app-switcher previews.

---

## Known Limitations

- **Row count mismatch.** More rows exist in SwiftData than the app displays. These fall into two observable categories: rows with `isDeleted != nil` (soft-deleted contacts — a documented app behavior) and rows with `isDeleted = nil` that cannot be decrypted (attributable to key rotation or migration via the existing `encryptionScheme` versioning field). Neither category is uniquely attributable to Secure Mode. A forensic examiner sees two distinct classes of "extra rows," each with a plausible innocent explanation. This is explicitly preferred over mass DELETE traces, which are unambiguous and precisely timestamped.
- **SE key rotation is observable.** A forensic examiner checking the Keychain will see that a new SE key was created and an old one was deleted. The timestamp of this event is correlatable with activation. This is unavoidable — the key deletion is the mechanism. It is a subtler signal than mass database deletions and lacks the corroboration that a mass DELETE would provide.
- **The blob file exists.** Even UUID-named and naturally timestamped via continuous background maintenance, the presence of an `.occbak` file in the App Group container proves something is being protected. Its size (padded to bucket boundaries) does not reveal content volume.
- **App deletion while Secure Mode is active is unrecoverable.** The App Group container is deleted with the app (all extensions ship in the same bundle, so no app remains to claim the group). The blob is gone. Locked contact rows are also gone. Users must be warned before activation that app deletion is equivalent to a permanent wipe of all hidden data. An off-device exported blob is the only recovery path.
- **Secure Mode substantially raises the bar against coercion and mid-tier adversaries. It is not state-actor proof.**
- Users in high-risk environments should power off the device and enable Lockdown Mode before anticipated encounters, carry minimal sensitive data, and treat Secure Mode as one layer in a broader operational security posture.

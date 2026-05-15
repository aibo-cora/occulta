# Secure Mode — Implementation Plan

## Implementation Order

**Phase 1 (ship-ready): Single-layer flat duress.** Steps 1–5 implement a fully functional PIN lock → duress PIN → decoy view with blob backup/restore and panic wipe. The plausible deniability stack (arbitrary-depth nesting) is designed but not built in Phase 1. The single-layer path covers 80% of the value and is the foundation everything else rests on; it must be rock-solid before stacking is added.

**Phase 2 (post-ship): Multi-layer stacking.** The `sealedCurrentNormal/Duress` verifier pair and the append-only blob stack are additive changes that build on Phase 1 without modifying its core flows. Phase 2 begins after Phase 1 has been tested end-to-end under adversarial conditions.

---

## Core Architecture — `Manager.Security`

`Manager.Security` is the single umbrella for all app-security hardening. It consolidates what was previously three separate types (`SecureModeManager`, `Manager.PINManager`, `SecureModeConfig`) into one `@Observable` class owned by `OccultaApp` and injected via `.environment`.

**Why one type:**
- All three were tightly coupled — `SecureModeManager` read `SecureModeConfig` at init, `PINManager` read and wrote `SecureModeConfig` on every verify, both shared the same SE key derivation path. Keeping them separate forced callers to coordinate all three and created gaps (counter lifetime on view, externally settable state machine).
- `PINManager`'s PBKDF2/AES logic is preserved as a private internal type inside `Manager.Security` for testability, but it is not a public type.

**State machine:**

```
.noPIN   — no PIN configured; app opens directly
.pinOnly — PIN set, Secure Mode not activated; PINEntry on every scene activation
.active  — Secure Mode active; PINEntry on every scene activation; full data visible
.duress  — duress PIN entered; decoy view; hidden contacts locked; hidden vault locked
```

Transitions are owned exclusively by `Manager.Security.verify()` — no external caller can set state directly. The only exception is `activateSecureMode()` and `deactivatePIN()` which are privileged operations that modify persisted config and transition state atomically.

**`Manager.Security` public interface:**

```swift
// Setup
func configurePIN(_ pin: String) throws            // .noPIN → .pinOnly
func activateSecureMode(confirmingNormalPIN: String, duressPIN: String) throws  // .pinOnly → .active
func deactivateSecureMode(confirmingNormalPIN: String) throws   // .active → .pinOnly (Step 4 unwind)
func deactivatePIN(confirmingNormalPIN: String) throws          // .pinOnly → .noPIN

// Verification (owns all state transitions)
func verify(_ pin: String) throws -> PINVerifyResult

// Safe contact membership (used by ContactsListV2 in .duress)
func isSafeContact(_ identifier: String) -> Bool
func updateSafeContacts(_ ids: Set<String>) throws
```

**Interface contracts:**

- `deactivatePIN` is only valid in `.pinOnly`. Calling it in `.active` or `.duress` throws — the caller must deactivate Secure Mode first. This prevents accidentally removing the PIN without completing the full unwind.

- `verify()` in `.noPIN` throws `.notConfigured` rather than returning `.normal`. `PINEntry` should never appear in `.noPIN` state, so a call to `verify()` from that state is a caller contract violation — making it visible via throw is safer than silently passing through.

- `activateSecureMode` is two-phase: (1) verify `confirmingNormalPIN` against the existing verifier — throws immediately if wrong; (2) run key rotation (Step 4). If key rotation fails partway through, the `SecureModeOperation` resume/rollback record handles recovery on next launch. Phase 1 implementation may throw and leave the DB in a known partial state without the resume record — that gets added in Step 4.

**Wipe threshold behaviour by state:**
- `.noPIN` — no PIN, no wipe
- `.pinOnly` — wrong PIN counter increments; NO wipe threshold (user hasn't opted into Secure Mode)
- `.active` / `.duress` — full counter logic: 3 wrong → wipe; N consecutive duress → wipe

**`Manager.Security` owns its own `ModelContext`** derived from the shared `ModelContainer`, consistent with `ContactManager` and `VaultManager`. No caller passes a context to it.

**Dependency graph:**

```
OccultaApp
├── Manager.Security(@Observable)  ← new umbrella
│   ├── ModelContext               ← own context, derived from sharedModelContainer
│   ├── [private] PINManager       ← PBKDF2/AES logic, no longer public
│   └── reads/writes SecureModeConfig (@Model)
│       ├── sealedNormalVerifier: Data
│       ├── sealedDuressVerifier: Data?    ← optional; nil in .pinOnly state
│       ├── salt: Data
│       ├── wipeThreshold: Int
│       ├── isPINEnabled: Bool             ← replaces isActivated
│       ├── isSecureModeActivated: Bool
│       └── safeContactIDsEncrypted: Data?
├── Manager.App(@Observable)
│   ├── ref → ContactManager
│   └── ref → VaultManager
│       eraseAllData() called by Manager.Security on .wipe
├── ContactManager, VaultManager, ShardCustodyManager (unchanged)
└── .environment() injects all downward

PINEntry (View)
├── @Environment Manager.Security   ← replaces direct PINManager instantiation
└── onNormal / onDuress / onWipe closures wired at call site
```

---

## Step 1 — PIN Infrastructure ✅ (partial — needs restructuring)

**Done:**
- [x] `Tags` enum `CaseIterable`, `secureModePin` case
- [x] `deleteAllKeys()` iterates `Tags.allCases`
- [x] `deriveSecureModeKey()` on `Manager.Key` and `KeyManagerProtocol`
- [x] `TestKeyManager` in-memory implementation
- [x] `SecureModeConfig` SwiftData model (needs schema update below)
- [x] `PINManager` PBKDF2/AES logic and unit tests
- [x] `OccultaApp` schema includes `SecureModeConfig`
- [x] `Manager.App` with `eraseAllData()`
- [x] Soft-delete (`deletionToken`) on `Contact.Profile`
- [x] `Contact.Profile.descriptor` centralising `deletionToken == nil` filter
- [x] PQ migration hardening (v1-only predicate, skip soft-deleted rows)

**Remaining:**
- [ ] `SecureModeConfig` schema update: `sealedDuressVerifier: Data?` (was non-optional), rename `isActivated` → `isPINEnabled: Bool` + add `isSecureModeActivated: Bool`
- [ ] Build `Manager.Security` consolidating `SecureModeManager` + `PINManager` — own `ModelContext`, private `PINManager`, state machine `.noPIN / .pinOnly / .active / .duress`
- [ ] `Manager.Security.configurePIN(_:)` — builds `sealedNormalVerifier`, inserts config, transitions `.noPIN → .pinOnly`
- [ ] `Manager.Security.activateSecureMode(confirmingNormalPIN:duressPIN:)` — verifies existing normal PIN, builds `sealedDuressVerifier`, runs key rotation (Step 4), transitions `.pinOnly → .active`
- [ ] `Manager.Security.verify(_:)` owns all state transitions; wipe fires only in `.active` / `.duress`
- [ ] `Manager.Security.deactivatePIN(confirmingNormalPIN:)` — `.pinOnly → .noPIN`
- [ ] `Manager.Security.deactivateSecureMode(confirmingNormalPIN:)` — full unwind (Step 4), `.active → .pinOnly`
- [ ] Replace `SecureModeManager` in `OccultaApp` with `Manager.Security`; remove standalone `SecureModeManager` and public `PINManager`
- [ ] Unit tests via `TestKeyManager` + in-memory `ModelContainer`

---

## Step 2 — PIN Entry UI ✅ (mostly done)

- [x] `PINEntry` SwiftUI view — neutral black appearance, no branding
- [x] 6-digit keypad with `isVerifying` lock preventing double-submission
- [x] Fixed 500ms gate equalising timing across all outcomes
- [x] Routes on result: `.normal` → `onNormal()`, `.duress` → `onDuress()`, `.wrong` → shake + retry, `.wipe` → `onWipe()`
- [ ] `PINEntry` reads `Manager.Security` from environment instead of instantiating `PINManager` directly — counter lifetime moves off the view
- [ ] Wire `onWipe` to `Manager.App.eraseAllData()`
- [ ] Shown when `Manager.Security.state != .noPIN` — not only when Secure Mode is active. A user with only PIN lock enabled sees the same screen as a user with Secure Mode active.

---

## Step 3 — Contact Classification + Decoy View

- [x] Safe contact IDs stored as `safeContactIDsEncrypted: Data?` on `SecureModeConfig`
- [x] Classification UI — pre-populated by decrypting on appear; re-encrypted on save
- [ ] Settings flow:
  - `.noPIN` → "Enable PIN Lock" button (leads to PIN setup)
  - `.pinOnly` → "PIN Lock enabled" + "Activate Secure Mode" button + "Disable PIN Lock" button
  - `.active` → "Deactivate Secure Mode" (leads to normal-PIN confirmation + full unwind)
  - `.duress` → "Enable PIN Lock" (identical to `.noPIN` — never reveals Secure Mode is active)
- [ ] Decoy view: filter contact list to contacts that decrypt successfully with current SE key. Safe contacts were re-encrypted during activation; sensitive contacts were not — decryption returns nil. No explicit safe-list lookup at runtime; the key state is the filter.
- [ ] Vault tab visible in decoy view — shows as empty. Vault rows locked in-place (encrypted with deleted vault SE key).
- [ ] Safe contacts fully operational in decoy view (send, receive, decrypt `.occ`)
- [ ] **Inbound `.occ` from hidden contacts suppressed in duress mode.** Silently queued without surfacing any UI. Queue stored encrypted; existence not surfaced in duress mode. Processed on return to normal.
- [ ] **Decryption-failure contract — enforced at `ContactManager`.** Gate is `String.decryptedValue: String?`:

  ```swift
  /// Returns plaintext under the current device key, or nil if this field
  /// belongs to a hidden Secure Mode layer (key rotated away).
  /// Treat nil as "does not exist" — never substitute a placeholder or log the failure.
  var decryptedValue: String? { ... }
  ```

  Existing `decrypt() -> String` retained for display-only paths where empty string is acceptable. `decryptedValue` is strictly for gating visibility.

  **Share Extension is an out-of-process boundary.** Must never enumerate contact names or identifiers from raw SwiftData rows. All contact access in the extension routes through a shared helper enforcing the same contract.

  **Create `SECURE_MODE_DECRYPT_CONTRACT.md`** — living checklist of every `decryptedValue` call site, indexed by layer, process boundary, and test coverage.

---

## Plausible Deniability Stack — Architecture *(Phase 2)*

### Threat model

A coercer demands access at PIN-point. The goal is that no matter how many PIN entries are coerced, the app behaves identically to an ordinary contacts app at every depth. The coercer can never determine how many layers exist, whether they have reached the bottom, or whether any protected data has been withheld.

### Stack invariants

1. **Arbitrary depth.** There is no cap on the number of layers. Capping at 2 (as VeraCrypt does) is a smoking gun: a coercer who tries to activate another layer and finds it unavailable immediately knows hidden layers exist. Every layer must present an identical "Activate Secure Mode" option.
2. **PIN entry on every foreground.** `PINEntry` is presented on every launch and every `scenePhase` `.active` transition. The screen is indistinguishable regardless of depth.
3. **Deactivation only via PIN screen.** There is no "Deactivate" button in Settings. The only way to unwind a layer is to enter the correct normal PIN at the PIN screen. This prevents accidental data restoration under coercion.
4. **Settings button is 3-state but appears 2-state.** `.pinOnly` / `.inactive` → "Activate Secure Mode". `.active` → "Deactivate Secure Mode". `.duress` → **"Activate Secure Mode"** (identical to `.pinOnly`, never reveals that a layer is already active). Tapping Activate in duress mode runs the normal activation flow, pushing a new layer.

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
- [ ] Continuous background blob maintenance — triggered by `ModelContext.didSave`, incremental updates only. Blob exists with natural timestamps long before activation. **Debounced:** coalesce writes within a 30-second window. **Activation constraint:** during the key-rotation batch, all `ModelContext.didSave` observers that log counts or object identifiers must be temporarily suspended before the batch begins and resubscribed after it completes.
- [ ] **No-op blob writes on a schedule.** Rewrite the blob with fresh random padding every 24 hours of active app use even when no sensitive data has changed. Decouples blob's Last Modified timestamp from any meaningful event.
- [ ] **Activation sequence — key rotation, no row deletion:**
  1. Generate a new SE key for this layer
  2. Read `safeContactIDsEncrypted` while the old SE key is still live → get the safe contact ID set
  3. Serialize each sensitive contact (`deletionToken == nil`, not in safe set): persistent model ID + plaintext fields → blob payload. Soft-deleted contacts (`deletionToken != nil`) are skipped — lock naturally in step 7.
  4. Serialize vault entries → blob payload
  5. Re-encrypt each safe contact's fields under the new DB key
  6. Re-encrypt `safeContactIDsEncrypted` under the new DB key
  7. Delete the old SE key — sensitive contact rows, vault rows, and all data encrypted under the old DB key become locked ciphertext in-place. **No rows are deleted. No WAL deletion event occurs.**
  8. Build new layer's verifiers and update `SecureModeConfig`

- [ ] **Deactivation sequence (normal PIN, any depth):**
  1. Decrypt blob payload
  2. For each (persistentModelID, contactData): fetch the existing SwiftData row by ID and **UPDATE** its fields with data re-encrypted under the new DB key.
  3. Generate new vault SE key; restore vault entries to SwiftData via UPDATE
  4. Generate fresh prekeys for restored contacts
  5. Remove blob payload; update `SecureModeConfig` verifiers

- [ ] **Full unwind (Layer 1 normal PIN from any depth):** same as above but processes all stack payloads in a single atomic pass before clearing verifiers and deleting the blob file.

- [ ] `SecureModeOperation` SwiftData record — tracks activation/deactivation intent and current stage. Written before operation begins, deleted on clean completion. On next launch, incomplete record → resume or rollback automatically. All fields encrypted; record's existence must not reveal the operation type.
- [ ] Blob stored in the App Group container (`group.com.occulta.shared`) with `.completeFileProtection`.
- [ ] Optional: offer manual blob export (AirDrop / Files) as the last step before activation.

---

## Step 5 — App Integration + Panic Trigger Accessibility

- [ ] Wire `PINEntry` as app entry point when `Manager.Security.state != .noPIN`
- [ ] Present `PINEntry` on **every** `scenePhase` `.active` transition
- [ ] `PINEntry` reads `Manager.Security` from environment; `verify()` call drives all state transitions
- [ ] `onWipe` closure wired to `Manager.App.eraseAllData()`
- [ ] `onOpenURL` handler respects Secure Mode state — inbound `.occ` files queued until PIN entered; fingerprint lookup for hidden contacts returns "unknown sender"
- [ ] **Decryption-failure audit.** Before shipping, audit every query path: `ContactManager` fetch and search, `ExchangeManager` fingerprint resolution, `IdentityChallenge` sender lookup, Share Extension contact index sync, notification content. Write a test that activates Secure Mode in-memory, hides a contact, and asserts every query path returns the same result as if the contact had never been created.
- [ ] Settings Secure Mode button follows 4-state logic:
  - `.noPIN` → "Enable PIN Lock"
  - `.pinOnly` → "PIN Lock On" + "Activate Secure Mode"
  - `.active` → "Deactivate Secure Mode"
  - `.duress` → "Enable PIN Lock" (identical to `.noPIN` — never reveals a layer is active)
- [ ] Surface existing panic wipe via accessible trigger — back tap or shake — reachable outside Settings
- [ ] **Forward constraint — notifications.** If notifications are added in any future feature, they must never surface contact names, fingerprints, or any derivable identifier for contacts that fail to decrypt.

---

## Known Limitations

- **Row count mismatch.** More rows exist in SwiftData than the app displays. Soft-deleted rows (`deletionToken != nil`) and locked rows (`deletionToken == nil`, undecryptable) each have a plausible innocent explanation. Neither is uniquely attributable to Secure Mode.
- **SE key rotation is observable.** A forensic examiner checking the Keychain will see a new SE key created and an old one deleted. Timestamp is correlatable with activation. Unavoidable — the key deletion is the mechanism.
- **The blob file exists.** UUID-named and continuously maintained, but its presence in the App Group container proves something is being protected.
- **App deletion while Secure Mode is active is unrecoverable.** The App Group container is deleted with the app. Users must be warned before activation that app deletion is equivalent to a permanent wipe of all hidden data.
- **Secure Mode substantially raises the bar against coercion and mid-tier adversaries. It is not state-actor proof.**
- Users in high-risk environments should power off the device and enable Lockdown Mode before anticipated encounters, carry minimal sensitive data, and treat Secure Mode as one layer in a broader operational security posture.

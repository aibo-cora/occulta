# Secure Mode — Implementation Plan

## Implementation Order

**Phase 1 (ship-ready): Single-layer flat duress.** Steps 1–5 implement a fully functional PIN lock → duress PIN → decoy view with blob backup/restore and panic wipe. The plausible deniability stack (arbitrary-depth nesting) is designed but not built in Phase 1. The single-layer path covers 80% of the value and is the foundation everything else rests on.

**Phase 2 (post-ship): Multi-layer stacking.** Builds on Phase 1 without modifying its core flows. Begins after Phase 1 is tested end-to-end under adversarial conditions.

---

## Core Architecture — `Manager.Security`

`Manager.Security` is the single umbrella for all app-security hardening. `@Observable`, owned by `OccultaApp`, injected via `.environment`.

**State machine:**

```
.noPIN   — no PIN configured; app opens directly
.pinOnly — PIN set, Secure Mode not activated; PINEntry on every scene activation
.active  — Secure Mode active; full data visible
.duress  — duress PIN entered; decoy view; hidden contacts locked
```

State is derived from `SecureModeConfig` on every `init()` — never stored as a plaintext flag:
- `sealedDuressVerifier != nil` → `.active`
- `sealedNormalVerifier != nil` → `.pinOnly`
- no config → `.noPIN`

**Verifier scheme (no PBKDF2):**

`AES-GCM(HKDF(seKey, info: label ∥ pin), sentinel)`

SE key prevents all off-device attacks. PBKDF2 was removed: it added ~1s of main-thread blocking with no real security return — on-device code execution defeats any KDF regardless, and the 6-digit PIN space (1M) is brute-forceable in minutes on GPU independent of iteration count.

**`SecureModeConfig` — current schema (all properties optional, relevant ones encrypted):**

```swift
@Model final class SecureModeConfig {
    var sealedNormalVerifier:     Data?   // nil → .noPIN
    var sealedDuressVerifier:     Data?   // nil → .pinOnly
    var wipeThresholdEncrypted:   Data?   // encrypted Int; default 3
    var safeContactIDsEncrypted:  Data?   // encrypted [String]
}
```

All properties optional to avoid SwiftData migration on schema evolution. `wipeThreshold` is encrypted because it reveals Secure Mode configuration to a forensic examiner.

**`Manager.Security` public interface:**

```swift
// Setup
func configurePIN(_ pin: String) throws                                              // .noPIN → .pinOnly
func activateSecureMode(confirmingNormalPIN: String, duressPIN: String) throws       // .pinOnly → .active
func deactivateSecureMode(confirmingNormalPIN: String) throws                        // .active/.duress → .pinOnly
func deactivatePIN(confirmingNormalPIN: String) throws                               // .pinOnly → .noPIN

// Verification (owns all state transitions)
func verify(_ pin: String) throws -> PINVerifyResult

// Safe contact membership
func isSafeContact(_ identifier: String) -> Bool
func safeContactIDs() -> Set<String>
func updateSafeContacts(_ ids: Set<String>) throws
```

**Interface contracts:**

- `deactivatePIN` is only valid in `.pinOnly`. Caller must deactivate Secure Mode first.
- `verify()` in `.noPIN` throws `.notConfigured` — `PINEntry` should never appear in that state.
- `isLocked: Bool` lives in `OccultaApp` (UI layer), not in `Manager.Security`. It is set to `true` on every `scenePhase == .active` when `security.requiresPIN`, and cleared to `false` in `onNormal`. `Manager.Security` owns state; `OccultaApp` owns the lock gate.

**Wipe threshold behaviour:**
- `.noPIN` / `.pinOnly` — no wipe
- `.active` / `.duress` — 3 wrong PINs → `.wipe`; N consecutive duress entries → `.wipe`

---

## Step 1 — PIN Infrastructure ✅

- [x] `Tags` enum `CaseIterable`, `secureModePin` case, `deleteAllKeys()`
- [x] `deriveSecureModeKey()` on `Manager.Key` and `KeyManagerProtocol`
- [x] `TestKeyManager` in-memory implementation
- [x] `SecureModeConfig` SwiftData model — all optional, `wipeThresholdEncrypted`, no salt, no boolean flags
- [x] `Manager.Security` — own `ModelContext`, `PINManager` internal, state machine `.noPIN/.pinOnly/.active/.duress`
- [x] `Manager.Security.configurePIN(_:)` — builds `sealedNormalVerifier`, inserts config, transitions `.noPIN → .pinOnly`
- [x] `Manager.Security.activateSecureMode(confirmingNormalPIN:duressPIN:)` — verifies normal PIN, builds `sealedDuressVerifier`; key rotation TODO deferred to Step 4
- [x] `Manager.Security.verify(_:)` — owns all state transitions; duress + wrong counters in memory
- [x] `Manager.Security.deactivatePIN(confirmingNormalPIN:)` — `.pinOnly → .noPIN`
- [x] `Manager.Security.deactivateSecureMode(confirmingNormalPIN:)` — `.active/.duress → .pinOnly`; blob unwind TODO deferred to Step 4
- [x] `OccultaApp` schema includes `SecureModeConfig`
- [x] `Manager.App` with `eraseAllData()`
- [x] Unit tests via `TestKeyManager` + in-memory `ModelContainer` (29 tests)

---

## Step 2 — PIN Entry UI ✅

- [x] `PINEntry` view — neutral black, no branding
- [x] 6-digit keypad, `isVerifying` lock preventing double-submission
- [x] Fixed 500ms gate equalising timing across all outcomes
- [x] Two-phase setup: first entry stores PIN, second confirms; label switches "Passcode" → "Confirm Passcode"
- [x] Routes on result: `.normal` → `onNormal(String)`, `.duress` → `onDuress()`, `.wrong` → shake, `.wipe` → `onWipe()`
- [x] Reads `Manager.Security` from environment; counter lifetime off the view
- [x] `onNormal: (String) -> Void` (widened from `()` so Settings can pass PIN to `deactivatePIN`)
- [x] App launch gate in `OccultaApp` — `isLocked` state, `.overlay` on `TabView`, no animation, locks on every `scenePhase == .active`
- [ ] `onWipe` wired to `Manager.App.eraseAllData()` — **deferred; dry-test first**

---

## Step 3 — Settings UI + Contact Classification + Decoy View

### Settings → Security (4-state)

- [x] "Enable PIN" toggle — transitions `.noPIN ↔ .pinOnly` via `PINEntry` sheet
- [ ] "Activate Secure Mode" button — visible when `state == .pinOnly`. Taps into a dedicated sheet using `PINEntry` with a `mode` argument:
  - Mode `.confirmThenSet`: first entry confirms normal PIN, second entry sets duress PIN (with confirm step)
  - Calls `activateSecureMode(confirmingNormalPIN:duressPIN:)` on success
- [ ] "Deactivate Secure Mode" button — visible when `state == .active`. Sheet with `PINEntry` in normal verify mode; calls `deactivateSecureMode(confirmingNormalPIN:)` on success
- [ ] `state == .duress` → Settings → Security shows "Enable PIN" toggle in `on` state only — never reveals Secure Mode exists

### Contact classification

- [x] `safeContactIDsEncrypted` stored and encrypted on `SecureModeConfig`
- [x] `isSafeContact(_:)`, `safeContactIDs()`, `updateSafeContacts(_:)` on `Manager.Security`
- [ ] UI in Settings → Security to designate which contacts are "safe" (visible in decoy view)

### Decoy view

- [ ] `ContactsV2` checks `security.isDuressActive`; filters fetch to `safeContactIDs()` when true
- [ ] `VaultTab` shows empty/unavailable state when `security.isDuressActive`
- [ ] `onDuress` in `OccultaApp` wired: set `isLocked = false` (decoy view is the real app filtered — no special navigation)
- [ ] Inbound `.occ` from hidden contacts silently suppressed in duress mode; queued encrypted; processed on return to `.active`
- [ ] Safe contacts fully operational in decoy view (send, receive, decrypt `.occ`)

---

## Step 4 — Blob (Activation / Deactivation)

- [ ] `SecureMode+Blob` — each stack payload serialises:
  - Per sensitive contact: persistent model ID + plaintext field data re-encrypted under blob key
  - Sensitive contact identity public keys
  - **Vault PEKs only** (not vault file data). Each vault entry's Per-Entry Key, unwrapped and re-wrapped under the blob key. Vault files remain on disk encrypted with their PEKs — locked in-place without moving file data. Blob size is independent of vault storage size.
  - Prekeys are not serialised — locked in-place alongside contact rows; fresh prekeys generated on restore.
- [ ] Blob is a stack of independently-encrypted payloads in a single file. Push appends; pop removes outermost. Partial-read reveals nothing about other layers.
- [ ] Blob encryption: `AES-GCM(HKDF(seKey, info: "blob-key"), content)`. SE binding prevents offline attacks. No PBKDF2 (same rationale as PIN verifier).
- [ ] Each payload padded to nearest power-of-2 bucket boundary before encryption. File size reveals only bucket tier, not contact/vault count.
- [ ] Blob file: no header, no magic bytes, no version field, no layer count. UUID filename with `.occbak` extension — indistinguishable from vault backup.
- [ ] Continuous background blob maintenance triggered by `ModelContext.didSave`. Debounced 30s. Blob exists with natural timestamps before first activation.
- [ ] No-op blob rewrites on a 24h schedule — decouples Last Modified timestamp from meaningful events.
- [ ] **Activation sequence — key rotation, no row deletion:**
  1. Generate new SE key for this layer
  2. Read safe contact IDs while old SE key is live
  3. Serialise sensitive contacts (not soft-deleted, not in safe set) → blob payload
  4. Serialise vault PEKs → blob payload
  5. Re-encrypt safe contacts' fields under new DB key
  6. Re-encrypt `safeContactIDsEncrypted` under new DB key
  7. Delete old SE key — sensitive rows locked in-place
  8. Build verifiers; update `SecureModeConfig`
- [ ] **Deactivation sequence:**
  1. Decrypt blob payload
  2. For each (persistentModelID, data): fetch row by ID, UPDATE fields re-encrypted under new DB key
  3. Generate new vault SE key; restore vault PEKs via UPDATE
  4. Generate fresh prekeys for restored contacts
  5. Remove blob payload; update `SecureModeConfig` verifiers
- [ ] `SecureModeOperation` SwiftData record — tracks activation/deactivation stage. Written before operation begins, deleted on clean completion. All fields encrypted; record's existence must not reveal the operation type. **On next launch, incomplete record → automatic resume or rollback:**
  - Resume: re-enter the operation from the last completed stage (idempotent stage design required)
  - Rollback: restore the previous verifier state, delete any partial blob payload, leave DB rows in their pre-operation encrypted state
  - Activation failure before old SE key deletion → safe to retry from scratch
  - Activation failure after old SE key deletion → must complete forward (no rollback possible; resume is the only path)
  - Runs in a background `Task`; user sees a progress indicator; app backgrounding suspends and resumes on next foreground
- [ ] Blob stored in App Group container (`group.com.occulta.shared`) with `.completeFileProtection`.

---

## Step 5 — Wipe + Panic Trigger

- [x] `PINEntry` shown on every `scenePhase == .active` when `security.requiresPIN`
- [x] `onDuress` / `onWipe` stubs in place (empty — dry-test deferred)
- [ ] `onWipe` wired to `Manager.App.eraseAllData()` — **after dry-testing the full flow**
- [ ] `onOpenURL` respects Secure Mode — inbound `.occ` queued until PIN entered; hidden contact fingerprint lookup returns "unknown sender"
- [ ] Panic trigger accessible from decoy view — back tap or shake — calls `eraseAllData()` immediately without confirmation
- [ ] **Decryption-failure contract** — enforced at `ContactManager`, the single data authority. All fetch and search methods return `nil` (not empty string, not placeholder) for rows that fail decryption. The contract is: `decryptOrNil() == nil` is treated identically to "row never existed" by every caller — no secondary queries, no error logs, no timing differences.
  - A new wrapper type (`SecureModeDataProvider`) is explicitly rejected: it would create a parallel access path and the contract would only be as strong as adoption is universal. Enforce it at the source.
  - **`SECURE_MODE_DECRYPT_CONTRACT.md`** — living checklist of every `decryptOrNil` call site, indexed by layer, process boundary (main app / Share Extension / notifications), and test coverage. Must be updated on every PR that touches contacts or vault. Signed off before Phase 1 ships.
- [ ] **Decryption side-channel audit** before shipping: activate Secure Mode in-memory, hide a contact, assert every query path (`ContactManager`, `ExchangeManager`, `IdentityChallenge`, Share Extension, notifications) returns same result as if the contact never existed. Includes timing: no path should take measurably longer on a decryption failure than on a genuine empty result.

---

## Phase 2 — Plausible Deniability Stack *(post-Phase-1)*

### Threat model

A coercer demands access at PIN-point. No matter how many PIN entries are coerced, the app behaves identically to an ordinary contacts app at every depth. The coercer cannot determine how many layers exist, whether they have reached the bottom, or whether any protected data has been withheld.

### Stack invariants

1. **Arbitrary depth.** No cap. A cap (e.g. VeraCrypt's 2-layer limit) is a smoking gun — a coercer who tries to activate another layer and finds it unavailable immediately knows hidden data exists. Every layer presents an identical "Activate Secure Mode" option.
2. **PIN entry on every foreground.** `PINEntry` is identical regardless of depth.
3. **`state == .duress` → Settings shows "Enable PIN" only.** Never reveals a layer is active. Tapping "Activate Secure Mode" from within a duress view pushes a new layer.
4. **`currentDepth` is in-memory only.** Resets to 0 on every app kill. No persistent depth counter — that would be a forensic artifact. After a kill, the user enters any PIN and is routed to the corresponding level.

### `SecureModeConfig` — Phase 2 schema extension

Parallel arrays in the existing single row (no new rows, no joins):

```swift
// Added for Phase 2 — Phase 1 fields unchanged
var sealedNormalVerifiers:    [Data]   // index = depth; [0] is master (depth 0)
var sealedDuressVerifiers:    [Data]   // index = depth; entry at N drives push to N+1
var safeContactIDsPerLevel:   [Data]   // encrypted [String] per depth
```

The existing `sealedNormalVerifier` / `sealedDuressVerifier` fields become `sealedNormalVerifiers[0]` / `sealedDuressVerifiers[0]`. Migration: on first Phase 2 launch, wrap existing single values into index-0 of the arrays.

### `verify()` ordering at any depth

Given `currentDepth = N`:

1. Try `sealedNormalVerifiers[0]` (master) → match: pop all layers, restore all blobs, `currentDepth = 0`, state = `.active`
2. Try `sealedNormalVerifiers[1..N]` in order 1 → N → first match at K: pop layers K+1..N, restore blobs K+1..N, `currentDepth = K`, state = `.active`
3. Try `sealedDuressVerifiers[N]` → match: push to N+1, `currentDepth = N+1`, state = `.duress`
4. No match → `.wrong`; increment `wrongPINCount`

### PIN uniqueness constraint

At every setup step, validate the candidate PIN against all existing verifiers at all depths. Reject if any verifier opens with the candidate PIN. Without this, a collision between depth K's normal PIN and depth 0's normal PIN silently surfaces the real app when the user intends to stay at level K.

### Cascade delete

Disabling Secure Mode at depth N (i.e. calling `deactivateSecureMode` at depth N) must truncate `sealedNormalVerifiers`, `sealedDuressVerifiers`, and `safeContactIDsPerLevel` to length N, and restore all blob payloads at indices N+1…end. Orphaned deeper configs are unreachable and must not be left in the store.

### What Occulta adopts from VeraCrypt — and what it rejects

| Concept | Decision |
|---|---|
| No magic bytes in blob | **Adopted** |
| Fixed bucket sizes | **Adopted** |
| No-metadata blob format | **Adopted** |
| Two-layer cap | **Rejected** — any cap is a smoking gun |
| Outer/inner volume sharing physical space | **Not applicable** — Occulta uses an append-only stack file |

---

## Known Limitations

- **Row count mismatch.** More rows exist than the app displays. Soft-deleted and locked rows each have plausible innocent explanations. Soft-deleted rows are capped at 50 per entity type (evicted FIFO) to prevent unbounded database growth. Soft-deleted rows must never appear in any UI, Share Index, or query result.
- **SE key rotation is observable.** A forensic examiner checking the Keychain will see a new SE key created and an old one deleted. Timestamp is correlatable with activation. Unavoidable.
- **The blob file exists.** UUID-named and continuously maintained, but its presence in the App Group container proves something is being protected.
- **App deletion while Secure Mode is active is unrecoverable.** The App Group container is deleted with the app. Users must be warned before activation.
- **Counter resets on app kill.** `wrongPINCount` and `consecutiveDuressCount` are in-memory only. A coercer who kills and relaunches resets the wipe counter. Addressed by panic trigger (Step 5).
- **Secure Mode raises the bar against coercion and mid-tier adversaries. It is not state-actor proof.**

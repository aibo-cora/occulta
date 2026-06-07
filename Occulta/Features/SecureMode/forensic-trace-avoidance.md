# Forensic Trace Avoidance

Documents every measure taken to prevent a forensic examiner from detecting Secure Mode activation, recovering sensitive contact data, or observing behavioural tells — even with physical device access and raw filesystem/database tools.

**Severity scale**
- **Critical** — directly exposes sensitive contacts or makes Secure Mode activation detectable without any key material
- **High** — activation timing derivable, sensitive data recoverable with device-level access, or coercion scenario broken
- **Medium** — detectable with specific knowledge and tooling; low operational impact
- **Low** — minor timing or metadata correlation; negligible information value

---

## Blob File Forensics

Measures that prevent the `.occbak` file from being identified as a Secure Mode artefact.

| # | Measure | Severity | Status |
|---|---------|----------|--------|
| B1 | No-op blob exists from first launch | High | ✅ |
| B2 | Last-Modified timestamp normalised to app activity | High | ✅ |
| B3 | Fixed 32-slot file — constant size regardless of payload | Medium | ✅ |
| B4 | UUID filename + `.occbak` extension, no header | Medium | ✅ |
| B5 | SE key created at first launch, not at activation | High | ✅ |
| B6 | Random nonce per write | Low | ✅ |
| B7 | `isExcludedFromBackup = true` | Medium | ✅ |

### B1 — No-op blob from first launch
`maintainNoOpBlob()` runs in `OccultaApp.init()` on every install. A `.occbak` file is written before Secure Mode is ever configured. The file's creation timestamp predates activation by however long the app has been installed. A forensic examiner cannot use the blob's existence or creation date to infer that Secure Mode was activated, or when.

### B2 — Last-Modified timestamp normalisation
`rewriteNoOpBlob()` is called on every `ModelContext` save, debounced to 30 s, when Secure Mode is not active. The blob's Last-Modified timestamp tracks normal app activity (contact edits, vault saves) rather than spiking only at meaningful events like activation or PIN entry. Without this, a single modification timestamp would pinpoint exactly when Secure Mode ran.

### B3 — Fixed 32-slot file
The store file is always exactly `32 × (32 KB + 28)` = **1,049,472 bytes**, regardless of how many sensitive contacts exist or whether Secure Mode has ever been activated. Every slot — real payload or random padding — is sealed to exactly 32 KB of plaintext, producing an identical-sized ciphertext. The file size is constant across all states: no activation, freshly activated with 0 contacts, activated with 30 contacts. Without this, file size would vary with payload size and encode the sensitive contact count or activation state. (Prior to this format, plaintext was bucket-padded to the nearest power-of-2, which was weaker — size still revealed a tier.)

### B4 — UUID filename + `.occbak` extension, no identifying header
Vault backups use the same `.occbak` extension and are indistinguishable at the filesystem level. Vault backups start with a 4-byte "OCBK" magic; blobs do not — the vault restore path rejects blobs via `BackupError.invalidFormat`. No magic bytes, version field, layer count, or anything in the blob that labels it as Secure Mode data.

### B5 — SE key created at first launch
`writeNoOpBlob()` calls `Manager.Key().deriveSecureModeKey()` as a side effect. The Secure Mode SE key is created on first launch, not when Secure Mode is configured. Its Keychain entry's creation timestamp predates activation by the full install lifetime of the app.

### B6 — Random nonce per write; full slot regeneration
Each `push()`, `pop()`, and `rewrite()` re-seals **all 32 slots** with fresh 96-bit random nonces — real payloads and padding alike. Two consecutive blob files are cryptographically unrelated. Without full regeneration, static ciphertext in padding slots would be identifiable by diff, directly flagging which slots hold real payloads and making the permanently-excluded real slot trivially detectable after a few activation cycles.

### B7 — Excluded from backup
`isExcludedFromBackup = true` is set on every blob write. The blob does not appear in iCloud or iTunes/Finder backups. An examiner who obtains a device backup cannot find it.

---

## SQLite / Database Forensics

Measures that prevent recovery of deleted or sensitive data from the raw database file.

| # | Measure | Severity | Status |
|---|---------|----------|--------|
| S1 | DB key rotation on activation (cryptographic erasure) | Critical | ✅ |
| S2 | `PRAGMA secure_delete = ON` | High | ✅ |
| S3 | `.completeFileProtection` on SQLite + WAL + SHM | Critical | ✅ |
| S4 | `.completeFileProtection` re-applied on every save | Medium | ✅ |
| S5 | Sensitive contacts depth-filtered at UI (Design A — accepted forensic gap); page slack covered by S1 + S2 | Medium | ✅ Design decision |
| S6 | `visibleThroughDepth` watermark erased on deactivation | Medium | ✅ Bug 12 fixed |
| S7 | All vault entries stamped hidden under staged key during activation | High | ✅ Bugs 26 & 27 fixed |
| S8 | Vault entry row count and empty-vault UI visible during biometric-coerced duress — accepted gap (content cryptographically protected) | Medium | ✅ Design decision |

### S1 — DB key rotation on activation (cryptographic erasure)
The local DB key is `ECDH(ourSEKey_localDB, G)` — device-bound and accessible when the device is unlocked. In duress mode the device is unlocked, so the current DB key is derivable. Without rotation, an examiner who extracts the raw SQLite file could use the current DB key to decrypt page-slack still containing deleted sensitive contacts. After rotation, deleted pages are encrypted under the old key, which is deleted after commit — the current DB key decrypts nothing from those pages. This is the core reason the DB key rotates on activation.

### S2 — `PRAGMA secure_delete = ON`
Without this, SQLite leaves old ciphertext in free-list pages when rows are deleted or updated. That residue survives WAL checkpoints and is visible in raw disk images. With `secure_delete = ON`, SQLite zeroes freed pages before releasing them, eliminating ciphertext residue entirely. Set at init via a helper SQLite connection; stored in the database header and persists across all future connections, including SwiftData's own.

### S3 — `.completeFileProtection` on all SQLite files
The main `.sqlite`, `-wal`, and `-shm` files are stamped with `FileProtectionType.complete` at init. Files with this class are encrypted by the OS when the device is locked — inaccessible even to jailbreak-level reads. Without this, extracting the SQLite file while the device is locked is possible on a jailbroken device.

### S4 — File protection re-applied on every save
SwiftData can recreate `-wal` and `-shm` sidecar files after WAL merges, schema migrations, and conflict resolution. Newly created sidecar files receive iOS default protection (`completeUnlessOpen`), not `complete`. `OccultaApp` listens to `NSManagedObjectContext.didSaveObjectIDsNotification` and re-stamps all three files on every save so no sidecar can sit with weaker protection.

### S5 — Sensitive contacts remain in DB; page slack covered by S1 + S2
**Design A — intentional choice.** Sensitive contacts are not hard-deleted from the SQLite store. They remain in the DB re-encrypted under the new canonical key (same pass as safe contacts) with `visibleThroughDepth` set to a value that hides them at duress depth. The UI enforces this: at depth 0 (normal PIN) they are shown; at depth 1 (duress PIN) they are hidden by the contact list filter.

**Residual forensic gap:** a raw SQLite examination during a duress exposure can find these rows and decrypt them using the canonical key (derivable on an unlocked device). This is an **explicitly accepted trade-off** for Phase 1.

**Design B considered and deferred.** The alternative design leaves sensitive contacts as unreadable shells in the DB (fields encrypted under the deleted old key), with the blob as the sole readable copy. On normal PIN entry, contacts are loaded from the blob into memory and wiped on lock. An examiner in duress mode finds only unreadable shells — no canonical-key access helps. Design B provides a genuine cryptographic guarantee that Design A does not. It was deferred for Phase 1 in favour of implementation simplicity. The blob infrastructure already supports it; upgrading requires: (1) re-encrypting only safe contacts in activation step 8, (2) loading `inMemorySensitiveContacts` from the blob on normal unlock, (3) wiping that array on lock, (4) merging DB + in-memory contacts in the contact list view. Design B is the correct upgrade path if the threat model is elevated beyond mid-tier adversaries.

**Blob role under Design A.** The blob is sealed at activation with a snapshot of sensitive contacts. Because both the blob key and the DB canonical key derive from SE keys with identical access controls (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, no biometric gate), the blob provides no cryptographic advantage over the DB during a live duress exposure. Its roles are: (1) reliable restoration source during deactivation — deactivation re-encrypts contacts from blob plaintext under the staged key; (2) forensic cover object — present from first launch regardless of Secure Mode state (B1).

Page-slack protection from *pre-activation* rows is handled by S1 (DB key rotation — old key deleted) and S2 (`PRAGMA secure_delete = ON` — freed pages zeroed). Rows that persist across activation are encrypted under the new canonical key and are not residue in the forensic sense.

### S6 — `visibleThroughDepth` watermark erased on deactivation
Activation Step 5 migrates `nil → encrypt(Int.max)` for all safe contacts. Before Bug 12's fix, deactivation re-encrypted this value rather than clearing it, leaving a permanent non-null field on contacts that existed at activation time. An examiner could identify which contacts predated activation without decrypting anything. Deactivation now sets `visibleThroughDepth = nil` for all contacts and vault entries, restoring the pre-activation default.

### S7 — All vault entries stamped hidden under staged key during activation
`activateSecureMode` Step 8 re-encrypts every `VaultEntry.visibleThroughDepth` under the staged key, guaranteeing no entry leaks into duress mode. Three cases are handled without exception:

- **Non-nil, readable** — existing depth value re-encrypted under staged key verbatim.
- **Nil** (Bug 26 — entries predating `addEntry`'s depth stamp) — stamped `encode(0)` under staged key: hidden at all duress depths, visible at depth 0. Consistent with `addEntry`'s own convention for normal-mode entries.
- **Non-nil, unreadable** (Bug 27 — corrupt or wrong-key ciphertext) — treated as `encode(0)` under staged key. Fail-safe to hidden: an entry that is invisible in duress mode is a UX inconvenience; one that is visible is a security failure.

Deactivation Step 6 sets `entry.visibleThroughDepth = nil` unconditionally, restoring the pre-activation default for all entries.

### S8 — Vault entry row count and empty-vault UI: accepted gap
`VaultEntry.id` (UUID) and `createdAt` (Date) are plaintext SwiftData columns. A raw SQLite dump without any key material reveals how many vault entries exist and when they were created. This count is not depth-gated — it is the same whether read at depth 0 or depth N.

**UI mismatch tell.** A coercer who can also force biometric unlock (Face ID) sees the vault UI show 0 entries ("No entries yet") while the raw database contains N rows. That mismatch is a direct tell, structurally identical to the S5 contact-row gap.

**Why this is less severe than S5.** Vault entry *content* (`encryptedLabel`, `encryptedContent`, `encryptedEntryKey`) is sealed under a dedicated SE key that requires a fresh biometric evaluation — entirely independent of the local DB key that rotates during activation. A duress examiner who only holds the duress PIN cannot unlock the vault at all; they see "Vault Locked" with no UI evidence of hidden entries. The mismatch only materialises under the conjunction of duress PIN *and* forced biometric auth — a more demanding attack than PIN-only coercion.

**`visibleThroughDepth` at depth 0.** `addEntry` stamps every new entry with `visibleThroughDepth = encrypt(currentDepth)` even before Secure Mode is configured, so a non-nil value is not itself a Secure Mode tell. However, decrypting the field (canonical DB key, device unlocked) and finding `0` reveals the entry is hidden at all duress depths — confirming that the entry was deliberately excluded from the duress view.

**No mitigation path without architectural change.** Eliminating the row-count tell requires either (a) not persisting vault entries in SQLite — instead keeping them entirely in memory from an SE-encrypted blob, analogous to Design B for contacts — or (b) padding with decoy rows, which adds complexity without a strong attacker model. Both are deferred. The biometric gate on vault content means the current gap exposes only metadata (count, timestamps), not secrets, without biometric coercion.

---

## Keychain / AppLayerConfig Forensics

Measures that prevent detection via Keychain metadata or the persisted config row.

| # | Measure | Severity | Status |
|---|---------|----------|--------|
| K1 | `persistedDepth` + `pinEnabledPerDepth` encoding — gate state opaque | Medium | ✅ |
| K2 | `persistedDepth` and `pinEnabledPerDepth` always populated from first PIN write | Low | ✅ |
| K3 | Blob key HKDF-domain-separated from PIN verifier keys | Medium | ✅ |

### K1 — `persistedDepth` + `pinEnabledPerDepth` encoding
The lock state is stored as two independent encrypted structures on `AppLayerConfig`:
- `persistedDepth` — AES-GCM encrypted `Int`; the full `currentDepth` value persisted when the gate is lowered. Restored via `readPersistedDepth()`. Widened from the two-case `RoutingDepth` enum (Bug 50 fix) to carry depths > 1 from multi-layer coercion stacks.
- `pinEnabledPerDepth` — 32-entry padded array of AES-GCM encrypted `UInt8` values (`1` = gate active, `0` = gate suppressed under coercion). All 32 entries are always present, including random filler entries encrypted to `1`. The entry for the current depth is set to `0` when the user calls `disablePIN(at:confirmingPIN:)`. Restored per-depth via `readPinEnabled(at:)`. Each entry is forensically constant in size: `UInt8` encodes to one byte, so both values produce equal-length sealed boxes regardless of gate state (Bug 51 fix — a `Bool` encoding would differ by one byte).

No plaintext boolean flags. A raw `AppLayerConfig` row is all opaque `Data` — nothing about current gate state or routing depth is recoverable without the SE key.

### K2 — `persistedDepth` and `pinEnabledPerDepth` always populated from first PIN write
`configurePIN` calls `writePersistedDepth(0)` and initialises all 32 `pinEnabledPerDepth` entries to encrypted `1` immediately, so both structures are present from the moment any PIN is set. Without this, field absence vs. presence would distinguish no-PIN from PIN-only or Secure Mode states without any keys. Both structures are always present and always opaque.

### K3 — Blob key HKDF domain separation
Blob key: `HKDF(seKey_secureMode, info: "blob-key")`. PIN verifier keys: `HKDF(seKey_secureMode, info: label ∥ pin)`. Different `info` strings guarantee independent key streams. A blob compromise — requiring SE access but not biometrics — yields nothing about the PIN. A PIN verifier compromise yields nothing about blob content.

---

## UI & Behavioural Tells

Measures that prevent an observer from inferring Secure Mode state from app behaviour or UI differences.

| # | Measure | Severity | Status |
|---|---------|----------|--------|
| U1 | Settings PIN toggle interactive in `.normal` / `.duress` | High | ✅ |
| U2 | Grace period uniform across all depths (no tell from asymmetric behaviour) | High | ✅ Bug 41 fixed |
| U3 | `lastUnlockDate = nil` on activation | High | ✅ Bug 5 fixed |
| U4 | `fullScreenCover` for PIN lock — not underlappable by sheets | High | ✅ Bug 1 fixed |
| U5a | SwiftUI opacity overlay on `.inactive` / `.background` — hides content for PIN gate UX | High | ✅ Bug 54B fixed |
| U5b | Vault `lockGate` — replaces vault list with lock screen when `vault.isUnlocked = false` | High | ✅ (wins race via UIKit notification, SwiftUI render may lag) |
| U5c | `.privacySensitive(true)` on vault entry detail and new-entry sheet | Low | ✅ (widget/Focus Mode redaction only — no effect on OS snapshots) |
| U5d | OS app-switcher snapshot — KTX file taken after `applicationDidEnterBackground` returns (QA1838); animation frame pre-callback | Critical | ⚠️ Open — wrong hook (`willResignActive`) used in prior attempt; correct `didEnterBackground` cover not yet implemented |
| U6 | Share index filtered to depth-1 on lock | Critical | ✅ Bug 6 / Bug 54A fixed |

### U1 — PIN toggle always interactive
In `.normal` and `.duress` states (Secure Mode active), disabling the Settings PIN toggle calls `disablePIN(at:confirmingPIN:)` — it lowers the gate without removing verifiers. When Secure Mode is not active (`isSecureModeActive == false`), the toggle calls `deactivatePIN`. In all cases the toggle is interactive and the UI is indistinguishable. A coerced user asked to "turn off the PIN" produces the same visual result regardless of which state the app is in.

### U2 — Grace period uniform across all depths
`isWithinGracePeriod` applies at any depth — no `isRestricted` short-circuit. Bug 41 removed the unconditional `!self.isRestricted` guard that forced re-lock on every background transition in duress mode. That guard was itself a tell: a coercer who backgrounds and re-foregrounds the app would notice that no grace window exists in duress mode while one clearly existed at the normal-mode unlock screen. Uniform behaviour removes the asymmetry. The `lastUnlockDate = nil` call in `activateSecureMode` continues to force re-lock immediately after activation; no tell is introduced there.

### U3 — Grace period cleared on activation
`activateSecureMode` sets `lastUnlockDate = nil` before transitioning state. The timestamp from the PIN entry that unlocked the app before setup would otherwise allow a ~5 minute window after activation where background→foreground transitions bypass the PIN prompt entirely.

### U4 — `fullScreenCover` for PIN lock
The PIN gate uses `.fullScreenCover` rather than `.overlay`. SwiftUI overlays are layout primitives — iOS modal presentations (`.sheet`, `.fullScreenCover`) are UIKit-level operations that stack above any overlay unconditionally. A `.sheet` triggered by a notification tap or in-app action while locked was previously visible above the overlay PIN lock.

### U5a — SwiftUI opacity overlay (`isContentHidden`)

**Scope:** entire app root. **Layer:** SwiftUI (async render).

`Color(.systemBackground)` at opacity 1 when `security.isContentHidden = true`, opacity 0 otherwise. Applied as a SwiftUI `.overlay` on the root `TabView` — it does not conflict with `UIActivityViewController` or other UIKit modal presentations, which stack above SwiftUI's layer.

`isContentHidden` is set to `true` in:
- `handleInactive()` — when PIN is configured and the app becomes inactive (share sheet, home button, incoming call). Fixed in Bug 54B to remove the `vaultUnlocked` guard that was always false.
- `handleBackground()` — when the app fully backgrounds.
- `handleActive()` — when outside the grace period on foreground return (locked state).

`isContentHidden` is cleared to `false` in:
- `handleActive()` — when within the grace period (auto-unlock).
- `unlockNormal()` / `unlockDuress()` — after successful PIN entry.

**Role:** covers the app content during the PIN gate presentation gap — the window between `needsPINEntry = true` and the `fullScreenCover` PIN entry screen finishing its animation in. Also provides defense-in-depth for background transitions.

**Limitation:** SwiftUI state changes schedule a re-render and do not paint pixels synchronously. The OS may take the app-switcher snapshot before the overlay renders. This is the remaining gap addressed by U5d.

---

### U5b — Vault `lockGate`

**Scope:** vault tab only. **Layer:** SwiftUI conditional (replaces list content).

When `vault.isUnlocked = false`, the vault tab renders a "🔒 Unlock Vault" screen instead of the entry list. The vault locks synchronously via `UIApplication.willResignActiveNotification` — the same notification that fires before `onChange(.inactive)`. This means the lockGate transition is driven by the same UIKit notification that the vault uses to call `lock()`, so the vault's view update is queued at the same time as the UIKit notification processing.

**Why it partially wins the race:** `vault.lock()` runs synchronously in the notification sink, immediately clearing `authContext`. SwiftUI observes the `isUnlocked = false` change and schedules a re-render. This render is still async — on a loaded device it may not complete before the OS snapshot. The lockGate does not unconditionally win the race.

**Role:** ensures that a user who returns to the vault tab after the grace period sees the lock screen, not a stale list. Provides a second layer of content protection on the vault tab specifically.

**Does not replace U5a or U5d:** operates only on the vault tab, not the contacts list, chat screen, or any other sensitive view.

---

### U5c — `.privacySensitive(true)` on vault views

**Scope:** `VaultEntryDetail` (full view), `VaultNewEntrySheet` (seed phrase / note text editor). **Layer:** SwiftUI redaction system.

Marks content as privacy-sensitive for SwiftUI's `\.redactionReasons` environment. Causes automatic redaction in widget contexts and Lock Screen scenarios where the system sets `privacyReasons` in the environment.

**Does not affect OS snapshots.** `.privacySensitive` operates at SwiftUI's layout level; the OS snapshot is a CALayer-level capture of the rendered pixel buffer. The two systems are orthogonal. A `privacySensitive` view is not redacted in the app-switcher KTX file.

**Role:** prevents vault content appearing in Spring Board widgets, Focus Mode summaries, and other system surfaces that may render app content out of context. Correct and worth keeping; not a snapshot defence.

---

### U5d — UIKit privacy window (open — Bug 54 remaining gap)

**Scope:** entire app. **Layer:** UIKit `UIWindow` at `windowLevel > .alert` (synchronous).

A second `UIWindow` created at app init with a neutral view (app logo or blank `systemBackground`). Shown by setting `isHidden = false` synchronously inside `applicationDidEnterBackground`. Torn down by setting `isHidden = true` in `applicationDidBecomeActive`.

**Two separate snapshot surfaces:**

- **KTX forensic file** (`Library/SplashBoard/Snapshots/`): persistent; recoverable by Cellebrite, Magnet AXIOM. Per Apple Technical Q&A QA1838 (https://developer.apple.com/library/archive/qa/qa1838/_index.html): *"The snapshot is captured immediately after `-applicationDidEnterBackground:` returns."* A `UIWindow` installed synchronously in that method — no animation — is in the layer hierarchy when the method returns. iOS photographs the cover, not the underlying content. This measure closes the KTX gap.
- **Animation frame**: the live pixel buffer SpringBoard captures at gesture-start, before any app callback fires. Not persistent; only visible to a co-present observer. Not closed by this measure.

**Ordering with PIN `fullScreenCover`:** `didBecomeActiveNotification` fires before SwiftUI's `onChange(of: scenePhase)` for `.active`. The UIKit window is torn down before `handleActive()` sets `needsPINEntry = true` and the `fullScreenCover` begins presenting. No overlap.

**Relationship to U5a:** the SwiftUI overlay (U5a) remains. The two serve different purposes:
- UIKit window (U5d): closes the KTX snapshot race synchronously in `applicationDidEnterBackground`
- SwiftUI overlay (U5a): covers the PIN gate presentation gap (async, active while PIN entry animates in)

**Condition:** only shown when `security.requiresPIN && security.pinEnabled`. No-op for users without a PIN configured.

**Why prior implementations using `willResignActive` failed:**

`willResignActive` fires for many non-background events: share sheet presentation, incoming call, Face ID prompt, system alert. None of these produce a snapshot. More critically, `willResignActive` fires *before* `applicationDidEnterBackground` — before the KTX capture window opens. The hook was wrong.

Using `willResignActive` also introduces spurious cover flashes: every time the user opens the share sheet, the app momentarily loses focus, the cover installs, then the app returns to active. That is active UX harm for an event that produces no snapshot.

The async Combine delivery (`receive(on: DispatchQueue.main)`) in the first implementation added an additional failure: the UIKit window was enqueued on the run loop rather than installed inline. The 1–2 second visual delay observed in testing was the animation frame showing live content — a pre-callback surface unrelated to which hook was used.

**The remaining open concern — animation frame:**

The animation frame is captured before any app callback. The only reliable defence is a proactive model: sensitive content hidden by default, revealed on interaction, re-covered on inactivity. The app switcher then captures the covered idle state regardless of timing. This is a UX architecture decision, addressed in Bug 54's proposed Level 2 resolution.

---

### U6 — Share index filtered to depth-1 on lock

The share extension reads `ShareIndex.sqlite` from the app group directly — it has no PIN prompt and no access to the main app's security state. When the main app goes `.inactive` with a PIN configured (`requiresPIN && pinEnabled`), the index is immediately rebuilt with `safeContactIDs(atDepth: 1)` — contacts visible at the real layer but hidden at the first duress depth are excluded. Sensitive contacts are removed before the extension can query the index.

`syncShareIndex()` uses the contact DB key (`createHybridLocalEncryptionKey()`), not the vault key — it does not require `vault.isUnlocked`. Bug 54A removed the erroneous `vaultManager.isUnlocked` guard that caused the sync to be skipped on every inactive transition (vault always locks via `willResignActiveNotification` before `onChange(.inactive)` fires).

When the app returns to the foreground while still locked (`needsPINEntry = true`) or in restricted mode (`isRestricted = true`), the index stays at depth-1. On successful PIN entry (`unlockNormal`), the index is rebuilt with `shareIndexAllowedIDs = nil` (full contact list at depth 0).

---

## Content Gating

Measures that prevent sensitive message content from crossing the lock/depth boundary.

| # | Measure | Severity | Status |
|---|---------|----------|--------|
| C1 | Inbound message suppressed at set-time when restricted | High | ✅ Bug 1 fixed |
| C2 | Inbound message discarded at duress-unlock — zero processing before depth known | High | ✅ |

### C1 — Content gate at set-time
When the app is already unlocked in restricted mode (duress depth) and `buildOwnedBasket` runs inside `onOpenURL`, if the sender is not a safe contact the basket is suppressed and the standard "not addressed to you" error is surfaced. Without this, a notification tap while in duress mode could surface a message from a sensitive contact before the depth gate could prevent it.

### C2 — Raw data discarded at duress-unlock (Option B)
When the app is locked and a `.occ` file arrives, `onOpenURL` stores the raw encrypted bytes in `pendingFileData` without any processing — no decryption, no sender identification, no shard operations. If the duress PIN is then entered, `onDuress` clears `pendingFileData` without ever calling `buildOwnedBasket` and shows "This message was not addressed to you." If the normal PIN is entered, `onNormal` calls `processInboundFile(pendingFileData)` — the single function that owns all decryption and display logic. The content never crosses the depth boundary because it is never decrypted until the depth is confirmed as normal.

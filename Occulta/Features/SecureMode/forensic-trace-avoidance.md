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
| S9 | `globalTrusteeDepth` always non-nil; sole trustee mechanism, `GlobalShardConfig` orphaned | Medium | ✅ |

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

### S6 — `visibleThroughDepth` always non-nil; deactivation preserves it
Before Bug 12's fix, deactivation re-encrypted every contact's `visibleThroughDepth` rather than clearing or preserving it correctly, leaving a permanent non-null field on contacts that existed at activation time. An examiner could identify which contacts predated activation without decrypting anything.

Bug 12's original fix made deactivation set `visibleThroughDepth = nil` for all safe contacts, reasoning that nil matched "a contact that never went through Secure Mode." A later fix (May 22) made contact and vault-entry *creation* always stamp a non-nil value (`Int.max` for safe contacts, the real depth otherwise) — closing a related creation-time tell but silently invalidating Bug 12's assumption: after that change, a contact that never touched Secure Mode is also never nil. Bug 12's deactivation reset was carried forward unchanged during the later cascade-deactivation fix (July 30, which correctly stopped flattening genuinely classified contacts to nil but preserved the Int.max→nil branch "for forensic neutrality" — a rationale that no longer held).

Net effect until this fix: deactivation produced a minority of nil rows standing out against a majority-`Int.max` baseline — the opposite of blending in. **Current behavior:** deactivation re-seals safe contacts to `Int.max` under the staged key instead of clearing to nil, matching the same non-nil invariant every contact has carried since creation. A one-time migration (`DatabaseMigration.migrateSafeContactVisibilityBackfill`, run unconditionally on every launch) backfills any legacy nil rows predating the May 22 creation-time fix to `Int.max`. `visibleThroughDepth` is nil only for contacts not yet reached by that backfill; steady-state, no contact should ever be nil.

Vault entries are unaffected by this fix — `VaultEntry.visibleThroughDepth` deactivation (S7) already always preserves the real value and never manufactures nil, so it never had this regression. Its own legacy-nil population (entries predating `addEntry`'s depth stamp) is a separate, smaller, accepted gap: `VaultEntry` uses exact-match depth semantics, not a ceiling, so there is no non-nil value that reproduces nil's "visible at every depth" meaning without a dedicated sentinel — deferred pending a decision on introducing one.

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

### S9 — `globalTrusteeDepth`: always non-nil, sole trustee mechanism

`Contact.Profile.globalTrusteeDepth` marks a contact as a suggested default trustee for
Shamir shard distribution, at a specific depth (exact-match, mirroring
`VaultEntry.visibleThroughDepth`: -1 = not a trustee, N = trustee at exactly depth N).
Designed alongside S6's fix, so it never repeats the nil-as-default mistake: the field
is stamped at contact creation (`Contact+Manager.swift`), preserved through
activation/deactivation re-keying (including the blob round-trip via
`LayerContact.globalTrusteeDepth`), and backfilled for pre-existing contacts
(`DatabaseMigration.migrateGlobalTrusteeDepthBackfill`) — nil is never a valid steady
state, same invariant as `visibleThroughDepth`.

**Sole mechanism at every depth, including 0.** `globalTrusteeDepth` is the only global-
trustee storage `Vault+ShardSetup.swift` and `VaultGlobalTrustees.swift` read or write,
at any depth — a decoy trustee designation made under duress can never leak into the
real suggestion list, and vice versa, because there is exactly one field per contact,
gated by exact depth match. Without this, a vault entry set up while under duress could
seed its trustee suggestions from the real global list, leaking real trustees'
identities into a duress-visible screen — the same shape of leak as the vault-entries
depth bug (see
`Docs/Bugs/v1.10.0/Vault-Entries-Created-At-A-Duress-Depth-Leak-Into-The-Real-Vault.md`).

**`GlobalShardConfig` orphaned, not deleted.** The old flat trustee list this field
replaced (`GlobalShardConfig.trusteeIDs`) is migrated once
(`DatabaseMigration.migrateGlobalShardConfigToPerContact`: stamps `globalTrusteeDepth =
encrypt(0)` for each existing trustee, deletes the row) and then never read or written
by app code again. The model stays declared in the schema for one release, since this
project has no `VersionedSchema`/migration plan and dropping a whole `@Model` type
relies on SwiftData's untested (here) automatic entity-removal inference — not worth
the risk to real user data for what is otherwise a purely cosmetic cleanup. Scheduled
for outright removal once the migration has had time to run in the wild.

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
| U4 | PIN lock rendered by direct phase switch — no presentation layer to underlap | High | ✅ Bug 1 fixed; mechanism superseded by `AppScreen`'s `ScreenPhase` switch (Bug 56) |
| U5a | SwiftUI opacity overlay on `.inactive` / `.background` — hides content for PIN gate UX | High | ✅ Superseded — subsumed into `AppScreen`'s native UIKit cover (see U5d); `isContentHidden`/`handleInactive`/`handleBackground`/`handleActive` removed (Bug 56) |
| U5b | Vault `lockGate` — replaces vault list with lock screen when `vault.isUnlocked = false` | High | ✅ (wins race via UIKit notification, SwiftUI render may lag) |
| U5c | `.privacySensitive(true)` on vault entry detail and new-entry sheet | Low | ✅ (widget/Focus Mode redaction only — no effect on OS snapshots) |
| U5d | OS app-switcher snapshot — KTX file taken after `applicationDidEnterBackground` returns (QA1838); animation frame pre-callback | Critical | ✅ KTX gap closed (Bug 56, confirmed on-device) — ⚠️ animation-frame sub-issue remains open, see below |
| U6 | Share index filtered to depth-1 on lock | Critical | ✅ |

### U1 — PIN toggle always interactive
In `.normal` and `.duress` states (Secure Mode active), disabling the Settings PIN toggle calls `disablePIN(at:confirmingPIN:)` — it lowers the gate without removing verifiers. When Secure Mode is not active (`isSecureModeActive == false`), the toggle calls `deactivatePIN`. In all cases the toggle is interactive and the UI is indistinguishable. A coerced user asked to "turn off the PIN" produces the same visual result regardless of which state the app is in.

### U2 — Grace period uniform across all depths
`isWithinGracePeriod` applies at any depth — no `isRestricted` short-circuit. Bug 41 removed the unconditional `!self.isRestricted` guard that forced re-lock on every background transition in duress mode. That guard was itself a tell: a coercer who backgrounds and re-foregrounds the app would notice that no grace window exists in duress mode while one clearly existed at the normal-mode unlock screen. Uniform behaviour removes the asymmetry. The `lastUnlockDate = nil` call in `activateSecureMode` continues to force re-lock immediately after activation; no tell is introduced there.

### U3 — Grace period cleared on activation
`activateSecureMode` sets `lastUnlockDate = nil` before transitioning state. The timestamp from the PIN entry that unlocked the app before setup would otherwise allow a ~5 minute window after activation where background→foreground transitions bypass the PIN prompt entirely.

### U4 — PIN lock not underlappable by sheets
Originally used `.fullScreenCover` rather than `.overlay`, since SwiftUI overlays are layout primitives while iOS modal presentations (`.sheet`, `.fullScreenCover`) are UIKit-level operations that stack above any overlay unconditionally — a `.sheet` triggered by a notification tap or in-app action while locked was previously visible above the overlay PIN lock.

**Superseded by Bug 56's `AppScreen` refactor.** The PIN gate is no longer a `.fullScreenCover` presentation at all — `OccultaApp.phaseContent` directly `switch`es on `appScreen.phase` (`.covered` / `.pinRequired` / `.unlocked`) and renders `PINEntry` as plain root content when `.pinRequired`. There is no separate presentation layer to underlap in the first place, which is a stronger guarantee than `.fullScreenCover` provided — nothing (sheet, cover, or otherwise) can stack above content that never was a subordinate presentation.

### U5a — Superseded by `AppScreen`'s native UIKit cover

**Historical design (pre-Bug 56):** a SwiftUI `Color(.systemBackground)` opacity overlay on the root `TabView`, toggled by `security.isContentHidden`, set in `handleInactive()`/`handleBackground()`/`handleActive()` and cleared in `handleActive()`/`unlockNormal()`/`unlockDuress()`. Its documented limitation was exactly what motivated U5d: SwiftUI state changes schedule a re-render rather than painting synchronously, so the OS could take the app-switcher snapshot before the overlay actually rendered.

**Current state:** Bug 56 ("Refactor screen lifecycle into `AppScreen`") removed `isContentHidden`, `handleInactive`, `handleBackground`, `handleActive`, and `needsPINEntry` from `Manager.Security` entirely — grep confirms zero references left in the codebase. Content-hiding is now owned exclusively by `AppScreen`'s synchronous UIKit cover (installed in `sceneWillResignActive`/`sceneWillEnterForeground`, see U5d) plus the `.covered` case of `phaseContent`'s `ScreenPhase` switch, which renders `Color.clear` while the cover is up. There is no longer a separate SwiftUI-layer defense distinct from U5d — the two were merged into one synchronous, UIKit-native mechanism specifically to close U5a's own documented async-render gap.

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

### U5d — KTX snapshot: closed by `AppScreen`'s scene-delegate cover (Bug 56)

**Scope:** entire app. **Layer:** UIKit `UIView` cover installed via `UIWindowSceneDelegate` (synchronous).

**Current implementation** (`AppScreen.swift`, replacing the `UIApplicationDelegate`-level design originally proposed here): a plain `UIView` (`.systemBackground` + a centered spinner) is added as a subview of the key window, synchronously, inside `sceneWillResignActive(_:)` — guarded by `secureModeActive` (`security.isSecureModeActive`, i.e. a duress verifier exists at some depth), so it's a no-op for installs that have never configured Secure Mode. It is removed in `pinViewAppeared()` (once `PINEntry` is actually on screen) or immediately in `evaluate()` when no PIN is required. `sceneWillEnterForeground(_:)` re-installs it defensively on every warm return, before `sceneDidBecomeActive` runs `evaluate()` to decide whether it should stay up.

**Two separate snapshot surfaces** (this distinction still holds and is worth keeping in mind):

- **KTX forensic file** (`Library/SplashBoard/Snapshots/`): persistent; recoverable by Cellebrite, Magnet AXIOM. Per Apple Technical Q&A QA1838 (https://developer.apple.com/library/archive/qa/qa1838/_index.html): *"The snapshot is captured immediately after `-applicationDidEnterBackground:` returns."* **✅ Closed, confirmed on-device.** `sceneWillResignActive` fires strictly before `sceneDidEnterBackground` in the standard UIKit lifecycle — the cover is already in the view hierarchy well before the snapshot is taken, and nothing removes it in between (it only comes down on `pinViewAppeared()`/`evaluate()`, both of which run on the *foreground* return path, not before backgrounding). QA1838 only guarantees the snapshot is taken *no earlier than* `applicationDidEnterBackground` returns — it does not require the cover to be installed *in* that specific method, only that it's present and undisturbed by the time the snapshot fires.
- **Animation frame**: the live pixel buffer SpringBoard captures at gesture-start, before any app callback fires. Not persistent; only visible to a co-present observer. **⚠️ Still open** — not closed by this or any hook-timing-based measure; see below.

**Correcting this doc's own prior "wrong hook" claim.** An earlier version of this entry asserted that using `willResignActive`-family hooks (rather than `didEnterBackground`) was the root cause of a failed prior attempt, and marked U5d "Open" on that basis. That diagnosis conflated two distinct problems:
1. A *UX* concern — `willResignActive` also fires for non-backgrounding events (share sheet, incoming call, Face ID prompt, system alert), none of which produce a snapshot, so gating the cover on it alone causes spurious flashes. `AppScreen` avoids this by scoping the cover to `secureModeActive` and tying removal to concrete UI milestones (`pinViewAppeared()`), not by switching hooks.
2. An *implementation* bug in that specific prior attempt — async Combine delivery (`receive(on: DispatchQueue.main)`) enqueued the cover's installation on the run loop instead of executing it inline, producing the observed 1–2 second live-content flash. That was a synchronicity bug, not a hook-choice bug.

Neither problem required `didEnterBackground` specifically — `AppScreen`'s synchronous, inline install at `sceneWillResignActive` closes the actual KTX race, and does so earlier (and therefore at least as safely) as the originally-proposed `didEnterBackground`-based design. The dedicated second-`UIWindow`-at-`windowLevel > .alert` design sketched in earlier drafts of this entry was never built; the shipped `AppScreen` cover (a plain subview, not an elevated window) achieves the same result more simply.

**Relationship to U5a:** subsumed, not parallel — see U5a above. There is now exactly one synchronous cover mechanism, not two.

**Condition:** only installed when `security.isSecureModeActive`. No-op for users without Secure Mode configured.

**The remaining open concern — animation frame:**

The animation frame is captured before any app callback fires at all — before `sceneWillResignActive`, before anything `AppScreen` or any other in-process code can react to. No hook-timing fix closes this. The only reliable defence is a proactive model: sensitive content hidden by default, revealed on interaction, re-covered on inactivity, so the app-switcher's gesture-start frame captures the already-covered idle state regardless of timing. This remains a UX architecture decision, not yet implemented.

---

### U6 — Share index filtered to depth-1 on lock

The share extension reads `ShareIndex.sqlite` from the app group directly — it has no PIN prompt and no access to the main app's security state. `ContactManager+ShareIndex.swift`'s `syncShareIndex()` computes its filter depth at *call time* — `max(security.currentDepth, 1)` when `isSecureModeActive`, clamped so the extension never sees deeper than depth-1 even when the owner is authenticated at real depth 0; unfiltered when Secure Mode was never configured.

**Investigated during the Bug 56 `AppScreen` doc pass: is this still correct?** The pre-Bug-56 design (Bug 6 / Bug 54A) additionally rebuilt the index whenever the app went `.inactive`, via `Manager.Security.handleInactive()`. That specific trigger, and the `shareIndexAllowedIDs` property it wrote, no longer exist — both were removed along with the rest of `Manager.Security`'s old screen-lifecycle code. Traced every remaining path that can change `currentDepth` or `isSecureModeActive` against every existing `syncShareIndex()` call site:
- Unlock / duress-unlock — `PINEntry`'s `onAuthenticated`/`onDuress` (`OccultaApp.swift`).
- Any contact mutation, including classification/sensitivity changes (`saveClassification`/`setVisibility` both end in `modelContext.save()`) — `NSManagedObjectContext.didSaveObjectsNotification` on `ContactManager`'s own context (`Contact+Manager.swift`).
- `activateSecureMode` — `SecureModeSetupFlow.swift`.
- `deactivateSecureMode` — `SecureModeDeactivateFlow.swift`.

No path was found that changes either value without going through one of these four — **the missing `.inactive` trigger was not an active leak**, contrary to this section's own initial read. `syncShareIndex()`'s `max(_, 1)` floor also means true depth-0-only content is excluded from the index unconditionally, from the moment Secure Mode is first configured, independent of staleness.

**Added anyway, as defense-in-depth, not a bug fix:** `OccultaApp.swift`'s `scenePhase` handler now also calls `syncShareIndex()` on `.inactive`. This hedges against (a) the theoretical async-dispatch gap between a contact save and its `.receive(on: DispatchQueue.main)`-deferred resync landing before backgrounding, and (b) any future code path that changes security state without routing through one of the four functions above. `ContactManager+ShareIndex.swift`'s doc comment (previously claiming a `scenePhase == .active` trigger that never existed) now accurately lists all five call sites.

---

## Content Gating

Measures that prevent sensitive message content from crossing the lock/depth boundary.

| # | Measure | Severity | Status |
|---|---------|----------|--------|
| C1 | Inbound message suppressed at set-time when restricted | High | ✅ Bug 1 fixed — ⚠️ see C3, the rejection itself is a new, separate signal |
| C2 | Inbound message discarded at duress-unlock — zero processing before depth known | High | ✅ |
| C3 | Rejecting a known, non-safe sender's bundle under duress is a live duress-detection oracle | Critical | ⚠️ Open, unscoped |

### C1 — Content gate at set-time
When the app is already unlocked in restricted mode (duress depth) and `buildOwnedBasket` runs inside `onOpenURL`, if the sender is not a safe contact the basket is suppressed and the standard "not addressed to you" error is surfaced. Without this, a notification tap while in duress mode could surface a message from a sensitive contact before the depth gate could prevent it.

### C2 — Raw data discarded at duress-unlock (Option B)
When the app is locked and a `.occ` file arrives, `onOpenURL` stores the raw encrypted bytes in `pendingFileData` without any processing — no decryption, no sender identification, no shard operations. If the duress PIN is then entered, `onDuress` clears `pendingFileData` without ever calling `buildOwnedBasket` and shows "This message was not addressed to you." If the normal PIN is entered, `onNormal` calls `processInboundFile(pendingFileData)` — the single function that owns all decryption and display logic. The content never crosses the depth boundary because it is never decrypted until the depth is confirmed as normal.

### C3 — Rejecting a known sender is itself a detectable signal
C1's own mechanism produces a side effect it wasn't evaluated for: at depth 0, a bundle from any known contact always processes normally; at a duress depth, a bundle from a known contact who isn't marked safe *at that exact depth* is rejected outright, with a surfaced error, before decryption starts. Real mode has no code path that ever rejects a genuinely known contact's bundle — so that outcome, from a sender already proven to be paired with the device, is only reachable while restricted. A coercer with physical control of the device (this app's only pairing mechanism is physical UWB proximity, so they already have what's needed to force-pair a test identity) can use this as a direct, repeatable duress-detection test, independent of any content shown or hidden anywhere in the UI. Full write-up, scenario, and the fundamental tension this creates with C1's own purpose: `Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md`. Not yet scoped for a fix.

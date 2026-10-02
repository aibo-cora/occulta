# Forensic Trace Avoidance

Documents every measure taken to prevent a forensic examiner from detecting Secure Mode activation, recovering sensitive contact data, or observing behavioural tells — even with physical device access and raw filesystem/database tools.

**Retired, 2026-09-10 — the blob and local-DB-key-rotation mechanism this document was largely
built around is gone.** `Manager.LayerStore` (the sensitive-contact blob), the staged-key rotation
`activateSecureMode`/`deactivateSecureMode` used to drive, and every re-encryption pass built on top
of it were deleted whole (Removal Stages 0-4, `plan.md`). The reason: this session's own security
analysis (`plan.md`'s Stage 0 decision, `PASSPHRASE_LAYER_KEYS.md`'s honest framing) established that
against the realistic threat model — AFU forensic extraction, code execution on an unlocked device —
an examiner derives the local-DB key and the blob key with equal ease, neither gated by biometrics.
Rotating the key and sealing a blob under a sibling key bought no confidentiality against that
attacker; it only ever protected against a weaker one (a *locked*-device extraction, which the
device's own file-protection classes — S3/S4 below — already cover independently). The **Blob File
Forensics** section and S1 below are retired in full; S5-S7, S9, and K3 are updated to describe what
actually happens now: Secure Mode is UI-only depth filtering, and the file-protection/PRAGMA/timing
measures elsewhere in this document (S2, S3, S4, and everything outside the SQLite section) are
unaffected and remain the document's real protection against raw extraction. Sections retired or
substantively changed are marked inline; original text is kept below each as a historical record,
matching this feature's own convention in `bugs.md`.

**Severity scale**
- **Critical** — directly exposes sensitive contacts or makes Secure Mode activation detectable without any key material
- **High** — activation timing derivable, sensitive data recoverable with device-level access, or coercion scenario broken
- **Medium** — detectable with specific knowledge and tooling; low operational impact
- **Low** — minor timing or metadata correlation; negligible information value

---

## Blob File Forensics — retired, 2026-09-10

**There is no blob.** `Manager.LayerStore`, the `.occbak` sensitive-contact store, and every
measure below that defended it were deleted in full (Removal Stage 2, `plan.md`) — see the notice
at the top of this document for why. Nothing in this section describes shipped code any more. Kept
below verbatim as a historical record of what the blob's own forensic-cover design looked like.

Measures that prevented the `.occbak` file from being identified as a Secure Mode artefact.

| # | Measure | Severity | Status |
|---|---------|----------|--------|
| B1 | No-op blob exists from first launch | High | Retired 2026-09-10 |
| B2 | Last-Modified timestamp normalised to app activity | High | Retired 2026-09-10 |
| B3 | Fixed 32-slot file — constant size regardless of payload | Medium | Retired 2026-09-10 |
| B4 | UUID filename + `.occbak` extension, no header | Medium | Retired 2026-09-10 |
| B5 | SE key created at first launch, not at activation | High | Retired 2026-09-10 |
| B6 | Random nonce per write | Low | Retired 2026-09-10 |
| B7 | `isExcludedFromBackup = true` | Medium | Retired 2026-09-10 |

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
| S1 | DB key rotation on activation (cryptographic erasure) | Critical | Retired 2026-09-10 |
| S2 | `PRAGMA secure_delete = ON` | High | ✅ |
| S3 | `.completeFileProtection` on SQLite + WAL + SHM | Critical | ✅ |
| S4 | `.completeFileProtection` re-applied on every save | Medium | ✅ |
| S5 | Sensitive contacts depth-filtered at UI (accepted forensic gap); page slack covered by S2 | Medium | ✅ Design decision |
| S6 | `visibleThroughDepth` watermark erased on deactivation | Medium | ✅ Bug 12 fixed; see 2026-09-10 update |
| S7 | Vault entries stamped hidden by explicit classification, not by activation | High | ✅ Bugs 26 & 27 fixed; see 2026-09-10 update |
| S8 | Vault entry row count and empty-vault UI visible during biometric-coerced duress — accepted gap (content cryptographically protected) | Medium | ✅ Design decision |
| S9 | `globalTrusteeDepth` always non-nil; sole trustee mechanism, `GlobalShardConfig` orphaned | Medium | ✅ |

### S1 — DB key rotation on activation (cryptographic erasure) — retired, 2026-09-10

**There is no more key rotation.** `activateSecureMode`/`deactivateSecureMode` no longer touch the
local DB key at all — no staged key, no commit, no superseded-key deletion (Removal Stages 0-3,
`plan.md`). The page-slack protection this measure describes is genuinely gone, not merely
unneeded: a deleted contact's page slack, once cryptographically erased by a rotation, is no longer
re-erased by anything. What remains covering deleted-row residue is S2 (`secure_delete = ON`, which
zeroes freed pages at delete time regardless of any key) — a real but different guarantee, since it
protects at the moment of deletion rather than retroactively re-encrypting everything each
activation.

**Why this was removed rather than kept.** The rotation's actual protective value was already
reassessed, independently of this removal, against the realistic threat model: an AFU-capable
examiner derives the local DB key from an unlocked device with no biometric gate, identically before
and after any rotation — there was never a key the rotation put out of that attacker's reach. See
the notice at the top of this document and `plan.md`'s Stage 0 entry for the full reasoning. Kept
below verbatim as a historical record of what the measure did while it existed.

**Original text (historical):** The local DB key is `ECDH(ourSEKey_localDB, G)` — device-bound and
accessible when the device is unlocked. In duress mode the device is unlocked, so the current DB key
is derivable. Without rotation, an examiner who extracts the raw SQLite file could use the current
DB key to decrypt page-slack still containing deleted sensitive contacts. After rotation, deleted
pages are encrypted under the old key, which is deleted after commit — the current DB key decrypts
nothing from those pages. This is the core reason the DB key rotates on activation.

### S2 — `PRAGMA secure_delete = ON`
Without this, SQLite leaves old ciphertext in free-list pages when rows are deleted or updated. That residue survives WAL checkpoints and is visible in raw disk images. With `secure_delete = ON`, SQLite zeroes freed pages before releasing them, eliminating ciphertext residue entirely. Set at init via a helper SQLite connection; stored in the database header and persists across all future connections, including SwiftData's own.

### S3 — `.completeFileProtection` on all SQLite files
The main `.sqlite`, `-wal`, and `-shm` files are stamped with `FileProtectionType.complete` at init. Files with this class are encrypted by the OS when the device is locked — inaccessible even to jailbreak-level reads. Without this, extracting the SQLite file while the device is locked is possible on a jailbroken device.

### S4 — File protection re-applied on every save
SwiftData can recreate `-wal` and `-shm` sidecar files after WAL merges, schema migrations, and conflict resolution. Newly created sidecar files receive iOS default protection (`completeUnlessOpen`), not `complete`. `OccultaApp` listens to `NSManagedObjectContext.didSaveObjectIDsNotification` and re-stamps all three files on every save so no sidecar can sit with weaker protection.

### S5 — Sensitive contacts remain in DB; UI-only depth filtering

**Updated, 2026-09-10.** Sensitive contacts were never hard-deleted from the SQLite store (that was
Bug 13's own finding, closed as a design decision below this entry). What changed is *why* they
remain readable: there is no more re-encryption pass at all — `activateSecureMode`/
`deactivateSecureMode` do not touch `Contact.Profile` fields (Removal Stages 0-3, `plan.md`). A
contact's `visibleThroughDepth` is set once, by the same explicit classification action
(`ContactManager.setVisibility`/`saveClassification`) whether or not Secure Mode has ever been
activated, and stays exactly as written until the user changes it again. The UI enforces visibility
the same way it always did: at depth 0 (normal PIN) a contact classified sensitive is shown; beyond
its ceiling, it is hidden by the contact list filter.

**Residual forensic gap, unchanged in shape:** a raw SQLite examination during a duress exposure can
find these rows and decrypt them using the canonical key (derivable on an unlocked device, no
biometric gate). This was already an **explicitly accepted trade-off** before this removal — the
removal did not create this gap, it removed a rotation step that this session's own security analysis
established was not meaningfully closing it either (see the notice at the top of this document).

**Design B is not a future upgrade path any more — the machinery it would have required is gone.**
The alternative design this entry used to describe (sensitive contacts as unreadable DB shells, the
blob as sole readable copy, contacts loaded into memory on unlock and wiped on lock) depended entirely
on `Manager.LayerStore` and the staged-key rotation, both deleted. Building it again would mean
re-building the blob mechanism from nothing, against the same security analysis that concluded it
wasn't buying real protection against the realistic threat model. Bug 108, which found Design B's own
missing fifth step (no mechanism to persist a mid-session edit), is closed as moot for the same
reason — nothing is asking that question any more.

Page-slack protection from any deleted row is handled by S2 (`PRAGMA secure_delete = ON` — freed
pages zeroed at deletion time) alone now; S1's rotation-based re-erasure is retired, see above.

### S6 — `visibleThroughDepth` always non-nil

**Updated, 2026-09-10.** The migration and creation-time invariant this entry describes are
unaffected by the removal — `visibleThroughDepth` is still always non-nil from creation onward
(`Int.max` for safe contacts, the real depth otherwise), and `DatabaseMigration.
migrateSafeContactVisibilityBackfill` still backfills any legacy nil rows on every launch. What no
longer applies is the *deactivation* half of this entry's history: there is no more "deactivation
re-seals safe contacts to `Int.max` under the staged key" step, because deactivation does not touch
`Contact.Profile` at all now. The invariant this entry protects (no contact is ever observably nil in
steady state) is maintained entirely by the creation-time stamp and the launch migration — it no
longer has a second enforcement point at deactivation, because there is nothing left for deactivation
to re-seal or accidentally regress.

Vault entries: see S7 below, substantially rewritten — the "deactivation always preserves the real
value" claim this paragraph used to make about them no longer holds the way it used to.

### S7 — Vault entry visibility: creation-time stamp only, no lifecycle reset

**Rewritten, 2026-09-10 — this entry used to describe activation/deactivation actively managing every
vault entry's visibility on every cycle. That no longer happens, and the difference is not purely
cosmetic — see the note at the end.**

`VaultEntry.visibleThroughDepth` is stamped exactly once, at creation, with `currentDepth`
(`Vault+Manager.swift:253`, `Vault+Manager+Backup.swift:280`), and compared by **exact match**
(`value == depth`, not a ceiling — `Vault+Model.swift:267`'s own doc comment explains why: a ceiling
would let an entry created at a duress depth leak upward into every shallower depth, including the
real depth-0 vault). Nothing else writes this field any more. The three historical cases this entry
used to describe activation handling (Bugs 26 and 27, both about what happens to a nil or unreadable
stamp) are moot as *activation-time* concerns — activation runs no loop over vault entries at all —
but their underlying fail-safe answer is unchanged at the one remaining read site:
`Manager.Security.isEntryVisible` passes `whenUnclassified: false`, so a nil or undecryptable stamp
still resolves to hidden while restricted, regardless of how it got that way.

**What actually changed, and why it matters:** activation's old bulk re-stamp and deactivation's old
bulk reset (`entry.visibleThroughDepth = nil` on every deactivation) together guaranteed that a stale
depth stamp from one duress session could never survive into a later, unrelated one — depth *numbers*
are reused across duress sessions (a fresh activation always walks back up through 1, 2, 3... the same
way), so without a reset, an entry created during one duress session can resurface in a later,
unrelated session that happens to reach the same depth number. Filed as **`bugs.md` Bug 110** — low
severity (it resurfaces content at the same restriction level it was already exposed to, not a leak
into a safer view; S7's core exact-match protection against upward leakage into the real vault is
unaffected), open, not fixed in this removal effort.

### S8 — Vault entry row count and empty-vault UI: accepted gap
`VaultEntry.id` (UUID) and `createdAt` (Date) are plaintext SwiftData columns. A raw SQLite dump without any key material reveals how many vault entries exist and when they were created. This count is not depth-gated — it is the same whether read at depth 0 or depth N.

**UI mismatch tell.** A coercer who can also force biometric unlock (Face ID) sees the vault UI show 0 entries ("No entries yet") while the raw database contains N rows. That mismatch is a direct tell, structurally identical to the S5 contact-row gap.

**Why this is less severe than S5.** Vault entry *content* (`encryptedLabel`, `encryptedContent`, `encryptedEntryKey`) is sealed under a dedicated SE key that requires a fresh biometric evaluation — entirely independent of the local DB key (which no longer rotates at all — see S1). A duress examiner who only holds the duress PIN cannot unlock the vault at all; they see "Vault Locked" with no UI evidence of hidden entries. The mismatch only materialises under the conjunction of duress PIN *and* forced biometric auth — a more demanding attack than PIN-only coercion.

**`visibleThroughDepth` at depth 0.** `addEntry` stamps every new entry with `visibleThroughDepth = encrypt(currentDepth)` even before Secure Mode is configured, so a non-nil value is not itself a Secure Mode tell. However, decrypting the field (canonical DB key, device unlocked) and finding `0` reveals the entry is hidden at all duress depths — confirming that the entry was deliberately excluded from the duress view.

**No mitigation path without architectural change.** Eliminating the row-count tell requires either (a) not persisting vault entries in SQLite — instead keeping them entirely in memory from an SE-encrypted blob, analogous to Design B for contacts — or (b) padding with decoy rows, which adds complexity without a strong attacker model. Both are deferred. The biometric gate on vault content means the current gap exposes only metadata (count, timestamps), not secrets, without biometric coercion.

### S9 — `globalTrusteeDepth`: always non-nil, sole trustee mechanism

`Contact.Profile.globalTrusteeDepth` marks a contact as a suggested default trustee for
Shamir shard distribution, at a specific depth (exact-match, mirroring
`VaultEntry.visibleThroughDepth`: -1 = not a trustee, N = trustee at exactly depth N).
Designed alongside S6's fix, so it never repeats the nil-as-default mistake: the field
is stamped at contact creation (`Contact+Manager.swift`) and updated only by the explicit
trustee-designation action (`ContactManager+Classification.swift`) — a deliberate,
depth-level policy choice, not a byproduct of Secure Mode's lifecycle. **Updated,
2026-09-10:** the "preserved through activation/deactivation re-keying" this entry used
to describe no longer applies — activation/deactivation touch no `Contact.Profile` field
at all now (Removal Stages 0-3, `plan.md`), so this field is simply never touched by
either, the same way S6 describes for `visibleThroughDepth`. It is unaffected by the
`VaultEntry` depth-reuse gap (`bugs.md` Bug 110) for the same reason `originDepth` is:
a global-trustee designation is a deliberate per-depth-severity policy meant to apply
consistently to any future session reaching that depth, not a session-specific accident.
Backfilled for pre-existing contacts (`DatabaseMigration.migrateGlobalTrusteeDepthBackfill`)
— nil is never a valid steady state, same invariant as `visibleThroughDepth`.

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
| K3 | Blob key HKDF-domain-separated from PIN verifier keys | Medium | Retired 2026-09-10 |

### K1 — `persistedDepth` + `pinEnabledPerDepth` encoding
The lock state is stored as two independent encrypted structures on `AppLayerConfig`:
- `persistedDepth` — AES-GCM encrypted `Int`; the full `currentDepth` value persisted when the gate is lowered. Restored via `readPersistedDepth()`. Widened from the two-case `RoutingDepth` enum (Bug 50 fix) to carry depths > 1 from multi-layer coercion stacks.
- `pinEnabledPerDepth` — 32-entry padded array of AES-GCM encrypted `UInt8` values (`1` = gate active, `0` = gate suppressed under coercion). All 32 entries are always present, including random filler entries encrypted to `1`. The entry for the current depth is set to `0` when the user calls `disablePIN(at:confirmingPIN:)`. Restored per-depth via `readPinEnabled(at:)`. Each entry is forensically constant in size: `UInt8` encodes to one byte, so both values produce equal-length sealed boxes regardless of gate state (Bug 51 fix — a `Bool` encoding would differ by one byte).

No plaintext boolean flags. A raw `AppLayerConfig` row is all opaque `Data` — nothing about current gate state or routing depth is recoverable without the SE key.

### K2 — `persistedDepth` and `pinEnabledPerDepth` always populated from first PIN write
`configurePIN` calls `writePersistedDepth(0)` and initialises all 32 `pinEnabledPerDepth` entries to encrypted `1` immediately, so both structures are present from the moment any PIN is set. Without this, field absence vs. presence would distinguish no-PIN from PIN-only or Secure Mode states without any keys. Both structures are always present and always opaque.

### K3 — Blob key HKDF domain separation — retired, 2026-09-10
**There is no blob key.** The blob it was separated from was deleted along with the rest of `Manager.LayerStore` (Removal Stage 2, `plan.md`) — see the notice at the top of this document. Kept below verbatim as a historical record.

**Original text (historical):** Blob key: `HKDF(seKey_secureMode, info: "blob-key")`. PIN verifier keys: `HKDF(seKey_secureMode, info: label ∥ pin)`. Different `info` strings guarantee independent key streams. A blob compromise — requiring SE access but not biometrics — yields nothing about the PIN. A PIN verifier compromise yields nothing about blob content.

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

### U6 — Share index removed; the extension no longer reads contacts

**Resolved by deletion, 2026-08-16.** This section used to describe how `ShareIndex.sqlite` — a
mirror of the contact list living in the App Group so the share extension could draw a recipient
picker — was kept filtered to depth 1 at all times, since the extension has no PIN prompt and no
access to the security state.

The picker moved into the main app (Bug 84), behind the PIN gate, where the authenticated depth is
known. `syncShareIndex()`, its five call sites, and the `ShareableContact` model are gone, and
`ShareSession.removeLegacyContactIndex` deletes the file and its `-wal`/`-shm` companions from the
App Group on every foreground, so an upgrade does not leave the mirror behind. The rows were always
AES-GCM sealed, but the file's existence, row count, sizes, and mtime are relationship metadata, and
nothing reads them any more.

What this retires: the entire class of defect where the mirror was written at the wrong depth —
Bugs 6, 65, 66, 67, 68, and 69 — along with the reconciliation argument this section carried, which
had to enumerate every path that could change `currentDepth` or `isSecureModeActive` and check each
one against a `syncShareIndex()` call site. There is no longer a second copy to keep in agreement
with the first.

What remains in the App Group: `pending/<session-uuid>/`, holding files the user has explicitly
chosen to share, sealed under the share-staging SE key (`ShareStagingKeyManager`, formerly
`ShareIndexKeyManager`) with `.completeFileProtection`, named positionally, swept after an hour.
That key keeps its `share.index` tag and HKDF info string — it still seals staged files and
manifests, and changing either would strand it.

One consequence worth recording here rather than only in the bug: the old `max(currentDepth, 1)`
clamp meant a contact classified as real-only could not be reached from the iOS share sheet at any
depth, including depth 0. The in-app picker runs at the authenticated depth, so that contact is now
shareable — at depth 0, and only there.

---

## OS-Level Artifacts Outside the Container

Added 2026-08-15. Every other section of this document covers artifacts *this app writes*, where
file protection (S3) applies. These two are different in kind: iOS writes them, they live outside
the app container, and **this app's own file-protection measures cannot reach them** — nothing this
app does, deactivation included, touches either. That makes them the weakest link in the document,
and they were absent from it until now. (**Historical note, 2026-09-10:** this paragraph originally
also named key rotation, S1, alongside file protection as a measure that couldn't reach these
artifacts. S1 itself is now retired — see the notice at the top of this document — so the point
simplifies rather than changes: file protection was always the one that mattered for artifacts
outside the container, since rotation never touched anything outside it either.)

| # | Measure | Severity | Status |
|---|---------|----------|--------|
| O1 | Sensitive text inputs excluded from the keyboard's dynamic lexicon | High | ✅ (residual: pre-existing entries) |
| O2 | Sensitive copies are device-local and expiring | High | ✅ (residual: in-window readability) |

### O1 — Keyboard dynamic lexicon

**Scope:** vault label and content editor (`Vault+NewEntrySheet.swift`), shared contact text row
(`ContactFormV2.swift`). **Layer:** `UITextInputTraits` via SwiftUI modifiers.

iOS learns words typed into ordinary text inputs and stores them in the keyboard's dynamic lexicon
at `/private/var/mobile/Library/Keyboard/*-dynamic-text.dat`. That file is outside the app
container, is not covered by our `.completeFileProtection`, is encrypted under no Occulta key, and
**survives deactivation and key rotation** — so a seed phrase typed into the vault was recoverable
from a device image long after S1 had cryptographically erased the vault itself.

**Measure:** `.autocorrectionDisabled()` on all three inputs — which maps to
`UITextInputTraits.autocorrectionType = .no`, the standard mitigation for this vector (OWASP MASVS
MSTG-STORAGE-5) — plus `.textInputAutocapitalization(.never)` on the content editor, where
never-capitalize is also plain correctness, since seed phrases are lowercase.

**Not affected: the PIN.** `PINEntry` is a custom `KeypadButton` grid and never raises the system
keyboard, so no PIN digit has ever reached the lexicon.

**Distinct from U5c.** That editor already carried `.privacySensitive(true)`, which addresses
SwiftUI's redaction system — widgets, Lock Screen, Focus summaries. Orthogonal surface. Its presence
is why this gap survived: the field looked handled.

**Residual — words typed before this shipped are still in the lexicon, and nothing here removes
them.** The lexicon is per-keyboard, not enumerable by the app, and has no API for selective
deletion; it ages out only as the user types other things. The only user-side reset is
Settings → General → Transfer or Reset iPhone → Reset → Reset Keyboard Dictionary, which is itself
a conspicuous act. **Third-party keyboards are outside this measure entirely** — they receive
keystrokes in their own process with their own storage, and `autocorrectionType` is advisory to
them at best.

---

### O2 — System pasteboard and Universal Clipboard

**Scope:** vault entry copy (`Vault+EntryDetail.swift`), signed message copy (`Sign.swift`),
composed message copy (`ComposableMessage.swift`). **Layer:** `UIPasteboard.general`.

`UIPasteboard.general` persists indefinitely, is readable by any app on the device, and — the part
that matters most here — **syncs to the user's other Apple devices over Universal Clipboard unless
`.localOnly` is set**. A decrypted vault entry assigned to `.string` therefore left the device over
the network, which nothing else in this app does at all.

**Measure:** all three sites go through `UIPasteboard.copySensitive(_:)`
(`Occulta/Extensions/UIPasteboard.swift`), which sets `.localOnly: true` and a 120 s
`.expirationDate`. A single entry point rather than three inline fixes, because the failure mode was
precisely that one site already knew the pattern and the two carrying the more sensitive payloads
did not.

**Residual — the pasteboard is still readable by every app on the device for those 120 s**, and the
expiry is enforced by the OS, not by us; a forensic image captured inside the window may contain the
plaintext. `.localOnly` closes the cross-device hop, not on-device exposure.

**Not a defect: pasting into another app moves plaintext beyond our reach.** That is what the copy
button is for, and no measure here should try to prevent it.

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

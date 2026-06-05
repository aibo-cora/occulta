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

---

## Wipe State Forensics

Measures that prevent the content-wipe state from being detectable as a forensic artifact.

| # | Measure | Severity | Status |
|---|---------|----------|--------|
| W1 | `activeWipeDepth` always non-nil — sentinel masks wipe occurrence | Low | ⬜ Pending implementation |
| W2 | Content deletion via hard-delete + `secure_delete = ON` | Medium | ⬜ Pending implementation |

### W1 — `activeWipeDepth` always non-nil

`AppLayerConfig.activeWipeDepth` could trivially reveal wipe history if it were nil in the normal case and non-nil only after a wipe event. The same forensic-neutrality principle applied to `persistedDepth`, `pinEnabled`, and `coercerBaseDepth` applies here: the field is written from first PIN configuration using a sentinel value (`Int.max` = no active wipe). On disk it is always a non-nil encrypted blob. Without the SE key the value is indistinguishable from any other encrypted `AppLayerConfig` field. With the SE key a forensic examiner can decode it, but that is the same access level required to read all other state — not an incremental exposure.

### W2 — Content deletion leaves WAL timestamp

Hard-deleting contacts and vault entries at wipe time writes deletion records to the SQLite WAL. With `PRAGMA secure_delete = ON`, freed pages are zeroed before release, removing ciphertext residue. The WAL checkpoint following the wipe flushes these to the main file. A forensic examiner inspecting the WAL before checkpoint would see deletion timestamps correlated with the wipe event. This is analogous to the mass `ZMODIFICATIONDATE` update at activation (already accepted in Known Limitations) and has no additional mitigation.

---

## Keychain / AppLayerConfig Forensics

Measures that prevent detection via Keychain metadata or the persisted config row.

| # | Measure | Severity | Status |
|---|---------|----------|--------|
| K1 | `persistedDepth` + `pinEnabled` two-field encoding — gate state opaque | Medium | ✅ |
| K2 | `persistedDepth` always non-nil from first PIN config | Low | ✅ |
| K3 | Blob key HKDF-domain-separated from PIN verifier keys | Medium | ✅ |

### K1 — `persistedDepth` + `pinEnabled` two-field encoding
The lock state is stored as two independent encrypted fields on `AppLayerConfig`:
- `persistedDepth` — AES-GCM encrypted `RoutingDepth` (`.normal` or `.duress`); restored by `Manager.Security.init` via `readRoutingDepth()`.
- `pinEnabled` — AES-GCM encrypted `Bool`; `false` = gate suppressed under coercion while verifiers remain intact; restored via `readPinEnabled()`.

No plaintext boolean flags. A raw `AppLayerConfig` row reveals four opaque `Data` blobs — nothing about current gate state or routing depth without the SE key.

### K2 — `persistedDepth` and `pinEnabled` always non-nil from first PIN write
`configurePIN` calls `writeRoutingDepth(.normal)` and `writePinEnabled(true)` immediately so both fields are non-nil from the moment any PIN is set. Without this, field absence vs. presence would distinguish no-PIN from PIN-only or Secure Mode states without needing any keys. Now both fields are always present and always opaque.

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
| U5 | Screenshot blank on `.inactive` via SwiftUI overlay | Low | ✅ |
| U6 | Share index filtered to depth-1 on lock | Critical | ✅ Bug 6 fixed |

### U1 — PIN toggle always interactive
In `.normal` and `.duress` states (Secure Mode active), disabling the Settings PIN toggle calls `disablePINFromCurrentDepth` — it lowers the gate without removing verifiers. When Secure Mode is not active (`isSecureModeActive == false`), the toggle calls `deactivatePIN`. In all cases the toggle is interactive and the UI is indistinguishable. A coerced user asked to "turn off the PIN" produces the same visual result regardless of which state the app is in.

### U2 — Grace period uniform across all depths
`isWithinGracePeriod` applies at any depth — no `isRestricted` short-circuit. Bug 41 removed the unconditional `!self.isRestricted` guard that forced re-lock on every background transition in duress mode. That guard was itself a tell: a coercer who backgrounds and re-foregrounds the app would notice that no grace window exists in duress mode while one clearly existed at the normal-mode unlock screen. Uniform behaviour removes the asymmetry. The `lastUnlockDate = nil` call in `activateSecureMode` continues to force re-lock immediately after activation; no tell is introduced there.

### U3 — Grace period cleared on activation
`activateSecureMode` sets `lastUnlockDate = nil` before transitioning state. The timestamp from the PIN entry that unlocked the app before setup would otherwise allow a ~5 minute window after activation where background→foreground transitions bypass the PIN prompt entirely.

### U4 — `fullScreenCover` for PIN lock
The PIN gate uses `.fullScreenCover` rather than `.overlay`. SwiftUI overlays are layout primitives — iOS modal presentations (`.sheet`, `.fullScreenCover`) are UIKit-level operations that stack above any overlay unconditionally. A `.sheet` triggered by a notification tap or in-app action while locked was previously visible above the overlay PIN lock.

### U5 — Screenshot blank on `.inactive`
A `Color(.systemBackground)` overlay is shown when `scenePhase == .inactive` and a PIN is configured. This blocks the app-switcher screenshot without a UIKit modal presentation, which would conflict with a concurrently presented `UIActivityViewController`. The blank is cleared immediately on `.active`.

### U6 — Share index filtered to depth-1 on lock
The share extension reads `ShareIndex.sqlite` directly — it has no PIN prompt. When the main app goes `.inactive` with a PIN active, the index is immediately rebuilt with `safeContactIDs(atDepth: 1)` before the app suspends. Sensitive contacts are removed from the index before the extension could query it. When the app returns to the foreground while still locked, the index stays at depth-1 until a successful PIN entry.

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

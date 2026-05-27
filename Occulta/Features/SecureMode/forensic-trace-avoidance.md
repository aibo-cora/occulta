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
| B3 | Ciphertext size bucket-padded to power-of-2 | Medium | ✅ |
| B4 | UUID filename + `.occbak` extension, no header | Medium | ✅ |
| B5 | SE key created at first launch, not at activation | High | ✅ |
| B6 | Random nonce per write | Low | ✅ |
| B7 | `isExcludedFromBackup = true` | Medium | ✅ |

### B1 — No-op blob from first launch
`maintainNoOpBlob()` runs in `OccultaApp.init()` on every install. A `.occbak` file is written before Secure Mode is ever configured. The file's creation timestamp predates activation by however long the app has been installed. A forensic examiner cannot use the blob's existence or creation date to infer that Secure Mode was activated, or when.

### B2 — Last-Modified timestamp normalisation
`rewriteNoOpBlob()` is called on every `ModelContext` save, debounced to 30 s, when Secure Mode is not active. The blob's Last-Modified timestamp tracks normal app activity (contact edits, vault saves) rather than spiking only at meaningful events like activation or PIN entry. Without this, a single modification timestamp would pinpoint exactly when Secure Mode ran.

### B3 — Bucket padding
Before AES-GCM encryption, plaintext is zero-padded to the nearest power-of-2 boundary (256, 512, 1024 … bytes). The ciphertext size on disk reveals only a tier — "between 256 and 512 bytes" — not the exact number of contacts serialised into the blob. Without padding, file size would directly encode the sensitive contact count.

### B4 — UUID filename + `.occbak` extension, no identifying header
Vault backups use the same `.occbak` extension and are indistinguishable at the filesystem level. Vault backups start with a 4-byte "OCBK" magic; blobs do not — the vault restore path rejects blobs via `BackupError.invalidFormat`. No magic bytes, version field, layer count, or anything in the blob that labels it as Secure Mode data.

### B5 — SE key created at first launch
`writeNoOpBlob()` calls `Manager.Key().deriveSecureModeKey()` as a side effect. The Secure Mode SE key is created on first launch, not when Secure Mode is configured. Its Keychain entry's creation timestamp predates activation by the full install lifetime of the app.

### B6 — Random nonce per write
Each `seal()` and `writeNoOpBlob()` generates a fresh 96-bit random nonce. Two consecutive blob files are cryptographically unrelated — diffing them reveals nothing about what changed between writes.

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
| S5 | Sensitive contacts depth-filtered at UI; page slack covered by S1 + S2 | Medium | ✅ Design decision |
| S6 | `visibleThroughDepth` watermark erased on deactivation | Medium | ✅ Bug 12 fixed |

### S1 — DB key rotation on activation (cryptographic erasure)
The local DB key is `ECDH(ourSEKey_localDB, G)` — device-bound and accessible when the device is unlocked. In duress mode the device is unlocked, so the current DB key is derivable. Without rotation, an examiner who extracts the raw SQLite file could use the current DB key to decrypt page-slack still containing deleted sensitive contacts. After rotation, deleted pages are encrypted under the old key, which is deleted after commit — the current DB key decrypts nothing from those pages. This is the core reason the DB key rotates on activation.

### S2 — `PRAGMA secure_delete = ON`
Without this, SQLite leaves old ciphertext in free-list pages when rows are deleted or updated. That residue survives WAL checkpoints and is visible in raw disk images. With `secure_delete = ON`, SQLite zeroes freed pages before releasing them, eliminating ciphertext residue entirely. Set at init via a helper SQLite connection; stored in the database header and persists across all future connections, including SwiftData's own.

### S3 — `.completeFileProtection` on all SQLite files
The main `.sqlite`, `-wal`, and `-shm` files are stamped with `FileProtectionType.complete` at init. Files with this class are encrypted by the OS when the device is locked — inaccessible even to jailbreak-level reads. Without this, extracting the SQLite file while the device is locked is possible on a jailbroken device.

### S4 — File protection re-applied on every save
SwiftData can recreate `-wal` and `-shm` sidecar files after WAL merges, schema migrations, and conflict resolution. Newly created sidecar files receive iOS default protection (`completeUnlessOpen`), not `complete`. `OccultaApp` listens to `NSManagedObjectContext.didSaveObjectIDsNotification` and re-stamps all three files on every save so no sidecar can sit with weaker protection.

### S5 — Sensitive contacts remain in DB; page slack covered by S1 + S2
Sensitive contacts are not hard-deleted from the SQLite store. They remain in the DB encrypted under the canonical key with `visibleThroughDepth` set to a value that hides them at duress depth. The UI enforces this: at depth 0 (normal PIN) they are shown; at depth 1 (duress PIN) they are hidden by the contact list filter.

**Residual forensic gap:** a raw SQLite examination during a duress exposure can find these rows and decrypt them using the canonical key (derivable on an unlocked device). This is an accepted trade-off: hard-deleting them would make them invisible to the real user in normal mode, defeating the core use case. Page-slack protection from *pre-activation* rows is handled by S1 (DB key rotation — old key deleted) and S2 (`PRAGMA secure_delete = ON` — freed pages zeroed). Rows that persist across activation are encrypted under the new canonical key and are not residue in the forensic sense.

### S6 — `visibleThroughDepth` watermark erased on deactivation
Activation Step 5 migrates `nil → encrypt(Int.max)` for all safe contacts. Before Bug 12's fix, deactivation re-encrypted this value rather than clearing it, leaving a permanent non-null field on contacts that existed at activation time. An examiner could identify which contacts predated activation without decrypting anything. Deactivation now sets `visibleThroughDepth = nil` for all contacts and vault entries, restoring the pre-activation default.

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
| U2 | Grace period zero in restricted mode | High | ✅ |
| U3 | `lastUnlockDate = nil` on activation | High | ✅ Bug 5 fixed |
| U4 | `fullScreenCover` for PIN lock — not underlappable by sheets | High | ✅ Bug 1 fixed |
| U5 | Screenshot blank on `.inactive` via SwiftUI overlay | Low | ✅ |
| U6 | Share index filtered to depth-1 on lock | Critical | ✅ Bug 6 fixed |

### U1 — PIN toggle always interactive
In `.normal` and `.duress` states (Secure Mode active), disabling the Settings PIN toggle calls `disablePINFromCurrentDepth` — it lowers the gate without removing verifiers. When Secure Mode is not active (`isSecureModeActive == false`), the toggle calls `deactivatePIN`. In all cases the toggle is interactive and the UI is indistinguishable. A coerced user asked to "turn off the PIN" produces the same visual result regardless of which state the app is in.

### U2 — Grace period always zero in restricted mode
`isWithinGracePeriod` returns `false` when `isRestricted`. In duress mode, every return from background requires PIN re-entry. An attacker cannot use a brief background-foreground cycle to skip the PIN prompt after the device has been handed over unlocked.

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
| C2 | Inbound message suppressed at duress-unlock if sender not safe | High | ✅ Bug 1 fixed |

### C1 — Content gate at set-time
When the app is already unlocked in restricted mode (duress depth) and `buildOwnedBasket` runs inside `onOpenURL`, if the sender is not a safe contact the basket is suppressed and the standard "not addressed to you" error is surfaced. Without this, a notification tap while in duress mode could surface a message from a sensitive contact before the depth gate could prevent it.

### C2 — Content gate at duress-unlock
A message may arrive and queue into `openedFileContents` while the app is locked, before any PIN determines the security depth. If the duress PIN is then entered, the `onDuress` callback checks `isSafeContact` against the pending basket owner before clearing `isLocked`. If the sender is not visible at duress depth, the basket is cleared and the error shown. Sensitive contacts are absent from the DB in Secure Mode, so `isSafeContact` returns `false` for them naturally.

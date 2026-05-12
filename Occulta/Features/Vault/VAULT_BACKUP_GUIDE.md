# Vault Backup Guide

Occulta Vault — export/import and full device-loss recovery reference.
Commit this file alongside any PR that touches vault backup, export, or import.

---

## Design intent

Vault backup solves a problem that SSS alone cannot: **full content recovery after
device loss**.

SSS recovers per-entry encryption keys (PEKs). It does not recover the encrypted
content — `encryptedLabel` and `encryptedContent` live in SwiftData on the device.
If the device is lost, the ciphertext is gone and PEK reconstruction is useless
without it. A backup file provides the missing ciphertext half.

These two mechanisms are complementary, not alternatives:

| Mechanism | Recovers | Requires |
|-----------|----------|----------|
| SSS (per-entry) | One entry's PEK | k trustees + ciphertext on device |
| Vault backup | All entry content | Backup file + k BEK shards from trustees |

---

## Why not a passphrase

Passphrase-based backup was considered and rejected. A passphrase is only as
strong as the user's memory and discipline. Forgetting the passphrase makes the
backup permanently unrecoverable. It also introduces a memorised secret as the
weakest link in the vault's security model, which conflicts with the design goal
of hardware-bound key material.

---

## Backup encryption key (BEK)

The BEK is a **random 32-byte key generated once** and stored as an AES-GCM
sealed blob, using the vault master key — the same wrapping model as per-entry
PEKs, but at vault scope:

```
BEK            = SecRandomCopyBytes(32)
encryptedBEK   = AES-GCM(BEK, using: vaultKey, nonce: random, authenticating: bekAAD)
```

`encryptedBEK` is persisted in a dedicated SwiftData model (`BackupEncryptionKey`) following
the same `id: UUID` + `encryptedPayload: Data` pattern used throughout the vault.
At most one row exists; reads fetch the first row, writes delete-and-replace (same
convention as `GlobalShardConfig`). The raw BEK bytes are available in memory when
the vault is unlocked (vaultKey unwraps them), and nowhere else.

The backup file is AES-256-GCM sealed under the BEK:

```
backup file = AES-GCM(
    plaintext:      JSON(VaultBackup),
    using:          BEK,
    nonce:          random 12 bytes,
    authenticating: backupFileAAD
)
```

`backupFileAAD` covers a fixed domain string + backup format version, preventing
a backup file from being decrypted with a BEK from a different context.

### Why not HKDF-derive BEK from the vault key

The vault key is `ECDH(ourSEKey, P-256 generator G)` — deterministic and
device-specific. Deriving `BEK = HKDF(vaultKey)` would mean a different device
produces a different BEK, making every backup file permanently unrecoverable after
device loss. This defeats the purpose of backup. BEK must be a stored value, not
a derived one.

### Why not store BEK in the Secure Enclave

SE-resident keys cannot have their raw bytes extracted — that is the SE's core
security guarantee. Shamir's Secret Sharing requires operating on the raw key
bytes. BEK must be accessible in memory (under vault unlock) to be split into
shards. The vaultKey wrapping provides hardware-bound protection at rest; biometric
authentication gates access.

### Why not store BEK in the Keychain

Keychain is a valid storage location for a sealed blob, but it breaks the
consistency of the vault's storage model — all other encrypted vault state lives
in SwiftData. Keychain items also behave differently under backup and restore
scenarios, which matters for the device-migration path. A `BackupKey` SwiftData
model keeps all vault state in one container and follows the established pattern.

---

## BEK trustee distribution

The BEK is Shamir-split and distributed to trustees via the same `OccultaBundle`
shard pipeline used for per-entry PEK shards. From the trustee's perspective, a
BEK shard is an ordinary `CustodyShard` row — no marking distinguishes it from a
per-entry shard.

The BEK trustee picker is pre-populated from the user's Global Trustees with a
GLOBAL badge on each pre-populated entry. The user can add or remove trustees
before confirming distribution.

```
shards = ShamirSecretSharing.split(secret: BEK, threshold: k, shares: n)
```

Each shard is wrapped as a `SignedAttribute(.shard)` — signed with the owner's
SE identity key — and delivered via `distributeShards`. The `entryID` field in
the signed attribute carries the BEK's stable distribution UUID (stored inside
`encryptedBEK` payload) rather than a VaultEntry UUID.

---

## Core security invariant

> **Trustees hold BEK shards. Trustees do not hold the backup file.**

| Assets held | What an attacker gets |
|---|---|
| Backup file only | Encrypted blob, unreadable |
| k BEK shards only | A key with no ciphertext to decrypt |
| Backup file + k BEK shards | Full vault access |

The attack that cannot be prevented cryptographically: a trustee obtains the
backup file through a side channel (shared cloud folder, same messaging app,
physical access to the owner's storage). If k trustees acquire the backup file,
the vault is fully exposed. The UI must make this concrete at every export touch
point.

---

## Practical trustee-set equivalence

In practice, users maintain one trustee set and use the same trustees for every
vault entry. Given this, per-entry SSS and BEK SSS have identical colluding-trustee
security properties: if k trustees collude and hold the backup file, they can
recover the entire vault regardless of which scheme is used.

The per-entry SSS model's theoretical advantage — trustee isolation per entry — is
a UX fiction. A single BEK with one SSS distribution is therefore the correct
architecture: simpler, with no practical security regression.

---

## VaultBackup structure

```
VaultBackup: Codable {
    version:   Int                  // bump on breaking format changes
    createdAt: Date
    entries:   [VaultBackupEntry]
}

VaultBackupEntry: Codable {
    id:        UUID                 // original VaultEntry.id
    entryType: Int                  // VaultEntryType raw value
    createdAt: Date
    label:     Data                 // plaintext UTF-8 bytes
    content:   Data                 // plaintext bytes
}
```

`VaultBackupEntry` is a transient in-memory type — it is never stored in SwiftData.
Plaintext fields are safe here for the same reason `SealedPayload` carries a
plaintext `message`: the struct is serialised and immediately sealed under the BEK
before any I/O. The BEK's AES-GCM seal is the only encryption layer needed.

On import, fresh PEKs are generated for every entry under the new device's vault
master key, exactly as if the entries were created new.

---

## Export flow

1. Vault must be unlocked (biometric authentication).
2. Unwrap `encryptedBEK` under `vaultKey` → raw BEK bytes in memory.
3. Decrypt every `VaultEntry` to plaintext using the existing PEK path.
4. Serialise all entries as `VaultBackup` JSON.
5. `AES.GCM.seal(json, using: BEK)` → backup file bytes. Zero BEK from memory.
6. Write to a `.occbak` file via `UIDocumentPickerViewController` (user chooses
   destination). App does not choose on behalf of the user.

Export is blocked unless **k or more BEK shards are in `.confirmed` status**
(trustee's app has acknowledged receipt). `.pending` shards do not count toward
the threshold — a trustee who hasn't confirmed cannot return their shard during
recovery, making the backup unrecoverable. Export is also blocked if
`encryptedBEK` does not exist (BEK not yet set up).

The export button has two distinct disabled states:
- **Not set up**: `shardMetadata == nil` → *"Set up backup recovery first"*
  with a CTA to the BEK trustee picker.
- **Coverage insufficient**: fewer than `k` shards are `.confirmed` → *"Waiting
  for trustees to confirm — N of K confirmed"* with a CTA to the trustee picker.

---

## Import flow

Import is not a blocking first step. On a new device the user provides the
`.occbak` file. The app stores it as a **pending restore** and shows a
"waiting for trustees" state. Vault content is not accessible until k BEK shards
have been collected and BEK reconstructed.

### BEK shard collection via auto-handback

BEK shards are collected automatically as the owner re-establishes contact with
trustees via proximity exchange (same UWB ≤ 0.25 m + Diceware word confirmation
used for initial key exchange).

When a trustee's app processes a proximity exchange and detects that the incoming
public key differs from the stored key for that contact (key update), it
automatically queues a `.handback` operation containing the stored BEK shard. The
shard is delivered in the next `.occ` bundle to the owner's new device.

Once k BEK shards have been received the app reconstructs and decrypts
automatically:

```
BEK = Shamir.combine(k BEK shards)
AES.GCM.open(backupFile, using: BEK) → VaultBackup JSON
```

For each `VaultBackupEntry`:
1. Generate a fresh PEK (`SecRandomCopyBytes`, 32 bytes).
2. Seal label and content under PEK.
3. Seal PEK under the new device's vault master key → `encryptedEntryKey`.
4. Insert new `VaultEntry` into SwiftData.

Then re-wrap and persist BEK on the new device:

```
encryptedBEK = AES-GCM(BEK, using: newDeviceVaultKey)
```

Zero BEK from memory.

---

## SSS redistribution and contact re-establishment after import

Three things become stale on device migration and require post-import action:

**1. Re-establish contacts**
> "Your contacts have been restored, but encrypted messaging requires re-exchanging
> keys via proximity. Meet each contact to restore secure communication."

All ECDH sessions are stale (new identity key). Re-exchange via proximity restores
them and simultaneously triggers BEK shard auto-handback for trustees.

**2. Redistribute BEK shards**
After auto-handback, trustees no longer hold BEK shards (their `CustodyShard`
rows are deleted once the owner sends `.returnAcknowledged`). New shards must be
distributed for future recovery coverage.

> "Your backup recovery shards have been used. Redistribute to your trustees to
> restore backup recovery coverage."

**3. Redistribute per-entry shards**
Import generates new PEKs for every entry. All existing per-entry SSS shards are
now stale — they reference PEKs that no longer exist on this device.

> "Your vault was restored. Trustees holding per-entry recovery shards need to
> receive new shards — the previous ones are no longer valid."

All three prompts are surfaced in `VaultPostRestoreSheet`, shown automatically on
the first vault unlock after a successful restore. The sheet persists across app
restarts (backed by a `UserDefaults` flag) until the user taps **Done**. Tapping
"Set up backup recovery" from the sheet dismisses it and pushes
`VaultShardSetup(mode: .backup)` directly onto the vault `NavigationStack`.

---

## BEK lifecycle

| Event | Action |
|---|---|
| First BEK setup | Generate BEK, seal as `encryptedBEK`, SSS-split, distribute shards to trustees |
| Vault backup exported | No BEK rotation required |
| Trustee added or removed | Revoke old BEK shards; re-split same BEK with new set; redistribute. Consider rotating BEK (generate fresh) if former trustees should lose access |
| Vault imported on new device | Re-wrap BEK under new device vaultKey; redistribute BEK shards (old ones consumed by auto-handback) |
| BEK shards fall below threshold | UI warning: export blocked, redistribution required |

### BEK rotation on trustee change

Revoking old BEK shards prevents former trustees from participating in future
reconstructions. However, if a former trustee retained their shard (e.g. revoke
not yet delivered) and later obtains the backup file, they contribute to a quorum.
For high-security trustee changes, generate a fresh BEK, re-encrypt a new backup,
and redistribute. The UI warns:

> "Changing your trustees requires a new backup export. Your previous backup can
> still be recovered using shards held by your previous trustees."

---

## Backup staleness

After every successful export, a `BackupExportMetadata` snapshot is sealed under
the vault key (`AES-GCM`, AAD: `"occulta.backup-export-meta-v1"`) and written to
`Application Support/backup-export-meta.dat` with `.completeFileProtection`.
No plaintext leaves the app at any point.

On each vault unlock, `refreshBackupStaleness()` decrypts the snapshot and compares
it against current state, producing a `BackupStalenessReport` with three independent
signals:

| Signal | Trigger | Severity |
|---|---|---|
| `bekRotated` | Current `distributionID ≠ snapshot distributionID` | Critical (red) — existing file unrestorable |
| `newEntryCount` | Current entry count > snapshot entry count | Warning (amber) — entries missing from backup |
| `trusteeSetChanged` | Current shard count ≠ snapshot shard count | Warning (amber) — coverage may have shifted |

Each active signal renders as a separate row in the **Needs Attention** section of
the vault list. Tapping any row opens the export educational sheet. All three
warnings clear automatically after the next successful export.

`backupStaleness` is `nil` when the vault is locked, no export has been done on
this device, or all three signals are false. After a restore, the flag starts `nil`
until the user performs a fresh export on the new device.

---

## Threat model

| Threat | Defence |
|---|---|
| Backup file intercepted | AES-GCM under BEK; unreadable without k trustee shards |
| k trustees collude (no backup file) | A key with no ciphertext to decrypt |
| k trustees collude + have backup file | Full vault access — separation is the only defence |
| Trustee device compromised | < k shards; BEK not reconstructable |
| Backup file corrupted | GCM authentication tag rejects tampered bytes |
| BEK shards below threshold | Export blocked; redistribution required |
| encryptedBEK lost with device | BEK reconstructed from trustee shards on new device |
| Former trustee retains shard after revoke-not-delivered | Rotate BEK on high-stakes trustee changes; UI warns |

---

## Backup row in vault list

The BEK setup and backup status surface as a **persistent row at the bottom of
the vault entry list**, separated from normal entries by a small spacing gap.
It is not a vault entry — it carries no PEK, no label, no content. It is a
first-class UI fixture that graduates through four states:

| State | Appearance | Tap action |
|---|---|---|
| Not set up | Low opacity, subtitle: *"Set up backup recovery"* | Opens BEK shard setup sheet |
| Waiting for trustees | Amber, subtitle: *"Waiting for trustees — N of K confirmed"* | Opens trustee status sheet |
| Ready (k confirmed, not yet exported) | Normal opacity, badge or subtle indicator | Opens export flow (future) |
| Exported at least once | Normal, subtitle: last export date | Opens export flow (future) |

The row is **always visible** while the vault is unlocked — it does not disappear
after setup. This keeps backup as a first-class vault feature rather than a
buried settings item, and ensures users can always see their current backup
health at a glance.

### Visual design

- Same row height as a vault entry row.
- Icon: distinct from entry icons (e.g. a shield or archive glyph).
- Lowered opacity (`0.45`) in the *Not set up* state to signal inactivity.
- Amber tint on icon and subtitle text in the *Waiting* state (mirrors the
  existing Attention section colour language).
- A small top spacing (`24 pt`) separates it from the last real entry.
- No swipe actions.

### BEK shard setup view

Opened by tapping the row in the *Not set up* or *Waiting* states.
Pushed as a **navigation destination** inside the vault `NavigationStack` —
consistent with how per-entry shard setup is presented, and avoids sheet
presentation complexity. Back button dismisses.

Reuses the existing per-entry shard setup view components:

- **Trustee picker** — same contact list with Global Trustee filter and GLOBAL
  badge. Pre-populated from Global Trustees.
- **Threshold stepper** — identical to per-entry setup.
- **Per-trustee delivery status** — same confirmed / pending indicators.

Differences from the per-entry sheet:
- Header copy explains this is for the **backup file**, not a specific entry.
- An inline banner (amber) explains that export is locked until k trustees
  confirm: *"You'll be able to export your backup once N trustees confirm
  receipt of their recovery piece."*
- No entry name or entry icon — the sheet title is *"Backup Recovery"*.

The export action is **not present** in this sheet at this stage.

---

## Export UI requirements

Export is a Settings action, not a feature flag. It requires:

1. **BEK distribution check**: export is disabled if BEK shards have not been
   distributed or fall below threshold. Reason shown inline.

2. **Mandatory educational sheet** (shown every time, no persistent dismiss):
   - What the backup file contains: all vault entries, encrypted
   - What it does NOT contain: the decryption key (held by trustees as shards)
   - Explicit warning: backup file + k trustee shards = full vault access
   - Storage guidance: "Store this file somewhere your trustees cannot access"
   - "I understand" CTA — no checkbox, must be read

3. **Destination picker**: `UIDocumentPickerViewController`. App does not choose
   the destination on behalf of the user.

4. **No sharing sheet to contacts**: the export action must not offer AirDrop,
   Messages, or any channel that could route the file to a trustee.

---

## Recovery dashboard

The recovery dashboard is the persistent section shown in the vault list from
the moment a `.occbak` file is stored until reconstruction completes. Because
shard collection requires physical proximity exchanges that may span multiple
days, the section survives app restarts and updates in real time as shards arrive.

### What the app knows during restore

Before BEK reconstruction succeeds, the threshold, total trustee count, and
trustee identities are all unknown. The manifest that would carry this information
— `ShardDistributionMetadata` inside the `BackupEncryptionKey` row — existed only
on the old device. Embedding it in the `.occbak` file would require either cleartext
(ruled out) or sealing it under a key the new device doesn't have yet (circular).

The GCM oracle (`AES.GCM.open` authentication) is the only signal available:
reconstruction is attempted after every shard arrival; success means done.

**Available during restore:**

| Data point | Available |
|---|---|
| Number of shards received so far | ✅ |
| Whether reconstruction has succeeded | ✅ |
| Threshold (k) | ✗ |
| Total trustees (n) | ✗ |
| Which trustee sent a given shard | ✗ |
| How many more shards are needed | ✗ |

### Requirements

- **Persistent**: shown as a section in the vault list (not in place of it — the
  vault is usable immediately for new entries). Survives app restarts.
- **Count only**: display the raw received count. Do not imply a known total or
  threshold — neither is available. "N recovery pieces collected" is the correct
  and complete representation.
- **Plain language only**: no crypto terminology. Call shards "recovery pieces".
  Do not name the cryptographic mechanism.
- **Auto-advance**: reconstruction is attempted automatically after every shard
  arrival and on every unlock. No manual tap required — the section disappears
  when reconstruction succeeds.

### What it must not do

- Show a progress bar, dots, or fraction (e.g. "2 of 3") — the denominator is
  unknown and displaying one would be fabricated.
- Use the words "shard", "BEK", "Shamir", "threshold", or "encryption key".
- Require any action between shard collection and vault reconstruction — the
  transition must be fully automatic once enough pieces are in.

### Implementation status

Implemented as the "Recovery in Progress" section in `Vault+Tab.swift`. Spinner
header, received-count subtitle, footer guidance. Section disappears when
`pendingRestoreActive` transitions to `false` after successful `attemptBEKRestore`.

---

## Future: macOS companion app sync

A macOS companion app was considered as an alternative backup transport. Rather
than a manual `.occbak` file export, the Mac would act as a trusted sync target:
the vault would replicate to the Mac automatically over the local network or iCloud,
with the Mac holding an encrypted copy that could be used for recovery.

In this model the Mac can also act as an additional BEK shard holder — effectively
a "trusted device" shard using the same SSS scheme as human trustees. This gives
the macOS sync path without weakening the cryptographic model.

This is a future addition and explicitly out of scope for v1. The `.occbak` file
model is the v1 implementation. The macOS sync path should be designed to coexist
with, not replace, the trustee-SSS model — both provide independent recovery routes.

---

## File format

Extension: `.occbak`
UTI: `com.github.aibo-cora.occulta.backup`

Wire format:
```
magic (4 bytes: "OCBK") ∥ nonce (12 bytes) ∥ ciphertext ∥ GCM tag (16 bytes)
```

The plaintext is `JSONEncoder().encode(VaultBackup)`.

The four-byte magic prefix `4F 43 42 4B` ("OCBK") allows fast format detection
without attempting decryption.

---

## Implementation status

| Component | Status |
|---|---|
| BEK generation + vaultKey wrapping → `encryptedBEK` SwiftData singleton | ✅ |
| BEK SSS split + shard delivery (reuse existing pipeline) | ✅ |
| Backup row in vault list (graduated appearance, 3 states) | ✅ |
| BEK shard setup view (`VaultShardSetup(mode: .backup)`) | ✅ |
| BEK shard collection via auto-handback on contact key re-exchange | ✅ |
| Pending restore: `pending-restore.occbak` + shard file + vault-list progress section | ✅ |
| BEK reconstruction (Shamir.combine + GCM oracle) + re-wrap under new device vaultKey | ✅ |
| `VaultBackup` / `VaultBackupEntry` Codable models | ✅ |
| Export: unwrap encryptedBEK + decrypt all entries + AES-GCM seal | ✅ |
| Export: `UIDocumentPickerViewController` via `BackupPickerPresenter` + `.occbak` UTI | ✅ |
| Export: section-footer trigger below Backup Recovery row | ✅ |
| Export educational sheet (mandatory, no persistent dismiss) | ✅ |
| Export disabled until k BEK shards are `.confirmed` | ✅ |
| Import: AES-GCM open + fresh PEK regeneration + SwiftData insert | ✅ |
| BEK erosion warning in Attention section (`VaultBEKAttentionRow`) | ✅ |
| Post-restore prompts (`VaultPostRestoreSheet`): contacts + BEK redistribution + entry shards | ✅ |
| Stale-backup tracking: 3 signals, sealed metadata, rows in Attention section | ✅ |
| BEK rotation (`rotateBEK()`) | ✅ |
| Recovery dashboard (count-based; per-trustee status infeasible — see Recovery dashboard section) | ✅ |
| Future: macOS companion app sync | 🔲 |

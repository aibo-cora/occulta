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
| Vault backup | All entry content | Backup file + KEY_A + k KEY_B shards |

---

## Why not a passphrase

Passphrase-based backup was considered and rejected. A passphrase is only as
strong as the user's memory and discipline. Forgetting the passphrase makes the
backup permanently unrecoverable. It also introduces a memorised secret as the
weakest link in the vault's security model, which conflicts with the design goal
of hardware-bound key material.

---

## Backup encryption key (BEK)

The BEK is **derived**, not generated or stored:

```
BEK = HKDF-SHA256(
    inputKeyMaterial: vaultKey,
    salt:             nil,
    info:             "vault-backup-encryption-key"
)
```

The BEK is re-derived on demand whenever the vault is unlocked. No SE slot is
consumed, no persistent storage required. If the vault key changes, the BEK
changes with it.

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

---

## Two-key model

The BEK is never distributed directly. Instead, two derived keys gate access:

```
KEY_A  = random 32 bytes           (owner's companion shard file)
KEY_B  = BEK XOR KEY_A             (Shamir-split to trustees)
```

**KEY_A** lives only in the owner's hands, exported as a companion `.occshard`
file at backup setup time. The owner stores this separately from the backup file.

**KEY_B** is Shamir-split into n shards and distributed to trustees via the
existing shard delivery pipeline. Trustees receive a KEY_B shard — they cannot
distinguish it from a per-entry PEK shard. No special marking.

Recovery requires both halves:

```
BEK = KEY_A XOR KEY_B
```

Neither the owner (KEY_A only) nor k trustees (KEY_B only) can reconstruct BEK
alone. Both are required.

### Core security invariant

| Assets held | What an attacker gets |
|---|---|
| Backup file only | Encrypted blob, unreadable |
| KEY_A only | Half a key, nothing to decrypt |
| k KEY_B shards only | Half a key, nothing to decrypt |
| KEY_A + k KEY_B shards (no backup file) | BEK, but no ciphertext |
| Backup file + KEY_A (no shards) | BEK half, unreadable |
| Backup file + k KEY_B shards (no KEY_A) | BEK half, unreadable |
| Backup file + KEY_A + k KEY_B shards | Full vault access |

The attack that cannot be prevented cryptographically: the owner stores KEY_A
and the backup file in the same location, and k trustees collude. The UI must
make this concrete at every export touch point (see Export UI requirements).

---

## Practical trustee-set equivalence

In practice, users maintain one trustee set and use the same trustees for every
vault entry. Given this, per-entry SSS and BEK SSS have identical colluding-trustee
security properties: if k trustees collude and hold the backup file and KEY_A,
they can recover the entire vault regardless of which scheme is used.

The per-entry SSS model's theoretical advantage — trustee isolation per entry — is
a UX fiction. A single BEK with one SSS distribution is therefore the correct
architecture: simpler, with no practical security regression.

---

## BEK trustee distribution

The BEK trustee picker is pre-populated from the user's Global Trustees — the same
contacts used for per-entry SSS — with a GLOBAL badge on each pre-populated entry.
The user can add or remove trustees before confirming distribution.

KEY_B shards are delivered via the same `OccultaBundle` shard pipeline. From the
trustee's perspective, a KEY_B shard is an ordinary `CustodyShard` row — no
marking distinguishes it from a per-entry PEK shard.

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

Entries are serialised in plaintext inside the backup structure. The BEK's
AES-GCM seal is the only encryption layer. There is no PEK layer in the backup —
PEKs are internal implementation details that do not survive device migration.

On import, fresh PEKs are generated for every entry under the new device's vault
master key, exactly as if the entries were created new.

---

## Export flow

1. Vault must be unlocked (biometric authentication).
2. App derives BEK from vault key via HKDF.
3. App decrypts every `VaultEntry` to plaintext using the existing PEK path.
4. Serialise all entries as `VaultBackup` JSON.
5. `AES.GCM.seal(json, using: BEK)` → backup file bytes.
6. Write to a `.occbak` file via `UIDocumentPickerViewController` (user chooses
   destination). App does not choose on behalf of the user.

The BEK must already be distributed to trustees (KEY_B shards delivered) before
export is permitted. If no BEK distribution exists or shards fall below threshold,
the export action is blocked with an explanation.

KEY_A companion file is generated once at BEK setup time and is not re-exported
with each backup — the same KEY_A file covers all backups until trustees change.

---

## Import flow

Import is not a blocking first step. On a new device the user provides the
`.occbak` file and the KEY_A companion file. The app stores these as a **pending
restore** and shows a "waiting for trustees" state. Vault content is not accessible
until k KEY_B shards have been received.

### KEY_B shard collection via auto-handback

KEY_B shards are collected automatically as the owner re-establishes contact with
trustees via proximity exchange (same UWB ≤ 0.25 m + Diceware word confirmation
used for initial key exchange).

When a trustee's app processes a proximity exchange and detects that the incoming
public key differs from the stored key for that contact (i.e. a key update), it
automatically queues a handback operation containing the stored KEY_B shard. The
shard is delivered in the next `.occ` bundle to the owner's new device.

Once k KEY_B shards have been received the app reconstructs automatically:

```
KEY_B = Shamir.combine(k KEY_B shards)
BEK   = KEY_A XOR KEY_B
```

Then proceeds to decrypt:

```
AES.GCM.open(backupFile, using: BEK) → VaultBackup JSON
```

For each `VaultBackupEntry`:
1. Generate a fresh PEK (`SecRandomCopyBytes`, 32 bytes).
2. Seal label and content under PEK.
3. Seal PEK under the new device's vault master key → `encryptedEntryKey`.
4. Insert new `VaultEntry` into SwiftData.

**Dependency:** the exchange flow must support "update existing contact's key" as
a first-class outcome (not just "create new contact"). Without this, the trustee's
app cannot associate the incoming exchange with an existing `CustodyShard` row and
auto-handback will not fire.

---

## SSS redistribution and contact re-establishment after import

Import generates new PEKs for every entry. All existing per-entry SSS shards held
by trustees are now stale — they reference PEKs that no longer correspond to any
entry. The trustees still hold valid KEY_B shards (the BEK does not change on
import as long as the vault key is preserved via HKDF).

Two post-import prompts are shown on first vault unlock after import:

**1. Re-establish contacts**
> "Your contacts have been restored, but encrypted messaging requires re-exchanging
> keys via proximity. Meet each contact to restore secure communication."

All ECDH sessions are stale on a new device (new identity key). Re-exchange via
proximity restores them and, for trustees, also triggers KEY_B auto-handback.

**2. Redistribute per-entry shards**
> "Your vault was restored. Trustees holding per-entry recovery shards need to
> receive new shards — the previous ones are no longer valid."

Navigates to per-entry shard distribution setup for any entry that previously had
SSS configured.

---

## BEK lifecycle

| Event | Action |
|---|---|
| BEK setup | Generate KEY_A, derive KEY_B = BEK XOR KEY_A, split KEY_B via SSS, distribute to trustees; export KEY_A as companion file |
| Vault backup exported | No BEK rotation required |
| Trustee set changes | Revoke old KEY_B shards, generate new KEY_A, redistribute KEY_B; existing backups require old KEY_A + old trustee shards to recover |
| Vault imported on new device | BEK unchanged (HKDF output stable while vault key stable); per-entry PEKs regenerated |
| KEY_B shards fall below threshold | UI warning: export blocked, redistribution required |

BEK rotation (on trustee set change) generates a new KEY_A and a new KEY_B split.
Existing backup files sealed under the old BEK are still recoverable as long as
the old KEY_A companion file and k old KEY_B shards are available. The UI must
warn:

> "Changing your trustees rotates the backup key. Any existing backup files can
> only be decrypted with your old KEY_A file and shards held by your previous
> trustees. Export a new backup after updating your trustees."

---

## Threat model

| Threat | Defence |
|---|---|
| Backup file intercepted | AES-GCM under BEK; unreadable without KEY_A + k KEY_B shards |
| KEY_A file intercepted (no shards, no backup) | Half a key; useless alone |
| k trustees collude (no backup file, no KEY_A) | BEK half; nothing to decrypt |
| k trustees collude + KEY_A (no backup file) | Full BEK; still no ciphertext |
| Backup file + KEY_A obtained (no shards) | BEK half; still unreadable |
| Backup file + KEY_A + k trustee shards | Full vault access — separation is the only defence |
| Trustee device compromised | < k shards; KEY_B not reconstructable |
| Backup file corrupted | GCM authentication tag rejects tampered bytes |
| KEY_B shards below threshold | Export blocked; redistribution required |
| User stores KEY_A alongside backup file | Reduces to: backup file + k shards → full access |

---

## Export UI requirements

Export is a Settings action, not a feature flag. It requires:

1. **BEK distribution check**: export is disabled if KEY_B shards have not been
   distributed or fall below threshold. Reason shown inline.

2. **Mandatory educational sheet** (shown every time, no persistent dismiss):
   - What the backup file contains: all vault entries, encrypted
   - What it does NOT contain: the decryption key (split between KEY_A and trustees)
   - Explicit warning: KEY_A + backup file + k trustee shards = full vault access
   - Storage guidance: "Store the backup file somewhere separate from your KEY_A
     file, and somewhere your trustees cannot access"
   - "I understand" CTA — no checkbox, must be read

3. **Destination picker**: `UIDocumentPickerViewController`. App does not choose
   the destination on behalf of the user.

4. **No sharing sheet to contacts**: the export action must not offer AirDrop,
   Messages, or any channel that could route the file to a trustee.

---

## Future: macOS companion app sync

A macOS companion app was considered as an alternative backup transport. Rather
than a manual `.occbak` file export, the Mac would act as a trusted sync target:
the vault would replicate to the Mac automatically over the local network or iCloud,
with the Mac holding an encrypted copy that could be used for recovery.

This approach eliminates the manual file management burden and removes the risk of
the user misplacing the KEY_A companion file or the backup file. The Mac itself
(or a specific Secure Enclave / Keychain item on it) would serve as the KEY_A
equivalent.

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
| BEK derivation (HKDF from vault key — no storage) | 🔲 |
| KEY_A generation + companion `.occshard` file export | 🔲 |
| KEY_B = BEK XOR KEY_A + SSS split + shard delivery (reuse existing pipeline) | 🔲 |
| BEK trustee picker (pre-populated from Global Trustees, GLOBAL badge) | 🔲 |
| KEY_B shard collection via auto-handback on contact key re-exchange | 🔲 |
| Contact key-update exchange outcome (prerequisite for auto-handback) | 🔲 |
| Pending restore state (store .occbak + KEY_A, waiting-for-trustees UI) | 🔲 |
| BEK reconstruction (XOR KEY_A ⊕ KEY_B) | 🔲 |
| `VaultBackup` / `VaultBackupEntry` Codable models | 🔲 |
| Export: derive BEK + decrypt all entries + AES-GCM seal | 🔲 |
| Export: document picker + `.occbak` UTI registration | 🔲 |
| Import: AES-GCM open + PEK regeneration + SwiftData insert | 🔲 |
| Post-import contact re-establishment prompt | 🔲 |
| Post-import SSS redistribution prompt | 🔲 |
| BEK rotation on trustee change + stale-backup warning | 🔲 |
| Export educational sheet (mandatory, no persistent dismiss) | 🔲 |
| Export disabled when KEY_B below threshold | 🔲 |
| KEY_B erosion warning (mirrors per-entry erosion banner) | 🔲 |
| Future: macOS companion app sync | 🔲 |

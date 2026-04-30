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
| Vault backup | All entry content | Backup file + BEK shards (or passphrase — rejected, see below) |

---

## Why not a passphrase

Passphrase-based backup was considered and rejected. A passphrase is only as
strong as the user's memory and discipline. Forgetting the passphrase makes the
backup permanently unrecoverable. It also introduces a memorised secret as the
weakest link in the vault's security model, which conflicts with the design goal
of hardware-bound key material.

---

## Backup encryption key (BEK)

A random 32-byte backup encryption key (BEK) is generated once per vault. The
BEK is split using Shamir's Secret Sharing (same GF(2⁸) implementation as
per-entry SSS) and distributed to the user's trustees via the existing shard
delivery pipeline.

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

Recovery: collect ≥ k BEK shards from trustees → reconstruct BEK →
`AES.GCM.open(backupFile, using: BEK)` → `VaultBackup` plaintext.

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

## The core security invariant

The vault's security against a colluding trustee set rests on one guarantee:

> **Trustees hold BEK shards. Trustees do not hold the backup file.**

With that separation intact:

| Asset held | What an attacker gets |
|---|---|
| BEK shards only | A key with nothing to decrypt |
| Backup file only | An encrypted blob, unreadable |
| Both | Full vault access |

This is the same principle as per-entry SSS: trustees are key custodians, not
data custodians. The backup file is the ciphertext half. Trustees are the key half.
They must never be in the same hands.

---

## Practical trustee-set equivalence

In practice, users maintain one trustee set and use the same trustees for every
vault entry. Given this, per-entry SSS and BEK SSS have identical colluding-trustee
security properties: if k trustees collude and hold the backup file, they can
recover the entire vault regardless of which scheme is used.

The per-entry SSS model's theoretical advantage — trustee isolation per entry — is
a UX fiction. Option B (single BEK, one SSS distribution) is therefore the correct
architecture: simpler, with no practical security regression.

---

## Export flow

1. Vault must be unlocked (biometric authentication).
2. App decrypts every `VaultEntry` to plaintext using the existing PEK path.
3. Serialise all entries as `VaultBackup` JSON.
4. `AES.GCM.seal(json, using: BEK)` → backup file bytes.
5. Write to a `.occbak` file via `UIDocumentPickerViewController` (user chooses
   destination).

The BEK must already be distributed to trustees before export is permitted. If
no BEK distribution exists, the export action is blocked with an explanation.

---

## Import flow

1. User selects a `.occbak` file.
2. App retrieves BEK shards from trustees via the standard shard collection flow
   (same `.handback` / `ReconstructShard` pipeline), or uses an already-reconstructed
   BEK if one is buffered from a prior collection.
3. `AES.GCM.open(backupFile, using: BEK)` → `VaultBackup` JSON.
4. For each `VaultBackupEntry`:
   a. Generate a fresh PEK (`SecRandomCopyBytes`, 32 bytes).
   b. Seal label and content under PEK.
   c. Seal PEK under the new device's vault master key → `encryptedEntryKey`.
   d. Insert new `VaultEntry` into SwiftData.
5. Post-import: per-entry SSS distributions are invalidated (new PEKs). Surface
   a prompt to redistribute for any entry that previously had SSS configured.

---

## SSS redistribution after import

Import generates new PEKs for every entry. All existing per-entry SSS shards held
by trustees are now stale — they reference PEKs that no longer correspond to any
entry. The trustees still hold valid BEK shards (the BEK does not change on import).

Post-import prompt (shown once, on first vault unlock after import):

> "Your vault was restored. Trustees holding per-entry recovery shards need to
> receive new shards — the previous ones are no longer valid."

The prompt navigates to the shard distribution setup for affected entries.

---

## BEK lifecycle

| Event | Action |
|---|---|
| First vault setup | Generate BEK, prompt user to distribute BEK shards to trustees |
| Trustee set changes | Revoke old BEK shards, generate new BEK, redistribute |
| Vault backup exported | No BEK rotation required |
| Vault imported on new device | BEK unchanged; per-entry PEKs regenerated |
| BEK shard falls below threshold | UI warning: redistribute before export is possible |

BEK rotation (on trustee set change) requires re-distributing shards but does not
invalidate existing backup files sealed under the old BEK — those files become
unrecoverable if the old BEK shards are gone. The UI must warn:

> "Changing your trustees rotates the backup key. Any existing backup files can
> only be decrypted with shards held by your previous trustees. Export a new backup
> after updating your trustees."

---

## Threat model

| Threat | Defence |
|---|---|
| Backup file intercepted (no shards) | AES-GCM under BEK; unreadable without shards |
| k trustees collude (no backup file) | No ciphertext to decrypt |
| k trustees collude + have backup file | Full vault access — separation is the only defence |
| Trustee device compromised | < k shards; BEK not reconstructable |
| Backup file corrupted | GCM authentication tag rejects tampered bytes |
| BEK shards fall below threshold | Export blocked; redistribution required |
| User forgets to export after trustee change | Old backup file permanently unrecoverable; UI warns before trustee change |

### The critical operational risk

The attack that cannot be prevented cryptographically: a trustee obtaining the
backup file through a side channel (shared cloud folder, same messaging app,
physical access). If k trustees acquire the backup file, the vault is fully
exposed.

**The UI must make this concrete at every export touch point:**

> "If any of your trustees obtains this file, they can reconstruct your entire
> vault. Store it somewhere your trustees cannot access — a different cloud account,
> external drive, or device they have no access to."

---

## Export UI requirements

Export is a Settings action, not a feature flag. It requires:

1. **BEK distribution check**: export is disabled if BEK shards have not been
   distributed or fall below threshold. Reason shown inline.

2. **Mandatory educational sheet** (shown every time, no persistent dismiss):
   - What the file contains: all vault entries, encrypted
   - What it does NOT contain: the decryption key (held by trustees)
   - Explicit warning: trustees + this file = full vault access
   - Storage guidance: "Store it somewhere your trustees cannot access"
   - "I understand" CTA — no checkbox, must be read

3. **Destination picker**: `UIDocumentPickerViewController`. App does not choose
   the destination on behalf of the user.

4. **No sharing sheet to contacts**: the export action must not offer AirDrop,
   Messages, or any channel that could route the file to a trustee.

---

## File format

Extension: `.occbak`
UTI: `com.github.aibo-cora.occulta.backup`

Wire format:
```
nonce (12 bytes) ∥ ciphertext ∥ GCM tag (16 bytes)
```

The plaintext is `JSONEncoder().encode(VaultBackup)`.

A four-byte magic prefix `4F 43 42 4B` ("OCBK") precedes the nonce to allow
fast format detection without attempting decryption.

---

## Implementation status

| Component | Status |
|---|---|
| BEK generation + SE-backed storage | 🔲 |
| BEK SSS split + shard delivery (reuse existing pipeline) | 🔲 |
| BEK shard collection + reconstruction | 🔲 |
| `VaultBackup` / `VaultBackupEntry` Codable models | 🔲 |
| Export: decrypt all entries + AES-GCM seal | 🔲 |
| Export: document picker + `.occbak` UTI registration | 🔲 |
| Import: AES-GCM open + PEK regeneration + SwiftData insert | 🔲 |
| Post-import SSS redistribution prompt | 🔲 |
| BEK rotation on trustee change + stale-backup warning | 🔲 |
| Export educational sheet (mandatory, no persistent dismiss) | 🔲 |
| Export disabled when BEK below threshold | 🔲 |
| BEK erosion warning (mirrors per-entry erosion banner) | 🔲 |

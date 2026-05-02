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

`encryptedBEK` is persisted in SwiftData as a vault-level singleton. The raw BEK
bytes are available in memory when the vault is unlocked (vaultKey unwraps them),
and nowhere else.

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

Export is blocked if `encryptedBEK` does not exist (BEK not yet set up) or if
the BEK shard distribution falls below threshold.

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

**Dependency:** the exchange flow must support "update existing contact's key" as
a first-class outcome (not just "create new contact"). Without this, the trustee's
app cannot associate the incoming exchange with an existing `CustodyShard` row and
auto-handback will not fire.

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

Prompts 2 and 3 are shown on first vault unlock after import.

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

The recovery dashboard is the primary UI from the moment the user initiates a
restore until the vault is fully rebuilt. Because shard collection requires
physical proximity exchanges that may span multiple days, the vault tab must
surface persistent, actionable restore progress rather than a generic loading
state.

### Requirements

- **Persistent**: shown in place of the vault until reconstruction completes.
  Survives app restarts — pending restore state is persisted.
- **Per-trustee status**: list each trustee with a simple reached / not yet
  indicator. Showing which trustees to prioritise is more useful than a raw
  shard count.
- **Plain language only**: no crypto terminology. Call shards "recovery pieces".
  Do not name the cryptographic mechanism.
- **Auto-advance**: when the threshold is reached, transition to "Rebuilding
  vault…" automatically — do not require a manual tap.
- **Rebuilding progress**: brief sequential steps shown during reconstruction
  and import (collect → rebuild → redistribute), each checked off as it
  completes.
- **Unreachable trustee fallback**: a way to mark a trustee as unreachable
  so the user understands they must reach the remaining trustees to meet
  threshold. Does not change the cryptographic threshold — informs the user
  which trustees they still need.

### What it must not do

- Reveal which shard index belongs to which trustee.
- Use the words "shard", "BEK", "Shamir", "threshold", or "encryption key".
- Require any action between shard collection and vault reconstruction — the
  transition must be fully automatic once k pieces are in.

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
| BEK generation + vaultKey wrapping → `encryptedBEK` SwiftData singleton | 🔲 |
| BEK SSS split + shard delivery (reuse existing pipeline) | 🔲 |
| BEK trustee picker (pre-populated from Global Trustees, GLOBAL badge) | 🔲 |
| BEK shard collection via auto-handback on contact key re-exchange | 🔲 |
| Contact key-update exchange outcome (prerequisite for auto-handback) | 🔲 |
| Pending restore state (store .occbak, waiting-for-trustees UI) | 🔲 |
| BEK reconstruction (Shamir.combine) + re-wrap under new device vaultKey | 🔲 |
| `VaultBackup` / `VaultBackupEntry` Codable models | 🔲 |
| Export: unwrap encryptedBEK + decrypt all entries + AES-GCM seal | 🔲 |
| Export: document picker + `.occbak` UTI registration | 🔲 |
| Import: AES-GCM open + PEK regeneration + SwiftData insert | 🔲 |
| Post-import BEK shard redistribution prompt | 🔲 |
| Post-import per-entry SSS redistribution prompt | 🔲 |
| Post-import contact re-establishment prompt | 🔲 |
| BEK rotation on trustee change + stale-backup warning | 🔲 |
| Export educational sheet (mandatory, no persistent dismiss) | 🔲 |
| Export disabled when BEK below threshold | 🔲 |
| BEK erosion warning (mirrors per-entry erosion banner) | 🔲 |
| **Recovery dashboard** (required before ship — see Recovery dashboard section) | 🔲 |
| Future: macOS companion app sync | 🔲 |

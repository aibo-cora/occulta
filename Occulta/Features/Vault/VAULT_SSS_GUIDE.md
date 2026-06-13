# Vault SSS Guide

Occulta Vault — Shamir's Secret Sharing engineering reference.  
Commit this file alongside any PR that touches the vault or SSS implementation.

---

## Design intent

SSS is a **per-entry** recovery mechanism. Each vault entry has its own randomly
generated symmetric key (per-entry key, PEK). The PEK is split into shards and
distributed to trusted contacts. A contact who receives a shard holds one piece
of that specific entry's key — not the vault key, not any other entry's key.

This means:
- Different entries can have different trustees and different thresholds.
- Losing one entry's shards does not affect recovery of other entries.
- A trustee who becomes untrusted can be cut off from a specific entry without
  affecting the rest of the vault.

---

## Encryption model (target)

```
vault key (SE-derived)
  └── encryptedEntryKey  →  per-entry key (PEK, 32 random bytes)
        │                    AAD = entry.aad(for: .entryKey)
        ├── encryptedLabel    (AES-GCM, AAD = entry.aad(for: .label))
        │   └── SealedLabelPayload { type: VaultEntryType, label: String }
        ├── encryptedContent  (AES-GCM, AAD = entry.aad(for: .content))
        └── shardDistributionEncrypted  (AES-GCM, AAD = entry.aad(for: .shardDistribution))
```

`aad(for: VaultField)` appends a 1-byte field discriminator to the
`id ∥ timestamp` base, so each ciphertext is bound to its role.
A cross-field swap (e.g. substituting `encryptedContent` bytes for
`encryptedLabel`) fails GCM authentication.

`entryType` is stored inside `SealedLabelPayload` — never in a plaintext
SwiftData column. Cold-disk forensics cannot determine entry categories
without the vault key.

Normal access path:
1. Unlock vault → derive vault key from SE via ECDH.
2. Unwrap PEK: AES-GCM open(encryptedEntryKey, using: vaultKey, authenticating: aad(for: .entryKey)).
3. Decrypt label/content with PEK, passing the matching field discriminator.

SSS path:
- Split the PEK (not the vault key) into n shards.
- Distribute shards via .occ to trustees (ML-KEM required — see below).
- Recovery: collect ≥ k shards, reconstruct PEK, decrypt entry.

---

## Recovery scope

SSS recovers the **per-entry key (PEK) only** — not the encrypted content.

`encryptedLabel` and `encryptedContent` live in the `VaultEntry` SwiftData row on
Alice's device. Reconstruction (`tryFinalizeReconstruction`) fetches that row by
`entryID` and decrypts it using the reconstructed PEK. If the device is lost and
the SwiftData store is gone, the ciphertext is gone — no number of shards can
recover it.

This is intentional and matches industry standard SSS deployments (SLIP-39,
enterprise key management, hardware wallet recovery): trustees are **key custodians**,
not data custodians. Distributing ciphertext to trustees was considered and rejected
for the following reasons:

- **Collusion attack surface**: k colluding trustees can silently decrypt a full
  entry without Alice's involvement or awareness. Without ciphertext distribution,
  k colluding trustees reconstruct the PEK but have no ciphertext to apply it to.
- **Compromised trustee device**: with ciphertext at rest on a trustee's device,
  an attacker who compromises that device holds the encrypted target plus one share.
  The threshold property still holds, but the attack surface is materially worse.
- **Size metadata**: AES-GCM does not pad. Every trustee can observe exact plaintext
  sizes from the ciphertext length, revealing information about the entry even though
  the content is encrypted.
- **Trust relationship mismatch**: users selecting trustees understand them as key
  holders. Silently making them data holders is a different and larger trust grant
  that users are unlikely to reason about correctly.

### Content backup is the user's responsibility

Full recovery from device loss requires two independent components:

1. **PEK** — reconstructed from k shards via SSS (what this system provides).
2. **Ciphertext** — `encryptedLabel` + `encryptedContent` from a vault backup
   (user's responsibility).

Alice must maintain a separate vault backup — a passphrase-protected export stored
in iCloud Drive, a password manager, or physical media — for full device-loss
recovery. SSS alone is not sufficient.

Recovery flow with both components:

```
backup file  → encryptedLabel, encryptedContent
shards (≥ k) → reconstruct PEK
PEK + encryptedContent → plaintext
PEK + new vault key    → new encryptedEntryKey (re-establishes normal access path)
```

The two halves are independent. A backup without shards is useless if the vault
key is lost. Shards without a backup reconstruct a key with nothing to decrypt.
Neither alone is sufficient; together they constitute full recovery.

### What to surface in the UI

Two touch points surface this boundary without interrupting the user:

**Shard distribution setup (`VaultShardSetup`)** — an amber cautionary note
below the "Information-theoretic security" note, visible before the user taps
"Mark for Distribution":

> ⚠️ Key recovery only  
> Shards protect your encryption key — not the entry content. To recover your
> content after device loss, export a separate vault backup.

**Entry detail (`VaultEntryDetail`)** — a low-weight secondary note, shown only
when `shardDistributionEncrypted != nil`, positioned after the erosion banner and
before the provenance block:

> 🔑 Shards protect your encryption key — not the entry content. Export a vault
> backup separately to ensure full recovery after device loss.

No action button is attached to either note. The warning is informational only;
navigation to the export flow is the user's responsibility via vault settings.

---

## Shard signing

Each shard is wrapped in a `SignedAttribute(category: .shard)` signed by the
owner's SE identity key. The signing payload (v2) is:

```
"occulta-signed-attribute-v2" ∥ attrID ∥ "shard" ∥ entryID
∥ createdAt UInt64 BE ∥ expiry flag (0x00 | 0x01 ∥ expiresAt UInt64 BE)
∥ shardBytes
```

Including `entryID` binds the shard to a specific PEK generation. A shard from
a previous distribution (old PEK) fails verification even against the same
signing key, because the `entryID` in the payload won't match.

Including `createdAt` and `expiresAt` in the payload prevents a trustee from
modifying those fields in stored JSON to extend a shard's validity past its
intended lifetime. Without this, a trustee who receives a shard with a 1-year
expiry could edit the serialized `expiresAt` to nil — the ECDSA signature would
still verify because the expiry wasn't covered. With v2, any modification to
`createdAt` or `expiresAt` invalidates the signature.

`expiresAt` is always nil for shards in the current implementation — enforcement
is deferred until expiry is actually set. The signed payload already covers the
field so future enforcement will have a cryptographically verified value to check.

### Signature verification after device loss

The SE key is non-exportable and non-migratable. On a new device, Alice has a
new SE key and cannot verify signatures made by her old key.

During recovery on a new device, signature verification is skipped. Shard
integrity falls back to AES-GCM authentication: if the reconstructed PEK
successfully opens the sealed entry (authentication tag passes), the shards
were intact. GCM authentication replaces ECDSA verification in the recovery
path.

The ECDSA signature's value is preventing tampered shards during **normal
operation** (Alice still has her old key). It is not a recovery-path guarantee.
Document this in user-facing recovery instructions.

---

## Trustee eligibility: ML-KEM required

A contact can only be a trustee if he has ML-KEM key material
(`quantumKeyMaterialEncrypted != nil` on their key record). Contacts without it
are excluded from trustee selection before the UI renders the picker — they
never appear as an option.

Why ML-KEM is mandatory:

Shards are the highest-value HNDL (harvest-now-decrypt-later) target in the
system. A passive adversary who archives shard bundles today and waits for a
cryptographically relevant quantum computer can solve ECDLP on any recorded
P-256 public key and recover the session key — unless a second, quantum-resistant
primitive is also in the derivation.

Forward secrecy does not protect against this. A quantum computer derives the
private key from the public key that is always visible in the recorded bundle
(ephemeral public key in `.forwardSecret`, long-term public key in
`.longTermFallback`). Deleting keys from the SE after use does not help a
future quantum computer that never needed the stored bytes.

ML-KEM-1024 in the hybrid session key is the only defense against HNDL.
Requiring it for trustees makes the gate explicit and enforced in code.

All contacts exchanged via UWB already have ML-KEM material — the key exchange
flow always generates it. Contacts added via Bluetooth-only exchange do not.

---

## Shard delivery session key

Shard bundles always use **`longTermFallback` + ML-KEM**. Prekeys are never
consumed for shard traffic.

### Encryption API

A single **`encryptBundle(data:for:shardOperations:)`** handles all outbound
bundles. Mode selection is automatic and enforced inside the function — it
cannot be bypassed at the call site:

```
shardMode = data == nil || shardOperations.contains { $0.attribute != nil }
```

**Shard mode** (any `.distribute` or `.handback` op present, or `data == nil`):
- ML-KEM required; throws `trusteeLacksQuantumMaterial` if absent.
- `contactPrekey: nil` — `Manager.Crypto.seal` uses `longTermFallback`.
- No prekey consumption. No prekey sync batch. No model context save.
- `data` defaults to a human-readable fallback for old builds.

**Message mode** (no `attribute`-carrying ops, `data` non-nil):
- Normal v3fs path: `configureForwardSecrecy`, prekey pop (→ `.forwardSecret`
  when a prekey is available, `.longTermFallback` when exhausted), pending
  prekey sync batch attached, prekey state saved.

The condition keys on `op.attribute != nil` rather than enumerating kinds —
any future operation that carries a `SignedAttribute` automatically gets shard
mode treatment without touching the gate.

The private `resolveKeyMaterial(for:requireQuantum:)` helper decrypts the
contact's key record once; both modes call it.

Session key derivation:
```
HKDF-SHA256(
  inputKeyMaterial: ECDH(senderLongTermPriv, recipientLongTermPub) ⊕ ML-KEM shared secret,
  salt: XOR(recipientPub, senderPub),
  info: contextString
)
```

Why `longTermFallback` and not forward-secret prekeys:

Classical forward secrecy protects against **private key extraction from
storage** — if key bytes leak from a file, a memory dump, or a server, past FS
sessions are still opaque. The SE identity key is hardware-protected and
non-exportable; classical extraction is not a realistic threat model here.

Against a quantum adversary, both modes are equally vulnerable: a quantum
computer solves ECDLP on the public key recorded in the bundle — the ephemeral
public key for FS, the long-term public key for `longTermFallback`. Deleting
private keys from the SE does not prevent the adversary from deriving them from
the public key they already have. ML-KEM is the defence against this attack
regardless of mode.

Given that the SE makes classical key extraction extremely hard and ML-KEM
covers the quantum path, `longTermFallback` + ML-KEM provides the same
practical security as FS + ML-KEM for shard traffic. It is simpler: no prekey
batch management, no consumption of a finite per-contact resource, no fallback
logic needed in the delivery path.

---

## Shard delivery envelope

Each shard is delivered as a `.occ` bundle using `longTermFallback + ML-KEM`.

The `shardOperations` array carries data-carrying operations only:

| Kind | Payload |
|---|---|
| `.distribute` | `SignedAttribute` — shard to store (first distribution) |
| `.replace` | `SignedAttribute` (new shard) + `attributeID` (ID of old shard to delete) |
| `.handback` | `SignedAttribute` — owner's shard returned by trustee on key rotation |

`attributeID` in `.replace` allows the recipient to discard the superseded shard.
Trustees on older builds that don't understand `attributeID` retain the superseded
shard; it is harmless — the old PEK fails GCM authentication against the rotated entry.

Operations no longer in the protocol (removed in favour of manifest fields):
`.acknowledge`, `.revoke`, `.inquire`, `.notFound`, `.returnAcknowledged`.

---

## What Bob stores

When Bob receives a shard from Alice, he stores a `CustodyShard` row containing
only:
- A random per-row `id` (plaintext SwiftData key — no other plaintext).
- An `encryptedPayload` blob — AES-GCM seal of `{ ownerKeyFingerprint,
  ownerContactIdentifier, signedAttribute }` under the shard custody key,
  AAD = `id` (id-only, no timestamp).

`ownerContactIdentifier` is Alice's contact identifier in Bob's contact book.
It is stored inside the sealed payload — never plaintext — so cold-disk forensics
cannot link a shard row to a specific contact without the shard custody key.

Bob does not need: the entry label, the threshold, or how many other trustees
Alice chose.

### Privacy at rest

No plaintext column links a row to a contact. Cold-disk forensics learns
"Bob holds N shards" — nothing about which contacts those shards belong to,
when they were received, or how many shards each contact has outstanding.
Resolving owner identity requires the SE-protected shard custody key.

Looking up shards by contact identifier or `SignedAttribute.id` (for `.revoke`,
`replacesID` matching, or auto-return) requires decrypting every row. The
realistic N is low hundreds at most, so the cost is negligible. If N grows, a
launch-time in-memory `(rowID → attrID, contactIdentifier)` cache is the cheap
upgrade.

---

## Reconstruction flow

1. Trustees detect Alice's key change during proximity exchange and auto-return
   their shards. Each sends `.handback` operations in the next outbound bundle to
   Alice (see "Owner key rotation = auto-return trigger" below).
2. Alice's app collects arriving shards into the `ReconstructShard` buffer.
3. When ≥ k shards are buffered, `tryFinalizeReconstruction` runs automatically.
4. If Alice still has her original SE key: verify each shard's signature.
   If on a new device: skip signature verification, rely on GCM authentication.
5. Run `ShamirSecretSharing.reconstruct(shares:)` → 32-byte PEK.
6. Attempt `AES.GCM.open(encryptedContent, using: PEK, authenticating: aad())`.
   - Success: GCM authentication confirms shard integrity. Re-wrap PEK under
     current vault key and save as new `encryptedEntryKey`.
   - Failure: one or more shards are corrupt or from the wrong distribution.
     Surface error; do not persist.
7. Zero the reconstructed PEK bytes immediately after re-wrapping.

After successful reconstruction Alice's `shardDistributionEncrypted` still exists
but references trustees who may no longer hold shards (they were returned and will
be deleted on `.returnAcknowledged`). The entry detail view surfaces a
"re-establish recovery" prompt the first time Alice opens the entry after
reconstruction, asking her to redistribute.

---

## Reconstruction buffer (`ReconstructShard`)

Owner-side transient queue for `.handback` bundles arriving during recovery. Each
arriving shard becomes one `ReconstructShard` row, sealed under the recovery
buffer key with AAD = `id` (id-only). The plaintext columns carry no
identifying information.

Sealed payload: `{ entryID, attrID, signedAttribute }`. The `entryID` lives
inside the seal so a forensic reader cannot tell which entries are mid-recovery
or how many shards have arrived per entry.

### Why a separate model from CustodyShard

Different roles, different keys, different lifecycles. CustodyShard is custody
*for someone else*, sealed under the shard custody key, long-lived. ReconstructShard
is a self-recovery receive buffer, sealed under the recovery buffer key, transient.
Keeping them as distinct types means the type system enforces "you cannot decrypt
one with the other" and a stray cleanup query cannot accidentally cross-contaminate.

### Lifecycle

| Event                            | Action                                                      |
|----------------------------------|-------------------------------------------------------------|
| `.handback` arrives, vault locked | Insert row. Finalisation deferred to next vault unlock.     |
| `.handback` arrives, vault unlocked | Insert row, then opportunistic `tryFinalizeReconstruction`. |
| Vault unlock                     | Sweep all entries with `shardDistributionEncrypted` and finalise any that crossed threshold while locked. |
| Reconstruction succeeds          | Bulk-delete all rows whose payload references that `entryID`. |
| User cancels recovery            | Bulk-delete by `entryID` (decrypt-and-filter).              |

Multiple recoveries coexist trivially because rows are filtered by the sealed
`entryID` field at decrypt time — no new types needed for parallel recoveries.

`VaultManager` is `@MainActor` — all calls to `tryFinalizeReconstruction` and
`tryFinalizeAllReconstructions` are serialised on the main thread. Concurrent
finalisation is not possible in practice; no additional locking is needed.

---

## ShardRecord.status transitions

`ShardRecord` (inside `ShardDistributionMetadata`) tracks the owner's view of each distributed shard.

Valid transitions:

| From         | To           | Trigger                                                                          |
|--------------|--------------|----------------------------------------------------------------------------------|
| `.pending`   | `.confirmed` | Trustee's `custodyManifest` includes this shard's ID                            |
| `.pending`   | `.lost`      | Trustee's `custodyManifest` is non-nil, ID absent, no `PendingShardDistribute` row |
| `.confirmed` | `.lost`      | Trustee's `custodyManifest` is non-nil, ID absent, no `PendingShardDistribute` row |
| `.confirmed` | `.revoked`   | Owner removes this trustee; ID omitted from `expectedShards` going forward      |
| `.pending`   | `.revoked`   | Owner removes this trustee before confirmation                                  |

Invalid / rejected transitions:

- `.lost → .confirmed` — a lost shard cannot be un-lost by a late manifest appearance.
- `.revoked → any` — revocation is terminal; redistribution creates a new `ShardRecord` with a new `attrID`.

The `.pending` → `.lost` transition requires a **non-nil manifest** (confirming the trustee is a capable build and has responded) **and** no active `PendingShardDistribute` row (confirming delivery is not still in flight). An absent ID in a nil manifest is inconclusive and triggers no status change.

`.revokePending` remains in the enum for backward-compatible decoding of existing serialized data. New code never sets this status — revocation transitions directly to `.revoked`.

### Why custody-key-class access (no biometric)

`.handback` bundles can arrive while the vault is locked. The recovery buffer
key is derived from the custody SE key (device-unlock, no biometric) so the
buffer can absorb shards without prompting. Reconstruction itself still requires
the vault unlocked — re-wrapping the recovered PEK under the vault key needs
the vault SE key.

### Privacy at rest

| | Without ReconstructShard | With ReconstructShard |
|---|---|---|
| Cold-disk forensics | (can't recover at all from process kill) | "Alice has N rows in the reconstruct buffer." Nothing about which entries, how many shards each, or who sent them. |

---

## Shard revocation

Revocation is implicit — no `.revoke` operation is required.

**What triggers revocation:**
- Owner removes a trustee from the trustee list (user action).
- Re-distribution: Alice distributes new shards to a different trustee set; old
  trustee IDs are absent from future `expectedShards`, causing trustees to delete them.

**Alice's side:** on revocation, `ShardRecord.status` transitions directly to `.revoked`
(no intermediate `.revokePending` state). Alice stops including the revoked shard ID
in `expectedShards`. On Bob's next bundle to Alice, the ID is absent from his manifest
(Bob deleted it based on `expectedShards`). The status is already terminal.

**Bob's side:** on receiving `expectedShards` that omits an ID he holds (with matching
fingerprint), `processExpectedShards` deletes the `CustodyShard` row immediately.

`.revoked` is a terminal state — the shard must be re-distributed as a new
record with a new `attrID` to restore coverage.

**Threshold erosion:** when `.lost` or `.revoked` records reduce the active
shard count below `threshold`, the entry detail view shows an inline warning
prompting redistribution. Active = `.pending` + `.confirmed` shards only.

---

## Shard custody and recovery buffer keys

Shard operations require a dedicated SE key — separate from the identity key
and the vault key.

**Tag:** `"shard.custody.occulta"`  
**Access:** `kSecAttrAccessibleWhenUnlockedThisDeviceOnly + .privateKeyUsage`  
**No biometric flag** — device-unlock level only.

Why no biometric? Shard requests arrive in inbound bundles, processed automatically
on receipt. If the shard custody key required Face ID per operation, Bob would need to
open the app and interact each time a contact requests a shard back. Full automation
(zero UI involvement for Bob) is the design goal.

Two distinct symmetric keys are HKDF-derived from this single SE key:

| Symmetric key            | HKDF info                          | Seals          |
|--------------------------|------------------------------------|----------------|
| Shard custody key        | `Occulta-v1-shard-custody-2026`    | CustodyShard   |
| Recovery buffer key      | `Occulta-v1-recovery-buffer-2026`  | ReconstructShard |

Domain separation guarantees that a CustodyShard blob and a ReconstructShard
blob are never decryptable with the same symmetric key, even though they share
an SE source.

The year suffix in the info strings is frozen at the time the keys were first
derived and cannot be changed without invalidating all existing sealed rows for
existing users. Treat these strings as opaque immutable constants — the year
carries no operational meaning.

Derivation: `ECDH(shardCustodySEKey, G) → HKDF-SHA256(salt: custodyPubKey, info: <info>)`

---

## Contact identifier for shards

`ShardRecord.contactIdentifier` is a `String` holding `Contact.Profile.identifier`
— a stable SwiftData UUID created on profile init. It does not change across key
re-exchanges and does not encode the public key fingerprint.

`CustodyShard.Payload.ownerKeyFingerprint` is `Data` (SHA-256 of the owner's public
key) — the shard-receiving side has the owner's public key from the signed
attribute itself. It lives inside the sealed payload, not in a plaintext
column.

---

## Inbound bundle processing order

Every `SealedPayload` may carry three shard-related fields:

- `shardOperations: [ShardOperation]?` — data-carrying operations (`.distribute`, `.replace`, `.handback`).
- `custodyManifest: [UUID]?` — trustee reporting which shards it currently holds.
- `expectedShards: [UUID]?` — owner declaring which shards it expects the trustee to hold.

Processing order when a bundle arrives:

1. **`shardOperations`** — handled in order:
   - `.distribute` — store new `CustodyShard`; if sender's fingerprint differs from existing shards for this contact, delete all mismatch-fingerprint shards (owner completed recovery and is redistributing).
   - `.replace` — store new `CustodyShard`, delete the shard with `attributeID` (superseded). Same mismatch cleanup as distribute.
   - `.handback` — hand shard bytes to the reconstruction flow via `acceptReturnedShard`. No acknowledgement queued; see "Owner key rotation" below.

2. **`custodyManifest`** (owner-side processing) — for each active `ShardRecord` for this sender:
   - ID present in manifest → mark `.confirmed`; delete `PendingShardDistribute` row.
   - ID absent, manifest non-nil, no distribute row → mark `.lost`.
   - ID absent, distribute row exists → delivery in progress; no change.
   - Manifest `nil` → no-op (old-build sender).

3. **`expectedShards`** (trustee-side processing) — for each `CustodyShard` held for this sender whose fingerprint **matches** the sender's current public key:
   - ID in expected list → keep.
   - ID not in expected list → delete (implicit revoke).
   Mismatch-fingerprint shards are never deleted by this step.

---

## Trustee key rotation = implicit shard loss

When a trustee (Bob) re-exchanges keys with Alice, Bob's identity key fingerprint
has changed. Since Occulta has no in-app identity key rotation, this can only mean
Bob is on a new device. A new device is a clean app install: Bob's SwiftData store
is empty, so his `CustodyShard` rows no longer exist.

Bob's first outbound bundle to Alice after the exchange will carry `custodyManifest: []`.
Alice sees the expected shard ID absent from a non-nil manifest, with no
`PendingShardDistribute` row (the distribute was previously confirmed) → marks `.lost`.

Note: `Contact.Profile.identifier` is a stable SwiftData UUID created on init and
does not change across key re-exchanges. Alice's `ShardDistributionMetadata` remains
valid after Bob re-exchanges — only the shard itself is gone, not the routing metadata.

---

## Owner key rotation = auto-return trigger

When Alice re-exchanges keys with Bob (Alice got a new device), Bob detects that
Alice's key fingerprint differs from the previously stored one. This is an unambiguous
signal that Alice lost her device and vault — key exchange is proximity-only, so a
changed fingerprint cannot be injected remotely.

Bob's app responds automatically, with no separate scheduling model:

1. **Detection** — at bundle build time, `buildShardOperations` inspects every
   `CustodyShard` for Alice. Any shard whose stored `ownerKeyFingerprint` differs
   from Alice's current key fingerprint is a **mismatch shard**.
2. **Deliver** — mismatch shards are included as `.handback(signedAttribute)` in
   every outbound bundle to Alice. Bob does not delete these rows pre-emptively.
   `encryptBundle` enforces ML-KEM when `.handback` ops are present.
3. **Alice receives `.handback`** — `acceptReturnedShard` stores each shard in the
   `ReconstructShard` buffer (sealed under the recovery buffer key, no biometric).
   `tryFinalizeReconstruction` is triggered opportunistically.
4. **Cleanup** — when Alice successfully redistributes (sends `.distribute` with her
   new fingerprint), `handleDistribute` detects the fingerprint change and deletes
   all mismatch-fingerprint shards for Alice's contact. No explicit acknowledgement
   is needed. Bob stops including `.handback` ops because the mismatch rows are gone.

### Key notes

- No `PendingShardReturn` model. Mismatch detection is a live computation at build time.
- No `.returnAcknowledged` operation. Cleanup is triggered by the new `.distribute`.
- If Bob holds shards for Alice across multiple vault entries, all are returned in
  one or more bundles (one `.handback` per shard, all in `shardOperations`).
- The returned `SignedAttribute`s were signed with Alice's old SE key. Verification
  fails on Alice's new device by design — GCM authentication on reconstruction is
  the integrity check (see "Signature verification after device loss").
- If Alice re-exchanges again before sending a `.distribute` (she's still recovering),
  Bob's fingerprint check still fires and `.handback` ops keep retrying idempotently.
  `acceptReturnedShard` deduplicates by `signedAttribute.id`.

---

## Shard custody reconciliation

### The approach: manifest-based (push, continuous)

Every outbound bundle carries two optional reconciliation fields:

| Field | Direction | Contents |
|---|---|---|
| `custodyManifest: [UUID]?` | trustee → owner | All shard IDs currently held for this owner |
| `expectedShards: [UUID]?` | owner → trustee | All shard IDs owner expects trustee to hold |

These fields piggyback on every bundle — including normal message bundles — at zero
protocol overhead (they are optional JSON fields; `nil` means no shard relationship
with this contact or old-build sender).

**How Alice's status updates:** on every incoming bundle from Bob, `processCustodyManifest`
walks Alice's `ShardDistributionMetadata` for shards assigned to Bob. Presence
confirms custody (`.confirmed`); absence with no in-flight distribute row marks loss
(`.lost`). No explicit `.acknowledge` or `.notFound` operation required.

**How Bob's custody is kept clean:** on every incoming bundle from Alice,
`processExpectedShards` walks Bob's `CustodyShard` rows for Alice. Any matching-
fingerprint shard whose ID is absent from `expectedShards` is deleted immediately
(implicit revoke). No explicit `.revoke` operation required.

**Why push is better here than the earlier pull approach (`.inquire`):**
- Every bundle exchange is an implicit reconciliation — no stale-after-N-days heuristic.
- Silent data loss (Bob reinstalls without key change) is detected on Bob's next
  outbound bundle via `custodyManifest: []`, rather than requiring Alice to probe.
- No `PendingShardNotFound`, `PendingShardAcknowledge`, `PendingShardRevoke` models.
  Status is derived from live manifest data, not queued operations.

### What this does not fix

- **Bob never opens the app.** No client-side mechanism can query a completely silent
  peer. This is unchanged from the pull approach.
- **Trustees Alice rarely or never messages.** `custodyManifest` and `expectedShards`
  piggyback on natural traffic. A trustee Alice never messages will never be reconciled
  until the next exchange. A "Check Coverage" button that sends protocol-only bundles
  to all trustees of an entry is the planned fix; it is not yet implemented.
- **Old-build trustees.** A trustee running a build without manifest support sends
  `nil` for `custodyManifest`. Alice treats `nil` as "no update" — stale `.confirmed`
  status is possible until the trustee upgrades.

### `PendingShardDistribute` lifecycle

Unlike the old fire-and-forget pattern, `PendingShardDistribute` rows now persist
until the shard is confirmed via `custodyManifest`:

- **Inserted** by `queueDistribute` after `prepareShards`.
- **Included** in every outbound bundle to the trustee (automatic retry on bundle loss).
- **Deleted** when the shard ID appears in the trustee's `custodyManifest` (Alice marks `.confirmed`).

This guarantees delivery: if a distribute bundle is lost in transit, the next bundle
will retry automatically. The trustee deduplicates on receive.

---

## Vault health monitoring

Health monitoring runs on the **current device** after vault unlock. It answers
"is my recovery setup in good shape right now?" — it is not part of the
new-device recovery flow (that is the `ReconstructShard` / `tryFinalizeReconstruction`
system documented above).

Three independent signals are surfaced:

| Signal | Property | Requires vault unlock |
|---|---|---|
| Per-entry key (PEK) shard health | `recoveryHealth` | ✅ |
| Backup encryption key (BEK) status | `bekSetupState` | ✅ |
| Vault backup staleness | `backupStaleness` | ✅ |

All three are `nil` / `.notSetup` when the vault is locked and are recomputed
together on every relevant state change.

---

### PEK shard health — `RecoveryHealthSummary`

`VaultManager.recoveryHealth: RecoveryHealthSummary?` is an `@Observable` property
computed on every vault unlock, `deleteEntry`, `updateShardStatus`, and
`prepareShards` call. It is `nil` when the vault is locked.

`recomputeRecoveryHealth()` walks every `VaultEntry` with
`shardDistributionEncrypted`, decrypts the metadata, and counts active shards
(`.pending` or `.confirmed`). Entries whose active count falls below their
threshold are collected into `RecoveryHealthSummary.affected`:

```
struct RecoveryHealthSummary {
    enum EntryStatus { case degraded, critical }
    struct AffectedEntry {
        let entryID:   UUID
        let label:     String
        let entryType: VaultEntryType
        let status:    EntryStatus   // critical = 0 active; degraded = 1…k-1 active
        let active:    Int
        let threshold: Int
    }
    let affected: [AffectedEntry]   // sorted: critical first, then degraded, both α
}
```

Entries at or above threshold are healthy and do not appear in `affected`.

#### Vault tab Attention section

When `recoveryHealth.affected` is non-empty and the filter is not set to
`.shards`, `VaultTab` surfaces an **Attention** section above the normal entry
list. Each affected entry is shown as a `VaultAffectedEntryRow`:

- **Degraded** (amber): subtitle shows `N of K recovery pieces` — the user can
  still redistribute to restore coverage.
- **Critical** (red): subtitle shows `recovery unavailable` — all active shards
  are gone; redistribution is required before recovery is possible.

Tapping any row navigates to the entry's detail, where the user can redistribute
shards. Entries already shown in the Attention section are excluded from the
normal entry list below to avoid duplication.

The section header colour follows the worst status in the set: red if any entry
is critical, amber if all are merely degraded.

#### PEK update triggers

| Event | Triggers recompute |
|---|---|
| Vault unlock | ✅ |
| `prepareShards` (new distribution) | ✅ |
| `updateShardStatus` (acknowledge / notFound) | ✅ |
| `deleteEntry` | ✅ |
| Vault lock | clears to nil |

---

### BEK status — `BEKSetupState`

`VaultManager.bekSetupState: BEKSetupState` reflects the current distribution
state of the Backup Encryption Key. The BEK encrypts `.occbak` export files;
its shards are what allow Alice to restore a backup on a new device without
her original SE key.

```
enum BEKSetupState: Equatable {
    case notSetup                                          // no BEK in SwiftData
    case waitingForConfirmations(confirmed: Int, threshold: Int)  // BEK exists, below threshold
    case ready                                             // confirmed ≥ threshold
}
```

State derivation:

```
bekSetupState:
  → try bekShardMetadata()          // decrypt BackupEncryptionKey row
  → nil                  → .notSetup
  → meta.confirmed < k   → .waitingForConfirmations(confirmed, threshold)
  → meta.confirmed ≥ k   → .ready
```

`confirmed` counts only `.confirmed` shards (not `.pending`). A BEK shard is
confirmed when the trustee's `custodyManifest` includes it — the same manifest
mechanism used for PEK shards.

**Why `.notSetup` is critical:** an unset BEK means any exported backup file is
undecryptable without Alice's original SE key. If that device is lost, the
backup is permanently inaccessible. Users should be prompted to export a backup
and distribute BEK shards before they consider their vault protected.

`bekSetupState` is a computed property — it reads the sealed `BackupEncryptionKey`
row on every call. It is not cached; call sites should avoid tight loops.

---

### Backup staleness — `BackupStalenessReport`

`VaultManager.backupStaleness: BackupStalenessReport?` is `nil` when the vault
is locked, when no backup has ever been exported from this device, or when the
backup is fully current. A non-nil value means the last exported `.occbak` file
no longer faithfully represents the vault's current state.

```
struct BackupStalenessReport {
    let bekRotated:        Bool   // rotateBEK() called since last export — file permanently unrestorable
    let newEntryCount:     Int    // entries created after last export
    let trusteeSetChanged: Bool   // trustee count differs from export snapshot

    var isStale: Bool { bekRotated || newEntryCount > 0 || trusteeSetChanged }
}
```

Staleness is computed by `refreshBackupStaleness()`, called from `exportBackup()`
and on vault unlock. It compares the sealed `VaultSnapshot` recorded at last
export against the current SwiftData state.

**Severity ordering for UI surfaces:**

| Reason | Severity | User action |
|---|---|---|
| `bekRotated` | Critical — existing file unrestorable | Export a new backup immediately |
| `newEntryCount > 0` | Warning — entries missing from backup | Export a new backup |
| `trusteeSetChanged` | Warning — distribution drift | Export a new backup |

`bekRotated` takes priority: if the BEK has been rotated, the current file
cannot be decrypted regardless of other conditions, and no partial recovery is
possible from it.

#### Staleness update triggers

| Event | Action |
|---|---|
| `exportBackup()` | Resets staleness — writes new `VaultSnapshot` |
| Vault unlock | `refreshBackupStaleness()` called — updates `backupStaleness` |
| `rotateBEK()` | Sets `bekRotated = true` in the snapshot diff |
| New entry added | Increments `newEntryCount` on next `refreshBackupStaleness()` |
| Vault lock | `backupStaleness` stays at last computed value (read from `@Observable`) |

---

## Implementation status

| Component                             | Status        |
|---------------------------------------|---------------|
| SSS math (split / reconstruct)        | ✅ Done        |
| Shard signing (SE key, v2 payload)    | ✅ Done        |
| entryID binding in signature          | ✅ Done        |
| expiresAt / createdAt in signature    | ✅ Done        |
| ShardStatus / ShardRecord model       | ✅ Done        |
| ShardDistributionMetadata rewrite     | ✅ Done        |
| CustodyShard SwiftData model (encrypted at rest) | ✅ Done |
| ReconstructShard buffer (encrypted at rest) | ✅ Done   |
| Shard custody SE key                  | ✅ Done        |
| Recovery buffer key (HKDF domain-sep) | ✅ Done        |
| ShardOperation in SealedPayload       | ✅ Done        |
| Schema registration (App)             | ✅ Done        |
| Per-entry encryption keys (PEK)       | ✅ Done        |
| VaultEntry model update (PEK fields)  | ✅ Done        |
| VaultManager PEK unwrap path          | ✅ Done        |
| Trustee ML-KEM gate (eligibility enforcement) | ✅ Done        |
| ShardCustodyManager (inbound router)  | ✅ Done        |
| .occ delivery pipeline (longTermFallback + ML-KEM) | ✅ Done |
| Reconstruction flow                   | ✅ Done        |
| Reconstruction buffer + finalise on unlock | ✅ Done   |
| New-device recovery (no SE key)       | ✅ Done        |
| Shard distribution UI (V4 Trust-first, ML-KEM gate) | ✅ Done |
| Threshold erosion warning (entry detail) | ✅ Done     |
| Aggregate PEK health indicator (vault tab attention section) | ✅ Done |
| BEKSetupState health signal (bekSetupState)                  | ✅ Done |
| Backup staleness report (backupStaleness / BackupStalenessReport) | ✅ Done |
| Vault health dashboard (VaultRecoverySettings — BEK + PEK + backup) | ✅ Done |
| ownerContactIdentifier in CustodyShard.Payload | ✅ Done |
| [ShardOperation]? on SealedPayload (multi-shard bundles) | ✅ Done |
| .returnAcknowledged ShardOperation kind | ✅ Done |
| attrIDs: [UUID] on ShardOperation (acknowledge payload) | ✅ Done |
| PendingShardReturn SwiftData model    | ✅ Done |
| PendingReturnAcknowledge SwiftData model | ✅ Done |
| Key-change detection in exchange flow | ✅ Done |
| Auto-return trigger + delivery hook   | ✅ Done |
| Return acknowledge send + cleanup     | ✅ Done |
| Feature flag (hidden until done)      | ✅ Done        |
| ShardRecord.distributedAt field                         | ✅ Done     |
| custodyManifest field on SealedPayload                  | ✅ Done     |
| expectedShards field on SealedPayload                   | ✅ Done     |
| processCustodyManifest (ShardCustodyManager)            | ✅ Done     |
| processExpectedShards (ShardCustodyManager)             | ✅ Done     |
| buildCustodyManifest (ShardCustodyManager)              | ✅ Done     |
| buildExpectedShards (ShardCustodyManager)               | ✅ Done     |
| Fingerprint-mismatch handback (build-time, no model)   | ✅ Done     |
| Mismatch-shard cleanup on new distribute                | ✅ Done     |
| PendingShardDistribute delete-on-confirm lifecycle      | ✅ Done     |
| Manifest-based status update (locked-vault replay)      | ✅ Done     |
| Backup scope warning in VaultShardSetup + VaultEntryDetail | ✅ Done |
| AAD field discrimination (VaultField discriminator byte, B1) | ✅ Done |
| entryType encrypted in SealedLabelPayload — no plaintext column (B2) | ✅ Done |
| PendingShardStatusUpdate model (locked-vault status replay)  | ✅ Done |
| Threshold guard in reconstructEntry (fail-fast before Lagrange) | ✅ Done |
| Idempotent handleDistribute (duplicate shard delivery safe)   | ✅ Done |
| Vault backup export (user-facing, prerequisite for full device-loss recovery) | 🔲 Recommended |

---

## Known threat model properties

- **< k shards:** information-theoretically independent of the secret.
  An attacker with t < k shards learns nothing about the PEK.
- **Shard mixing across entries:** impossible — each distribution uses
  independent random polynomials. Mixing shards from two different splits
  produces garbage that fails GCM authentication.
- **Stale shards:** reconstruct an old PEK. GCM decryption fails immediately.
  No plaintext is exposed.
- **New device, no old SE key:** signature verification skipped. GCM
  authentication on decryption substitutes as integrity check.
- **Malicious trustee sending tampered shard:** ECDSA signature fails (normal
  operation). On new device: GCM decryption fails if the shard bytes were
  altered.
- **Harvest-now-decrypt-later (HNDL):** a passive adversary archives shard
  bundles today and waits for a quantum computer to break P-256. Both FS and
  longTermFallback mode are equally vulnerable to this attack — a quantum
  computer derives the private key from the public key recorded in the bundle,
  without ever needing the stored key material. ML-KEM in the hybrid session key
  is the only defence. The mandatory ML-KEM gate on trustee selection ensures
  every shard bundle uses a session key that requires breaking ML-KEM-1024 in
  addition to P-256 to decrypt. As of 2026 no known classical or quantum attack
  achieves this within the security parameter.
- **Cross-field ciphertext swap:** `encryptedLabel`, `encryptedContent`,
  `encryptedEntryKey`, and `shardDistributionEncrypted` each carry a distinct
  1-byte field discriminator in their AAD. Substituting one field's ciphertext
  for another fails GCM authentication before any plaintext is produced.
- **Entry category metadata leak:** `entryType` is sealed inside
  `SealedLabelPayload` and never stored in a plaintext column. Cold-disk
  forensics observes encrypted blobs only — entry categories (seed phrase,
  note, key token) are not recoverable without the vault key.
- **GF(2⁸) arithmetic timing:** `gfMul` and `gfInv` contain data-dependent
  branches. On Apple Silicon this is acceptable for SSS (not key derivation),
  but the implementation is not formally constant-time.

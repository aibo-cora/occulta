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
        ├── encryptedLabel    (AES-GCM, AAD = entry.aad())
        └── encryptedContent  (AES-GCM, AAD = entry.aad())
```

Normal access path:
1. Unlock vault → derive vault key from SE via ECDH.
2. Unwrap PEK: AES-GCM open(encryptedEntryKey, using: vaultKey).
3. Decrypt label/content with PEK.

SSS path:
- Split the PEK (not the vault key) into n shards.
- Distribute shards via .occ to trustees (ML-KEM required — see below).
- Recovery: collect ≥ k shards, reconstruct PEK, decrypt entry.

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

A contact can only be a trustee if they have ML-KEM key material
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

Two functions handle outbound shard traffic in `ContactManager`:

- **`encryptShardBundle(operations:for:)`** — standalone shard-protocol bundle.
  Always requires ML-KEM (throws `trusteeLacksQuantumMaterial` if absent).
  Never consumes prekeys, never carries a prekey sync batch. Accepts an array
  so all operations for one contact travel in a single bundle (e.g., one
  `.acknowledge` per received `.distribute`; all `.distribute` ops for a trustee).

- **`encryptBundle(data:for:shardOperations:)`** — regular message bundle with
  optional piggybacked shard operations. Enforces ML-KEM when `shardOperations`
  contains any `.handback` op — the ML-KEM gate applies regardless of call site.
  Consumes prekeys and carries prekey sync batches as normal.

Both call the shared private `resolveKeyMaterial(for:requireQuantum:)` helper
so the key-lookup and quantum-decode logic is defined exactly once.

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

Each shard is delivered to a trustee as a `.occ` bundle using `longTermFallback`
mode. The delivery envelope (inside `SealedPayload.shardOperations`) carries:

```
newShard:    SignedAttribute   // the shard to store
replacesID:  UUID?             // ID of an older shard this supersedes (nil on first distribution)
```

`replacesID` allows the recipient's app to automatically discard the old shard
when the owner re-distributes after a content change. The old shard reconstructs
a key that no longer encrypts anything (the PEK was rotated), so it is harmless
— but automatic cleanup prevents accumulation of stale shards.

Trustees running an older build that does not process `replacesID` will retain
the superseded shard indefinitely. This is safe: the old shard's reconstruction
attempt produces the old PEK, which fails GCM authentication against the
rotated entry. No plaintext is exposed and no action is required.

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

| From        | To           | Trigger                                      |
|-------------|--------------|----------------------------------------------|
| `.sent`     | `.confirmed` | Trustee sends `.acknowledge`                 |
| `.sent`     | `.lost`      | Trustee sends `.notFound`; trustee key change |
| `.confirmed`| `.lost`      | Trustee becomes unreachable after confirmation |
| any         | `.revoked`   | Owner explicitly revokes the shard           |

Invalid / rejected transitions:

- `.lost → .confirmed` — a lost shard cannot be un-lost by a late acknowledgement.
- `.revoked → any` — revocation is terminal; the shard must be re-distributed as a new record with a new `attrID`.

The transition `.confirmed → .lost` is valid because a trustee may lose their device after having previously acknowledged custody.

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

`.revoke` carries only the `attrID` — it is globally unique so no `entryID` is
needed. Bob's inbound handler deletes the matching `CustodyShard` row immediately.

**What triggers revocation:**
- Owner removes a trustee from the trustee list (user action).
- Re-distribution of an entry: new shards supersede old ones; Alice sends
  `.revoke` for each old `attrID` alongside or after the new `.distribute`.

**Alice's side:** when Alice generates a `.revoke` bundle, she marks the
corresponding `ShardRecord.status` to `.revoked` before (or atomically with)
sending. `.revoked` is a terminal state — the shard must be re-distributed as
a new record with a new `attrID` to restore coverage.

**Threshold erosion:** when `.lost` or `.revoked` records reduce the active
shard count below `threshold`, the entry detail view shows an inline warning
prompting redistribution. Active = `sent` + `confirmed` shards only.

---

## PEK rotation (content change)

When an entry's content changes (if editing is ever supported):
1. Generate a new PEK.
2. Re-encrypt label and content with the new PEK.
3. Seal new PEK under vault key → update `encryptedEntryKey`.
4. Run a fresh SSS split on the new PEK.
5. Deliver new shards with `replacesID` set to each trustee's current attrID.
6. Trustees' apps automatically discard the old shard on receipt.

Old shards are cryptographically inert after rotation — they reconstruct the
old PEK which no longer encrypts anything.

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

A single `SealedPayload` may carry `[ShardOperation]?` — a list rather than a
single operation. All operations in the list are processed in the order below.
This allows multiple shards (e.g. from several vault entries) to be returned in
one bundle without multiple round trips.

When a bundle carrying one or more `ShardOperation`s arrives:

1. **Revocations** (`.revoke`) — delete `CustodyShard` immediately; no further action.
2. **Distributions** (`.distribute`) — store new `CustodyShard`; if `replacesID != nil`,
   delete the old shard with that id.
3. **Handbacks** (`.handback`) — hand shard bytes to the reconstruction flow; queue a
   `PendingReturnAcknowledge` record so Alice confirms receipt in her next outbound bundle.
4. **Return acknowledgements** (`.returnAcknowledged`) — trustee receives confirmation
   that owner stored the returned shards; delete matching `CustodyShard` rows and the
   `PendingShardReturn` record for those `attrID`s.
5. **Acknowledgments** (`.acknowledge`) — update `ShardRecord.status` to `.confirmed`.
6. **Not-found** (`.notFound`) — mark `ShardRecord.status` as `.lost`.

Processing is crash-safe: `PendingShardReturn` rows are retained until the owner
confirms receipt via `.returnAcknowledged`. Undelivered returns are retried on the
next outbound bundle to the owner.

---

## Trustee key rotation = implicit shard loss

When a trustee (Bob) re-exchanges keys with Alice, Bob's identity key fingerprint
has changed. Since Occulta has no in-app identity key rotation, this can only mean
Bob is on a new device. A new device is a clean app install: Bob's SwiftData store
is empty, so his `CustodyShard` rows no longer exist.

Alice detects the fingerprint change and marks that shard's `ShardRecord.status` as
`.lost` — no explicit "I lost my shard" message type is needed.

Note: `Contact.Profile.identifier` is a stable SwiftData UUID created on init and
does not change across key re-exchanges. Alice's `ShardDistributionMetadata` remains
valid after Bob re-exchanges — only the shard itself is gone, not the routing metadata.

---

## Owner key rotation = auto-return trigger

When Alice re-exchanges keys with Bob (Alice got a new device), Bob detects that
Alice's key fingerprint differs from the previously stored one. This is an unambiguous
signal that Alice lost her device and vault — key exchange is proximity-only, so a
changed fingerprint cannot be injected remotely.

Bob's app responds automatically:

1. **Trigger** — on key exchange completion, compare the incoming fingerprint against
   the stored one. If they differ, look up all `CustodyShard` rows where
   `ownerContactIdentifier` matches Alice's contact identifier.
2. **Schedule** — upsert one `PendingShardReturn` row per matching contact (not per
   shard — the pending record covers all shards for that contact). If a row for
   this contact already exists (Alice re-exchanged again before delivery), update
   `scheduledAt` rather than inserting a second row. Encrypted at rest under the
   shard custody key: `Payload { contactIdentifier, scheduledAt }`, AAD = id-only.
3. **Deliver** — before any outbound bundle is sent to Alice, check for a
   `PendingShardReturn` for her. If found, generate `.handback` operations for **all**
   matching `CustodyShard` rows and include them in `SealedPayload.shardOperations`.
   All shards for the contact travel in the same bundle — partial returns are not
   allowed. `ContactManager.encryptBundle` enforces ML-KEM when `shardOperations`
   contains `.handback` ops: if Alice's new key lacks quantum material the call
   throws `trusteeLacksQuantumMaterial` (cannot happen in practice — UWB exchange
   always produces quantum material — but the gate is explicit in code).
4. **Confirm** — Alice receives the `.handback` operations, stores each in
   `ReconstructShard`, and queues a `PendingReturnAcknowledge` record: `Payload
   { contactIdentifier, attrIDs: [UUID] }`, sealed under the recovery buffer key,
   AAD = id-only. In her next outbound bundle to Bob, she includes a
   `.returnAcknowledged` operation carrying those `attrID`s. `PendingReturnAcknowledge`
   is deleted on send (not on Bob's confirmation). If Bob never receives it and
   resends, Alice re-inserts the shards idempotently — re-reconstruction produces
   the same PEK and re-wrapping is safe. The retry cycle terminates when Bob
   receives one acknowledgement and deletes his custody rows.
5. **Cleanup** — Bob receives `.returnAcknowledged`, matches the `attrID`s against
   his `CustodyShard` rows, deletes the confirmed rows, and deletes the
   `PendingShardReturn` record. Bob never deletes a shard until he has explicit
   confirmation that Alice stored it.

### Why delivery is deferred to the next message

Injecting the shard return into the key exchange handshake would couple two distinct
operations and complicate failure handling. Alice may not have her vault initialised
at the moment of exchange (she just got her new device). Deferral gives Alice time to
set up, and uses the existing outbound bundle pipeline without modification to the
exchange protocol.

### Badge for pending shard returns

When Bob has `PendingShardReturn` rows awaiting delivery, the UI surfaces a badge
to alert him that shards are queued for auto-return. Implementation deferred —
data model planned, view not yet built.

### Key notes

- `PendingShardReturn` is deleted only after `.returnAcknowledged` is received,
  not on send. If Alice's app never acknowledges (crash, new device again), Bob
  retries on his next outbound bundle to Alice.
- If Bob holds shards for Alice across multiple vault entries, all are returned in
  a single bundle (one `.handback` operation per shard, all in `shardOperations`).
- The returned `SignedAttribute`s were signed with Alice's old SE key. Verification
  fails on Alice's new device by design — GCM authentication on reconstruction is
  the integrity check (see "Signature verification after device loss").

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
| ownerContactIdentifier in CustodyShard.Payload | ✅ Done |
| [ShardOperation]? on SealedPayload (multi-shard bundles) | ✅ Done |
| .returnAcknowledged ShardOperation kind | ✅ Done |
| attrIDs: [UUID] on ShardOperation (acknowledge payload) | ✅ Done |
| PendingShardReturn SwiftData model    | ✅ Done |
| PendingReturnAcknowledge SwiftData model | ✅ Done |
| Key-change detection in exchange flow | ✅ Done |
| Auto-return trigger + delivery hook   | ✅ Done |
| Return acknowledge send + cleanup     | ✅ Done |
| PEK rotation on content change        | ❌ Not started |
| Inbox / Requests tab (+ badge)        | ❌ Not started |
| Feature flag (hidden until done)      | ✅ Done        |

---

## Inbox / Requests tab (not started)

A unified inbox for all actionable inbound items. Currently two kinds exist:
pending shard returns (for trustees) and identity verification challenges.
Designed to be extensible (document signing, key rotation, etc.).

### Why a tab, not auto-presented sheets

SwiftUI presents only one sheet at a time from the root `WindowGroup`. If the
user has any sheet open (reading a message, share sheet, etc.) and an identity
challenge arrives, the new sheet silently fails to appear. This is a real
existing bug for identity challenges — the `incomingChallenge` binding gets set
but nothing shows. The inbox tab fixes this: items persist regardless of what
UI state the app is in when they arrive.

### Design decisions

- **Pending shard returns**: Bob sees a badge when `PendingShardReturn` rows
  exist (shards queued for auto-return to an owner who got a new device). Bob
  does not act manually — delivery is automatic on the next outbound bundle.
  The badge is informational only.
- **Identity challenges**: currently auto-present a sheet. Should also route
  to the inbox as a persistent fallback. If the app is idle, auto-present the
  sheet (preserving current behaviour). If any sheet is active, badge the tab.
- **Identity challenge persistence**: challenges are currently ephemeral —
  `OutstandingChallengeStore` holds some state but there is no SwiftData record.
  A `PendingIdentityChallenge` SwiftData model is needed to support the inbox.
- **No past history for now**: the inbox shows only actionable items. A future
  logs screen can surface completed returns and past challenges.
- **Urgency sorting**: identity challenges should rank above shard returns —
  the challenger is actively waiting. Sort by kind first, then `receivedAt`.
- **Tab visibility**: show the tab only when the badge count is > 0, or always
  show it. Decision deferred — depends on how often items arrive in practice.

### Not needed
- Cryptographic shard revocation — old shards become inert automatically when
  the PEK rotates. `replacesID` in the delivery envelope handles cleanup.
- Recipient-side threshold enforcement — Lagrange interpolation with fewer than
  k shares produces a random value with no relation to the secret. The GCM
  authentication tag on decryption is the practical enforcement.

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
- **GF(2⁸) arithmetic timing:** `gfMul` and `gfInv` contain data-dependent
  branches. On Apple Silicon this is acceptable for SSS (not key derivation),
  but the implementation is not formally constant-time.

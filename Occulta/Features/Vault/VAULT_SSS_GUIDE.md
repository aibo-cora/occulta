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

ML-KEM-768 in the hybrid session key is the only defense against HNDL.
Requiring it for trustees makes the gate explicit and enforced in code.

All contacts exchanged via UWB already have ML-KEM material — the key exchange
flow always generates it. Contacts added via Bluetooth-only exchange do not.

---

## Shard delivery session key

Shard bundles always use **`longTermFallback` + ML-KEM**. Prekeys are never
consumed for shard traffic.

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
mode. The delivery envelope (inside `SealedPayload.shardOperation`) carries:

```
newShard:    SignedAttribute   // the shard to store
replacesID:  UUID?             // ID of an older shard this supersedes (nil on first distribution)
```

`replacesID` allows the recipient's app to automatically discard the old shard
when the owner re-distributes after a content change. The old shard reconstructs
a key that no longer encrypts anything (the PEK was rotated), so it is harmless
— but automatic cleanup prevents accumulation of stale shards.

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

1. Alice requests her shards back from trustees via `.occ` (or out-of-band).
2. Each trustee sends their `SignedAttribute` back via `.occ`.
3. Alice's app collects ≥ k shards.
4. If Alice still has her original SE key: verify each shard's signature.
   If on a new device: skip signature verification, rely on GCM authentication.
5. Run `ShamirSecretSharing.reconstruct(shares:)` → 32-byte PEK.
6. Attempt `AES.GCM.open(encryptedContent, using: PEK, authenticating: aad())`.
   - Success: GCM authentication confirms shard integrity. Re-wrap PEK under
     current vault key and save as new `encryptedEntryKey`.
   - Failure: one or more shards are corrupt or from the wrong distribution.
     Surface error; do not persist.
7. Zero the reconstructed PEK bytes immediately after re-wrapping.

---

## Reconstruction buffer (`ReconstructShard`)

Owner-side transient queue for `.respond` bundles arriving during recovery. Each
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
| `.respond` arrives, vault locked | Insert row. Finalisation deferred to next vault unlock.     |
| `.respond` arrives, vault unlocked | Insert row, then opportunistic `tryFinalizeReconstruction`. |
| Vault unlock                     | Sweep all entries with `shardDistributionEncrypted` and finalise any that crossed threshold while locked. |
| Reconstruction succeeds          | Bulk-delete all rows whose payload references that `entryID`. |
| User cancels recovery            | Bulk-delete by `entryID` (decrypt-and-filter).              |

Multiple recoveries coexist trivially because rows are filtered by the sealed
`entryID` field at decrypt time — no new types needed for parallel recoveries.

### Why custody-key-class access (no biometric)

`.respond` bundles can arrive while the vault is locked. The recovery buffer
key is derived from the custody SE key (device-unlock, no biometric) so the
buffer can absorb shards without prompting. Reconstruction itself still requires
the vault unlocked — re-wrapping the recovered PEK under the vault key needs
the vault SE key.

### Privacy at rest

| | Without ReconstructShard | With ReconstructShard |
|---|---|---|
| Cold-disk forensics | (can't recover at all from process kill) | "Alice has N rows in the reconstruct buffer." Nothing about which entries, how many shards each, or who sent them. |

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

Derivation: `ECDH(shardCustodySEKey, G) → HKDF-SHA256(salt: custodyPubKey, info: <info>)`

---

## Contact identifier for shards

`ShardRecord.contactIdentifier` is a `String` holding the contact's identifier from
`Contact.Profile`. A future migration to `Data` (SHA-256 of the contact's public key)
is planned for the ShardCustodyManager phase, which will have direct access to the
contact's key record.

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
3. **Requests** (`.request`) — write `PendingShardRequest`; deduplicate by `attrID`
   (update `receivedAt` only on duplicates); process automatically if device is unlocked.
4. **Responses** (`.respond`) — hand shard bytes to the reconstruction flow; queue a
   `PendingReturnAcknowledge` record so Alice confirms receipt in her next outbound bundle.
5. **Return acknowledgements** (`.returnAcknowledged`) — trustee receives confirmation
   that owner stored the returned shards; delete matching `CustodyShard` rows and the
   `PendingShardReturn` record for those `attrID`s.
6. **Acknowledgments** (`.acknowledge`) — update `ShardRecord.status` to `.confirmed`.
7. **Not-found** (`.notFound`) — mark `ShardRecord.status` as `.lost`.

Processing is crash-safe: `PendingShardRequest.processed` stays `false` until the
response bundle has been successfully queued. Unprocessed records are retried on next
app launch.

---

## Trustee key rotation = implicit shard loss

When a trustee (Bob) re-exchanges keys with Alice, Bob's old public key is replaced.
Any shard Alice distributed to Bob was encrypted to Bob's old session key — Bob's new
SE key cannot derive the same session key, so Bob can no longer decrypt the bundle.
Alice marks that shard's `ShardRecord.status` as `.lost` immediately on detecting
Bob's key change — no explicit "I lost my shard" message type is needed.

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
2. **Schedule** — insert one `PendingShardReturn` row per matching contact (not per
   shard — the pending record covers all shards for that contact). Encrypted at rest
   under the shard custody key: `Payload { contactIdentifier, scheduledAt }`,
   AAD = id-only.
3. **Deliver** — before any outbound bundle is sent to Alice, check for a
   `PendingShardReturn` for her. If found, generate `.respond` operations for all
   matching `CustodyShard` rows and include them in `SealedPayload.shardOperations`.
   The bundle is encrypted to Alice's new identity key using the standard
   `longTermFallback + ML-KEM` mode (the new key was stored during the exchange).
4. **Confirm** — Alice receives the `.respond` operations, stores each in
   `ReconstructShard`, and queues a `PendingReturnAcknowledge` record: `Payload
   { contactIdentifier, attrIDs: [UUID] }`, sealed under the recovery buffer key,
   AAD = id-only. In her next outbound bundle to Bob, she includes a
   `.returnAcknowledged` operation carrying those `attrID`s.
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

### Badge for pending shard requests

When Bob has `PendingShardRequest` rows awaiting his response, the UI surfaces a
badge on the relevant section. Implementation deferred — data is already written,
only the view is missing.

### Key notes

- `PendingShardReturn` is deleted only after `.returnAcknowledged` is received,
  not on send. If Alice's app never acknowledges (crash, new device again), Bob
  retries on his next outbound bundle to Alice.
- If Bob holds shards for Alice across multiple vault entries, all are returned in
  a single bundle (one `.respond` operation per shard, all in `shardOperations`).
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
| PendingShardRequest SwiftData model   | ✅ Done        |
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
| Shard request / return flow           | ✅ Done        |
| Reconstruction flow                   | ✅ Done        |
| Reconstruction buffer + finalise on unlock | ✅ Done   |
| New-device recovery (no SE key)       | ✅ Done        |
| ownerContactIdentifier in CustodyShard.Payload | ❌ Not started |
| [ShardOperation]? on SealedPayload (multi-shard bundles) | ❌ Not started |
| .returnAcknowledged ShardOperation kind | ❌ Not started |
| attrIDs: [UUID] on ShardOperation (acknowledge payload) | ❌ Not started |
| PendingShardReturn SwiftData model    | ❌ Not started |
| PendingReturnAcknowledge SwiftData model | ❌ Not started |
| Key-change detection in exchange flow | ❌ Not started |
| Auto-return trigger + delivery hook   | ❌ Not started |
| Return acknowledge send + cleanup     | ❌ Not started |
| PEK rotation on content change        | ❌ Not started |
| Inbox / Requests tab (+ badge)        | ❌ Not started |
| Feature flag (hidden until done)      | ✅ Done        |

---

## Inbox / Requests tab (not started)

A unified inbox for all actionable inbound items. Currently two kinds exist:
shard requests and identity verification challenges. Designed to be extensible
(document signing, key rotation, etc.).

### Why a tab, not auto-presented sheets

SwiftUI presents only one sheet at a time from the root `WindowGroup`. If the
user has any sheet open (reading a message, share sheet, etc.) and an identity
challenge or shard request arrives, the new sheet silently fails to appear. This
is a real existing bug for identity challenges — the `incomingChallenge` binding
gets set but nothing shows. The inbox tab fixes this: items persist regardless
of what UI state the app is in when they arrive.

### Design decisions

- **Shard requests**: always go to inbox queue (`PendingShardRequest`). Never
  auto-presented. Bob sees a badge on the tab, responds when ready.
- **Identity challenges**: currently auto-present a sheet. Should also route
  to the inbox as a persistent fallback. If the app is idle, auto-present the
  sheet (preserving current behaviour). If any sheet is active, badge the tab.
- **Identity challenge persistence**: challenges are currently ephemeral —
  `OutstandingChallengeStore` holds some state but there is no SwiftData record.
  A `PendingIdentityChallenge` SwiftData model is needed to support the inbox.
- **No past history for now**: the inbox shows only actionable (`.pending`)
  items. A future logs screen can query terminal-state records
  (`PendingShardRequest.status` in `.sent / .declined / .notFound`). The data
  is already being written; only the view is missing.
- **Urgency sorting**: identity challenges should rank above shard requests —
  the challenger is actively waiting. Sort by kind first, then `receivedAt`.
- **Tab visibility**: show the tab only when the badge count is > 0, or always
  show it. Decision deferred — depends on how often requests arrive in practice.

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
  every shard bundle uses a session key that requires breaking ML-KEM-768 in
  addition to P-256 to decrypt. As of 2026 no known classical or quantum attack
  achieves this within the security parameter.
- **GF(2⁸) arithmetic timing:** `gfMul` and `gfInv` contain data-dependent
  branches. On Apple Silicon this is acceptable for SSS (not key derivation),
  but the implementation is not formally constant-time.

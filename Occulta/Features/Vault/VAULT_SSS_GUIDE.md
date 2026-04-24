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
- Distribute shards via .occ to trustees.
- Recovery: collect ≥ k shards, reconstruct PEK, decrypt entry.

**Current state:** The PEK layer does not yet exist. All entries currently
share the vault key directly. Implementing per-entry keys is the first
prerequisite for per-entry SSS.

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

## Shard delivery envelope

Each shard is delivered to a trustee as a `.occ` bundle, encrypted to the
trustee's verified public key. The delivery envelope carries:

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

When Bob receives a shard from Alice, he stores:
- The `SignedAttribute` (shard bytes + Alice's signature + attrID).
- Alice's contact identifier (so he knows whose shard it is).
- Nothing else. Bob does not need: the entry label, the threshold, or how many
  other trustees Alice chose.

The `attrID` is sufficient to match an incoming `replacesID` from Alice.

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

## Shard custody key

Shard operations require a dedicated third SE key — separate from the identity key
and the vault key.

**Tag:** `"shard.custody.occulta"`  
**Access:** `kSecAttrAccessibleWhenUnlockedThisDeviceOnly + .privateKeyUsage`  
**No biometric flag** — device-unlock level only.

Why no biometric? Shard requests arrive in inbound bundles, processed automatically
on receipt. If the shard custody key required Face ID per operation, Bob would need to
open the app and interact each time a contact requests a shard back. Full automation
(zero UI involvement for Bob) is the design goal.

Derivation: `ECDH(shardCustodySEKey, G) → HKDF-SHA256(salt: custodyPubKey, info: kShardCustodyKeyInfo)`  
Info string: `"Occulta-v1-shard-custody-2026"`

Used to encrypt `HeldShard.encryptedAttribute` (a JSONEncoder(SignedAttribute) blob).

---

## Contact identifier for shards

`ShardRecord.contactIdentifier` is a `String` holding the contact's identifier from
`Contact.Profile`. A future migration to `Data` (SHA-256 of the contact's public key)
is planned for the ShardCustodyManager phase, which will have direct access to the
contact's key record.

`HeldShard.ownerKeyFingerprint` is already `Data` (SHA-256 of the owner's public key)
— the shard-receiving side has the owner's public key from the signed attribute itself.

---

## Inbound bundle processing order

When a bundle carrying a `ShardOperation` arrives:

1. **Revocations** (`.revoke`) — delete `HeldShard` immediately; no further action.
2. **Distributions** (`.distribute`) — store new `HeldShard`; if `replacesID != nil`,
   delete the old shard with that id.
3. **Requests** (`.request`) — write `PendingShardRequest`; deduplicate by `attrID`
   (update `receivedAt` only on duplicates); process automatically if device is unlocked.
4. **Responses** (`.respond`) — hand shard bytes to the reconstruction flow.
5. **Acknowledgments** (`.acknowledge`) — update `ShardRecord.status` to `.confirmed`.
6. **Not-found** (`.notFound`) — mark `ShardRecord.status` as `.lost`.

Processing is crash-safe: `PendingShardRequest.processed` stays `false` until the
response bundle has been successfully queued. Unprocessed records are retried on next
app launch.

---

## Contact key rotation = implicit shard loss

When a contact re-exchanges keys with Alice, their old public key is replaced. Any
shard Bob stored was sealed under Alice's old PEK and signed with her old identity key.
Alice treats the old shards as `.lost` immediately on key rotation — no explicit
"I lost my shard" message type is needed.

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
| HeldShard SwiftData model             | ✅ Done        |
| PendingShardRequest SwiftData model   | ✅ Done        |
| Shard custody SE key                  | ✅ Done        |
| ShardOperation in SealedPayload       | ✅ Done        |
| Schema registration (App)             | ✅ Done        |
| Per-entry encryption keys (PEK)       | ✅ Done        |
| VaultEntry model update (PEK fields)  | ✅ Done        |
| VaultManager PEK unwrap path          | ✅ Done        |
| ShardCustodyManager (inbound router)  | ❌ Not started |
| .occ delivery pipeline                | ❌ Not started |
| Shard request / return flow           | ❌ Not started |
| Reconstruction flow                   | ✅ Done        |
| New-device recovery (no SE key)       | ✅ Done        |
| PEK rotation on content change        | ❌ Not started |
| "Shards held for contacts" UI         | ❌ Not started |
| Feature flag (hidden until done)      | ❌ Not started |

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
- **GF(2⁸) arithmetic timing:** `gfMul` and `gfInv` contain data-dependent
  branches. On Apple Silicon this is acceptable for SSS (not key derivation),
  but the implementation is not formally constant-time.

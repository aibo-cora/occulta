# Group Messaging — Specification

**Status:** Design complete, pending implementation  
**Target release:** v1.9.0  
**Related:** `Docs/Features/Bundle/SPEC.md`, `Docs/Features/Crypto/bundle.md`

---

## Overview

Send one encrypted bundle to multiple contacts. A random session key encrypts a single shared ciphertext; the session key is then wrapped once per recipient using their stored ECDH + ML-KEM material. Delivered out-of-band (SMS, WhatsApp, Signal, email, etc.).

No message persistence in this release. Groups are a local construct — a named list of contacts used to build the recipient set at send time.

---

## Wire Format — OccultaBundle Changes

### New Mode case

```swift
case group
```

One case only. No PQ variant — PQ is applied silently when ML-KEM material is on file for the contact, classical otherwise. Old builds decode `.group` as `.unsupported` → `BundleError.unsupportedMode` → "requires a newer version of Occulta."

### OccultaBundle (top level)

```
OccultaBundle
├── version                     // unchanged
├── secrecy
│   ├── mode = .group           // NEW
│   ├── ephemeralPublicKey      // Data() — empty; per-recipient ephemeral lives in Recipient
│   └── prekeyID               // nil
├── ciphertext                  // AES-GCM(SealedPayload, sessionKey)
├── fingerprintNonce            // unchanged — sender routing
├── senderFingerprint           // unchanged — sender routing
└── group: GroupEnvelope?       // NEW — nil for all existing single-recipient bundles
```

### GroupEnvelope

```
GroupEnvelope
├── id: UUID                    // stable group identifier — cleartext, included in AAD
└── recipients: [Recipient]     // one entry per visible contact at send time
```

### Recipient

```
Recipient
├── fingerprint: Data           // SHA-256(recipientPubKey || fingerprintNonce)
├── fingerprintNonce: Data      // 16 random bytes
├── secrecyContext: SecrecyContext   // per-recipient ephemeral pub key + prekey ID
└── wrappedKey: Data            // AES-GCM(sessionKey.rawRepresentation, wrappingKey)
```

> **No quantum material in Recipient.** The ML-KEM shared secret is established during proximity key exchange and stored on the contact record. The sender retrieves it at wrap time — nothing extra travels on the wire.

### SealedPayload

Unchanged. No group name or metadata added. The receiver learns the message content after decryption; no additional group context is needed in the payload.

### Additional Authenticated Data (AAD)

```
version.rawValue || JSON(secrecy) || groupID.uuidString
```

The group UUID is appended to the standard AAD, binding the ciphertext to the specific group and preventing cross-group replay.

---

## Crypto Flows

### Encrypt

1. Generate random 256-bit `sessionKey`
2. Encode `SealedPayload` (message, prekey batch if needed)
3. `AES.GCM.seal(payload, using: sessionKey, authenticating: aad)` → `ciphertext`
4. For each **visible** contact:
   - Generate ephemeral P-256 keypair
   - Derive `wrappingKey` via ECDH + ML-KEM (same derivation path as today, PQ when available)
   - `AES.GCM.seal(sessionKey.rawRepresentation, using: wrappingKey)` → `wrappedKey`
   - Assemble `Recipient`
5. Assemble `GroupEnvelope`, attach to bundle, serialize

### Decrypt

1. Decode bundle — `group != nil` → take group path
2. Find `Recipient` where `fingerprint` matches own public key
3. Derive `wrappingKey` via ECDH + ML-KEM using `secrecyContext` — prekey consumed from SE on success
4. Decrypt `wrappedKey` → `sessionKey`
5. Verify AAD (`version + secrecy + groupID`), decrypt `ciphertext` → `SealedPayload`

---

## Version Gating

A contact can only be added to a group if their known app version is ≥ `1.9.0`. This is derived from the `appVersion` field already present in every received `SealedPayload` and stored as `maxBundleVersion` on the contact record.

`Version.max(forAppVersion:)` is extended with a group-capable watermark at `1.9.0`. Contacts with `maxBundleVersion >= groupCapable` are eligible for group membership.

> A contact who has never sent a bundle has no known app version and cannot be added to a group. The version is proven by receipt, not self-reported at add time.

**Runtime gate:** old builds receiving a group bundle decode `mode` as `.unsupported` → `BundleError.unsupportedMode` → "requires a newer version of Occulta." No silent failure, no data loss.

---

## SwiftData — Group Entity

```swift
@Model Group
├── encryptedID: Data?           // UUID, encrypted — prevents correlation with wire bundle
├── encryptedName: Data?         // display name
├── encryptedMemberIDs: Data?    // [String] of contact identifiers, serialized + encrypted
└── encryptedCreatedAt: Data?
```

All fields encrypted under the local DB key. SwiftData's `persistentModelID` is the only plaintext identifier and reveals nothing about the group.

**Members as a single encrypted blob, not as individual rows.** A separate member table would leak member count to a forensic examiner even with values encrypted. The blob reveals count only after decryption with the local DB key.

**Deletion:** hard delete only. No `deletionToken`, no tombstone. A deleted group leaves no recoverable trace.

---

## Secure Mode — Depth Filtering

Groups have no `visibleThroughDepth` field. Filtering is applied to **members** at two points:

- **View time** — decrypt member blob, filter by each contact's `visibleThroughDepth` vs current depth, display only visible members. A coercer viewing group membership sees only depth-appropriate contacts.
- **Send time** — same filter applied when building `Recipient` slots. Hidden contacts receive no slot and no bundle.

The stored member blob always contains the full list. Filtering is in-memory and stateless. No filtered subset is ever persisted.

> **UI must surface the filtered recipient list before the user sends.** No silent omissions — if 1 of 3 members is hidden at the current depth, the send screen shows "2 recipients" explicitly.

---

## Forensic Trace Properties

- N group records visible in SwiftData store — same accepted tradeoff as contacts (count without content)
- No plaintext fields on any group record
- No member row count leak — single encrypted blob per group
- Group UUID stored encrypted — cannot be correlated with a cleartext `GroupEnvelope.id` in an intercepted bundle without decrypting the local store
- Hard deletion — no soft-delete residue
- Bundle leaks recipient slot count (N) to anyone holding the bundle — accepted, per design choice of one shared bundle

---

## Out of Scope (v1.9.0)

- Message persistence / conversation threading
- Group admin roles
- Member notifications ("you were added to a group")
- Key ratcheting on member removal — not needed; each bundle uses a fresh random session key

# Group Messaging — Specification

**Status:** Design complete, pending implementation  
**Target release:** v1.9.0  
**Related:** `Docs/Features/Bundle/SPEC.md`, `Docs/Features/Crypto/bundle.md`  
**Findings:** `Docs/Features/Group Messaging/FINDINGS.md`

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
│   ├── mode = .group           // NEW — signals group bundle; per-recipient path in Recipient.secrecyContext
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
├── id: UUID                    // stable group identifier — cleartext, included in outer AAD
└── recipients: [Recipient]     // one entry per member in the active layer at send time
```

### Recipient

```
Recipient
├── fingerprint: Data           // SHA-256(recipientPubKey || fingerprintNonce)
├── fingerprintNonce: Data      // 16 random bytes
├── secrecyContext: SecrecyContext   // per-recipient key-exchange fields
│   ├── mode                   // .forwardSecret (prekey path) or .longTermFallback (exhausted)
│   ├── ephemeralPublicKey     // sender's ephemeral P-256 public key for this recipient
│   └── prekeyID              // UUID of consumed prekey, or nil on longTermFallback path
└── wrappedPayload: Data        // AES-GCM(RecipientPayload, wrappingKey, AAD: groupID || fingerprint)
```

```
RecipientPayload
├── sessionKey: Data            // 32 bytes — decrypts the shared ciphertext
└── prekeyBatch: PrekeySyncBatch?  // sender's fresh prekeys for this recipient, or nil
```

> **No quantum material in Recipient.** The ML-KEM shared secret is established during proximity key exchange and stored on the contact record. The sender retrieves it at wrap time — nothing extra travels on the wire.

> **`Recipient.secrecyContext.mode`** signals the key-derivation path for unwrapping. The receiver reads this per-recipient, not the outer `bundle.secrecy.mode`. This reuses the existing `SecrecyContext` type — no new fields required.

### SealedPayload

Unchanged structurally. For group bundles, `SealedPayload.prekeyBatch` is always `nil` — prekey replenishment moves to `RecipientPayload` inside each `Recipient.wrappedPayload`.

**Prekey replenishment in group bundles is per-recipient.** Each recipient's `wrappedPayload` carries both the session key and their own prekey batch (when the sender's stock for that contact is below the replenishment threshold or the long-term fallback path is used). The shared `SealedPayload` carries no prekey data. Only the intended recipient can derive the wrapping key, so the prekey batch is as isolated as it was in the single-recipient path.

### Additional Authenticated Data

**Outer ciphertext AAD:**
```
version.rawValue || JSON(secrecy) || groupID.uuidString
```
Binds the shared ciphertext to this specific group. Prevents cross-group replay.

**Per-recipient `wrappedPayload` AAD:**
```
groupID.uuidString || recipientFingerprint
```
Binds both the session key and the prekey batch to this group and this specific recipient. Prevents a compromised wrapping key from being used to substitute a chosen session key for a different recipient or group.

---

## Crypto Flows

### Encrypt

1. Generate random 256-bit `sessionKey`
2. Encode `SealedPayload` (message only — `prekeyBatch = nil`)
3. `AES.GCM.seal(payload, using: sessionKey, authenticating: outerAAD)` → `ciphertext`
4. For each member in the active layer:
   - Compute `fingerprintNonce = SecrecyContext.generateNonce()`
   - Compute `fingerprint = SHA-256(recipientPubKey || fingerprintNonce)`
   - If prekey available:
     - Generate ephemeral P-256 keypair
     - Derive `wrappingKey` via ECDH + ML-KEM using contact prekey (prekey consumed)
     - Set `secrecyContext.mode = .forwardSecret`
   - If no prekey available:
     - Derive `wrappingKey` via long-term identity ECDH + ML-KEM
     - Set `secrecyContext.mode = .longTermFallback`, `ephemeralPublicKey = Data()`, `prekeyID = nil`
   - Build `RecipientPayload(sessionKey: sessionKey, prekeyBatch: batchIfNeeded(for: contact))`
   - `recipientAAD = groupID || fingerprint`
   - `AES.GCM.seal(RecipientPayload, using: wrappingKey, authenticating: recipientAAD)` → `wrappedPayload`
   - Assemble `Recipient`
5. Assemble `GroupEnvelope`, attach to bundle, serialize

`batchIfNeeded(for:)` follows the same threshold logic as single-recipient sends — include a fresh prekey batch when the contact's stored stock for this sender falls below the replenishment watermark, or when `secrecyContext.mode == .longTermFallback`.

### Decrypt

1. Decode bundle — `group != nil` → take group path
2. Find `Recipient` where `fingerprint` matches own public key
3. Read `Recipient.secrecyContext.mode`:
   - `.forwardSecret` → derive `wrappingKey` via ephemeral ECDH + ML-KEM using stored prekey (prekey consumed)
   - `.longTermFallback` → derive `wrappingKey` via long-term identity ECDH + ML-KEM
4. `recipientAAD = groupID || fingerprint`
5. Decrypt `wrappedPayload` authenticating `recipientAAD` → `RecipientPayload`
6. If `RecipientPayload.prekeyBatch != nil` → store batch for the sender
7. Decrypt `ciphertext` authenticating `outerAAD` using `RecipientPayload.sessionKey` → `SealedPayload`

---

## Version Gating

A contact can be added to a group only if their known app version is ≥ `1.9.0`.

**Implementation:** Add `encryptedAppVersion: Data?` to `Contact.Profile` (SwiftData lightweight migration — new optional column, no migration plan required). When a bundle is received, store the raw `appVersion` string from `SealedPayload` encrypted under the local DB key alongside the existing `maxBundleVersion`. Group eligibility evaluates:

```swift
storedAppVersion.compare("1.9.0", options: .numeric) != .orderedAscending
```

This decouples feature capability gating from wire format version tracking. `maxBundleVersion` continues to serve wire format selection only.

> A contact who has never sent a bundle has no stored app version and cannot be added to a group. The version is proven by receipt, not self-reported at add time. Ineligible contacts in the member picker are labeled **"Send them a message first"** — not silently grayed out.

**Runtime gate:** old builds receiving a group bundle decode `mode` as `.unsupported` → `BundleError.unsupportedMode` → "requires a newer version of Occulta."

---

## SwiftData — Group Entity

```swift
@Model Group
├── encryptedID: Data?           // UUID, encrypted — prevents correlation with wire bundle
├── encryptedName: Data?         // display name, readable at any depth (same local DB key)
├── realMemberSlots: [Data]      // always 32 entries — real layer members + random filler
├── duressMemberSlots: [Data]    // always 32 entries — duress layer members + random filler
└── encryptedCreatedAt: Data?    // second-precision TimeInterval — milliseconds truncated
```

All fields encrypted under the local DB key. SwiftData's `persistentModelID` is the only plaintext identifier and reveals nothing about the group.

### Two-array member model

Group membership uses two independent fixed-capacity arrays — one per layer — mirroring the `sealedNormalVerifiers` / `sealedDuressVerifiers` pattern in `AppLayerConfig`.

Each array always contains exactly 32 entries. Real member slots hold `AES-GCM(contactIdentifier)` — UUID strings are 36 bytes, producing a fixed 64-byte ciphertext. Unused slots hold 64 cryptographically random bytes, indistinguishable from real entries in size and appearance.

**Hard cap: 32 members per layer.** This is sufficient for personal, family, and small-team use cases within Occulta's threat model (proximity-exchanged contacts, out-of-band delivery). The fixed capacity directly determines the forensic footprint per group (2 × 32 × 64 bytes = 4 KB). The coincidence with `AppLayerConfig.maxVerifierCount` is incidental.

**Write behaviour:** on every add or remove, both arrays are fully recomputed with fresh nonces. A database diff between any two snapshots shows all 64 entries changed — no slot position, no modified entry, no touched array is identifiable.

**Routing:** `currentDepth == 0` → read/write `realMemberSlots`. `currentDepth > 0` → read/write `duressMemberSlots`. The coercer operates entirely within their own independent array and learns nothing about the real layer.

**Group names** are decryptable at any depth — the local DB key is shared across layers, same as contact names. This is accepted and consistent with existing behaviour.

**Deletion:** hard delete only. No `deletionToken`, no tombstone.

---

## Secure Mode — Depth Routing

Only contacts are filtered by depth via `visibleThroughDepth`. Groups are not filtered — depth selects which member array is active. All group names are visible at all depths.

- **View time** — decrypt the active layer's member slots, skip filler (failed decrypts), display real entries only.
- **Send time** — build `Recipient` slots from the active layer's member slots only.

The duress layer starts as pure filler. Having zero members in the duress layer — or no groups at all at depth > 0 — is indistinguishable from a user who does not use groups at that depth. No UX obligation to populate the duress layer. Duress group setup is the user's responsibility, consistent with the existing secure mode model for contacts and vault entries.

> **UI must surface the active-layer recipient count before the user sends.** No silent omissions.

---

## UI Notes

- **Compose style:** Quick mode only in v1.9.0. Thread mode is excluded from group detail — no `ComposeStyleToggle` shown.
- **Member picker — two sections:**
  - **Can receive group messages** — contacts with `encryptedAppVersion >= "1.9.0"`, tappable to add.
  - **Cannot receive group messages** — all others, non-interactive. Section header copy:
    - `encryptedAppVersion == nil`: "Version unknown — ask them to send you a message"
    - `encryptedAppVersion < "1.9.0"`: "Ask them to update Occulta"
    - If both sub-cases are present, use the broader label: "These contacts need a newer version of Occulta or haven't messaged you yet."
- **Send screen:** displays active-layer recipient count explicitly before the user shares the bundle.

---

## Forensic Trace Properties

- N group records visible in SwiftData store — same accepted tradeoff as contacts (count without content)
- No plaintext fields on any group record
- Two fixed-size arrays (32 × 64 bytes each) per group — member count in either layer is not derivable without the local DB key; real and duress arrays are forensically identical in size and structure
- Full recompute with fresh nonces on every write — no diff attack can identify which slot changed or which layer was modified
- A coercer at depth > 0 operates on `duressMemberSlots` only — no cross-array probe vector; filling 32 duress slots reveals only that the cap is 32, not how many real slots are occupied
- Group UUID stored encrypted — cannot be correlated with a cleartext `GroupEnvelope.id` in an intercepted bundle without the local DB key
- `encryptedCreatedAt` stored at second precision — millisecond correlation attacks not possible
- Hard deletion — no soft-delete residue
- **SQLite WAL:** prior array states persist in the WAL until the next checkpoint; all values are encrypted blobs. Pre-existing condition for all contact and config data — accepted. WAL checkpoint on app launch limits accumulation.
- **Bundle leaks recipient slot count (N)** to anyone holding the bundle — accepted, inherent to one-bundle design. Bundle size also independently indicates N (fixed per-recipient struct size) — same accepted tradeoff.
- **`groupID` is a stable cleartext traffic correlation vector** — an interceptor collecting multiple bundles can cluster them by group without decrypting. Accepted: the sender controls distribution via chosen transport; rotating group ID per send would break AAD binding.

---

## Known Limitations (v1.9.0)

- **No delivery confirmation.** The sender cannot know if any recipient imported and decrypted the bundle. Recipients on older builds receive the bundle but see "requires a newer version" — the sender is not informed.
- **Duress layer group setup requires user initiative.** No in-app prompting or setup flow. Future work: secure mode setup wizard.

---

## Out of Scope (v1.9.0)

- Message persistence / conversation threading
- Thread mode in group compose
- Group admin roles
- Member notifications ("you were added to a group")
- Key ratcheting on member removal — not needed; each bundle uses a fresh random session key
- Proactive prekey replenishment warnings
- Duress group setup guidance

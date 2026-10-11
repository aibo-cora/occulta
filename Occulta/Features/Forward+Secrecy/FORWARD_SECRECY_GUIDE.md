# Forward Secrecy Guide

Internal engineering reference for one-time prekeys: how they are stored, sent, used and deleted.
Commit this file alongside any PR that touches the forward secrecy implementation.

Describes prekey continuity stage 1 (`Docs/Features/Prekey Continuity/DESIGN.md` §8). The design doc holds the
decisions and their reasons; this guide holds how the code works. The flow diagram is `forward_secrecy_flow.md`.

---

## Where the code lives

| Type | File | Job |
|---|---|---|
| `PrekeyRecord` | `PrekeyRecord.swift` | The value: everything about prekeys between us and one contact. Data only. |
| `PrekeyRecordCodec` | `PrekeyRecordCodec.swift` | The fixed 16 KB format, and reading the JSON `ForwardSecrecy` stored before stage 1. Lossless. |
| `PrekeyBookkeeper` | `PrekeyBookkeeper.swift` | The rules: which key to seal to, which batch to accept, what a used key proves, when keys go, the size limits. Pure. |
| `PrekeySecretsManager` | `PrekeySecretsManager.swift` | The Enclave and keychain: generating keys, and the legacy keychain keys. |
| `ContactManager` + `SenderPrekeys` | `Services/Contact+Manager+Prekeys.swift` | The only reader and writer of a record: loads, calls the others, stores, saves, flushes the log. |
| `deriveOutboundKey` / `deriveInboundKey` | `Crypto+Manager+KeyDerivation.swift` | Session keys for both directions and both key kinds. |
| `findAndOpenRecipientSlot` | `Crypto+Manager+GroupDecrypt.swift` | Trial-opens group slots and consumes the prekey that opened one. |

`Contact.Profile` holds the sealed record and does nothing with it.

---

## The record

One `PrekeyRecord` per contact, sealed in `Contact.Profile.prekeyRecordEncrypted`:

```swift
struct PrekeyRecord {
    var ownBatches: [OwnBatch]          // ours, for the contact to seal to: id, createdAt, retiredAt, isPending,
                                        //   keys (16-byte id, Enclave blob; a public key only for a
                                        //   carried-over key without a blob, derived from the blob otherwise),
                                        //   lastResort (stage 2: kept with its batch, never removed by use)
    var inboundBatches: [InboundBatch]  // theirs, for us to seal to: id, keys (id, public key)
    var inboundLastResort: InboundKey?  // stage 2: their last-resort key, outliving their one-time keys
    var acceptedBatchIDs: [Data]        // IDs of their batches already accepted, the 8 most recent
    var latestInboundGeneratedAt: Date? // the date rule, for their batches that carry no ID
    var legacyKeys: LegacyKeys          // our keychain prekeys from before stage 1: none | inUse | retired(since:)
}
```

- **Fixed size (Bug 161).** The codec writes `[0x02][UInt32 length][binary plist][zeros]`, always 16 KB, so the
  sealed field's length says nothing about either side's activity.
- **Never nil.** Written empty when a contact is created (`save(contact:)`, `createContacts(from:)`), overwritten
  with the sealed empty record when it is deleted, and carried over for every existing row by
  `DatabaseMigration.migratePrekeyRecords`. A NULL would separate contacts who exchanged messages from those who
  didn't, with no key needed.
- **The old field** `forwardSecrecyEncrypted` is nil on every row after the migration and `private`. Only the
  migrations reach it, through `retiredForwardSecrecyEncrypted`.
- **An unreadable record** reads as empty with `legacyKeys = .inUse`. The keys held from that contact are lost
  until their next long-term message brings new ones.

---

## Two directions

- **Their keys** (`inboundBatches`): public keys the contact generated and sent us. We seal to them, oldest first.
- **Our keys** (`ownBatches`): we generated them; the contact seals to them. The private halves are Enclave keys.

---

## Our private keys

**Stage 1 keys are Enclave blobs in the record.** `PrekeySecretsManager.generateEnclaveKeys` creates
`SecureEnclave.P256.KeyAgreement.PrivateKey`s (`privateKeyUsage`, `WhenUnlockedThisDeviceOnly`). CryptoKit makes no
keychain item: the wrapped `dataRepresentation` (143 bytes) in the record is the only copy. Deleting it from the
record deletes the key. The blob is useless off this device's Enclave.

**Legacy keys stay in the keychain.** Prekeys made before stage 1 are keychain Enclave keys tagged
`"prekey.<contactID>.<uuid>"`. The keychain never returns an Enclave key's wrapped blob, so they can't move into
the record. The record doesn't list them; `legacyKeys` says whether any may still be in use. They are deleted by
tag prefix once due (see the sweep).

**Lookup order** (`SenderPrekeys.privateKey`): the record's blob for that prekey ID, else the keychain. Both kinds
come back as `PrekeyPrivateKey` (`.enclave` or `.keychain`) and derive through the same function, so a sender
can't tell which one it sealed to.

---

## Key derivation

`Manager.Key.forwardSecretSessionKey(ecdhOutput:ownPublicKey:peerMaterial:quantumMaterial:)`:

```
ikm  = ECDH(ourPrivate, theirPublic)  [ || the two ML-KEM shared secrets, sorted ]
salt = peerPublicKey XOR ownPublicKey            (both 65-byte X9.63)
info = kTransportKeyInfo, or kHybridFSTransportKeyInfo with ML-KEM
key  = HKDF-SHA256(ikm, salt, info), 32 bytes
```

The `SecKey` path gets the ECDH output from `SecKeyCopyKeyExchangeResult`, the CryptoKit path from
`sharedSecretFromKeyAgreement`. `ForwardSecretDerivationEquivalenceTests` proves the two give the same key.

The mode name is authoritative: `forwardSecretNoPQ` and `longTermNoPQ` derive without ML-KEM whatever quantum
material is on file.

---

## Sending

`encryptBundle` / `encryptGroupBundle`:

1. Load the record. `PrekeyBookkeeper.takeInboundPrekey` takes the contact's oldest key and removes it.
2. A key → forward-secret slot (`forwardSecret`, or `forwardSecretNoPQ` without ML-KEM): an ephemeral key pair in
   memory, ECDH against the prekey. No key → long-term slot (`longTermFallback` / `longTermNoPQ`): ECDH between
   the identity keys.
3. Attach our pending batch, if any, with its ID (`pendingBatchForWire`). It rides every message until the contact
   uses a key from it.
4. Store the record; the caller saves.

Contacts on 1.9.0+ get the group bundle format with a one-entry recipient list; older ones get the single-recipient
format. Shard content needs forward secrecy: with no key for the contact, it is dropped and the message goes on the
long-term path, so delivery never waits on prekeys. The receiver drops it from long-term bundles too, whatever the
sender did.

---

## Receiving

`decryptSealed` (single-recipient) and `openGroup` (group), in this order:

1. Identify the sender by fingerprint. `senderPrekeys(for:)` sweeps their record (saved and flushed at once if it
   deleted anything) and returns a `SenderPrekeys` holding it.
2. Derive the key and open: `deriveInboundKey`, or `findAndOpenRecipientSlot` trying each slot.
3. **Consume the prekey the moment it has opened something** (§2.2 of `SECURITY_CHECKLIST.md`):
   `SenderPrekeys.consume` deletes a legacy key from the keychain, applies the bookkeeping below, stores, saves and
   checkpoints the write-ahead log, all before any later check can reject the bundle.
4. The remaining checks: shared ciphertext, sender proof, the sender-signature gates, payload decoding.
5. Accept the batch the sender attached (`acceptInboundBatch`).
6. If the bundle was long-term and no batch of ours is pending, generate one (`installFreshBatch`).
7. Store the record and save.

A rejected bundle still has steps 1 and 3 saved. That is the fail-secure direction: the key already derived the
wrapping key, so keeping it would keep the message openable on a seized phone. Someone holding our batch can make
us burn its keys and deliver it early; nothing more.

**The private key never outlives `deriveInboundKey`.** Consumption happens after it returns: `SecItemDelete` on an
item whose `SecKey` is still referenced crashes on release (mistake 5).

---

## New batches — one trigger

A long-term bundle from a contact with no batch of ours pending. A long-term bundle means they have none of our keys
left. Nothing else generates: not `encryptBundle`, not a low count, not a first message. Two fallback messages each
way bootstrap a new pair.

Generation runs **after every check that can reject the bundle** (Bug 159): a rejected bundle generates nothing.
That also keeps Enclave key creation out of the ECDH call stack (mistake 4). `generateEnclaveKeys` is all or
nothing: on the first failure it throws, and the keys already made vanish with it, leaving no item behind.

`install` makes the new batch pending with a random 16-byte ID. At most one batch is pending.

---

## What a used key proves (`PrekeyBookkeeper.consume`)

- **Delivery (Bug 157).** A key from the pending batch proves the contact received it: the batch stops being
  pending and its ID and public keys, needed only to send it, are dropped. A key from any other batch leaves the pending
  batch alone.
- **Retirement.** Senders use keys oldest first, so a key from batch *n* retires every older batch.
- **Legacy keys.** The first use of a record-held key moves `legacyKeys` from `inUse` to `retired(since:)`.

---

## Accepting their batch (`PrekeyBookkeeper.accept`)

- **With an ID (Bug 158):** dropped if that ID was accepted before, accepted otherwise, whatever its date.
- **Without an ID** (an older build): the date rule, accepted only if newer than the last one accepted without an
  ID.
- Accepting replaces the keys held from that contact.
- Outside the limits → `Errors.invalidPrekeySyncBatch`: an ID that isn't 16 bytes, more than 15 keys, a key that
  isn't 65 bytes, a key ID over 36 bytes (a UUID string). No build sends anything larger; the launch migration
  drops a carried-over batch outside them.

---

## The sweep (D1, Bug 156)

`ContactManager.sweepPrekeys` deletes retired batches 30 days after retirement, and the contact's legacy keychain
keys by tag 30 days after they retired, exactly once (`legacyKeys` → `.none`). The 30 days are kept for messages
sealed to those keys and still in transit.

- **On receipt**, for the sender, before the bundle is opened (`senderPrekeys(for:)`).
- **At unlock**, for the contacts visible at the authenticated depth, at every depth
  (`OccultaApp.sweepPrekeysIfUnlocked`), flushed by the checkpoint every unlock already takes.

The clock starts at retirement, and retirement needs the contact to move to a newer batch. A key lost in transit
from the batch they are still using stays until they do (Bug 156's residual, open).

---

## Size limits

The bookkeeper keeps the record within what 16 KB is budgeted for, so the codec never has to trim:

| Limit | Value | Enforced in |
|---|---|---|
| Our own keys | 48 | `install`: oldest retired keys first; never a key not yet retired, which are at most 2 × 15 |
| Their keys per batch | 15 | `accept` |
| Their key ID | 36 bytes | `accept` |
| Accepted batch IDs | 8 | `accept` |

Stage 1 holds one batch of theirs; the budget allows two, for stage 4. The limits bound keys, not entries, and each
of our batch entries costs about 45 bytes beyond its keys, so the worst case is 48 own keys in as many entries as
they can form with two full batches of theirs. With stage 2's last-resort keys that is the pending batch's 16 plus
32 one-key entries, and the contact's last-resort key: 15,874 bytes, counting the pending batch's public keys as
stored, which leaves room to store them again. The size test keeps 256 bytes of margin. It fits because a delivered
batch drops its ID; with IDs kept the stage 1 shape was 16,508, past the 16,379 available. The codec throws
`overCapacity` past 16 KB, which can only mean a broken invariant. Measure with distinct values, dates included: a
binary plist stores a repeated value once, so a fixture with repeated IDs, blobs or dates understates the size
(mistake 19). And measure the shape with the most entries, not the fewest (mistake 20).

---

## No silent security degradation

With a prekey in hand, any failure on the forward-secret path throws. It never quietly produces a long-term bundle.

| Error | Cause |
|---|---|
| `invalidRecipientMaterial` | long-term key is not exactly 65 bytes |
| `invalidPrekeyMaterial` | the prekey's public key is not exactly 65 bytes |
| `ephemeralKeyGenerationFailed` | the ephemeral key pair could not be generated |
| `keyDerivationFailed` | ECDH or HKDF failed despite valid key material, or no private key for the prekey ID |

---

## AAD

```
computeAdditionalAuthentication() = version.rawValue.utf8 || sortedKeys(JSON(SecrecyContext))

Covered by the GCM tag:      version, mode, ephemeralPublicKey, prekeyID
Group bundles also cover:    group.blind (shared ciphertext, and each slot's wrapped payload)
Routing only, not in AAD:    fingerprintNonce, senderFingerprint
Inside the ciphertext:       the payload, its prekey batch, the message
```

Always use `OccultaBundle.computeAdditionalAuthentication(version:secrecy:)` on both seal and open. Its encoder
uses `.sortedKeys`; without it two encoders order keys differently and every open fails (mistake 7).

---

## Wire format

```
OccultaBundle {
  version                    — in AAD
  secrecy {
    mode                     — in AAD: forwardSecret | forwardSecretNoPQ | longTermFallback | longTermNoPQ | group
    ephemeralPublicKey       — in AAD: 65 bytes, empty on the long-term path
    prekeyID                 — in AAD: the prekey's UUID, or nil
  }
  ciphertext                 — AES-GCM: nonce || ct || tag
  fingerprintNonce           — routing, not in AAD
  senderFingerprint          — routing, not in AAD
  group?                     — group format: blind and one recipient slot per member, each with its own secrecy context
}

PrekeySyncBatch {            — inside SealedPayload (single-recipient) or RecipientPayload (group)
  generatedAt                — Date, for the date rule
  id?                        — 16 random bytes on every batch a stage 1 build generates; omitted when nil, as
                               for an older build's batch or one carried over from before stage 1, which must
                               keep travelling without one
  prekeys: [WirePrekey {
    id                       — UUID string
    publicKey                — 65 bytes
  }]                         — no contactID on the wire
  lastResort?                — stage 2: a WirePrekey the sender may seal to more than once once out of
                               one-time keys. Its id never appears in a bundle's prekeyID: a bundle sealed
                               to it carries HMAC-SHA256(id as UUID bytes, ephemeral public key) as a UUID
                               (`SecrecyContext.lastResortPrekeyID`)
}
```

`WirePrekey` carries no `contactID`: our identifier for the contact must not travel, or it would leak the
relationship graph. The receiver supplies its own. `OccultaTests/Interop/InteropVectors.json` pins these bytes,
`prekeyBatchWithID` included.

---

## Historical mistakes

1. **Double-encrypting prekey blobs inside ForwardSecrecy.** Individual blobs passed through `cryptoOps.encrypt()`
   inside an already encrypted struct; `JSONDecoder` saw ciphertext and every pop failed silently.
2. **SE tag constructed from the raw UUID.** The lookup passed the bare prekey ID instead of
   `"prekey.<contactID>.<id>"`, so it always returned nil and forward-secret decryption never succeeded.
3. **Silent fallback when FS was intended.** ECDH failure with a valid prekey produced a long-term bundle; the
   caller believed it sent forward-secret.
4. **SE writes interleaved with ECDH.** Generating inside `seal`, right before ECDH, corrupted memory in
   `securityd`.
5. **SecKey held across SecItemDelete.** `CFRelease` on freed SE memory crashed.
6. **fatalError on a nil ECDH error.** `SecKeyCopyKeyExchangeResult` can fail without setting its error.
7. **Non-deterministic AAD.** `JSONEncoder()` without `.sortedKeys` → spurious `authenticationFailure`.
8. **version not in AAD.** The version could be flipped with no GCM failure, showing the wrong security badge.
9. **Speculative batch generation in encryptBundle**, on low stock. Generation is reactive to a long-term bundle.
10. **ownPrekeys array** to recover tag sequences. The tag is deterministic from contact and prekey ID.
11. **Pending batch overwritten** by a second fallback, orphaning the first batch's keys.
12. **Bootstrap batch generation in encryptBundle.** The fallback exchange bootstraps without a special case.
13. **Generating before the bundle was checked (Bug 159).** A rejected bundle left Enclave keys and a pending
    batch behind.
14. **Any used key cleared the pending batch (Bug 157)**, including one from an older batch, so a batch could
    count as delivered before it went anywhere.
15. **Deduplicating batches by date alone (Bug 158).** A sender whose clock went back could never deliver a batch
    again.
16. **No deletion of unused keys (Bug 156).** Keys a contact never used stayed in the Enclave for good.
17. **A record whose length tracked activity (Bug 161)**, and whose NULL separated contacts never written to.
18. **Prekey deleted only after every check (§2.2).** A bundle that opened and was then rejected left its key
    alive.
19. **A size budget measured with repeated values.** The worst-case fixture repeated one inbound key ID, which a
    binary plist stores once, and used 16-key batches against a 30-key limit. It passed at 13 KB; the real limits
    needed 19 KB, past the 16 KB record. Fixed by distinct values and tighter inbound limits.
20. **A size budget measured on three batches.** The limits bound keys, not the entries holding them, and every
    entry has a fixed cost. 48 keys spread over 34 entries, which a chatty contact losing a file per batch
    produces, came to 16.5 KB. Fixed by dropping a batch's ID at delivery and testing that shape.

---

## Protocol review checklist

Before implementing any cryptographic feature, complete every item in `CRYPTO_REVIEW_CHECKLIST.md`.
This guide is for implementation. The checklist is for protocol design. Both are required.

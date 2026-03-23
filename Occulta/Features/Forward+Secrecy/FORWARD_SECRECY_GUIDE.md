# Forward Secrecy Development Guide

Occulta v3fs — internal engineering reference.
Add this file to any PR that touches the forward secrecy implementation.

---

## Mental model: two arrays, two directions

Every `Contact.Profile` holds two prekey arrays and one pending delivery slot.

| Property | Whose keys | Direction | Operation |
|---|---|---|---|
| `contactPrekeys` | Their public keys | Received FROM contact | Pop FIFO when encrypting TO them |
| `ownPrekeys` | Our public keys | Sent TO contact | Find by ID / remove when they encrypt back to us |
| `pendingOutboundBatch` | Our freshly generated batch | Outbound | Rides every message until receipt is confirmed |

**contactPrekeys:** their keys → Alice pops one → uses it for ECDH → encrypts to Bob

**ownPrekeys:** our keys → Alice appended when generating → Bob uses one → Alice
finds it by Prekey.id to reconstruct SE tag → derives session key

**Why two arrays:**
Using a single array caused a silent collision. When Bob exhausted Alice's prekeys and
sent a fallback bundle with a new batch, `syncInboundPrekeys` replaced the entire store.
Alice's own prekeys — needed to look up SE private keys — were overwritten.
The next time Bob used one of Alice's keys, her SE tag lookup failed silently.

---

## The pending batch guarantee

**The problem with any flag approach:**
Clearing a flag on encrypt is too early. The message might not be sent, not be opened,
or be opened out of order. No delivery receipt exists without a server.

**The solution:**
Attach the same batch to every outbound message until we receive cryptographic proof
that the contact received it. The proof is unforgeable: they sent a .forwardSecret
bundle that opened successfully using one of our prekeys.

```
pendingOutboundBatch lifecycle:
  generateBatch()          → store in pendingOutboundBatch
  encryptBundle()          → attach pendingOutboundBatch to every message
  removeOwnPrekeyData()    → fires on successful FS open from them
  clearPendingBatch()      → called immediately after removeOwnPrekeyData
```

Edge cases this handles:
- Message encrypted but not sent: next message includes the same batch
- Message sent but not opened: same
- Two messages in flight with same batch: sequence guard is idempotent on receive
- Messages opened out of order: same batch in both, no-op on duplicate
- Both sides exhausted simultaneously: both detect inbound .longTermFallback,
  both generate new batches, recovery is automatic on next message in either direction

---

## SE operation ordering

**Rule: all SE writes must complete before any ECDH begins.**

```
CORRECT:
  generateBatch()           → SE writes done
  encryptForwardSecret()    → ECDH, AES-GCM, zero SE side effects

WRONG:
  encryptForwardSecret() calling generateBatch() internally,
  immediately followed by generateEphemeralKeyPair() + ECDH
```

**SecKey lifetime rule:**

`SecItemDelete` (inside `consume()`) invalidates the SE item backing the `SecKey`.
If ARC releases the `SecKey` after `SecItemDelete`, `CFRelease` crashes with
`malloc: pointer being freed was not allocated`.

The `SecKey` must go out of scope BEFORE `consume()` is called:

```swift
let decrypted: Data? = try {
    guard let privKey = prekeyManager.retrievePrivateKey(for: prekey) else { return nil }
    let key = crypto.deriveSessionKey(ephemeralPrivateKey: privKey, ...)
    return try crypto.openBundle(bundle, using: key)
    // privKey released here at closing brace
}()
prekeyManager.consume(prekey: prekey)   // SecKey is gone — safe
```

---

## AAD requirements

```
fullAAD() = version.rawValue.utf8 || sortedKeys(JSON(SecrecyContext))

In AAD (tamper causes authenticationFailure):
  version, mode, ephemeralPublicKey, prekeyID, prekeySequence, prekeyBatch

Not in AAD (routing metadata):
  fingerprintNonce, senderFingerprint
```

Routing fields must be outside AAD: the recipient needs them to identify the sender
before deriving the session key — putting them inside would create a circular dependency.
Tampering with routing fields makes the bundle undeliverable but cannot expose plaintext.

**Rules:**
- Always use `bundle.fullAAD()` on open and `Manager.Crypto.computeAAD(version:secrecy:)` on seal
- `JSONEncoder` for AAD must always use `.sortedKeys` — without it, different encoder
  instances produce different key orderings and AAD bytes diverge, causing spurious
  `authenticationFailure` on every open

---

## No silent security degradation

If the caller provides a non-nil `contactPrekey` (requesting FS), any failure **throws**
rather than producing a `.longTermFallback` bundle. The caller intended FS. Silently
falling back would show the wrong security badge and waste the popped prekey.

Error types:
- `invalidRecipientMaterial` — long-term key is not exactly 65 bytes
- `invalidPrekeyMaterial`    — contact's prekey.publicKey is not exactly 65 bytes
- `ephemeralKeyGenerationFailed` — SE could not generate the throwaway key pair
- `keyDerivationFailed`     — ECDH failed despite valid key material

The fallback path is entered only when `contactPrekey` is nil.

---

## syncInboundPrekeys: prune-then-append, not replace

Blind replace discards valid unconsumed prekeys from the previous batch.
The correct semantics:

1. **Prune** entries with `sequence < incoming.sequence - 1`.
   Those private keys are already deleted from the sender's SE.
   Keeping them wastes pop slots — they can never produce a valid session key.

2. **Append** the new batch to what remains.
   Keys at sequence `incoming.sequence - 1` are still valid (SE retains them as a buffer).

Blobs that fail decryption are kept defensively — never prune what you cannot read.

---

## ownPrekeys pruning

`ownPrekeys` uses append semantics. After each `generateBatch`, call
`pruneOwnPrekeys(olderThan: currentSequence - 1, decryptor:)` to remove dead blobs.
The SE prunes the same threshold — mirror it in SwiftData.

Blobs that fail decryption are kept defensively.

---

## generateBatch failure handling

The generation loop throws `PrekeyError.seKeyCreationFailed` on any SE failure rather
than continuing with a partial batch. A partial batch would advance the sequence and
prune old keys, leaving the contact with fewer prekeys than expected and no safety buffer.
Throw and let the caller retry.

---

## HKDF domain separation

| Path | Info string |
|---|---|
| Transport (message encryption) | `"Occulta-v1-transport-2025"` |
| Local database encryption | `"Occulta-v1-local-db-2025"` |

These strings are baked into every existing encrypted record.
⚠️ Changing them is a one-way breaking migration. Change once, never change again.

---

## Input validation

All public key material must be validated before ECDH. Validated at three entry points:

1. `recipientMaterial` in `encryptBundle` — long-term key from SwiftData
2. `contactPrekey.publicKey` in `encryptForwardSecret` — from received PrekeySyncBatch (attacker-influenced)
3. `bundle.secrecy.ephemeralPublicKey` in `decrypt` — from decoded JSON bundle (attacker-influenced)

```swift
guard material.count == 65 else { throw EncryptionError.invalidRecipientMaterial }
```

---

## Common mistakes — historical record

1. **Single prekey array for both directions.** `contactPrekeys` served both inbound and
   outbound. Sequences advanced, one direction overwrote the other, decrypt silently failed.

2. **Silent fallback when FS was intended.** ECDH failure with a valid contactPrekey called
   `self.fallback(...)` silently. UI showed FS; encryption used long-term keys.

3. **generateBatch silently truncating on SE failure.** The `continue` on failure advanced
   the sequence and pruned old keys with a partial batch. Fixed: throw immediately.

4. **SE writes interleaved with ECDH.** `generateBatch` inside `encryptForwardSecret`
   followed immediately by ECDH → SE daemon produced malloc corruption.

5. **SecKey held across SecItemDelete.** `consume()` called while `SecKey` still in scope
   → `CFRelease` on freed SE item → `malloc: pointer being freed was not allocated`.

6. **fatalError on nil ECDH error.** `SecKeyCopyKeyExchangeResult` can return nil without
   populating the error parameter. Force-unwrap of nil → undefined behaviour.

7. **Non-deterministic AAD.** `JSONEncoder()` without `.sortedKeys` produced different key
   orderings across instances → spurious `authenticationFailure` on every decrypt.

8. **version not in AAD.** Attacker could flip version from `.v3fs` to `.v1` without
   triggering GCM failure → UI displayed wrong security badge.

9. **Blind replace in syncInboundPrekeys.** New batch replaced entire store, discarding
   valid unconsumed prekeys from the previous batch → those messages became undecryptable.

10. **No pending batch mechanism.** Bob stuck in fallback indefinitely after exhausting
    Alice's prekeys — no way to notify Alice she needed to generate new keys for him.

---

## Protocol review checklist

Before implementing any cryptographic feature, complete every item in
`CRYPTO_REVIEW_CHECKLIST.md`. This guide is for implementation;
the checklist is for protocol design. Both are required.

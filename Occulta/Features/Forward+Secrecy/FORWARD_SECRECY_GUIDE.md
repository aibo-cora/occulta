# Forward Secrecy Development Guide

Occulta — internal engineering reference.
Commit this file alongside any change to the forward secrecy implementation.

---

## The Two-Array Invariant

Every `Contact.Profile` holds two prekey arrays that must never be confused.

| Property | Whose keys | Direction | Operation |
|---|---|---|---|
| `contactPrekeys` | **Their** public keys | Received FROM contact | Pop (FIFO) when encrypting TO them |
| `ownPrekeys` | **Our** public keys | Sent TO contact | Find by ID / remove when decrypting |

**Mnemonic:** `contactPrekeys` = the pile of stamps they gave us. `ownPrekeys` = the receipts for stamps we sent them.

Violations of this invariant break decryption silently. The GCM tag will not catch it — the wrong session key is derived before any authenticated data is checked.

### Checklist before touching prekey storage

- [ ] `encryptBundle` pops from `contactPrekeys` (their key for our ECDH)
- [ ] `encryptBundle` appends new batch to `ownPrekeys` (our keys we just sent)
- [ ] `decrypt` searches `ownPrekeys` by `bundle.secrecy.prekeyID` (our key they used)
- [ ] `decrypt` removes from `ownPrekeys` on success (not on failure)
- [ ] `decrypt` calls `syncInboundPrekeys` on `contactPrekeys` (their new keys for us)

---

## SE Operation Ordering

The Secure Enclave `securityd` daemon crashes with `malloc: pointer being freed was not allocated`
if SE writes (`SecKeyCreateRandomKey`, `SecItemDelete`) and ECDH (`SecKeyCopyKeyExchangeResult`)
are interleaved in the same call stack.

**Rule: all SE writes must complete before any ECDH operation begins.**

```
✅  generateBatch()       → (SE writes done)
    encryptForwardSecret() → (ECDH, AES-GCM — zero SE side effects)

❌  encryptForwardSecret() → generateBatch() inside → ECDH immediately after
```

### SecKey lifetime rule

`SecItemDelete` (inside `PrekeyManager.consume`) invalidates the SE item backing the `SecKey`.
If ARC releases the `SecKey` after `SecItemDelete`, `CFRelease` is called on freed memory.

**Rule: the `SecKey` reference must go out of scope BEFORE `consume()` is called.**

The closure pattern enforces this:

```swift
let decrypted: Data? = try {
    guard let privKey = prekeyManager.retrievePrivateKey(for: prekey) else { return nil }
    let sessionKey = crypto.deriveSessionKey(ephemeralPrivateKey: privKey, ...)
    return try crypto.openBundle(bundle, using: sessionKey)
    // ← privKey released here at closing brace
}()

// privKey is gone — safe to call SecItemDelete
prekeyManager.consume(prekey: prekey)
```

**Never** call `consume()` inside the same scope that holds a `SecKey` reference.

---

## AAD Requirements

Every field in `SecrecyContext` is authenticated by the AES-GCM tag via AAD.
Fields outside `SecrecyContext` (`fingerprintNonce`, `senderFingerprint`, `version`) must also
be covered — `version` is included in `fullAAD()`.

```
AES-GCM tag covers:
  ✅ SecrecyContext (mode, ephemeralPublicKey, prekeyID, prekeySequence, prekeyBatch)
  ✅ version (prepended to AAD via fullAAD())
  ✅ ciphertext (always covered by GCM)
  — fingerprintNonce and senderFingerprint are routing metadata, not authenticated
```

**Rule: always call `bundle.fullAAD()` on open, `computeAAD(version:secrecy:)` on seal.**
Never compute AAD inline with a bare `JSONEncoder()`.

**Rule: `JSONEncoder` for AAD must always use `.sortedKeys`.**
Without sorted keys, two encoder instances can produce different byte sequences for the same struct,
causing spurious `authenticationFailure` on every open.

---

## Entropy Validation

`SecRandomCopyBytes` can fail (boot-time entropy starvation, hardware fault).
The return value must always be checked.

```swift
// ✅ correct
guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
    throw OccultaBundle.BundleError.entropyUnavailable
}

// ❌ wrong — silent zero nonce
_ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
```

A zero nonce makes `senderFingerprint` identical across all bundles from the same sender,
defeating cross-bundle unlinkability.

---

## HKDF Domain Separation

Two different key derivation purposes must use two different `info` strings.
Sharing an info string means if two code paths ever produce the same ECDH IKM,
they silently derive the same key.

| Path | Info string |
|---|---|
| Transport (message encryption) | `"Occulta-v1-transport-2025"` |
| Local database encryption | `"Occulta-v1-local-db-2025"` |

**⚠️ BREAKING CHANGE WARNING**
Changing the info string invalidates all previously encrypted data.
Do this once at the right time, then never again.

---

## Input Validation

All public key material entering the ECDH path must be validated before use.

```swift
// P-256 x963 uncompressed point: 0x04 || X(32) || Y(32) = 65 bytes exactly
guard material.count == 65 else { return nil }
```

Passing wrong-length material to `SecKeyCreateWithData` returns nil silently.
Making the failure explicit at the validation site produces a clear error rather than
a confusing nil session key deep in the crypto stack.

---

## Prekey Accumulation and Pruning

`ownPrekeys` uses append semantics. Without pruning, it grows indefinitely as new batches
are generated for a contact.

**Rule: prune `ownPrekeys` immediately after `generateBatch` using the same sequence threshold.**

The SE prunes keys with `sequence < currentSequence - 1`.
`ownPrekeys` must be pruned with the same threshold so dead blobs (whose SE private keys
no longer exist) do not accumulate in SwiftData.

```swift
// After generateBatch for sequence N:
// SE prunes: seq < N - 1
// ownPrekeys must also prune: seq < N - 1
if seq > 1 {
    contact.pruneOwnPrekeys(olderThan: seq - 1) { try? cryptoOps.decrypt(data: $0) }
}
```

---

## Inbound Batch Size Limit

The `PrekeySyncBatch` inside a received bundle is attacker-controlled data.
Always validate size before processing.

```swift
guard inboundBatch.prekeys.count <= Manager.PrekeyManager.defaultBatchSize * 2 else {
    throw ContactManager.Errors.invalidPrekeySyncBatch
}
```

A legitimate peer sends at most `defaultBatchSize` (15) prekeys per batch.
The 2× factor gives headroom for future batch size changes.

---

## Testing Requirements for Crypto Features

Every forward secrecy change must include tests covering:

- [ ] **Two-array isolation**: encrypt then decrypt for the same contact, verify ownPrekeys and contactPrekeys never contain each other's data
- [ ] **Bidirectional conversation**: Alice → Bob uses Bob's prekey; Bob → Alice uses Alice's prekey; both decrypt correctly; no cross-contamination
- [ ] **Sequence advancement with pruning**: after batch N+2 is generated, batch N blobs are pruned from both SE and ownPrekeys
- [ ] **AAD tamper**: flip each SecrecyContext field individually; verify `openBundle` throws on each
- [ ] **Version tamper**: flip bundle.version; verify `openBundle` throws
- [ ] **Batch size limit**: bundle with oversized batch is rejected before any SE write
- [ ] **Entropy failure path**: if generateNonce throws, encryption throws (does not fall back silently)
- [ ] **Input validation**: recipientMaterial of wrong length causes encryptForwardSecret to throw, not fall back silently

---

## Common Mistakes Caught in This Codebase

1. **Single array for both prekey directions** — caused by treating `contactPrekeys` as a generic prekey store. Always ask: "whose keys are these, and in which direction?"

2. **SE writes inside encryptForwardSecret** — `generateBatch` was called inside the crypto function, interleaved with ECDH. Moved to ContactManager before the crypto call.

3. **SecKey held across SecItemDelete** — `consume()` was called while `prekeyPrivKey` was still a local variable. Fixed with closure-scoped release.

4. **`fatalError` on ECDH failure** — `SecKeyCopyKeyExchangeResult` can return nil with `error == nil`. Force-unwrapping the nil error caused heap corruption. Replace all `fatalError` with `return nil`.

5. **Non-deterministic AAD** — `JSONEncoder()` without `.sortedKeys` produced different key orderings across instances, causing spurious `authenticationFailure`. Always use `.sortedKeys` for AAD.

6. **`decryptForwardSecret` as monolithic SE+ECDH+GCM** — combining SE key retrieval, ECDH, and AES-GCM in one function made it impossible to control SecKey lifetime. Separated into `deriveSessionKey` (SE+ECDH) and `openBundle` (GCM only).

---

## Protocol Review Checklist

Before implementing any cryptographic feature, complete every item in `CRYPTO_REVIEW_CHECKLIST.md`.
This guide is for implementation; the checklist is for protocol design.
Both are required.

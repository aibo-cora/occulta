# Occulta Bundle — Encrypted Message Envelope

An **OccultaBundle** is the encrypted container used to send any data between two Occulta contacts — messages, vault shards, prekey material, and identity challenges. Every bundle is addressed to a single recipient and can only be opened by the device that holds the matching private key.

---

## The Big Picture

When you send a message, Occulta does not send your words directly. It:

1. Packages your message (and any attached operations) into a structured envelope
2. Derives a unique session key for this specific message
3. Encrypts the envelope with that key using AES-256-GCM
4. Attaches just enough public metadata for the recipient to find the right decryption key
5. Sends the result — nothing readable is ever on the wire

The recipient reverses the process: finds the matching private key, derives the same session key, decrypts, verifies the authentication tag. If anything was tampered with in transit, the tag fails and the bundle is rejected before any plaintext is produced.

---

## What Travels on the Wire

A bundle has two layers: a small **plaintext envelope** and a large **encrypted payload**.

### Plaintext Envelope (readable by anyone)

| Field | Purpose |
|---|---|
| `version` | Protocol version. Unknown versions are rejected. |
| `secrecy` | Key-exchange metadata: mode, ephemeral public key, prekey ID. Used as tamper-evident AAD. |
| `fingerprintNonce` | 16 random bytes, unique per bundle. |
| `senderFingerprint` | `SHA-256(senderPublicKey ∥ nonce)` — lets the recipient identify who sent this without exposing the sender's key directly. |

Everything in the plaintext envelope is **authenticated** by the AES-GCM tag — any modification causes decryption to fail. An observer can see that a bundle exists and who the sender is (via the fingerprint), but learns nothing about the content.

### Encrypted Payload (only the recipient can read)

| Field | Present when |
|---|---|
| `message` | Always — the actual message bytes |
| `prekeyBatch` | Sender is out of prekeys and needs new ones from the recipient |
| `shardOperations` | A vault shard is being distributed, replaced, or returned |
| `custodyManifest` | A list of shard IDs the recipient should confirm |
| `expectedShards` | A list of shard IDs the sender expects back |
| `identityChallenge` | An identity verification request |

All of these travel inside the same AES-GCM operation — one key, one tag, one atomic decryption.

**Why not put the prekey batch in the plaintext envelope?** It used to be there. Moving it inside the ciphertext hides prekey public keys and their count from passive observers, eliminating a relationship-graph leak.

---

## Encryption Modes

Each bundle is labelled with a **mode** that tells the recipient exactly which key derivation to use. There is no guessing or fallback — if the mode is unknown, the bundle is rejected with a clear error rather than a cryptic decryption failure.

### Forward Secret + Hybrid PQ (`forwardSecret`)

The strongest mode. Used when both parties have exchanged keys via UWB proximity.

**How the session key is derived:**
- Sender generates a throwaway (ephemeral) key pair, used for this message only
- Sender performs ECDH with the recipient's *prekey* (a one-time public key, not the long-term identity key)
- The ML-KEM shared secrets from the original UWB exchange are folded in
- HKDF-SHA256 combines everything into a 256-bit session key

The prekey is consumed after opening — it cannot be reused. Even if an attacker records this bundle and later compromises both parties' long-term keys, they still cannot derive this session key. The ephemeral key is gone; the prekey is gone.

The ML-KEM component means the session key is also resistant to quantum computers (harvest-now-decrypt-later attacks).

### Forward Secret, Classical (`forwardSecretNoPQ`)

Same as above but without ML-KEM. Used when the recipient's quantum key material is unavailable (not yet exchanged, or damaged). The ephemeral + prekey path still provides full forward secrecy against classical attackers. Old builds that receive this mode see an explicit "unsupported" error rather than a cryptic failure.

### Long-Term Fallback + Hybrid PQ (`longTermFallback`)

Used when prekeys are exhausted. The session key is derived from both parties' long-term identity keys (ECDH is symmetric — both sides arrive at the same value) plus the ML-KEM shared secrets. No ephemeral key is involved, so this mode does not provide forward secrecy. A bundle encrypted here is protected as long as both long-term private keys remain secure. The ML-KEM component still guards against quantum attackers.

A bundle in this mode always carries a fresh prekey batch inside the ciphertext, so the next message can return to the `forwardSecret` path.

### Long-Term Fallback, Classical (`longTermNoPQ`)

Same as above but without ML-KEM. Used when prekeys are exhausted AND the recipient's quantum key material is unavailable. Offers the same properties as standard ECDH encryption. Old builds see an explicit "unsupported" error.

---

## Security Properties

### Authentication and Tamper Detection

AES-256-GCM produces a 128-bit authentication tag that covers both the ciphertext and the Additional Authenticated Data (AAD). The AAD is `version ∥ secrecyContext` (sorted-key JSON, deterministic). Any modification to any part of the bundle — content, mode, ephemeral key, prekey ID, version — causes the tag check to fail immediately. No plaintext is ever returned from a failed bundle.

### Forward Secrecy

In `forwardSecret` and `forwardSecretNoPQ` modes, the ephemeral private key and the recipient's prekey private key are both destroyed after the message is opened. An attacker who compromises both devices' long-term keys at any point in the future cannot retroactively decrypt these messages.

### Post-Quantum Resistance (HNDL)

"Harvest now, decrypt later" is an attack where a passive observer records encrypted traffic today and decrypts it once a quantum computer is available. Bundles in `forwardSecret` and `longTermFallback` modes fold ML-KEM (a NIST-standardised post-quantum key encapsulation mechanism) shared secrets into the session key alongside ECDH. Breaking the session key requires breaking both the classical and quantum-resistant components — a quantum computer alone is not enough.

The ML-KEM secrets come from the original UWB proximity exchange. They are device-bound, never transmitted after the exchange, and encrypted at rest under the local DB key.

### Sender Anonymity

The `senderFingerprint` is `SHA-256(senderPublicKey ∥ nonce)`. An observer who does not know the sender's public key cannot determine who sent the bundle. The recipient, who has the sender's public key stored, can verify the fingerprint. The nonce is unique per bundle, so fingerprints cannot be correlated across messages.

### No Metadata Leakage

Prekey batches, shard operations, and other structured payloads are all inside the ciphertext. The plaintext envelope reveals only: that a bundle exists, the protocol version, the key-exchange mode, and the sender fingerprint. No contact names, no payload types, no prekey counts.

### Version Pinning

Unknown `version` or `mode` values are decoded as `.unsupported` and rejected before any key derivation is attempted. This prevents older builds from silently misinterpreting a bundle encrypted with a newer scheme.

---

## Key Exchange Prerequisite

The hybrid PQ modes (`forwardSecret`, `longTermFallback`) require that both parties have previously completed a UWB proximity key exchange. That exchange produces:
- Each party's long-term P-256 identity public key (stored in the contact record)
- ML-KEM shared secrets from mutual encapsulation (stored encrypted under the local DB key)
- An initial prekey batch from each party

Without a prior exchange, the app falls back to the NoPQ modes. If quantum material is lost or damaged (e.g. after a Secure Mode deactivation cycle predating Bug 30's fix), re-exchange restores it.

---

## Protocol Version

The current wire version is `v3fs`. The version tag is included in the AAD so it cannot be stripped or downgraded without breaking the authentication tag.

| Version | Description |
|---|---|
| `v1` | Long-term SE key only. No forward secrecy. Legacy. |
| `v2` | Ephemeral key path. Never shipped. |
| `v3fs` | Per-contact consumed prekey batches. Current. |

---

## Compatibility

| Sender → Receiver | Result |
|---|---|
| Current → Current | All four modes supported |
| Current (NoPQ) → v1.7.0 | `unsupportedMode` error on receiver (explicit, not CryptoKitError) |
| v1.7.0 → Current | Hybrid modes work; classical legacy bundles work |
| Either → Unknown build | Rejected at version or mode check |

If a contact is on an old build that cannot open a NoPQ bundle, the solution is for both parties to update — or, to restore quantum key material via re-exchange so hybrid modes can be used again.

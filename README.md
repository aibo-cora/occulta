# Occulta

> **The cryptographic address book the world has been missing.**

In a world where your contacts and trust are locked inside messaging apps, Occulta gives you true control. Collect verified public keys from friends, family, and colleagues through secure, in-person exchanges using Nearby Interaction — no servers, no phone numbers, no intermediaries.

Once exchanged, encrypt any file, photo, video, or document for anyone in your collection — and share it however you want: AirDrop, email, iMessage, any chat app. Your data stays hidden from analysis and sale.

Because Occulta requires no phone number, no server account, and no password, there is no account to take over remotely. Your cryptographic identity is a P-256 key pair bound to your device's Secure Enclave — it cannot be SIM-swapped, phished, or provider-hijacked from a distance. Every trust relationship requires physical presence to establish, and the same to replace.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Cryptographic Protocol](#cryptographic-protocol)
- [Post-Quantum Protection](#post-quantum-protection)
- [Forward Secrecy](#forward-secrecy)
- [Key Exchange Flow](#key-exchange-flow)
- [Encryption Flow](#encryption-flow)
- [Vault & Secret Sharing](#vault--secret-sharing)
- [Account Takeover Resistance](#account-takeover-resistance)
- [Security Properties](#security-properties)
- [Threat Model](#threat-model)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Building](#building)
- [Contributing](#contributing)
- [License](#license)

---

## How It Works

Occulta is an **offline-first, serverless cryptographic contact book** for iOS. The core insight is that the hardest problem in end-to-end encryption is not *encryption itself* — it is *key distribution*: how do you know that the public key you hold actually belongs to the person you think it does?

Most systems solve this by trusting a server (Signal, iMessage) or a web-of-trust (PGP). Occulta uses physical proximity. If you are standing next to someone and your devices measure the distance between you at ≤ 25 centimeters, you are almost certainly talking to the right person.

That proximity event — measured by Apple's UWB (Ultra-Wideband) chip — is what gates the key exchange. No server ever sees your keys. No phone number is required. The trust is physical.

---

## Cryptographic Protocol

[Security Analysis](https://github.com/user-attachments/files/25865710/occulta_crypto_protocol.docx)

### Key Generation

Each device generates one **P-256** (secp256r1) identity key pair on first launch. The private key is created using the **Secure Enclave** — it is wrapped by the SE's hardware key so that only this specific SE chip can use it. The wrapped key blob is stored in the Keychain database alongside all other Keychain items. The SE does not store keys internally; it protects them. The key cannot be extracted, exported, read in plaintext, or included in device backups. The `ThisDeviceOnly` accessibility attribute prevents the wrapped blob from migrating to other devices via backup or restore.

```
Key type:       P-256 (kSecAttrKeyTypeECSECPrimeRandom)
Key size:       256 bits
Protection:     Apple Secure Enclave (kSecAttrTokenIDSecureEnclave)
Access control: kSecAttrAccessibleWhenUnlockedThisDeviceOnly + privateKeyUsage
Persistence:    kSecAttrIsPermanent = true
Tag:            "master.key.privacy.turtles.are.cute"
```

The public key is exported in **X9.63 uncompressed point format** (65 bytes: `0x04 || X || Y`) for exchange and storage.

### Key Storage Model

Occulta stores several categories of cryptographic material. Understanding where each lives and how it is protected is critical to evaluating the threat model.

**Secure Enclave–protected keys (Keychain, wrapped by SE hardware):**

| Key | Tag / Account | Purpose |
|---|---|---|
| P-256 identity key | `master.key.privacy.turtles.are.cute` | Long-term identity, ECDH for transport and local DB |
| P-256 local DB key | `local.db.se.key.occulta` | ECDH component of hybrid local encryption key |
| P-256 prekeys | `prekey.<contactID>.<uuid>` | Per-message forward secrecy, deleted after single use |

These keys are stored in the Keychain database as SE-wrapped blobs. The Secure Enclave never releases the unwrapped key material — all cryptographic operations (ECDH, signing) are performed inside the SE chip. An attacker who extracts the Keychain database gets wrapped blobs that are unusable without physical access to the specific SE that created them.

**Keychain items (not SE-protected):**

| Item | Account | Purpose |
|---|---|---|
| Random component | `local.db.random.key.occulta` | 256-bit random half of hybrid local DB encryption key |

Stored as a `kSecClassGenericPassword` with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Not SE-wrapped, but encrypted at rest by iOS Data Protection and excluded from backups.

**SwiftData (encrypted at application layer):**

| Data | Encryption key | Purpose |
|---|---|---|
| Contact names, metadata | Hybrid local DB key | Contact records at rest |
| Peer P-256 public keys | Hybrid local DB key | Stored for ECDH when encrypting to a contact |
| `QuantumKeyMaterial` | Hybrid local DB key | ML-KEM shared secrets + ciphertexts from exchange |
| `ForwardSecrecy` struct | Hybrid local DB key | Inbound prekey batches, pending outbound batch |

All SwiftData fields containing sensitive data are encrypted with AES-256-GCM before being written to the database. The encryption key is derived from both the SE-protected local DB key and the random Keychain component via HKDF. This means decryption requires access to both the specific Secure Enclave and the specific Keychain — neither alone is sufficient.

**ML-KEM material specifically:** The ML-KEM-1024 private key exists only during the exchange session as a `SecureEnclave.MLKEM1024.PrivateKey` reference. It is released immediately after decapsulation and is never persisted. The ML-KEM shared secrets (32 bytes each) and ciphertexts are persisted in the `QuantumKeyMaterial` struct, encrypted at rest in SwiftData. These shared secrets are needed on every subsequent encryption and decryption operation for PQ contacts — they are mixed into every session key derivation via HKDF.

### Shared Secret Derivation

When two parties exchange public keys, the shared symmetric key derivation depends on whether the exchange included post-quantum key material.

**Classical path** (v1 contacts or iOS < 26):

```
Step 1 — ECDH:
  algorithm:  ecdhKeyExchangeCofactorX963SHA256
  output:     32-byte raw shared secret

Step 2 — HKDF:
  KDF:        HKDF<SHA256>
  IKM:        raw ECDH shared secret (32 bytes)
  Salt:       XOR(peerPublicKey_bytes, ourPublicKey_bytes)  [65 bytes each]
  Info:       "Occulta-v1-transport-2025" (UTF-8)
  Output:     32 bytes → SymmetricKey (AES-256)
```

**Hybrid post-quantum path** (contacts exchanged on iOS 26+ with ML-KEM-1024):

```
Step 1 — ECDH:
  algorithm:  ecdhKeyExchangeCofactorX963SHA256
  output:     32-byte raw ECDH shared secret

Step 2 — ML-KEM shared secrets:
  Two independent 32-byte shared secrets from mutual encapsulation (Option A).
  Sorted lexicographically so both sides produce identical input.

Step 3 — HKDF:
  KDF:        HKDF<SHA256>
  IKM:        ECDH_secret || sorted(ML-KEM_secret_1, ML-KEM_secret_2)  [96 bytes]
  Salt:       XOR(peerPublicKey_bytes, ourPublicKey_bytes)  [65 bytes each]
  Info:       "Occulta-v2-hybrid-pq-transport-2026" (UTF-8)
  Output:     32 bytes → SymmetricKey (AES-256)
```

The hybrid construction is secure if *either* algorithm remains unbroken. If ML-KEM is found to have a flaw, P-256 ECDH still provides classical security. If a quantum computer breaks P-256, ML-KEM-1024 still provides NIST Level 5 quantum resistance.

Both paths coexist in the codebase. The contact record determines which path is used — contacts with `QuantumKeyMaterial` use the hybrid path, contacts without it use the classical path. There is no guessing or fallback chain.

### Message & File Encryption

All content encryption uses **AES-256-GCM**:

```
Algorithm:  AES-GCM
Key size:   256 bits (derived via HKDF above)
Nonce:      96-bit random nonce (AES.GCM.Nonce(), generated per message)
AAD:        version || sortedKeys(JSON(SecrecyContext))
Output:     combined = nonce || ciphertext || tag  (CryptoKit combined format)
```

AES-256-GCM is quantum-resistant — Grover's algorithm reduces effective key strength to 128-bit equivalent, which remains computationally infeasible.

### Local Database Encryption

Contact data at rest (names, keys, metadata) is encrypted on-device before being stored in SwiftData. The local encryption key uses a hybrid construction combining two independent components:

```
Component 1 — SE-derived:
  ECDH(localDB_SE_privkey, G)  →  32 bytes
  where G is the P-256 generator base point (fixed, embedded in app)

Component 2 — Random:
  256-bit random value stored in Keychain
  Generated once via SecRandomCopyBytes, never rotated

Hybrid key:
  HKDF<SHA256>(
    IKM:    SE_component || random_component   [64 bytes]
    Salt:   localDB_SE_public_key_x963         [65 bytes]
    Info:   "Occulta-v2-local-db-pq-2026"
    Output: 32 bytes → SymmetricKey (AES-256)
  )
```

The SE component provides hardware binding — the key cannot be derived without this specific Secure Enclave. The random component provides post-quantum resistance — a quantum adversary who recovers the SE private key via Shor's algorithm still faces ~2^128 (Grover's bound) on the 256-bit random half. An attacker needs both components to derive the hybrid key.

This means local data can only be decrypted on the device that holds both the original Secure Enclave key and the Keychain random component. Restoring a backup to a different device renders local data permanently inaccessible. This is the intended security posture.

### Signing

Identity verification uses **ECDSA**:

```
Algorithm:  SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
Encoding:   X9.62 DER
Digest:     SHA-256
Output:     hex-encoded signature string
```

### Verification Words (Diceware)

After a key exchange completes, both parties see a set of human-readable **Diceware words** derived from the shared key material. Both parties must read these words aloud and confirm they match before the key is stored.

For hybrid PQ exchanges, the Diceware derivation includes both exchange nonces (16 bytes each, committed in the discovery message before proximity is confirmed) so that verification words are unique on every exchange session, even between the same key pairs. This prevents complacency from recognizing "familiar" words on a re-exchange.

```
Classical:  HKDF(ECDH_secret, info: "Occulta-v1-transport-2025")
Hybrid PQ:  HKDF(ECDH_secret || ML-KEM_secrets, info: "Occulta-v2-diceware-2026" || sorted(nonce_A, nonce_B))
```

---

## Post-Quantum Protection

### The Threat

Occulta's classical key agreement uses ECDH P-256. Shor's algorithm on a sufficiently powerful quantum computer can derive a P-256 private key from its public key in polynomial time. An adversary who records public keys exchanged today could decrypt all associated messages years from now when quantum computers become capable. This is the "harvest now, decrypt later" attack.

### The Defense: Hybrid ECDH + ML-KEM-1024

On devices running iOS 26 or later, Occulta performs a hybrid key agreement during the in-person exchange that combines classical ECDH P-256 with **ML-KEM-1024** (NIST FIPS 203, Security Level 5). ML-KEM is a lattice-based Key Encapsulation Mechanism with no known quantum speedup.

The ML-KEM-1024 private key is generated inside the **Secure Enclave** via `SecureEnclave.MLKEM1024.PrivateKey`. All decapsulation operations are performed by the SE chip internally — the private key never exists in app memory. This matches the hardware isolation model of the P-256 identity key: the key is protected by the SE, not stored in it. The SE wraps the key so that only this specific chip can perform operations with it. After decapsulation completes, the reference is released and the key becomes inaccessible.

### Mutual Encapsulation (Option A)

Both devices generate an ephemeral ML-KEM-1024 key pair during the exchange. Both sides encapsulate against the other's public key, producing two independent shared secrets. Both sides send their ciphertext to the peer, who decapsulates to recover the same shared secret.

```
Alice → Bob:  ML-KEM public key (1,568 bytes)
Bob → Alice:  ML-KEM public key (1,568 bytes)
Alice → Bob:  ML-KEM ciphertext (1,568 bytes)  — Bob decapsulates → secret_AB
Bob → Alice:  ML-KEM ciphertext (1,568 bytes)  — Alice decapsulates → secret_BA
```

Both sides now hold `secret_AB` and `secret_BA`. These are sorted lexicographically and concatenated with the ECDH shared secret before a single HKDF pass. Neither side has a privileged role — the protocol is fully symmetric.

### Storage

All ML-KEM artifacts from the exchange — both shared secrets and both ciphertexts — are grouped in a single `QuantumKeyMaterial` struct, encrypted as one AES-GCM blob, and stored on the contact record in SwiftData. The encryption key is the hybrid local DB key (SE + random component). The ML-KEM shared secrets are not SE-protected at rest — they are application-layer encrypted like all other contact data. Their confidentiality depends on the hybrid local DB key remaining secret, which in turn depends on both the Secure Enclave and the Keychain random component.

This follows the same pattern as the `ForwardSecrecy` struct: decrypt once when needed, read fields, discard plaintext.

### Quantum Protection of Forward-Secret Messages

For PQ contacts, every forward-secret message is **directly** quantum-resistant — not merely transitively protected through the chain of encrypted prekey delivery.

The session key for each forward-secret message is derived from both the classical ECDH (ephemeral × prekey) and the ML-KEM shared secrets from the original exchange:

```
IKM  = ECDH(ephemeralPriv, prekeyPub) || sorted(ML-KEM_secret_1, ML-KEM_secret_2)
Salt = XOR(prekeyPub, ephemeralPub)
Info = "Occulta-v2-hybrid-pq-fs-transport-2026"
```

A quantum attacker who can break the P-256 ECDH between the ephemeral key and the prekey still cannot derive the session key without also recovering the ML-KEM shared secrets. Those secrets are stored encrypted in SwiftData under the hybrid local DB key and are never transmitted on the wire after the initial exchange.

This is a stronger property than transitive protection alone. Transitive protection argues that prekey public keys are safe because they travel inside encrypted payloads whose root is PQ-protected. That argument is valid and provides defense-in-depth — prekey public keys still never travel in the clear. But the direct inclusion of ML-KEM material in every FS session key means that even if an attacker somehow obtained a prekey public key (device compromise, memory forensics), they still cannot break any individual message without also possessing the ML-KEM shared secrets.

For the **long-term fallback path** (when prekeys are exhausted), the same direct hybrid construction applies — ML-KEM secrets are mixed into the fallback session key via `kHybridTransportKeyInfo`. Every message to a PQ contact, whether forward-secret or fallback, is independently quantum-resistant.

### Backward Compatibility

PQ capability is negotiated implicitly via optional fields in the exchange message — not via a version bump. A v1 peer's JSON decoder silently ignores the `encapsulationKey`, `nonce`, and `ciphertext` fields it doesn't recognize. The exchange completes as classical, and messages are encrypted with the classical derivation path.

On iOS < 26, the PQ provider is nil. The device sends its identity without an ML-KEM public key and falls back to classical on receive. No crash, no error, no degraded UX — just classical security.

Contacts exchanged before the PQ upgrade retain their classical-only key material. They can re-exchange in person to establish hybrid PQ protection.

---

## Forward Secrecy

### The Problem

Without forward secrecy, every message to a contact is encrypted with the same long-term session key derived from ECDH(ourIdentity, theirIdentity). If either device is compromised, every past and future message between the pair is exposed.

### The Solution: Single-Use Prekeys

Occulta uses per-message prekeys to achieve forward secrecy. Each device generates batches of P-256 key pairs in the Secure Enclave, tagged `prekey.<contactID>.<uuid>`. The public halves are delivered to the contact inside encrypted payloads. When encrypting a message, the sender consumes one of the recipient's prekeys:

```
1. Pop oldest prekey from contact's stored batch
2. Generate throwaway ephemeral P-256 key pair (in memory, never persisted)
3. Session key = HKDF(ECDH(ephemeralPriv, prekeyPub), ...)
4. AES-GCM.seal(SealedPayload, using: sessionKey, authenticating: AAD)
5. Ephemeral private key discarded immediately
```

On decryption, the recipient reconstructs the SE tag from the prekey ID in the bundle, retrieves the SE-wrapped private key, derives the same session key, opens the payload, and **immediately deletes the prekey from the Secure Enclave**. That prekey can never be used again. The session key never existed in persistent storage on either side.

### Prekey Delivery

Prekey public keys are never exposed in the clear. They travel exclusively inside AES-GCM-encrypted `SealedPayload` blobs — the same ciphertext that carries the message content. This is enforced at the type level: `WirePrekey` only appears inside `SealedPayload`, never in the unencrypted `SecrecyContext` (AAD).

New prekey batches are generated reactively: when a device receives a `longTermFallback` bundle (meaning the sender had no prekeys left to use), it generates a fresh batch and attaches it to the next outbound message. There is no speculative generation.

### Prekey Quantum Resistance

Prekey public keys are P-256 — classically secure but quantum-vulnerable in isolation. However, two layers protect them from quantum attack:

**Direct protection:** For PQ contacts, every session key (including fallback messages that carry prekey batches) is derived from both ECDH and ML-KEM material. A quantum attacker cannot decrypt the payload containing the prekeys without breaking ML-KEM.

**Structural protection:** Even if a quantum attacker could somehow obtain a prekey public key, they cannot break any message encrypted with that prekey. Every FS session key for PQ contacts includes ML-KEM shared secrets in the HKDF input. Breaking the P-256 ECDH(ephemeral, prekey) is insufficient — the ML-KEM component remains unbroken.

For classical-only contacts (no ML-KEM material), prekeys are protected only by the classical encryption of the payload that delivered them. A future quantum attacker who recorded the exchange could eventually break the P-256 ECDH, recover the prekey public keys, and then break individual messages. This is the expected limitation of a classical-only contact — re-exchange in person on iOS 26+ to upgrade to hybrid PQ protection.

---

## Key Exchange Flow

The exchange uses two Apple frameworks in concert: **MultipeerConnectivity (MC)** for peer discovery and data transport, and **NearbyInteraction (NI)** for proximity measurement. On iOS 26+, a third phase adds ML-KEM-1024 mutual encapsulation for post-quantum protection.

```
Phase 1 — Discovery (MC):
  1. Both devices advertise and browse on the local network.
  2. On mutual discovery, an MC session is established.
  3. Both devices exchange NI discovery tokens over MC.

Phase 2 — Proximity Gate (NI):
  4. NI session starts using the received discovery token.
  5. UWB measures the distance between the devices.
  6. When distance ≤ 0.25m, the proximity gate opens.
  7. The P-256 public key is transmitted over MC.
  8. On iOS 26+: the ML-KEM-1024 encapsulation key is transmitted alongside.

Phase 3 — ML-KEM Encapsulation (iOS 26+ only):
  9. Each device encapsulates against the other's ML-KEM public key.
  10. Ciphertexts are exchanged over MC.
  11. Each device decapsulates the received ciphertext using the SE private key.
  12. Both sides now hold two independent ML-KEM shared secrets.

Phase 4 — Verification:
  13. Both devices derive Diceware verification words from the combined key material.
  14. Users read words aloud and confirm they match.
  15. On confirmation, the contact (keys + ML-KEM material) is stored.
```

### Security Properties of the Exchange

- The P-256 and ML-KEM public keys are only transmitted **after** NI confirms distance ≤ 25 cm.
- Each device uses a **random UUID** as its MC peer display name, preventing fingerprinting across sessions.
- A MITM guard checks that the inbound identity packet came from the **same MC peer ID** confirmed by UWB proximity. The peer ID is set the moment NI confirms proximity, before key generation begins.
- Phase 3 is skipped entirely when exchanging with a v1 peer (no ML-KEM public key received).
- The ML-KEM-1024 private key lives in the Secure Enclave for the duration of the exchange and is released after decapsulation.
- All delegate callbacks (MC and NI) are dispatched to the main queue for thread safety and `@Observable` correctness.

---

## Encryption Flow

Once you have a contact's verified public key, you can encrypt any data for them:

```
First message (long-term fallback):
  1. Retrieve contact's stored public key (decrypted from SwiftData)
  2. If contact has QuantumKeyMaterial:
       HKDF(ECDH_secret || ML-KEM_secrets, info: kHybridTransportKeyInfo) → sessionKey
     Else:
       HKDF(ECDH_secret, info: kTransportKeyInfo) → sessionKey
  3. Encode SealedPayload { message, prekeyBatch: nil }
  4. AES-GCM.seal(SealedPayload, using: sessionKey, authenticating: AAD)
  5. Contact detects fallback → generates our prekeys → sends them back

Subsequent messages (forward secret):
  1. Pop oldest prekey from contact's stored batch
  2. generateEphemeralKeyPair() → throwaway key, never persisted
  3. If contact has QuantumKeyMaterial:
       HKDF(ECDH(ephPriv, prekey) || ML-KEM_secrets, info: kHybridFSTransportKeyInfo) → sessionKey
     Else:
       HKDF(ECDH(ephPriv, prekey), info: kTransportKeyInfo) → sessionKey
  4. Encode SealedPayload { message, prekeyBatch: pendingBatch or nil }
  5. AES-GCM.seal(SealedPayload, using: sessionKey, authenticating: AAD)
  6. Ephemeral private key discarded; recipient deletes prekey from SE on decrypt
```

Decryption mirrors this: the recipient reconstructs the session key using their Secure Enclave prekey private key and the sender's ephemeral public key (plus ML-KEM secrets if available), verifies the GCM tag, decodes the payload, and deletes the prekey. The session key never existed in persistent storage on either side.

---

## Vault & Secret Sharing

Occulta Vault stores encrypted entries (label + content). Each entry has its own randomly generated **per-entry key (PEK)** — the vault master key only wraps the PEK, not the content directly. This means recovery can be scoped per entry: different entries can have different trustees and different thresholds.

### Encryption model

```
vault key (SE-derived)
  └── encryptedEntryKey  →  per-entry key (PEK, 32 random bytes)
        ├── encryptedLabel    (AES-GCM, AAD = entry.aad())
        └── encryptedContent  (AES-GCM, AAD = entry.aad())
```

### Shamir's Secret Sharing

The PEK is split using SSS over GF(2⁸) (Lagrange interpolation, field polynomial 0x11B). A threshold-of-n split produces n shards; any k ≥ threshold reconstruct the PEK. With fewer than k shards an attacker learns nothing about the PEK — information-theoretic security, not computational.

Splitting is per-entry. Different entries use independent random polynomials; shards from different distributions are incompatible and fail GCM authentication if mixed.

### Shard signing

Each shard is wrapped in a `SignedAttribute(category: .shard)` signed by the owner's SE identity key. The v2 signing payload binds:

```
"occulta-signed-attribute-v2" ∥ attrID ∥ "shard" ∥ entryID
∥ createdAt UInt64 BE ∥ expiry flag ∥ shardBytes
```

`entryID` binding prevents a shard from a previous PEK generation from being accepted against a rotated entry. `createdAt`/`expiresAt` in the payload prevent a trustee from extending validity by editing stored JSON — any modification invalidates the ECDSA signature.

On a new device the owner's SE key is gone; signature verification is skipped. GCM authentication on reconstruction substitutes as the integrity check.

### Shard delivery

Shards are delivered as `.occ` bundles using `longTermFallback` + **mandatory ML-KEM**. A contact without ML-KEM key material cannot be selected as a trustee. This gates every shard bundle behind a session key that requires breaking ML-KEM-1024 in addition to P-256 to recover — the only practical defence against harvest-now-decrypt-later attacks. Forward secrecy is not used for shard traffic; `longTermFallback` + ML-KEM provides equivalent practical security for this threat model without consuming prekeys.

### What a trustee stores

A trustee stores a `CustodyShard` row containing only:
- A random per-row `id` (plaintext SwiftData key).
- An `encryptedPayload` blob — AES-GCM seal of `{ ownerKeyFingerprint, ownerContactIdentifier, signedAttribute }` under the shard custody key, AAD = `id`.

No plaintext column links a shard to a specific contact. Cold-disk forensics learns "N shards stored" — nothing about ownership, timing, or which entries are covered.

### Shard custody key

A dedicated SE key (tag `"shard.custody.occulta"`, device-unlock level, no biometric) is used exclusively for shard operations. Two symmetric keys are HKDF-derived from it:

| Symmetric key       | HKDF info                         | Seals            |
|---------------------|-----------------------------------|------------------|
| Shard custody key   | `Occulta-v1-shard-custody-2026`   | CustodyShard     |
| Recovery buffer key | `Occulta-v1-recovery-buffer-2026` | ReconstructShard |

Device-unlock (not biometric) allows shard bundles to be stored automatically on receipt without requiring the user to open the app.

### Reconstruction

1. Trustees detect Alice's key change during proximity exchange and auto-return shards via `.handback` operations in the next outbound bundle.
2. Alice's app buffers arriving shards in `ReconstructShard` (encrypted under the recovery buffer key).
3. When ≥ k shards are buffered, `tryFinalizeReconstruction` runs automatically.
4. Old device: verify each shard's ECDSA signature. New device: skip, rely on GCM.
5. `ShamirSecretSharing.reconstruct(shares:)` → 32-byte PEK.
6. `AES.GCM.open(encryptedContent, using: PEK)` — success confirms shard integrity.
7. Re-wrap PEK under current vault key; zero PEK bytes immediately.

### Threat model

| Threat | Defence |
|--------|---------|
| < k shards | Information-theoretically zero leakage |
| Stale shards (old PEK) | GCM decryption fails immediately |
| Tampered shard | ECDSA fails (normal); GCM fails on new device |
| Shard mixing across entries | GCM authentication rejects incompatible shares |
| HNDL (quantum adversary archives bundles) | Mandatory ML-KEM-1024 in session key |
| Trustee device loss | Owner detects fingerprint change → marks shard `.lost`; UI prompts redistribution |

---

## Account Takeover Resistance

Most end-to-end encrypted tools bind identity to something that can be stolen remotely:

| Tool | Identity anchor | Remote takeover path |
|---|---|---|
| Signal | Phone number | SIM-swap → register new device → contacts see attacker's key |
| iMessage | Apple ID | Apple ID compromise → new device added → transparent to contacts |
| PGP | Email address | No key server authentication; key can be uploaded under any UID |

These are not flaws in the cryptography — they are consequences of requiring identity to be remotely accessible. Occulta removes the attack surface at the architecture level.

**What Occulta uses as identity:** a P-256 key pair generated inside your device's Secure Enclave. The private key never leaves the chip. There is no phone number, no account, no password, no server that knows who you are.

**What this means in practice:**

- A SIM-swap attack gives an attacker your phone number. Occulta does not know your phone number.
- An Apple ID or Google account compromise gives an attacker your cloud identity. Occulta has no cloud account.
- A provider receiving a legal demand to insert a surveillance key has no server to compel. There is no server.
- A credential phishing attack has no password to steal.

The only way to substitute a key in Occulta is to be physically present (≤ 25 cm) during an exchange and defeat the UWB proximity gate, the peer ID guard, *and* the Diceware out-of-band word verification simultaneously — which requires the target to cooperate or be deceived in person.

**This is a complement to Signal, not a replacement.** Signal is the right tool when your contact is across the world and you need an accessible encrypted channel today. Occulta is the right tool when you can meet once, establish a hardware-bound trust anchor, and then send documents over any channel indefinitely without worrying that the other end has been remotely compromised.

**Concrete scenario:** A journalist exchanges keys with a source in person. From that point on, any file dropped into an `.occ` bundle is encrypted to a key that lives in the source's Secure Enclave. Even if the source's Signal account is SIM-swapped, their iCloud is subpoenaed, or their phone number is ported — none of that touches the hardware key the journalist holds. The source's device is the trust anchor.

### Re-verification

If you need to confirm a contact hasn't been replaced since your last exchange, Occulta includes a signed identity challenge protocol — a challenge-response bundle signed by the contact's SE key that proves they still hold the same private key without requiring a physical re-exchange. This is available for any contact in your collection.

---

## Security Properties

| Property | Status | Notes |
|---|---|---|
| Private key extraction | ✅ Not possible | SE-wrapped; operations performed inside SE chip |
| Private key at rest | ✅ SE-wrapped in Keychain | Protected by SE hardware key, not stored inside the SE |
| Key agreement (classical) | ✅ ECDH P-256 | Industry standard |
| Key agreement (PQ) | ✅ Hybrid ECDH + ML-KEM-1024 | NIST Level 5, SE-backed, iOS 26+ |
| Session key derivation | ✅ HKDF-SHA256 | Domain-separated info strings per path |
| Content encryption | ✅ AES-256-GCM | Authenticated encryption, quantum-resistant |
| Nonce reuse | ✅ Random per message | Each seal call generates a fresh nonce |
| Bundle integrity | ✅ AAD covers version + key-exchange fields | Tampering causes GCM failure |
| Forward secrecy | ✅ Per-message, v3fs | Ephemeral + single-use prekeys; SE deletion on decrypt |
| FS quantum resistance | ✅ Direct (PQ contacts) | ML-KEM secrets mixed into every FS session key |
| FS quantum resistance | ⚠️ Transitive only (classical contacts) | Prekeys protected by classical encryption of delivery payload |
| Prekey confidentiality | ✅ Encrypted in transit | Public keys travel only inside AES-GCM ciphertext |
| Metadata leakage | ✅ No contact identifiers on wire | WirePrekey carries id + publicKey only |
| ML-KEM private key isolation | ✅ Secure Enclave | SE reference released after decapsulation, never persisted |
| ML-KEM secret storage | ⚠️ Application-layer encrypted | Stored in SwiftData under hybrid local DB key, not SE-wrapped |
| MITM during exchange | ✅ Diceware verification + peer ID guard | Human-verifiable, nonce-freshened |
| Proximity spoofing | ✅ UWB hardware enforcement | ≤ 0.25m threshold |
| Server-side exposure | ✅ None | No backend exists |
| Remote account takeover | ✅ No attack surface | No phone number, server account, or password |
| Identity re-verification | ✅ Challenge-response | Signed ECDSA challenge; proves SE key continuity without re-exchange |
| Backward compatibility | ✅ Classical fallback | v1 peers and iOS < 26 exchange classically, no breakage |
| Backup passphrase KDF | ⚠️ SHA-256 (single round) | Should be PBKDF2/Argon2id |
| Android interoperability | ❌ Not supported | iOS + Secure Enclave only |

---

## Threat Model

**Occulta protects against:**

- A messaging platform reading your files or contact list
- A cloud provider scanning attachments for advertising
- A network attacker intercepting your encrypted files in transit
- Someone finding an encrypted file on your device or in email
- A remote attacker with no physical access substituting keys
- SIM-swap and phone number hijacking (no phone number exists in the system)
- Server-side account compromise or provider-compelled key insertion (no server exists)
- Credential phishing (no password)
- A passive observer correlating messages to relationships via wire metadata
- Compromise of long-term keys exposing past messages (forward secrecy)
- A quantum adversary recording public keys today for future decryption (hybrid PQ key agreement)
- A quantum adversary targeting individual forward-secret messages (ML-KEM secrets mixed into every FS session key for PQ contacts)

**Occulta does not protect against:**

- An attacker physically present at a key exchange who can observe and intercept the MC channel before NI proximity is confirmed (mitigated but not eliminated by the peer ID guard and Diceware verification)
- Compromise of the device itself (unlocked phone, jailbreak, MDM) — an attacker with full device access can decrypt the SwiftData store and extract ML-KEM shared secrets, breaking the PQ protection for that contact
- Loss of your iPhone — contact keys are device-local with no automatic backup
- Weak passphrases used with the contact export feature
- Future message confidentiality after device compromise — forward secrecy protects past messages, not future ones
- Contacts exchanged before the PQ upgrade remain classical-only until re-exchanged in person
- A quantum attacker targeting classical-only contacts — prekeys and messages are protected by P-256 ECDH only

---

## Architecture

```
Occulta/
├── Services/
│   ├── Crypto+Manager.swift       # AES-GCM encrypt/decrypt (local + transport)
│   ├── Key+Manager.swift          # Secure Enclave ops, ECDH, HKDF, hybrid derivation
│   ├── Exchange+Manager.swift     # MC + NI + ML-KEM exchange orchestration
│   └── Contact+Manager.swift      # SwiftData CRUD, bundle encrypt/decrypt dispatch
│
├── Features/
│   ├── PostQuantum/
│   │   ├── PQProvider.swift       # ML-KEM-1024 operations (iOS 26+, SE-backed)
│   │   └── QuantumKeyMaterial.swift  # Codable struct for ML-KEM artifacts
│   │
│   └── Forward+Secrecy/
│       ├── OccultaBundle.swift    # Wire format: version, SecrecyContext, SealedPayload
│       ├── PrekeyManager.swift    # SE prekey lifecycle: generate, retrieve, consume, delete
│       └── ForwardSecrecy.swift   # Per-contact FS state (encrypted at rest)
│
├── Models/
│   ├── Contact+Model.swift        # SwiftData schema (Profile, Key, PhoneNumber, …)
│   ├── Identity.swift             # Local device identity record
│   └── Transfers.swift            # Basket, File, EncryptedFile
│
├── Protocols/
│   └── KeyManagerProtocol.swift   # Abstraction for testing (TestKeyManager)
│
└── UI/
    └── ...
```

**Dependencies:** All cryptographic operations use Apple-native frameworks only — `CryptoKit`, `Security.framework`, `NearbyInteraction`, and `MultipeerConnectivity`.

---

## Requirements

- iOS 17.0+
- iPhone with U1 or U2 chip (UWB required for key exchange)
- iOS 26+ for post-quantum hybrid key exchange (ML-KEM-1024)

---

## Building

```bash
git clone https://github.com/nicedayyura/Occulta.git
cd Occulta
open Occulta.xcodeproj
```

Build and run on a physical device. The Secure Enclave and UWB are not available in the Simulator.

---

## Contributing

Contributions are welcome. Please read `CODE_GENERATION_GUIDELINES.md` and `CRYPTO_REVIEW_CHECKLIST.md` before submitting any code that touches cryptographic operations.

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

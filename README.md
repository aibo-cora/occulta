# Occulta

> **The cryptographic address book the world has been missing.**

In a world where your contacts and trust are locked inside messaging apps, Occulta gives you true control. Collect verified public keys from friends, family, and colleagues through secure, in-person exchanges using Nearby Interaction — no servers, no phone numbers, no intermediaries.

Once exchanged, encrypt any file, photo, video, or document for anyone in your collection — and share it however you want: AirDrop, email, iMessage, any chat app. Your data stays hidden from analysis and sale.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Cryptographic Protocol](#cryptographic-protocol)
- [Post-Quantum Protection](#post-quantum-protection)
- [Forward Secrecy](#forward-secrecy)
- [Key Exchange Flow](#key-exchange-flow)
- [Encryption Flow](#encryption-flow)
- [Security Properties](#security-properties)
- [Threat Model](#threat-model)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Building](#building)
- [Contributing](#contributing)
- [License](#license)

---

## Cryptographic Protocol

### Key Generation

Each device generates one **P-256** (secp256r1) identity key pair on first launch. The private key is generated directly inside the **Apple Secure Enclave** and never leaves it — not in memory, not on disk, not in iCloud backups.

```
Key type:       P-256 (kSecAttrKeyTypeECSECPrimeRandom)
Key size:       256 bits
Storage:        Apple Secure Enclave (kSecAttrTokenIDSecureEnclave)
Access control: kSecAttrAccessibleWhenUnlockedThisDeviceOnly + privateKeyUsage
Persistence:    kSecAttrIsPermanent = true
Tag:            "master.key.privacy.turtles.are.cute"
```

The public key is exported in **X9.63 uncompressed point format** (65 bytes: `0x04 || X || Y`) for exchange and storage.

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

Contact data at rest (names, keys, metadata) is encrypted on-device before being stored in SwiftData. The local encryption key is derived the same way as the transport key, but the "peer" is a fixed P-256 public key embedded in the app:

```swift
// The fixed key is the x963 representation of the P-256 generator base point G.
// ECDH(ourPrivateKey, G) → deterministic key tied solely to our Secure Enclave key.
```

This means local data can only be decrypted on the device that holds the original Secure Enclave key. Restoring a backup to a different device without key migration will render local data inaccessible.

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

The ML-KEM-1024 private key is generated inside the **Secure Enclave** via `SecureEnclave.MLKEM1024.PrivateKey`. The private key never exists in app memory — all decapsulation operations are performed by the SE chip internally. This matches the hardware isolation of the P-256 identity key.

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

All ML-KEM artifacts from the exchange — both shared secrets and both ciphertexts — are grouped in a single `QuantumKeyMaterial` struct, encrypted as one AES-GCM blob, and stored on the contact record. This follows the same pattern as the `ForwardSecrecy` struct: decrypt once when needed, read fields, discard plaintext.

### Transitive Protection of Forward-Secret Messages

Prekey public keys are never exposed in the clear. They travel exclusively inside AES-GCM-encrypted `SealedPayload` blobs. The chain of protection traces from the identity-level hybrid key agreement through every subsequent message:

1. The first fallback bundles (carrying the initial prekey batches) are encrypted with the hybrid ECDH + ML-KEM session key.
2. Each forward-secret message is encrypted with a session key derived from a prekey that was delivered inside a hybrid-protected payload.
3. New prekey batches ride inside forward-secret messages, themselves protected by prekeys from the previous generation.

A quantum attacker cannot extract any prekey public key without first breaking the encryption of the bundle that carried it. Since the root of the chain is quantum-resistant, every link in the chain is transitively protected.

### Backward Compatibility

PQ capability is negotiated implicitly via optional fields in the exchange message — not via a version bump. A v1 peer's JSON decoder silently ignores the `encapsulationKey`, `nonce`, and `ciphertext` fields it doesn't recognize. The exchange completes as classical, and messages are encrypted with the classical derivation path.

On iOS < 26, the PQ provider is nil. The device sends its identity without an ML-KEM public key and falls back to classical on receive. No crash, no error, no degraded UX — just classical security.

Contacts exchanged before the PQ upgrade retain their classical-only key material. They can re-exchange in person to establish hybrid PQ protection.

---

## Key Exchange Flow

The exchange uses two Apple frameworks in concert: **MultipeerConnectivity (MC)** for peer discovery and data transport, and **NearbyInteraction (NI)** for proximity measurement. On iOS 26+, a third phase adds ML-KEM-1024 mutual encapsulation for post-quantum protection.

```
Alice                                              Bob
  |                                                  |
  |── MCNearbyServiceAdvertiser (start) ────────────>|
  |<─ MCNearbyServiceBrowser (found peer) ──────────|
  |                                                  |
  |── MC invite ─────────────────────────────────── >|
  |<─ MC accept ────────────────────────────────────|
  |                                                  |
  |  [MC session connected]                          |
  |                                                  |
  |  PHASE 1 — Discovery                            |
  |── Exchange{token, nonce} ───────────────────────>|
  |<─ Exchange{token, nonce} ───────────────────────|
  |                                                  |
  |  [NISession.run(peerToken)]                      |
  |                                                  |
  |  [NINearbyObject.distance ≤ 0.25m] ←── UWB ──> |
  |                                                  |
  |  PHASE 2 — Identity + ML-KEM public keys        |
  |── Exchange{P-256 pub + ML-KEM pub} ────────────>|
  |<─ Exchange{P-256 pub + ML-KEM pub} ────────────|
  |                                                  |
  |  [MITM guard: verify sender == proximate peer]   |
  |                                                  |
  |  PHASE 3 — ML-KEM ciphertexts                   |
  |── Exchange{ML-KEM ciphertext} ─────────────────>|
  |<─ Exchange{ML-KEM ciphertext} ─────────────────|
  |                                                  |
  |  [Each side decapsulates → two shared secrets]   |
  |                                                  |
  |  [Derive hybrid key → Diceware words]            |
  |  [User confirms words match out-of-band]         |
  |  [Store P-256 key + QuantumKeyMaterial]           |
```

**Key points:**

- The exchange nonce is committed in Phase 1, before proximity is confirmed, preventing a MITM from choosing nonces after seeing identity keys.
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
  3. ECDH(ephemeralPriv, contactPrekey.publicKey) → HKDF → sessionKey
  4. Encode SealedPayload { message, prekeyBatch: pendingBatch or nil }
  5. AES-GCM.seal(SealedPayload, using: sessionKey, authenticating: AAD)
  6. Ephemeral private key discarded; recipient deletes prekey from SE on decrypt
```

Decryption mirrors this: the recipient reconstructs the session key using their Secure Enclave prekey private key and the sender's ephemeral public key, verifies the GCM tag, decodes the payload, and deletes the prekey. The session key never existed in persistent storage on either side.

---

## Security Properties

| Property | Status | Notes |
|---|---|---|
| Private key extraction | ✅ Not possible | Secure Enclave hardware isolation |
| Private key at rest | ✅ Never persisted in plaintext | Enclave-managed |
| Key agreement (classical) | ✅ ECDH P-256 | Industry standard |
| Key agreement (PQ) | ✅ Hybrid ECDH + ML-KEM-1024 | NIST Level 5, SE-backed, iOS 26+ |
| Session key derivation | ✅ HKDF-SHA256 | Domain-separated info strings per path |
| Content encryption | ✅ AES-256-GCM | Authenticated encryption, quantum-resistant |
| Nonce reuse | ✅ Random per message | Each seal call generates a fresh nonce |
| Bundle integrity | ✅ AAD covers version + key-exchange fields | Tampering causes GCM failure |
| Prekey batch integrity | ✅ Encrypted inside ciphertext | Batch invisible to observers |
| Prekey quantum resistance | ✅ Transitive | Prekey public keys never travel in the clear; protected by PQ chain |
| Forward secrecy | ✅ Per-message, v3fs | Ephemeral + single-use prekeys; SE deletion on decrypt |
| Metadata leakage | ✅ No contact identifiers on wire | WirePrekey carries id + publicKey only |
| MITM during exchange | ✅ Diceware verification + peer ID guard | Human-verifiable, nonce-freshened |
| Proximity spoofing | ✅ UWB hardware enforcement | ≤ 0.25m threshold |
| Server-side exposure | ✅ None | No backend exists |
| ML-KEM private key isolation | ✅ Secure Enclave | SecureEnclave.MLKEM1024.PrivateKey, never in app memory |
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
- A passive observer correlating messages to relationships via wire metadata
- Compromise of long-term keys exposing past messages (forward secrecy)
- A quantum adversary recording public keys today for future decryption (hybrid PQ key agreement)
- Harvest-now-decrypt-later attacks against the entire message chain (transitive PQ protection via encrypted prekey delivery)

**Occulta does not protect against:**

- An attacker physically present at a key exchange who can observe and intercept the MC channel before NI proximity is confirmed (mitigated but not eliminated by the peer ID guard and Diceware verification)
- Compromise of the device itself (unlocked phone, jailbreak, MDM)
- Loss of your iPhone — contact keys are device-local with no automatic backup
- Weak passphrases used with the contact export feature
- Future message confidentiality after device compromise — forward secrecy protects past messages, not future ones
- Contacts exchanged before the PQ upgrade remain classical-only until re-exchanged in person

---

## Architecture

```
Occulta/
├── Manager/
│   ├── Crypto+Manager.swift          # AES-GCM encrypt/decrypt (local + transport)
│   ├── Crypto+ForwardSecrecy.swift   # seal(), open(), session key derivation
│   ├── Key+Manager.swift             # SE identity key, ECDH, HKDF
│   ├── Key+Manager+PQ.swift          # Hybrid ECDH + ML-KEM HKDF derivation
│   ├── Key+Manager+Ephemeral.swift   # Ephemeral key pair generation
│   ├── Prekey+Manager.swift          # SE prekey lifecycle (generate, retrieve, consume)
│   ├── Exchange+Manager.swift        # MultipeerConnectivity + NearbyInteraction + PQ exchange
│   └── Contact+Manager.swift         # SwiftData CRUD, encryptBundle, decrypt
│
├── Models/
│   ├── Contact+Model.swift           # SwiftData schema (Profile, Key, PhoneNumber, …)
│   ├── Contact+Model+Prekeys.swift   # ForwardSecrecy operations on Contact.Profile
│   ├── ForwardSecrecy.swift          # Encrypted prekey state struct
│   ├── QuantumKeyMaterial.swift       # Encrypted ML-KEM shared secrets + ciphertexts
│   ├── OccultaBundle.swift           # Wire format, SealedPayload, SecrecyContext
│   ├── Prekey.swift                  # Internal prekey type (SE tag construction)
│   └── ExchangeResult.swift          # Post-exchange UI + Diceware verification
│
├── Services/
│   └── PQProvider.swift              # ML-KEM-1024 operations (SE + in-memory), iOS 26 gating
│
└── Views/
    └── KeyExchange.swift             # Exchange UI, proximity session, duplicate detection
```

**Dependencies:** All cryptographic operations use Apple-native frameworks only — `CryptoKit`, `Security.framework`, `NearbyInteraction`, and `MultipeerConnectivity`. There are no third-party cryptographic dependencies. Post-quantum operations use `SecureEnclave.MLKEM1024` from CryptoKit (iOS 26+).

**Data persistence:** SwiftData with encrypted fields. Sensitive strings (names, notes) and key material are encrypted with AES-GCM before storage. The `ForwardSecrecy` struct and `QuantumKeyMaterial` struct are each encrypted as single blobs, ensuring cryptographic state is always read and written atomically.

**iOS version support:** Deployment target is iOS 18. Post-quantum protection requires iOS 26+ and is negotiated at exchange time. All ML-KEM availability gating is confined to `PQProvider.swift` — no `#available` checks appear elsewhere in the codebase.

# Occulta

> **The cryptographic address book the world has been missing.**

In a world where your contacts and trust are locked inside messaging apps, Occulta gives you true control. Collect verified public keys from friends, family, and colleagues through secure, in-person exchanges using Nearby Interaction — no servers, no phone numbers, no intermediaries.

Once exchanged, encrypt any file, photo, video, or document for anyone in your collection — and share it however you want: AirDrop, email, iMessage, any chat app. Your data stays hidden from analysis and sale.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Cryptographic Protocol](#cryptographic-protocol)
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

## How It Works

Occulta is an **offline-first, serverless cryptographic contact book** for iOS. The core insight is that the hardest problem in end-to-end encryption is not *encryption itself* — it is *key distribution*: how do you know that the public key you hold actually belongs to the person you think it does?

Most systems solve this by trusting a server (Signal, iMessage) or a web-of-trust (PGP). Occulta uses physical proximity. If you are standing next to someone and your devices measure the distance between you at ≤ 25 centimeters, you are almost certainly talking to the right person.

That proximity event — measured by Apple's UWB (Ultra-Wideband) chip — is what gates the key exchange. No server ever sees your keys. No phone number is required. The trust is physical.

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

When two parties exchange public keys, a shared symmetric key is derived using a two-step process:

**Step 1 — ECDH:**
```
algorithm:  SecKeyAlgorithm.ecdhKeyExchangeCofactorX963SHA256
output:     32-byte raw shared secret
```

**Step 2 — HKDF:**
```
KDF:        HKDF<SHA256>
IKM:        raw ECDH shared secret (32 bytes)
Salt:       XOR(peerPublicKey_bytes, ourPublicKey_bytes)  [65 bytes each]
Info:       "Occulta-v1-encryption-key-2025" (UTF-8)
Output:     32 bytes → SymmetricKey (AES-256)
```

The XOR salt binds the derived key to the specific key pair involved, ensuring that the same ECDH secret used with a different identity pair produces a different session key.

### Message & File Encryption

All content encryption uses **AES-256-GCM**:

```
Algorithm:  AES-GCM
Key size:   256 bits (derived via HKDF above)
Nonce:      96-bit random nonce (AES.GCM.Nonce(), generated per message)
Output:     combined = nonce || ciphertext || tag  (CryptoKit combined format)
```

The combined format includes the authentication tag, providing integrity and authenticity guarantees in addition to confidentiality.

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

After a key exchange completes, both parties see a set of human-readable **Diceware words** derived deterministically from the shared key material. Both parties must read these words aloud and confirm they match before the key is stored.

```
Input:   shared key bytes (from HKDF output)
Output:  N words from Diceware word list, separated by "-"
Purpose: Out-of-band confirmation that no key substitution occurred mid-exchange
```

If an attacker had substituted keys during the exchange (a MITM attack), the Diceware words derived by each party would differ. This provides human-verifiable authenticity.

### Contact Export / Backup

Contacts can be exported as an encrypted blob using a user-supplied passphrase:

```
Key derivation:  SHA-256(passphrase_utf8)   ⚠️  see security note below
Encryption:      AES-256-GCM
```

> **⚠️ Security note:** The current backup key derivation uses a single SHA-256 hash of the passphrase. This is fast to compute, which makes it easier to brute-force weak passphrases. A future version will replace this with PBKDF2 or Argon2id to increase the cost of offline attacks. When using the backup feature today, use a strong passphrase (minimum 5 random Diceware words recommended).

---

## Key Exchange Flow

The exchange uses two Apple frameworks in concert: **MultipeerConnectivity (MC)** for peer discovery and data transport, and **NearbyInteraction (NI)** for proximity measurement.

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
  |── Exchange{NIDiscoveryToken} ───────────────────>|
  |<─ Exchange{NIDiscoveryToken} ───────────────────|
  |                                                  |
  |  [NISession.run(peerToken)]                      |
  |                                                  |
  |  [NINearbyObject.distance ≤ 0.25m] ←── UWB ──> |
  |                                                  |
  |── Exchange{NIDiscoveryToken + PublicKey(x963)} ->|
  |<─ Exchange{NIDiscoveryToken + PublicKey(x963)} --|
  |                                                  |
  |  [MITM guard: verify sender == peer who          |
  |   received our identity]                         |
  |                                                  |
  |  [Derive shared key → generate Diceware words]   |
  |                                                  |
  |  [User confirms words match out-of-band]         |
  |                                                  |
  |  [Store encrypted public key in SwiftData]       |
```

**Key points:**

- The public key is only transmitted **after** NI confirms distance ≤ 25 cm. An attacker in the same room but not directly adjacent cannot trigger the exchange.
- Each device uses a **random UUID** as its MC peer display name, preventing fingerprinting across sessions.
- A MITM guard checks that the inbound identity packet came from the **same MC peer ID** that received our own identity packet. Mismatches are flagged.
- The NISession is invalidated immediately after the public key is transmitted, limiting the exposure window.

---

## Encryption Flow

Once you have a contact's verified public key, you can encrypt any data for them:

```
1. Retrieve contact's stored public key (decrypted from SwiftData)
2. createSharedSecret(using: contactPublicKey)
      └─ ECDH(ourSecureEnclaveKey, contactPublicKey)
      └─ HKDF<SHA256>(ikm, salt=XOR(keys), info="Occulta-v1-...")
3. AES-GCM.seal(plaintext, using: sessionKey, nonce: .random)
4. Output: combined bytes (nonce || ciphertext || tag)
5. Share the combined bytes via any channel (AirDrop, email, etc.)
```

Decryption by the recipient mirrors this exactly — they derive the same shared key using their Secure Enclave private key and your stored public key, then AES-GCM.open() the combined blob.

---

## Security Properties

| Property | Status | Notes |
|---|---|---|
| Private key extraction | ✅ Not possible | Secure Enclave hardware isolation |
| Private key at rest | ✅ Never persisted in plaintext | Enclave-managed |
| Key agreement | ✅ ECDH P-256 | Industry standard |
| Session key derivation | ✅ HKDF-SHA256 | Proper KDF with domain separation |
| Content encryption | ✅ AES-256-GCM | Authenticated encryption |
| Nonce reuse | ✅ Random per message | Each seal call generates a fresh nonce |
| MITM during exchange | ✅ Diceware verification + peer ID guard | Human-verifiable |
| Proximity spoofing | ✅ UWB hardware enforcement | ≤ 0.25m threshold |
| Server-side exposure | ✅ None | No backend exists |
| Backup passphrase KDF | ⚠️ SHA-256 (single round) | Should be PBKDF2/Argon2id |
| Forward secrecy | ⚠️ Not provided | Long-term keys used directly |
| Android interoperability | ❌ Not supported | iOS + Secure Enclave only |

---

## Threat Model

**Occulta protects against:**

- A messaging platform reading your files or contact list
- A cloud provider scanning attachments for advertising
- A network attacker intercepting your encrypted files in transit
- Someone finding an encrypted file on your device or in email
- A remote attacker with no physical access substituting keys

**Occulta does not protect against:**

- An attacker physically present at a key exchange who can observe and intercept the MC channel before NI proximity is confirmed (mitigated but not eliminated by the peer ID guard and Diceware verification)
- Compromise of the device itself (unlocked phone, jailbreak, MDM)
- Loss of your iPhone — contact keys are device-local with no automatic backup
- Weak passphrases used with the contact export feature
- Metadata — Occulta encrypts *content*, not the fact that you communicate with someone

---

## Architecture

```
Occulta/
├── Manager/
│   ├── Crypto+Manager.swift     # AES-GCM encrypt/decrypt (local + transport)
│   ├── Key+Manager.swift        # Secure Enclave ops, ECDH, HKDF key derivation
│   ├── Exchange+Manager.swift   # MultipeerConnectivity + NearbyInteraction orchestration
│   └── Contact+Manager.swift    # SwiftData CRUD operations
│
├── Models/
│   ├── Contact+Model.swift      # SwiftData schema (Profile, Key, PhoneNumber, …)
│   └── ExchangeResult.swift     # Post-exchange UI + Diceware verification view
│
└── Views/
    └── KeyExchange.swift        # Exchange UI, proximity session, duplicate detection
```

**Dependencies:** All cryptographic operations use Apple-native frameworks only — `CryptoKit`, `Security.framework`, `NearbyInteraction`, and `MultipeerConnectivity`. There are no third-party cryptographic dependencies.

**Data persistence:** SwiftData with encrypted fields. Sensitive strings (names, notes) and key material are encrypted with AES-GCM before storage, using a local key derived from the Secure Enclave identity key.

---

## Requirements

- **iOS 16.0+**
- **iPhone 11 or later** (U1/UWB chip required for Nearby Interaction)
- Xcode 16+
- No server, no account, no network required after installation

---

## Building

```bash
git clone https://github.com/aibo-cora/occulta.git
cd occulta
open Occulta.xcodeproj
```

Select your target device (NearbyInteraction cannot be fully tested in the simulator — a fixed public key is substituted automatically in simulator builds via `#if targetEnvironment(simulator)`).

Build and run. On first launch, Occulta generates your P-256 identity key pair inside the Secure Enclave. This key is permanent until you explicitly delete it via **Settings → Reset Identity**.

---

## Contributing

Occulta is open source under the Apache 2.0 license. Contributions are welcome, particularly in these areas:

- **PBKDF2 / Argon2id** for the contact export passphrase KDF
- **QR code fallback** for key exchange on devices without UWB
- **Key recovery / backup** that preserves the no-server guarantee
- **Android client** using Android Keystore + Nearby Connections API
- **Formal security review** of the HKDF salt construction and MITM guard logic

Please open an issue before submitting a pull request for significant changes.

---

## Privacy Policy

Occulta collects no data. There are no servers. There is no analytics. There is no account. Your keys, contacts, and encrypted files never leave your device unless you explicitly share them.

See [privacy-policy.md](privacy-policy.md) for the full policy.

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

---

*Built by a privacy and security enthusiast, for the global community.*

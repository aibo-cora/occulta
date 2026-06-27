# Occulta

> **The cryptographic address book the world has been missing.**

[**Download on the App Store →**](https://apps.apple.com/us/app/occulta/id6758548781)

Occulta is a contact book where every entry is a cryptographic key you collected in person. Meet someone, hold your phones close, and exchange keys over UWB — no servers, no accounts, no phone numbers. Once you have their key, you can encrypt any file for them and send it over any channel you like: AirDrop, email, iMessage, Signal, anything. Only they can open it.

---

## Who It's For

**Professionals with legally sensitive information** — doctors, lawyers, accountants, journalists. When sensitive files move through a messaging platform, they travel through infrastructure someone else controls. Occulta removes that infrastructure: files are encrypted to a key that lives only on your contact's device, so there is nothing for a platform or a subpoena to reach.

**Travelers and activists** operating in high-risk environments. Your cryptographic identity in Occulta is locked to a hardware chip on your specific iPhone. No one can impersonate you remotely or take over your identity by compromising an account.

**Anyone who wants their private files to stay private.** You don't need a specific adversary to want your information to be yours.

---

## Features

### Key Exchange

To add a contact, both of you open Occulta and bring your phones within 25 cm of each other. The app uses Apple's UWB chip to confirm you're genuinely close, then exchanges your cryptographic keys directly between devices. No server is involved. After the exchange, both of you read a short set of words aloud to verify the keys match — then the contact is saved.

The result: a contact whose identity is guaranteed by physics, not by a server or a username.

→ [How the exchange works technically](https://github.com/aibo-cora/occulta/wiki/Key-Exchange-Flow)

---

### Encrypt Anything

Once you have someone's key, tap their name in Occulta and attach any file — a photo, document, video, voice note. Occulta encrypts it into an `.occ` bundle that only they can open. Share the bundle however you want. The channel doesn't matter: the encryption is independent of the delivery method.

Each message uses a fresh key that is thrown away after use, so a future device compromise cannot expose past messages.

→ [How encryption works technically](https://github.com/aibo-cora/occulta/wiki/Encryption-Flow) · [Forward secrecy](https://github.com/aibo-cora/occulta/wiki/Forward-Secrecy)

---

### Post-Quantum Protection

On iOS 26 and later, Occulta adds a second layer of encryption on top of the standard key exchange using ML-KEM-1024 — a quantum-resistant algorithm standardized by NIST. This protects against adversaries who record your encrypted traffic today hoping to decrypt it years from now when quantum computers become powerful enough to break standard encryption.

→ [How post-quantum protection works](https://github.com/aibo-cora/occulta/wiki/Post-Quantum-Protection)

---

### Vault

Vault is a secure place to store sensitive notes, credentials, and documents — encrypted the same way your messages are. Each entry can be split among trusted contacts using secret sharing: you choose a threshold (e.g. any 2 of 3 contacts), and Occulta splits the entry's encryption key into shards. If you lose your device, your trustees can return their shards and you recover your vault. No shard holder can read your data alone.

→ [How the Vault and secret sharing work](https://github.com/aibo-cora/occulta/wiki/Vault-and-Secret-Sharing)

---

### Group Messaging

Encrypt a file or message for multiple contacts at once and share it as a single bundle. Each recipient gets their own individually wrapped copy of the decryption key — only they can open it, and no recipient can probe the key of another.

Groups are local: a named list of contacts on your device. No server, no membership notifications. Deliver the bundle over any channel, same as individual messages.

Forward secrecy and post-quantum protection apply per recipient. The duress layer model extends to groups — a coerced unlock shows a separate member list with no trace of the real one.

→ [How group messaging works](https://github.com/aibo-cora/occulta/wiki/Group-Messaging)

---

### Secure Mode

Secure Mode protects against someone forcing you to unlock your phone. You set two PINs: a real one and a duress one. The duress PIN unlocks a decoy view — same app, same layout, but sensitive contacts and vault entries are hidden. A coercer cannot tell which PIN they received.

Additional protections:
- The "Disable PIN" toggle leaves depth filtering active — disabling the lock doesn't reveal hidden contacts.
- The app leaves no forensic trace that Secure Mode is in use; the configuration file is written from first launch on every install.
- Up to 32 nested duress layers are supported.

→ [How Secure Mode works technically](https://github.com/aibo-cora/occulta/wiki/Secure-Mode)

---

### Account Takeover Resistance

Occulta has no account. Your identity is a key that lives in your iPhone's Secure Enclave — a dedicated hardware chip that never lets the key leave. There is no password to phish, no phone number to SIM-swap, no cloud account to compromise, and no server to subpoena.

If someone takes over your Signal account or iCloud, they cannot read your Occulta messages or impersonate you in Occulta. Your contacts will simply stop receiving valid bundles from "you" — and that silence is the signal.

---

## What It Doesn't Do

Occulta is not a messaging app and doesn't replace Signal or iMessage. It has no chat interface. It encrypts files and lets you verify identity — delivery is up to you.

Cross-device sync is intentional absent. Keys live on one device. If you lose your iPhone without vault recovery configured, you lose your keys.

Android is not supported.

→ [Full threat model](https://github.com/aibo-cora/occulta/wiki/Threat-Model) · [Security properties](https://github.com/aibo-cora/occulta/wiki/Security-Properties)

---

## Technical Documentation

- [Cryptographic Protocol](https://github.com/aibo-cora/occulta/wiki/Cryptographic-Protocol)
- [Key Exchange Flow](https://github.com/aibo-cora/occulta/wiki/Key-Exchange-Flow)
- [Encryption Flow](https://github.com/aibo-cora/occulta/wiki/Encryption-Flow)
- [Forward Secrecy](https://github.com/aibo-cora/occulta/wiki/Forward-Secrecy)
- [Post-Quantum Protection](https://github.com/aibo-cora/occulta/wiki/Post-Quantum-Protection)
- [Vault & Secret Sharing](https://github.com/aibo-cora/occulta/wiki/Vault-and-Secret-Sharing)
- [Secure Mode](https://github.com/aibo-cora/occulta/wiki/Secure-Mode)
- [Threat Model](https://github.com/aibo-cora/occulta/wiki/Threat-Model)
- [Security Properties](https://github.com/aibo-cora/occulta/wiki/Security-Properties)
- [Architecture](https://github.com/aibo-cora/occulta/wiki/Architecture)
- [Group Messaging](https://github.com/aibo-cora/occulta/wiki/Group-Messaging)
- [Group Messaging — Technical](https://github.com/aibo-cora/occulta/wiki/Group-Messaging-Technical)
- [Security Analysis (PDF)](https://github.com/user-attachments/files/25865710/occulta_crypto_protocol.docx)

---

## Requirements

- iOS 17.0+
- iPhone with U1 or U2 chip (required for UWB key exchange)
- iOS 26+ for post-quantum hybrid key exchange

---

## Building

```bash
git clone https://github.com/aibo-cora/occulta.git
cd Occulta
open Occulta.xcodeproj
```

Build and run on a physical device. The Secure Enclave and UWB are not available in the Simulator.

---

## Contributing

Contributions are welcome. Please read `CODE_GENERATION_GUIDELINES.md` and `CRYPTO_REVIEW_CHECKLIST.md` before submitting any code that touches cryptographic operations.

---

## License

GNU Affero General Public License v3.0. See [LICENSE](LICENSE) for details.

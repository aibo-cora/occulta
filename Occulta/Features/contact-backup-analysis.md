# Contact Backup — Analysis & Conclusion

## The Feature Concept

A contact backup would serialize all contact records, their associated public keys, and their stored prekey public keys into an encrypted file, stored externally (iCloud, email, another device), allowing restoration of the contact list after device loss.

On the surface this seems valuable: losing a device today means losing every contact relationship permanently, requiring each contact to be re-exchanged in person via UWB proximity.

## Why Full Restore Doesn't Work

Occulta's session keys are derived as:

```
ECDH(ourIdentitySEKey, contactPublicKey) → HKDF → session key
```

The identity SE key is P-256, generated in the Secure Enclave, tagged `"master.key.privacy.turtles.are.cute"`. It is hardware-bound and never leaves the device. After device loss, a new identity SE key is generated — a completely different key pair.

With a new identity key, every session key changes. Specifically, after restore you **cannot**:
- Decrypt any previously received messages (session keys are different)
- Send messages your contacts can decrypt immediately (they have your old public key; your new key is unrecognized by their routing)
- Fully resume communication without some form of re-introduction

A backup that fully restored communication ability — including the ability to decrypt old messages — would require exporting the identity private key. That would fundamentally undermine the Secure Enclave guarantee that is Occulta's core security property.

## What a Backup Can Enable: Soft Re-Introduction

While full restore is impossible, a backup that includes contacts' stored prekey public keys enables a weaker but useful bootstrap mechanism via a new protocol mode.

In v3fs, the session key has two components:

```
ECDH(ourEphemeralPriv, contactPrekeyPub)  → secret 1
ECDH(ourIdentitySEKey, contactPub)         → secret 2 (long-term)
combined → HKDF → session key
```

On a new device, secret 2 is wrong: the new identity SE key produces a different value than the old one. The recipient cannot decrypt.

However, the protocol could support a **re-introduction mode** that drops the long-term component entirely:

```
ECDH(ourEphemeralPriv, contactPrekeyPub) → HKDF → session key
```

The sender uses a stored prekey public key from the backup, generates a fresh ephemeral pair, and encrypts a payload containing their new identity public key. The recipient decrypts using only the prekey component and extracts the new identity key to update their contact record.

This is mechanically feasible as a new protocol version (v4 or a distinct envelope type).

### Security of Re-Introduction Mode

**What it proves**: the sender had prior access to the contact's prekey public key — something only a prior contact (or someone who compromised the backup) would possess. Knowledge of the prekey limits the attack surface to prior relationships.

**What it does not prove**: that the sender is the same person who held the old identity key. The long-term component is absent. Identity continuity is not cryptographically guaranteed.

**The gap**: an adversary who obtained the contact backup could send re-introduction messages impersonating the original user to all their contacts. The prekey functions as a shared secret but not as an identity proof.

**Closing the gap**: out-of-band re-verification after re-introduction. A simple confirmation via any secondary channel ("I lost my phone, confirm you received my re-introduction?") closes the identity continuity gap. This is weaker than the original UWB word verification but acceptable for re-establishment of an existing trusted relationship.

### Net Result After Restore

| Capability | Immediate | After Re-Introduction | After Out-of-Band Verify |
|---|---|---|---|
| Know who contacts are | ✓ | ✓ | ✓ |
| Send messages | ✗ | ✓ (pending acceptance) | ✓ |
| Receive new messages | ✗ | ✓ (after contact updates) | ✓ |
| Decrypt old messages | ✗ | ✗ | ✗ |
| Full identity trust | ✗ | ✗ | ✓ |

Old messages are permanently inaccessible — the old session keys are gone with the old identity key. This is correct behavior, not a gap.

## What the Backup Must Contain

For re-introduction to work, the backup must include:

- Contact names and identifiers
- Contact identity public keys
- **Contact stored prekey public keys** — the one-time public keys we hold for sending them FS messages
- Encrypted contact metadata fields (already ciphertext — include as-is)

The backup does **not** need to include our own prekey private keys — those are consumed per-message and cannot be backed up meaningfully.

## What the Backup File Would Expose

An adversary who obtained the encrypted backup and broke the encryption would learn:

- Who your contacts are (names, identifiers, social graph)
- Their public keys and prekey public keys
- With the prekeys: the ability to send re-introduction messages impersonating you

They would **not** be able to:
- Decrypt any messages (session keys require your identity SE key)
- Impersonate you to contacts who independently verify the re-introduction out-of-band

The risk profile is: **metadata exposure + impersonation risk during the re-introduction window**. For journalists and activists, the social graph exposure alone may be the entire intelligence target. The backup should be treated as highly sensitive and stored with at minimum the same care as the device itself.

## The Secure Mode Blob Is Different

The Secure Mode blob performs a similar serialization but works because it is local and the identity SE key still exists on the same device. Nothing changed cryptographically. Restoration is a decrypt-and-reinsert operation under the same identity key. No re-introduction protocol is needed.

An external backup has no equivalent guarantee. The device that reads it has a different identity key.

## Conclusion

**A contact backup feature has limited but real value** — not for full restore, but for soft re-introduction that gets relationships back to "pending out-of-band re-verification" rather than "start completely from scratch."

Building it requires:
1. A new re-introduction protocol mode (v3fs without long-term component, new identity key in payload)
2. Backup serialization including contact prekey public keys
3. Strong encryption of the backup file (the prekeys inside enable impersonation if compromised)
4. Clear user communication: old messages are gone permanently, re-introduction requires out-of-band confirmation, backup file is sensitive

**Priority**: low. The UX improvement is real but the security caveats are significant and the protocol work is non-trivial. Build Secure Mode first. Revisit contact backup as a later addition once the re-introduction protocol is designed carefully.

---

*Documented May 2026. Initial conclusion ("do not build") revised after identifying that stored contact prekey public keys enable a soft re-introduction mechanism via a modified forward-secrecy protocol mode — weaker than the original UWB exchange but stronger than starting from scratch.*

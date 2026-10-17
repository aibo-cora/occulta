# Introduction Cards — Specification (v1, direct sharing)

**Status:** Draft, 2026-10-16. Not implemented.
**Decisions:** [FINDINGS.md](FINDINGS.md). This document pins down formats and procedures. Where it is more specific than FINDINGS (§2's field list, Q-05's storage), this document wins, and FINDINGS points here.
**Builds on:** `release/v2.0.0` with prekey continuity stages 1 and 2 merged (PR #110):
- `PrekeyRecord`, `PrekeySecretsManager` and `Manager.Key.forwardSecretSessionKey`;
- the group bundle format with `senderEphemeralSignature` and `bodyDigest`;
- `FORWARD_SECRECY_GUIDE.md`.

**Settles:** Q-12. The ML-KEM ciphertext travels inside a classical outer layer in the slot (§4.3).

Names: **Bob** issues a card for his pending contact Carol. **Carol** imports it. A **card conversation** is their exchange of messages between redemption and the meeting. **Bootstrap** is the opening part of a card conversation, before both sides hold the full post-quantum material.

---

## 1. Keys

Each side holds its own set of the following for one relationship. None of them is the identity key, and none outlives the meeting (§7) or a discard (§6.7).

| Key | Kind | Held as | Lifetime |
|---|---|---|---|
| **Card agreement key** | `SecureEnclave.P256.KeyAgreement`, `.privateKeyUsage`, `WhenUnlockedThisDeviceOnly` | `dataRepresentation` blob in the card field (§5) | Until the meeting or a discard |
| **Card signing key** | `SecureEnclave.P256.Signing`, same policy | Blob in the card field | Same |
| **Card ML-KEM key** | `SecureEnclave.MLKEM1024`, same policy (not CryptoKit's default `AfterFirstUnlock`) | Blob in the card field (4,788 bytes measured) | Until the full post-quantum material is held (§4.2) |

**Why two P-256 keys, unlike the identity key.** The identity key is a tagged keychain item (`Manager.Key`), which `SecKey` uses for both ECDH and ECDSA. A tagged item per card would show how many cards exist in a keychain listing, and Q-05 rules that out. CryptoKit's Enclave keys create no keychain item, so the blob is the only copy, as with stage 1 prekeys. Each CryptoKit Enclave key is typed for either agreement or signing, which is why there are two.

**No prekeys on the card (decided 2026-10-16).** Contacts who met in person start the same way: they hold no prekeys for each other after the ceremony, and prekeys start flowing in their first messages (FORWARD_SECRECY_GUIDE, "two fallback messages each way bootstrap a new pair"). Card contacts do likewise:
- Carol's introduction carries her batch.
- Bob's first reply carries his.
- Until then, Carol seals to Bob's card agreement key (§4.3).

This replaces the 2026-10-15 decision to put a batch of 15 on the card, which gave card contacts better first-message protection than people who met in person, at the cost of:
- the prekey-ID linkage (§4.6);
- a trial over 15 keys if the IDs were hidden;
- a card tied into `PrekeyRecord`.

**The cost:** Carol's messages sent before she holds Bob's batch aren't forward-secret on Bob's side. Bob keeps his card agreement key until the meeting, so someone who later holds Bob's unlocked phone could open copies of those messages they saved. Ordinary contacts' first messages have the same property. The secrecy label says so (§6.5).

**OccultaCore addition.** `PostQuantumProvider` today hands out an in-memory handle (`generateKeyPair() -> privateKeyHandle: Any`), which is released after the ceremony. Cards need an ML-KEM private key that survives until the other side's ciphertext arrives. That requires two additions to the provider: a key that can be persisted as a blob, and decapsulation from that blob. Both are first-party, with no new dependency.

**Confirmed 2026-10-16** (`IntroCardEnclaveKeyPersistenceTests`, on an Apple Silicon Simulator with Enclave access). An Enclave ML-KEM-1024 key created with this policy reloads from its `dataRepresentation` after the original is released. It has the same public key and decapsulates to the encapsulator's shared secret. No software fallback is needed. CryptoKit's API is `SecureEnclave.MLKEM1024.PrivateKey(accessControl:)`, `.dataRepresentation` and `init(dataRepresentation:)`.

**iOS 26 at both ends** (Q-06). Below it, card creation is disabled and import fails (FINDINGS W-copy).

---

## 2. The card (wire, unbranded)

A card is a fixed **1,770-byte** binary blob. It has no magic bytes, no version byte, no extension and no file type (Q-04). It is shared as a file with a random 12-hex-character name.

| Offset | Size | Field |
|---|---|---|
| 0 | 65 | Card agreement public key, X9.63 |
| 65 | 65 | Card signing public key, X9.63 |
| 130 | 8 | Expiry, Unix seconds, UInt64 big-endian |
| 138 | 1,568 | ML-KEM-1024 encapsulation key |
| 1,706 | 64 | ECDSA P-256 signature, raw `r ‖ s` |

**Signing payload:** `"Occulta-introduction-card-v1"` ‖ bytes 0..<1706. The signature is made with the card signing key over that payload (CryptoKit hashes with SHA-256).

**Raw, not DER.** A DER signature is 70 to 72 bytes, so the card's length would vary.

**Recognition (Q-04 rule).** A file is a card if and only if all of the following hold:
- it is exactly 1,770 bytes;
- every public key parses as a valid P-256 point;
- the encapsulation key is a valid ML-KEM-1024 key: FIPS 203's modulus check, meaning every one of the 1,024 12-bit coefficients is below 3329, run on every iOS version (decided 2026-10-17). CryptoKit's `MLKEM1024.PublicKey(rawRepresentation:)` checks only the length on iOS 26.2, so a correctly signed card with a garbage key would otherwise be recognised and then fail when Carol encapsulates. `CardIntroduction.verify` applies the same check to Carol's key;
- the signature verifies under the signing key in the card.

The domain label appears only inside the signing payload, never in the file. A later card version gets a new label and its own check, tried in turn, with no version byte.

**Expiry** is the creation time plus 24 hours (Q-05). Import refuses an expired card. Bob's phone enforces the deadline (§6.4).

---

## 3. Messages in a card conversation

Every message in a card conversation uses the existing group format (`mode = .group`) with one recipient slot. Both sides run a build that supports cards, so the outer `version` is this build's current one (`.bodyDigestCapable` today). **No new `Version` or `Mode` case**: a card conversation's bundles carry the same visible fields as any 1:1 bundle.

Inside a card conversation, wherever the existing code uses the identity key, it uses the sender's card keys instead:

| Existing use | In a card conversation |
|---|---|
| `senderFingerprint = SHA-256(senderPub ‖ nonce)` | `senderPub` = sender's **card agreement** public key |
| `senderEphemeralSignature` (ECDSA over the slot's ephemeral public key) | Made with the sender's **card signing** key, DER as today |
| `senderProof = HMAC(sessionKey, senderLongTermPublicKey)` | The sender's card agreement public key |
| Long-term fallback ECDH (`longTermFallback` / `longTermNoPQ`) | ECDH between the two **card agreement** keys |
| `QuantumKeyMaterial` | Held in the card field (§5), not on `contactPublicKeys` |

---

## 4. Bootstrap and the post-quantum material (settles Q-12)

### 4.1 Why a bootstrap phase

After the ceremony, ordinary contacts already hold `QuantumKeyMaterial`: two ML-KEM shared secrets, one encapsulated each way. A card pair has none yet, so each side encapsulates once to the other's card ML-KEM key, and the ciphertext has to travel with the messages.

Delivery is manual and can arrive out of order. So **every bootstrap message from Carol is self-contained**: whichever one arrives first redeems the card.

The card carries no prekeys (§1). So Carol's bootstrap messages are sealed to Bob's **card agreement key**, ephemeral to static. Bob's bootstrap messages are sealed to the prekey batch in Carol's introduction, as any message to a contact with a batch is.

### 4.2 State on each side

| | Holds after | Sends bootstrap until |
|---|---|---|
| **Carol** | Import: `ss1, ct1` = Encapsulate(Bob's card ML-KEM key), done once. Her own ML-KEM key pair. | She opens any message from Bob: that gives her `ss2` (Decapsulate `ct2`). Then she holds full material and deletes her ML-KEM private key |
| **Bob** | Redemption: `ss1` = Decapsulate(`ct1`), then `ss2, ct2` = Encapsulate(Carol's ML-KEM key), done once. Full material from then on. Deletes the card ML-KEM private key | He opens a non-bootstrap message from Carol, which proves she holds `ss2` |

Full material maps onto the existing type with no change: `QuantumKeyMaterial(encapsulatedSecret, decapsulatedSecret, ourCiphertext, peerCiphertext)`.

### 4.3 Bootstrap slot layout

The `Recipient` is unchanged on the wire:

```
Recipient {
  secrecyContext { mode: .forwardSecret, ephemeralPublicKey, prekeyID }   // as any hybrid FS slot
  wrappedPayload = AES-GCM(K_outer, BootstrapLayer, AAD: blind)            // nonce ‖ ct ‖ tag
}

BootstrapLayer (binary) {
  mlkemCiphertext : 1,568 bytes                                           // ct1 from Carol, ct2 from Bob
  inner           : AES-GCM(K_inner, JSON(RecipientPayload), AAD: blind ‖ mlkemCiphertext)
}
```

**Carol's slots** are sealed ephemeral to static: `ecdh = ECDH(ephemeral, Bob's card agreement key)`.
- Their `prekeyID` is a **random** version-4 UUID. It names no key, and it fills a field that every forward-secret slot carries and readers expect: `deriveInboundKey` requires one.
- Nothing in the slot matches anything on the card.

**Bob's slots** go to a key in Carol's batch, as usual, or long-term between the card agreement keys if he has used her batch up.

**Keys.** `ecdh` is the slot's ECDH output. `own` and `peer` are the two 65-byte public keys, as in `forwardSecretSessionKey`.

| Key | Derivation |
|---|---|
| `K_outer` | `forwardSecretSessionKey(ecdh, own, peer, quantumMaterial: nil)`. Classical, `kTransportKeyInfo` |
| `K_inner`, Carol → Bob | `HKDF-SHA256(ikm: ecdh ‖ ss1, salt: peer XOR own, info: "Occulta-v2-card-bootstrap-2026")`, 32 bytes |
| `K_inner`, Bob → Carol | `forwardSecretSessionKey(ecdh, own, peer, quantumMaterial: QKM(ss1, ss2))`. The existing hybrid derivation, `kHybridFSTransportKeyInfo` |

**Why an outer layer, not a field.**
- A new `Recipient` field would make card bundles recognisable on the wire.
- The ML-KEM ciphertext isn't secret, so wrapping it classically costs no post-quantum strength. Everything secret is inside `inner`, under a key that mixes in an ML-KEM secret.
- `blind ‖ mlkemCiphertext` as the inner AAD binds the ciphertext to the payload.

**Why `mode: .forwardSecret`.** It matches an ordinary iOS 26 slot, so bootstrap bundles don't stand out, and the content is under a hybrid key. **The secrecy label isn't read from it for card slots.** Carol's slots, sealed to Bob's card agreement key, aren't forward-secret on Bob's side, so both phones label them **Standard Encryption**: Carol's compose before she holds Bob's batch, and Bob's view of them (§6.5). Claim no more than the design delivers.

**Opening.**
- A side still in bootstrap tries the ordinary hybrid slot key first, then the bootstrap layer. Both derive from the same ECDH output, so the second try is two HKDFs and a GCM check.
- **Bob** derives Carol's bootstrap slots from his card agreement key. He takes that path when the slot's `prekeyID` names none of his prekeys.
- A side out of bootstrap tries only the ordinary key, except that Carol also accepts a late bootstrap from Bob.

Nothing on the wire says which one it is.

### 4.4 The introduction (Carol's bootstrap messages)

A new optional field in `RecipientPayload`, decoded with `decodeIfPresent` like the fields added before it:

```
RecipientPayload.introduction: CardIntroduction? {
  agreementKey          : 65 bytes     // Carol's card agreement public key
  signingKey            : 65 bytes     // Carol's card signing public key
  mlkemEncapsulationKey : 1,568 bytes  // Carol's ML-KEM-1024 key
  signature             : DER          // Carol's card signing key
}
```

**Signing payload:** `"Occulta-card-introduction-v1"` ‖ SHA-256(Bob's 1,770 card bytes) ‖ `agreementKey` ‖ `signingKey` ‖ `mlkemEncapsulationKey`.

The card digest ties the introduction to this card, so it can't be replayed against another card. The signature ties Carol's agreement key to her signing key, which an agreement key can't do itself. Carol's prekey batch travels in the existing `RecipientPayload.prekeyBatch`. The slot's `senderEphemeralSignature`, made with the same signing key, authenticates it. **Every bootstrap message from Carol carries the identical introduction.**

### 4.5 Size (decided 2026-10-16: no padding)

A bootstrap slot is about 1.6 KB larger than an ordinary one, from the ML-KEM ciphertext. Carol's slots add the introduction on top, about 2.3 KB in JSON. Slots aren't padded to hide this.

**Decided 2026-10-16: no padding.** Anyone who can see these bundles on the channel has already seen the 1,770-byte card cross the same channel, so the size adds nothing they don't know. Padding every slot to bootstrap size would cost about 4 KB on every message from every contact, for no measurable gain.

### 4.6 Prekey IDs and the card (no longer applies)

Recorded 2026-10-16 while the card still carried 15 prekeys. Their IDs, printed on the card, would have appeared in the readable `prekeyID` of Carol's first messages: `SecrecyContext` is authenticated, not encrypted. So anyone holding the card could have picked those messages out.

**Removed with the prekeys** (§1, 2026-10-16). Carol's first slots carry a random `prekeyID`, and nothing on the card matches anything in a bundle. Testing a slot against Bob's card agreement key needs the ECDH output, so holding the card doesn't help.

---

## 5. The card field (at rest)

A new property, `Contact.Profile.introductionCardEncrypted: Data`, sealed with the local DB key like every other field.

**Codec**, modelled on `PrekeyRecordCodec`: `[0x01][UInt32 length][binary plist of CardState][zeros]`, always **N bytes**.

- **Never nil.** It is written when a contact is created and overwritten with the sealed empty state on delete. A launch migration writes it for every existing row, as `migratePrekeyRecords` did, so a NULL can't tell contacts apart.
- **Discarding a card overwrites** the field with the empty state, at the same size.
- **N is set by a size test** on the largest state, with distinct values everywhere (FORWARD_SECRECY_GUIDE mistakes 19 and 20). The provisional value is **12 KB**. Measured blob sizes: ML-KEM-1024 4,788 bytes, P-256 143 bytes each. The largest state, Carol's `imported`, comes to about 8.5 KB before plist overhead (card 1,770 + 2 × 143 + 4,788 + ss1 32 + ct1 1,568 + expiry). 12 KB leaves about 3 KB of margin. The sizes came from a Simulator, so the size test also runs on a device before release.

```
enum CardState {
  case empty
  case issued(       // Bob, card out and unused
      card: Data,                    // the 1,770 bytes, for "Share card…" again
      agreementKey: Data, signingKey: Data, mlkemKey: Data,   // Enclave blobs
      expiresAt: Date)
  case imported(     // Carol, until she opens Bob's first message
      peerCard: Data,                // Bob's 1,770 bytes: his card keys and ML-KEM key, and the digest for the introduction
      agreementKey: Data, signingKey: Data, mlkemKey: Data,   // Carol's blobs
      ss1: Data, ct1: Data, expiresAt: Date,
      sentFirstMessage: Bool)        // set on her first send; decides the sweep (§6.4)
  case conversation( // both sides, until the meeting or a discard
      agreementKey: Data, signingKey: Data,                   // own blobs
      peerAgreementKey: Data, peerSigningKey: Data,
      mlkemKey: Data?,               // Carol's, until she holds ss2
      quantum: QuantumKeyMaterial?,  // full material once held
      bootstrapOpen: Bool,           // still sending bootstrap (§4.2)
      peerIntroduction: Data?)       // Bob: Carol's introduction, to check duplicates
}
```

**What goes in `PrekeyRecord`** (no format change, and nothing until there's a conversation):
- **Carol** makes her own batch at import, as a pending own batch. It travels in her introduction.
- **Bob** makes his at redemption, once every check has passed, as `installFreshBatch` does after a long-term bundle. It travels in his first reply.
- Each accepts the other's batch as usual.

**Tier** (FINDINGS §3 table), computed from the field and never stored:
- `empty` with no `contactPublicKeys`: Pending exchange.
- `issued`: still Pending exchange.
- `imported` or `conversation`: Not verified.
- In-person keys: Verified.

---

## 6. Procedures

### 6.1 Create (Bob)

**Preconditions:** a pending contact, iOS 26, and a field that is `empty` or `issued`. An `issued` card is cancelled first (§6.2).

1. Generate the card agreement, signing and ML-KEM keys.
2. Build and sign the card (§2).
3. Store `issued`, then save.

Key generation is all or nothing: if any step fails, nothing is stored and no blob survives.

### 6.2 Cancel

Write `empty`. The blobs exist only in the field, so overwriting it deletes the keys.

### 6.3 Import (Carol)

1. **Recognise** the file (§2). **Refuse** it if it's expired, or below iOS 26.
2. **Attach** it to a contact Carol picks, or a new one. What happens depends on that contact's field (decided 2026-10-16):

   | Field | Result |
   |---|---|
   | any, when the card is one of the user's own (its agreement key matches an `issued` card on any contact, at any depth) | **Refuse** (W-18), checked first after expiry (decided 2026-10-17). Otherwise a person could start a conversation with themselves |
   | `empty` (pending) | Import |
   | `imported` (waiting on an earlier card from Bob) | **Replace.** Write the new `imported` state over the old one, which deletes its keys. Bob can only issue a card from a pending contact, so a new card means his side never got Carol's message, or he discarded the conversation |
   | `conversation` | **Refuse** (W-16). A card claiming to be from Bob must not replace a live conversation: anyone could send one |
   | `issued` (Carol's own card out to Bob: the cards crossed) | **Key order decides** (decided 2026-10-16). Compare the two cards' agreement public keys (X9.63, bytewise). If Bob's is lower, cancel Carol's card (§6.2) and import Bob's. If Carol's is lower, refuse (W-17): Bob's phone, importing Carol's card, makes the same comparison, cancels Bob's card and imports hers. Exactly one card survives, with no question asked. If only the side whose own card wins imports, it waits until the other imports or the cards expire |
3. **Generate** Carol's card agreement, signing and ML-KEM keys, and her own prekey batch.
4. **Encapsulate** to Bob's card ML-KEM key, which gives `ss1` and `ct1`.
5. **Store** `imported`, then save.

### 6.4 Expiry

- **Bob's phone** enforces it at receipt, at every depth (Q-03), and in the unlock sweep across every contact at every depth. An expired `issued` card is cancelled (§6.2).
- **Carol's phone** shows the deadline. It refuses to send a first message after `expiresAt`, so it doesn't send one that can't open.
- **Carol's phone clears a dead card in the unlock sweep,** at every depth: an `imported` field past `expiresAt` with `sentFirstMessage == false` is written `empty`, which deletes its keys and returns Bob's contact to Pending (decided 2026-10-16). The sweep does this, not opening the contact. A contact hidden at a duress depth may never be opened, and cleanup tied to viewing would be a write someone could observe.
- **If Carol sent something, her phone keeps the card.** She can't tell whether Bob opened it in time, and his reply can only be opened with her card keys and `ss1`. It stays until Bob's reply arrives, or until a new card from Bob replaces it (§6.3). There's no timer (decided 2026-10-16), so a slow reply is never cut off.
- **The deadline is when Bob opens the message, not when Carol sends it** (decided 2026-10-16). Carol's send time can't be trusted, because an interceptor would simply backdate it. So a message sent just before the deadline and opened just after fails. The copy says so: the first message "must reach Bob by {date}" (FINDINGS W-01, W-02, W-05, W-09). There's no grace period, which would only lengthen the window for an intercepted card.

### 6.5 Send

| Sender state | Slot |
|---|---|
| Carol `imported` (she holds no batch of Bob's yet) | Bootstrap layer with `ct1` and `introduction`, sealed ephemeral to static to Bob's card agreement key with a random `prekeyID`. **Labelled Standard Encryption** on both phones |
| Bob `conversation` with `bootstrapOpen` | Bootstrap layer with `ct2`. FS to Carol's batch, or long-term |
| Either side, `conversation` without `bootstrapOpen` | Ordinary hybrid slot using the stored material |

Carol's first send sets `sentFirstMessage`, saved before the bundle is handed to the share sheet. A bundle that may have left must never leave the card open to the sweep.

Any failure on these paths throws. A card contact never gets a classical-only or identity-key bundle in their place (FORWARD_SECRECY_GUIDE, "No silent security degradation").

### 6.6 Receive order

1. **Parse** the bundle.
2. **Identify the sender** by `senderFingerprint` across all contacts, hidden ones included. The candidate key is the identity key from `contactPublicKeys`, or the peer card agreement key from an `imported` field (Bob's, read from `peerCard`) or a `conversation` field.
3. **Matched:** open as today. A side in bootstrap uses §4.3's order.
   - **Bob** checks that a repeated introduction is byte-identical to the stored one, and rejects a bundle whose introduction differs.
   - **Carol** treats the first message she opens from Bob as `ss2`: she decapsulates `ct2`, stores full material and deletes her ML-KEM key.
   - **Bob** clears `bootstrapOpen` on the first non-bootstrap slot from Carol.
4. **No match: redemption.** For each contact whose field is `issued`, at every depth, and for each `.forwardSecret` slot:
   - Expired → cancel (§6.2) and go on.
   - Compute ECDH(card agreement key, the slot's ephemeral key), derive `K_outer` and try the bootstrap layer.
   - Decapsulate `ct1` with the card ML-KEM key to get `ss1`. Derive `K_inner` and open the inner layer.
   - Run the checks in this order:
     1. the introduction's signature against this card's digest;
     2. `senderEphemeralSignature` under the introduction's signing key;
     3. `senderFingerprint == SHA-256(introduction.agreementKey ‖ fingerprintNonce)`;
     4. `bodyDigest`, then the body.
   - **All pass:**
     - Encapsulate to Carol's ML-KEM key to get `ss2` and `ct2`.
     - Store `conversation` (`bootstrapOpen = true`, full material).
     - Delete the card ML-KEM key.
     - Accept Carol's batch. Generate Bob's first batch for her (§5), then save.
   - **A check fails:** the card stays `issued`, and nothing is consumed or generated.
5. **Nothing opened:** reject exactly as an unrecognised sender, at every depth.

Finding the card costs one ECDH per active card per slot. Cards expire after a day, so few are active at once. Someone holding a card can make Bob's phone do that work, and nothing more.

### 6.7 Discard (W-15, Bob)

Write `empty`. Drop the contact's inbound batch, own batches and accepted batch IDs from the record. The contact is Pending again.

---

## 7. Meeting check

It runs only when the exchange is started from a contact whose field is `conversation`, and **only after the ceremony's own confirmation succeeds**. A ceremony that fails gives no card verdict.

**Transcript.** Every value below is one both sides hold identically once the ML-KEM step completes (`HybridExchangeResult`):

```
T = SHA-256("Occulta-card-meeting-v1"
            ‖ sorted(identityKey_A, identityKey_B)
            ‖ sorted(nonce_A, nonce_B)
            ‖ sorted(mlkemCiphertext_A, mlkemCiphertext_B))
```

Each element is written as its length (UInt16, big-endian) followed by its bytes (decided 2026-10-17). The inputs are fixed-width today (65, 16 and 1,568 bytes), but without a length prefix, inputs of other lengths could produce the same transcript (testing found `("ab","c")` and `("a","bc")`). Sorting is on the raw element bytes.

**Proof message.** A new ceremony message, which every card-capable build sends:
- 64 bytes: a raw ECDSA signature by the card signing key over `"Occulta-card-meeting-proof-v1" ‖ T ‖ signerIdentityKey`;
- or, with no card conversation for this contact, 64 random bytes.

The signer's identity key in the payload stops a proof being reflected back to its sender. A random filler is indistinguishable from `r ‖ s`, so the message doesn't tell the person in front whether you have a card conversation with them.

**Verdict,** on a side with a card conversation:
- **The peer's proof verifies** under the stored `peerSigningKey`: **W-12**.
- **Otherwise: W-11.** That covers a filler, a bad signature, or no proof message from an older build. The real Carol always has a card-capable build.

**Either way:** the contact takes the identity keys and material from the ceremony, the card field is written `empty`, and the card batches are dropped from the record (§6.7's cleanup). Nothing about the verdict is stored (Q-10).

---

## 8. Hard blocks (FINDINGS §6)

One predicate: **the contact's field is `imported` or `conversation`.** Vault trustee, shard content, payment cards, identity challenge, Presence Verification and groups refuse when it's true.

Card keys never enter `contactPublicKeys`, so code that reads verified keys finds none. Each feature's refusal still needs a test of its own.

---

## 9. Duress (Q-03)

- **The card field lives on the contact,** so a card is at its contact's depth.
- **Receipt (§6.6) and expiry (§6.4) ignore the current depth.**
- **Every write keeps the field's size.**
- **A hidden contact's card opening at a duress depth** is the presence oracle accepted on 2026-08-13, with no new shape.

---

## 10. Interop vectors to record

These are recorded from the Swift implementation into `OccultaTests/Interop/InteropVectors.json` and never edited (see that file's `about`). Signatures are random, so the vectors pin signing payloads. GCM vectors use a fixed nonce, as the existing `gcm` kind does.

| Name | Kind | Pins |
|---|---|---|
| `card.v1.encoding` | new `card` | The 1,770 bytes from fixed keys and expiry, with the signature taken as input |
| `card.v1.signingPayload` | `signingPayload` | Label ‖ bytes 0..<1706 |
| `card.v1.introduction.signingPayload` | `signingPayload` | Label ‖ card digest ‖ the three keys |
| `card.v1.bootstrapKey.carol` | `fsKey` | `K_inner` from a fixed `ecdh`, keys and `ss1` |
| `card.v1.bootstrapLayer` | `gcm` | Outer and inner GCM with fixed keys and nonces |
| `recipientPayload.introduction` | `recipientPayload` | JSON with the `introduction` field |
| `card.v1.field.{empty,issued,imported,conversation}` | new `cardField` | The codec's bytes before sealing |
| `card.v1.meeting.transcript` / `.proofPayload` | `signingPayload` | `T` and the proof payload |

---

## 11. Tests

FINDINGS' action-item tests, plus these:
- A card that differs in any byte fails recognition, as does a file of 1,769 or 1,771 bytes.
- An expired card is refused at import and on arrival, at every depth.
- Redemption by the second, not the first, of Carol's bootstrap messages, followed by the first arriving: both open.
- Import into an `imported` contact replaces it and leaves none of the old keys. Import into a `conversation` contact is refused and changes nothing.
- Crossing cards (§6.3): when both phones import, exactly one card survives on both, the one with the lower agreement key. When one phone imports, its card is cancelled if the other card is lower, or the import is refused if its own card is lower.
- The sweep clears an expired `imported` field only when `sentFirstMessage` is false, at every depth, keeping the field's size.
- A bootstrap from a second sender with a different introduction on the same card is rejected after redemption.
- Carol's slots sealed to Bob's card agreement key carry a random version-4 `prekeyID` that matches nothing on the card.
- Carol's compose and Bob's view of her bootstrap messages show Standard Encryption. Both show Forward Secret once Carol seals to Bob's batch.
- A failed redemption leaves the card `issued` and generates nothing.
- Swapping only the card's ML-KEM key fails recognition (the signature covers it).
- `K_inner` (Carol) differs from both `K_outer` and the ordinary hybrid key for the same ECDH.
- Bootstrap ends on both sides exactly as in §4.2, including Bob's late bootstrap arriving after Carol is out of it.
- The card field is the same length in every state, before and after sealing.
- A proof filler and a real proof are the same length. W-11 for no proof message.
- Every §8 feature refuses `imported` and `conversation` contacts.
- A card agreement key's Enclave blob can't be loaded as a signing key, or the reverse. This needs a real Enclave. The two-key design doesn't depend on the answer, but if loading does work, one key could do both jobs later.

Card key creation needs a real Enclave and gets `.enabled(if: secureEnclaveAvailable())`. Everything else injects keys: codec, recognition, signing payloads, derivations, and the state rules.

---

## 12. Migration plan

| Stage | Change | Data |
|---|---|---|
| A | `introductionCardEncrypted` added to `Contact.Profile` (SwiftData lightweight, additive) | A launch migration writes the sealed `empty` state to every row, as `migratePrekeyRecords` did. No existing field changes |
| B | Card creation and import behind the iOS 26 gate | New rows only |
| C | Receive and send paths read the field | Behaviour changes only for contacts with a non-empty field |

**Rollback:** iOS can't downgrade an App Store build, and an older build never opens a newer store. A failed stage A migration leaves the field unwritten, which reads as `empty`. The next launch retries it.

---

## 13. Open items

- **N** (§5): set during the build by a size test on the largest state (Carol's `imported` state), with distinct values everywhere, plus a margin, rounded up to 4 KB. About 12 KB per contact is expected. Agreed 2026-10-16; this is a measurement, not a design question.
- **`PostQuantumProvider` persistence** (§1): API to add, with tests. The Enclave check passed on 2026-10-16 (§1), so no fallback decision is needed.

# Passphrase-Derived Layer Keys — Replacing PINs with Diceware Phrases

**Status:** Proposed, 2026-09-10. Not scheduled for `v1.11.0` — filed against a future **v2.0.0**.
Sequenced *after* the current Secure Mode simplification (`plan.md`'s removal-stages plan: drop the
blob mechanism and staged local-DB-key rotation, revert to pure UI-layer filtering — see that doc for
status). This document assumes that simplification has already landed: no blob, no staged-key rotation,
no `Manager.LayerStore`. It proposes a different, independent mechanism to close the gap that removal
deliberately accepts.

**v2.0.0 release plan, 2026-09-30 — `Docs/v2.0.0/`.** That folder holds this design as steps 1–5 of a
wider hardening plan: the steps around it, a proposed staged rollout, and a protection assessment. This
document stays the owner of the cryptographic design, and that folder owns sequencing.

**Sequencing precondition met, confirmed 2026-09-11 — see `bugs.md` Bug 119.** Removal Stages 0-4
shipped 2026-09-10; `Manager.LayerStore`, the staged-key protocol, and `RotationRegistry` are
confirmed gone (grepped, zero matches, repeatedly this session). The blocker §5 names is cleared —
§2's open structural question (per-row multi-key sealing without reintroducing Bug 109's tell) is the
next real design work, not this document's own sequencing gate. Bug 119 also grounds §0's framing
against the actual current `Key+Manager.swift` code (`createVaultSEKey`'s access-control flags,
`deriveVaultKey`'s literal HKDF inputs) rather than describing the gap abstractly, cross-references
Bug 62's Gap 2/residual-risk as a case this design closes as a side effect if built with non-editable,
high-entropy phrases, and names one concrete instance of §2's "every consumer needs re-auditing" cost:
`VaultManager.Backup.updateShardStatus`'s cross-depth BEK scan, which assumes one shared key today and
would need to route by `distributionID` instead under per-depth keys.

**Also closes Gap 3's trigger mechanism, not its deeper problem — Bug 62, re-examined 2026-09-11.**
`masterPINCollision` exists only because today's routing is array-comparison (scan
`sealedNormalVerifiers`/`sealedDuressVerifiers` for a match), which is what makes an accidental
6-digit collision (1-in-10⁶) a nameable, detectable event worth a special error case. Canary-based
per-depth authentication (§1) needs no equivalent setup-time check at ~90 bits — accidental collision
between two independently-generated phrases is ~1-in-2⁹⁰, not worth guarding against. No check, no
error, no oracle for a targeted wipe to respond to. **What this doesn't touch: Gap 3's own "deeper
structural problem"** — once the real depth-0 secret is known to a hostile party via direct
compulsion rather than probing, the app still can't distinguish that from the real owner's own
legitimate entry, and the Bug 13 hard-delete conflict this raises is identical regardless of secret
format. That part was never a guessing-difficulty question and isn't resolved by anything in this
document. Nothing here is a design
decision — findability and confirmation only; §2 remains unresolved.

**What this is.** A redesign of how Secure Mode's per-depth PIN gates content, replacing the numeric
PIN (today: pure UI-routing, contributes zero entropy to any encryption key) with a 6–7 word diceware
phrase that is an actual key-derivation input. The goal: make the key that decrypts a given depth's
sensitive content require something that is never present on the device at all, closing the AFU
(After-First-Unlock forensic extraction) gap discussed at length in this feature's own design history —
see the "how does the second attacker get the key" and "is it impossible if we pair ECDH with diceware"
exchanges that motivated this doc, both 2026-09-10.

**Why now, why not just harden the PIN.** Today's PIN is a verifier comparison only —
`Manager.Security.verify(pin)` checks it against `sealedNormalVerifiers`/`sealedDuressVerifiers` and
sets `state`/`currentDepth`. The actual local-DB key (`Manager.Key().createHybridLocalEncryptionKey()`)
is derived from a Secure Enclave ECDH plus a Keychain-stored random component — neither of which
involves the PIN at all, and neither of which needs a biometric, only "device unlocked." A forensic
tool with AFU-level code execution never has to pass the PIN check; it asks the SE and Keychain
directly, bypassing the app's own logic entirely. Swapping the PIN for a longer phrase *without* making
it a KDF input changes nothing here — the verifier is not what an AFU attacker interacts with. The
phrase only matters if it's mixed into the key itself.

---

## 1. Core derivation

For depth `D`, with the user's diceware phrase `P_D` for that depth:

```
passphraseComponent_D = Argon2id(
    password: UTF8(P_D),
    salt:     <32 random bytes, unique per depth per install, stored plaintext in AppLayerConfig —
               salts are not secret, they only need to be unique>,
    params:   <memory/time/parallelism — needs real tuning, see §4>
) → 32 bytes

seComponent_D = ECDH(depth_D_SE_privkey, G)   — same fixed-generator-point mechanism already used
                                                 throughout this codebase (Key+Manager.swift), one
                                                 SE key per depth, tag e.g. "layer.\(D).se.key.occulta"

layerKey_D = HKDF-SHA256(
    IKM:  passphraseComponent_D ‖ seComponent_D,
    salt: seComponent_D's own public key, x963 (binds to this depth's specific SE key generation),
    info: "occulta-layer-key-v1"
) → 32-byte SymmetricKey
```

Two components, two different guarantees: the SE half is device-binding (this key only derives on
*this* device, matching every other key in this app), the passphrase half is human-only (nothing to
extract from the device, full stop). Losing either half is enough to prevent derivation — an attacker
needs *both* the physical device (or its SE, which cannot leave it) *and* the phrase.

**No separate stored verifier.** Unlike today's PIN, correctness isn't checked by comparing against a
stored hash — a stored verifier is itself an offline dictionary-attack target, and for the numeric PIN
today that's fine because the entropy is low and the real protection is app-level lockout, not the
hash's strength. Here it would be the wrong tradeoff: a fast, separately-stored verifier hash would let
an attacker who's captured `seComponent_D` (trivial under AFU, as always) brute-force `P_D` against a
*cheap* comparison instead of against Argon2id's deliberately expensive one. Authentication instead
works the way LUKS/VeraCrypt volumes do: derive `layerKey_D` and attempt to open a small known-format
canary (or the depth's own header record); success means the phrase was right, failure means it wasn't.
This also removes the current design's dependency on lockout/rate-limiting *for security* — with ~78–90
bits of entropy behind a slow KDF, offline brute force is infeasible even with unlimited attempts and no
rate limit at all. (Lockout can still exist for UX/anti-shoulder-surfing reasons; it stops being the
thing actually holding the line.)

**Requirement, added 2026-09-29 (threat review): the SE must take part in every guess, not once.** As
written above, `seComponent_D = ECDH(SE_priv, G)` is a constant. Under AFU the attacker calls the SE once,
keeps the 32 bytes, and guesses `P_D` offline on a GPU farm — "needs both the device and the phrase" holds
for one call only, after which the device is irrelevant. This is today's `deriveSecureModeKey()` weakness
carried forward: that key is also a constant, which is why the current 6-digit verifiers fall in under a
second under AFU. Fix: feed the stretched phrase *into* the SE operation.

```
s_D           = KDF(UTF8(P_D), salt_D)                 — PBKDF2/Argon2id, as above
Q_D           = P256.KeyAgreement.PrivateKey(rawRepresentation: s_D).publicKey
seComponent_D = ECDH(depth_D_SE_privkey, Q_D)          — one SE call per unlock attempt
layerKey_D    = HKDF-SHA256(IKM: s_D ‖ seComponent_D, …) — as above
```

Every guess now needs the seized phone's SE, one at a time, at SE speed; nothing can be moved to a GPU farm
unless the SEP itself is broken. At 90 bits this is margin rather than the thing holding the line — but it
is exactly the margin that matters if the SEP does fall, and it costs one SE call per unlock. (`s_D` outside
the P-256 scalar range fails `rawRepresentation:`; probability ~2⁻³², handle by re-deriving with a counter.)

---

## 2. The open structural question: what does `layerKey_D` actually protect?

This is the part that isn't settled, and it's the crux of whether this proposal is simpler than what
it replaces or just differently shaped.

**Naively:** each depth's *own* sensitive content gets encrypted under `layerKey_D` instead of the one
shared canonical key every depth currently uses. That's what makes "compelling the duress phrase" only
reveal that depth's content — a real, structural partition, not a UI filter over uniformly-readable
storage. This is the actual point of the whole exercise; without it, this proposal degrades back to
"harder-to-guess PIN, same zero-entropy-contribution problem" from §0.

**But this reopens exactly the tell this feature's own history already found the hard way (Bug 109,
`bugs.md`).** If a row belonging to depth 2 is encrypted under `layerKey_2`, then someone holding only
`layerKey_1` (the duress depth they were compelled to reveal) who tries to decrypt it gets an
authentication failure — not silence, an *unmistakable, structural signal* that content exists which
their key doesn't open. Under the current (pre-removal) design this was one field on flagged contacts;
under a fully realized per-depth-key design it would be *every row not visible at the depth being
examined* — a much louder version of the identical problem.

**The fix is the same shape as `Manager.LayerStore`'s own filler-slot pattern** (`sealRandom`, fixed
32-slot array, real content indistinguishable from decoy without the key) — every row would need
*something* that opens cleanly under every depth's key, real content under the depths it belongs to,
random filler everywhere else, so decryption never fails, only decodes to nothing meaningful for the
wrong depth. That is a real, nontrivial per-row (or per-field) multi-key sealing scheme — structurally
close to what the blob array already did for contacts, generalized to arbitrary content and gated by
passphrase-derived keys instead of a single rotating-and-deleted one.

**Honest framing:** this proposal is not "the simple version of Design B." Done correctly — without
reintroducing Bug 109's tell — it converges on comparable structural complexity to the mechanism the
current removal plan is stripping out, trading "rotate a key forward and delete the old one" for "seal
content under N static per-depth keys with filler padding for every depth it doesn't belong to." What's
genuinely different, and the actual reason this is worth building despite that, is the primitive
underneath: a *human secret absent from the device* instead of *device-resident material with a
predictable deletion schedule*. That's a real upgrade in what the mechanism can promise against AFU
specifically. It is not a complexity discount.

**Verified 2026-09-12 — the storage shape this section lands on has a second, independent leak, orthogonal
to whether content-partitioning itself is airtight.** Checked directly across every per-depth-keyed object
currently shipped (`BackupEncryptionKey` rows; `AppLayerConfig`'s `sealedNormalVerifiers`/
`sealedDuressVerifiers`/`pinEnabledPerDepth` arrays; `VaultEntry.visibleThroughDepth`/`.deletionToken`;
`Contact.Profile`'s depth fields; `CustodyShard`/`ReconstructShard`/`PendingShardDistribute` rows):
**writing one depth's data never touches any other depth's stored bytes.** Exactly one thing currently
shipped does the opposite — `backup-export-meta.dat` (`ExportMetaSlotCodec`, `Vault+Manager+Backup.swift`),
which re-encodes and reseals its entire 32-slot blob under one fresh nonce on every write, so every byte
changes regardless of which slot's plaintext actually moved. Everything else — including the mechanism
this section sketches ("structurally close to what the blob array already did") — inherits the narrower
behavior quietly unless whoever builds it deliberately re-adopts the old array's actual
reseal-every-slot-with-fresh-nonces mechanism, which the codebase's current dominant pattern (rows, not
arrays) has dropped everywhere it was tried (`VAULT_KEY_LAYERING.md` item 7's own accounting of this exact
loss for BEK's rows — accepted there as a narrow, physical-reimaging-only risk).

The consequence is worse here than it was for BEK, given what this document is actually trying to buy:
two on-disk snapshots taken over time, diffed with no key at all, show exactly which depth's row (or slot)
keeps changing — and ordinary life happens overwhelmingly more often at the real depth than at any duress
depth, which exists only for the rare coercion window. An examiner watching write frequency across
snapshots doesn't need `layerKey_D` for any depth to guess which one is real; the *shape of the activity
itself* points there, independent of whether this section's content-partitioning and filler-padding end up
built perfectly. A design whose whole premise is "compelling one depth's phrase reveals nothing about any
other depth" needs this closed too, not just decryption-failure tells (Bug 109) — silence isn't free if the
silence has a rhythm.

**Not resolved here — this adds a second open requirement to whatever §2's eventual per-row/per-slot
mechanism turns out to be**, on top of the multi-key-sealing question already unresolved above: either
every depth's slot gets touched on every write (the old array's actual mechanism, at whatever storage-churn
cost that implies once derivation is human-passphrase-gated rather than free SE-only derivation), or some
other mechanism hides write-frequency-by-depth. Flagging, not deciding.

**Requirement, added 2026-09-26 (`bugs.md` Bug 123, closed as subsumed into Bug 119):** whatever re-seals
the small per-row fields under layer keys must also bind each ciphertext to its row and field, with an
AAD built from the row's `id` and a field tag, as `VaultEntry.aad(for:)` does for the content fields.
Today they all seal through `Data.encrypt(using:)` with one fixed AAD byte, so a value copied from one row
to another decrypts cleanly. That is harmless while any on-device code can use the local key and forge the
values outright, and becomes a real gap once it can't. Fields: `VaultEntry.visibleThroughDepth`/
`.deletionToken`, `BackupEncryptionKey.depth`/`.deletionToken`, `Contact.Profile.originDepth`/
`.visibleThroughDepth`/`.globalTrusteeDepth`, `PendingShamirSecretRestore.attributeID`/`.deletionToken`.
Doing it in the same migration costs nothing extra.

**Requirement, decided 2026-10-04: message keys must not route around the layer keys.** Sealing the
database under `layerKey_D` does not cover the keys that open messages. Without this requirement, a
surrendered duress phrase plus one keychain query exposes the hidden contacts that the rest of this
section hides.

*The leaks, against code at `732f4f3`:*
- Prekey private keys are Enclave keys tagged `prekey.<contactID>.<uuid>` (`Prekey.seTag`). Listing the
  keychain names every contact that has prekeys. A contactID absent from the surrendered depth is a
  hidden contact, and comparing images shows how often each one messages.
- An Enclave key is usable by anyone holding the passcode (`.privateKeyUsage`,
  `WhenUnlockedThisDeviceOnly`). A captured `.occ` carries `prekeyID` in the clear.
- What else the session key needs (`Crypto+Manager+KeyDerivation.swift`, `deriveInboundKey`):
  - `.forwardSecret` and `.longTermFallback` also mix in the contact's ML-KEM secrets, which are stored on
    the contact (`quantumKeyMaterialEncrypted`). Once the record is sealed under layer keys, a depth that
    can't see the contact can't open these messages. **These modes need no change.**
  - `.forwardSecretNoPQ` and `.longTermNoPQ` need only the prekey or the identity key, both usable with
    the passcode. **These are the gap.**

*Why prekeys stay in the Enclave.* Moving them into the contact's record would hide them behind the
phrase but break forward secrecy. Consider an image taken before a prekey is used, with the phrase obtained
after: the old image holds the sealed key, and the phrase opens it. Only an Enclave key is absent from
every image and gone for good once deleted. A deleted keychain item survives in an older image of the
keychain, which the passcode opens. So the fix keeps the Enclave key and makes *using* it insufficient
on its own, the way ML-KEM already does for its modes.

**Superseded for prekeys, 2026-10-06** (`Docs/Features/Prekey Continuity/DESIGN.md` §9, decision D9). An
Enclave key kept in the keychain is not "absent from every image". It is a wrapped blob stored on disk
(Apple DTS). Nothing documents that deleting it revokes an older copy, and the keychain records each item's
creation date and doesn't scrub deleted rows. Prekeys stay Enclave keys, but their wrapped blobs move into
the contact's sealed record, generated through CryptoKit. That requires the phrase as well as the passcode to
use an old copy, and it leaves no keychain items for items 2 and 3 below to hide. Item 1 is unchanged.

*The requirement:*
1. **Every classical-only pair gets a per-contact secret.** It is mixed into both the forward-secret and
   the fallback derivation, the same way ML-KEM's secrets are, and stored in the contact's record. New
   pairs derive it at the in-person exchange. Existing pairs exchange it in band, one forward-secret
   message each way, each side contributing half. After its prekey is consumed, an earlier image can't
   open that message. Until both halves arrive, the pair stays in the old mode. Sending in the new mode
   needs the peer's version to support it, through the existing `maxBundleVersion` negotiation.
2. **Prekey tags are random and name no contact.** *(Superseded by D9 above: new prekeys have no keychain
   item, and legacy ones retire within 30 days.)* The map from prekey ID to tag lives in the contact's
   record. Existing prekeys are retagged in place. Whether `SecItemUpdate` can change the tag of an
   Enclave key on a device needs checking first. `KeychainMigrationSETests` shows the Simulator can't be
   trusted for that kind of update. Deleting and regenerating instead strands messages already sent to
   the old prekeys (Bug 82).
3. **Random padding of the Enclave prekeys.** *(Superseded by D9 above, for the same reason.)* About 15 prekeys per contact otherwise reveals roughly how
   many contacts exist, hidden ones included. Each install creates a random number of dummy Enclave
   keys, indistinguishable from real prekeys.
   - **Created once, never touched.** The count is drawn once per install. No depth ever deletes or
     replaces a dummy, so no depth ever has to tell a dummy from a real prekey, and no list of dummies
     exists anywhere.
   - **What it hides:** in one image, the adversary sees the total but not the dummy count. Hidden
     contacts whose prekeys fit inside the random range pass as dummies. A range of 32–128, for example,
     covers about six hidden contacts holding a full batch each. The range is not decided.
   - **Build-up:** all dummies exist before any old `prekey.<contactID>.*` tag is retagged, so no image
     catches a partly built pool next to real tags. Enclave key generation time on an iPhone 11 decides
     whether that fits in one sitting. Measure it before choosing.
   - **Coverage:** every install gets the dummies, not only installs with duress depths. Rule 3 of the
     rollout plan applies for the same reason.
   - **Rejected 2026-10-04: replacing dummies at the end of each real-depth session.** It would make
     prekey changes that the surrendered depth can't account for look normal across repeated images. It
     was dropped because it adds almost nothing measurable:
     - Those prekey changes come only from a hidden contact's messages, and the transport's records
       usually show those messages anyway.
     - A session the adversary forces at a duress depth still shows that nothing was replaced.
     - It only matters if row changes between images are hidden too (the write-frequency requirement
       above).

     It would also have needed the real depth to work out which keys no record claims, to read
     coercer-created depths through a chain of stored child keys, and to round its counts. A
     fixed-size pool was rejected for the same reason: holding the total fixed means deleting dummies.

4. **The sender fingerprint is keyed with the per-contact secret (decided 2026-10-04).** Today it is
   `SHA-256(senderPublicKey ‖ nonce)` in the clear (`OccultaBundle.SecrecyContext.fingerprint`). Anyone
   holding the user's public key, which every contact has, can therefore attribute `.occ` files to the
   user wherever they turn up.
   - **The new tag** is an HMAC over a fresh nonce, keyed with the secret the two contacts share: the
     ML-KEM secret, or item 1's classical one. Only the two of them can compute it, and the recipient
     routes exactly as before, one computation per contact.
   - **Group format.** Every send since 1.9.0 uses it, a single contact included. Today a group file
     carries one outer fingerprint for all recipients. Instead, each `Recipient` entry carries its own
     tag, and the outer fingerprint is dropped. The `recipients` array already shows how many recipients
     there are, so per-entry tags reveal nothing new.
   - **Identity challenges** build the fingerprint separately (`IdentityChallenge+Manager.swift`) and get
     the same change.
   - **Mixed groups.** The outer fingerprint remains while any recipient in a file hasn't upgraded, so
     until then that file stays attributable.
   - **What it protects:** attribution of files that reach the adversary without the transport's records,
     such as files on a seized contact's phone, moved through Files, or forwarded. Where the transport's
     records exist, they already show who sent what.

*Open, not decided. None of these is accepted:*
- Messages from senders on old versions, in the classical-only modes, open with the passcode until both
  sides support item 1.
- The transport's own records (who sent which file to whom, and when) show that a relationship exists. An
  ongoing two-way exchange with a contact the surrendered depth doesn't show can't pass as a deleted
  contact. That is outside the app.
- Across repeated images, prekeys the surrendered depth can't account for disappear and appear. A new
  batch for a hidden contact shows up as about 15 new keys.
- In one image, hidden contacts beyond what the random padding covers make the total stand out.

---

## 3. Duress compatibility

Each depth needs its own independently-memorized phrase (mirrors today's per-depth verifier array —
`sealedNormalVerifiers`/`sealedDuressVerifiers` already have this shape, just swap "PIN" for "phrase").
Compelling one depth's phrase derives exactly that depth's key and nothing else — assuming §2's
content-partitioning is actually built, this is where the duress property genuinely holds
cryptographically rather than by UI convention. Setup flow needs to make clear to the user that each
layer's phrase is independent and none of them can recover another.

**Requirements, added 2026-09-29 (threat review):**
- **Every depth's phrase has the same length.** Shortening duress phrases because "they get surrendered
  anyway" is a tell: an attacker cracks the short ones offline, and the one depth that holds out is the real
  one. Uniform strength is part of indistinguishability, not a nicety.
- **Phrases are app-generated and not editable.** User-chosen phrases collapse the entropy the numbers in §4
  assume. Confirmation in the shape of a BIP-39 seed check (already in §4's Recovery paragraph).

---

## 4. Practical constraints

**No native Argon2id.** This codebase deliberately ships zero third-party crypto dependencies — the one
SPM dependency (`swift-crypto`) was removed in `v1.10.3` specifically because it added nothing over
CryptoKit (see `CLAUDE.md`'s Build & Test section). CryptoKit and CommonCrypto do not provide Argon2id.
Two real options, not yet chosen between:
- Vendor and audit a pure-Swift Argon2id implementation — reopens exactly the dependency-risk question
  this project has been deliberately avoiding, just as source instead of SPM.
- Use PBKDF2-HMAC-SHA256 via `CommonCrypto`'s `CCKeyDerivationPBKDF` (natively available, zero new
  dependencies) with a high iteration count. Weaker than Argon2id against GPU/ASIC parallel attack
  (PBKDF2 is not memory-hard), but consistent with the project's existing crypto posture. Iteration
  count needs real analysis against current hardware, not a guessed constant.

This tradeoff should be settled deliberately, not defaulted into — it's a straight security-vs-dependency-
purity call for whoever builds this.

**Sized 2026-09-29 (threat review) — at 7 words, PBKDF2 is enough; at 6 it is not.** 7776-word list, 12.9
bits/word; PBKDF2-HMAC-SHA256 tuned to ~1 s on the slowest supported device (iPhone 11, A13), assumed ~1M
iterations — measure, don't trust that constant. Expected time to crack, order of magnitude:

| Attacker | 6 words (77.5 bits) | 7 words (90.5 bits) |
|---|---|---|
| 1M RTX-4090-class GPUs | ~400,000 years | ~3 billion years |
| All of Bitcoin's SHA-256 throughput, hypothetically repurposed (absurd upper bound) | **~3.5 years** | ~27,000 years |

The second row is the one that matters for a state-level threat model: custom SHA-256 hardware exists at
that scale, and PBKDF2 is not memory-hard. So the choice is **7 words + PBKDF2** (no new dependency) or
6 words + Argon2id — not 6 words + PBKDF2. §1's "~78–90 bits … infeasible" holds at the top of that range
only. The SE-per-guess requirement in §1 would keep both rows off-device entirely; the table is the
fallback if the SEP is broken.

**UX — no more silent derivation.** Today's SE-only key derives automatically, gated only by device
unlock; nothing prompts the user for anything beyond Face ID. A passphrase-gated key can't work that
way — Argon2id (or even a well-tuned PBKDF2) is deliberately slow, so it can't run on every field
decrypt. The derived `layerKey_D` needs to be cached in memory for a session, the same shape
`VaultManager`'s `LAContext`-gated key already uses, with the same bounded-exposure caveat already
flagged in this conversation: a live memory-inspection-capable AFU exploit could still catch a cached
key mid-session, same as it could today.

**Requirement, added 2026-09-29 (threat review): phrase entry must leave no keyboard trace.** Words typed
into an ordinary text field are learned into the iOS keyboard's dynamic lexicon — a standard forensic
artifact that survives the app's own data. Seven diceware words there leak the secret itself *and* signal
that something is being hidden. Entry must go through `isSecureTextEntry` or an in-app word picker built
from the wordlist, with autocorrect, predictive text, and paste off. Nothing about the phrase may reach the
pasteboard, logs, or state restoration snapshots. This is a forensic-trace requirement in its own right, and
it applies whichever way the rest of this document is settled.

**Recovery.** Forgetting `P_D` makes depth `D`'s content permanently unrecoverable — no biometric
fallback, no Apple ID reset path, nothing. This is a materially different risk profile from the current
"lose the device, Face ID gets a new one back in" story, and needs explicit setup-time UX (a
confirmation flow in the shape of a BIP-39 seed-phrase check, not just "type it once and hope") and
clear user-facing warning copy. A forgotten depth-2 phrase does not need to endanger depth-0 or depth-1
— each depth's loss is independent, matching §3.

---

## 5. Sequencing

Not started. Depends on the current removal-stages plan (`plan.md`) landing first — building this on
top of the still-present blob/rotation machinery would mean maintaining two parallel key-hierarchy
concepts at once. Once removal lands, the next real design work is §2: settle whether/how per-row
multi-key sealing is built, since that decision determines whether this is a moderate feature addition
or a rebuild of the same scale as what's being removed.

**Proposed staged rollout, 2026-09-30 — `Docs/v2.0.0/ROLLOUT_PLAN.md`. Not decided.** If adopted, it
replaces the single migration assumed above. The migration splits by data: the vault first, then
contacts, then the remaining depth-stamped records. It never splits by requirement: each slice gets §1,
§1's Enclave-per-guess requirement, §2's every-depth sealing, its write-frequency requirement, and the
row and field AAD, all at once. Every depth on a device migrates in one step. The phrase replaces the
PIN for every lock user, not only for users with duress depths. §2 remains the blocker. Design it for
vault and contacts together, even though the vault would ship first.

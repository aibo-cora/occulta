# Passphrase-Derived Layer Keys — Replacing PINs with Diceware Phrases

**Status:** Proposed, 2026-09-10. Not scheduled for `v1.11.0` — filed against a future **v2.0.0**.
Sequenced *after* the current Secure Mode simplification (`plan.md`'s removal-stages plan: drop the
blob mechanism and staged local-DB-key rotation, revert to pure UI-layer filtering — see that doc for
status). This document assumes that simplification has already landed: no blob, no staged-key rotation,
no `Manager.LayerStore`. It proposes a different, independent mechanism to close the gap that removal
deliberately accepts.

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

---

## 3. Duress compatibility

Each depth needs its own independently-memorized phrase (mirrors today's per-depth verifier array —
`sealedNormalVerifiers`/`sealedDuressVerifiers` already have this shape, just swap "PIN" for "phrase").
Compelling one depth's phrase derives exactly that depth's key and nothing else — assuming §2's
content-partitioning is actually built, this is where the duress property genuinely holds
cryptographically rather than by UI convention. Setup flow needs to make clear to the user that each
layer's phrase is independent and none of them can recover another.

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

**UX — no more silent derivation.** Today's SE-only key derives automatically, gated only by device
unlock; nothing prompts the user for anything beyond Face ID. A passphrase-gated key can't work that
way — Argon2id (or even a well-tuned PBKDF2) is deliberately slow, so it can't run on every field
decrypt. The derived `layerKey_D` needs to be cached in memory for a session, the same shape
`VaultManager`'s `LAContext`-gated key already uses, with the same bounded-exposure caveat already
flagged in this conversation: a live memory-inspection-capable AFU exploit could still catch a cached
key mid-session, same as it could today.

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

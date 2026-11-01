# OccultaCore: Open Items

Defects and deferred work for the package. Numbered `OC-n` so they don't collide with the repo-wide `Bug n`
sequence in `Docs/Features/Secure Mode/bugs.md`; if one is fixed, record it there as a Bug and point to it from
here. "Open, needs a decision" means nobody has decided it: it is not accepted.

---

## OC-1: `TransportKeyDerivation` does not check `ecdhOutput`'s length (fixed)

**Status:** Fixed 2026-11-01, on `v2.1.0/transport-key-derivation-throws`, not merged. Recorded as Bug 191 in
`Docs/Features/Secure Mode/bugs.md`; the entry below is what was found. Found when the function was extracted
(step 2); recorded 2026-10-31.

**Fix.** `sessionKey` now `throws(TransportKeyDerivation.Error)` instead of returning `nil`. It rejects
`ecdhOutput.count != 32` with `invalidECDHOutputLength`, and the other three checks each throw their own case, so a
caller sees which input was wrong. The app's callers use `try?` and are unchanged. Why it throws, and what it
costs: `decisions.md`, 2026-11-01.

**What happens.** `sessionKey` checks both public keys (65 bytes) and, in the hybrid form, both ML-KEM secrets
(32 bytes), and returns `nil` otherwise. `ecdhOutput` it takes as given. HKDF accepts any input length, so an
empty `ecdhOutput` is not rejected: in the classical form the IKM is empty and the key is a function of the salt
(two public keys) and the label alone, which an observer can compute. In the hybrid form it leaves the key resting
on the ML-KEM secrets alone. A short or wrong-sized output derives a key just as quietly.

**Who is exposed.** Every Occulta caller passes 32 bytes (the file's review block, 4.7), and the interop
vectors pin that. A host app is exposed if its ECDH call returns something else (an error path that yields empty
`Data`, the raw shared point where the X9.63 output was meant, a different requested size). The README tells a
host app to pass exactly 32 bytes, which is a comment standing in for a check.

**Options.**
- Reject `ecdhOutput.count != 32` and return `nil`, as the other inputs are. It changes no recorded vector (they
  are all 32) and needs one test per wrong length. A caller that passes a size other than 32 on purpose, if one
  exists, would start getting `nil`; none is known in the app.
- Leave it and keep the sentence in the README and the review block.

**Not decided here.** The first costs a few lines and makes the function consistent. Whether it also needs an app
change (the callers already handle `nil` for the other inputs) has not been checked beyond the call sites listed
in SPEC §6.

**Test added with the fix.** In `OccultaCoreAPITests/TransportKeyDerivationTests.swift`, next to the existing
length rejections: `ecdhOutput` of 0, 16, 31, 33 and 64 bytes throws `invalidECDHOutputLength`, classical and
hybrid, and the `ReadmeExamplesTests` transport example still passes.

---

## OC-2: Occulta's non-card ML-KEM key arrivals do not run `MLKEMKeyCheck`

**Status:** Open, needs a decision. Observed 2026-10-31 while documenting the package; call sites read the same
day. Not a downgrade.

`MLKEMKeyCheck`'s own comment tells a host app to run it where a peer's key arrives. In Occulta only
`OccultaFormats` calls it (`IntroductionCard` and `CardIntroduction`, for the card's ML-KEM key). `encapsulate`
returns `nil` for a key CryptoKit refuses, and CryptoKit checks only the length, so a malformed 1,568-byte key
reaches `encapsulate()` and fails there. What each caller of `encapsulate(peerPublicKeyData:)` does:

- **The in-person exchange** (`Exchange+Manager.swift`, the identity handler): the one peer key that arrives
  unchecked. On `nil` the handler returns. It does not take the classical branch, which is entered only when the
  peer sent no ML-KEM key, there is no provider, or there is no private key. So a malformed key stalls the
  exchange rather than downgrading it. The residual is the user experience: the exchange stops with no error.
- **Introduction cards** (`ContactManager+Cards.swift`): keys the card format has already checked. Import throws
  `CardError.keyGenerationFailed`; the meeting path skips the entry.
- **The tier PQ records** (`Key+Manager.swift`, `KeyManagerProtocol.swift`) and **share staging**
  (`ShareStagingKeyManager.swift`): encapsulate to a key pair generated on the spot, never a peer's. They throw or
  return `nil`, and never store a classical record in place of a hybrid one.

**The decision:** whether the exchange should run `MLKEMKeyCheck` when the identity arrives, so a malformed key
fails the exchange with an error the user sees instead of stalling it. The security outcome is the same either
way.

---

## OC-3: Hybrid seal/open is deferred

**Status:** Deferred 2026-10-31, until a host app needs it. Not a defect.

Why it was deferred is in `decisions.md`, "Step 3". The design settled before the deferral, so it isn't
re-derived:

- `seal` and `open` take `TransportKeyDerivation`'s inputs and return `AES.GCM.SealedBox.combined` as one `Data`.
- The ML-KEM secrets are pre-shared: no per-message KEM ciphertext in the blob.
- The blob has no version byte, no magic and no post-quantum marker.
- The caller states the post-quantum mode by passing or omitting the secrets. The function never infers it from
  the blob.
- The host's version goes in its label (`info`).
- Never trial-decrypt across keys: AES-GCM is not key-committing, so a message can open under more than one.

Until then, the README shows the host app's own AES-GCM call on `TransportKeyDerivation`, with the header as
authenticated data, and `ReadmeExamplesTests` keeps it compiling.

---

## Not filed, for the record

- The doc comments of `PostQuantumProvider` and `ShamirSecretSharing` name Occulta internals (`ExchangeManager`,
  `VaultManager.Backup.verifiedKey`), and the review blocks name `SaltInfo` and `PrekeySecretsManager`. They are
  comments, not compiled in, and the label policy (decisions.md) is about what a host app's binary and wire
  traffic carry. Rewording them is a choice for whoever prepares the package for copying out; the code does not
  need it.

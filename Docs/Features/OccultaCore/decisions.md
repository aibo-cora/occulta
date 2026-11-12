# OccultaCore: Decisions

What was decided about the package, when, and what it costs. What exists today is in [SPEC.md](SPEC.md); open
items are in [bugs.md](bugs.md). The repo-wide index is `Docs/General/decisions.md`, which points here.
When one of these is revisited, add a dated note under it instead of rewriting it.

Format: Decision, Why, Consequences. All dated 2026-10-05 unless the entry says otherwise.

---

## License stays AGPL-3.0

**Decision:** The modules are licensed like the app, AGPL-3.0. An app that links them must be AGPL-3.0 and publish
its source.

**Consequences:** GPL-family terms clash with App Store distribution, so closed-source and App Store adopters are
ruled out. The README says so at the top. This is a limit on who can adopt it, accepted as the price of the
license, and is not a reason to relicense.

## API scope: primitives only

**Decision:** The public product, `OccultaCore`, holds primitives: Shamir, the post-quantum provider, the ML-KEM
key check and the transport key derivation. Occulta's wire and at-rest formats stay app-only in `OccultaFormats`,
because they carry Occulta-identifying constants (the `OCCB` magic, the `occulta-signed-attribute-v2` prefix).
Host apps manage their own keys and do not interoperate with Occulta. The contact-exchange protocol is deferred to
the Android work, and the full contact book is not offered.

**Why:** A host app that used the formats would put Occulta's name in every message it sends, and the formats are
useless to it without Occulta's key management.

**Consequences:** A second app gets building blocks and writes its own envelope. Anyone who wants to read
Occulta's formats from another platform reads `Docs/` and `OccultaTests/Interop/InteropVectors.json`, not this
package.

## Label policy: the host chooses its labels and key tags

**Decision:** A host app passes its own HKDF `info` and its own key tags. Nothing Occulta-named lands in a host
app. Occulta's own labels (`SaltInfo`) are wire format and never change.

**Why:** The label is the function's only domain separation, and a shared label is a shared key space. Occulta's
labels also name Occulta in anything derived with them.

**Consequences:** `TransportKeyDerivation` has no label of its own to default to. Occulta's doc comments in the
source still name Occulta internals (SPEC §8); the compiled target contains no Occulta-named string.

## Two modules, not `@_spi`

**Decision:** The boundary between the public API and the app-only formats is a module boundary: `OccultaCore` and
`OccultaFormats`, with the dependency running one way.

**Why:** `@_spi` hides a symbol from autocomplete and not from the binary, and one `import` is all that separates
a host app from the formats. A module the host does not link cannot be imported by accident, and
`--explicit-target-dependency-import-check error` makes the API tests prove it.

**Consequences:** Two products and two import lines in the app. The check in SPEC §7 has to keep running in CI.

## No public signer (step 6, verified 2026-10-31)

**Decision:** The package offers no signing API.

**Why:** Step 6 was checked on 2026-10-31 and nothing in the primitives called for one. The reasoning is not
recorded beyond that; if a host app asks for a signer, decide it then and write the reasoning here.

**Consequences:** A host app calls Security.framework or CryptoKit itself.

## Step 4: checked reconstruction, no share type

**Decision:** Shamir's public reconstruction is `reconstruct(shares:maxAttempts:isCorrect:)`, the Bug 95 subset
search moved from `VaultManager.Backup.verifiedKey`. There is no share type; a share is `[UInt8]`. The unchecked
reconstruction is `internal`.

**Why:** Interpolation returns a wrong secret without throwing when a share is bad, so an API that offers it
unchecked offers a way to get a wrong key silently. Moving the search keeps one implementation of the order,
cap and zeroing that Bug 95 pinned (`Docs/General/decisions.md`, "Recover past poisoned shares by subset search
against the GCM tag"; moved 2026-10-13).

**Consequences:** Every caller must have something to check against. The result is as strong as that check, and
**AES-GCM is not key-committing**: a check built on a GCM tag over ciphertext an attacker supplied can be
satisfied by ciphertext crafted to open under two keys. That is documented on the function and in the README. A
share's 33-byte shape is a convention callers must keep.

## Step 3: hybrid seal/open, deferred (2026-10-31)

**Decision:** Not built, until a host app needs it. `TransportKeyDerivation` is the stopping point: a host app
builds its own AES-GCM call on it, as Occulta does.

**Why:** No Occulta path could use such a function, so there is nothing to extract and nothing to test it
against. The only exact match is the legacy receive-only long-term path. Every live transport path authenticates a
header, and the main ones need the session key beyond one seal: streamed bodies (one key, many chunks), the
group HMAC sender proof, and the per-recipient key wraps.

**Consequences:** The design was settled before the deferral and is recorded in bugs.md OC-3 so that it
isn't re-derived. Nothing is built.

## `sessionKey` throws typed errors instead of returning nil (2026-11-01)

**Decision:** `TransportKeyDerivation.sessionKey` is `throws(TransportKeyDerivation.Error) -> SymmetricKey`. The cases
are `invalidOwnPublicKeyLength`, `invalidPeerPublicKeyLength`, `invalidECDHOutputLength` and
`invalidPostQuantumSecretLength`, checked in that order, and they carry no data. `ecdhOutput` must now be 32 bytes.

**Why:** `nil` could not tell a caller which input was wrong, and the one input nothing checked, `ecdhOutput`, was the
one whose absence made the key computable from public values (bugs.md OC-1; Bug 191). Fixing the missing check with
another `nil` would have left a host app guessing. The cases carry no associated values so that no key bytes can end
up in an error, a log or a crash report.

**Consequences:** A public API break, taken now because no host app uses the package. The app's callers (`Manager.Key`,
`TestKeyManager`, the card code, `PQTestKeyPair`) use `try?`, so they return the same `nil` as before, no new error
text reaches the UI or a log, and no interop vector moves. A caller that passed an `ecdhOutput` of another size on
purpose would now get an error; none is known. `PostQuantumProvider`'s optional returns are a separate question, not
decided here.

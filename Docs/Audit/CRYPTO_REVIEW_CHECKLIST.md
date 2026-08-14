# Occulta Crypto Review Checklist

**What this is:** a design-time review applied to *one cryptographic path*, producing a written artifact that lives in the code at the decision point. It is not a release gate.

**Relationship to [`SECURITY_CHECKLIST.md`](SECURITY_CHECKLIST.md):** that document is a binary pre-release sweep over invariants of already-shipped code. This one runs **before implementation**, on a change, and its output is prose reasoning rather than a tick. Both are required; neither substitutes for the other.

**Output:** a comment block at the top of the file or immediately above the function that owns the path, in the format under [Recording the review](#recording-the-review). Two exemplars are live in the codebase and are the reference for tone and depth:

- `Occulta/Features/Vault/ShamirSecretSharing.swift:9-48` — SSS Math Path
- `Occulta/Services/Key+Manager.swift:615-644` — Vault Key Derivation Path (v2)

---

## When this is required

Run it before writing code that does any of the following:

- Introduces or changes a **signing domain prefix**, or adds a category/type within an existing signed family
- Creates a new **Secure Enclave key**, or changes the access control on an existing one
- Adds or changes a **key derivation** (HKDF, ECDH, any KDF input)
- Changes the **byte layout of a signing payload**, or how one is canonicalized
- Touches **prekeys**, forward secrecy, or the hybrid PQ path
- Creates a new **signed artifact that crosses a trust boundary** to another device or party
- Changes **encryption at rest** — what is sealed, under which key, with which AAD

It is **not** required for UI changes that display already-verified material, for test-only code, or for refactors that provably do not alter any byte on the wire or at rest. If you are unsure whether a refactor qualifies, it qualifies.

**Nothing merges without the block.** A path whose answer to a section is genuinely "none" records that explicitly — see `Key+Manager.swift:640`, *"No prekey public keys involved. Checklist item 4.6: N/A."* Silence is not an answer.

---

## 1. Key ownership map

**Answer, for every key the path touches:**

1. Its type and custody — SE-resident, software, or ephemeral-in-memory.
2. Its keychain tag, if persistent, and confirmation the tag is not shared with another purpose.
3. Whether the private half is extractable. If it is software-held, say what wraps it.
4. Whether the public half is stored or exported, and what harvest surface that creates.
5. **"Key material shared between contacts: yes/no."** Answer this literally — both exemplars do.

**Rules:**

- The Secure Enclave is the mandatory root for signing. A software key may *add* unforgeability but must never be sufficient alone.
- One tag, one purpose. Reusing a tag across purposes is a finding, not a shortcut.
- A private key is never exported, never leaves the device, and never crosses a process boundary.
- Purpose-scoped keys are for *derivation and encryption*. Introducing a second **signing** key requires justifying why the identity key cannot serve — and the justification must survive §4.3.

## 2. Consumption events

**Answer:**

1. What material in this path is one-time-use, and what consumes it.
2. When consumption occurs relative to the operation succeeding, and whether deletion is immediate or deferred.
3. Which buffers hold plaintext key material after the call returns, and who is responsible for zeroing them — name the call site.
4. Whether the operation is **idempotent** and, where it releases something, **one-way**.
5. Whether the key is re-derivable on demand or lost once consumed.

**Rules:**

- Deferred cleanup of consumed key material is a finding. Delete at the point of successful use.
- Zeroing responsibility is documented at the call site that owns the buffer, not left implicit — see `ShamirSecretSharing.swift:15`, which pushes it to `prepareShards` by name.
- Any release of secret material to another party must be one-way and idempotent: replaying the release must not produce additional material, and must not roll back state.
- Failure paths delete what success paths delete. Say so explicitly.

## 3. Multi-party trace

**Answer:** a worked example with named parties, showing what each holds at each step, and what a party who is *not* the intended recipient can compute. The exemplars use "2-of-3 with contacts Bob, Carol, Dave" — follow that concreteness.

1. Who receives what, in order.
2. What is provably distinct between recipients (distinct evaluation points, distinct ciphertexts, distinct prekeys).
3. What a recipient learns about *other* recipients.
4. What an attacker holding some subset below the threshold can compute.
5. Whether any two parties can ever hold identical material.

**Rules:**

- **Per-device pools are never shared.** Prekey batches scoped to one device must not be reused for another — this is the historical prekey-batch flaw and is the reason this section exists as its own step.
- Two recipients holding identical secret material is a finding unless the design explicitly requires it and §4 states the consequence.
- Malformed input from a peer is rejected, not repaired. Duplicate-index and duplicate-identity checks belong in the code, not in the assumption.

## 4. Security property verification

The most-cited section. Answer each sub-item, or record it N/A with a reason.

**4.1 — The property, in one sentence.** What is claimed to hold, stated so it could be falsified. *"(k−1)-out-of-n perfect secrecy plus correct reconstruction with exactly k or more shares"* is the standard.

**4.2 — Attacker bound.** What an attacker holding less than the threshold actually sees. State whether the bound is information-theoretic or computational — they are not interchangeable and the difference belongs in the block.

**4.3 — Domain separation and cross-protocol safety.** The item every ruling in `Master Feature & Expansion Analysis.md` cites.

- A new artifact type gets a **new, versioned domain prefix**, or a new category *inside* the signed payload of an existing family. Both are valid; mixing them is not.
- Prefixes are never changed once shipped. Changing one invalidates every artifact signed under it.
- Existing signing paths are never modified to accommodate a new one.
- The signing payload must be **unambiguously parseable**: every variable-length field carries an explicit length prefix. Bare concatenation of two variable-length fields is a finding — `"AB"∥"C"` and `"A"∥"BC"` produce identical bytes, and where those bytes name a destination or a recipient, that is a substitution vector.
- Fields that select meaning — a category, a type, a rail — go **inside** the signed bytes. See `SignedAttribute.swift:20`: *"Including `category` prevents a category-substitution attack."*
- **Never sign an attacker-supplied digest with the identity key.** A path that signs externally-provided bytes requires a dedicated key with a distinct tag.
- Any unsigned digest the design relies on gets its own domain string, distinct from every signing prefix, so no signing path can ever emit bytes equal to it.

**4.4 — Harvest-now posture.** Whether a public key or ciphertext produced here is durable enough to be worth harvesting, and what happens when P-256 falls. State whether the path is in scope for hybrid PQ (`#23`) and why. Note that hybrid signatures defend the quantum case only — a software PQ key wrapped under an SE-derived key falls with the SE.

**4.5 — Access control and device binding.** Write out the **actual** `SecAccessControlCreateWithFlags` flags and accessibility class, not the intended ones.

> This sub-item exists because assuming a gate that is not there has happened. The identity key is `[.privateKeyUsage]` with no biometric flag (`Key+Manager.swift:94-97`), so identity-key signing is silent on an unlocked device — a property that was asserted backwards in a feature design before anyone read the constructor. If your block says "biometric-gated," quote the flags.

Also state: whether the key is invalidated by biometric re-enrolment (`.biometryCurrentSet`), whether a passcode path exists, and whether an `LAContext` is cryptographically enforced by the key's own policy or is merely an application-level check. The second is not a security property and must not be described as one.

**4.6 — Prekey public keys.** If the path publishes, consumes, or stores prekey material:

- One-time use is enforced, and the private half is deleted from the SE immediately on successful `open()`.
- Pools are scoped per device and never shared (§3).
- Exhaustion falls back to long-term ECDH, never to plaintext, and piggybacks a fresh batch.
- A prekey public key is never mistaken for, or substituted into, an identity-key position.

If no prekey material is involved, record: *"No prekey public keys involved. Checklist item 4.6: N/A."*

**4.7 — Not achieved.** The explicit list of properties this path does **not** provide. Both exemplars carry one, and it is the most valuable line in each. Authentication, forward secrecy, post-quantum resistance, replay resistance — name what is absent, so a later reader does not assume it.

## 5. Layer boundary check

**Answer:**

1. Input and output types.
2. Every external call the path makes.
3. Confirmation that the file contains no SwiftData access, no UI, and no `KeyManagerProtocol` calls if it is a pure-math path.
4. How it is tested without a real Secure Enclave.

**Rules:**

- Pure crypto files take and return plain types (`Data`, `SymmetricKey`, `[[UInt8]]`) and touch nothing else.
- SE access lives in `Key+Manager`, not scattered across feature code.
- Unit tests use `TestKeyManager` only. A test that requires the real SE is a test that will not run in CI.
- Per `CLAUDE.md`, every implementation carries unit tests; for crypto paths that includes the failure and rejection cases, not only the happy path.

---

## Recording the review

A comment block at the decision point, using this exact header so it is greppable:

```swift
//  CRYPTO_REVIEW_CHECKLIST — <Path Name>
//  ════════════════════════════════════════
//  1. Key ownership map
//     - …
//
//  2. Consumption events
//     - …
//
//  3. Multi-party trace — example: <concrete named scenario>
//     - …
//
//  4. Security property verification
//     - …
//
//  5. Layer boundary check
//     - …
```

Name the path, not the file — *"SSS Math Path,"* *"Vault Key Derivation Path (v2)."* Version the name when the path changes in a way that breaks compatibility, so the block and the wire format stay in step.

Keep it at the decision point. The 2026-06-10 repo audit singled these blocks out as the practice worth keeping precisely because the reasoning sits where the decision was made, not in a document nobody opens.

---

## Gate

- [ ] All five sections answered, or explicitly N/A with a reason
- [ ] §4.3 answered for every new or changed prefix, category, or payload layout
- [ ] §4.5 quotes the actual access-control flags
- [ ] §4.7 lists what is *not* achieved
- [ ] Block committed in the same change as the code it describes
- [ ] Unit tests cover the rejection paths named in §3

**Reviewed by:** ___________________
**Path:** ___________________
**Date:** ___________________

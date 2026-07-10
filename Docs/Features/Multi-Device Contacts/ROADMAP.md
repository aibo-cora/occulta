# Device-Bound, Recoverable Through People — Release Roadmap

**Status:** Strategic plan, pre-R0
**Date:** 2026-07-05
**Scope:** Three-year feature arc: Owner Device Set → Guardian Revocation → Passkey Provider → Recovery Layer

---

## Executive Summary

Occulta's core thesis is *identity anchored in hardware and physical presence instead of servers*. This roadmap extends that thesis across three dimensions:

1. **Device Set (R1):** Two of your iPhones become one attested identity. Losing one is an inconvenience, not an identity death.
2. **Guardian Revocation (R2):** Losing *all* devices kills your keys, not your contacts' trust in a ghost. Physical contacts you've verified can revoke your identity on your behalf.
3. **Passkey Provider (R3–R4, optional):** Extend device-bound identity to service logins. The moat engages when recovery flows through physically verified humans.

The invariant, stated once and enforced everywhere: **private keys are *never* recoverable** — not passkey keys, not identity keys. "Recovery" means exactly three things:
- (a) **Sibling credentials** already live on your other Device Set member
- (b) **Identity continuity** — contacts keep trusting you because your surviving device is cross-signed
- (c) **Fast re-enrollment** — the encrypted ledger of *what* to re-enroll survives through guardians

---

## ⚠️ Constraint Alerts — introduced by this feature set, mitigated in the plan

### 1. ASCredentialIdentityStore leaks your RP list to the system

**Problem:** The standard way to register QuickType suggestions is `ASPasskeyCredentialIdentity` records (RP ID + username) into the system credential store. That store lives outside the hybrid-DB-key envelope — only iOS data protection. Your list of accounts is metadata visible to the system.

**Mitigation:** Never register identities by default. The provider still works for passkey requests without them (the system routes `ASPasskeyCredentialRequest` to enabled providers by RP ID matching against our own encrypted store). QuickType registration becomes an explicit, documented opt-in toggle labeled with exactly this trade-off (R3, Step 7).

### 2. The extension must never gain access to the identity key or the main local DB key

**Problem:** The naive implementation moves the existing Keychain items into a shared access group so the extension can decrypt. This widens the blast radius of the entire contact graph to a second process for no reason — the extension never needs contacts.

**Mitigation:** A **second, independent hybrid store** ("passkey store": its own SE ECDH-with-G key + its own Keychain random component, new `info` string `occulta-passkey-store-v1`) lives in the shared access group. `master.key.privacy.turtles.are.cute` and the main DB key components stay app-private. Hard isolation, enforced by access-group membership (R3, Step 2).

### 3. Biometric ACL choice is a lockout vector

**Problem:** `kSecAccessControl` with `.biometryCurrentSet` invalidates every passkey SE key the day the user re-enrolls a fingerprint — self-inflicted total credential loss.

**Decision:** `.userPresence` (biometric with passcode fallback) as default, `.biometryCurrentSet` as an expert toggle with an explicit destruction warning. This is a deliberate, documented trade, not an accident (R3, Step 4).

### 4. Guardian escrow of the RP ledger reveals your account list under K-of-N collusion

**Problem:** Not keys — keys are unrecoverable by design — but "which services this person uses" is sensitive metadata.

**Mitigation:** Information-theoretically safe below K shares (Shamir), disclosed honestly at opt-in, and the escrow is off by default (R4, Step 3).

### 5. Release-build logging in a new process

**Problem:** The extension is a fresh target that won't inherit your `#if DEBUG` discipline automatically.

**Mitigation:** Extend the banned-log list (RP IDs, usernames, credential IDs, user handles) to the new target; `#if DEBUG` only, CI-enforced (R3, Step 9).

### 6. PQ gap on secondary devices (temporary, visible)

**Problem:** A contact's messages to your second device are classical-path until that device obtains ML-KEM material. This is a real security-property delta.

**Mitigation:** Never fake the badge. Secondary devices display "PQ: classical path only" per-device in the contact detail view. R1.1 uplift: device B's ML-KEM encapsulation key travels to the contact *inside* the existing PQ-protected channel through device A — transitive protection (R1, Step 9).

### 7. Two SDK verifications before committing

1. `SecureEnclave.P256` key usage from within an `ASCredentialProviderExtension` via shared access group — expected to work, verify on-device.
2. Whether cross-device (hybrid QR/BLE) passkey requests route to third-party providers on the current SDK.

Neither blocks R1/R2 (R3, Step 10 gate).

### 8. Hybrid device-set signatures are opportunistic, not guaranteed

**Problem:** `SecureEnclave.MLDSA65`/`MLDSA87` (iOS 26+, ML-DSA-capable SE only) let the device-set cert carry a PQ signature alongside the classical one — but the app floor for R1 is iOS 16 + U1. Most set members won't have PQ-capable hardware for years, and public keys/signatures are far larger than P-256 (ML-DSA-65: ~1952-byte public key, ~3309-byte signature).

**Mitigation:** Hybrid signing is additive, never required — see R1 Step 2. The `hybridCapable` flag lives *inside* the classically-signed payload so a relay can't silently strip the PQ signature and downgrade a capable device without also breaking the classical signature (same anti-downgrade shape as the bundle's existing "explicit unsupported error, never silent fallback" rule). Wire-size growth is bounded to sets that actually negotiate hybrid, and stays inside the existing optional-sub-envelope budget (R0, Step 4).

---

## Release Sequencing

| Release | Ships | Feature | Floor | Flag |
|---|---|---|---|---|
| R0 | Design gates only | Protocol review (no code) | — | — |
| R1 | 2026 Q4 | Owner Device Set | iOS 16 + U1 (both) | `enableOwnerDeviceSet` |
| R2 | 2027 Q1 | Guardian Revocation Custody | iOS 16 | `enableGuardianRevocation` |
| R3 | 2027 Q2 | Passkey Provider | iOS 17 | `enablePasskeyProvider` |
| R4 | 2027 Q3 | Recovery Layer (coverage + escrow) | iOS 17 | `enableRecoveryLedger` |
| R5 | 2027 Q4+ | Guardian Succession (gated, exploratory) | iOS 18+ | — |

R1's floor (iOS 16 + U1) is the *classical* cert path. Hybrid ML-DSA signing (Alert #8) is an opportunistic upgrade negotiated per-device on iOS 26+/ML-DSA-capable SE — it does not raise the feature floor.

### Sequencing Rationale

Passkeys ship *third*, not first — shipped alone they inherit the lockout objection that caps device-bound adoption. **The recovery substrate (R1, R2) must exist before the credential feature that depends on it.** Device Set without revocation is a half-told recovery story. Guardian Succession is exploratory and gated pending full R0-style review.

---

## R0 — Design Gates (one sprint, zero code)

No implementation begins until these gates pass. Each section is a separate checklist owned by a single owner, reviewed independently.

### 1. Run CRYPTO_REVIEW_CHECKLIST.md end-to-end

Separately, for each of the three new protocols:
- Device-set certificates (R1)
- Guardian revocation (R2)
- Passkey issuance/assertion (R3)

Per house rule, **no cryptographic code before all items check**. The §3 multi-party traces that matter most:
- Prekey pools across *own* devices (the historical batch-sharing flaw now has a new way to reoccur — device A and device B must never share pools for the same contact)
- Shard distribution to N guardians

### 2. Register domain prefixes in one place

Extend the `SaltInfo`/constants pattern:
- `occulta-device-set-v1`
- `occulta-device-revocation-v1`
- `occulta-identity-revocation-v1`
- `occulta-revocation-wrap-v1`
- `occulta-passkey-store-v1`

Every future signature verification rejects cross-prefix input — same mandate as `IDENTITY_CHALLENGE_PROTOCOL`.

### 3. Write the threat-model delta doc per feature

Write **before** implementation (checklist §4: state what is NOT achieved). The four honest deltas:
- PQ gap on secondary devices (encryption)
- PQ gap on device-set certs when either device lacks ML-DSA SE support (signing, iOS 26+ only — Alert #8)
- Guardian collusion metadata exposure
- Passkey hardware-binding is user-verifiable, not RP-attestable

### 4. Wire-format rule confirmation

Everything below travels as **optional sub-envelopes on `SealedPayload`** riding `v3fs` + existing modes. **No new `Version` or `Mode` cases** — the `OccultaBundle` comment is the law. Old builds decode, ignore the unknown field, render nothing, break nothing.

---

## R1 — Owner Device Set

**Goal:** Two of your iPhones become one attested identity; losing one is an inconvenience, not an identity death.

### 1. Ceremony

Reuse `ExchangeManager` wholesale: MC session, `NIDiscoveryToken`, ≤0.25m gate, Diceware confirm — between your own two devices. New session-type flag only. Both devices require U1 (iPhone 11+, no SE-model iPhones); the NFC fallback from the Master Analysis can extend coverage later, not now.

### 2. Certificate format (hybrid: classical + opportunistic PQ)

Payload, biometric-gated: `prefix ∥ certVersion ∥ peerDevicePubKey ∥ peerDeviceMLDSAPubKey? ∥ hybridCapable ∥ exchangeNonce ∥ timestamp`.

- `peerDeviceMLDSAPubKey` is present iff the signing device's Secure Enclave supports `SecureEnclave.MLDSA65` (iOS 26+, ML-DSA-capable hardware). `hybridCapable` is the same boolean, carried *inside the signed payload* — not inferred from field presence alone.
- Each device SE-signs this payload twice: `classicalSignature` (`SecureEnclave.P256`, always) and, iff `hybridCapable`, `pqSignature` (`SecureEnclave.MLDSA65`).
- Bidirectional — the set exists only when both certs verify (classical, and PQ where claimed). Nonce comes from the ceremony (replay-dead). Requiring biometrics on *both* devices during one UWB session is the anti-evil-maid property: an attacker holding your unlocked phone cannot enroll their device without your face/finger, twice.

**Anti-downgrade property:** because `hybridCapable` is bound inside the classically-signed payload, a relay cannot strip `pqSignature` to force silent classical-only fallback without also invalidating `classicalSignature`. A cert claiming `hybridCapable = true` with a missing or invalid `pqSignature` is rejected outright — never silently downgraded (§5).

### 3. Storage

New optional SwiftData fields, default `nil`, on your own identity record: set-member public keys + certs, encrypted under the hybrid local DB key like everything else. Lightweight migration per the model-evolution rules.

### 4. Distribution to contacts

New optional `deviceSet: DeviceSetAnnouncement?` on `SealedPayload`, piggybacked on the next outbound bundle to each contact — the exact pattern `prekeyBatch` and `identityChallenge` already use.

### 5. Contact-side acceptance rule (the security core)

Accept a set member if and only if the cert verifies under a key *already pinned* for that identity. Never transitive, never from an unpinned key. Cap set size (4). Surface every set change through the Compromise Detection UI path — a device addition is exactly the event that feature exists to make visible.

Verification order:
1. Verify `classicalSignature` against the pinned P-256 key — mandatory, unconditional. Fail closed if this fails, full stop.
2. If `hybridCapable` is true, `pqSignature` must also be present and verify against `peerDeviceMLDSAPubKey` — reject the whole cert if either is missing or fails. Do **not** fall back to classical-only in this case (that's the downgrade hole §2 closes).
3. If `hybridCapable` is false, accept on the classical signature alone and badge the member "PQ: classical path only" in the device-set UI (same honest-badge pattern as the encryption gap, §9/Alert #6).

Net effect: forging or suppressing a device's PQ-capable status requires breaking the classical P-256 signature, not just the PQ one — an attacker can never silently downgrade a hybrid-capable member.

### 6. Encryption to a set

Reuse the shipped `useMultipleRecipientMessageFormat` capsule array: one session key, wrapped per set-member key. Each member is an independent crypto recipient.

### 7. Forward secrecy per device (highest risk, highest oversight)

Each set member maintains its own prekey pools per contact; SE tags already scope by `contactID` — extend scoping so pools are per-(contact, own-device) and write the §3 trace test proving device A never consumes or ships device B's prekeys. 

**This is the one place this plan can recreate the documented historical prekey flaw.** Spend the most careful design hours here.

### 8. Intra-set revocation

Surviving device live-signs `occulta-device-revocation-v1 ∥ lostDevicePubKey ∥ timestamp` (it has an SE — no pre-signing needed) and distributes via the same envelope. Contacts drop the revoked key immediately; UI: "Alex removed a device."

### 9. PQ posture

Ship R1 with secondary devices on the classical path, badged per-device in the contact detail view ("PQ: classical path only"). 

R1.1 uplift: device B's ML-KEM encapsulation key travels to the contact *inside* the existing PQ-protected channel through device A — transitive protection, matching the documented transitive model — with direct PQ restored at the next physical meeting. Never fake the badge.

### 10. Tests + gate

Mirror OCCULTA_TEST_PLAN structure:
- Input validation (cert length, off-curve keys, oversized ML-DSA fields)
- Tamper table (flipped cert fields → signature fail)
- Hybrid-specific cases: `pqSignature` stripped with `hybridCapable = true` → reject (not classical-fallback); `hybridCapable` flipped false with a valid `pqSignature` still attached → reject (classical signature no longer matches payload); `peerDeviceMLDSAPubKey` swapped for another device's PQ key → `pqSignature` fails
- Attack scenarios (unpinned-key cert injection, cross-identity cert replay, set-size overflow DoS, device A/B prekey isolation)
- Mandatory old/new build fixture tests — a v1.3 build must decode a set-carrying bundle (classical-only *and* hybrid) and render the message untouched, ignoring the PQ fields entirely

Fixtures into CI permanently.

---

## R2 — Guardian Revocation Custody

**Goal:** Losing *all* devices kills your keys, not your contacts' trust in a ghost.

### 1. Pre-signed certificate

At enrollment, SE signs `occulta-identity-revocation-v1 ∥ identityRootPubKey ∥ issuedAt`. Revokes the identity — all set members — terminally.

Plaintext of this cert never persists; it is generated, wrapped (step 2), split (step 3), and discarded in one flow.

### 2. Encrypt-to-knowledge wrap

`AES-GCM(cert, key: HKDF(identityRootPubKey, info: "occulta-revocation-wrap-v1"))`.

Anyone can relay the blob; only holders of your public key — people you physically met — can open it. Broadcasting leaks nothing to non-contacts: no graph, no identity, random bytes. This is what makes guardian *distribution* metadata-clean.

### 3. Split and distribute

Shamir K-of-N over the wrapped blob's key material using the shipped SSS implementation, delivered through the existing `ShardOperation` protocol (`.distribute` / `.acknowledge` / `.revoke` are already in `OccultaBundle`) — near-zero new wire surface.

Constant-time GF(2^8) path already exists per the Master Analysis notes.

### 4. Guardian release flow

Guardian-side UI: "Alex reports total device loss" → release shard to a coordinating guardian → K shards reconstruct → broadcast wrapped blob to the guardian's own full contact list (safe per step 2).

Recipients verify the SE signature against their pinned key and mark the identity revoked-pending-re-exchange.

### 5. Abuse containment

K-of-N is the defense against a coerced or malicious guardian; the worst achievable outcome is a forced re-exchange — denial of convenience, never confidentiality loss. State this in the threat-model delta and the guardian-selection UI.

### 6. Consumption discipline

Release is one-way and idempotent:
- Duplicate shard release is a no-op
- A revocation seen twice is a no-op
- A revocation for an already-re-exchanged identity still displays (terminal actions don't race)

### 7. Tests + gate

- Shard round-trip under `TestKeyManager`
- Wrap/unwrap by holder vs. non-holder
- K−1 shards yield nothing
- Tampered cert → signature fail
- Replay idempotence
- Old-build fixture (ShardOperation path already tolerates unknown attributes — prove it stays true)

---

## R3 — Passkey Provider

**Goal:** SE-bound WebAuthn credentials with the isolation model from Alerts #1–#3.

### 1. Target + entitlements

New `ASCredentialProviderExtension` target: AutoFill Credential Provider entitlement, app group, and one **new** keychain access group for passkey artifacts only.

Main app gates all UI behind `#available(iOS 17, *)` (app floor stays iOS 16).

### 2. Isolated passkey store

Second hybrid store: fresh SE key (tag `passkey.store.root`) ECDH-against-G + fresh Keychain random component, both in the shared group, HKDF info `occulta-passkey-store-v1`.

Encrypts RP records (rpID, user handle, username, credentialID, creation date).

**The main DB key and identity key never enter the shared group** — enforce with a unit test that asserts access-group membership of every Keychain item at launch in DEBUG.

### 3. Per-credential SE keys

`SecureEnclave.P256.Signing.PrivateKey`, tag `passkey.<credentialID>`, `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`.

`credentialID` = 16 random bytes from `SecRandomCopyBytes` — never derived from key material.

### 4. ACL decision

Default `.userPresence`; expert toggle for `.biometryCurrentSet` with a destruction warning:

> "Re-enrolling Face ID permanently destroys these credentials."

Document the trade in-app, not just in code.

### 5. Registration path

Handle `ASPasskeyCredentialRequest` (registration):
- Honor `excludedCredentials`
- authenticatorData with AT+UV flags, zero AAGUID, COSE ES256 public key
- Attestation format `none` (we cannot produce Apple-rooted attestation — the honest limitation, now a code comment)

### 6. Assertion path

authenticatorData ∥ clientDataHash signed by the credential's SE key, DER out, `signCount = 0` constant — matching platform-authenticator behavior and avoiding cross-device counter state.

(A small number of strict enterprise RPs dislike 0; documented, accepted.)

### 7. QuickType off by default

RP matching runs against our encrypted store inside the extension. The `ASCredentialIdentityStore` opt-in lives in settings with the metadata disclosure written out.

### 8. No network, provably

Extension target compiles with zero networking symbols; CI gate greps the extension binary's imports for `URLSession`/`Network`/`CFNetwork` and fails the build on a hit. Privacy nutrition label unchanged.

### 9. Logging

Extend the banned-log list (RP IDs, usernames, credential IDs, user handles) to the new target; `#if DEBUG` only, CI-enforced.

### 10. Tests + gate

- WebAuthn vector tests (registration object decodes per spec, assertion verifies against extracted COSE key)
- Tamper table (wrong rpID → no credential surfaced; clientDataHash substitution → RP-side verify fails)
- Duplicate-registration/excluded-credential handling
- ACL behavior on device
- **Two SDK verifications from Alert #7 signed off on hardware** before this gate passes

---

## R4 — Recovery Layer (the actual promise)

### 1. Coverage ledger

Per-credential device-coverage map inside the passkey store, synced between set members through the encrypted channel (they're contacts of each other, cryptographically).

Dashboard: "12 of 14 accounts covered on both devices."

### 2. Dual-enrollment nudges

WebAuthn credentials are minted only in an RP ceremony, so the second device can't self-provision — the honest mechanism is a nudge:

> "GitHub has a passkey only on this iPhone — add one from your iPad at next sign-in"

Deep-linking where RPs support it.

### 3. Ledger escrow (opt-in)

Ledger blob encrypted under a fresh key; key Shamir-split to guardians via the R2 machinery; blob stored alongside each shard.

After total loss: K guardians → ledger plaintext → you know exactly what to re-enroll on the new device via each RP's recovery flow.

**Keys were never in the blob; nothing here can violate the invariant.**

### 4. Total-loss runbook

In-app and rehearsable:
1. Revoke via guardians (R2)
2. Restore ledger (R4.3)
3. Re-exchange with contacts physically
4. Re-enroll passkeys from the ledger

A recovery path users have never rehearsed is a recovery path that fails; ship a dry-run mode.

---

## R5 — Guardian Succession (gated, do not commit yet)

New device gets fresh UWB ceremonies with K guardians who co-sign a succession statement linking new key to revoked identity.

Proximity-rooted, but it changes the trust-acceptance rule for every contact — advisory-only UI ("endorsed by 3 people *you* have physically verified"), never silent key replacement.

**Full R0-style checklist cycle and its own threat-model doc before a line of code.** If the design review can't hold the "never silent" property, it stays unshipped.

---

## Cross-Release Exit Criteria

Every release must verify:

1. **Checklist gate re-run** against the as-built design
2. **Fixture decode** of every prior shipped version green in CI
3. **Zero new plaintext at rest** (audit the SwiftData schema diff)
4. **Zero new cleartext wire fields** (audit the bundle diff — everything rides inside `SealedPayload`)
5. **Locked `info` strings untouched** (domain prefixes are final once shipped)
6. **Threat-model delta doc merged with the code**

---

## Trade-off Analysis: Why Hesitation Is Partly Correct

### The Two Great Reasons To Ship This

**First: usage frequency.** Occulta's core loop is episodic (you exchange keys occasionally, encrypt files occasionally). Episodic apps get deleted in storage purges. Passkeys are the opposite: five to twenty touchpoints a day. An app you authenticate with daily is an app that survives on the phone long enough for the proximity contact book to become valuable. That's a retention engine for the mission.

**Second: unique moat.** Device-bound passkeys alone are commodity — 1Password could use them tomorrow. The moat only engages when recovery flows through physically verified humans: Device Set enrollment is a UWB ceremony, guardians are people you've stood next to. The defensible product isn't "passkeys," it's "your service logins inherit your human trust graph."

### The Decent Reason That Doesn't Fully Justify It

Philosophical coherence. If Occulta's thesis is "identity anchored in hardware and physical presence instead of servers," passkeys extend that thesis to services. But notice the thesis has to be restated to make passkeys fit — the original framing ("authentication between people") is sharper, and under that framing passkeys are a detour.

### The Honest Case Against

A credential provider is the **largest attack surface and support burden** of anything in this roadmap — a second process, a shared keychain group, per-RP WebAuthn quirks, AutoFill edge cases, and lockout tickets. For zero-vulnerability posture, that's expensive real estate.

You'd also be fighting a free platform default, which is a brutal conversion funnel.

Every hour spent there is an hour not spent on the duress cluster, Wi-Fi Aware, or document signing — features that serve the people-to-people thesis directly and have documented demand.

### The Recommendation

**Skip passkeys for now, and lose nothing by doing so.** R1 and R2 serve identity-between-people on their own merits (device loss and revocation are unsolved problems in your core product today). Ship those because they complete the mission.

If, a year from now, retention data says you need a daily-use hook, the passkey substrate will already exist and the decision becomes cheap. Building the recovery layer first and deferring the credential layer isn't a compromise — it's the version of this roadmap where every shipped line serves the thesis you just articulated.

---

## References

- [FINDINGS.md](FINDINGS.md) — Design sessions and resolved open questions
- [Master Feature & Expansion Analysis](../Master%20Feature%20%26%20Expansion%20Analysis.md) — Broader product roadmap context
- [CRYPTO_REVIEW_CHECKLIST.md](../../Audit/CRYPTO_REVIEW_CHECKLIST.md) — Protocol review gate (R0)

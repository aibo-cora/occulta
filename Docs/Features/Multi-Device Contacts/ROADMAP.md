# Device-Bound, Recoverable Through People — Release Roadmap

**Status:** Strategic plan, pre-R0. **R1's scope was narrowed 2026-07-10 — see note below.**
**Date:** 2026-07-05 (R1 scope revised 2026-07-10)
**Scope:** Three-year feature arc: Multi-Device Contacts → Guardian Revocation → Passkey Provider → Recovery Layer

> **2026-07-10 scope decision:** the "backup phone that just works across your whole contact list" ambition originally driving R1 is **shelved**, not built. The secure design (direct physical re-pairing per contact — see R1 below) makes that promise hold only for a handful of close contacts someone is willing to re-meet in person; for a real contact list, the cost of re-pairing with everyone outweighs the convenience of a second device. That's not a flaw in this design specifically — it's structural, the necessary price of Occulta's no-vouching invariant, and no better version of it exists. What remains in scope: the underlying data-model fix (concurrent device keys, so re-pairing a second device no longer *silently overwrites* the first device's access to a contact — a real defect today). No UX investment is planned to promote or streamline broad multi-device adoption. Full reasoning: [FINDINGS.md](FINDINGS.md), Design Session 5.

---

## Executive Summary

Occulta's core thesis is *identity anchored in hardware and physical presence instead of servers*. This roadmap extends that thesis across three dimensions:

1. **Multi-Device Contacts (R1, narrowed):** *Not* a flagship "backup phone that just works" feature — that ambition is shelved (see note above). What ships: a data-model fix so pairing a second device with a contact adds a key instead of silently overwriting the first device's. If you *do* re-pair a second device directly with a contact — the same ceremony as first contact, no vouching, no shortcut — both stay valid for that contact. No UX is built to encourage doing this broadly.
2. **Guardian Revocation (R2):** Losing *all* devices kills your keys, not your contacts' trust in a ghost. Physical contacts you've verified can revoke your identity on your behalf.
3. **Passkey Provider (R3–R4, optional):** Extend device-bound identity to service logins. The moat engages when recovery flows through physically verified humans.

The invariant, stated once and enforced everywhere: **private keys are *never* recoverable** — not passkey keys, not identity keys. **A second, equally strict invariant governs trust itself: no mechanism may grant trust to a new key except a fresh physical UWB exchange; only revocation may travel by signature alone, because narrowing trust is always safe and granting it never is** (see [FINDINGS.md](FINDINGS.md), Design Sessions 3–4 — an earlier cert-vouching design for R1 was rejected on exactly this principle). "Recovery" means exactly three things:
- (a) **Sibling credentials** already live on your other device, independently, because you physically re-paired it with each contact
- (b) **Identity continuity** — contacts who've physically verified more than one of your devices keep trusting whichever one survives, because neither depended on the other
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

### 6. Two SDK verifications before committing

1. `SecureEnclave.P256` key usage from within an `ASCredentialProviderExtension` via shared access group — expected to work, verify on-device.
2. Whether cross-device (hybrid QR/BLE) passkey requests route to third-party providers on the current SDK.

Neither blocks R1/R2 (R3, Step 10 gate).

### 7. Multi-device re-pairing doesn't scale with contact count — accepted, not mitigated

**Problem:** Holding the no-vouching invariant (see Executive Summary; [FINDINGS.md](FINDINGS.md) Design Sessions 3–4) means adding a device requires physically re-pairing it with every contact individually — there is no cryptographic shortcut, deliberately. This is real friction, and it's exactly why R1's scope was narrowed (2026-07-10, see status note): the friction outweighs the convenience for anyone with a real contact list, so "make multi-device broadly convenient" isn't a goal worth chasing here.

**Decision:** don't mitigate — accept it as a known limit and don't build UX to encourage broad adoption of re-pairing multiple devices. It remains *possible* (a user can re-pair a second device with a contact they care enough about to re-meet), just not promoted or streamlined. If usage data ever shows real demand from users with small, close contact circles, revisit with UX investment then — not speculatively now.

---

## Release Sequencing

| Release | Ships | Feature | Floor | Flag |
|---|---|---|---|---|
| R0 | Design gates only | Protocol review (no code) | — | — |
| R1 | Opportunistic, low-priority | Multi-Device Contacts (narrowed to bug fix) | iOS 16 + U1 | `enableMultiDeviceContacts` |
| R2 | 2027 Q1 | Guardian Revocation Custody | iOS 16 | `enableGuardianRevocation` |
| R3 | 2027 Q2 | Passkey Provider | iOS 17 | `enablePasskeyProvider` |
| R4 | 2027 Q3 | Recovery Layer (coverage + escrow) | iOS 17 | `enableRecoveryLedger` |
| R5 | 2027 Q4+ | Guardian Succession (gated, exploratory) | iOS 18+ | — |

R1's floor matches the existing UWB exchange requirement exactly — there is no separate ceremony or protocol to raise it. Adding a device is running the same pairing flow again, per contact. R1 moved from a committed 2026 Q4 slot to opportunistic/low-priority once its scope narrowed to the data-model bug fix (2026-07-10) — it's a real defect worth fixing, but not one that justifies dedicated near-term engineering time on its own.

### Sequencing Rationale

Passkeys ship *third*, not first — shipped alone they inherit the lockout objection that caps device-bound adoption. **R2 stands on its own merits and does not depend on R1's scope.** R1's narrowed form (a data-model fix, not a flagship feature) doesn't constitute "recovery substrate" in any meaningful sense — losing all your devices (R2's problem) is orthogonal to whether `Contact.Profile` supports concurrent device keys (R1's problem). Guardian Succession is exploratory and gated pending full R0-style review.

---

## R0 — Design Gates (one sprint, zero code)

No implementation begins until these gates pass. Each section is a separate checklist owned by a single owner, reviewed independently.

### 1. Run CRYPTO_REVIEW_CHECKLIST.md end-to-end

Separately, for each of the new protocols/models:
- Multi-device key and prekey isolation model (R1) — no new protocol (R1 reuses the existing exchange ceremony unchanged), but the concurrent-key data model and per-device prekey scoping still need sign-off
- Guardian revocation (R2)
- Passkey issuance/assertion (R3)

Per house rule, **no cryptographic code before all items check**. The §3 multi-party traces that matter most:
- Prekey pools across *own* devices (the historical batch-sharing flaw now has a new way to reoccur — device A and device B must never share pools for the same contact)
- Shard distribution to N guardians

### 2. Register domain prefixes in one place

Extend the `SaltInfo`/constants pattern:
- `occulta-device-revocation-v1`
- `occulta-identity-revocation-v1`
- `occulta-revocation-wrap-v1`
- `occulta-passkey-store-v1`

Every future signature verification rejects cross-prefix input — same mandate as `IDENTITY_CHALLENGE_PROTOCOL`.

### 3. Write the threat-model delta doc per feature

Write **before** implementation (checklist §4: state what is NOT achieved). Originally two honest deltas, down from an earlier draft's four once removing R1's cert mechanism removed two PQ-signing deltas that no longer applied. **Revised 2026-08-03:** R1 grew from a pure data-model bug fix into a scoped mothership/revocation/custody-authority model across FINDINGS.md Design Sessions 7–9, and "R1 has none" no longer reflects what's actually being built. Current deltas:

- **R1, the pairing mechanism itself: still none.** Every device-contact pairing remains a full physical UWB exchange, identical in strength to any other contact relationship (D-07, unchanged by Sessions 7–9) — no vouching, no shortcut. This part of the original disclosure still holds exactly as written.
- **R1, mothership is not a single global property of an identity.** Which of a user's devices is authoritative for shard/custody ops and revocation is resolved independently by each contact, from that contact's own local pairing-order history with the user's devices (Q-07). A user with two devices paired with different contacts in a different order can have — plausibly, not just theoretically — different contacts simultaneously recognizing *different* devices as their mothership. There is no single "my mothership" the app can show or the user can reason about without per-contact awareness it doesn't currently surface (Design Session 9).
- **R1, revocation is eventually consistent, not guaranteed-delivered.** Even with the required reconfirmation-on-exchange behavior (Design Session 9), a contact who never returns online never learns of a revocation. If the revoked device was stolen rather than merely lost, that contact keeps trusting the attacker's device indefinitely. Inherent to serverless, peer-to-peer delivery — not solvable inside R1's scope, only mitigated.
- **R1, the duress-resistance property is not automatic.** Restricting custody/revocation authority to the mothership only protects a user under coercion if the mothership happens to be a device not on their person at the time of coercion. Since mothership assignment is accidental (delta above) and invisible (Q-05, no device UI), a user cannot currently arrange this deliberately. The protection is real when it lands; nothing today makes it land on purpose.
- Guardian collusion metadata exposure — **now also reachable via R1**, not only R2's original "total device loss" framing: R1 §6 routes any mothership-specific loss through R2's guardian mechanism, so R1's guardian-dependent path inherits this delta too.
- Passkey hardware-binding is user-verifiable, not RP-attestable (R3)

### 4. Wire-format rule confirmation

Everything below travels as **optional sub-envelopes on `SealedPayload`** riding `v3fs` + existing modes. **No new `Version` or `Mode` cases** — the `OccultaBundle` comment is the law. Old builds decode, ignore the unknown field, render nothing, break nothing.

---

## R1 — Multi-Device Contacts (scope narrowed to a data-model fix)

*(Renamed from "Owner Device Set." The earlier design named after a shared, cross-device "set" object that this resolution doesn't have — see the rejection below. Full history: [FINDINGS.md](FINDINGS.md), Design Sessions 3–5.)*

**Goal, narrowed (2026-07-10):** fix the defect where pairing a second device with an existing contact silently overwrites the first device's key — `Contact.Profile` should hold several concurrently-active device keys, not one. This is *not* a bid to make "backup phone that just works across your whole contact list" a promoted, first-class feature — that ambition was assessed and shelved: the secure mechanism (direct physical re-pairing per contact) only pays off for a handful of close contacts someone would re-meet in person anyway, and there's no cheaper version of it that doesn't reintroduce vouching. What ships is quiet infrastructure: if a user re-pairs a second device with a contact, both stay valid for that contact, instead of one silently breaking.

**Why not a device-to-device ceremony.** An earlier design had your two devices pair with *each other*, produce a signed cert, and have contacts accept the new device transitively on the strength of that signature — never physically meeting it. That was explicitly rejected: under Occulta's threat model (person with physical access under duress, not just a remote attacker), a single coerced cert ceremony would silently compromise the vouching device owner's *entire* contact graph in one event, with no physical tell for any contact to notice. Direct re-pairing, by contrast, requires an attacker to physically stage a ceremony with every contact individually — an attack-cost gap the cert model erased. The standing principle this holds to: **no mechanism may grant trust to a new key except a fresh physical UWB exchange; revocation is the only thing that may travel by signature alone**, because narrowing trust is always safe and granting it never is.

### 1. Ceremony

None — new, that is. Reuse the existing exchange flow exactly as it stands today. Adding a device to an existing contact is: from that contact's `Contact.Profile`, start "add a device," and run the ordinary UWB pairing ceremony again with the new device, directly with that contact. No new session type, no device-to-device step, no cert. This is [FINDINGS.md](FINDINGS.md) D-07's resolved flow, unchanged by this rewrite.

### 2. Data model

`Contact.Profile` moves from "one active key, rotation history" to "several concurrently-active keys, one per device." `deviceID: String` is added to `Key` (D-03) — minted once, at first exchange with that specific device, never reassigned. `expiredOn` becomes an explicit per-device kill switch rather than the implicit single-key rotation behavior it accidentally has today (D-05, D-06). New optional column, lightweight SwiftData migration; existing rows get `deviceID == nil`, treated as one implicit legacy device, no backfill needed.

### 3. Fan-out at existing call sites

All 34 call sites reading `contactPublicKeys` (D-06) split into two categories: fan-out sites (encryption/decryption, identity challenge) move from `.last` to `.filter { $0.expiredOn == nil }` — *all* active devices, not one. Display sites (fingerprint view, "last exchanged" label) keep showing one key by product decision, since no multi-device picker UI exists yet — not a data-model gap, a deferred UI decision.

### 4. Encryption to multiple devices

Reuse the shipped `useMultipleRecipientMessageFormat` capsule array exactly as group messaging already does: one session key, wrapped once per active device-key belonging to the contact. No wire-format change — `GroupRecipient` already takes a raw public key with no contact identifier threaded through the crypto layer at all (D-01).

### 5. Forward secrecy per device (highest risk, highest oversight)

Each device gets its own prekey pool with each contact, established the ordinary way during its own direct exchange — no bootstrapping needed, because there is no device that hasn't physically exchanged. SE tags extend to `"prekey.<contactID>.<deviceID>.<id>"` (D-02, D-03); `ContactManager` fans out one `GroupRecipient` per (contact, device) pair, each carrying that device's own `pendingBatch` computed against that device's own threshold (D-04). Device A never sees device B's prekeys or replenishment batches — a useful isolation property if one device is later compromised.

**This is the one place this plan can recreate the documented historical prekey flaw.** Write the trace test proving device A never consumes or ships device B's prekeys before this ships.

### 6. Revocation — authority restricted to the per-contact mothership

**Added 2026-08-03 (FINDINGS.md, Design Session 7):** revocation authority is scoped to a contact's current *mothership* device — the same "trusted device" Q-07 already computes (oldest key with `expiredOn == nil` for that contact), now governing revocation in addition to shard-op routing. No new state: this is a jurisdiction extension of an existing computed value, not a new field. Reason: without this restriction, revocation is symmetric — any surviving device can forge "the primary is lost," so compromising a low-value secondary is enough to kill trust in the legitimate primary across the whole contact graph. Full reasoning: FINDINGS.md, Design Session 7.

Three paths, all narrowing trust only — consistent with the standing principle above:
- **The lost device is a secondary, the mothership survives:** the mothership live-signs `occulta-device-revocation-v1 ∥ lostDevicePubKey ∥ timestamp` (it has an SE — no pre-signing needed) and distributes it directly to every contact who has the lost device's key pinned. Contacts drop the revoked key immediately; UI: "Alex removed a device."
- **Voluntary handoff — the mothership is still possessed and working, but the user wants a different device to hold authority (added 2026-08-03, FINDINGS.md Design Session 9):** distinct from "lost." The mothership device signs a revocation of *its own* public key — nothing in the Design Session 7 restriction prevents self-revocation, only revocation of *other* devices. This distributes the same way as any other revocation, and authority shifts to the next-oldest surviving device automatically, exactly as in the lost-mothership case below — but no guardians are involved, because the device signing is fully present and functional. This case exists specifically so a mismatched pairing-order (e.g., a test device that happened to pair first) can be corrected without a guardian flow.
- **The lost device is the mothership itself, unavailable to sign anything:** no surviving secondary may revoke it unilaterally — that would reopen the symmetric-authority hole this restriction exists to close. Falls through to R2 (Guardian Revocation) — see R2 §4's updated framing, which already supports single-device revocation, not only total loss. Mothership authority then shifts automatically to the next-oldest surviving device per contact; this is a side effect of the existing recomputation, not a separate promotion step.

**Delivery is not fire-and-forget (added 2026-08-03, FINDINGS.md Design Session 9 — [HIGH] finding, must close before shipping; mechanism resolved in Design Session 10):** a contact who is offline or drops the initial broadcast has no way to self-heal onto the correct answer, which is a real security gap, not just an availability one — if the lost device was stolen rather than merely lost, a desynced contact keeps honoring a signature from a device an attacker now holds. There is no automatic delivery channel to retry over — every bundle post-pairing (`ActivityView`'s share sheet) is a manual, user-triggered send, so "retry" cannot mean a background process. Resolution: every outbound bundle to that contact carries the full known-revoked-device set unconditionally, for as long as the relationship exists — no acknowledgment tracking, since redundant delivery is already safe (revocation processing is idempotent). A permanently-dormant contact who's never messaged again is disclosed as a residual, unclosable gap (see R0 §3 delta doc), surfaced to the user via an informational "may not know yet" list rather than left silent.

### 7. PQ posture

No gap to disclose, and no separate section needed beyond this line: every device-contact pairing is a full live UWB exchange, so ML-KEM material is established identically to any other relationship — mutual encapsulation, cached, folded into every session key, exactly per bundle.md. There is no "secondary device" from the protocol's point of view; each device is a first-class, independently-verified relationship with its own full PQ material from day one.

### 8. UX cost — accepted, not mitigated (Alert #7)

Adding a device means re-pairing with every contact individually. Unlike the original plan, no UX (checklists, reminders, promoted "add a device" flows) is being built to make this convenient at scale — see the scope note at the top of this document and Alert #7. This section exists so the fix doesn't get silently re-scoped upward later without revisiting that decision.

### 9. Tests + gate

Mirror OCCULTA_TEST_PLAN structure:
- Data-model migration (existing single-key rows get `deviceID == nil`, treated as one implicit legacy device)
- Fan-out correctness at all 34 D-06 call sites (encryption/decryption reach every active device; display sites pick one sensibly)
- Prekey/pool isolation trace test — device A never touches device B's pool for the same contact
- Revocation: tamper table (flipped fields → signature fail), replay idempotence, "no surviving device" correctly falls through to R2 rather than failing silently
- Mandatory old/new build fixture — a pre-multi-device build must decode a multi-key-carrying bundle and render the message untouched (D-01 predicts this should already hold with zero wire changes; prove it)

Fixtures into CI permanently.

---

## R2 — Guardian Revocation Custody

**Goal:** Losing *all* devices kills your keys, not your contacts' trust in a ghost.

### 1. Pre-signed certificate — per device, not per identity

At enrollment, **each device's own SE** signs `occulta-identity-revocation-v1 ∥ thisDevicePubKey ∥ issuedAt`. There is no shared root key to sign once for every device — SE keys are non-exportable and device-bound by construction (D-02), which is exactly what makes multi-device work at all under R1. If you carry more than one device, you have one pre-signed cert per device.

Plaintext of each cert never persists; it is generated, wrapped (step 2), bundled and split (step 3), and discarded in one flow.

### 2. Encrypt-to-knowledge wrap — one per device, bundled

Each device's cert is wrapped separately: `AES-GCM(cert, key: HKDF(thisDevicePubKey, info: "occulta-revocation-wrap-v1"))`. All of a user's wrapped device-blobs are then bundled into a single escrow payload.

Anyone can relay the bundle; only a contact holding a *given device's* public key — someone who physically met that specific device — can open that device's blob. A contact who only ever met one of your two devices can still revoke the one they know; they simply can't open the other device's blob, which is correct — they were never trusted to. Broadcasting leaks nothing to non-contacts: no graph, no identity, random bytes. This is what makes guardian *distribution* metadata-clean.

### 3. Split and distribute

Shamir K-of-N over one root secret that gates every per-device wrap key in the bundle, so guardians manage a single K-of-N split regardless of how many devices you carry — delivered through the existing `ShardOperation` protocol (`.distribute` / `.acknowledge` / `.revoke` are already in `OccultaBundle`) — near-zero new wire surface.

Constant-time GF(2^8) path already exists per the Master Analysis notes.

### 4. Guardian release flow

Guardian-side UI covers two cases, not just one (revised 2026-08-03, FINDINGS.md Design Session 7): "Alex reports total device loss" **or** "Alex's mothership device was lost, other devices still work" — R1 §6 routes mothership-specific loss here even when secondaries survive, since no secondary may unilaterally revoke a mothership. Either way: release shard to a coordinating guardian → K shards reconstruct → broadcast the full bundle to the guardian's own full contact list (safe per step 2).

Each recipient opens only the blob(s) matching a device key they actually have pinned, verifies the SE signature against it, and marks that device revoked-pending-re-exchange. A contact who only ever knew one of your devices only ever revokes that one — correct, not a partial failure. This is what makes the mothership-only case work without a separate mechanism: the per-device cert/blob design already supports revoking exactly one device.

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
- **Two SDK verifications from Alert #6 signed off on hardware** before this gate passes

---

## R4 — Recovery Layer (the actual promise)

### 1. Coverage ledger

Per-credential device-coverage map inside the passkey store, synced between your own devices.

**Open question, not resolved here:** this assumed a direct encrypted channel between your own devices ("they're contacts of each other, cryptographically") — that assumption no longer holds under R1's resolved model, where your own devices never establish any relationship with each other at all, only with contacts. Since R3/R4 are already the deferred half of this roadmap (see Trade-off Analysis), this doesn't need solving now, but it does need its own resolution before R4 is scoped for real — likely either a guardian-mediated sync path or accepting the coverage dashboard is per-device, not unified.

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

**Second: unique moat.** Device-bound passkeys alone are commodity — 1Password could use them tomorrow. The moat only engages when recovery flows through physically verified humans: Multi-Device Contacts is built from direct physical UWB pairings with each contact, guardians are people you've stood next to. The defensible product isn't "passkeys," it's "your service logins inherit your human trust graph."

### The Decent Reason That Doesn't Fully Justify It

Philosophical coherence. If Occulta's thesis is "identity anchored in hardware and physical presence instead of servers," passkeys extend that thesis to services. But notice the thesis has to be restated to make passkeys fit — the original framing ("authentication between people") is sharper, and under that framing passkeys are a detour.

### The Honest Case Against

A credential provider is the **largest attack surface and support burden** of anything in this roadmap — a second process, a shared keychain group, per-RP WebAuthn quirks, AutoFill edge cases, and lockout tickets. For zero-vulnerability posture, that's expensive real estate.

You'd also be fighting a free platform default, which is a brutal conversion funnel.

Every hour spent there is an hour not spent on the duress cluster, Wi-Fi Aware, or document signing — features that serve the people-to-people thesis directly and have documented demand.

### The Recommendation

**Skip passkeys for now, and lose nothing by doing so.** R2 serves identity-between-people on its own merits (total device loss and recovery is a real, unsolved problem today) — ship it because it completes the mission. R1, since its 2026-07-10 narrowing, is a small data-model bug fix, not a mission-critical feature; ship it opportunistically, not as a reason to prioritize this arc.

If, a year from now, retention data says you need a daily-use hook, the passkey substrate will already exist and the decision becomes cheap. Building the recovery layer first and deferring the credential layer isn't a compromise — it's the version of this roadmap where every shipped line serves the thesis you just articulated.

---

## References

- [FINDINGS.md](FINDINGS.md) — Design sessions and resolved open questions
- [Master Feature & Expansion Analysis](../Master%20Feature%20%26%20Expansion%20Analysis.md) — Broader product roadmap context
- [CRYPTO_REVIEW_CHECKLIST.md](../../Audit/CRYPTO_REVIEW_CHECKLIST.md) — Protocol review gate (R0)

# Presence Verification ("Live Check") — Specification

**Status:** Draft for review
**Date:** June 12, 2026
**Builds on:** Identity Challenge protocol (shipped, `Occulta/Features/IdentityChallenge/`)
**Master analysis entry:** Feature #15, `Docs/Features/Master Feature & Expansion Analysis.md`
**Feature flag:** `presenceVerification` (features.plist)

---

## 1. Problem

AI voice clones need ~3 seconds of sample audio. Real-time video deepfakes participate
interactively in conference calls. Caller ID is trivially spoofed. The documented losses:

- Arup (Sep 2025): finance employee wired **$25M** after a video call in which every
  participant, including the CFO, was synthetic.
- Singapore (Mar 2025): **$499K** authorized on a deepfake Zoom call.
- FBI IC3 2025: 22,000+ AI-fraud complaints, **$893M** in losses.
- Consumer side: voice-clone "family emergency" scams are the subject of 2025–2026
  advisories from the FBI, FTC, BBB, CNN, CBS, and McAfee. The universally recommended
  countermeasure is a verbal **safe word** — static, leakable, forgettable, and
  extractable from a panicked victim.
- Enterprise side: Scattered Spider's helpdesk playbook (MGM) — phone the IT desk,
  impersonate an employee, get MFA reset. Incumbent fixes (Nametag, HYPR Affirm) are
  cloud services running government-ID + selfie biometric pipelines.

Google shipped **Fake Call Detection** on June 2, 2026: an RCS handshake confirming a
call from a saved contact originates from that contact's device. Android-only,
Google-mediated, RCS-bound. iOS has no equivalent; no serverless equivalent exists on
any platform.

**Occulta's claim:** a deepfake can clone a face and a voice; it cannot produce an ECDSA
signature from the Secure Enclave key that was exchanged at ≤25 cm. The physically
verified contact graph is the exact trust anchor this problem needs, and both parties in
any verification by definition have Occulta and a prior UWB exchange — the closed-loop
objection that removed Document Signing does not apply here.

---

## 2. What already exists (inventory)

The Identity Challenge protocol shipped the hard half. Current state:

| Component | File | Status |
|---|---|---|
| 72-byte `ChallengePayload` (nonce ∥ timestamp ∥ challengerFingerprint), fixed binary layout | `IdentityChallenge+Payload.swift` | Shipped |
| `ResponsePayload` (nonce ∥ DER ECDSA signature) | `IdentityChallenge+Payload.swift` | Shipped |
| Domain-prefixed signing (`occulta-identity-challenge-v1`), SE ECDSA via `signIdentityChallenge` | `IdentityChallenge+Crypto.swift` | Shipped |
| Three-phase lifecycle: create → decrypt/approve/respond → verify; nonce one-shot store; rate limit (1 outstanding per contact) | `IdentityChallenge+Manager.swift` | Shipped |
| Encrypted transport on `OccultaBundle` (`v3fs` + `longTermFallback`), fallback text for old builds | `IdentityChallenge+Manager.swift` | Shipped |
| Biometric gate on approval (`LAContext`), share-sheet `.occ` staging, in-memory `verifiedAt` badge | `IdentityChallenge+Coordinator.swift` | Shipped |

### Why the shipped feature cannot claim *presence*

1. **Window:** `timestampWindow = 3600 s`. One hour proves "this contact still controls
   their key," not "this person is in this conversation right now."
   *(Observation, do not fix here: comments in `IdentityChallenge+Manager.swift` still
   say "5-minute window" — stale since commit `ca5691e` widened the constant to 3600.)*
2. **Transport friction:** four share-sheet hops (challenge out → in, response out → in).
   Unusable mid-call; depends on a messaging channel the attacker may control or monitor
   for timing.
3. **No intent binding:** the responder's approval sheet asks them to "sign this
   verification" without stating *what they are attesting to*. A signature that means
   "I am in a live conversation with you right now" must say so on the approving device —
   this is the primary relay-attack mitigation (§6).

The feature is therefore an extension: a **presence mode** with a tight window, a
distinct signing domain, intent-explicit approval UX, and (M2) a QR transport for the
desktop-video-call scenario.

---

## 3. Protocol design

### 3.1 Envelope

New optional sibling field on `OccultaBundle.SealedPayload`:

```swift
/// nil on every payload that is not part of a presence check.
let presence: PresenceEnvelope?
```

Per the guidance documented in `IdentityChallenge+Envelope.swift`, per-feature envelopes
are separate optional fields, **not** new `Kind` cases on `IdentityChallengeEnvelope` —
an unknown enum raw value would fail the whole `SealedPayload` decode on old builds,
killing the fallback-message degradation path. With a sibling field, old builds ignore
the unknown JSON key and render the fallback `message`:

```
[Occulta] This is a live presence check. Update Occulta to respond.
[Occulta] This is a live presence confirmation. Update Occulta to verify.
```

`PresenceEnvelope` mirrors `IdentityChallengeEnvelope`: `kind` (`challenge` / `response`),
binary `payload`, `contextNote` (challenge only, same 500-byte cap and truncation rules,
same "never markdown/HTML" rendering rule).

### 3.2 Payloads

- **Challenge:** reuse the existing 72-byte `ChallengePayload` layout unchanged
  (nonce 32 ∥ timestamp 8 BE ∥ challengerFingerprint 32). Intent is carried by the
  envelope type and the signing domain, not by the payload bytes.
- **Response:** new fixed-prefix layout — `PresenceResponsePayload`:

```
Offset  Length  Field
     0      32  challengeNonce      — echoed
    32       8  responderTimestamp  — UInt64 BE, Unix seconds, responder's signing time
    40     var  signature           — DER ECDSA (final field, no length prefix)
```

The responder timestamp is the field that makes "signed N seconds ago" honest — without
it the verifier could only bound freshness by the challenge's creation time.

### 3.3 Signing domain

```swift
static let presenceDomainPrefix = "occulta-presence-v1"
```

Signed bytes (single shared builder function, same rule as `buildSignedData` — both
sides MUST construct identical bytes):

```
presenceDomainPrefix ∥ nonce(32) ∥ challengerFingerprint(32) ∥ responderTimestamp(8)
```

Distinct prefix ⇒ a presence signature can never be accepted by the identity-challenge
verifier or any future Document Signing feature, and vice versa. This is the same
cross-protocol-reuse defense already documented in `IdentityChallenge+Crypto.swift`.
The challenge timestamp is bound via the verifier's nonce → outstanding-entry lookup;
it does not need to be re-signed.

### 3.4 Constants

```swift
enum Presence {
    static let presenceWindow: TimeInterval = 120     // |now − responderTimestamp| hard bound, verifier side
    static let challengeTTL:   TimeInterval = 600     // challenge creation → response acceptance
    static let clockSkewGrace: TimeInterval = 30      // reuse existing value
    // nonce length, rate limit, contextNote cap: reuse IdentityChallenge values
}
```

120 s covers the realistic loop — challenge arrives, contact picks up phone, Face ID,
response travels back — while making a relayed or pre-staged response operationally
hard. Verifier UI always displays the measured age ("signed 9 seconds ago"), so even
within the window the human sees staleness.

### 3.5 Lifecycle (delta from Identity Challenge)

Same three phases, same one-shot nonce store, same coarse-grained error collapse
(rule 4: never reveal which check failed). Differences:

| Step | Identity Challenge | Presence |
|---|---|---|
| Verifier accept window | 3600 s from challenge creation | `challengeTTL` 600 s from creation **and** `presenceWindow` 120 s from `responderTimestamp` (skew-graced both directions) |
| Responder staleness check | 1 h soft | 600 s soft |
| Approval sheet copy | "sign this verification" | intent-explicit, names the challenger (§5) |
| Result UX | "Verified N minutes ago" badge | "**Present** — signed N seconds ago" verdict screen; never promoted to a lingering badge older than `presenceWindow` |

The shipped `verifiedAt` badge stays as-is for identity checks. Presence results are
displayed once and not persisted (§7).

---

## 4. Transports

### M1 — Messaging transport (ships first; zero new wire mechanics)

The existing `.occ` share-sheet flow, carrying the presence envelope. Covers:

- **Voice call on the phone:** "I'm going to send you a Live Check — approve it." The
  `.occ` travels over iMessage/WhatsApp/email *alongside* the call. The channel being
  attacker-controlled is acceptable: authenticity lives in the signature, freshness in
  the window. The attacker can drop the proof, but cannot forge it — and absence of
  proof is the signal.
- **Helpdesk / async enterprise:** contextNote carries the ticket reference
  ("Re: MFA reset #4821"). For this workflow the *identity* check (1 h window) is often
  the right tool; presence mode is for "I am talking to you right now."

### M2 — QR live path (the Arup scenario)

For desktop/laptop video calls, where phones are free on both ends:

1. Verifier taps **Live Check → Show code** → phone displays challenge QR.
   Verifier holds it to their webcam.
2. Real contact scans the QR off their screen with Occulta → intent-explicit approval →
   Face ID → SE signs → phone displays response QR. They hold it to their webcam.
3. Verifier scans the response QR off their own screen → verdict: green
   "**Present** — signed 9 seconds ago with the key you exchanged in person on Mar 3."

No messaging channel, no server, works inside the call medium itself. A deepfake
participant can only satisfy this by relaying to the real person within the window —
see §6.

**Compact frames (QR-specific wire format).** A full `OccultaBundle` (JSON, base64
ciphertext, hybrid-KEM fields) is likely 1.5–2 KB — hostile to screen-to-camera
scanning. The QR path instead carries **plaintext** fixed-layout frames:

- Challenge frame: version byte ∥ `ChallengePayload` (72 B) → ~80 B QR.
- Response frame: version byte ∥ `PresenceResponsePayload` (~112 B) → ~120 B QR.

Privacy analysis of plaintext frames — what a passive observer of a *recorded call*
learns: a random nonce; `challengerFingerprint = SHA-256(pubkey ∥ nonce)`, unlinkable
without the challenger's public key (Occulta public keys are never published); a DER
signature verifiable only with the responder's public key (same property). No names, no
identifiers, no linkability across checks (fresh nonce each time). This matches the
forensic-cleanliness mandate: a recorded QR is opaque noise to anyone outside the
two contact books. Scanning-side challenger identification: responder's app computes
`SHA-256(contactKey ∥ nonce)` across stored contacts to resolve who is asking — O(contacts),
fine at Occulta's scale, and a non-match is rejected before any UI is shown.

**Single-device limitation (stated, not solved):** if the call runs on the same phone
as Occulta (FaceTime on the only device), the QR path is unusable — switching apps
pauses the call video. UI detects nothing here; the Live Check sheet simply offers both
paths and the copy explains when each applies. Fallback is M1.

---

## 5. Approval UX (the security-critical screen)

The responder's approval sheet is the relay-attack mitigation. Required elements:

> **Yura** is asking you to confirm you are in a live conversation with them
> **right now**.
>
> *"Confirming the wire transfer for the Henderson account"* ← contextNote, plain text
>
> If you are **not** currently talking with Yura, tap Decline — someone may be
> impersonating you to them.
>
> [ Decline ]   [ Confirm — Face ID ]

Rules:

- Challenger display name comes from the responder's own contact record (decrypted
  locally), never from the payload.
- contextNote rendered as plain text only (existing rule), visually distinct from
  Occulta's own copy so a note cannot impersonate UI.
- Biometric prompt reason: `"Confirm you are in this conversation"` — the LA sheet is
  the last thing seen before signing; its text must restate intent.
- No "always allow" or batching. Every presence check is one explicit approval.

---

## 6. Threat model

### Defeated

| Attack | Why it fails |
|---|---|
| Voice clone / real-time video deepfake of a contact | Cannot sign; no key |
| Caller-ID spoofing / SIM swap | Phone number plays no role in the protocol |
| Replay of an old response | One-shot nonce store + 120 s `presenceWindow` + signed `responderTimestamp` |
| Forged or tampered frames | ECDSA over domain-prefixed bytes; GCM-authenticated envelope on the M1 path |
| Cross-protocol signature reuse | Distinct domain prefix per protocol |
| Observer of the channel / recorded call (M2 plaintext frames) | Learns only unlinkable hashes, a nonce, and a signature it cannot verify (§4) |
| Probing by a non-contact | M1: cannot derive the session key. M2: fingerprint resolves to no stored contact; rejected pre-UI |

### Residual (documented, partially mitigated)

- **Relay (parallel-session) attack:** the attacker, mid-deepfake-call with the victim,
  simultaneously contacts the real person under a pretext and induces them to approve a
  Live Check naming the victim. Mitigations: the approval sheet names the challenger and
  states the live-conversation claim (the real person must actively lie to their own
  device about a conversation they are not in); the 120 s window forces the relay to run
  in real time; education copy on the verdict screen. This is the same residual class as
  number-matching MFA. **Not eliminated. Marketing copy must never claim it is.**
- **Coerced or compromised contact:** presence proves *the person with the key actively
  approved*, not that they are free, honest, or alone. Out of scope by design.
- **Compromised responder device with biometric bypass:** equivalent to full device
  compromise; out of scope for every Occulta feature.

### Explicit non-claims

Presence Verification does **not** authenticate the media stream (the voice/video could
still be synthetic while the real person approves from elsewhere — what is proven is
that the human holding the key actively confirms being in a conversation with *you*,
now). It is not continuous attestation; it is a point-in-time check. Repeat it before
any irreversible action ("verify, then wire").

---

## 7. Privacy and forensic cleanliness

- Outstanding challenges and presence outcomes live in the existing **in-memory** store
  pattern; nothing persists across termination. No verification history is written
  anywhere by default. (Deliberate: "who checked whom, when" is itself sensitive
  metadata — and a history feature would need Travel Mode integration before it could
  exist at all.)
- M1 temp `.occ` files: same handling as identity challenges today (`writeOCC` to
  `temporaryDirectory`). The M2 QR path writes no files at all.
- No network calls, no analytics, no new entitlements, no background execution.

---

## 8. Implementation plan

Per CLAUDE.md, each step has a verify gate. TestKeyManager covers all SE paths.

```
M1 — presence mode over existing transport
1. PresenceEnvelope + PresenceResponsePayload + presence signed-data builder
   → verify: round-trip encode/decode tests; truncation/cap tests;
     cross-domain test: identity-challenge signature MUST fail presence
     verification and vice versa (the single most important test in the feature)
2. Presence phases on the manager (sibling methods or mode parameter — decide in
   review; bias to whichever keeps Identity Challenge code untouched)
   → verify: injected-clock tests at presenceWindow and challengeTTL boundaries
     (±skew grace), replay rejection, wrong-sender rejection, rate limit
3. SealedPayload.presence routing in the inbound pipeline + old-build fallback
   → verify: old-decoder simulation test (decode SealedPayload JSON containing
     presence key with a pre-presence model) renders fallback message
4. Approval sheet + verdict screen + contact-card "Live Check" entry point
   → verify: manual on-device pass incl. Face ID gate; copy review against §5
5. features.plist flag `presenceVerification`
   → verify: flag off ⇒ no entry points visible, inbound presence envelope
     renders fallback message

M2 — QR live path
6. Compact frame codecs (version byte + fixed layouts)
   → verify: round-trip tests; malformed/short-data rejection; frame size
     assertions (≤ 200 B)
7. QR render + camera scan (reuse key-exchange QR components) + screen-scan flow
   → verify: manual two-device test against a laptop screen at typical
     video-call resolution/compression; document the failure mode if the
     counterpart's webcam feed is too degraded to scan
8. Challenger resolution by fingerprint scan over stored contacts
   → verify: unit test incl. no-match rejection before UI
```

Out of scope for v1: numeric fallback codes (read-aloud), verification history,
group/multi-party checks, any persistence, any server-assisted anything.

## 9. Open questions for review

1. `presenceWindow` = 120 s — tight enough to constrain relays, loose enough for a
   fumbled Face ID retry? 90 s was considered; pick during device testing.
2. Manager shape: sibling `Presence.Manager` vs. mode parameter on the existing
   manager. Sibling keeps the shipped code untouched (CLAUDE.md surgical-change rule)
   at the cost of some duplication.
3. Should the M1 fallback strings reuse the identity-challenge wording exactly, to
   avoid revealing to an old-build observer that a *presence* check (vs. identity
   check) occurred? Leaning yes — one generic string for both.
4. Enterprise pilot framing (helpdesk workflow doc) — separate doc once M1 ships;
   belongs with Expansion A packaging, not in this spec.

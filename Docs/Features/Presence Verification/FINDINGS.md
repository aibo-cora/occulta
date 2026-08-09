# Presence Verification — Design Findings

**Status:** Exploratory — companion to [SPEC.md](SPEC.md), which remains delayed per its §6 July 10, 2026 addendum. Nothing here is scoped for a release.
**Context:** Design discussion, 2026-08-09. Captures an alternative construction reached while reviewing the Organizational Identity Graph feature, whose Design Session 5 (D-15) derived the underlying principle in a different setting. Recorded here because the conclusion is about `#15`, not about the org feature.

---

## Design Session 1 — Intent Signing as an Alternative Construction (2026-08-09)

**Question raised:** `#15` is delayed because the relay/parallel-session attack (SPEC.md §6) has no known guaranteed fix. Is there a different construction of the same product value that the relay attack does not reach?

**Answer: possibly — by reversing the direction of the protocol.** Not a fix for presence verification. A different primitive that delivers most of the same product outcomes and is structurally out of the relay attack's reach, at the cost of a behavioral dependency stated openly below.

### D-01 · Reverse the direction: attest to your own intent, not to a circumstance

SPEC.md's protocol has the *verifier* challenge the *prover* to attest to a **circumstance**: "you are in a live conversation with me, now." That is the shape the relay attack exploits, because a circumstance can be manufactured by an attacker and the prover has no way to tell from the request itself that it is being misused.

The inversion: the **requester originates** a signed, human-readable statement of what they are asking for, and the recipient verifies it.

> *"I am asking you for $5,000."* — signed by the requester's SE key, under a domain-separated prefix, pinned to the physically-verified contact.

A voice clone cannot produce that signature. More importantly, **pretexting the real person does not produce it either**, which is the property the current construction lacks.

### D-02 · Why this is not the content-binding §6 already rejected

SPEC.md §6's July 10 addendum explicitly considered and rejected content-binding: *"mixing session-specific live-call content into the signed challenge raises the bar but is not a guarantee: a sufficiently resourced attacker running both the deepfake call and a synchronized real-time relay of that content defeats it too."* That rejection is correct and is not being re-litigated.

The distinction is in **what the signer is attesting to**, not in how much content is bound:

| | Signer attests to | Can an attacker manufacture a plausible pretext? |
|---|---|---|
| SPEC.md §3 (and its content-bound variant) | An external circumstance — "I am in a call with you" | **Yes.** "We're verifying your account, your mother is on the line" is entirely plausible to an honest person |
| This construction | The signer's **own intent** — "I am asking you for $5,000" | **No plausible pretext exists.** The statement is self-evidently about the signer giving away their own position, addressed to a named party |

The relay attack works against the current design because the real contact can approve honestly and still be wrong — they are attesting to something they cannot fully observe. Under the inversion, relaying requires the real contact to knowingly sign a false statement about their own intent. That is not a relay; that is the contact participating in the fraud, which is out of scope by the same reasoning that puts coercion out of scope (SPEC.md §6, "Coerced or compromised contact").

This is a **structural** difference, not a bar-raising one. It deserves the same scrutiny that reclassified the original residual, not a fast acceptance.

### D-03 · Scope limit: works only where the requester still holds their key

The inversion applies wherever the person making the request has their key:

- **Family money requests** (`#27`'s grandparent-scam case) — the requester asks; natural fit.
- **BEC / wire fraud** (`#26`) — already this shape; payment instructions are signed by the party supplying them.
- **Deepfake executive fraud** (the Arup scenario) — the impersonated executive holds their key; finance requires a signed instruction. Works.

It does **not** apply to account recovery, where the requester has definitionally lost the key that would sign. This maps exactly onto the split found independently in `Organizational Identity Graph/FINDINGS.md` Design Session 5 (D-15): establishing a *new* key has no content to bind against and needs physical presence; authorizing a *described action* against an existing key does not.

Stating the limit up front matters because "verify a caller claiming to be from your bank's fraud team" — a scenario adjacent to `#15`'s pitch — falls outside it. That caller has no key and never did.

### D-04 · `#27` is only partially blocked on `#15` — the Master doc overstates the dependency

`Master Feature & Expansion Analysis.md` #15's July 10 addendum states that Anti-Scam Family Circle (`#27`) *"is built entirely on top of this primitive."* Reading `#27`'s own three components (Master doc §27) shows that is not accurate:

1. **Assisted Mode** — a one-button presence challenge with plain-language verdicts. **Genuinely blocked on `#15`.** This is the component the inversion would replace.
2. **Second Opinion** — forwards a suspicious request to a designated family guardian as a structured basket; reply renders as a verdict card. Explicitly *"One basket type plus UX; zero new crypto."* **Not blocked on `#15` at all** — it depends on no presence primitive.
3. **Money-request rule** — ties into `#26`, which is Near-term and independently scoped. **Blocked only through `#26`'s own optional pairing with `#15`**, not intrinsically.

So two of three components are shippable today, and the third has a candidate replacement in D-01. `#27` carried the highest reach-to-lift ratio of the July 10 pass and the app's most natural viral loop; leaving it wholly shelved on an inaccurate dependency is a real cost.

### D-05 · The primitive largely exists — this is an extension of `#26`, not a new build

`#26` (Verified Payment Instructions) already specifies exactly this shape for one payload type: a structured sub-envelope signed by the sender's SE key under `"occulta-payment-instructions-v1"`, pinned to the physically-verified contact, rendered as an immutable card with loud signed-change diffing. Its stated design rationale is the same one reached here — *"the defense needed at the moment of wiring is a trusted asynchronous artifact, not just a challenge."*

The extension is to carry that pattern to non-payment requests (a request for money, for gift cards, for codes, for an action) under its own domain prefix. Zero new cryptography, same house pattern, same no-server posture. `#26` is already Near-term priority, so the marginal lift is small if sequenced alongside it.

---

## Open Questions (Unresolved)

### Q-01 · The "I lost my phone" adaptation — the real residual, and it is behavioral

The scam adapts. When an unsigned request is refused, the pretext becomes *"I can't sign, my phone is gone"* — which is precisely the emergency framing grandparent-scams already use. The construction does not defeat this cryptographically and must not claim to.

What it actually does is **convert an unsolvable cryptographic problem into a tractable behavioral one**: from "can an attacker fake presence" (§6: no known fix) to "will the family hold a pre-agreed line." That line is *"no signature, no money — especially if they say they lost their phone."*

This is the same class of defense as the verbal safe word that `#15`'s §1 positions against — but without the two failure modes that make safe words weak: it cannot leak (nothing to overhear or extract), and it cannot be forgotten (the app enforces it). That is a genuine improvement, and it is a strictly weaker claim than `#15` set out to make. **Any product copy must state it as a policy the family adopts, never as a guarantee the protocol provides.**

Whether that trade is acceptable is the question this whole session turns on, and it is a product decision, not a protocol one.

### Q-02 · Action-string wording is security-critical and unspecified

The security argument in D-02 collapses entirely if the signed statement is ambiguous about **direction and beneficiary**. "$5,000 transfer between you and Mom" is signable under a plausible pretext ("your mother is sending you money, sign to receive"). "I am asking Mom for $5,000, to be sent to account ···4471" is not.

This needs the same treatment SPEC.md §5 already gives the approval screen (*"the security-critical screen"*) — a specified, constrained vocabulary, not free text supplied by the requesting app. Unresolved.

### Q-03 · Replay and expiry semantics

A signed request must be one-shot and expiring, or a legitimate request from last year becomes a replayable artifact. SPEC.md §3.4's existing nonce-store and window constants are the obvious precedent, but the timescales differ — an asynchronous request may legitimately sit unread for hours, unlike a 120 s presence window. Not designed.

---

## Recommendation

Run this as its own design pass, gated on Q-01 being answered as a **product** decision first — the engineering is small and largely already specified by `#26`, so the expensive question is whether a policy-dependent defense is one this project is willing to ship and describe honestly.

Independently of that decision, `#27`'s Second Opinion component should be unshelved now (D-04). It is blocked on nothing, it was ruled the highest reach-to-lift item of its pass, and it currently sits idle behind a dependency it does not have.

**This does not unblock `#15`.** SPEC.md's construction and its §6 delay stand exactly as written. What this offers is a different primitive that reaches several of the same outcomes by a route the relay attack does not travel — and one that explicitly cannot cover account recovery or unknown-caller verification.

---

## Action items

- Answer Q-01 as a product decision before any protocol work: is a policy-dependent, honestly-described defense acceptable here?
- Master doc `#15` addendum: correct the claim that `#27` is *"built entirely on top of this primitive"* (D-04) — two of its three components are not.
- Unshelve `#27`'s Second Opinion component independently of `#15`.
- If pursued: scope Q-02 (constrained action-string vocabulary) and Q-03 (replay/expiry) alongside `#26`, not separately — same primitive, same release.
- Cross-reference `Organizational Identity Graph/FINDINGS.md` D-15, which reached the same principle from the enterprise side.

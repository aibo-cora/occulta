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

---

## Design Session 2 — Pre-Authored Payment Cards and Request Binding (2026-08-09)

**Question raised:** run the design pass Session 1 called for, and evaluate a proposal alongside it — banking/wallet details held in **pre-authored, biometrically signed cards** that the owner maintains ahead of time and attaches to a request, so that card and request are independently verifiable.

**Headline finding: the card is the stronger half.** Session 1's intent signature proves *who asked*. The card constrains *where value can go*. The second is worth more, because redirecting funds to an account the attacker controls is the objective of essentially every payment scam — and a pinned card makes redirection require a new signature from the real person, which is exactly the thing an attacker cannot obtain.

### D-06 · The composition — long-lived card, ephemeral request, and the request MUST bind the card

Two artifacts with different lifetimes, both SE-signed under their own domain prefixes, both biometric-gated by construction (SE key use already requires a biometric gate — this is not a new property to build):

| | Card | Request |
|---|---|---|
| Content | "Value reaching me goes to account/IBAN/wallet ···4471" | "I am asking you for $5,000" |
| Lifetime | Long-lived, versioned, maintained by the owner | One-shot, expiring |
| Signed | Once at authoring, re-signed only on change | Per event |
| Security value | Constrains destination | Proves the ask |

**Protocol requirement, load-bearing:** the request payload must include a **digest of the specific card it references**. Without that binding, a legitimately signed request and an attacker-supplied card can be mixed and matched, and the whole construction fails. A signed request must mean "send $X to the account in card ⟨digest⟩, which I also signed" — one statement, not two independently relayable ones.

This split also resolves the freshness tension cleanly: the card is old on purpose (age is the signal, D-08), and freshness comes from the request's own expiry, not from re-signing the card.

> **Storage model superseded by Design Session 3 (2026-08-09) — D-13.** The two-artifact split and the digest binding stand. What changes is where the card *lives*: it is long-lived at the owner, transmitted with every request, and retained by the recipient only as a baseline record (`{digest, first-seen, last-seen, masked tail}`) rather than as a stored card. Defensive behaviour is unchanged; Q-04 closes as a side effect.

### D-07 · The card constrains the destination — this materially answers Q-01

Session 1's residual (Q-01) was that the scam adapts to *"I can't sign, I lost my phone,"* leaving the defense resting on a family holding a policy line. Cards narrow that considerably.

Consider the grandparent scam with cards deployed. The recipient's app holds one card for their child, pinned, unchanged for eight months. The request must reference it. The attacker cannot produce a new card without the real child's key. So even against a **fully deceived** victim who believes every word of the pretext, the money can only travel to the child's actual bank account — recoverable, and not under the attacker's control.

**The scam's economics collapse.** Total loss becomes "funds are sitting in your kid's account."

That is a different and much better security posture than "refuse unsigned requests," and it is easier for a family to hold, because the rule constrains a *destination* that is already fixed rather than requiring judgment in the moment. The policy becomes **"money only ever goes to a card you already have"** — no assessment of the caller's story required.

**Honest limits.** Gift cards, wire-to-stranger, and cash-app-to-new-recipient scams route outside the card system entirely, so the behavioral rule still has to cover them ("never gift cards, never a destination without a card"). And the whole construction only protects payments to counterparties you have physically met — see D-10.

### D-08 · Card age is a first-class security signal, not incidental metadata

The BEC playbook is a **last-minute change** of banking details. `#26` already answers this with loud signed-change diffing. Pre-authoring strengthens it into something sharper: a card carries a visible history.

- *"This card has been unchanged since March"* — strong signal.
- *"This card was created four minutes ago"* — the thing that should stop a transaction cold.

The UI should surface card age and change history at the moment of payment, with the same care SPEC.md §5 gives the approval screen. A newly created or recently changed card is not invalid — people do change banks — but it must be visually distinct from a settled one, and the burden of confirming a change out-of-band belongs at that moment.

### D-09 · Relationship to `#26` — a real extension, not a duplicate

`#26` already specifies payment details as a signed artifact rendered as *"a pinned, immutable verified card"* with signed-change diffing. The card concept is genuinely already there. What this proposal adds:

1. **Pre-authoring** — cards exist before any transaction, rather than being sent per-transaction.
2. **Reuse** — one card attaches to many requests; no re-entry of banking details.
3. **Composition with a signed request** — replacing `#26`'s rule (3), which currently pairs with a live `#15` presence check and therefore inherits `#15`'s delay.
4. **Age as an explicit security property** (D-08), implicit in `#26`'s diffing but not first-class.

Item 3 is the important one for this doc: **it lets `#26` deliver its anti-BEC value without `#15`.** `#26` is already Near-term priority, so the marginal lift is small if scoped into the same release.

### D-10 · Prior art and honest scoping

This is, in effect, **serverless Confirmation of Payee** — the UK bank-run scheme that matches payee name to account before a transfer — extended to crypto rails and requiring no bank participation. Naming the analogue is useful for positioning and keeps the claim proportionate.

The differentiator is real: no bank in the loop, works across any rail including wallet addresses, and it defends the clipboard-hijacking attack class (address substitution malware) because the recipient's app compares against a **pinned card** rather than trusting a pasted string. That connects to Expansion I's smart-wallet work.

**The scoping limit that must not be glossed:** this protects payments to people you have physically met. A large share of real fraud loss is payments to *strangers* — fake invoices, romance, investment scams — which the closed loop cannot reach at all. The addressable slice is known-counterparty payments: `#26`'s real-estate and vendor cases, and the family case. That is a substantial and well-documented slice, but it is a slice.

---

### Session 1's open questions, revisited

- **Q-01 (behavioral residual)** — materially improved by D-07, not eliminated. The policy shifts from "refuse unsigned requests" (requires in-the-moment judgment) to "funds only to an existing card" (a fixed constraint). Gift-card and stranger-payment channels remain outside it.
- **Q-02 (action-string wording)** — largely resolved. With a card reference carrying the destination, the request payload becomes structured — amount, card digest, optional reason — rather than free text. The ambiguity attack ("$5,000 transfer between you and Mom") is much harder to express when the direction is implied by whose card is bound.
- **Q-03 (replay/expiry)** — resolved by the split in D-06: requests are one-shot and expiring; cards are long-lived and versioned. Two different mechanisms for two different lifetimes, rather than one compromise.

### New open questions

**Q-04 · Card revocation has no reliable delivery path. — CLOSED by Design Session 3 (D-11).** *The card now travels with every request, so there is no stale-card state to repair and no revocation to deliver. Original text kept for the reasoning trail.* An owner closes an account and signs a replacement card — but delivery runs on the same manual share-sheet transport as everything else (verified 2026-08-09, `Organizational Identity Graph/FINDINGS.md` F-02). A counterparty who never receives it will pay to a dead account. Not a *security* failure — funds do not reach an attacker — but an operational one, and it needs an explicit answer rather than discovery in production. The unconditional-reattachment pattern from `Multi-Device Contacts/FINDINGS.md` Design Session 10 is the obvious precedent.

**Q-05 · Duress-signed cards.** Someone coerced into signing a card pointing at an attacker's account defeats the construction entirely. The duress cluster applies as it does everywhere, and D-08's age signal is the partial mitigation (a brand-new card at payment time is exactly the flag). Whether anything stronger is warranted here is undecided.

**Q-06 · Multiple cards per contact.** Checking, savings, a crypto wallet — the request must specify which, and the selection UI is a place where a rushed user makes mistakes. Unscoped.

**Q-07 · Third-party PII at rest. — REWRITTEN by Design Session 3 (D-14), not closed.** *Full cards are no longer stored; only `{digest, first-seen, last-seen, masked tail}` is. But a digest over bank details is brute-forceable (~2⁴⁰–2⁵⁰ real-world entropy), so it remains PII for bank rails and is genuinely protective only for crypto addresses. The real gain is masked display, not storage elimination. Original framing below.* Holding a counterparty's card means holding their banking details on your device. `#26` already has this property for received instructions, and the local DB is encrypted, but the exposure is real under a compromised or coerced device, and it is *someone else's* data with no control on their side. Consider deniable-partition handling (`#6`), the same recommendation F-07 made for org credentials.

---

### Recommendation

**Pursue this, and sequence it inside `#26` rather than as a separate feature.** The card half stands on its own merits, materially improves Session 1's weakest point, requires no new cryptography, and lets an already-Near-term feature deliver its core anti-BEC value without waiting on `#15`.

The intent-signature half (Session 1) is worth keeping in the same release, but it is now clearly the junior partner: it proves who asked, while the card constrains where value goes, and only the second survives a fully deceived victim.

Q-01's product decision from Session 1 still stands, but it is a smaller decision than it was — the policy a family must hold is now concrete and destination-bound rather than a judgment call under pressure.

### Action items

- Scope the card/request split into `#26` directly; note the extension in the Master doc's `#26` entry rather than leaving it only here.
- Specify the request→card digest binding (D-06) as a hard protocol requirement before any implementation — the construction fails without it.
- Design the card-age and change-history surface (D-08) with SPEC.md §5's "security-critical screen" discipline.
- Answer Q-04 (revocation delivery) using the unconditional-reattachment precedent.
- Carry the D-10 scoping limit into any positioning material: this protects payments to physically-met counterparties, not payments to strangers.

---

## Design Session 3 — Card Transport: Send Every Time, Store a Baseline (2026-08-09)

**Question raised:** should the counterparty's card be held on the recipient's device at all, or sent fresh with every request?

**Answer: send it every time — and keep a minimal comparison baseline.** The transport instinct is right and closes a real open problem. Dropping storage *entirely* would remove the primary BEC defense, so the two are complements rather than alternatives.

### D-11 · Sending the card with every request — adopted

Three properties, all of them wins:

- **Freshness is automatic.** Every request carries current details, so "I closed that account" propagates with the next payment rather than needing a separate revocation broadcast over the manual share-sheet transport. This closes Q-04 (see below) without new mechanism.
- **Each request is self-contained.** The recipient verifies the card's signature against the identity key they already pinned at the UWB exchange — no dependency on what they happen to hold locally. Same property that made the org graph's artifacts independently verifiable (`Organizational Identity Graph/FINDINGS.md` D-10).
- **Survives recipient device loss or reinstall.** A counterparty who re-pairs is immediately functional; nothing needs re-sending out of band.

### D-12 · Storage-free removes change detection, which *is* the BEC defense

`#26`'s rule (2) — *"changes must be signed by the same key, and the UI diffs loudly (⚠ account number changed from the instructions received June 3)"* — requires remembering a previous value. With nothing stored, there is nothing to compare against.

The BEC playbook is precisely a **last-minute change of banking details**. A design where every request arrives fresh and unremarkable renders that change invisible: the attack becomes indistinguishable from normal operation. This is not a degradation at the margin; it removes the specific control the feature exists to provide.

Two further losses follow:

- **Card age (D-08) disappears.** "Unchanged since March" versus "created four minutes ago" is a memory-dependent signal.
- **D-07's strongest claim weakens.** The "fully deceived victim cannot lose the money" property assumed a pinned destination. If the counterparty is themselves coerced into signing a fresh card (Q-05), a stored baseline raises a loud diff; with no baseline, the attacker's card arrives looking entirely ordinary.

### D-13 · Resolution — authoritative content in transit, tripwire at rest (supersedes D-06's storage model)

- **The card in the request is the authoritative content.** It carries the destination, it is verified per request, and it is what the payment acts on.
- **The stored record is a tripwire, not a dependency.** Persist only `{digest, first-seen, last-seen, masked tail}` — never the full details.

That baseline is sufficient for all three defensive behaviours: change detection (digest comparison), age (first-seen), and a diff the user can act on — *"account ending ···4471 → ending ···8823, changed today."* Masking the displayed value arguably improves the diff over `#26`'s original framing, since a stale full account number on screen is itself something a confused user might act on.

Q-04's revocation problem then resolves as a side effect rather than a mechanism: sign a replacement card, the next request carries it, the recipient sees a loud diff. No broadcast, no delivery guarantee needed.

### D-14 · The digest's privacy benefit is partial, and must be described as such

A stored digest is weaker protection than it appears for bank rails. Account and routing numbers carry low entropy — very roughly 2⁴⁰–2⁵⁰ once real-world structure is accounted for (a few tens of thousands of valid ABA routing numbers, account numbers typically 8–12 digits) — so an attacker holding the device can brute-force a digest back to the account. Salting does not help, because the salt must be stored alongside it.

- **Crypto addresses:** the digest is genuinely protective (2¹⁶⁰), and the addresses are public anyway.
- **Bank details:** treat the digest as PII regardless. It belongs in the encrypted local DB with everything else.

This reframes Q-07 rather than solving it. The card was always going to live in an encrypted database; the real exposure was a coerced or compromised *unlocked* device, and a digest does not help there either. The genuine improvement is the **masked display** — casual inspection shows `···4471` rather than full details. That is a reduction in harm, not an elimination, and Q-07 should say so rather than implying the digest closes it.

---

### Session 2's open questions, revisited

- **Q-04 (revocation delivery) — closed.** Dissolved by D-11: the current card always travels with the request, so there is no stale-card state to repair and no broadcast to deliver.
- **Q-05 (duress-signed cards) — unchanged, and now more clearly load-bearing.** The stored baseline is the only thing that flags an attacker's freshly-signed card, which makes D-13's tripwire the mitigation rather than an optimisation.
- **Q-06 (multi-card selection) — partially simplified.** Selection moves to the sender at send time, on the device of the person who knows which account they want, rather than the recipient choosing among stored cards. The rushed-user risk shifts rather than vanishing.
- **Q-07 (third-party PII at rest) — rewritten, not closed.** See D-14. Reduced to masked display plus a brute-forceable digest for bank rails; genuinely protective for crypto rails.

### Action items

- Update D-06's composition table: the card is long-lived *at the owner*, transmitted per request, and retained by the recipient only as a baseline record.
- Specify the baseline record shape `{digest, first-seen, last-seen, masked tail}` alongside the request→card digest binding when this is scoped into `#26`.
- Q-07 in Session 2 should be read through D-14 — the digest is a partial mitigation, not a solution.
- Diff and age surfaces (D-08, D-13) remain a security-critical screen per SPEC.md §5 discipline.

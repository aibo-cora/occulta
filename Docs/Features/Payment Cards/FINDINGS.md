# Verified Payment Cards — Design Findings

**Status:** Exploratory — no SPEC.md yet. Scoped as an extension of Consumer Feature `#26` (Verified Payment Instructions, `Master Feature & Expansion Analysis.md` §26), which is **Near-term** priority.
**Origin:** Consolidated 2026-08-09 from `Presence Verification/FINDINGS.md` Design Sessions 2–3, which reached this design while looking for a construction of `#15` that the relay attack does not reach. Payment-card material has been removed from that doc; see [Provenance](#provenance).

---

## Problem

Business Email Compromise and payment-redirection fraud are the largest documented loss pool adjacent to this app: **$3.05B in BEC losses across 24,768 complaints** (FBI IC3 2025), **$275.1M in real-estate wire fraud alone** (up from ~$173M), with 86% of BEC losses moving by wire/ACH and effectively unrecoverable. The family-facing variant — voice-clone "grandparent" scams — accounts for a further **$2.4B in reported FTC losses for adults 60+**.

The attack is always the same shape: **redirect funds to an account the attacker controls**, usually via a last-minute "our bank details have changed."

The industry's own best practice is a verbal code agreed with your title company at the start of a transaction — leakable, forgettable, and socially engineerable. `#26` established the cryptographic replacement. This doc extends it.

---

## The design

### D-01 · Two artifacts with different lifetimes

Both SE-signed under their own domain-separated prefixes, both biometric-gated by construction (SE key use already requires a biometric gate — not a new property to build).

| | **Card** | **Request** |
|---|---|---|
| Content | "Value reaching me goes to account/IBAN/wallet ···4471" | "I am asking you for $5,000" |
| Authored | Once, ahead of time, by the owner | Per event |
| Lifetime | Long-lived, versioned, maintained by the owner | One-shot, expiring |
| Held by | The owner; transmitted with every request (D-03) | Transient |
| Security role | **Constrains the destination** | Proves the ask |

The request's security property — that the signer attests to their *own intent* rather than to an observable circumstance, so no plausible pretext exists for producing it — is established in [Presence Verification/FINDINGS.md](../Presence%20Verification/FINDINGS.md) D-01–D-02 and not restated here.

### D-02 · The request MUST bind a digest of the card — load-bearing

Without this binding, a legitimately signed request and an attacker-supplied card can be mixed and matched, and the construction fails outright.

A signed request must mean **"send $X to the account in card ⟨digest⟩, which I also signed"** — one statement, not two independently relayable ones.

This is the single specification item that must be settled before any implementation work begins.

### D-03 · The card travels with every request

Not stored-and-referenced; transmitted each time. Three consequences, all wins:

- **Freshness is automatic.** "I closed that account" propagates with the next payment. No revocation broadcast, no delivery guarantee needed — which is what closes the revocation problem entirely (see Closed questions).
- **Each request is self-contained.** The recipient verifies the card's signature against the identity key already pinned at the UWB exchange, with no dependency on local state. Same property that made the org graph's artifacts independently verifiable (`Organizational Identity Graph/FINDINGS.md` D-10).
- **Survives recipient device loss or reinstall.** A counterparty who re-pairs is immediately functional.

### D-04 · The recipient stores a baseline, not a card

Persist only `{digest, first-seen, last-seen, masked tail}` — never full details.

This is sufficient for all three defensive behaviours: change detection (digest comparison), age (first-seen), and an actionable diff — *"account ending ···4471 → ending ···8823, changed today."*

Masking the displayed value is arguably an improvement on `#26`'s original diff framing, since a stale full account number on screen is itself something a confused user might act on.

**Storage cannot be dropped entirely.** `#26` rule (2) — *"changes must be signed by the same key, and the UI diffs loudly"* — requires remembering a previous value. With nothing stored, a last-minute account switch becomes indistinguishable from normal operation, which is precisely the attack. Card age (D-06) and the deceived-victim property (D-05) go with it.

---

## Why it works

### D-05 · The destination constraint survives a fully deceived victim

This is the standout property, and it is rare. Almost every anti-fraud control fails once the victim believes the story.

Consider the grandparent scam with cards deployed. The recipient's app holds a baseline for their child's card, unchanged for eight months. The request must reference it. The attacker cannot produce a new card without the real child's key. So even against a victim who believes **every word** of the pretext, funds can only travel to the child's actual bank account — recoverable, and not under the attacker's control.

**The scam's economics collapse:** total loss becomes "the money is sitting in your kid's account."

The resulting policy is also easier to hold than "refuse unsigned requests," because it constrains a *destination* already fixed rather than requiring judgement under pressure: **"money only ever goes to a card you already have."**

### D-06 · Card age is a first-class security signal

The BEC playbook is definitionally a last-minute change. Pre-authoring turns that into a visible signal:

- *"This card has been unchanged since March"* — strong.
- *"This card was created four minutes ago"* — should stop a transaction cold.

Surface age and change history at the moment of payment, with the discipline `Presence Verification/SPEC.md` §5 applies to its approval screen. A new or recently-changed card is not invalid — people do change banks — but it must be visually distinct, and the burden of out-of-band confirmation belongs at that moment.

---

## Scope and limits

### D-07 · What this cannot reach

- **Payments to strangers.** Romance, investment, and fake-invoice scams from vendors never met are permanently outside the closed loop. This is a large share of total fraud loss.
- **Gift cards and cash-app rails**, which route around the card system entirely.
- **A behavioural dependency survives.** "Only pay to an existing card" must be held as a policy. Better than a safe word — it cannot leak and cannot be forgotten — but it is not a cryptographic guarantee and copy must never imply otherwise.
- **"Two independent verifications" is weaker than it sounds.** The same SE key signs both artifacts; key compromise yields both. The split buys clarity and an age signal, not independent security domains.

### D-08 · Prior art and differentiation

This is, in effect, **serverless Confirmation of Payee** — the UK bank-run scheme matching payee name to account before transfer — extended to crypto rails and requiring no bank participation.

| | Coverage | Gap |
|---|---|---|
| UK Confirmation of Payee | Bank-run, name-to-account | Participating UK banks only; no crypto |
| US | — | No equivalent shipping |
| Title/escrow industry | Verbal codes, callbacks, insurance | Leakable, socially engineerable, post-hoc |
| Crypto wallet address books | Local convenience | Unsigned, trust-on-first-use, no binding to a verified human |

The genuine differentiator: **a payee destination cryptographically bound to a human you physically verified, with tamper-evident change history, serverless, cross-rail.** It also defends address-substitution (clipboard-hijacking) malware, because the recipient's app compares against a signed card rather than trusting a pasted string — which connects to Expansion I's smart-wallet work.

---

## Relationship to `#26`

`#26` already specifies payment details as a signed artifact rendered as *"a pinned, immutable verified card"* with signed-change diffing. The card concept exists there. This adds:

1. **Pre-authoring** — cards exist before any transaction rather than being sent per-transaction.
2. **Reuse** — one card serves many requests; no re-entry of banking details.
3. **Composition with a signed request**, replacing `#26` rule (3)'s pairing with a live `#15` presence check.
4. **Age as an explicit security property** (D-06), implicit in `#26`'s diffing but not first-class.
5. **A defined transport and storage model** (D-03, D-04).

**Item 3 is the sequencing consequence: `#26` can deliver its core anti-BEC value without `#15`.** `#26` is already Near-term, so marginal lift is small if scoped into the same release.

---

## Open questions

### Q-01 · Duress-signed cards — load-bearing

Someone coerced into signing a card pointing at an attacker's account defeats the construction entirely. The duress cluster applies as everywhere, and D-06's age signal is the partial mitigation — a brand-new card at payment time is exactly the flag.

**This was a side note until D-04 made the stored baseline the *only* thing that flags an attacker's freshly-signed card.** It now carries the mitigation rather than merely optimising it, and deserves a real answer rather than deferral to the duress cluster.

### Q-02 · Multiple cards per contact

Checking, savings, a crypto wallet — the request must specify which. Under D-03 the selection moves to the sender at send time, on the device of the person who knows which account they want, which is better than the recipient choosing among stored cards. The rushed-user risk shifts rather than vanishing. Unscoped.

### Q-03 · Third-party PII at rest — partial mitigation, not a solution

A digest over bank details is brute-forceable: account and routing numbers carry roughly 2⁴⁰–2⁵⁰ real-world entropy (a few tens of thousands of valid ABA routing numbers; account numbers typically 8–12 digits), and salting does not help because the salt must be stored alongside.

- **Crypto addresses:** genuinely protective (2¹⁶⁰), and public anyway.
- **Bank details:** treat the digest as PII; it belongs in the encrypted local DB with everything else.

The card was always going into an encrypted database, and the real exposure is a coerced or compromised *unlocked* device — where a digest does not help either. The genuine gain is **masked display**, a reduction in harm rather than an elimination. Consider deniable-partition handling (`#6`), the same recommendation `Organizational Identity Graph/FINDINGS.md` F-07 made for org credentials.

### Q-04 · Competitive timing on bank rails

EU regulation has been pushing verification-of-payee onto SEPA transfers. If banks solve this for bank rails, the differentiated slice narrows toward crypto, cross-border, and non-bank rails. **Not verified against current regulation** — check before this informs positioning.

### Q-05 · `CRYPTO_REVIEW_CHECKLIST` gate

`#26`'s ruling requires running `CRYPTO_REVIEW_CHECKLIST §4` (Security property verification). The convention is live and exercised in-code (`ShamirSecretSharing.swift`, `Key+Manager.swift`) with a fixed five-section template, but the canonical document at the referenced path `Docs/Audit/CRYPTO_REVIEW_CHECKLIST.md` was not locatable on 2026-08-09. Deferred, not resolved. The gate is followable today by matching the in-code pattern.

---

## Closed

**Card revocation delivery — closed by D-03.** Previously flagged as needing an explicit answer: an owner closes an account, signs a replacement, but delivery runs on the manual share-sheet transport (`Organizational Identity Graph/FINDINGS.md` F-02), so a counterparty who never receives it pays to a dead account. Dissolved once the card travels with every request — there is no stale state to repair and nothing to broadcast. Sign a replacement, the next request carries it, the recipient sees a loud diff.

---

## Adoption and viability

**Technical viability: high.** Zero new cryptography — domain-separated signing, structured payloads, existing bundle transport, and the card UI concept already present in `#26` rule (1). Low-medium lift per `#26`'s own assessment.

**Audience: the most mainstream-reaching item on the roadmap.** This is the feature that reaches people who would never install a privacy app — a home buyer installing because their title company asked, an adult child installing to protect a parent. `#27`'s install loop is physically verified by construction, since every install requires a UWB ceremony with someone already in the network.

**The risk is concentrated in one place: two-sided cold start.** Nothing about the design is uncertain; whether a title office can get clients to install an app mid-transaction is. `#26`'s ruling notes that *"one cautious title office can adopt unilaterally for its clients"* — that unilateral adoption is the thing to test before scaling investment.

**Strongest wedge: real-estate/title.** Transaction value ($300K+) justifies friction, the parties already meet in person, and the loss is catastrophic and uninsured. Family case second, carrying `#27`'s viral loop.

**Gating is internal, not external** — specification work and house-process items, no dependency on another vendor's product decisions or another organisation's risk appetite. That contrasts sharply with the org identity graph, whose gates are both external.

---

## Action items

- Specify the request→card digest binding (D-02) before any implementation — the construction fails without it.
- Specify the baseline record shape `{digest, first-seen, last-seen, masked tail}` (D-04).
- Design the age and diff surfaces (D-04, D-06) as security-critical screens per `Presence Verification/SPEC.md` §5 discipline.
- Answer Q-01 (duress-signed cards) properly rather than deferring to the duress cluster — D-04 made it structural.
- Verify Q-04 (bank verification-of-payee timing) before positioning work.
- Carry D-07's scoping limit into any positioning material: this protects payments to physically-met counterparties, not payments to strangers.
- Scope into `#26` rather than as a separate feature.

---

## Provenance

Consolidated 2026-08-09 from `Presence Verification/FINDINGS.md` Design Sessions 2 (Pre-Authored Payment Cards and Request Binding) and 3 (Card Transport: Send Every Time, Store a Baseline), both dated 2026-08-09. Items were renumbered for readability; the mapping below preserves traceability to commits `c9a3238` and `0a717ef`.

| This doc | Original |
|---|---|
| D-01 | Session 2 D-06 (as amended by Session 3 D-13) |
| D-02 | Session 2 D-06 (digest binding) |
| D-03 | Session 3 D-11 |
| D-04 | Session 3 D-12, D-13 |
| D-05 | Session 2 D-07 |
| D-06 | Session 2 D-08 |
| D-07 | Session 2 D-10 (scoping half) |
| D-08 | Session 2 D-10 (prior art half) |
| Relationship to `#26` | Session 2 D-09 |
| Q-01 | Session 2 Q-05 |
| Q-02 | Session 2 Q-06 |
| Q-03 | Session 2 Q-07, as rewritten by Session 3 D-14 |
| Closed (revocation) | Session 2 Q-04, closed by Session 3 D-11 |

Retained in `Presence Verification/FINDINGS.md` because they concern `#15`/`#27` rather than payments: Session 1 D-01–D-05 (the intent-vs-circumstance construction), D-04 (the `#27` dependency correction), and Q-01–Q-03 (the behavioural residual, action-string wording, replay semantics).

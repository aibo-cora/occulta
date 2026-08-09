# Verified Payment Cards — Design Findings

**Status:** Exploratory — no SPEC.md yet. Scoped as an extension of Consumer Feature `#26` (Verified Payment Instructions, `Master Feature & Expansion Analysis.md` §26), which is **Near-term** priority.
**Origin:** Consolidated 2026-08-09 from `Presence Verification/FINDINGS.md` Design Sessions 2–3, which reached this design while looking for a construction of `#15` that the relay attack does not reach. Extended 2026-08-09 by a gap review that settled the key architecture, the payload layouts, the storage model, and the threat model; see [Provenance](#provenance).

---

## Problem

Business Email Compromise and payment-redirection fraud are the largest documented loss pool adjacent to this app: **$3.05B in BEC losses across 24,768 complaints** (FBI IC3 2025), **$275.1M in real-estate wire fraud alone** (up from ~$173M), with 86% of BEC losses moving by wire/ACH and effectively unrecoverable. The family-facing variant — voice-clone "grandparent" scams — accounts for a further **$2.4B in reported FTC losses for adults 60+**.

> **[UNCITED]** These figures are carried from `#26` without sources. They are load-bearing for the priority ruling and for all positioning material, and the docs are discoverable (`Docs/Audit/LanguageRiskReview2026-08-01/`). Add report edition, URL, and retrieval date before any of this reaches public copy.

The attack is always the same shape: **redirect funds to an account the attacker controls**, usually via a last-minute "our bank details have changed."

The industry's own best practice is a verbal code agreed with your title company at the start of a transaction — leakable, forgettable, and socially engineerable. `#26` established the cryptographic replacement. This doc extends it.

---

## The design

### D-01 · Three artifacts with different lifetimes

| | **Certificate** | **Card** | **Request** |
|---|---|---|---|
| Content | "This payment key is mine" | "Value reaching me goes to account ···4471" | "I am asking you for $5,000" |
| Signed by | Identity key (SE) | Payment key (SE) | Payment key (SE) |
| Authored | Once per device | Content once, ahead of time; signed per recipient at send (D-15) | Per event |
| Lifetime | Long-lived, versioned | Long-lived, versioned, expiring | One-shot, expiring |
| Held by | Owner; sent with every request | Owner; sent with every request (D-03) | Transient |
| Bound to | The signing device | The recipient (D-15) | The payer (D-11) |
| Security role | Roots the payment key in the pinned identity | **Constrains the destination** | Proves the ask |

**Correction (2026-08-09).** The original D-01 asserted both artifacts were *"biometric-gated by construction (SE key use already requires a biometric gate — not a new property to build)."* **This was false.** The identity key is created with `[.privateKeyUsage]` only (`Key+Manager.swift:94-97`) and `signData` calls `SecKeyCreateSignature` with no `LAContext` and no prompt (`Key+Manager.swift:315-322`). Identity-key signing is **silent on an unlocked device**. Only the vault key carries `.biometryCurrentSet + .devicePasscode` (`Key+Manager.swift:655`); `shardCustody` is explicitly *"no biometric flag"* (`Key+Manager.swift:749`).

The gate is a new property, and D-09 builds it. Until then, Q-01's duress exposure is worse than previously stated: a coercer holding an unlocked phone does not need to compel a biometric — they open the app and sign.

The request's security property — that the signer attests to their *own intent* rather than to an observable circumstance, so no plausible pretext exists for producing it — is established in [Presence Verification/FINDINGS.md](../Presence%20Verification/FINDINGS.md) D-01–D-02 and not restated here. Its two open questions (action-string wording, replay/expiry) are answered by D-11.

### D-02 · Two digests, not one — they have opposite requirements

The original D-02 named "a digest of the card" as the single blocking specification item and did not say what the digest covers. Splitting it is the answer, because the binding job and the change-detection job pull in opposite directions.

| | `cardDigest` — in the request | `destinationDigest` — in the baseline |
|---|---|---|
| Job | Bind this request to exactly one card | Detect that the destination changed |
| Covers | The card's **entire** canonical signing payload | The rail's destination tuple **only** |
| Failure if wrong | Mix-and-match becomes possible | Every benign re-issue fires the tripwire |

A signed request means **"send $X to the account in card ⟨cardDigest⟩, which I also signed"** — one statement, not two independently relayable ones. Without the binding the construction fails outright.

If a single digest did both jobs, either the binding weakens or the owner re-signing an identical card — new `createdAt`, corrected bank name — renders as *"account changed today."* That is alarm fatigue on the one control carrying the entire BEC defence.

**Ruling: `destinationDigest` covers the destination only.** Payee name and label changes bump the version and are visible in the card, but do not fire the red alarm. Keeping the alarm rare is what keeps it credible (D-06).

Three requirements follow:

- **Never digest the signature.** ECDSA's random `k` makes an identical card produce a different signature each time it is signed, so card identity would be non-deterministic and the tripwire would fire on a no-op re-sign.
- **Length-prefix every variable-length field** as `UInt16 BE length ∥ bytes`. `SignedAttribute.signingPayload` concatenates bare (`SignedAttribute.swift:134-155`); that is unambiguous only because no `Category` case is a prefix of another and `value` sits last — safe by luck of the enum, not by construction. A card has several free-text fields where `"AB"∥"C"` and `"A"∥"BC"` collide, and a canonicalization ambiguity here *is* a destination-substitution vector.
- **Normalization is per-rail and must be injective on valid inputs.** Without it `GB29 NWBK…` and `GB29NWBK…` are different destinations. Over-normalize — strip non-alphanumerics, lowercase an EIP-55 address — and a checksum dies or two destinations collapse into one digest, which is a silently suppressed diff. Requires an explicit per-rail table, not implementation discretion.

### D-03 · The card travels with every request

Transmitted each time, alongside the certificate — never referenced by digest alone. The payer also retains the last one received (D-04), but that is a fallback: freshness is a property of transmission, not of storage. Three consequences:

- **Freshness is automatic.** "I closed that account" propagates with the next payment. No revocation broadcast, no delivery guarantee needed for the benign case (see [Revocation](#revocation)).
- **Each artifact is self-contained.** The recipient verifies the certificate against the identity key pinned at the UWB exchange, then the card against the payment key the certificate carries. No dependency on local state. Same property that made the org graph's artifacts independently verifiable (`Organizational Identity Graph/FINDINGS.md` D-10).
- **Survives payer device loss or reinstall.** A payer who re-pairs is immediately functional.

**The resilience is one-sided.** The reverse is not true: when the *payee* wipes or replaces their phone, their SE identity key regenerates, re-pairing mints a fresh key (`Multi-Device Contacts/FINDINGS.md:37`), and signed key rotation does not exist — it is parked as the projected "Contact Migration Protocol." Every card that payee ever signed stops verifying, and from the payer's side **a legitimate phone upgrade and an impersonation attempt are the same event**. Failing closed is correct; the cost is real and belongs recorded. For the real-estate wedge it means a title officer replacing their phone invalidates every client's card and each client must return in person.

**Transport is manual.** F-02 (`Organizational Identity Graph/FINDINGS.md`) stands here: there is no automatic delivery channel post-pairing, and every peer-to-peer bundle goes through `ActivityView.swift`'s share sheet. Org Graph D-14 exempted *relying-party-directed* artifacts; cards are peer-to-peer and are the case D-14 left in scope. See [Adoption](#adoption-and-viability) for what that costs and where.

### D-04 · The recipient stores the signed card in full, plus one locally-observed index

**Ruled 2026-08-09 (Q-06): the tripwire wins over storage minimization.** The original design stored `{digest, first-seen, last-seen, masked tail}` and explicitly *not* the card, on PII grounds. That is reversed. Two tables:

```
StoredCard           (contactID, cardID)            → latest signed SignedAttribute blob, receivedAt
DestinationBaseline  (contactID, destinationDigest) → firstSeenAt, lastSeenAt
```

`DestinationBaseline` holds the only thing not derivable from a card: **local observation.** Version, destination, masked tail and the card's own `createdAt` all come from the stored blob, so no third table is needed — this is simpler than the minimal design it replaces, not more complex.

Storing the signed artifact rather than extracted fields buys three things, and the first is a security property:

- **It closes baseline poisoning.** A stored plain destination can be edited by an attacker with an unlocked payer device, pre-seeding a row so a later attacker card shows no change. A stored *signed card* cannot be forged — the attacker would need the payee's payment key. The residual reduces to row *deletion*, which fails safe: the next card reads as first-seen and fires the age signal (D-06).
- **It fixes the diff.** With only a masked tail stored, an attacker can pick a destination whose last four digits match — trivial for a vanity-generated crypto address. The digest comparison still fires, but the user reads *"···4471 → ···4471, changed today"* and concludes it is a glitch. The tripwire technically works while being defeated in practice. Full destinations make the diff show what actually changed.
- **It survives transport suppression.** An attacker who owns the channel can drop the bundle and send plain instructions instead. A payer holding the last good signed card can still pay the known destination without the attacker-controlled channel supplying anything.

**D-03 is unchanged: the card still travels with every request.** Storage is a fallback and a memory, not a replacement — freshness depends on transmission. What storage removes is the payer's *dependency* on that transmission.

- **First-seen belongs to the destination, not the card.** *"Have I paid this account before, and since when"* is the question D-06 actually asks. A new card lineage aimed at a known destination inherits its age — which is what makes the age signal immune to card churn and to the per-device lineages D-09 introduces.
- **Version and rollback are checked against `StoredCard`**, scoped per device.

**Cost, accepted deliberately:** full counterparty destinations at rest (Q-03). Mitigated by machinery the [Forensic cleanliness](#forensic-cleanliness) section already requires — encrypted DB, non-nil depth from creation, cascade delete — and by the fact that the app already holds full destinations for the owner's own cards (D-12). The exposure grows; the class does not.

**Version is a hard check, not a display field.** Four rules:

| Observed | Action |
|---|---|
| `version > stored` | Accept; diff the destination if it changed |
| `version == stored`, same destination | Idempotent re-receipt; silent |
| `version == stored`, different destination | **Forked card — hard reject.** No benign path produces this |
| `version < stored` | **Refuse the artifact.** Not a diff, not a warning |

The last rule is the point. Without it a replayed older-but-validly-signed card renders as an ambiguous *"···4471 → ···8823, changed today"* that the user resolves by guessing direction. With it, rollback is a rejection rather than a judgement call.

**Version does not close replay on its own.** A payer who never saw the newer card matches the replayed old one exactly, sees no diff, and reads its age as *old and stable* — the reassuring case. Only the request's expiry (D-11) bounds that.

**Storage cannot be dropped entirely.** `#26` rule (2) — *"changes must be signed by the same key, and the UI diffs loudly"* — requires remembering a previous value. With nothing stored, a last-minute account switch is indistinguishable from normal operation, which is precisely the attack. See Q-03 and Q-06: the case for storing *more* than this has since strengthened three separate ways.

**Masking is a surface rule, not a storage rule.** See [Threat model](#threat-model) — getting it backwards removes the only defence against paste-swap malware.

### D-05 · The destination constraint survives a fully deceived victim

This is the standout property, and it is rare. Almost every anti-fraud control fails once the victim believes the story.

Consider the grandparent scam with cards deployed. The payer's app holds a destination baseline for their child, unchanged for eight months. The request must reference a card the child signed, and the attacker cannot produce one.

**Corrected framing (2026-08-09).** The original text read *"funds can only travel to the child's actual bank account."* That is the copy D-07 prohibits: Occulta never moves money, and the payer types the destination into their own bank. `#26`'s own wording is the correct one — the attacker's destination *"cannot even be **represented** as verified."*

> So even against a victim who believes every word of the pretext, the attacker's destination cannot be represented as verified: the app shows an unsigned instruction to an account it has never seen, beside a card unchanged for eight months. What the victim does next is still theirs — but the decision has become **"ignore a plain warning," not "detect a lie."**

**When the policy holds, the scam's economics collapse:** total loss becomes "the money is sitting in your kid's account." That is the outcome conditional on the policy, not the default outcome.

The policy is also easier to hold than "refuse unsigned requests," because it constrains a *destination* already fixed rather than requiring judgement under pressure: **"money only ever goes to a card you already have."**

### D-06 · Card age is a first-class security signal — read from local observation only

The BEC playbook is definitionally a last-minute change. Pre-authoring turns that into a visible signal:

- *"This destination has been unchanged since March"* — strong.
- *"This destination was first seen four minutes ago"* — should stop a transaction cold.

**Age must be driven by `firstSeenAt`, never by the card's signed `createdAt`.** The signed timestamp is whatever the signing device claimed. A coercer with the owner's unlocked phone — Q-01's exact scenario — produces a freshly-signed card bearing a `createdAt` of eight months ago, and every signature verifies. `firstSeenAt` is written by the payer's own device on receipt and cannot be influenced remotely at all.

The honest formulation: **age means "how long *I* have known this destination," never "how old the sender says it is."** The card's own `createdAt` may be displayed, but never as a security signal and never outranking first-seen on the screen.

Surface age and change history at the moment of payment, with the discipline `Presence Verification/SPEC.md` §5 applies to its approval screen. A new or recently-changed destination is not invalid — people do change banks — but it must be visually distinct, and the burden of out-of-band confirmation belongs at that moment.

### D-09 · Key architecture: a dedicated payment key, rooted by certificate

**Decision: a dedicated SE payment signing key per device, protected by `.userPresence`, bound to the identity key by a signed certificate.** Cards and requests are both signed by it.

`#I`'s dedicated-key mandate does *not* apply here — it is scoped to *"signing attacker-supplied digests with the identity key,"* and card payloads are owner-authored, fixed-layout and category-bound. The house pattern agrees: `prepareShards` signs raw key material with the identity key (`Vault+Manager+Shards.swift:87-94`), and every purpose-scoped tag in `Tags` is an encryption/derivation key. There is one signing key in the app today.

The reason for a second one is D-01's correction: the identity key has no biometric gate and cannot acquire one (access control is fixed at creation; changing it means regenerating the identity key and re-pairing every contact). A dedicated key is the only option that makes *"an attacker holding your unlocked phone cannot silently repoint your money"* a hardware property rather than a code path.

- **Policy is `.userPresence`, not `.biometryCurrentSet`.** The stronger flag invalidates the key whenever the user adds a fingerprint or re-enrols Face ID, forcing every card to be re-authored and every payer to see version bumps. The passcode fallback is a real residual and is listed as such in the threat model rather than pretended away.
- **Certificate:** `sign_identityKey(payment_pubKey ∥ deviceID ∥ version ∥ createdAt)`, travelling with every request. The payer verifies it against the identity key pinned at UWB, then verifies card and request against the payment key it carries.
- **Per-device by construction.** SE keys are non-extractable, so each authoring device has its own payment key and its own certificate signed by *that device's* identity key. This stays on the right side of the standing no-vouching rule: `cert_B` only verifies for a payer who pinned `identity_B`, which only happens through a physical ceremony with device B. The certificate scopes a purpose key *within* a device; it never extends trust across one.
- **Certificate versioning reuses D-04's rules.** Store `highestCertVersionSeen` per `(contactID, deviceID)`; reject anything lower. This is what creates a compromise-revocation path that did not previously exist — see [Revocation](#revocation) case 2.

### D-10 · Card schema — destination is a rail-tagged tuple

```
"occulta-signed-attribute-v2" ∥ id(36) ∥ "paymentCard" ∥ createdAt(8) ∥ expiryFlag ∥ expiresAt(8) ∥ value
```

where `value` carries the card's own canonical, length-prefixed layout:

```
cardID(36) ∥ version(UInt32 BE) ∥ rail(1) ∥ LP(destination tuple…)
          ∥ LP(label) ∥ LP(payeeName) ∥ LP(institution) ∥ currency(3, ISO-4217; 0x000000 = any)
  ∥ LP(recipientKeyFingerprint)                                    ← D-15
```

Per-rail destination tuples, in fixed field order:

| Rail | Destination tuple |
|---|---|
| `.achUS` | routingABA(9) + accountNumber + accountType |
| `.wireUS` | routingABA + accountNumber + bankName + **reference** |
| `.iban` | IBAN + BIC? + **reference** |
| `.ukFPS` | sortCode(6) + accountNumber(8) |
| `.crypto` | chainID (CAIP-2) + address + acceptedAssets? |

**The tuple is what `destinationDigest` covers — all of it.** Digesting only "the account number" leaves a coerced routing-number change undetected (account numbers are not globally unique), and omitting `chainID` lets a card be re-pointed at a chain where funds are unrecoverable. Use CAIP-2 rather than a homegrown chain enum; the failure mode of the latter is exactly the ambiguity this section removes.

**The wire/IBAN reference is inside the tuple.** In real estate, money landing at the right bank under the wrong escrow file is a lost wire, not a clerical error. Excluded elsewhere to keep the alarm rare.

**`payeeName` verifies nothing.** It is self-asserted; a coerced owner signs a card naming themselves over a mule account and every signature verifies. It earns its place as a **cross-system check** — banking apps display the beneficiary name at confirmation, and comparing that screen against a signed name catches a substitution Occulta never sees. It must never be presented as a verified fact. See D-08 for the consequence to prior-art framing.

**Mismatch rules are asymmetric, on D-05's own recoverability logic:**

- **Crypto chain or asset mismatch → hard reject.** Wrong-chain sends are permanent and uninsured.
- **Fiat currency mismatch → warn, do not block.** A EUR wire into a USD account is legal and merely expensive; blocking produces a false refusal, warning produces the out-of-band phone call.

**Free-text fields inherit SPEC §5's impersonation rule.** `label`, `payeeName`, `institution` and `reference` render on a security-critical screen, and a label reading `"✓ Verified — same as before"` must not be able to imitate app chrome. Plain text only, visually distinct, byte-capped with the sender-truncates / receiver-rejects-as-malformed pattern from `IdentityChallenge+Constants.swift:31`.

**Fail closed on unknown rails.** A build that does not recognise a rail enum rejects the card outright. A half-rendered destination is worse than none.

### D-11 · Request spec — structured data, locally generated wording

Answers `Presence Verification/FINDINGS.md` Q-02 and Q-03, which govern this artifact and were left behind when the payment material moved.

```
requestID(36) ∥ cardDigest(32) ∥ amount(UInt64 BE, minor units) ∥ currency(3)
             ∥ createdAt(8) ∥ expiresAt(8) ∥ LP(payerKeyFingerprint) ∥ LP(note)?
```

**Q-02 answered by deleting the field.** Q-02 asked for a constrained vocabulary; the stronger answer is that no action string travels at all. The request carries structured data, and the *verifying* device generates the sentence from its own localized template:

> **Yura** is asking you to send **$5,000** to their account ending **···4471** — a destination you've had since March.

Direction and beneficiary are unambiguous by construction rather than by discipline. Nothing can be worded ambiguously, nothing localizes on the wire, and nothing can impersonate app chrome. The age clause renders from the local `DestinationBaseline`, so the reassuring half of the sentence is the half an attacker cannot influence.

An **optional** free-text note may travel under SPEC §5's existing `contextNote` rules. It carries context, never security meaning.

**Q-03 answered:** `expiresAt` inside the signed payload, inheriting `SignedAttribute`'s tamper-proofing (`SignedAttribute.swift:22-25`). Default window **~72 hours**, author-adjustable within a cap — Q-03 is right that the 120 s presence window does not transfer, since a wire request legitimately sits unread over a weekend, but the window must stay short enough to bound D-04's replay residual. **One-shot** via a consumed-`requestID` store retained until each entry's own `expiresAt`, then dropped; SPEC §3.4's outstanding-challenge store is the precedent.

**Bind the payer's key fingerprint.** Not for ordinary relay — a re-aimed request still points at the payee's real account, so the attacker gains nothing. The reason is **duress amplification**: coerce one signature aimed at the attacker's account, then broadcast that single card+request pair to every contact the victim has. Without the binding, one compromised signature is worth N victims. With it, one. The cost — asking three people means three signatures and three biometric prompts — is friction in the right direction.

### D-12 · Cards are `SignedAttribute`s, not a new signed type

New categories `.paymentCard`, `.paymentRequest` (and `.paymentReceipt` if D-14's phase-2 item lands). No new domain prefix.

`category` is **inside** the signing payload — *"Including `category` prevents a category-substitution attack"* (`SignedAttribute.swift:20`) — so a signature over `.financial` does not verify against a `.paymentCard` payload. The category is the intra-family domain separation, and `.shard` (raw GF(2⁸) key material) already coexists safely with `.medical` under the same prefix. A new prefix would re-solve a solved problem.

The stronger argument is infrastructure: `signedAttributes` is already wired into Secure Mode — carried in the layer store (`SecureMode+LayerStore.swift:47`), re-encrypted across key rotation (`Contact+Model+Reencrypt.swift:45`), restored under the staged key during classification (`ContactManager+Classification.swift:272`). A parallel type would mean re-earning every one of those guarantees by hand.

Three items follow:

- **The owner's own cards need a home.** `signedAttributes` hangs off `Contact.Profile` and holds *other people's* attributes; there is no self-profile (searched `isSelf`, `selfProfile`, `selfContact` — no matches). The shard flow is the model: `SignedAttribute` is the artifact, with separate models for owner-side holding (`PendingShardDistribute`) and recipient-side state (`CustodyShard`). Cards need the same, and the owner's store holds **full destinations in the clear** — a larger at-rest exposure than the baselines Q-03 reasons about, on the device of the person being protected.
- **The baselines are their own models.** D-04's tables are not `SignedAttribute`s; the payer verifies the card and discards it. `CustodyShard`'s sealing under `deriveShardCustodyKey()` — an SE-derived key independent of both the DB canonical key and the vault key — is the right precedent.
- **[WIRE COMPAT] Adding a category can break a contact's whole attribute set.** `Category` has no custom `init(from:)`, so an unknown raw value throws — fine in isolation, and the fail-closed behaviour D-10 wants. But `signedAttributes` decodes as an *array*: one `.paymentCard` reaching a build that predates it can fail the entire array decode, taking that contact's medical, emergency and shard attributes with it. `SignedAttribute.swift:27-30` notes v1→v2 needed no migration *only because SSS had not shipped*. Cards will ship. Needs either a lenient per-element decode or a stated minimum-version gate before the first card is sent.

### D-13 · Exchange cards at the UWB ceremony, before any transaction exists

Nothing requires a request to accompany a card. A card can be sent alone — and it should be, at pairing.

This is the strongest deployment of the design and it does three jobs at once:

1. **It defeats the playbook directly.** The BEC attack is a last-minute change; a baseline established at the first in-person meeting means the very first payment already carries months of age and the attacker's window never opens.
2. **It answers first-card TOFU.** A card exchanged under physical presence has the one provenance remote duress cannot reach. A card that instead arrives remotely with no prior baseline should say so plainly: *"first destination from this contact, never confirmed in person."*
3. **It answers transport suppression.** An attacker who controls the email thread can drop the bundle and send plain instructions instead. If the payer already holds a baseline, a payment with **no card attached is conspicuous** rather than unremarkable.

It also reframes cold start: the install and the card exchange are the same event, not two. The real-estate wedge makes this natural — you meet the title officer at the start of the transaction, which is exactly when the card should be exchanged.

**The ceremony is also where the sensitivity prompt belongs** (Q-01, step 3). A contact created at depth 0 defaults to visible at every duress depth, so the moment a counterparty becomes payment-relevant is the moment to ask whether they should be hidden in restricted view.

### D-14 · Failure paths: does the app vouch for these bytes?

One dividing rule, and it is what makes the copy discipline in [Positioning](#positioning-and-copy-discipline) enforceable in UI rather than aspirational.

**Unverifiable → not a card.** Bad signature, unpinned key, failed or rolled-back certificate, version rollback, forked lineage, unknown rail. The destination **must never render in copyable form**. A warning badge over a copyable account number is how a rushed user copies it anyway.

**Verified but flagged → render, flag prominently.** New destination, recently changed, expired card, currency mismatch. Per SPEC §5 discipline.

### D-15 · Cards are recipient-bound, and signed lazily at send

The card's signing payload carries `LP(recipientKeyFingerprint)`, exactly as D-11's request does.

**Why: it makes depth filtering a hard gate on both artifacts instead of one.** D-11's payer binding already protects requests against manual transport — the binding is inside the signed bytes, so moving the `.occ` file by share sheet or email cannot retarget it, and minting a request for a hidden contact is impossible because the app has no fingerprint to bind. Cards had no equivalent: being unaddressed is what made them reusable, and it meant a coerced card delivered through any channel verified for anyone holding the payee's pinned key.

With binding, a card coerced at a duress depth is usable only against contacts the coercer could select — by construction, the ones classified non-sensitive. **This closes Q-01's outranking residual for every hidden contact.**

**It does not cost what it appears to.** The obvious objection is N signatures per card version, and for a title office with 200 clients that reads as F-02's arithmetic all over again. It dissolves under lazy signing:

- The **content** is authored once and lives in the Vault unsigned, with a version.
- The **signature** is minted at send time, when the recipient is already known and a presence evaluation is already happening for the request.
- Cache `{recipientFingerprint → signature}` beside the content; mint on first send to a given payer, reuse after, invalidate the whole set on a version bump.

N never materializes. A card update costs **zero** signatures — it bumps the version and propagates lazily through D-03, which is already how freshness works. The send-side arithmetic is unchanged, because nothing here requires a proactive broadcast.

**Details that matter:**

- **Version stays global to the content**, not per-recipient. "This is the fifth revision of my card" is meaningful across counterparties and keeps D-04's rollback rules uniform. A counterparty added later receiving v5 as their first card is harmless — they have no baseline, so it reads as first-seen.
- **`cardDigest` now differs per recipient**, since the fingerprint is inside the signed payload. That is correct: a request to Alice binds Alice's card digest.
- **`destinationDigest` is unaffected**, and must stay that way. It covers the rail tuple only (D-02, D-10). Folding the recipient into it would give two payers different digests for the same account and break the tripwire — a trap worth naming, since both digests now live in the same payload.
- **The certificate stays unbound.** It states that a payment key belongs to an identity key; that is harmless to anyone who sees it, and binding it would add signatures for no gain.
- **The request keeps its own payer binding**, now partly redundant — a request referencing a card bound to someone else fails anyway. Kept deliberately, so the request remains independently meaningful rather than deriving its security from another artifact.

**Pre-implementation check:** whether SE signing batches under a single pre-evaluated `LAContext` or costs one prompt per signature. Lazy signing keeps this to two signatures per send in the normal case, so it is no longer load-bearing — but `Master Feature & Expansion Analysis.md` §18 flags it as unestablished, and it decides whether any future bulk re-issue flow is viable at all. Cheap to settle; settle it.

**What is given up:** broadcasting a card to a counterparty without a signing action. D-13 already puts that at a ceremony, so nothing real is lost. `#26` reuse survives intact — the owner never re-enters banking details, which is what that promise was about.

### D-16 · Cards are acknowledged on receipt — version, never timestamp

On verifying and pinning a card, the payer signs a short acknowledgement: `(cardID, version)` bound to the payee's fingerprint, under the payer's payment key.

**Transmitted is not received, and the design currently conflates them.** D-03's send is fire-and-forget over F-02's share sheet, so a payee knows only that they shared something. Closing that gap does two jobs:

- **Transport suppression becomes visible.** An attacker who controls the channel drops the bundle and sends plain instructions instead; today neither party can tell. With acknowledgement, the payee sees nothing come back and the natural response is an out-of-band call. A threat-model residual moves from unclosed to detectable.
- **Version propagation becomes knowable.** Q-01's post-duress requirement — flag which contacts have not received the superseding version — is otherwise guesswork from the sender's local record of what they *sent*. Acknowledgement makes it evidence, in precisely the case Q-01 accepts as unrecallable.

**No fine-grained timestamp, and this is not negotiable.** An acknowledgement carrying *when* is a read receipt — the *"who checked whom, when"* class `Presence Verification/SPEC.md` §7 refuses to persist — and in a coercive household, a controlling family member learning when someone opened the app is a real harm to exactly this feature's audience. The payee needs *"Bob is on v8."* They never need *"Bob opened the app at 14:23."*

The payee retains the highest acknowledged version per contact, so a replayed old acknowledgement degrades to stale information rather than anything exploitable.

**Cost splits by flow:** free at a UWB ceremony, where the channel is already live and which D-13 makes the primary path; a manual send back for remote updates, landing on the payer — often the less engaged party.

### D-17 · The diff challenge is a notification, not an authorization gate

When a received card's destination differs from the pinned baseline, the payer may send the payee a challenge: *"a card bearing your signature, with details that do not match what I hold, is in play."*

**It adds no cryptographic strength, and the name invites the opposite reading.** Challenge and response run between the same two keys — a coercer who can sign the card can sign the response. Nothing about this gates anything.

What it adds is real regardless: today the diff is purely local to the payer, and the payee never learns their card was questioned. For a payee who was coerced and has since regained control, this is the **only live-attack signal anywhere in the design**.

**User-initiated, never automatic.** A device that emits a signal on every diff is a device that phones home. One tap on *"ask them about this"* is the out-of-band confirmation the design already instructs users to perform, made easier rather than automated.

Nothing about a challenge persists on either side.

---

## Lifecycle

The doc above specifies artifacts; this specifies transitions. Kind matters as much as name — **local** touches nothing outside the device, **outbound/inbound** crosses a trust boundary, **derived** is computed from state rather than received.

| Event | Side | Kind | Fires |
|---|---|---|---|
| `cardAuthored` | payee | local | content created or revised; version assigned |
| `cardSigned(recipient)` | payee | local | lazily, at send (D-15) |
| `cardTransmitted(recipient)` | payee | outbound | fire-and-forget; proves nothing |
| `cardAcknowledged(recipient, version)` | payee | inbound | the only proof of arrival (D-16) |
| `certificatePinned(contact)` | payer | inbound | first verification against the UWB-pinned identity (D-09) |
| `cardReceived(contact, cardID, version)` | payer | inbound | sets `firstSeenAt` on a new destination, updates `lastSeenAt`, runs D-04's version rules |
| `cardRejected(reason)` | payer | inbound | D-14's fail-closed set — bad signature, rollback, fork, wrong recipient binding, unknown rail |
| `destinationChanged(from, to)` | payer | **derived** | the tripwire |
| `requestReceived` | payer | inbound | expiry and one-shot checks (D-11) |
| `requestConsumed` | payer | local | `requestID` retained until its own expiry |
| `diffChallengeSent` / `diffChallengeReceived` | both | user-initiated | D-17 |
| `contactKeyChanged` → `cardsInvalidated(contact)` | payer | derived | loudly and at once (Q-07) |
| `depthReturnedToZero` → `reIssuePrompt` | payee | local | Q-01's post-duress flow, driven by acknowledged versions |
| `cardExpired` | both | derived | from `expiresAt` |
| `paymentRecorded` | payer | outbound | **phase 2** (Q-08) |

### Events specify transitions; they are not rows

Persisting this sequence would build a complete payment audit trail — who paid whom, when, how often — on a device whose adjacent feature refuses to write verification history at all (`Presence Verification/SPEC.md` §7), and would undo most of Q-03.

**Only derived state persists**, and it is already settled: `StoredCard`, `DestinationBaseline` (first- and last-seen, the minimum that supports age and diff), consumed `requestID`s until their own expiry, and highest-acknowledged-version per contact (D-16). Everything else in the table above is transient by construction — including every challenge.

Two rows carry more weight than their description suggests. **`cardAcknowledged` is what turns Q-01's post-duress flag from guesswork into evidence.** And **`destinationChanged` is marked derived on purpose**: the tripwire is computed locally from state rather than received from anyone, which is exactly why it survives full key compromise (see below).

---

## Threat model

Written in `Presence Verification/SPEC.md` §6's form.

### Defeated

- **Forged certificate, card or request** — needs SE-held keys. Hardware-excluded.
- **Mix-and-match** (genuine request + attacker's card) — D-02's `cardDigest` binding.
- **Retargeting a coerced artifact by moving the file.** Both card (D-15) and request (D-11) bind their counterparty inside the signed bytes, so share-sheet, email or AirDrop delivery to a different contact fails verification. Recipient selection is a hard gate on artifact creation, not a UI convenience.
- **Backdated card faking age** — D-06 reads locally-observed `firstSeenAt`.
- **Silent duress card.** A coerced card *must* change the destination digest and bump the version, so it always renders as a loud diff, and it cannot forge age. **A duress attacker cannot make a change quiet.** Q-01's exposure narrows to two cases: the first card from a contact (mitigated by D-13), and a payer who sees the diff and proceeds anyway.
- **Rollback to an older signed card** — D-04's `version < stored` refusal, *provided* the payer has seen the newer one.
- **Duress amplification across contacts** — D-11's payer-fingerprint binding.
- **Unknown-rail downgrade** — D-10's fail-closed rendering makes this denial of service, not bypass.
- **Cross-protocol signature reuse** — D-12's category-in-payload separation. Note the third domain string: `destinationDigest` is unsigned but still needs its own prefix, distinct from every signing prefix, so no signing path can emit bytes equal to a destination digest.

### Residual

- **The attacker simply does not use Occulta.** Plain email, "our details changed," no artifacts. This is the actual BEC attack; only the payer's policy touches it. It is the primary residual, not a footnote.
- **Transport suppression.** The attacker owns the channel and drops the bundle. **Detectable** via D-16 — the payee sees no acknowledgement — and mitigated by D-13, but not prevented: detection depends on the payee noticing an absence.
- **Replay against a payer who never saw the newer card.** No diff, and age reads as reassuring. Bounded only by D-11's request expiry.
- **Clipboard / address-substitution malware on the payer's device** — see the surface rule below.
- **Baseline row deletion on an unlocked payer device.** Poisoning is closed by D-04 (a stored row is a signed card and cannot be forged); deletion remains possible and fails safe — the next card reads as first-seen and fires the age signal.
- **Passcode-path signing.** D-09's `.userPresence` means a coercer who knows the passcode can sign. Deliberate trade against `.biometryCurrentSet`'s re-enrolment invalidation.
- **First card from a contact**, where no baseline exists by construction. D-13 is the mitigation.
- **A duress-signed card outranks what a *visible* contact holds, and cannot be recalled.** Q-01 accepts this deliberately — the alternative is a duress-detection oracle. D-15's recipient binding confines it to contacts the coercer could select; `expiresAt` and re-issuance bound it in time. Never eliminated.

### If the identity key itself is recovered

Distinct from a coercer *using* the key on a device: an attacker holding key material signs offline, forever, with no gate and arbitrary `createdAt`.

- **Quantum** breaks the private key from the public key — remotely, for every user at once. `#23` (hybrid SE-ECDSA + ML-DSA) is the answer, at app level; cards inherit it and must not build a variant (see Q-08).
- **SE extraction** requires physical possession and yields one user's keys. **`#23` does not help here**, and its ruling does not say so: the ML-DSA private key is *"wrapped under the hybrid local DB key,"* which is itself SE-derived (`Key+Manager.swift:468`). Hybrid signatures put the second lock's key inside the first lock. Fine against quantum (AES-256 survives Grover); zero added defence against SE compromise.

**What survives total key compromise is only what was locally observed:**

1. **The tripwire, which does not rest on signatures at all.** The diff compares against what *this device* recorded. An attacker with every key still cannot make a changed destination look unchanged without attacking the payer's device separately.
2. **`firstSeenAt`** — signed timestamps are forgeable under compromise; local observation is not.
3. **Physical presence.** UWB at ≤25 cm binds a key to an event no key material can re-stage remotely. This is why the standing no-vouching rule matters more than it looks: key extraction never buys the attacker a *new* relationship.

**Targeted compromise is detectable by corroboration, universal compromise is not.** `#22` (mutual-contact key corroboration) and `#27`'s Second Opinion are the practical layer, and Second Opinion is already unblocked.

`#E`/`#11` co-signature on high-value cards is the only genuinely *preventive* defence against single-key extraction — one SE is not enough — and is named as the escalation path, not designed here.

### Explicit non-claims

- **Occulta never executes, brokers, or observes a payment.** No bank integration, no transaction hook. Display-and-compare only. Every guarantee is conditional on the payer looking.
- **The destination is constrained in what the app will vouch for**, never in where money can go.
- **A physically-met counterparty can be the fraudster.** The design proves *who* and *where*, never *honest*. D-07 covers strangers; this is different.
- **`payeeName` is self-asserted and verifies nothing** (D-10).
- **Nothing confirms the wire that left matched the request that asked** (Q-08).
- **A compromised OS defeats everything**, as with any app.

### The masking surface rule

D-08 originally claimed the design defends clipboard-hijacking malware *"because the recipient's app compares against a signed card rather than trusting a pasted string."* Occulta is not in the paste path. The real control is the payer visually comparing against their **bank's** confirmation screen, which only works if the full destination is on screen at that moment.

If masking applied everywhere, the payer would compare four digits — worthless against a vanity-generated crypto address, and 1-in-10,000 against an attacker who chooses the collision. The same collision also degrades the diff itself, which is part of why D-04 now stores full destinations rather than tails.

**Rule: masking is a display choice, never a storage one.** The full destination is available both in transit (D-03) and at rest (D-04), and the payment screen must show it in full. Masking applies to history and list views only. Backwards, and the only defence against paste-swap is gone.

---

## Forensic cleanliness

`Presence Verification/SPEC.md` §7 refuses persistence deliberately — *"no verification history is written anywhere by default"* — and states that a history feature *"would need Travel Mode integration before it could exist at all."*

D-04's stored cards and baselines **are** a history feature. **Secure Mode integration is therefore a precondition of this design, not a follow-up.** On seizure a row set discloses who this person pays, on which rail, since when, how recently, and — after Q-06's ruling — **the account numbers themselves**, in full, for every counterparty. Org Graph F-07's "affiliation-in-a-file" argument applies unchanged and with more to find.

Requirements, inherited rather than re-derived from `Occulta/Features/SecureMode/forensic-trace-avoidance.md`:

- **A non-nil depth field from creation** on every new model here. S6 (`visibleThroughDepth`) and S9 (`globalTrusteeDepth`) both landed on this rule so that presence-versus-absence of the field is never itself a tell. The shard work reached it by retrofit and records the cost.
- **`PRAGMA secure_delete`** (S2) and **`.completeFileProtection` re-applied on every save** (S3/S4).
- **S8's accepted-gap reasoning for row counts** applies verbatim to card rows.
- **Contact classification inheritance.** `StoredCard` and `DestinationBaseline` are contact-keyed and must filter off `isVisible(atDepth:)`, or hiding a contact leaks them through the card store — their existence *and* their bank details. See Q-01 step 3.
- **Cascade delete on contact removal**, and Secure Mode purge behaviour, specified up front. `Docs/Bugs/v1.10.0/Shard-Custody-Not-Cleaned-Up-On-Contact-Deletion.md` is a long-running instance of exactly this class — contact-keyed SwiftData models with no purge path — and names a second (`Message.Draft`). A surviving baseline row for a deleted contact is a record of a financial relationship the user believes they erased.
- **The consumed-`requestID` store** (D-11) inherits the same treatment. It is less exposed because entries self-expire, which is worth stating rather than assuming.
- **Temp files now carry bank details.** SPEC §7 accepts `.occ` files in `temporaryDirectory`, sized for a challenge nonce. The same path now carries full payment destinations; cleanup timing and the acceptance reasoning both need re-examining against the new content.

**One point in the design's favour:** unlike an org-membership credential, a payment card is mundane. A coerced user handing over a phone showing payment cards looks like someone who uses a finance app. There is no "why are you hiding this" tell in the content itself, which makes this unusually good decoy-depth material rather than a liability.

---

## Scope and limits

### D-07 · What this cannot reach

- **Payments to strangers.** Romance, investment, and fake-invoice scams from vendors never met are permanently outside the closed loop. This is a large share of total fraud loss.
- **Gift cards and cash-app rails**, which route around the card system entirely.
- **A behavioural dependency survives.** "Only pay to an existing card" must be held as a policy. Better than a safe word — it cannot leak and cannot be forgotten — but it is not a cryptographic guarantee and copy must never imply otherwise.
- **"Two independent verifications" is weaker than it sounds.** Under D-09 the same payment key signs both card and request, and the identity key roots it; device compromise yields all three. The split buys clarity and an age signal, not independent security domains.
- **A counterparty you met can still defraud you.** Identity and destination are proven; honesty is not.

### D-08 · Prior art and differentiation

| | Coverage | Gap |
|---|---|---|
| UK Confirmation of Payee | Bank-run, name-to-account | Participating UK banks only; no crypto |
| EU Verification of Payee | Mandated, name/ID-to-IBAN, SCT **and** SCT Inst | Euro-area only until Jul 2027; euro rails only; warning, not a block; mule accounts in a matching name |
| US Fed Payee Name Verification | FI-facing, rail-agnostic, inference over 12 months of transaction history | Optional, not mandated; no consumer-visible guarantee; a risk signal rather than a registry match |
| Title/escrow industry | Verbal codes, callbacks, insurance | Leakable, socially engineerable, post-hoc |
| Crypto wallet address books | Local convenience | Unsigned, trust-on-first-use, no binding to a verified human |

**This is not "serverless Confirmation of Payee."** The original framing claimed it was; CoP's entire mechanism is the payer's bank matching a name against the destination account, and Occulta has no bank connection. The one thing CoP catches — *"this account is not actually the person you named"* — is precisely what this design cannot catch (D-10).

The genuine differentiator, which the table above states correctly: **a payee destination cryptographically bound to a human you physically verified, with tamper-evident change history, serverless, cross-rail.** Different axis from CoP, genuinely valuable, not the same control.

It also raises the bar against address-substitution malware — subject to the masking surface rule in the threat model — which connects to Expansion I's smart-wallet work.

---

## Positioning and copy discipline

Payment cards carry no §2232/§1519 exposure; this is the feature aligned with FBI, FTC and industry guidance. The **inverse** risk is the live one: overstating a fraud-prevention guarantee to the audience this doc calls *"the most mainstream-reaching item on the roadmap"* — home buyers and elderly parents, least equipped to evaluate a cryptographic claim, largest foreseeable loss. Reliance is the exposure, not obstruction.

**Never:** *"funds can only go to…"* · *"prevents wire fraud"* · *"stops BEC"* · *"verified payee"* (implies CoP-style name matching, D-10) · any construction where the app is the subject of a verb about money movement.

**Acceptable:** *"Occulta will never show payment details as verified unless your counterparty signed them"* · *"a last-minute change of account can't reach you unsigned"* · *"you'll see that this account is new."*

**The test: every claim must be about what the app displays, never about where money goes.**

Route positioning material through the same path `Docs/Audit/LanguageRiskReview2026-08-01/` established — with counsel, before publication — for the opposite failure mode to the Secure Mode docs. That review's scope note should record that this second class exists, so the next pass does not look only for obstruction language.

---

## Relationship to `#26`

`#26` already specifies payment details as a signed artifact rendered as *"a pinned, immutable verified card"* with signed-change diffing. This adds:

1. **Pre-authoring** — cards exist before any transaction rather than being sent per-transaction, and are exchanged at the ceremony (D-13).
2. **Reuse** — one card serves many requests; no re-entry of banking details.
3. **Composition with a signed request**, replacing `#26` rule (3)'s pairing with a live `#15` presence check.
4. **Age as an explicit security property** (D-06), implicit in `#26`'s diffing but not first-class.
5. **A defined transport and storage model** (D-03, D-04).
6. **A defined key architecture** (D-09) — `#26` assumed the sender's existing SE key, which D-01's correction shows has no biometric gate.

**Item 3 is the sequencing consequence: `#26` can deliver its core anti-BEC value without `#15`.** `#26` is already Near-term, so marginal lift is small if scoped into the same release.

**Retained from `#26`, not dropped:** the *"wire executed to account ending 1234, $X, [time]"* confirmation receipt reusing the `#24` pattern. Deliberately phase 2 — see Q-08 for why it is worth more than "optional later."

---

## Open questions

### Q-01 · Duress-signed cards — **answered 2026-08-09**

**Ruling: duress-signed cards are permitted by design. The feature behaves identically under coercion.** The answer is not prevention — prevention is unachievable and attempting it is a bug — but four separate properties: *don't detect, don't degrade, hide the targets, bound the damage.*

#### 1. Don't detect

Nothing in this feature may attempt to infer that the operator is under coercion, and nothing may branch on such an inference. `Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md` is the standing precedent for why: a behaviour that differs under duress hands the coercer a detector.

#### 2. Don't degrade

Card authoring, signing, and sending work exactly as they do at depth 0. No refusal, no extra confirmation, no reduced limits, no silent failure.

This is the house position, not a preference. `Contact+Model.swift:105-113` makes the identical argument for `originDepth`, choosing floor semantics over exact-match specifically so a duress-born contact does not *"start rejecting bundles again the moment depth passes N, reproducing the exact duress-detection tell this field exists to remove."* A payment feature that declined to sign under coercion would rebuild that tell, and a coercer who cannot get a card signed learns there is a depth above the one they are standing in.

#### 3. Hide the targets

The protection is the shipped contact-classification mechanism, not a new one. A coercer can obtain a signed card; what they cannot obtain is the list of people worth sending it to, because `isVisible(atDepth:)` filters recipient selection exactly as it filters everything else.

**The gap that makes this fail in practice:** contacts created at depth 0 default to `Int.max` — visible at *every* duress depth (`Contact+Manager.swift:205-207`). Hiding happens only if the user actively classified the contact as sensitive in a separate pass. For payment cards the timing is exactly wrong: D-13 puts card exchange at the UWB ceremony, which is the moment the contact is created wide open, and a newly-paired counterparty is the highest-value target the user has.

**Required: prompt for classification at card exchange.** Not a generic classification nag — a specific prompt at the ceremony, *"you've exchanged payment details with X; hide X in restricted view?"*, tying the decision to the moment the stakes become concrete. Shown only at depth 0, so it is not itself a tell.

**Three things must inherit classification or the hiding leaks:**

- `StoredCard` and `DestinationBaseline` are contact-keyed. Unfiltered, they disclose both a hidden contact's existence and their bank details. The shard work already solved this shape — real shards from safe contacts get correct ceiling-based visibility off the existing classification — so inherit it deliberately rather than assuming it.
- The owner's own card store needs a depth stamp. At a duress depth the coercer otherwise sees the operator's full account list, and the presence of a crypto card is disclosure in itself.
- Row counts, per `forensic-trace-avoidance.md` S8.

#### 4. Bound the damage

Three properties already in the design, none of which the coercer can defeat:

- **A duress card cannot be quiet.** It must change the destination digest and bump the version, so it always renders as a loud diff (threat model).
- **Its age cannot be forged.** D-06 reads locally-observed `firstSeenAt`, not the signed `createdAt`.
- **It expires.** The mandatory `expiresAt` ([Revocation](#revocation)) bounds the window without requiring any channel.

**The residual, narrowed by D-15 and stated plainly.** A duress-signed card still cannot be recalled: coerced into signing version 7, the operator can later author version 8, but only contacts who *receive* it are protected, and D-04's version rule accepts v7 as newer from anyone who never saw v8. Supersede and outlive, never retract — revocation case 4 in a different costume.

**What D-15 removes:** because the card now binds a recipient, a coerced card is only usable against contacts the coercer could *select* — those visible at the coercion depth. Hidden contacts are unreachable by a coerced card, not merely unlikely to be reached. The residual is therefore bounded to the contact set the operator deliberately classified as non-sensitive, which is the trade this whole answer is built on. Manual transport of the `.occ` file does not widen it, because the binding is inside the signed bytes.

**Required: stamp the owner's card store with the depth it was authored at, and on return to depth 0 prompt to re-issue, flagging which contacts have not yet received the new version.** That flag is the only thing standing between a coerced signature and an indefinite window.

### Q-03 · PII at rest — **answered 2026-08-09**

A digest over bank details is brute-forceable: account and routing numbers carry roughly 2⁴⁰–2⁵⁰ real-world entropy, and salting does not help because the salt must be stored alongside.

- **Crypto addresses:** genuinely protective (2¹⁶⁰), and public anyway.
- **Bank details:** treat the digest as PII; it belongs in the encrypted local DB with everything else.

**After Q-06's ruling the entropy argument is moot** — the destination is stored in full, so there is nothing to brute-force. It is retained above because it explains why the digest was never the protection it appeared to be, which is part of why the ruling went the way it did.

**Q-06's ruling enlarges this, deliberately.** D-04 now stores full counterparty destinations, not digests and tails, so the at-rest exposure is real rather than theoretical and the digest's brute-force cost stops being the interesting question. What remains true is that the original reasoning already conceded the point: the real exposure was always a coerced or compromised *unlocked* device, where a digest never helped. Masked display survives as harm reduction in list and history views (surface rule), not as a storage strategy.

**What is stored:** the owner's own cards (full destinations, signed), `StoredCard` for counterparties (same), `DestinationBaseline`, and the consumed-`requestID` store. Encryption at rest, non-nil depth from creation, contact-classification inheritance (Q-01) and cascade delete are settled in [Forensic cleanliness](#forensic-cleanliness) and are not re-argued here. Four decisions remain.

**1 · Cards live in the Vault, under the vault key. No dedicated store, no dedicated sealing key.**

An earlier draft of this answer argued the opposite on two grounds, both wrong. *"A vault unlock per payment"* — the vault session is scoped by a pre-evaluated `LAContext` held in memory (`Vault+Manager.swift:46`), so it is one unlock per session, not per operation. *"`.biometryCurrentSet` locks the operator out"* — the vault key is `[.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode]`, and the passcode branch survives biometric re-enrolment.

The decisive argument runs the other way, and is the same one D-12 used for `SignedAttribute`: **do not build a parallel mechanism that has to re-earn Secure Mode's guarantees by hand.** Vault residence inherits rotation-on-activation (S1's cryptographic erasure), backup participation, and the re-encryption path. A dedicated store re-implements all three, with three chances to get them wrong.

**And it fixes a default.** `VaultEntry.visibleThroughDepth` is **exact-match, not a ceiling** (`Vault+Model.swift:188`) — *"visible only at exactly depth N."* A card authored at depth 0 is therefore invisible at every duress depth by construction, with no classification step. Contacts default to `Int.max` (visible everywhere), which is the gap Q-01 has to cover with a prompt; vault entries default the right way round.

**No dedicated sealing key.** The one argument for separation was backup scope — keeping payment destinations out of exported vault backups. It does not survive: vault backups are encrypted and user-initiated, and cards *should* be restored, because a lost baseline is a lost tripwire history, which after Q-06 is the last line of defence. Compartmentalization buys nothing else, since both keys are SE-derived and fall to the same coerced unlock.

**Unchanged:** D-09's *signing* key stays separate. That key exists because the identity key has no gate and cannot acquire one; nothing here touches that reasoning.

**Noted, not fixed:** `Key+Manager.swift:783-799` mints the shard custody key lazily on `errSecItemNotFound`, so that key's existence discloses that shard custody has been used — in tension with `forensic-trace-avoidance.md` B5 (*"SE key created at first launch, not at activation"*, rated High). Pre-existing and out of scope here; recorded so it is not copied.

**3 · Deniability: integrate with Secure Mode. `#6` is a later strengthening, not the requirement.** The earlier text recommended `#6` (Plausibly Deniable Vault Partitions), which is Phase 2 and unbuilt. The shipped depth machinery is what this feature must integrate with, and it is already a precondition. `#6` would add hidden-volume indistinguishability on top; nothing here is blocked on it.

**4 · Superseded `DestinationBaseline` rows need a retention policy.** Kept indefinitely they accumulate a complete record of every account every counterparty has ever used — a financial history that outlives every transaction and that nothing in the design prunes. Discarding them loses the *"you have paid this account before"* signal when a counterparty switches back, which is genuinely useful.

Keep them, and treat them as the most seizure-exposed rows in the feature: depth-scoped, cascade-deleted, plus a user-facing **"forget payment history for this contact."** That last item matters because these are the only rows a user would ever think to clear, and nothing currently lets them.

**The floor, as a non-claim:** a coerced unlock at depth 0 with real contacts visible exposes all of it. No key separation or storage shape raises that floor — it is the same floor every feature in this app has, and this question should stop implying a storage decision could change it.

Consistent with `Organizational Identity Graph/FINDINGS.md` F-07's conclusion for org credentials, on a larger payload.

### Q-04 · Competitive timing on bank rails — **answered 2026-08-09**

The question assumed a future event. It already happened, and it lands elsewhere than expected.

**EU — live since 9 October 2025.** Verification of Payee is mandatory for euro-area PSPs under Regulation (EU) 2024/886 (Instant Payments Regulation), covering **both** standard SEPA Credit Transfers and SCT Inst, not instant alone. It matches the IBAN against the payee name or company identifier at initiation. Non-euro-area EU PSPs have until 9 July 2027.

**It does not reach this feature's loss pool.** The IC3 figures driving the priority ruling are US; VoP is euro-denominated SEPA. The strongest wedge — US title and escrow — is entirely outside its scope, as is every crypto rail.

**US — moved, but far less.** The Fed added **Payee Name Verification** to FedDetect Notification Services in late 2025. It is optional rather than mandated, reaches institutions on FedLine Direct/Command rather than consumers, and works by *"initially leveraging 12 months of historical transaction data"* — an inference-based risk signal, not an authoritative registry match. FedNow is exploring real-time enablement.

**Net effect on positioning: it sharpens the story rather than narrowing it.** VoP *is* name-to-account matching, which D-08 establishes Occulta cannot do. The two are complementary and fail differently — VoP is defeated by a mule account opened in a matching name; this design is defeated by a coerced signature. A regulated incumbent occupying the name-matching axis removes the temptation to claim it.

**It also validates D-05's corrected framing.** Even the mandated, bank-integrated control ends at a warning the payer may click through. The behavioural residual is where the state of the art stops, not a weakness peculiar to a serverless design — and positioning may say so.

**Where the slice genuinely narrows:** euro-area bank-to-bank transfers, against a naive attacker supplying their own name and IBAN. Everything else — US rails, crypto, non-euro EU until July 2027, mule accounts in a matching name — is untouched.

Sources: [Crédit Agricole CIB](https://www.ca-cib.com/en/news/securing-sepa-payments-verification-payee-service-becomes-mandatory-october-2025), [PwC Legal](https://legal.pwc.de/en/news/articles/verification-of-payee-requirements-vop-under-the-eus-instant-payments-regulation-ipr), [ECB](https://www.ecb.europa.eu/paym/retail/instant_payments/html/instant_payments_regulation.en.html), [Federal Reserve Financial Services](https://www.frbservices.org/financial-services/multiservice-solutions/payee-name-verification). Retrieved 2026-08-09.

### Q-05 · `CRYPTO_REVIEW_CHECKLIST` — **closed 2026-08-09**

`#26`'s ruling requires `CRYPTO_REVIEW_CHECKLIST §4`, and the canonical document did not exist — while being cited by `README.md:144` as an instruction to **external contributors**, by four master-doc rulings, and by `Multi-Device Contacts/ROADMAP.md` as the R0 gate, where `FINDINGS.md:319` states *"nothing in this plan ships before it's created and run."*

Written: [`Docs/Audit/CRYPTO_REVIEW_CHECKLIST.md`](../../Audit/CRYPTO_REVIEW_CHECKLIST.md), extracted from the two live in-code exemplars (`ShamirSecretSharing.swift:9-48`, `Key+Manager.swift:615-644`) and preserving their five-section template and the §4 sub-numbering the code already cites.

**Sections this feature must answer specifically:** §4.3 for the new categories and payload layouts (D-02, D-10, D-12), §4.5 for D-09's `.userPresence` key and the binding certificate, §1 for justifying a second signing key at all, and §4.7 for the non-claims already listed in the threat model.

### Q-06 · Storage minimization versus forgery detection — **ruled 2026-08-09: the tripwire wins**

The original D-04 justified minimal storage on PII grounds. Against that: the full destination must be displayed at payment time anyway; the baseline is the only surviving defence under key compromise, precisely because it is not cryptographic; and not storing the card leaves the payer dependent on a transport the attacker may control.

Storing less is better against seizure; storing more is better against forgery. **Ruled in favour of forgery detection.** Seizure exposure is already mitigated by Secure Mode's depth machinery, which is a precondition of this feature regardless; nothing else mitigates forgery.

Two consequences beyond the storage shape, both recorded in D-04: storing the *signed* card rather than extracted fields closes baseline poisoning, and full destinations make the diff legible against a chosen masked-tail collision. The ruling made the design smaller — two tables instead of three — which is a reasonable signal it was the right way round.

### Q-07 · Key-change handling — card-local, **not** a Multi-Device dependency

**Corrected 2026-08-09.** An earlier draft of this question claimed Multi-Device R1 (the `deviceID` concurrent-key model) was a prerequisite. It is not. D-09's certificate carries its own `deviceID` in the signed payload, so this feature keys `highestCertVersionSeen` on `(contactID, certDeviceID)` in **its own** table. The only thing card verification needs from `Contact.Profile` is the pinned identity public key, which today's single-slot model supplies. Cards work correctly in every scenario the app currently supports.

What is real:

- **The silent-overwrite defect is inherited, not created.** `Multi-Device Contacts/FINDINGS.md:176` documents that pairing a second device with an existing contact overwrites the first device's key. That scenario is already broken — the payee's first device also stops receiving messages. Cards make the *consequence* worse, not the defect more likely.
- **The payee-replaces-phone case is unaddressed, and R1 does not fix it.** That is key *rotation*, not concurrent keys (D-03's asymmetry). Re-pairing mints a fresh key and every card that payee signed stops verifying. The fix is signed key rotation — the projected "Contact Migration Protocol" — not the `deviceID` column.
- **Forward coupling, not a gate.** When multi-device does ship, D-09's per-device certificates need several identity keys simultaneously verifiable. That is a note for whoever builds R1; it does not block this feature.

**What this feature must build, and can build alone:** when a contact's pinned identity key changes, invalidate every stored card for that contact **loudly and at once**, rather than letting them fail one at a time as unverifiable artifacts. D-14's fail-closed rule applied to a key change. Entirely card-local.

**Unrelated hazard worth carrying:** Multi-Device's own Q-07 found that `processExpectedShards` treats a sender-key fingerprint mismatch as key rotation and hands shards back — a heuristic that cannot distinguish "rotated" from "second device." Card verification must never reuse that pattern. A card that fails to verify is unverifiable, full stop; never resolved by inferring rotation.

### Q-08 · Receipts — **answered 2026-08-09, and the question was two questions**

`#26` records one receipt, after payment. There are two distinct artifacts here and they were being conflated.

**Card-delivery acknowledgement → first release (D-16).** *"I hold your card, version 8."* Free in the ceremony flow, closes transport suppression, and supplies the evidence Q-01's post-duress re-issue flag needs. It carries no timestamp, so it retains nothing and does not pull `#23` into scope.

**Payment receipt → phase 2**, as `#26` had it, for the reasons below. Two categories rather than one artifact with a mode: different trigger, different content, and the `SignedAttribute` family already discriminates by category.

The distinction that decides the split: a version acknowledgement is *state*, superseded by the next one. A payment record is *history*, valuable precisely because it is retained — which is what makes it verified long after authoring, and therefore the trigger for Q-09.

#### The payment receipt, for whenever phase 2 arrives

`#26` records it as optional. It creates a **detection window inside the recall window**: the payer signs what they actually did — self-reported, so a deceived payer faithfully reports the attacker's account — and the payee knows instantly that `···8823` is not theirs. Misdirection that would otherwise surface days later surfaces in minutes, and wire recall plus the IC3 kill-chain both work best inside 24–72 hours against a loss category that is 86% unrecoverable.

Self-reporting suffices because the artifact is authored by the party who may be deceived and checked by the party who knows the truth.

Shape: a `.paymentReceipt` category binding `requestID` and `cardDigest`, signed by the payer's payment key. Two consequences: a receipt store is a record of payments made and inherits the forensic requirements; and **retained receipts are the trigger that pulls `#23` into scope**, since they are verified long after authoring (see below).

Recommendation stands: keep it out of the first release, but the rationale above is why it is worth more than "optional later" when it comes.

### Q-09 · `#23` (hybrid PQ) is excluded — recorded so the exclusion is visible

`#23` is scoped by **verification** longevity — *"must remain unforgeable for decades"* — while D-01's "long-lived" is **authoring** longevity. Cards are verified contemporaneously; nobody validates a card in 2040. If P-256 falls, the exposure is the pinned identity key, which is an app-level decision cards inherit.

Affirmative arguments for exclusion: `#23` itself flags ML-DSA-87's ~4.6 KB *"if ever used on the wire"* against `#21`'s padding buckets, and cards are the worst case — three signed artifacts on every request. `#23` is Mid-term and SDK-gated; cards are Near-term.

**Do not build a forward-compatibility slot.** The versioned domain prefix is already the house's wire-evolution mechanism. Record instead that a future v3 is a real migration *because cards will have shipped* — `SignedAttribute.swift:27-30` got away with v1→v2 only because SSS had not.

---

## Revocation

Previously recorded as "closed." It is four cases.

**1. Benign — the owner closes an account. Closed by D-03.** Sign a new version, the next request carries it, the payer sees a diff. No transport needed, nothing to broadcast.

**2. Payment key compromised. Closed by D-09.** The identity key signs a superseding certificate at a higher version; anything lower is rejected. Retires a compromised payment key without touching the identity key and without re-pairing. This case had no answer before D-09.

**3. Identity key compromised. Cannot be closed — and revocation is the wrong frame.** Every mechanism is authorised by the key the attacker holds. The compensating control is the tripwire: the attacker can act, but not silently (threat model).

**4. Proactive retraction — genuinely open.** *"Stop paying me, something is wrong,"* with no request to piggyback on. There is no channel: F-02's share sheet is the only transport, `#19`'s guardian revocation certificates inherit the same wall, and `#18`'s per-device revocation broadcast is designed but not built. The honest answer is out-of-band — phone the counterparty — consistent with the policy layer the design already depends on.

**Why case 4 is survivable: the design is pull-shaped.** Nothing is paid unless a request arrives, so an undelivered revocation fails safe. That is the inverse of the standing-credential model Org Graph D-09 had to abandon, where absence of a refresh meant a credential kept working. Cards get revocation-by-absence for free.

**Cards carry a mandatory `expiresAt`.** The field already exists inside the signing payload and is already tamper-proof (`SignedAttribute.swift:22-25`), so this is not new machinery. It bounds replay of stale card+request pairs independently of D-11's request expiry, keeps the age signal honest by forcing periodic re-authoring, and fails closed when a payee abandons the app. Long timescale — 12 months is the right order; the *request* carries the short window. It bounds staleness, never compromise: an attacker holding the key signs fresh expiries.

---

## Adoption and viability

**Technical viability: high.** Zero new cryptography — domain-separated signing under an existing family (D-12), structured payloads, existing bundle transport, and the card UI concept already present in `#26` rule (1). D-09 adds one SE key and a certificate, which is house-pattern work.

**Gating is internal, and shallower than one draft of this doc claimed.** Q-05 (the review checklist) is the one real gate. Q-07 turned out not to be a Multi-Device dependency at all — cards work on today's contact-key model, and the key-change handling they need is card-local. No other vendor's roadmap is involved, and no other feature blocks this one.

**Transport friction is worst where the doc is most optimistic.** For real estate, one share-sheet action against a $300K wire is irrelevant. For the family case it is an elderly parent receiving a file attachment and knowing to open it in Occulta — the demographic `#27` describes as never navigating challenge/attestation vocabulary. The Share Extension plan (`Occulta/Features/ShareExtension/`) is the realistic mitigation and should be treated as a dependency for that audience.

**Audience: the most mainstream-reaching item on the roadmap.** This is the feature that reaches people who would never install a privacy app — a home buyer installing because their title company asked, an adult child installing to protect a parent. `#27`'s install loop is physically verified by construction, since every install requires a UWB ceremony with someone already in the network.

**The risk is concentrated in one place: two-sided cold start.** Nothing about the design is uncertain; whether a title office can get clients to install an app mid-transaction is. `#26`'s ruling notes that *"one cautious title office can adopt unilaterally for its clients"* — that unilateral adoption is the thing to test before scaling investment. D-13 narrows it usefully: the install and the card exchange are one event.

**Strongest wedge: real-estate/title.** Transaction value ($300K+) justifies friction, the parties already meet in person, and the loss is catastrophic and uninsured. Family case second, carrying `#27`'s viral loop — while noting it is the case the manual transport serves worst.

---

## Action items

**Before any implementation:**

- Write `Docs/Audit/CRYPTO_REVIEW_CHECKLIST.md` (Q-05). Blocks this and Multi-Device R0. Extract from the in-code blocks.
- Specify the two digests, per-rail normalization table, and length-prefixed layouts (D-02, D-10).
- ~~Rule on Q-06~~ — ruled 2026-08-09 in favour of the tripwire; D-04 rewritten. Carry the consequence into the deniability work (Q-03): the at-rest payload is now full destinations.
- Confirm D-09's key architecture against `CRYPTO_REVIEW_CHECKLIST §4` once it exists, including the third domain string for `destinationDigest`.
- Resolve D-12's wire-compat item: lenient per-element decode or a minimum-version gate, before the first card is sent.
- Settle whether SE signing batches under one pre-evaluated `LAContext` (D-15) — not load-bearing under lazy signing, but it decides whether any bulk re-issue flow is possible. `Master Feature & Expansion Analysis.md` §18 flags it as unestablished.
- Build the loud key-change invalidation (Q-07) inside this feature. No Multi-Device dependency; R1's priority stands as set.

**Design:**

- Age, diff, and failure-path surfaces (D-06, D-14) as security-critical screens per `Presence Verification/SPEC.md` §5 discipline.
- Secure Mode integration for all new models (Forensic cleanliness) — non-nil depth from creation, cascade delete, purge behaviour. Precondition, not follow-up.
- The owner-side card store (D-12) — Vault entries under the vault key (Q-03), inheriting exact-match depth, rotation-on-activation, backup, and re-encryption.
- Retention policy and a user-facing "forget payment history for this contact" for superseded `DestinationBaseline` rows (Q-03).
- `StoredCard` and `DestinationBaseline` must inherit contact classification off `isVisible(atDepth:)` (Q-01) — otherwise hiding a contact leaks them through the card store.
- Sensitivity prompt at card exchange (Q-01, D-13) — contacts default to `Int.max`, so the ceremony is the only reliable moment to ask.
- Post-duress re-issue prompt, flagging contacts who have not received the superseding card version — driven by D-16's acknowledged versions, not by a local record of what was sent (Q-01).
- Delivery acknowledgement (D-16) and the user-initiated diff challenge (D-17), neither of which persists anything beyond highest-acknowledged-version per contact.

**Positioning:**

- Cite the loss figures with edition and retrieval date.
- Verify Q-04 (bank verification-of-payee timing) before positioning work.
- Carry D-07's scoping limit and the copy rules into any positioning material; route through the language-review path.

**Elsewhere in the repo:**

- Record `#23`'s SE-extraction limitation in its own ruling (threat model), where someone scoping `#23` will see it.
- Cross-reference this doc from `Presence Verification/FINDINGS.md` Q-02 and Q-03, which D-11 answers.
- Scope into `#26` rather than as a separate feature.

---

## Provenance

Consolidated 2026-08-09 from `Presence Verification/FINDINGS.md` Design Sessions 2 and 3; items renumbered for readability. Extended the same day by a gap review (this doc's D-09–D-14, the threat model, forensic cleanliness, positioning, and Q-06–Q-09).

| This doc | Original |
|---|---|
| D-01 | Session 2 D-06 (as amended by Session 3 D-13); **biometric claim corrected, gap review** |
| D-02 | Session 2 D-06 (digest binding); **split into two digests, gap review** |
| D-03 | Session 3 D-11; **rotation asymmetry and transport reality added** |
| D-04 | Session 3 D-12, D-13; **reversed by Q-06 ruling — stores the signed card in full plus a locally-observed index** |
| D-05 | Session 2 D-07; **overclaim corrected against `#26`'s own wording** |
| D-06 | Session 2 D-08; **age source corrected to local observation** |
| D-07 | Session 2 D-10 (scoping half) |
| D-08 | Session 2 D-10 (prior art half); **CoP framing withdrawn** |
| D-09 – D-14 | Gap review, 2026-08-09 |
| D-15 | Gap review, 2026-08-09 — recipient-bound cards, lazily signed; closes Q-01's residual for hidden contacts |
| D-16, D-17 | Gap review, 2026-08-09 — delivery acknowledgement and diff challenge |
| Lifecycle | Gap review, 2026-08-09 — event model as specification, explicitly not as storage |
| Threat model, Forensic cleanliness, Positioning | Gap review, 2026-08-09 |
| Q-01 | Session 2 Q-05; **answered 2026-08-09** — duress cards permitted by design; don't detect, don't degrade, hide the targets, bound the damage |
| Q-02 (multiple cards) | Session 2 Q-06 — **closed** by D-04's `cardID` keying and destination-scoped age |
| Q-03 | Session 2 Q-07, rewritten by Session 3 D-14; **answered 2026-08-09** — Vault residence under the vault key, no dedicated store or sealing key, Secure Mode not `#6`, baseline retention |
| Q-04, Q-05 | Unchanged / sharpened |
| Q-06 – Q-09 | Gap review, 2026-08-09 |
| Revocation | Session 2 Q-04, closed by Session 3 D-11; **re-scoped to four cases** |

Retained in `Presence Verification/FINDINGS.md` because they concern `#15`/`#27` rather than payments: Session 1 D-01–D-05 (the intent-vs-circumstance construction), D-04 (the `#27` dependency correction), and Q-01 (the behavioural residual). **Q-02 and Q-03 of that doc are answered here by D-11** and should be cross-referenced from it.

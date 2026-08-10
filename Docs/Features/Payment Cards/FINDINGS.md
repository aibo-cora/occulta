# Verified Payment Cards — Design Findings

**Status:** Exploratory — no SPEC.md yet. Scoped as an extension of Consumer Feature `#26` (Verified Payment Instructions, `Master Feature & Expansion Analysis.md` §26), which is **Near-term** priority.
**Origin:** Consolidated 2026-08-09 from `Presence Verification/FINDINGS.md` Design Sessions 2–3, which reached this design while looking for a construction of `#15` that the relay attack does not reach. Extended 2026-08-10 by a gap review that settled the key architecture, the payload layouts, the storage model, and the threat model; see [Provenance](#provenance).

---

## Problem

Business Email Compromise and payment-redirection fraud are the largest documented loss pool adjacent to this app. From the **FBI IC3 2025 Internet Crime Report** (published 2026; 1,008,597 complaints, $20.877B total losses):

- **BEC: $3,046,598,558 across 24,768 complaints** — the **#2 crime type by losses**, up from $2.77B the prior year, averaging ~$123K per complaint.
- **Real-estate fraud: $275.1M across 12,368 complaints.**
- **86% of BEC losses moved by wire transfer or ACH**, and are effectively unrecoverable.

The family-facing side is a separate dataset and must not be conflated with the above. The **FTC's December 2025 report to Congress** records **$2.4B in total fraud losses reported by adults 60+ for 2024**, up roughly fourfold from ~$600M in 2020 — driven principally by investment, romance and impersonation scams. **Voice-clone "grandparent" scams are one impersonation subtype and are not separately quantified in that figure.** The FTC further estimates the true annual cost at **$10.1B–$81.5B** once underreporting is accounted for, so the reported number is a floor.

Sources: [IC3 2025 Annual Report](https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf), [NAR on IC3 real-estate figures](https://www.nar.realtor/magazine/real-estate-news/online-real-estate-fraud-climbed-to-275m-in-2025-fbi-says), [FTC press release, Aug 2025](https://www.ftc.gov/news-events/news/press-releases/2025/08/ftc-data-show-more-four-fold-increase-reports-impersonation-scammers-stealing-tens-even-hundreds), [FTC report to Congress, Dec 2025](https://www.ftc.gov/news-events/news/press-releases/2025/12/ftc-issues-annual-report-congress-agencys-actions-protect-older-adults). Verified 2026-08-10.

> **Corrected 2026-08-10.** The inherited text attributed the whole $2.4B to voice-clone grandparent scams and presented it alongside 2025 IC3 data. It is total 60+ fraud losses across all categories, for 2024. An *"up from ~$173M"* real-estate comparison was also carried from `#26`; it could not be sourced and has been dropped here and at both upstream sites.

The attack is always the same shape: **redirect funds to an account the attacker controls**, usually via a last-minute "our bank details have changed."

**These figures are the documented pool, not the addressable one.** D-07 puts payments to strangers permanently outside the closed loop, and much of BEC is vendor-impersonation between parties who have never physically met. See [Adoption](#adoption-and-viability) for the reconciliation, and the copy rule that follows from it.

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

**Correction (2026-08-10).** The original D-01 asserted both artifacts were *"biometric-gated by construction (SE key use already requires a biometric gate — not a new property to build)."* **This was false.** The identity key is created with `[.privateKeyUsage]` only (`Key+Manager.swift:94-97`) and `signData` calls `SecKeyCreateSignature` with no `LAContext` and no prompt (`Key+Manager.swift:315-322`). Identity-key signing is **silent on an unlocked device**. Only the vault key carries `.biometryCurrentSet + .devicePasscode` (`Key+Manager.swift:655`); `shardCustody` is explicitly *"no biometric flag"* (`Key+Manager.swift:749`).

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

Transmitted each time, alongside the certificate — never referenced by digest alone. The payer also retains the last one received (D-04), but that is a fallback: freshness is a property of transmission, not of storage.

**Three delivery contexts, all permitted:**

1. **At the UWB ceremony, card alone.** D-13's recommendation — a recommendation about *when*, not a restriction on *how*.
2. **In a regular bundle alongside a request.** The main path, and what makes freshness automatic.
3. **In a regular bundle, standalone, remotely.** A card update carrying no ask.

Context 3 is not optional: **Q-01's post-duress re-issue depends on it.** Reaching only the contacts who happen to be transacting would leave everyone else holding the coerced version — precisely the people the re-issue exists for. Traffic shape is already covered, because a card field in `RecipientPayload` must be always-present and tier-padded (D-15), so a card-only bundle is indistinguishable from any other.

Three consequences:

- **Freshness is automatic.** "I closed that account" propagates with the next payment. No revocation broadcast, no delivery guarantee needed for the benign case (see [Revocation](#revocation)).
- **Each artifact is self-contained.** The recipient verifies the certificate against the identity key pinned at the UWB exchange, then the card against the payment key the certificate carries. No dependency on local state. Same property that made the org graph's artifacts independently verifiable (`Organizational Identity Graph/FINDINGS.md` D-10).
- **Survives payer device loss or reinstall.** A payer who re-pairs is immediately functional.

**The resilience is one-sided.** The reverse is not true: when the *payee* wipes or replaces their phone, their SE identity key regenerates, re-pairing mints a fresh key (`Multi-Device Contacts/FINDINGS.md:37`), and signed key rotation does not exist — it is parked as the projected "Contact Migration Protocol." Every card that payee ever signed stops verifying, and from the payer's side **a legitimate phone upgrade and an impersonation attempt are the same event**. Failing closed is correct; the cost is real and belongs recorded. For the real-estate wedge it means a title officer replacing their phone invalidates every client's card and each client must return in person.

**Transport is manual.** F-02 (`Organizational Identity Graph/FINDINGS.md`) stands here: there is no automatic delivery channel post-pairing, and every peer-to-peer bundle goes through `ActivityView.swift`'s share sheet. Org Graph D-14 exempted *relying-party-directed* artifacts; cards are peer-to-peer and are the case D-14 left in scope. See [Adoption](#adoption-and-viability) for what that costs and where.

### D-04 · The recipient stores the signed card in full, plus one locally-observed index

**Ruled 2026-08-10 (Q-06): the tripwire wins over storage minimization.** The original design stored `{digest, first-seen, last-seen, masked tail}` and explicitly *not* the card, on PII grounds. That is reversed. Two tables:

```
Contact.Profile.signedAttributes   filtered to .paymentCard  → the latest card per cardID
DestinationBaseline  (contactID, destinationDigest)          → firstSeenAt, lastSeenAt
PinnedCertificate    (contactID, version)                    → the signed certificate
consumed requestIDs  → until each entry's own expiresAt
acknowledgedVersion  (contactID)                             → highest acknowledged (D-16)
```

**There is no `StoredCard` model.** *(Corrected 2026-08-10 when the sealing key was decided.)* D-12 said *"the baselines are their own models — the payer verifies the card and discards it,"* which Q-06 reversed without anyone updating it. Since the payer now retains the signed card, and `Contact.Profile.signedAttributes` is precisely a per-contact store of `SignedAttribute`s, a received card belongs there under category `.paymentCard`. That inherits classification, re-encryption, the layer store and cascade-on-contact-delete rather than re-earning them.

`highestVersionSeen` needs no field either — the retained card *is* the highest version seen.

**Certificates are retained, not per-card key copies.** *(Replaces the security review's "store the payment public key with the card.")* Re-verifying a stored card needs the key from the certificate current when it arrived, so keeping only the latest certificate strands every earlier card on a legitimate rotation. Retaining the certificates themselves is better than copying a public key onto every card — one payment key signs many cards — and the same history serves D-09's requirement to surface a previously unseen `deviceID`.

**Sealing key: the local DB canonical key — the same key as the rest of the contact record.** See Q-03.

`DestinationBaseline` holds the only thing not derivable from a card: **local observation.** Version, destination, masked tail and the card's own `createdAt` all come from the stored blob, so no third table is needed — this is simpler than the minimal design it replaces, not more complex.

Storing the signed artifact rather than extracted fields buys three things, and the first is a security property:

- **It closes baseline poisoning.** A stored plain destination can be edited by an attacker with an unlocked payer device, pre-seeding a row so a later attacker card shows no change. A stored *signed card* cannot be forged — the attacker would need the payee's payment key. The residual reduces to row *deletion*, which fails safe: the next card reads as first-seen and fires the age signal (D-06).
- **It fixes the diff.** With only a masked tail stored, an attacker can pick a destination whose last four digits match — trivial for a vanity-generated crypto address. The digest comparison still fires, but the user reads *"···4471 → ···4471, changed today"* and concludes it is a glitch. The tripwire technically works while being defeated in practice. Full destinations make the diff show what actually changed.
- **It survives transport suppression.** An attacker who owns the channel can drop the bundle and send plain instructions instead. A payer holding the last good signed card can still pay the known destination without the attacker-controlled channel supplying anything.

**D-03 is unchanged: the card still travels with every request.** Storage is a fallback and a memory, not a replacement — freshness depends on transmission. What storage removes is the payer's *dependency* on that transmission.

- **First-seen belongs to the destination, not the card.** *"Have I paid this account before, and since when"* is the question D-06 actually asks. A new card lineage aimed at a known destination inherits its age — which is what makes the age signal immune to card churn and to the per-device lineages D-09 introduces.
- **Version and rollback are checked against the retained card**, scoped per device.

**Cost, accepted deliberately:** full counterparty destinations at rest (Q-03). Mitigated by machinery the [Forensic cleanliness](#forensic-cleanliness) section already requires — encrypted DB, non-nil depth from creation, cascade delete — and by the fact that the app already holds full destinations for the owner's own cards (D-12). The exposure grows; the class does not.

**Cross-contact destination reuse is detectable and currently unused.** *(Added by security review, 2026-08-10.)* The baseline is keyed `(contactID, destinationDigest)`, so if two contacts present the **same** destination nothing notices — yet one drop account serving multiple victims is a standard BEC pattern, and the digests are already sitting there to compare. Legitimate collisions exist (two people at one firm, one escrow account), so it is a flag rather than a rejection, and all the data is local so it creates no new exposure. An available detection the design is not taking.

**Version is a hard check, not a display field.** Four rules:

| Observed | Action |
|---|---|
| `version > stored` | Accept; diff the destination if it changed |
| `version == stored`, same destination | Idempotent re-receipt; silent |
| `version == stored`, different destination | **Forked card — hard reject.** No benign path produces this |
| `version < stored` | **Refuse the artifact.** Not a diff, not a warning |

The last rule is the point. Without it a replayed older-but-validly-signed card renders as an ambiguous *"···4471 → ···8823, changed today"* that the user resolves by guessing direction. With it, rollback is a rejection rather than a judgement call.

**A fifth rule, from D-14:** a version jumping implausibly far above `stored` is **rejected**, not accepted. `version` is signer-chosen, so a coerced `UInt32.max` would otherwise make the fourth rule permanently refuse every legitimate successor for that lineage.

**Version does not close replay on its own.** A payer who never saw the newer card matches the replayed old one exactly, sees no diff, and reads its age as *old and stable* — the reassuring case. Only the request's expiry (D-11) bounds that.

**Storage cannot be dropped entirely.** `#26` rule (2) — *"changes must be signed by the same key, and the UI diffs loudly"* — requires remembering a previous value. With nothing stored, a last-minute account switch is indistinguishable from normal operation, which is precisely the attack. See Q-03 and Q-06: the case for storing *more* than this has since strengthened three separate ways.

**Masking is a surface rule, not a storage rule.** See [Threat model](#threat-model) — getting it backwards removes the only defence against paste-swap malware.

### D-05 · The destination constraint survives a fully deceived victim

This is the standout property, and it is rare. Almost every anti-fraud control fails once the victim believes the story.

Consider the grandparent scam with cards deployed. The payer's app holds a destination baseline for their child, unchanged for eight months. The request must reference a card the child signed, and the attacker cannot produce one.

**Corrected framing (2026-08-10).** The original text read *"funds can only travel to the child's actual bank account."* That is the copy D-07 prohibits: Occulta never moves money, and the payer types the destination into their own bank. `#26`'s own wording is the correct one — the attacker's destination *"cannot even be **represented** as verified."*

> So even against a victim who believes every word of the pretext, the attacker's destination cannot be represented as verified: the app shows an unsigned instruction to an account it has never seen, beside a card unchanged for eight months. What the victim does next is still theirs — but the decision has become **"ignore a plain warning," not "detect a lie."**

**When the policy holds, the scam's economics collapse:** total loss becomes "the money is sitting in your kid's account." That is the outcome conditional on the policy, not the default outcome.

The policy is also easier to hold than "refuse unsigned requests," because it constrains a *destination* already fixed rather than requiring judgement under pressure: **"money only ever goes to a card you already have."**

### D-06 · Card age is a first-class security signal — read from local observation only

The BEC playbook is definitionally a last-minute change. Pre-authoring turns that into a visible signal:

- *"This destination has been unchanged since March"* — strong.
- *"This destination was first seen four minutes ago"* — should stop a transaction cold.

**Age is framed relative to the relationship, never absolutely.** Absolute age can simply be waited out: a card delivered standalone (D-03, context 3) ages quietly in a context with no payment pressure, so by the time a request arrives *"first seen today"* has become *"first seen last week"* and reads as ordinary. The comparison that matters is against how long the counterparty has been known:

> You have known this contact since March. You have only paid this account since last week.

A destination younger than the relationship stays visibly young for as long as that remains true, which is what removes the attacker's option to wait.

**Age must be driven by `firstSeenAt`, never by the card's signed `createdAt`.** The signed timestamp is whatever the signing device claimed. A coercer with the owner's unlocked phone — Q-01's exact scenario — produces a freshly-signed card bearing a `createdAt` of eight months ago, and every signature verifies. `firstSeenAt` is written by the payer's own device on receipt and cannot be influenced remotely at all.

The honest formulation: **age means "how long *I* have known this destination," never "how old the sender says it is."** The card's own `createdAt` may be displayed, but never as a security signal and never outranking first-seen on the screen.

Surface age and change history at the moment of payment, with the discipline `Presence Verification/SPEC.md` §5 applies to its approval screen. A new or recently-changed destination is not invalid — people do change banks — but it must be visually distinct, and the burden of out-of-band confirmation belongs at that moment.

### D-09 · Key architecture: a dedicated payment key, rooted by certificate

**Decision: a dedicated SE payment signing key per device, protected by `.userPresence`, bound to the identity key by a signed certificate.** Cards and requests are both signed by it.

`#I`'s dedicated-key mandate does *not* apply here — it is scoped to *"signing attacker-supplied digests with the identity key,"* and card payloads are owner-authored, fixed-layout and category-bound. The house pattern agrees: `prepareShards` signs raw key material with the identity key (`Vault+Manager+Shards.swift:87-94`), and every purpose-scoped tag in `Tags` is an encryption/derivation key. There is one signing key in the app today.

The reason for a second one is D-01's correction: the identity key has no biometric gate and cannot acquire one (access control is fixed at creation; changing it means regenerating the identity key and re-pairing every contact). A dedicated key is the only option that makes *"an attacker holding your unlocked phone cannot silently repoint your money"* a hardware property rather than a code path.

- **Policy is `.userPresence`, not `.biometryCurrentSet`.** The stronger flag invalidates the key whenever the user adds a fingerprint or re-enrols Face ID, forcing every card to be re-authored and every payer to see version bumps. The passcode fallback is a real residual and is listed as such in the threat model rather than pretended away.
- **Certificate:** `sign_identityKey("occulta-payment-cert-v1" ∥ LP(payment_pubKey) ∥ LP(deviceID) ∥ version(UInt32 BE) ∥ createdAt(8) ∥ expiresAt(8))`, travelling **with every card** — not "with every request."

  **The domain prefix is mandatory and was missing.** *(Added by `CRYPTO_REVIEW_CHECKLIST` §4.3 run, 2026-08-10.)* The certificate is a **fourth signing format**, outside the `SignedAttribute` family, signed by the **identity key** — the same key that signs `occulta-identity-challenge-v1` and `occulta-signed-attribute-v2`. As originally written it carried no prefix and no category, so nothing separated it from either. No collision is reachable today only because an x963 public key begins `0x04` while the challenge prefix begins `0x6F` — luck, not construction, and precisely the criticism D-02 levels at bare concatenation. §4.3 admits no exception: a new artifact type takes a versioned prefix or a category inside an existing family. Length-prefix the variable-length fields for the same reason. Two of D-03's three delivery contexts carry no request, and a card without its certificate is unverifiable, so tying the certificate to requests breaks the ceremony path, which is the primary one. The payer verifies it against the identity key pinned at UWB, then verifies card and request against the payment key it carries.
- **The certificate expires.** *(Added by security review, 2026-08-10.)* Cards and requests both carry `expiresAt`; the certificate originally did not, leaving a compromised payment key valid forever, since retiring it requires a superseding certificate and delivery is revocation case 4 — the open one. Card expiry bounds each artifact but not the key: the attacker simply signs fresh cards. Same reasoning that made card expiry mandatory — bounds staleness with no channel required, fails closed on abandonment.
- **Per-device by construction.** SE keys are non-extractable, so each authoring device has its own payment key and its own certificate signed by *that device's* identity key. This stays on the right side of the standing no-vouching rule: `cert_B` only verifies for a payer who pinned `identity_B`, which only happens through a physical ceremony with device B. The certificate scopes a purpose key *within* a device; it never extends trust across one.
- **Certificate version is global per contact, NOT per `(contactID, deviceID)`.** *(Corrected by security review, 2026-08-10 — the original per-device scoping was void.)* `deviceID` is a field the signer chooses; nothing binds it to a real device. Scoping the counter by it means anyone who can sign a certificate bypasses monotonicity entirely by incrementing `deviceID` instead of `version` — a fresh `deviceID` has no stored version, so it is first-seen and accepted. That would leave [Revocation](#revocation) case 2 claiming a superseding certificate retires a compromised payment key when nothing forces the attacker back into the same partition.

  Store `highestCertVersionSeen` per **`contactID`**; reject anything lower regardless of the `deviceID` claimed. A genuinely new device must then still exceed the highest version that contact has ever presented, and minting a fresh `deviceID` buys nothing. This is the same ruling D-15 reached for card version — global to the signer, not to an attacker-choosable partition.

  **A previously unseen `deviceID` for a known contact must surface as prominently as a new destination.** Today it would appear silently.

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

**The name comes from the payer's own contact record, never from the card.** *(Added by security review, 2026-08-10.)* SPEC §5 already settles this — *"display name comes from the responder's own contact record (decrypted locally), never from the payload."* D-10 applies the impersonation rule to `payeeName` and friends as *displayed fields*, but the generated sentence is app copy, and rendering a card-supplied string inside it is precisely the impersonation that rule exists to prevent. **The sentence is built from local contact data plus structured numbers only — no string from the card ever enters it.**

An **optional** free-text note may travel under SPEC §5's existing `contextNote` rules. It carries context, never security meaning.

**PV Q-03 answered:** `expiresAt` inside the signed payload, inheriting `SignedAttribute`'s tamper-proofing (`SignedAttribute.swift:22-25`). Default window **~72 hours**, author-adjustable up to a maximum the **verifier** enforces — see D-14, since a cap the author applies is no cap under coercion. The 120 s presence window does not transfer, as a wire request legitimately sits unread over a weekend, but the window must stay short enough to bound D-04's replay residual. **One-shot** via a consumed-`requestID` store retained until each entry's own `expiresAt`, then dropped.

**No separate nonce field. `requestID` is the nonce**, and a second unique value would be redundant. But the construction differs from the precedent it is often compared to, and three of its properties are requirements rather than incidental facts:

**Why it is not SPEC §3.4's nonce.** That nonce is **verifier-issued** — the challenger mints it to prove liveness in a challenge–response. A payment request is **sender-originated** (PV D-01's inversion), so there is no verifier to issue anything. A sender-chosen unique ID plus a consumed-store is the correct shape here; reaching for a verifier nonce by analogy would invent a round trip the design deliberately does not have.

1. **`requestID` must be CSPRNG-generated and must remain inside the signed payload.** Swift's `UUID()` draws from a CSPRNG on Apple platforms, and D-11's layout signs it — but both are requirements, and relaxing either silently defeats the consumed-store, since a mutable ID can be rewritten to look unseen.
2. **Replay protection is expiry-bounded, therefore clock-dependent.** Dropping a store entry at `expiresAt` is safe only because a replay then fails the expiry check instead — a rolled-back device clock re-opens *both*. Low severity, since it needs the payer's unlocked device, but `IdentityChallenge+Constants.swift` already carries `clockSkewGrace` and `timestampWindow` for this exact class and the request should inherit that thinking rather than rediscover it.
3. **The store is local**, so it survives neither a reinstall nor a second payer device — see the threat model's residuals.
4. **Consumption is marked *before* the request is displayed, never after.** *(Added by `CRYPTO_REVIEW_CHECKLIST` §2 run, 2026-08-10, which asks when consumption occurs relative to the operation succeeding.)* Mark-before fails safe: a crash loses the request and the payee re-issues. Mark-after allows replay within the window on a crash loop. Marking must also be idempotent — re-processing the same bundle is a no-op, not an error.

**Layer boundary: verification returns facts, the UI renders the sentence.** *(Added by §5 run.)* The generated sentence needs the local contact record and a localized template. Building it inside verification would give the crypto path SwiftData and localization dependencies, which §5 forbids. Verification emits structured facts — contact identifier, amount, currency, destination, age — and the presentation layer renders them.

**Bind the payer's key fingerprint.** Not for ordinary relay — a re-aimed request still points at the payee's real account, so the attacker gains nothing. The reason is **duress amplification**: coerce one signature aimed at the attacker's account, then broadcast that single card+request pair to every contact the victim has. Without the binding, one compromised signature is worth N victims. With it, one. The cost — asking three people means three signatures and three biometric prompts — is friction in the right direction.

### D-12 · Cards are `SignedAttribute`s, not a new signed type

New categories `.paymentCard`, `.paymentRequest` (and `.paymentReceipt` if D-14's phase-2 item lands). No new domain prefix.

`category` is **inside** the signing payload — *"Including `category` prevents a category-substitution attack"* (`SignedAttribute.swift:20`) — so a signature over `.financial` does not verify against a `.paymentCard` payload. The category is the intra-family domain separation, and `.shard` (raw GF(2⁸) key material) already coexists safely with `.medical` under the same prefix. A new prefix would re-solve a solved problem.

The stronger argument is infrastructure: `signedAttributes` is already wired into Secure Mode — carried in the layer store (`SecureMode+LayerStore.swift:47`), re-encrypted across key rotation (`Contact+Model+Reencrypt.swift:45`), restored under the staged key during classification (`ContactManager+Classification.swift:272`). A parallel type would mean re-earning every one of those guarantees by hand.

Three items follow:

- **The owner's own cards need a home.** `signedAttributes` hangs off `Contact.Profile` and holds *other people's* attributes; there is no self-profile (searched `isSelf`, `selfProfile`, `selfContact` — no matches). The shard flow is the model: `SignedAttribute` is the artifact, with separate models for owner-side holding (`PendingShardDistribute`) and recipient-side state (`CustodyShard`). Cards need the same, and the owner's store holds **full destinations in the clear** — a larger at-rest exposure than the baselines Q-03 reasons about, on the device of the person being protected.
- ~~**The baselines are their own models.** D-04's tables are not `SignedAttribute`s; the payer verifies the card and discards it.~~ **Superseded 2026-08-10.** Q-06 reversed the discard, so the received card *is* a retained `SignedAttribute` and belongs in `signedAttributes` under `.paymentCard`. The remaining models — `DestinationBaseline`, `PinnedCertificate`, and the two stores — are their own, under the **local DB canonical key** (Q-03), not the shard-custody pattern this bullet originally pointed at.
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

**Signed but out of bounds → not a card.** *(Added 2026-08-10 by the standing-check walk.)* Every numeric field in every artifact is chosen by the signer, so a valid signature says nothing about whether the value is sane. The verifier enforces the bounds; author-side limits are UI, not security, because the author may be under coercion.

- **`expiresAt` beyond the maximum window → reject.** Card and request both carry a signer-chosen expiry, and the entire expiry story — Q-01's "bound the damage," [Revocation](#revocation)'s "supersede and outlive," D-11's replay window — assumes expiry actually arrives. A coerced card carrying `expiresAt` in the year 2200 never expires. D-11's *"author-adjustable within a cap"* placed the cap on the wrong side.
- **`version` jumping implausibly far → reject.** `version` is a signer-chosen `UInt32`. A coerced card at `UInt32.max` **permanently blocks supersession of that lineage**: the owner's legitimate next version is refused forever by D-04's `version < stored` rule, and Q-01's whole mitigation is superseding. An escape exists — mint a new `cardID`, which Q-02's contact-wide diff renders correctly — but the lineage stays poisoned, so cap the increment rather than relying on the escape.

Both belong to the same family as Q-02, D-06 and D-09's `deviceID`, one level down: those asked *who chooses the identifier*, these ask *who chooses the number*.

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

**Multi-recipient delivery already exists, with a precedent of exactly this shape.** `CryptoManager.seal(sealedPayload:groupID:recipients:)` produces one shared outer ciphertext plus N per-recipient wrapped envelopes, and `OccultaBundle.RecipientPayload` (`OccultaBundle.swift:550`) carries **per-recipient distinct content** — `prekeyBatch`, `shardOperations`, `custodyManifest`, `expectedShards`. Shard distribution is the working instance: `prepareShards` signs N distinct artifacts, one per trustee, delivered in one bundle. Recipient-bound cards are that pattern with a new payload type.

**But card distribution must send N separate bundles, not one group bundle.** *(Added by `CRYPTO_REVIEW_CHECKLIST` §3 run, 2026-08-10.)* `OccultaBundle.recipients` is an array each recipient scans to find their own envelope, so **its length is visible to every recipient**. That is acceptable for group messaging, where membership is already known — but payment counterparties are not a group and have no relationship to each other. One bundle to 200 contacts tells each of them that the payee has 200 payment counterparties.

The consequence lands on the post-duress re-issue (Q-01): it is **N separate manual sends**, not one. F-02's arithmetic returns through a door this decision thought it had closed. Per-recipient signing still scales; per-recipient *delivery* does not.

Also from §2: a card-only bundle consumes a prekey like any other, so a bulk re-issue drains N prekeys and can push contacts into long-term ECDH fallback, losing forward secrecy on those sends. The fallback is designed behaviour, but the re-issue flow is the one place it fires in bulk.

**Requirement inherited:** every per-recipient field in `RecipientPayload` is tier-padded to fixed size with filler beyond the real count — `shardOperations` carries `.unsupported` entries, and `custodyManifestCount` exists because a zero count is otherwise ambiguous between "attempted and found nothing" and "never attempted." A card field must do the same: always present, tier-padded, with an explicit attempted-signal where absence is meaningful. Otherwise the presence or size of a card in a bundle leaks who is transacting — the `#21` traffic-shape concern the rest of the envelope already handles.

**Pre-implementation check — SE signing under one `LAContext`.** Partially settled, 2026-08-10.

- *Established:* the vault stores one pre-evaluated `LAContext` for a session (`Vault+Manager.swift:163`) and reuses it across many SE operations, with `Key+Manager.swift:638` stating the intent — *"pre-evaluated once per session; passed to SE to avoid per-op prompts."* A shipping pattern.
- *Not established:* nothing in the repo exercises a `.userPresence`-protected **signing** key with a reused context, because no such key exists. The apparent precedent — `prepareShards` signing N shards — prompts zero times, since the identity key carries no biometric flag at all (D-01's correction). Cannot be verified off-device; `TestKeyManager` bypasses the SE by design.
- *The detail that decides it:* the context is supplied via `kSecUseAuthenticationContext` when **retrieving** the key, and the returned `SecKey` handle carries the authorization — this is what `retrieveVaultPrivateKey(context:)` does. But `signData` calls `retrievePrivateKey()` **per signature** (`Key+Manager.swift:316`), which for a gated key is where each prompt lands. **The payment path must retrieve the authorized handle once per session and sign K times against it.** Written that way batching should hold; written like `signData` does today it will prompt K times.
- *Test, on device:* create a `.userPresence` key, evaluate one `LAContext` with `.deviceOwnerAuthentication`, retrieve once with that context, sign K times against the handle, count prompts. Bounded by the vault's inactivity timer either way, and no `touchIDAuthenticationAllowableReuseDuration` is configured anywhere, so there is no cross-context window to fall back on.

**What is given up:** broadcasting a card to a counterparty without a signing action. D-13 already puts that at a ceremony, so nothing real is lost. `#26` reuse survives intact — the owner never re-enters banking details, which is what that promise was about.

### D-16 · Cards are acknowledged on receipt — version, never timestamp

On verifying and pinning a card, the payer signs a short acknowledgement under their payment key. **Category `.paymentAck`, with a specified layout** — *(added by `CRYPTO_REVIEW_CHECKLIST` §4.3 run, 2026-08-10; the original described the content in prose only, leaving it with no category and therefore, under D-12's own reasoning, no domain separation)*:

```
value: cardID(36) ∥ version(UInt32 BE) ∥ LP(payeeKeyFingerprint)
```

**Transmitted is not received, and the design currently conflates them.** D-03's send is fire-and-forget over F-02's share sheet, so a payee knows only that they shared something. Closing that gap does two jobs:

- **Transport suppression becomes visible.** An attacker who controls the channel drops the bundle and sends plain instructions instead; today neither party can tell. With acknowledgement, the payee sees nothing come back and the natural response is an out-of-band call. A threat-model residual moves from unclosed to detectable.
- **Version propagation becomes knowable.** Q-01's post-duress requirement — flag which contacts have not received the superseding version — is otherwise guesswork from the sender's local record of what they *sent*. Acknowledgement makes it evidence, in precisely the case Q-01 accepts as unrecallable.

**No fine-grained timestamp, and this is not negotiable.** An acknowledgement carrying *when* is a read receipt — the *"who checked whom, when"* class `Presence Verification/SPEC.md` §7 refuses to persist — and in a coercive household, a controlling family member learning when someone opened the app is a real harm to exactly this feature's audience. The payee needs *"Bob is on v8."* They never need *"Bob opened the app at 14:23."*

The payee retains the highest acknowledged version per contact, so a replayed old acknowledgement degrades to stale information rather than anything exploitable.

**Acknowledgements are advisory and must never suppress a re-issue.** *(Added by security review, 2026-08-10.)* The ack carries no expiry and no freshness — deliberately, since a timestamp would make it a read receipt. That means an attacker who captured Bob's v8 ack can replay it after Bob reinstalls: the payee reads *"Bob has v8,"* skips re-issuing, and Bob's fresh install holds no baseline at all. That attacks Q-01's mitigation in exactly the scenario Q-01 exists for. So the re-issue prompt always permits re-sending to any contact, and an acknowledgement may inform the ordering of that list but must never remove anyone from it.

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
| `destinationChanged(from, to)` | payer | **derived** | the tripwire — computed against **all** destinations known for the contact, not one lineage (Q-02) |
| `requestReceived` | payer | inbound | expiry and one-shot checks (D-11) |
| `requestConsumed` | payer | local | `requestID` retained until its own expiry |
| `diffChallengeSent` / `diffChallengeReceived` | both | user-initiated | D-17 |
| `contactKeyChanged` → `cardsInvalidated(contact)` | payer | derived | loudly and at once (Q-07) |
| `depthReturnedToZero` → `reIssuePrompt` | payee | local | Q-01's post-duress flow, driven by acknowledged versions |
| `cardExpired` | both | derived | from `expiresAt` |
| `paymentRecorded` | payer | outbound | **phase 2** (Q-08) |

### Events specify transitions; they are not rows

Persisting this sequence would build a complete payment audit trail — who paid whom, when, how often — on a device whose adjacent feature refuses to write verification history at all (`Presence Verification/SPEC.md` §7), and would undo most of Q-03.

**Only derived state persists**, and it is already settled: the retained card in `signedAttributes`, `DestinationBaseline` (first- and last-seen, the minimum that supports age and diff), `PinnedCertificate`, consumed `requestID`s until their own expiry, and highest-acknowledged-version per contact (D-16). Everything else in the table above is transient by construction — including every challenge.

Two rows carry more weight than their description suggests. **`cardAcknowledged` is what turns Q-01's post-duress flag from guesswork into evidence.** And **`destinationChanged` is marked derived on purpose**: the tripwire is computed locally from state rather than received from anyone, which is exactly why it survives full key compromise (see below).

---

## Threat model

Written in `Presence Verification/SPEC.md` §6's form.

### Defeated

- **Forged card or request** — needs the SE-held payment key, and its use is gated (D-09). Hardware-excluded against key *extraction*; gated against key *use*.
- **Forged certificate** — needs the SE-held identity key. Hardware-excluded against extraction, but **not gated against use**: the identity key is `[.privateKeyUsage]` only (D-01's correction), so certificate minting is silent on an unlocked device. Distinguished from the line above deliberately, since that distinction is the entire reason D-09 exists.
- **Mix-and-match** (genuine request + attacker's card) — D-02's `cardDigest` binding.
- **Retargeting a coerced artifact by moving the file.** Both card (D-15) and request (D-11) bind their counterparty inside the signed bytes, so share-sheet, email or AirDrop delivery to a different contact fails verification. Recipient selection is a hard gate on artifact creation, not a UI convenience.
- **Backdated card faking age** — D-06 reads locally-observed `firstSeenAt`.
- **Silent duress card — *conditional on Q-02's cross-card diff being built*.** A coerced *revision* must change the destination digest and bump the version, so it renders as a loud diff, and it cannot forge age. But a coerced signer can mint a **new `cardID`** instead, which has no lineage and therefore no revision diff — under a per-lineage diff it degrades to "new destination," the weaker warning. The claim *"a duress attacker cannot make a change quiet"* holds **only** when the diff is computed against every destination known for that contact (Q-02). Built that way, minting and revising are equally loud and the attacker gains nothing by choosing either.
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
- **The consumed-`requestID` store is local, so one-shot is per-device and per-install.** A reinstall clears it, and each of a payer's devices keeps its own once multi-device lands — so within the ~72 h window the same request can be presented again and read as fresh. Not a double-payment, since Occulta moves no money; but *"pay me $5,000"* appearing twice and reading as legitimate both times is the class of confusion this feature exists to prevent. Bounded only by the request window, which is the argument for keeping that window short.
- **Clock rollback on the payer's device** re-opens an expired request whose store entry has already been dropped. Needs an unlocked device, which affords worse attacks — recorded because expiry-based replay protection is only ever as good as the clock behind it.
- **Pre-positioning a destination.** A coerced card delivered standalone (D-03, context 3) fires its diff at a moment with no payment pressure, where it is easily dismissed as *"they changed banks."* By the time a request arrives, the destination is established rather than new. Not silent — the diff did fire — but it fired when the user had least reason to care. Mitigated by D-06's relationship-relative age framing, which keeps a destination younger than the relationship visibly young no matter how long the attacker waits; not eliminated, since a payer who dismissed the first warning may dismiss the second.
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

## `CRYPTO_REVIEW_CHECKLIST` run — design stage, 2026-08-10

Run against [`Docs/Audit/CRYPTO_REVIEW_CHECKLIST.md`](../../Audit/CRYPTO_REVIEW_CHECKLIST.md). Design-stage, so §2 and §5 are partly answerable only at implementation; those are marked rather than skipped. Findings are recorded at their decisions above; what follows is the material that lives nowhere else.

**Gate: all four blockers now answered (2026-08-10).** The run raised four — certificate prefix (D-09), acknowledgement category and layout (D-16), payer-side sealing key (Q-03), consumption ordering (D-11) — and the last of them, the sealing key, was decided the same day. Three of the four were introduced by this run rather than found by the two reviews before it.

**The gate is not "passed" until it is re-run against the corrected design and against real code**, per the checklist's own rule that the block ships in the same change as the code it describes. What is recorded here is a design-stage run whose findings have all been answered.

### §1 · Key ownership map

| Key | Custody | Access control | Role |
|---|---|---|---|
| Identity | SE, `master.key.privacy.turtles.are.cute` | `[.privateKeyUsage]` — **no gate** | Signs certificates |
| Payment (new) | SE, new tag | `.userPresence` | Signs cards, requests, acknowledgements |
| Vault | SE, `vault.key.occulta.v1` | `.biometryCurrentSet .or .devicePasscode` | Seals the owner's cards at rest |
| Local DB canonical | SE-derived hybrid, `Tags.localDB` | Device-unlock level | Seals retained cards, baselines, certificates, the two stores (Q-03) |

**Key material shared between contacts: No.** Cards carry no secret material; nothing here is a key-distribution path. The payment public key is a *second* long-term P-256 public key on the wire — no change to §4.4's analysis, since if P-256 falls both fall, but recorded rather than discovered later.

### §2 · Consumption events

**Zeroing: N/A** — no path here holds key bytes. The only consumption event is `requestID` (D-11, ordering now specified). Prekeys are consumed indirectly by ordinary bundle transport, including card-only bundles (D-15).

### §3 · Multi-party trace

*Payee Yura, card v5 → IBAN X; payers Bob, Carol, Dave.*

- Yura signs `card_B`, `card_C`, `card_D` — distinct bytes, since the recipient fingerprint is in the payload (D-15), therefore distinct signatures.
- Bob holding `card_C` cannot use it: the binding check rejects. He learns Carol's public-key **fingerprint** and nothing else.
- No recipient learns another exists — **provided cards are distributed as N separate bundles** (D-15). In one group bundle, `OccultaBundle.recipients`'s length discloses the count to all of them.
- Below-threshold cases and duplicate-index checks: N/A, no threshold scheme.

### §4 · Security property verification

- **4.1 Property.** *A payer cannot be shown, as verified, a payment destination that the pinned counterparty did not sign for that specific payer.*
- **4.2 Attacker bound.** Computational — ECDSA P-256. Not information-theoretic.
- **4.3 Domain separation.** New categories inside `SignedAttribute` for card, request, ack (D-12, D-16); a new versioned prefix for the certificate, which is outside that family (D-09); a third, non-signing domain string for `destinationDigest`; length-prefixing throughout (D-02).
- **4.4 Harvest-now.** Excluded from `#23` per Q-09 — cards are verified contemporaneously, not decades later.
- **4.5 Access control.** Flags quoted in the table above. The `LAContext` batching behaviour is open and requires an on-device test (D-15).
- **4.6 Prekey public keys.** None published or stored by this design. Consumed only via ordinary bundle transport — see §2.
- **4.7 Not achieved.** No payment execution, no name-to-account verification, no counterparty honesty, no confirmation the wire matched the request, no defence against a compromised OS. See [Explicit non-claims](#explicit-non-claims).

### §5 · Layer boundary check

Verification takes bytes and returns structured facts; the presentation layer renders the sentence (D-11). SE access stays in `Key+Manager`. **`TestKeyManager` must be extended for the payment key** — without it no card-signing path is unit-testable, which collides with CLAUDE.md's requirement of unit tests for all implementations.

---

## Forensic cleanliness

`Presence Verification/SPEC.md` §7 refuses persistence deliberately — *"no verification history is written anywhere by default"* — and states that a history feature *"would need Travel Mode integration before it could exist at all."*

D-04's stored cards and baselines **are** a history feature. **Secure Mode integration is therefore a precondition of this design, not a follow-up.** On seizure a row set discloses who this person pays, on which rail, since when, how recently, and — after Q-06's ruling — **the account numbers themselves**, in full, for every counterparty. Org Graph F-07's "affiliation-in-a-file" argument applies unchanged and with more to find.

Requirements, inherited rather than re-derived from `Occulta/Features/SecureMode/forensic-trace-avoidance.md`:

- **A non-nil depth field from creation** on every new model here. S6 (`visibleThroughDepth`) and S9 (`globalTrusteeDepth`) both landed on this rule so that presence-versus-absence of the field is never itself a tell. The shard work reached it by retrofit and records the cost.
- **`PRAGMA secure_delete`** (S2) and **`.completeFileProtection` re-applied on every save** (S3/S4).
- **S8's accepted-gap reasoning for row counts** applies verbatim to card rows.
- **Contact classification inheritance.** `DestinationBaseline`, `PinnedCertificate` and the two stores are contact-keyed and must filter off `isVisible(atDepth:)`, or hiding a contact leaks them — their existence *and* their bank details. Retained cards get this for free by living in `signedAttributes` (Q-03). See Q-01 step 3.
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

### Q-01 · Duress-signed cards — **answered 2026-08-10**

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

- `DestinationBaseline`, `PinnedCertificate` and the two stores are contact-keyed. Unfiltered, they disclose both a hidden contact's existence and their bank details. The shard work already solved this shape — real shards from safe contacts get correct ceiling-based visibility off the existing classification — so inherit it deliberately rather than assuming it. Retained cards get it for free from `signedAttributes` (Q-03).
- The owner's own card store needs a depth stamp. At a duress depth the coercer otherwise sees the operator's full account list, and the presence of a crypto card is disclosure in itself.
- Row counts, per `forensic-trace-avoidance.md` S8.

#### 4. Bound the damage

Three properties already in the design, none of which the coercer can defeat:

- **A duress card cannot be quiet — provided the diff is contact-wide (Q-02).** A coerced revision always renders as a loud diff. A coerced *new* `cardID` has no lineage to diff against, so under a per-lineage comparison it degrades to the weaker "new destination" warning, and minting becomes the coercer's cheaper move. Q-02's cross-card diff is what makes this property true rather than aspirational.
- **Its age cannot be forged.** D-06 reads locally-observed `firstSeenAt`, not the signed `createdAt`.
- **It expires.** The mandatory `expiresAt` ([Revocation](#revocation)) bounds the window without requiring any channel.

**The residual, narrowed by D-15 and stated plainly.** A duress-signed card still cannot be recalled: coerced into signing version 7, the operator can later author version 8, but only contacts who *receive* it are protected, and D-04's version rule accepts v7 as newer from anyone who never saw v8. Supersede and outlive, never retract — revocation case 4 in a different costume.

**What D-15 removes:** because the card now binds a recipient, a coerced card is only usable against contacts the coercer could *select* — those visible at the coercion depth. Hidden contacts are unreachable by a coerced card, not merely unlikely to be reached. The residual is therefore bounded to the contact set the operator deliberately classified as non-sensitive, which is the trade this whole answer is built on. Manual transport of the `.occ` file does not widen it, because the binding is inside the signed bytes.

**Required: stamp the owner's card store with the depth it was authored at, and on return to depth 0 prompt to re-issue, flagging which contacts have not yet received the new version.** That flag is the only thing standing between a coerced signature and an indefinite window.

### Q-02 · Multiple cards per contact — **reopened and answered 2026-08-10**

Previously closed on the data model alone. That was the easy half.

**Settled, and unchanged:** N cards per contact are representable — retained cards live in `signedAttributes` keyed by their own `cardID`, `DestinationBaseline` independently by `(contactID, destinationDigest)`. The **sender selects** which card a request references (D-11 binds exactly one `cardDigest`), so the choice is made by the person who knows which account they want, on their own device; the payer is never asked to choose between a counterparty's accounts. Each card carries a `label` for that selection (D-10) — signed, display-only, under SPEC §5's impersonation rule. Per-recipient signing scales by D-15's lazy minting, so N cards × M counterparties never materializes.

**What was missed: there are three states, and a per-lineage diff collapses two of them.**

| State | Comparison available | Rendered today |
|---|---|---|
| First card ever from this contact | none | "new destination" — correct, D-13 mitigates |
| **New `cardID` from a contact you already hold cards for** | **yes, across cards** | "new destination" — **wrong, understates it** |
| Revision of a known `cardID` | yes, within lineage | the loud diff |

**Ruling: the diff is computed against every destination known for that contact, not against the referenced card's own lineage.** The payer already holds a `DestinationBaseline` row per known destination, so the stronger statement is always available:

> You have paid this contact at ···4471 since March. This request uses a different account, ···8823, first seen today.

**Why this is a security fix and not UI polish.** Under a per-lineage diff, a coerced signer is strictly better off **minting a new `cardID`** than revising an existing one — a new lineage has nothing to diff against, so it produces the weaker of the two warnings. Every claim in this doc that a duress card "cannot be quiet," including D-05's framing and the threat model's Defeated entry, implicitly assumed revision. Contact-wide diffing removes the attacker's choice: minting and revising are equally loud, so there is no cheaper move.

### Q-03 · PII at rest — **answered 2026-08-10**

A digest over bank details is brute-forceable: account and routing numbers carry roughly 2⁴⁰–2⁵⁰ real-world entropy, and salting does not help because the salt must be stored alongside.

- **Crypto addresses:** genuinely protective (2¹⁶⁰), and public anyway.
- **Bank details:** treat the digest as PII; it belongs in the encrypted local DB with everything else.

**After Q-06's ruling the entropy argument is moot** — the destination is stored in full, so there is nothing to brute-force. It is retained above because it explains why the digest was never the protection it appeared to be, which is part of why the ruling went the way it did.

**Q-06's ruling enlarges this, deliberately.** D-04 now stores full counterparty destinations, not digests and tails, so the at-rest exposure is real rather than theoretical and the digest's brute-force cost stops being the interesting question. What remains true is that the original reasoning already conceded the point: the real exposure was always a coerced or compromised *unlocked* device, where a digest never helped. Masked display survives as harm reduction in list and history views (surface rule), not as a storage strategy.

**What is stored:** the owner's own cards (full destinations, signed), counterparties' retained cards in `signedAttributes` (same), `DestinationBaseline`, `PinnedCertificate`, and the two stores. Encryption at rest, non-nil depth from creation, contact-classification inheritance (Q-01) and cascade delete are settled in [Forensic cleanliness](#forensic-cleanliness) and are not re-argued here. Four decisions remain.

**1 · Cards live in the Vault, under the vault key. No dedicated store, no dedicated sealing key.**

An earlier draft of this answer argued the opposite on two grounds, both wrong. *"A vault unlock per payment"* — the vault session is scoped by a pre-evaluated `LAContext` held in memory (`Vault+Manager.swift:46`), so it is one unlock per session, not per operation. *"`.biometryCurrentSet` locks the operator out"* — the vault key is `[.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode]`, and the passcode branch survives biometric re-enrolment.

The decisive argument runs the other way, and is the same one D-12 used for `SignedAttribute`: **do not build a parallel mechanism that has to re-earn Secure Mode's guarantees by hand.** Vault residence inherits rotation-on-activation (S1's cryptographic erasure), backup participation, and the re-encryption path. A dedicated store re-implements all three, with three chances to get them wrong.

**And it fixes a default.** `VaultEntry.visibleThroughDepth` is **exact-match, not a ceiling** (`Vault+Model.swift:188`) — *"visible only at exactly depth N."* A card authored at depth 0 is therefore invisible at every duress depth by construction, with no classification step. Contacts default to `Int.max` (visible everywhere), which is the gap Q-01 has to cover with a prompt; vault entries default the right way round.

**No dedicated sealing key.** The one argument for separation was backup scope — keeping payment destinations out of exported vault backups. It does not survive: vault backups are encrypted and user-initiated, and cards *should* be restored, because a lost baseline is a lost tripwire history, which after Q-06 is the last line of defence. Compartmentalization buys nothing else, since both keys are SE-derived and fall to the same coerced unlock.

**Unchanged:** D-09's *signing* key stays separate. That key exists because the identity key has no gate and cannot acquire one; nothing here touches that reasoning.

**The payer-side models: the local DB canonical key.** *(Raised by `CRYPTO_REVIEW_CHECKLIST` §1, decided 2026-08-10 — the last of the four gate blockers.)* The above settles the **owner's** cards; this settles what the payer holds.

**Not the vault key, and the reason is specific to this data.** Under it, receiving a request means unlocking before the app can read `DestinationBaseline` — so declining the unlock renders the attacker-supplied request **without its age and diff**. The signed content arrives either way; only the warning is gated. That inverts D-14 exactly: the part the app vouches for becomes optional while the part it does not stays visible. Failing closed instead makes viewing any incoming payment a biometric event, and friction here pushes people around the feature rather than through it.

**Not a dedicated key either.** `CustodyShard` is sealed independently because it holds material *on behalf of others*. This is mine — data received from a contact, about that contact, held for my own protection. A dedicated key would mean re-earning rotation-on-activation, classification filtering and the re-encryption path by hand, which is the third time that argument has come up and the third time it loses.

**So: the same key as the rest of the contact record.** `signedAttributes` already holds SE-signed sensitive attributes under it, with re-encryption (`Contact+Model+Reencrypt.swift:45`) and staged-key restore during classification (`ContactManager+Classification.swift:272`). A contact's payment card protected differently from their signed medical attribute would be an inconsistency with nothing behind it.

**The split is coherent:** the Vault holds *my secrets* — my own destinations, authored by me, gated because signing and sending them is the sensitive act. The contact record holds *what I know about others*. The owner's cards and the payer's retained cards land on opposite sides of a distinction the app already draws.

Consequence for D-04: cards collapse into `signedAttributes` and `StoredCard` disappears. Two wrinkles accepted — `signedAttributes` is a single encrypted blob holding a serialized array, so every read decodes all of that contact's attributes (fine at this N, and D-12's wire-compat item already covers the array-decode hazard); and certificate retention becomes its own small model rather than a field copied onto every card.

**Noted, not fixed:** `Key+Manager.swift:783-799` mints the shard custody key lazily on `errSecItemNotFound`, so that key's existence discloses that shard custody has been used — in tension with `forensic-trace-avoidance.md` B5 (*"SE key created at first launch, not at activation"*, rated High). Pre-existing and out of scope here; recorded so it is not copied.

**3 · Deniability: integrate with Secure Mode. `#6` is a later strengthening, not the requirement.** The earlier text recommended `#6` (Plausibly Deniable Vault Partitions), which is Phase 2 and unbuilt. The shipped depth machinery is what this feature must integrate with, and it is already a precondition. `#6` would add hidden-volume indistinguishability on top; nothing here is blocked on it.

**4 · Superseded `DestinationBaseline` rows need a retention policy.** Kept indefinitely they accumulate a complete record of every account every counterparty has ever used — a financial history that outlives every transaction and that nothing in the design prunes. Discarding them loses the *"you have paid this account before"* signal when a counterparty switches back, which is genuinely useful.

Keep them, and treat them as the most seizure-exposed rows in the feature: depth-scoped, cascade-deleted, plus a user-facing **"forget payment history for this contact."** That last item matters because these are the only rows a user would ever think to clear, and nothing currently lets them.

**The floor, as a non-claim:** a coerced unlock at depth 0 with real contacts visible exposes all of it. No key separation or storage shape raises that floor — it is the same floor every feature in this app has, and this question should stop implying a storage decision could change it.

Consistent with `Organizational Identity Graph/FINDINGS.md` F-07's conclusion for org credentials, on a larger payload.

### Q-04 · Competitive timing on bank rails — **answered 2026-08-10**

The question assumed a future event. It already happened, and it lands elsewhere than expected.

**EU — live since 9 October 2025.** Verification of Payee is mandatory for euro-area PSPs under Regulation (EU) 2024/886 (Instant Payments Regulation), covering **both** standard SEPA Credit Transfers and SCT Inst, not instant alone. It matches the IBAN against the payee name or company identifier at initiation. Non-euro-area EU PSPs have until 9 July 2027.

**It does not reach this feature's loss pool.** The IC3 figures driving the priority ruling are US; VoP is euro-denominated SEPA. The strongest wedge — US title and escrow — is entirely outside its scope, as is every crypto rail.

**US — moved, but far less.** The Fed added **Payee Name Verification** to FedDetect Notification Services in late 2025. It is optional rather than mandated, reaches institutions on FedLine Direct/Command rather than consumers, and works by *"initially leveraging 12 months of historical transaction data"* — an inference-based risk signal, not an authoritative registry match. FedNow is exploring real-time enablement.

**Net effect on positioning: it sharpens the story rather than narrowing it.** VoP *is* name-to-account matching, which D-08 establishes Occulta cannot do. The two are complementary and fail differently — VoP is defeated by a mule account opened in a matching name; this design is defeated by a coerced signature. A regulated incumbent occupying the name-matching axis removes the temptation to claim it.

**It also validates D-05's corrected framing.** Even the mandated, bank-integrated control ends at a warning the payer may click through. The behavioural residual is where the state of the art stops, not a weakness peculiar to a serverless design — and positioning may say so.

**Where the slice genuinely narrows:** euro-area bank-to-bank transfers, against a naive attacker supplying their own name and IBAN. Everything else — US rails, crypto, non-euro EU until July 2027, mule accounts in a matching name — is untouched.

Sources: [Crédit Agricole CIB](https://www.ca-cib.com/en/news/securing-sepa-payments-verification-payee-service-becomes-mandatory-october-2025), [PwC Legal](https://legal.pwc.de/en/news/articles/verification-of-payee-requirements-vop-under-the-eus-instant-payments-regulation-ipr), [ECB](https://www.ecb.europa.eu/paym/retail/instant_payments/html/instant_payments_regulation.en.html), [Federal Reserve Financial Services](https://www.frbservices.org/financial-services/multiservice-solutions/payee-name-verification). Retrieved 2026-08-10.

### Q-05 · `CRYPTO_REVIEW_CHECKLIST` — **closed 2026-08-10**

`#26`'s ruling requires `CRYPTO_REVIEW_CHECKLIST §4`, and the canonical document did not exist — while being cited by `README.md:144` as an instruction to **external contributors**, by four master-doc rulings, and by `Multi-Device Contacts/ROADMAP.md` as the R0 gate, where `FINDINGS.md:319` states *"nothing in this plan ships before it's created and run."*

Written: [`Docs/Audit/CRYPTO_REVIEW_CHECKLIST.md`](../../Audit/CRYPTO_REVIEW_CHECKLIST.md), extracted from the two live in-code exemplars (`ShamirSecretSharing.swift:9-48`, `Key+Manager.swift:615-644`) and preserving their five-section template and the §4 sub-numbering the code already cites.

**Sections this feature must answer specifically:** §4.3 for the new categories and payload layouts (D-02, D-10, D-12), §4.5 for D-09's `.userPresence` key and the binding certificate, §1 for justifying a second signing key at all, and §4.7 for the non-claims already listed in the threat model.

### Q-06 · Storage minimization versus forgery detection — **ruled 2026-08-10: the tripwire wins**

The original D-04 justified minimal storage on PII grounds. Against that: the full destination must be displayed at payment time anyway; the baseline is the only surviving defence under key compromise, precisely because it is not cryptographic; and not storing the card leaves the payer dependent on a transport the attacker may control.

Storing less is better against seizure; storing more is better against forgery. **Ruled in favour of forgery detection.** Seizure exposure is already mitigated by Secure Mode's depth machinery, which is a precondition of this feature regardless; nothing else mitigates forgery.

Two consequences beyond the storage shape, both recorded in D-04: storing the *signed* card rather than extracted fields closes baseline poisoning, and full destinations make the diff legible against a chosen masked-tail collision. The ruling made the design smaller — two tables instead of three — which is a reasonable signal it was the right way round.

### Q-07 · Key-change handling — card-local, **not** a Multi-Device dependency

**Corrected 2026-08-10.** An earlier draft of this question claimed Multi-Device R1 (the `deviceID` concurrent-key model) was a prerequisite. It is not. D-09's certificate carries its own `deviceID` in the signed payload, so this feature keys `highestCertVersionSeen` on `(contactID, certDeviceID)` in **its own** table. The only thing card verification needs from `Contact.Profile` is the pinned identity public key, which today's single-slot model supplies. Cards work correctly in every scenario the app currently supports.

What is real:

- **The silent-overwrite defect is inherited, not created.** `Multi-Device Contacts/FINDINGS.md:176` documents that pairing a second device with an existing contact overwrites the first device's key. That scenario is already broken — the payee's first device also stops receiving messages. Cards make the *consequence* worse, not the defect more likely.
- **The payee-replaces-phone case is unaddressed, and R1 does not fix it.** That is key *rotation*, not concurrent keys (D-03's asymmetry). Re-pairing mints a fresh key and every card that payee signed stops verifying. The fix is signed key rotation — the projected "Contact Migration Protocol" — not the `deviceID` column.
- **Forward coupling, not a gate.** When multi-device does ship, D-09's per-device certificates need several identity keys simultaneously verifiable. That is a note for whoever builds R1; it does not block this feature.

**What this feature must build, and can build alone:** when a contact's pinned identity key changes, invalidate every stored card for that contact **loudly and at once**, rather than letting them fail one at a time as unverifiable artifacts. D-14's fail-closed rule applied to a key change. Entirely card-local.

**Unrelated hazard worth carrying:** Multi-Device's own Q-07 found that `processExpectedShards` treats a sender-key fingerprint mismatch as key rotation and hands shards back — a heuristic that cannot distinguish "rotated" from "second device." Card verification must never reuse that pattern. A card that fails to verify is unverifiable, full stop; never resolved by inferring rotation.

### Q-08 · Receipts — **answered 2026-08-10, and the question was two questions**

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

**2. Payment key compromised. Closed by D-09 — and only because certificate version is global per contact.** The identity key signs a superseding certificate at a higher version; anything lower is rejected. Retires a compromised payment key without touching the identity key and without re-pairing. This case had no answer before D-09.

Under the original per-`(contactID, deviceID)` scoping the closure was illusory: `deviceID` is signer-chosen, so an attacker increments that instead of `version` and the counter resets. Corrected in D-09 by the 2026-08-10 security review; genuinely closed only with the global scoping in place.

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

### What this does that nothing else does

Every shipping control answers **"does this account belong to this name?"** — EU VoP, UK CoP, the Fed's Payee Name Verification, and the identity checks sold by wire-fraud vendors.

Cards answer a different question: **"is this the same account I have been paying since March?"** Banks answer it poorly because they do not know a user's history with a counterparty; per-transaction vendor services do not answer it at all. Yet the last-minute change *is* the playbook — the attack is the change, not the name. Everything below is a variation on that one difference.

### Use cases, with their honest counter

**1 · Crypto payments between people who know each other.** The strongest fit, and the only one with no incumbent whatsoever. Today: copy-paste an address and eyeball four characters. Clipboard-hijacking is live and common, and wrong-chain sends are a leading cause of permanent loss. Exchange whitelists exist but not for self-custody, and none bind an address to a physically-met person. D-10 puts `chainID` inside the signed destination, so a re-pointed chain is a hard reject. VoP, CoP and the Fed service touch none of this — it is outside bank rails entirely.
*Counter:* crypto-native users already run test transactions and keep address books; the gain is binding to a person, not to a label they typed.

**2 · An adult child protecting a parent.** No product exists here at all. Today the only defence is a safe word — leakable, forgettable. With cards exchanged at the last family visit, the parent's app already holds the daughter's account since March, and a voice clone cannot produce a signed card.
*Counter:* the scam adapts to *"I can't sign, my phone is gone"* — `Presence Verification/FINDINGS.md` Q-01, unsolved. This converts a cryptographic problem into a behavioural one; it does not remove it.

**3 · Cross-border freelance and contractor payments.** VoP is euro-area only until July 2027, CoP is UK banks, the Fed service is US institutions. Someone in Lisbon paying a developer in Buenos Aires has nothing, and no published timeline closes that.

**4 · Small business paying recurring vendors.** BEC's core target. Large firms have dual authorisation and positive pay; small ones have an accounting package with a payee record anyone can edit. A vendor card exchanged at a site visit means a "we've changed banks" email cannot be represented as verified.

**5 · US residential real estate.** The headline wedge, and the one with a real incumbent. Commercial wire-fraud services already sell to title companies **with insurance**, which this does not have. The honest differentiator is narrower than the wedge framing implies: cards catch the *change* across weeks, and involve no vendor holding a database of who is buying which house. Worth something to some buyers; not obviously worth more than an insured product a title company can purchase today.

### Who would not use this

- **Anyone paying a stranger** — romance, investment, and fake-invoice fraud from vendors never met are permanently outside (D-07).
- **Anyone unwilling to install an app and meet in person**, on both sides, before any money moves.
- **Anyone who wants recourse** — no insurance, no chargeback, no vendor to sue.
- **Anyone whose counterparty changes phones** — every card they signed stops verifying (D-03).

### The addressable pool is smaller than the documented one

The Problem section anchors on **$3.05B in BEC losses**; D-07 excludes payments to strangers. Those two facts sit sections apart and are never reconciled here.

A large share of BEC is vendor-impersonation where the parties have a *business* relationship but have never physically met — outside the closed loop exactly as a romance scam is. So the addressable slice is **real-estate wire fraud ($275.1M across 12,368 complaints), plus the fraction of BEC involving physically-met counterparties, plus the family case — which has no dollar figure at all**, because grandparent scams are not separately quantified in any public dataset (see the Problem section's correction).

That is not an argument against the feature. It is an argument that **$3.05B must never appear adjacent to a claim about what this addresses** — the same discipline [Positioning](#positioning-and-copy-discipline) already applies to the FTC elder figure, for the same reason.

---

## Action items

**Before any implementation:**

- ~~Write `Docs/Audit/CRYPTO_REVIEW_CHECKLIST.md` (Q-05)~~ — written 2026-08-10, and **run against this design; the gate did not pass.** Four blockers, three of which the run itself found: certificate domain prefix (D-09), acknowledgement category and layout (D-16), payer-side sealing key (Q-03, still undecided), request consumption ordering (D-11).
- ~~Decide the payer-side sealing key (Q-03, checklist §1)~~ — decided 2026-08-10: **the local DB canonical key**, the same key as the rest of the contact record. Not the vault key, because gating the tripwire behind an unlock would render attacker-supplied requests without their warnings. Consequence: cards collapse into `signedAttributes` and `StoredCard` disappears (D-04, D-12).
- Extend `TestKeyManager` for the payment key (checklist §5), or no card-signing path is unit-testable — which CLAUDE.md does not permit.
- Distribute cards as **N separate bundles, not one group bundle** (D-15, checklist §3), and re-scope Q-01's post-duress re-issue as N manual sends.
- Specify the two digests, per-rail normalization table, and length-prefixed layouts (D-02, D-10).
- ~~Rule on Q-06~~ — ruled 2026-08-10 in favour of the tripwire; D-04 rewritten. Carry the consequence into the deniability work (Q-03): the at-rest payload is now full destinations.
- ~~Confirm D-09's key architecture against `CRYPTO_REVIEW_CHECKLIST §4` once it exists~~ — done 2026-08-10; §4.3 found the certificate had no domain prefix at all. `destinationDigest`'s third domain string is recorded in the threat model and the checklist run.
- **Enforce verifier-side bounds on signer-chosen numerics (D-14):** maximum `expiresAt` window on card and request, and a ceiling on `version` jumps. Both are load-bearing — unbounded expiry defeats every "bounds the damage" claim, and an unbounded version can permanently block supersession of a lineage.
- Resolve D-12's wire-compat item: lenient per-element decode or a minimum-version gate, before the first card is sent.
- Run D-15's on-device `LAContext` batching test, and build the payment signing path to retrieve the authorized `SecKey` **once per session** rather than per signature as `signData` does today — that choice, not the SE, is what decides whether K signatures cost one prompt or K.
- Tier-pad the card field in `RecipientPayload` to match `shardOperations` (D-15), including an explicit attempted-signal — otherwise a card's presence or size in a bundle leaks who is transacting.
- Build the loud key-change invalidation (Q-07) inside this feature. No Multi-Device dependency; R1's priority stands as set.

**Design:**

- Age, diff, and failure-path surfaces (D-06, D-14) as security-critical screens per `Presence Verification/SPEC.md` §5 discipline.
- **The diff must be contact-wide, not per-lineage (Q-02).** Load-bearing, not cosmetic: a per-lineage diff makes minting a new `cardID` the coercer's cheapest move, and invalidates the "a duress card cannot be quiet" claim in both D-05 and the threat model.
- **Age must render relative to the relationship, not absolutely (D-06).** Absolute age can be waited out by pre-positioning a card standalone; relationship-relative age cannot.
- ~~**Standing check before SPEC**~~ — **walked 2026-08-10.** For every monotonic counter, comparison scope and "first seen," ask who chooses the identifier it is keyed by. Three findings were the same mistake at different sites: Q-02's per-lineage diff (attacker mints a new `cardID`), D-06's absolute age (attacker waits), D-09's per-`deviceID` certificate version (attacker mints a new `deviceID`).

  The walk found two more, one level down — *who chooses the **number***: signer-chosen `expiresAt` with no verifier-enforced maximum, and signer-chosen `version` with no ceiling, the latter able to block supersession of a lineage permanently. Both now in D-14. Remaining scopes checked clean: `destinationDigest` (content-derived, and a new destination *should* read as new), `requestID` (a new one is a new request, not a replay), `contactID` (minted locally at pairing), acknowledged version (already advisory per D-16).
- Surface a previously unseen `deviceID` for a known contact as prominently as a new destination (D-09).
- Consider flagging cross-contact destination reuse (D-04) — free to compute, and one drop account serving several victims is a standard BEC pattern.
- Secure Mode integration for all new models (Forensic cleanliness) — non-nil depth from creation, cascade delete, purge behaviour. Precondition, not follow-up.
- The owner-side card store (D-12) — Vault entries under the vault key (Q-03), inheriting exact-match depth, rotation-on-activation, backup, and re-encryption.
- Retention policy and a user-facing "forget payment history for this contact" for superseded `DestinationBaseline` rows (Q-03).
- `DestinationBaseline`, `PinnedCertificate` and the two stores must inherit contact classification off `isVisible(atDepth:)` (Q-01) — otherwise hiding a contact leaks them. Retained cards inherit it for free by living in `signedAttributes`.
- Sensitivity prompt at card exchange (Q-01, D-13) — contacts default to `Int.max`, so the ceremony is the only reliable moment to ask.
- Post-duress re-issue prompt, flagging contacts who have not received the superseding card version — driven by D-16's acknowledged versions, not by a local record of what was sent (Q-01).
- Delivery acknowledgement (D-16) and the user-initiated diff challenge (D-17), neither of which persists anything beyond highest-acknowledged-version per contact.

**Positioning:**

- ~~Cite the loss figures~~ — done 2026-08-10; IC3 figures confirmed exactly, FTC figure corrected (it is total 60+ fraud for 2024, not grandparent scams), unsourced ~$173M comparison dropped here and upstream.
- **Never pair the FTC elder figure with the grandparent-scam framing in copy.** It measures all 60+ fraud; the subtype this feature addresses is not separately quantified anywhere, so no number should be attached to it.
- **Never pair the $3.05B BEC figure with a claim about what this addresses.** D-07 excludes payments to strangers, and much of BEC is vendor-impersonation between parties who never met physically. The addressable slice is smaller than the documented pool — see [Adoption](#adoption-and-viability). Same rule, same reason as the FTC figure above.
- ~~Verify Q-04 (bank verification-of-payee timing)~~ — done 2026-08-10; EU VoP has been mandatory since 9 October 2025 and does not reach the US loss pool this feature is scoped against. See Q-04.
- Carry D-07's scoping limit and the copy rules into any positioning material; route through the language-review path.

**Elsewhere in the repo:**

- ~~Record `#23`'s SE-extraction limitation in its own ruling~~ — done 2026-08-10, as an addendum to `#23` in the master doc.
- ~~Cross-reference this doc from `Presence Verification/FINDINGS.md` Q-02 and Q-03~~ — done 2026-08-10; both marked answered there, with the substance inline so that doc still stands alone.
- Scope into `#26` rather than as a separate feature.

---

## Provenance

Consolidated 2026-08-09 from `Presence Verification/FINDINGS.md` Design Sessions 2 and 3; items renumbered for readability. Extended 2026-08-10 by a gap review (this doc's D-09–D-17, the lifecycle, the threat model, forensic cleanliness, positioning, and Q-06–Q-09).

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
| D-09 – D-14 | Gap review, 2026-08-10 |
| D-15 | Gap review, 2026-08-10 — recipient-bound cards, lazily signed; closes Q-01's residual for hidden contacts |
| D-16, D-17 | Gap review, 2026-08-10 — delivery acknowledgement and diff challenge |
| Standing-check walk | 2026-08-10 — every scope and signer-chosen field walked against "who picks this?" Found unbounded `expiresAt` and unbounded `version` (D-14); the latter can permanently block supersession of a lineage. Remaining scopes checked clean |
| Checklist run | 2026-08-10 — `CRYPTO_REVIEW_CHECKLIST` §1–§5 against the design. **Gate not passed.** Nine findings: certificate had no domain prefix at all (§4.3, the most serious); acknowledgement had no category or layout; payer-side sealing key never decided; request consumption ordering unspecified; card distribution in one group bundle discloses the recipient count to unrelated counterparties (§3), making the post-duress re-issue N manual sends; card-only bundles consume prekeys in bulk; second long-term public key on the wire; sentence generation risks a §5 boundary violation; `TestKeyManager` needs the payment key |
| Security review | 2026-08-10 — eight findings against the completed design. Voided the per-`deviceID` certificate version scoping (D-09) and with it revocation case 2; added certificate expiry; corrected certificate delivery from "every request" to "every card"; added the payment public key to `StoredCard` (superseded the same day by certificate retention, once `StoredCard` itself dissolved); barred card strings from the generated sentence (D-11); made acknowledgements advisory (D-16); split the Defeated entry on forged certificates from forged cards; recorded cross-contact destination reuse as an unused detection |
| Lifecycle | Gap review, 2026-08-10 — event model as specification, explicitly not as storage |
| Threat model, Forensic cleanliness, Positioning | Gap review, 2026-08-10 |
| Q-01 | Session 2 Q-05; **answered 2026-08-10** — duress cards permitted by design; don't detect, don't degrade, hide the targets, bound the damage |
| Q-02 (multiple cards) | Session 2 Q-06 — closed on the data model, then **reopened and answered 2026-08-10**: the diff must be contact-wide, or minting a new `cardID` becomes the coercer's cheapest move |
| Q-03 | Session 2 Q-07, rewritten by Session 3 D-14; **answered 2026-08-10** — Vault residence under the vault key, no dedicated store or sealing key, Secure Mode not `#6`, baseline retention |
| Q-04, Q-05 | Unchanged / sharpened |
| Q-06 – Q-09 | Gap review, 2026-08-10 |
| Revocation | Session 2 Q-04, closed by Session 3 D-11; **re-scoped to four cases** |

Retained in `Presence Verification/FINDINGS.md` because they concern `#15`/`#27` rather than payments: Session 1 D-01–D-05 (the intent-vs-circumstance construction), D-04 (the `#27` dependency correction), and Q-01 (the behavioural residual). **Q-02 and Q-03 of that doc are answered here by D-11** and should be cross-referenced from it.

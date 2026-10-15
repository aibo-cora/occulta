# Remote Key Exchange — Design Findings

**Status:** Assessment — no SPEC, and none recommended for the proposal as posed. The shape that survives review is the **Confirmed** rung already specified in `Friction/USER_ENGAGEMENT_FRICTION.md` Sweep 4, gated on the prerequisites in [Action items](#action-items). Not scoped for a release.
**Origin:** Design question raised 2026-08-11 — allow two users to exchange keys remotely by showing QR codes to each other over a video call and verifying the Diceware words, motivated by adoption (`USER_ENGAGEMENT_FRICTION.md` C1). Assessed against the shipped exchange protocol, the Sweep 4 trust ladder, and the `#15` relay ruling.

---

## The proposal

> A QR code + QR scanner in a view. Two users show their phones to each other through a video call, verify the Diceware words, complete the exchange. The public keys and ML-KEM material are exposed to the public. Motivation: increase the user base.

Assessed as stated: a **second, co-equal path** into the contact book that does not require physical proximity.

---

## Assessment

### D-01 · Exposing the public keys is not the loss — the premise should be dropped

The stated cost ("public keys, ML-KEM material will be exposed to the public") is not a cost.

Neither leg of the exchange depends on the confidentiality of what a QR would carry. The ECDH leg needs the SE-held P-256 scalar, which never leaves the Secure Enclave; the ML-KEM leg needs the SE-held decapsulation key, released the moment its single decapsulation completes (`Exchange+Manager.swift:593`). Publishing an encapsulation key, an identity key, a nonce, and a ciphertext gives an observer nothing it can use.

Note for accuracy, since it cuts the other way from how this is sometimes stated in review: the shipped exchange **does** encrypt this material in transit — `MCSession` is constructed with `encryptionPreference: .required` (`Exchange+Manager.swift:148`). But it is constructed with `securityIdentity: nil`, so peers are not authenticated and that encryption is not a security property the protocol relies on. It is transport hygiene, not a defence. The defence against an active MITM on that channel is the Diceware SAS, and nothing else.

So the QR channel costs nothing cryptographically. **What it does cost is metadata** — see D-08, which is a real finding and the only place the "exposed to the public" instinct lands correctly.

### D-02 · What the 25 cm gate actually buys, stated precisely

Proximity is not protecting key material. It does two jobs that nothing else in the app does:

1. **It binds a key to a specific human body.** You see Bob; Bob's phone is ≤ 25 cm from yours (`Exchange+Manager.swift:638`); therefore this key is Bob's. This is the "guaranteed by physics" claim (`README.md:27`).
2. **It caps attacker throughput.** An attacker must be physically present, once per victim. Attack rate is bounded by travel and physical risk.

Every downstream security claim in the product reduces to (1). The strategic value of the contact graph — *"the only identity graph on any platform where every entry was established by physical proximity"* (`Master Feature & Expansion Analysis.md:33`) — reduces to (2).

### D-03 · The Diceware SAS does not detect this attack, because it is not a wire MITM

This is the load-bearing finding, and it is easy to get wrong, because the SAS genuinely is strong against the attack it was built for.

The SAS is derived from the completed shared secret — raw ECDH ∥ both ML-KEM secrets (sorted), HKDF'd with both nonces (sorted) as info (`Key+Manager.swift:1349`), rendered as 5 EFF words ≈ **64.6 bits**, with each side's nonce committed in the discovery message before any identity key is seen (`Key+Manager.swift:1385`). It is not grindable and it comprehensively defeats a **wire** MITM: an attacker splicing the channel produces two different secrets, the two word lists differ, the humans catch it.

A relay attack is not a wire MITM. Mallory runs **two genuine, complete, untampered exchanges** — one with Alice while presenting a synthetic Bob, one with Bob under a separate pretext:

| | Wire MITM (what the SAS defeats) | Relay / identity substitution (what this opens) |
|---|---|---|
| What the attacker does | Splices one exchange | Runs two independent, legitimate exchanges |
| Shared secrets | Differ across the two legs | Each leg's pair agrees perfectly |
| Diceware words | **Mismatch — caught** | **Match on every screen — nothing to catch** |
| Remaining defence | — | "Is the face and voice on this stream really Bob?" |

The protocol has nothing to detect because nothing was tampered with. The entire security of the contact entry collapses onto human recognition of a video stream — the exact check that this repo's own `#15` §1 documents as commercially defeated (Arup, $25M; Singapore, $499K; IC3 2025, 22,000+ AI-fraud complaints).

**In the shipped in-person flow this attack does not exist**, because Mallory would have to be physically present at 25 cm wearing Bob's face.

### D-04 · This is the attack that already blocked `#15`, aimed at a strictly softer target

`Presence Verification/SPEC.md` §6's **July 10, 2026 addendum** reclassified precisely this attack class from residual to blocking:

> a relay ("mafia fraud") attack, a category in challenge-response authentication generally considered unsolvable without distance-bounding (round-trip time-of-flight measurement between prover and verifier) — infeasible here because network jitter over an arbitrary video/audio call swamps any timing signal precise enough to bound distance.

Remote key exchange is the same attack against a weaker starting position. Presence Verification at least begins from a key already established at ≤ 25 cm; the relay only has to defeat a freshness claim about an existing relationship. Remote exchange has **no prior anchor at all** — the deepfake *is* the enrollment, and there is no earlier ceremony for a later check to fall back on.

If the July 10 reasoning is correct — and nothing here challenges it — it applies to this proposal *a fortiori*. Shipping remote exchange as a co-equal path while `#15` stays delayed would be inconsistent, and the inconsistency runs in the dangerous direction.

The same ruling from the other side: Expansion A's partial unblock on 2026-08-09 turned entirely on *"a relay attack requires a channel to relay across, and a co-located ceremony has none"* (`Master Feature & Expansion Analysis.md:720`). Remote exchange supplies the channel.

### D-05 · The larger loss is economic, not cryptographic — the attacker-scaling cap disappears

| | In person (shipped) | QR over video call |
|---|---|---|
| Wire MITM | Blocked (SAS) | Blocked (SAS) |
| Relay / identity substitution | **Physically impossible** | **Undetectable by the protocol** (D-03) |
| Attacker cost per victim | Travel + physical risk + in-person deception | One video call |
| Victims per attacker per day | ~1 | Unbounded, parallel, cross-jurisdiction |
| Attacker must be identifiable in person | Yes | No |

The bottom three rows matter more than the second. A per-contact weakening is a tier problem and can be labelled. **Removing the physical rate limit is a property change in the graph itself**, and it is the property the product's strongest positioning rests on: *"We don't scan your iris to prove you're human. You met them."* (`Feature Ideation — 2026-07-10 Community Demand Pass.md:109`). A graph that can be populated remotely, in parallel, at zero marginal cost is not a proof-of-personhood artifact, whatever the badge on any individual row says.

### D-06 · There is no provenance field today, so the weakening is silent and global

`Contact.Profile` (`Occulta/Data Models/Contact+Model.swift:48–110`) carries `encryptionScheme`, `visibleThroughDepth`, `globalTrusteeDepth`, `maxBundleVersion`, `deletionToken`, and the duress-origin stamp. **It carries no record of how the key arrived.** Every consumer of the contact graph therefore assumes, implicitly and without a check, that every stored key was established at ≤ 25 cm.

A remote path added without provenance does not create a weaker tier. It silently lowers the floor under everything already built on the graph:

| Dependent | What breaks |
|---|---|
| **Vault shard custody** | A remotely-added contact can be designated a trustee (`globalTrusteeDepth`). Social-engineer K remote adds against a K-of-N threshold and the vault is recoverable by the attacker. |
| **Payment Cards / `#26`** | The wedge rests on physical provenance; `Payment Cards/FINDINGS.md:297` already requires a remotely-arriving first card to announce *"never confirmed in person."* That copy has no field to read. |
| **Identity Challenge (shipped)** | Attests continued control of a key a deepfake may have enrolled. The signature stays valid; the anchor is gone. |
| **Presence Verification `#15`** | Anchored to the same key. Its relay analysis assumes a physically-established baseline. |
| **Org Identity Graph (Expansion A)** | Loses the one differentiator that survived the `#15` delay (D-04). |
| **Key-change detection** | *"because every key was established in person, any unsigned change is unambiguously anomalous"* (`Master Feature & Expansion Analysis.md:112`) stops being true. |
| **`README.md:15, 86–89`** | *"No one can impersonate you remotely"* becomes false as written. |

Two consequences for any implementation:

- Provenance must be added to `Contact.Profile` and **backfilled** for existing rows. A nil/absent value is itself a signal, the same invariant already documented for `visibleThroughDepth` and `globalTrusteeDepth` (*"nil is not a valid steady state"*, `forensic-trace-avoidance.md` S6).
- The tier must be a **hard gate in code**, not a badge. Sweep 4's own caveat is explicit: *"warning fatigue is the primary failure mode… never a one-time dialog."* Trustee eligibility and card signing are the two places where a warning is not sufficient (Q-04).

### D-07 · Post-quantum protection does not survive the video-QR channel

Payload sizes, ML-KEM-1024 (FIPS 203):

| Frame | Contents | Raw bytes | Base64 |
|---|---|---|---|
| Identity | P-256 key (65) + encapsulation key (1568) + nonce (16) | ~1649 | ~2200 chars |
| Ciphertext | ML-KEM ciphertext (1568) | 1568 | ~2091 chars |

Either frame forces a **version-40 QR — 177 × 177 modules**, at or near the capacity ceiling of `CIQRCodeGenerator` at its default correction level. `Presence Verification/SPEC.md` §8 caps its own QR frames at **≤ 200 B** for exactly this reason, and even at that size flags the risk: *"document the failure mode if the counterpart's webcam feed is too degraded to scan."*

A 177 × 177 module code, rendered on a laptop screen, captured by a webcam, and pushed through conferencing-grade video compression, will not scan reliably. The realistic outcomes are multi-frame chunking (fragile, slow, human-mediated across four round trips) or degradation to the classical P-256-only path, which the protocol already supports as a fallback (`Exchange+Manager.swift:508`).

The second outcome is the one to plan for, and it is perverse: **the contacts established over a recorded, provider-hosted video call would be exactly the contacts with no harvest-now-decrypt-later protection.**

### D-08 · A QR held up on a video call is a durable third-party artifact — forensic-cleanliness violation

This is where the "exposed to the public" instinct is correct, though not for cryptographic reasons.

`CLAUDE.md` states the invariant: *"We must be forensic trace clean. We should not be leaving traces that we are hiding something."* A QR code displayed on a video call lands in the conferencing provider's recording, transcript, and thumbnail pipeline — infrastructure the user does not control and cannot later purge. The artifact is durable, timestamped, attributable to both participants, and proves **that both parties use Occulta and paired on this date**.

That is the same objection Sweep 4 already raises against contact cards — *"a publicly posted card is a durable 'I use Occulta' artifact, in tension with forensic cleanliness"* — but strictly worse, because the card at least travels over a channel the user chooses, while a video call is recorded on someone else's server by default and often by policy.

For the app's stated personas (travellers, activists, journalists — `README.md:13–15`) this alone is disqualifying for the video-call framing specifically. It does not disqualify a remote SAS over a **voice** channel with no visual artifact, which is what Sweep 4 actually specifies.

### D-09 · The honest counterweight: in absolute terms this tier is not reckless

Stated so the recommendation is not read as stronger than it is.

A key exchanged remotely with someone you know well, whose face and voice you recognise, with a 64-bit SAS compared live, is **substantially stronger than the default in Signal, WhatsApp, or iMessage**, where the overwhelming majority of relationships are TOFU and never verified. Sweep 4 places it at **Confirmed — *"strong vs MITM, no meeting needed"*** for that reason, and that placement is defensible.

Against an opportunistic attacker it holds. Against a funded attacker running real-time synthesis it does not (D-03), and against a resourced attacker running the graph at scale it removes the rate limit entirely (D-05).

So the finding is not *"remote exchange is insecure."* It is: **remote exchange is insecure relative to this product's own claims, and relative to the specific features that were built on the physical anchor.** Those are the things it costs, and they are recoverable only by giving up the claims (a marketing decision) or gating the dependents (an engineering one).

### D-10 · It probably does not fix the adoption problem it is proposed for

C1 is *"zero value at install"*: the first moment of value requires a second person **with the app already installed**, an iPhone 11+, two permissions, ≤ 25 cm, inside a 30 s window — *"six multiplied conditional probabilities."*

Remote exchange removes one of those six. It leaves the binding one untouched: **the other person still needs to install the app.** It helps exactly the pairs who have both already installed and cannot meet — a real but narrow set, and one that skews toward users who were going to convert anyway.

The friction report's own ranking puts the leverage elsewhere: **contact cards** (component 1 of Sweep 4 — encrypted first message, zero round trips, *"the actual friction-killer"*) and C2's exchange failure modes, where *"every failed exchange loses two users in person."* The consumer memo's read is that the ceremony is the story rather than the obstacle, and that the fix is finding moments where proximity is already natural (`CONSUMER_OPENING_AND_CEREMONY.md` §1.2).

**Weighing a root-of-trust change against a growth gain, this one buys less growth than it appears to and costs more trust than it appears to.**

---

## Open Questions

### Q-01 · Is the project willing to hold a two-tier claim in its own marketing? — blocking, and a product decision

Everything else here is tractable engineering. This is not.

The current claims are unconditional: *"No one can impersonate you remotely"* (`README.md:15`), *"no remote takeover path,"* *"the only attack surface is physics."* A Confirmed rung makes all of them conditional on a per-contact tier, in every asset, permanently — App Store copy, HN/r/netsec posts, the wiki, the security analysis PDF.

`#15`'s addendum set the precedent for exactly this decision and answered it the strict way: **delay until either a real guarantee exists, or the claim is narrowed explicitly *before* shipping.** The same fork applies here, and answering it is a prerequisite for any protocol work, not a follow-up to it.

### Q-02 · Provenance field semantics under the duress model — unresolved

Every app-specific field on `Contact.Profile` is encrypted and carries depth semantics, and the three existing depth stamps use three *different* rules (ceiling, exact-match, floor) for well-argued reasons. A provenance field is a property of the key, not of visibility, so it may need neither — but that must be ruled, not assumed:

- Encrypted or plaintext? (Consistency argues encrypted; a uniform enum present on every row leaks little either way.)
- Does a contact created at a duress depth get provenance recorded truthfully? A coercer reading `verified` on a contact the operator never met in person is an inconsistency; a coercer reading `remote` on a decoy contact is a tell.
- Backfill value and migration (D-06). Mandatory, non-optional.

### Q-03 · Transport shape — does the QR path preserve the nonce commitment?

The shipped protocol commits each side's nonce in the discovery message **before** either identity key is visible (`Key+Manager.swift:1385`), which is what makes the SAS non-grindable. Any QR transport must preserve that ordering across a human-paced, four-frame, screen-to-camera channel where either party can stall arbitrarily and re-render.

Related trap, and the reason this must be settled before any UX work: **the SAS must not be shortened for webcam legibility.** `CONSUMER_OPENING_AND_CEREMONY.md` §5 correctly notes short SAS formats (emoji triad ~18–24 bits, Diceware Lite ~13 bits) are sound *under commitment* — but those were specified for the **in-person** casual rung, where physical presence is independently proven. Over a remote channel a short SAS is the difference between a defence and a decoration, and the pressure to trim it for a 177 × 177 QR (D-07) will be strong. **All 5 words, or nothing.**

### Q-04 · Hard block or loud warning for the security-critical dependents?

Vault trustee designation and payment-card signing are the two places where D-06's badge is insufficient. Hard block is the defensible default and costs a real capability (a remote-only contact can never be a trustee, which for a geographically distributed family is exactly when trustees are wanted). Recommend hard block for v1 and revisit with evidence — the reverse order is not recoverable, since shards already distributed cannot be un-distributed.

### Q-05 · Does this reopen the introductions/no-vouching line? — check before scoping

Sweep 4's item 4 (introductions by a verified mutual) is flagged as *"a product-owner call, not an engineering one"* and remains open (D1). The no-vouching invariant is settled for own-device keys (`Multi-Device Contacts/ROADMAP.md`, Design Session 3, *"Rejected: self-vouching device certs"*). A Confirmed rung is **not** vouching — no third party asserts anything — so this is adjacent, not the same question. Recorded so the two are not merged during scoping, in either direction.

---

## Recommendation

**Do not build the proposal as posed** — a co-equal remote path into the contact book, verified by Diceware over a video call. D-03 shows the Diceware check does not defend against the attack the remote channel enables; D-04 shows that attack is the one already ruled blocking; D-06 shows the cost lands on features that have no field to defend themselves with; and D-10 shows the growth it buys is narrower than the framing suggests.

**The shape that survives is already specified.** Sweep 4's **Confirmed** rung — *"SAS compared over a live call"* — is this idea with the two properties the proposal lacks: it is a labelled second-class tier rather than a second front door, and it sits inside a ladder whose invariants (persistent per-contact badge, never rendering as Verified, identical cipher suite at every rung) were written for exactly this hazard. Build that, gated on Q-01, or build nothing.

**Do the growth work that is not gated on a trust decision first.** Contact cards (Sweep 4 item 1) are unblocked today, rank higher in the friction report's own ordering, and cost nothing in claims.

> **Stale citation found while writing this, 2026-08-11.** `USER_ENGAGEMENT_FRICTION.md` C2 still reports a silent key-save failure at `ExchangeResult.swift:132–136` — *"the Confirm button's catch block is empty… the exchange appears to succeed but the contact has no key."* That file no longer exists and the defect is fixed: the save path now lives at `KeyExchange.swift:269–299`, sets `saveState = .failed` on throw, and renders a "Couldn't save key" state with a Retry button (`KeyExchange.swift:206–214`). C2's remaining sub-findings were not re-verified in this pass. **The friction report's line references were last re-verified 2026-07-12 and should not be cited without checking.**

**Drop the video-call framing regardless of the above** (D-08). If a remote rung ships, the SAS belongs on a voice channel that leaves no durable artifact on a third party's servers. The QR-over-video transport additionally cannot carry the PQ material (D-07), so it degrades precisely the contacts most likely to be recorded.

---

## Action items

**Before any protocol work:**

- **Answer Q-01 as a product decision.** Is the project willing to hold a conditional, per-contact security claim in all public copy, permanently? `#15`'s precedent says narrow the claim explicitly *before* shipping, or do not ship. Everything below is wasted if this answers no.
- Rule Q-02 (provenance field semantics under the duress model) with the same discipline applied to `visibleThroughDepth` and `globalTrusteeDepth`. Backfill is mandatory, not optional.
- Rule Q-04. Recommend hard block on trustee eligibility and card signing for v1 — shards already distributed cannot be recalled.

**If pursued:**

- Add provenance to `Contact.Profile` and enforce it at every dependent site in D-06's table **before** any remote path is reachable, not alongside it.
- Fix the SAS length at 5 words for the remote rung and record the reason (Q-03), so that the webcam-legibility pressure in D-07 cannot quietly erode it later.
- Specify the QR frame ordering against the nonce-commitment invariant (Q-03), including the stall/re-render cases a human-paced channel permits.
- Decide PQ handling for remote contacts explicitly (D-07): multi-frame chunking, or a stated, badged classical-only tier. Silent degradation is not an option.
- Update `README.md:15, 86–89` and the wiki in the same change that makes the path reachable — not after.

**Independently of this feature:**

- Unblock the adoption work that carries no trust cost: contact cards (Sweep 4 item 1).
- Update `USER_ENGAGEMENT_FRICTION.md` C2 — its silent-key-save-failure finding is fixed and its file reference is dead (see the Recommendation's stale-citation note). Re-verify the rest of C2 while there.
- Cross-reference this doc from `Master Feature & Expansion Analysis.md` §15's addendum and from `USER_ENGAGEMENT_FRICTION.md` Sweep 4, so the Confirmed rung is not re-derived a third time from scratch.

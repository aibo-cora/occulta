# Organizational Identity Graph — Auth Protocol Generalization: Design Findings

**Status:** Exploratory — no SPEC.md yet, not scoped for a release
**Context:** Design discussion, 2026-08-09. Extends Expansion A (Organizational Identity Graph, `Master Feature & Expansion Analysis.md` lines 668–698) from a market-positioning ruling into an actual protocol sketch, then asks whether that protocol can be *generalized* — used by any relying party without a bespoke per-org integration — the same decoupling MCP achieves for tool access and WebAuthn achieves for authenticators.

**Problem statement:** Expansion A's May 2026 ruling narrowed the addressable market to three thin segments (gov-adjacent orgs, small high-trust organizations, a premium add-on to existing passkey deployments) but never specified *how* an org's login backend would actually verify an Occulta identity — the integration mechanism was left as "an enterprise SDK," undesigned. Separately, the June 2026 addendum tied Expansion A's strongest wedge (helpdesk/wire-transfer verification) to Presence Verification (`#15`), which was itself delayed in July over an unresolved relay attack. This doc treats the two as separable: the base auth mechanism only needs Identity Challenge (shipped, v1.8.x) — it doesn't require live Presence Verification, so it isn't blocked by that delay.

---

## Confirmed / Verified

### D-01 · Base protocol: an org-membership attestation over already-shipped primitives, no new cryptography

- **Org root** is just an ordinary Occulta identity — the HR/IT admin's own SE key. No new primitive.
- **Membership attestation** is a new domain-prefixed signed artifact, `"occulta-org-membership-v1"`, following the same house pattern every other new signed-artifact addition in this doc set uses (Guardian Revocation Certs, Destruction Receipts, Payment Instructions — new prefix only, no `Version`/`Mode` case, old builds ignore the unknown field, per the `OccultaBundle` no-bump house rule). Contents: employee pubkey, org ID, role, timestamp, root's signature over all of it.
- **Auth flow** is structurally identical to `IDENTITY_CHALLENGE_PROTOCOL`, re-targeted at a server instead of another Occulta device: the backend issues a nonce; the app signs `(nonce, membership_attestation)` with the employee's SE key; the backend verifies the SE signature (liveness, nonce/replay freshness) and, separately, the org root's signature on the attestation (chains to a root pubkey the org pinned when it turned this on).
- **Revocation without a CRL:** attestations are short-TTL and require periodic re-signing by the root, pushed as an ordinary basket. Offboarding is simply "stop re-signing." No revocation-list service, no always-on infrastructure — matches the zero-server invariant every other feature in this repo holds to.

Every piece here reuses a shipped mechanism (SE challenge-response = Identity Challenge, domain-separated signing = existing convention, basket delivery = existing transport). Nothing here requires new cryptography.

> **Superseded by Design Session 3 (2026-08-09).** The primitive-reuse argument holds and carries forward unchanged. What does not survive is the **standing-credential model** — a persistent membership attestation kept alive by periodic root re-signing. That model is the origin of F-01, F-02, F-05, F-06, and F-07, and its "basket delivery = existing transport" assumption is contradicted by the manual share-sheet reality (F-02). Replaced by D-09's one-shot, event-bound authorization artifact.

### D-02 · MCP's own generalization pattern doesn't transfer directly, but names the right shape to imitate

MCP's authorization spec is OAuth 2.1-based: a client obtains a scoped, audience-bound bearer token from an authorization server and presents it to a resource server. That's a **delegation** protocol — a client acting on a resource server on a user's behalf — a different layer from the **authentication** problem D-01 solves (proving a specific human is who they claim to be). The two don't compete; if anything, D-01 sits *upstream* of an MCP-style flow, supplying whatever authenticates the human before a token gets minted.

One transferable idea, not a design requirement: MCP's push toward sender-constrained tokens (DPoP — binding a bearer token to proof of possession of a key, because a bare bearer token is trivially replayable once stolen) is a problem D-01 never has in the first place. Every SE signature is inherently possession-bound; there's no bearer-token replay surface to retrofit against. Worth stating as an inherited property, not something to build.

### D-03 · Three layers for exposing D-01 generally, ranked by how much of the unique asset survives

**Layer 1 — WebAuthn/FIDO2 (`ASCredentialProviderExtension`).** Already scoped elsewhere as the Serverless Passkey Provider (`#20`, Master Feature doc). Universal on day one — every WebAuthn relying party accepts it with zero bespoke integration. Cost: WebAuthn's data model has no field for D-01's "vouched for, by whom, when" — verification reduces to key possession only, so Occulta becomes parity with 1Password/iCloud Keychain passkeys (ahead on one point — no cloud key sync — but the vouching graph itself is discarded, not exposed).

**Layer 2 — Portable Verifiable Credential / SD-JWT, Occulta as *issuer*.** The inverse of Expansion H's role (`Master Feature & Expansion Analysis.md` §H), which scopes Occulta as a *consumer* of externally-issued credentials. Here, D-01's membership attestation is re-encoded as a standard-format credential (W3C VC / SD-JWT) instead of an Occulta-proprietary blob. Any generic VC verifier — an increasingly commodity category per Expansion H's own July 2026 addendum, riding the EU Digital Identity Wallet / US mDL rollout — can check it with no Occulta-specific integration. This is the direct structural analog of MCP's client/server decoupling, applied to identity instead of tools, and the only layer that generalizes the *unique* asset (the physical-vouching graph) rather than discarding it.

**Layer 3 — OIDC identity provider ("Sign in with Occulta").** Maximal drop-in compatibility for existing enterprise SSO stacks, since nearly everything already speaks generic OIDC. Requires an always-on authorization server — even if self-hosted per-org rather than Occulta-run — which is a genuine departure from the zero-server invariant every other feature in this repo holds to. Not a footnote; a decision to make deliberately, not by default.

---

## Open Questions (Unresolved)

### Q-01 · Delegated vouching at org scale conflicts with the standing `no-self-vouching-device-trust` principle — blocking

None of D-01–D-03 solves how an org onboards past the handful of people the root can physically meet. Real orgs need delegation — a department head vouches for their own new hires without looping in the root each time — which is structurally the same mechanism [Multi-Device Contacts/FINDINGS.md](../Multi-Device%20Contacts/FINDINGS.md) (Design Session 3) already rejected for a single person's *second device*: a signature from an already-trusted key extending trust to a new key, with no fresh physical ceremony against the actual verifying party. The standing principle recorded there reads directly onto this case, just at a larger blast radius — a coerced or phished department head compromises a whole team's worth of trust, not one person's contact graph.

Candidate mitigations, none yet evaluated in depth:
- K-of-2 delegation — require two independent vouching signers per new member, not one.
- Capped delegation depth / fan-out per delegate.
- Time-boxed, explicitly revocable delegation grants issued by the root.

**This is the load-bearing open question for the whole feature.** None of D-03's three layers are worth building against an org-scale trust model until this has an answer — the same gating discipline Multi-Device Contacts applied to its own self-vouching question (Design Sessions 3–4) before any implementation plan was written.

> **Re-ranked, Design Session 2 (2026-08-09):** still blocking, but no longer the question to answer *first*. Three cheaper questions (F-01 root-key continuity, F-02 re-signing delivery, F-06 unlinkability) can each kill the feature at lower cost than designing a delegation model. F-03 also reframes the threat here: mundane process decay, not only coercion.
>
> **Dissolved, Design Session 3 (2026-08-09).** D-06 refuses to build delegation at all — depth-1 graph, scaled by widening the root roster and narrowing the enrolled population rather than by vouching downward. The candidate mitigations above (K-of-2, depth caps, time-boxed grants) need no evaluation because no delegation mechanism exists to constrain. Not answered — removed from the design.

### Q-02 · Which VC/DID method, if Layer 2 is pursued — not yet scoped

D-03's Layer 2 references "W3C VC / SD-JWT" at the same level of generality Expansion H already used for the consumer side, but doesn't pick a DID method, a key-binding scheme (`did:key` bound directly to the SE P-256 key? a custom `did:occulta` method?), or a credential schema for the membership-attestation claim type. Should be scoped alongside Expansion H's already-active scoping pass (same standards, opposite role — issuer vs. holder) rather than independently.

### Q-03 · Whether Layer 3 (OIDC IdP) is worth the zero-server departure at all — not yet decided

Nobody has weighed whether any concrete relying party actually requires OIDC specifically (versus accepting a VC verifier per Q-02), or whether this solves a problem that doesn't exist yet. Recommend leaving unscoped until a real relying-party requirement forces the question, rather than building an authorization server speculatively.

> **Superseded by Design Session 2 (2026-08-09) — should be Rejected, not left open.** "Unscoped pending a forcing requirement" understates the conflict: an OIDC authorization server *is* central login-event visibility, which the privacy mandate forbids outright. Leaving the door ajar invites a future pass to walk through it, because the forcing requirement will be the compliance audit trail the Enterprise Reality Check already names as a blocker. See F-08.

---

## Rejected

### Rejected (by precedent, not re-litigated here): a bespoke Occulta-only protocol with no generalization layer

The original Expansion A framing — a per-org bespoke challenge-response, no shared format — was the assumed default entering this discussion. Superseded once the MCP comparison (D-02) made the generalization gap explicit: a bespoke-only protocol requires every relying party to hand-integrate Occulta specifically, exactly the N×M problem OAuth, WebAuthn, and MCP all exist to avoid. Not reopened here.

---

## Recommendation

Layer 2 (D-03) is the one that actually answers "how do we generalize Occulta's unique auth capability" — it's the direct structural analog of MCP's decoupling, and the only layer that exposes the vouching graph rather than discarding it. Layer 1 is worth shipping regardless of this doc's outcome, since it's already scoped elsewhere (`#20`) and nearly free. Layer 3 should stay unscoped (Q-03) absent a concrete forcing requirement.

**None of this should move to a SPEC.md until Q-01 has an answer** — mirroring the exact gating discipline Multi-Device Contacts applied to its own self-vouching question before writing an implementation plan.

> **Revised by Design Session 2 (2026-08-09).** Layer 1 stands. Layer 3 moves to Rejected (Q-03 annotation, F-08). Layer 2's claim to "expose the vouching graph rather than discard it" does not survive review — see F-00 — and it now carries three gating questions of its own ahead of Q-01. The gating discipline itself is unchanged and reaffirmed.

---

## Action items

- Scope Q-01 (delegated vouching model) as its own design pass — the blocking dependency for everything else in this doc.
- Cross-reference Expansion H's VC/SD-JWT scoping work once active; Q-02 should ride alongside it rather than pick a DID method independently.
- No implementation-plan work until Q-01 resolves.

*(Superseded ordering — see Design Session 2's action items below.)*

---

## Design Session 2 — Security, Privacy & Adoption Review (2026-08-09)

**Question raised:** an honest review of D-01–D-03 and the Layer 2 recommendation across adoption, user friction, security, and privacy — specifically, whether any of this stays inside Occulta's privacy mandate (zero server, no central visibility, no metadata, forensic-trace-clean, physical proximity as the only trust-granting mechanism).

**Summary judgment:** D-01's protocol sketch is sound and genuinely cheap — it reuses shipped primitives correctly, and the no-SPEC-until-Q-01 gating is the right call. But the body above analyzes this as a *protocol design* problem, and the binding constraints are operational. Two of them are blocking, cheaper to answer than Q-01, and unmentioned above.

### F-00 · Layer 2's central claim doesn't hold — the moat evaporates at the generalization boundary

D-03 states Layer 2 is "the only layer that generalizes the *unique* asset (the physical-vouching graph) rather than discarding it." It isn't. A generic VC verifier checks an issuer signature against a trusted-issuer list. Whether that issuer arrived at the claim via a UWB ceremony or a button in an HR system is invisible to it — the credential reduces to "org root asserts membership," which is precisely what every existing IdP asserts. Generalizing the *envelope* is not the same as generalizing the asset.

Underneath that sits a harder fact the body never states: **physical provenance is not remotely verifiable.** An SE signature proves key possession. Nothing in D-01 proves a proximity ceremony ever happened — a modified client can mint an identical attestation. The only mechanism that would close it is Apple App Attest / DeviceCheck, which inserts Apple into the verification path and forfeits the no-intermediary property that Expansion H's own ruling identified as Occulta's genuine differentiator (`Master Feature & Expansion Analysis.md` §H: "Apple knows when you presented your ID, to whom, and where").

So the property the May 2026 ruling called uniquely Occulta's — "did our CTO personally verify this contractor?" — degrades at the trust boundary into "the org root says so," self-attested and unfalsifiable by the relying party. That is the exact boundary this doc set out to cross.

### Findings, ranked

**[BLOCKING] F-01 · Root key continuity is unaddressed — a bigger blocker than Q-01, and cheaper to answer.** D-01 makes the org root "just an ordinary Occulta identity — the HR/IT admin's own SE key." That key is non-exportable and device-bound by construction. Admin loses the phone → nothing can be re-signed → every attestation expires at TTL → the whole org is locked out with no recovery path. Admin leaves the company → root rotation → every attestation reissued and every relying party re-pins. No K-of-N root, no escrow, no rotation story is specified. Mechanisms that plausibly apply already exist and are not referenced: Guardian Revocation Certificates (`#19`) and the shipped SSS trustee custody (`#16`). Also unspecified: how the root pubkey is pinned by a relying party in the first place, and what a re-pin costs operationally.

**[BLOCKING] F-02 · Revocation-by-TTL collides with the transport reality, and removes emergency revocation entirely.** D-01's "no CRL — attestations are short-TTL and re-signed periodically, pushed as an ordinary basket" assumes a delivery channel that does not exist. [Multi-Device Contacts/FINDINGS.md](../Multi-Device%20Contacts/FINDINGS.md) Design Session 10 confirmed against code (2026-07-10) that there is **no automatic delivery channel post-pairing**: `Exchange+Manager.swift`'s `MCSession` covers only the initial UWB ceremony, and every subsequent bundle goes through `ActivityView.swift`'s `UIActivityViewController` — a manual, user-triggered share sheet, no persistent connection, no push. "The root periodically re-signs and pushes to every employee" therefore means the admin manually share-sheeting N attestations every TTL period. At 200 employees on a 7-day TTL that is 200 manual sends per week. (Whether the root's SE signing can be batched under one biometric prompt, or costs one prompt per attestation, is not established — worth checking, but it doesn't change the send-side arithmetic.)

Lengthening the TTL trades that for offboarding latency, which is directly compliance-relevant: a terminated employee holds valid credentials for the full window. Either way, the design has **no emergency revocation** — there is no way to invalidate before expiry, which is exactly what an org needs after a for-cause termination or a detected device compromise. A CRL is the mechanism that solves this, and it was rejected on architectural-purity grounds. This is the one place in the design where the zero-server invariant actively degrades the security outcome rather than improving it; it deserves to be named as a real trade rather than presented as a clean win.

**[HIGH] F-03 · At org scale the vouching graph collapses into hub-and-spoke.** Q-01 frames delegation as a coercion problem (a phished or coerced department head). The likelier failure is mundane: the ceremony becomes a step in orientation paperwork, executed by whoever staffs orientation. The graph then faithfully records "the onboarding coordinator vouched for everyone" — hub-and-spoke with extra physical friction, and none of the provenance value the feature exists to provide. K-of-2 delegation does not help when both signers are following the same HR checklist. Note also that Q-01's analogy to Multi-Device is *weaker* than stated: there, the vouched-for key belonged to a person the recipient had already met; here a delegate vouches for a stranger.

**[HIGH] F-04 · Remote onboarding exclusion and Q-01 are one constraint, not two.** The May 2026 ruling already conceded the point against passkeys ("we can onboard 10,000 remote employees with zero physical meetings"). Q-01's delegation model is the workaround for that exclusion, and it is the workaround precisely because it reintroduces the trust hole. The friction section and the security section of any future pass are describing the same wall from opposite sides; they should be resolved together.

**[MEDIUM] F-05 · Device loss means no login until the employee physically reaches HR.** There is no device continuity by design ([Multi-Device Contacts/FINDINGS.md](../Multi-Device%20Contacts/FINDINGS.md) Design Session 5). Every org runs a remote helpdesk recovery path; Occulta structurally cannot offer one. The irony is load-bearing: "helpdesk recovery *is* the attack" was this expansion's own June wedge, so the honest answer here is "no recovery" — which no org will accept as a login credential. Related unaddressed question: personal device or corporate device? Personal means an employee's private contact graph co-resides with a corporate credential the org cannot manage; corporate means MDM deployment, which the Enterprise Reality Check already lists as absent.

### Privacy mandate assessment

**Layer 1 — inside the mandate.** Per-RP SE keys, no server, no cross-RP correlation, no new artifact at rest beyond what `#20` already scopes. Clean.

**Layer 2 — two conflicts, neither named in the body above.**

**F-06 · [BLOCKING for Layer 2] Linkability.** A membership credential presented to multiple relying parties is a correlation handle across verifiers — the precise harm Expansion H's ruling praised Occulta for avoiding. Plain SD-JWT does not fix this: the issuer signature plus the holder key binding are stable across presentations. Unlinkable presentation requires batch-issued single-use credentials or BBS+-style proofs, and Expansion H explicitly ruled out building ZK primitives ("Do not build ZK primitives from scratch"). As sketched, Layer 2 ships a cross-verifier tracking credential inside a product positioned on the opposite property. This must be resolved before Q-02 picks a DID method, not after — it constrains the choice.

**F-07 · Forensic trace.** A signed org-membership blob resident on a personal phone is affiliation-in-a-file: discoverable on seizure, and self-describing. The stated target segments are gov-adjacent orgs, investigative journalism, and legal partnerships — populations for whom "this device proves a relationship with Org X" is the harm the duress cluster exists to prevent. Any org credential at rest needs deniable-partition handling (`#6`) or an equivalent, or the feature contradicts the mandate for exactly its own intended users. Nothing in D-01–D-03 addresses storage at rest.

**F-08 · Layer 3 is a mandate violation, not a trade-off to weigh.** An OIDC authorization server observes every authentication event: which employee, which relying party, when. That is central login-event visibility and a retained metadata trail — the thing the mandate forbids — and self-hosting it per-org changes who operates it, not what Occulta would be shipping. Worth naming *why* it stays tempting: the Enterprise Reality Check identifies "zero server means zero audit trail" as a compliance blocker in most regulated industries, and Layer 3 is the component that would resolve it. That makes it the most likely thing for a future pass to adopt quietly under commercial pressure. Record it as Rejected with the conflict stated, rather than as unscoped (Q-03 annotated accordingly).

### Adoption

**The August 9 addendum's separability claim is technically correct and commercially hollow.** The base protocol genuinely does not depend on `#15` — that part holds. But what made the enterprise story compelling was the *presence* claim ("this human is here, now"), not the *membership* claim ("this key belongs to an employee"). Membership-only is what Entra plus passkeys already ship at scale. The half that survives the `#15` delay is the half carrying no differentiation.

**Layer-vs-buyer mismatch.** Of the May ruling's three segments, only (3) — a premium add-on to existing passkey deployments — is realistic near-term. What segment (3) would actually deploy is **Layer 1**, which D-03 itself concedes discards the vouching graph. Layer 2 is recommended without a single named relying party that wants it. Its headline benefit ("no bespoke integration, generic verifiers are commoditizing") is a forecast, not a present fact: Expansion H's own build gate is issuer availability at a 2–3 year horizon, so at the moment Occulta would build Layer 2, the commodity verifier ecosystem it depends on does not yet exist.

**Nothing here changes the Enterprise Reality Check's conclusion.** That section already establishes the gating problems are certification, MDM, central administration, audit logging, and sales — not protocol design. This doc improves the protocol answer to a question that was not the blocker.

### Corrections to the body above

- **D-01's `OccultaBundle` no-bump citation is a category slip.** The compatibility argument ("old builds ignore the unknown field") governs Occulta-to-Occulta bundle parsing. The consumer of a membership attestation is a server-side verifier, versioned by whoever wrote it and upgraded on its own schedule. The house rule doesn't apply, and citing it indicates the design is still reasoning app-to-app for a feature that is app-to-server. Versioning and verifier-compatibility need their own answer.
- **D-01's zero-server framing needs a boundary line.** "No revocation-list service, no always-on infrastructure — matches the zero-server invariant" is true of the *revocation* mechanism specifically. The relying party in this design necessarily maintains state: nonce issuance, a replay cache, the pinned root, and a TTL clock. That is a server, it sits outside Occulta's trust boundary, and it is not a mandate violation — but the surrounding rhetoric blurs it, and a later reader could over-generalize.
- **D-02's DPoP observation stands and is worth keeping.** Sender-constrained-by-construction is a real inherited property, correctly scoped as an observation rather than a build item.

### Recommendation (this session)

1. **Ship Layer 1 (`#20`) on its own merits**, and state plainly in its positioning that it carries no vouching graph. It is the only layer with an identified buyer and it is unambiguously inside the mandate.
2. **Move Layer 3 to Rejected** with F-08's conflict recorded, rather than leaving it open pending a forcing requirement.
3. **Re-rank the gating questions ahead of Q-01.** F-01 (root continuity), F-02 (re-signing delivery over a manual-share-sheet transport), and F-06 (unlinkability) are each cheaper to answer than designing a delegation model, and each can independently end the feature. Q-01 remains blocking; it is no longer first.
4. **Add a deniability requirement (F-07)** for any org credential at rest before any SPEC.md work begins.
5. **Do not treat F-00 as fatal to the doc, but do stop claiming Layer 2 exposes the vouching graph.** What Layer 2 actually offers is a standards-shaped envelope with better integration economics — a real but much smaller claim, and one that should be evaluated against that smaller claim.

### Action items

- Re-order the body's gating: scope F-01, F-02, and F-06 as a single short feasibility pass *before* the Q-01 delegation design pass.
- Q-03: annotate as Rejected per F-08 (done, same date).
- Q-02: fold F-06's unlinkability constraint in as an input to the DID-method/credential-format choice, not a follow-on — it narrows the option space.
- Recommendation section: annotate F-00's correction so the Layer 2 claim isn't carried forward verbatim (done, same date).
- Master doc Expansion A: the August 9 addendum should note that the separable base protocol is also the non-differentiating half (Adoption above) — currently reads more favorably than this review supports.
- No implementation-plan work, unchanged.

---

## Design Session 3 — Alternative Architecture: Occulta as Enrollment Authority, Not Credential (2026-08-09)

**Question raised:** given Design Session 2's findings, how *would* an auth-systems designer build this for an org environment — not a critique pass, a counter-proposal.

**Thesis:** every blocking finding in Session 2 — F-01 (root continuity), F-02 (TTL re-signing over a manual transport), F-05 (device-loss lockout), F-06 (linkability), F-07 (forensic trace) — descends from a single decision in D-01: making Occulta a **standing credential**. Standing credentials must be always-available, cheaply revocable, and recoverable. Occulta is structurally bad at all three, and no protocol work fixes that. Invert the role and the findings stop being problems to solve; they stop existing.

### D-04 · Occulta is the enrollment and recovery authority; the daily credential is somebody else's

Enterprise identity's weak link is no longer the credential — passkeys/FIDO2 solved that, and D-03's Layer 1 concedes parity there. The attack moved upstream to **enrollment and recovery**: Scattered Spider does not phish passwords, it calls the helpdesk. That is the pattern the June 2026 addendum correctly identified as this expansion's wedge.

Lifecycle events are *rare, scheduled, high-value, and friction-tolerant*, which is precisely Occulta's shape — and the inverse of a daily login's requirements.

**The design:** the employee's daily credential stays whatever the org already runs — Entra/Okta passkeys, YubiKeys, or `#20` if they choose it. Occulta never sits in the login path. It gates exactly four events:

1. Initial credential enrollment (bind the FIDO2 registration to a physical ceremony)
2. Credential recovery / MFA reset
3. Adding a device
4. Step-up authorization for a small set of irreversible actions (wire approval, production root access)

**Note this decouples the feature from `#20` entirely.** The design works for an org that has never installed an Occulta credential provider and never will. That widens the addressable set well beyond anything D-03's three layers could reach, and removes a dependency the body above treated as foundational.

### D-05 · Root is a K-of-N pinned roster, never one admin's SE key

Closes F-01. The org root is a pinned roster of N admin identities — HR lead, IT lead, CISO, one device that lives in a safe — and an attestation requires K signatures over the payload. **Not Shamir**: K independent SE signatures the verifier checks against K pinned public keys. No new primitive, no secret sharing, no reconstruction.

Roster rotation requires K signatures from the *current* roster. Initial pinning at the relying party is out-of-band at deployment — trusted setup, and it should be labeled that plainly rather than dressed up as something stronger.

This also puts abuse containment where the blast radius actually is: no single compromised or coerced admin can enroll anyone.

> **Scope corrected by Design Session 4 (2026-08-09) — D-11.** The roster itself stands as designed. What does not: applying K-of-N to *every* attestation. That conflates roster changes (org-wide blast radius, K-of-N warranted) with individual enrollment or recovery (one-account blast radius, 1-of-N sufficient). Over-applying the threshold multiplies scheduling friction without proportionate security gain, and a control that gets routed around provides none. See D-11 for the per-event-class thresholds.

### D-06 · Flat graph, scoped population — Q-01 is dissolved, not solved

**Refuse to build delegation.** Depth-1 only: every enrollment ceremony involves a root-roster holder, physically. No transitive vouching, no delegation depth or fan-out caps, no K-of-2 mitigations to evaluate. Q-01's entire question space disappears rather than being answered.

Scaling comes from two moves, neither of which is delegation:

- **Widen the roster.** Regional IT leads *are* root-roster members, not delegates vouched for by a root.
- **Narrow the population.** Do not enroll headcount — enroll the accounts that matter: the ~50 with production access, the ~12 who can move money, the executives targeted by deepfake fraud. This is the same scoping the May 2026 ruling already arrived at commercially (segment 3, "premium complement for the highest-privilege roles"), now load-bearing architecturally.

Once enrollment is scoped to a high-privilege subset, the flat graph is sufficient by construction. F-03's hub-and-spoke collapse also stops mattering: the claim being sold is no longer "the CTO personally vetted this contractor" (undeliverable per F-00) but "this event required physical presence, which a remote attacker cannot fabricate" — weaker, honest, and sufficient to defeat the documented attacks.

### D-07 · Co-location removes the relay channel that blocked `#15`

The August 9 addendum argued separability from Presence Verification on the grounds that membership doesn't require presence. The stronger and more useful argument: **a relay attack requires a channel to relay across, and a co-located ceremony has none.** Employee and root-roster holder are in the same room at ≤25 cm over UWB. There is no remote leg for an attacker to occupy — which is the entire mechanism of the mafia-fraud-class attack that downgraded `#15` (SPEC.md §6, July 10 2026 addendum).

**Honest scoping that follows:** this design makes in-person the *only* reset path and makes that path cryptographic. If an org's policy permits remote reset, it needs `#15` and remains blocked. If policy requires physical appearance — which many high-security orgs already mandate, and whose standing complaint is that "someone showed a badge to a helpdesk tech" is unverifiable — it ships today.

Narrower than the June wedge. Real, and not blocked.

### D-08 · Integration is an admin-workflow verifier hook — not a VC, not an IdP

Drop D-03's Layer 2 for now (F-06 linkability, plus the commodity-verifier ecosystem is a 2–3 year forecast per Expansion H's own gate) and Layer 3 permanently (F-08).

The integration point is the **administrative/lifecycle workflow surface**, not the login surface. Major IdPs expose hooks intended for exactly this class of gate (Okta inline hooks/workflows, Entra custom authentication extensions and governance workflows — capability shape confirmed at design level, specific API fit not yet verified).

The verification question becomes local and genuinely answerable: *did K of the root keys we pinned sign an approval for this specific request ID, within the last few minutes, alongside the employee's own SE signature?* No generic verifier is asked to interpret a vouching graph — F-00's unsolvable problem — because the trust is local to the org that did the pinning, which is where it actually lives.

### D-09 · Event-bound payload and explicit consent

Payload: domain prefix (`"occulta-org-authz-v1"` or similar, per house convention), the RP-supplied request ID/nonce, a **human-readable action string** ("reset MFA for account X", "approve wire $Z to account W"), timestamp, employee public key, K root signatures, and the employee's own SE signature over all of the above. Both sides sign: the employee proves possession, the roster proves the ceremony was authorized.

The approval sheet must state exactly what is being authorized — the precise gap `#15`'s spec flagged in itself ("the responder's approval sheet does not state what is being attested") — and blind signing is refused, the same display-or-decline policy Expansion I already adopted.

One-shot by construction: bound to one request ID, consumed within minutes, worthless afterward. This is what makes F-02 disappear — there is no standing artifact to keep alive, so there is nothing to re-sign, nothing to expire, and nothing to revoke.

### D-10 · The audit trail belongs to the relying party — and gets better

F-08 identified the compliance audit gap as the thing that makes an OIDC IdP perpetually tempting. This design dissolves the temptation instead of yielding to it: **the RP keeps its own log, exactly as it already does, and those entries now carry signatures instead of a technician's assertion that a badge was checked.**

Strictly better audit than most orgs have for these specific events, with Occulta operating nothing — no console, no MDM story, no server, no second product. Directly addresses the Enterprise Reality Check's "zero server means zero audit trail" blocker without violating the mandate.

### What this resolves from Design Session 2

| Finding | Status under this design |
|---|---|
| F-01 root continuity | Closed by D-05 (K-of-N roster + roster rotation) |
| F-02 TTL re-signing / no emergency revocation | Dissolved by D-09 — no standing artifact exists to revoke or refresh |
| F-03 hub-and-spoke collapse | Defanged by D-06 — the claim sold no longer depends on graph provenance |
| F-04 remote onboarding excluded | Accepted and scoped, not solved (D-06/D-07) — in-person is the product |
| F-05 device loss = lockout | Dissolved — no daily dependency; lost phone means re-enroll in person, which is the existing process anyway |
| F-06 linkability | Largely dissolved by D-09 — nonce-bound per-event signatures are not reusable correlation handles |
| F-07 forensic trace | Largely dissolved — generate at use, do not persist; deniable-partition handling (`#6`) still recommended for at-risk segments |
| F-08 Layer 3 mandate violation | Avoided by D-08/D-10 |
| Q-01 delegated vouching | Dissolved by D-06 — no delegation is built |

### Rejected in this design

OIDC IdP (F-08). VC/SD-JWT issuer, for now (F-06 plus ecosystem timing). Standing membership attestations with TTL re-signing (D-01's model). Delegation in any form. Any admin console, MDM integration, or Occulta-operated audit service.

### Residual — disclosed, not solved

- **Physical presence proves presence, not identity.** The ceremony binds a key to a body in a room. Whether that body is who HR believes it to be still rests on the org's existing identity proofing at that moment. This is F-00's residue; it does not go away and must not be claimed away.
- **A coerced or malicious roster member** can enroll an attacker. K-of-N raises cost; it does not eliminate the path. The duress cluster's own threat model applies to roster devices.
- **Scale ceiling is real** — stated as a scoping rule (D-06), not a limitation to engineer around.
- **No certification.** FIPS/FedRAMP remain absent, so the May ruling's segment 1 stays closed regardless of this design.
- **Still not an enterprise sales product.** This is adopted bottom-up by a security-conscious org for its crown-jewel accounts. Consistent with the Enterprise Reality Check, not an escape from it.
- **Unverified:** the specific Okta/Entra hook APIs in D-08, and whether root-roster K-of-N signing has an acceptable admin UX (one biometric prompt per signer per event — fine at this event volume, but unmeasured).

### Recommendation

Treat D-04–D-10 as the working architecture for Expansion A and retire D-01's standing-credential model. The honest summary of the trade: this **gives up** the "cryptographic proof of who vouched for whom" story, which F-00 established is not deliverable across a trust boundary, and **keeps** "a remote attacker cannot fabricate this event," which is deliverable and is what the documented attacks actually exploit.

Gating discipline is unchanged — no SPEC.md yet. But the gate is no longer Q-01 (dissolved); it is D-08's integration-surface verification and D-05's admin-UX check, both cheap.

### Action items

- Verify D-08's hook surface against current Okta inline-hook and Entra custom-authentication-extension capabilities — this is now the primary feasibility gate.
- Prototype D-05's K-of-N roster ceremony UX to confirm admin-side cost at realistic event volume.
- Body above: annotate D-01 as superseded by D-04/D-09 (done, same date) and Q-01 as dissolved by D-06 (done, same date).
- Master doc Expansion A: fold in D-07's sharper separability argument — co-location removes the relay channel — which is a stronger claim than the August 9 addendum currently makes, and pairs with Session 2's correction that the separable half was non-differentiating.
- Expansion H cross-reference (Q-02) is no longer on the critical path under this design; leave it with H rather than tracking it here.
- No implementation-plan work until D-08 verifies.

---

## Design Session 4 — Friction Audit: K-of-N Scope, Event Frequency, Degraded Mode (2026-08-09)

**Question raised:** is a physical K-of-N ceremony not an enormous amount of friction to reset a credential?

**Answer: yes, and Session 3 applied more of it than its own security model requires.** One genuine design error (D-11), one wrong assumption underneath the friction estimate (D-12), one property of D-06 that was doing uncredited work (D-13), and one operational failure mode neither Session 3 nor the review caught (Q-04).

### D-11 · K-of-N governs the roster, not every event — corrects D-05

D-05 introduced the K-of-N pinned roster to close F-01 (root continuity): no single admin's lost or coerced device can brick the org or unilaterally enroll an attacker. That reasoning holds **for its actual scope**. D-05 then let K-of-N govern every attestation, which silently conflates events with very different blast radii:

| Event | Threshold | Rationale |
|---|---|---|
| Roster change (add/remove a roster member) | **K-of-N** | Blast radius is the whole org; this is the case F-01 exists for |
| Individual enrollment or recovery | **1-of-N** | Blast radius is one account |
| Top-tier step-up (wire above policy threshold, production root) | **K-of-N** | By org policy, not protocol requirement |

Requiring two roster holders physically present for a routine recovery buys very little over one and multiplies scheduling cost by exactly the amount that makes an org route around the control. **A control that gets bypassed provides no security** — over-applying the threshold is a security regression, not conservative design.

Verification impact is small: the relying party's check becomes "≥1 roster signature for enrollment/recovery, ≥K for roster updates and policy-flagged step-ups." A threshold parameter on the same verification path (D-08), not a second mechanism.

### D-12 · This is not a password reset — the frequency assumption underneath the friction estimate was wrong

Reasoning about friction from helpdesk password-reset volume anchors on the wrong world. Under D-04 the daily credential is a passkey; the recovery event is not "I forgot my password" but "I lost the device holding my credential."

Password-reset tickets are voluminous *because passwords are forgettable* — a driver absent from a passkey-first stack. Device loss runs on a multi-year cadence. For a population scoped per D-06, expected ceremony volume is single digits per year, not the ticket-queue figures the word "reset" evokes.

Stated explicitly because the friction objection is the first thing any pilot org will raise, and answering it on the wrong frequency model concedes an argument that doesn't need conceding.

### D-13 · Population scoping is a friction control, not only an architectural one — refines D-06

D-06 narrows enrollment to high-privilege accounts to keep the graph depth-1 and dissolve Q-01. It does a second job not credited there: **it is also what makes the friction survivable.**

At ~12 accounts that can move money and ~50 with production access, a handful of in-person events per year is negligible against the downside — the MGM helpdesk-reset incident ran to roughly $100M in reported cost. At full headcount the identical mechanism is indefensible. Same design, opposite verdict, determined entirely by scope. Scope is therefore a **load-bearing product parameter**, presented to a pilot org as a requirement rather than a preference.

**Adjacent claim, flagged as unvalidated:** many orgs reportedly already require in-person reset for privileged accounts, where the standing complaint is that "a technician checked a badge" is unverifiable and doesn't survive audit. If true, this design adds *provenance to friction already being paid* rather than adding friction — which would substantially change the pitch. It is convenient enough to be worth distrusting; validate against a real org before it enters any positioning material.

### Q-04 · Degraded mode when geography doesn't cooperate — open, must be answered before a pilot

No roster holder is reachable: the account holder is travelling, remote, or between offices when the device is lost. As designed, recovery cannot complete until physical co-location happens — potentially a week or more of lost privileged access.

Two candidate answers, neither evaluated:

- **Time-boxed lower-assurance credential** with reduced privileges, converting to full assurance at the next in-person opportunity. This reintroduces a remote issuance path — precisely what this design exists to remove — so it requires its own threat analysis before being taken seriously, not a convenience carve-out.
- **Privileged access stays suspended** until in-person recovery. Defensible for this population ("no production root from a hotel on a borrowed laptop" is the control working as intended), and free to implement — but only if stated as deliberate policy up front.

**Recommendation:** default to suspension, state it during onboarding, and treat any lower-assurance path as a separate design pass carrying its own threat model. Left open rather than decided because it is a policy question for a pilot org, not a protocol question. It must be answered *before* a pilot, not discovered by a stranded engineer mid-incident — this is the kind of gap that kills a pilot when it surfaces late.

### Action items

- D-05: annotate the K-of-N scope correction (done, same date).
- D-08 verification: include the per-event-class threshold (≥1 vs ≥K) in the hook-surface check — it affects what the integration must express.
- Validate D-13's in-person-reset claim against a real org before it enters positioning.
- Q-04 must be answered before any pilot commitment; default to suspension absent a reason to do otherwise.

---

## Design Session 5 — User Flows, Transport Reconsidered, Competitive Read (2026-08-09)

**Question raised:** what does the end-user flow actually look like, what alternatives exist, and who is better at defending against social engineering today?

Writing the flows out concretely — they had not been recorded anywhere — surfaced two findings that change the shape of the feature, and the competitive pass produced one uncomfortable answer worth recording before any positioning work.

### Reference · The four flows

**Flow A — Enrollment.** Actors: employee (E), roster holder (R), relying party (RP).

1. E is added to a privileged group; the IdP marks the account as requiring Occulta-gated enrollment and issues a request ID.
2. E and R meet physically (onboarding or a scheduled slot).
3. UWB exchange at ≤25 cm — the shipped key-exchange ceremony, unchanged.
4. R's device displays the action string ("Enroll credential for e.smith@corp — production access"); biometric confirm, SE signs.
5. E's device displays the same string; biometric confirm, SE signs.
6. Artifact (request ID, action string, timestamp, E's pubkey, both signatures) uploaded to the org's enrollment page.
7. RP verifies roster-signature chain, outstanding request ID, timestamp freshness, employee signature. Passkey registration proceeds.

**Flow B — Recovery (the helpdesk-attack case).** As A, except: the helpdesk opens the reset request but **cannot complete it** (no technician override — see Q-05); E arrives with a new device and a fresh SE identity key, the old one being unrecoverable by design; the ceremony re-establishes the key against R.

**Flow C — Step-up.** The portal generates a request naming the action ("Approve wire $250,000 to ACME Corp, acct ···4471"); approvers confirm on their own devices against that exact string; the portal verifies before releasing funds. Threshold per D-11.

**Flow D — Roster change.** K-of-N, in person, rare. Governs the pinned roster itself.

### D-14 · The share-sheet transport objection does not apply to RP-directed artifacts — refines F-02

F-02 established that Occulta has no automatic delivery channel post-pairing: every bundle reaching another *Occulta user* goes through a manual `UIActivityViewController` share sheet (verified against current code, 2026-08-09). That finding correctly killed D-01's standing-credential model, where the root must repeatedly push refreshed attestations to every employee.

It does **not** transfer to this architecture, for three reasons: the artifact's destination is a *server*, not an Occulta peer; it is not secret, so an ordinary TLS upload to the org's own portal is sufficient; and the user is already at a computer completing onboarding or recovery when it is produced. A one-time file upload at a moment the user is already transacting is not meaningful friction, and it requires no network code in Occulta — the zero-server invariant is untouched, since the server is the RP's and sits outside the trust boundary.

Recorded explicitly so F-02 is not later cited as a blanket transport objection to this design. F-02 stands as written for peer-to-peer delivery; it is out of scope here.

### D-15 · Step-up is remote-capable; enrollment and recovery are not — content binding substitutes for presence

D-07 argued co-location removes the relay channel that blocked `#15`. True, and it applies to Flows A, B, and D. **It is not required for Flow C**, and the reason generalizes into a clean rule:

- **Enrollment and recovery establish a new key.** There is no content to bind against — the assurance sought is "this key belongs to this person," which only physical presence can supply. Co-location required.
- **Step-up authorizes a described action against an already-established key.** The artifact names exactly what is being approved, so the assurance travels in the payload. Co-location unnecessary.

This is why the relay attack that downgraded `#15` doesn't reach Flow C: a presence challenge is contentless, so relaying it succeeds. Relaying a content-bound approval means the genuine approver reads "approve wire $250,000 to ACME" and declines if they didn't initiate it. Same logic as `#26` (Verified Payment Instructions).

**Residual, stated plainly:** content binding does not defend against an authorized approver being *deceived* into approving a transfer they believe is legitimate. That is authority abuse, and no cryptographic construction addresses it.

**Sequencing implication worth weighing:** Flow C may be the better first wedge than Flow B. It is remote-capable (no scheduling friction), content-bound (immune to the relay attack), maps onto `#26` which already sits at Priority 1 on the consumer roadmap, and defends the Arup-class deepfake scenario that motivated this expansion's June wedge. Flow B carries the more compelling story but all of the geography problems (Q-04).

### Q-05 · Does any real IdP support a genuine no-override policy? — verify alongside D-08

Flow B's entire value rests on the helpdesk technician being *unable* to complete a reset without the artifact. If the IdP retains a break-glass override — and most do, deliberately, because lockout is an operational catastrophe — then the attacker's path is to social-engineer the override rather than the reset, and the guarantee is void.

This is a deployment-configuration question, not a protocol question, but it gates the feature exactly as hard as D-08 does. Fold it into the same verification pass: can Okta/Entra express "for this account set, this reset path has no administrative override," and what does the org do when that policy strands someone (Q-04)?

### Competitive read

**The primary alternative is not a competitor product — it is pre-registered backup FIDO2 keys.** Issue privileged users two hardware keys, keep one in a safe. There is then no reset flow to attack at all. Roughly $50/user, no vendor, no ceremony, no integration, and it is what most competent security teams already reach for. It handles the large majority of this threat at a fraction of the complexity.

Occulta wins only the residual: both keys lost, a key sitting in a departed employee's drawer, or an org needing the recovery event itself to be **provable to an auditor** rather than merely logged. Real, defensible, and small. This comparison belongs in any honest positioning material; omitting it would not survive first contact with a competent security team.

**Purpose-built incumbents:** Nametag and HYPR Affirm (both already named in the Master doc's June 2026 addendum) do helpdesk identity verification today, and critically they work **remotely** — which this design structurally cannot. Their cost is precisely what Occulta's audience objects to: government-ID and biometric upload to a cloud vendor. Okta Identity Threat Protection and Entra Verified ID are the incumbents' native answers, bundled into stacks orgs already own. Process controls — manager approval over a pre-registered channel, callback to a known number, mandatory 24–72h delay with account-holder notification — are cheap, unglamorous, and effective against smash-and-grab attempts.

**Honest ranking for helpdesk social engineering specifically:** (1) backup keys plus a no-reset policy, which eliminates the surface rather than defending it; (2) Nametag/HYPR, purpose-built and remote-capable; (3) process controls, partial and nearly free; (4) Occulta — strongest cryptographic property for the events it covers, no remote path, deliberately narrow scope, unbuilt.

**Broader picture:** phishing is already solved by passkeys and Occulta adds nothing there; BEC/wire fraud is where Occulta is genuinely differentiated (D-15, `#26`); deepfake executive fraud is a strong fit with no iOS equivalent shipping (Google's Fake Call Detection is Android/RCS-only); insider threat is unaddressed here and largely across the field.

**Synthesis:** the best answer to social engineering is to deploy phishing-resistant auth everywhere and remove the reset path entirely. Occulta is a specialist tool for the last mile of that — where a reset genuinely must occur and must be provable. Defensible and honest, but not a category-leading position, and positioning must not imply otherwise.

**Vintage caveat:** this read draws on the Master doc's May–July 2026 competitive passes plus general knowledge, not a fresh vendor scan. Refresh Nametag/HYPR product and deployment status before any of it reaches external material.

### Action items

- Fold Q-05 into the D-08 verification pass — same conversation with the same IdP surfaces.
- Weigh D-15's sequencing implication: Flow C (step-up) as first wedge rather than Flow B (recovery), given it is remote-capable and already adjacent to `#26`.
- Refresh the Nametag/HYPR competitive read before positioning work.
- Master doc Expansion A: consider adding the backup-FIDO2-key comparison — it is the alternative any evaluator raises first, and its absence would read as an oversight.

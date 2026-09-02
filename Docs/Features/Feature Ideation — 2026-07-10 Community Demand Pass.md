# Occulta — Feature Ideation: Community Demand Pass
**Date:** July 10, 2026
**Sources:** Web-sourced demand research across r/privacy, r/signal, r/scams themes; FBI IC3 2025 Annual Report; FTC elder-fraud data; Chat Control reinstatement coverage (July 9, 2026); KOSA House passage (June 29, 2026); World ID / proof-of-personhood coverage; DV/stalkerware advocacy guidance (NNEDV Safety Net, Operation Safe Escape); real-estate wire-fraud industry guidance; C2PA provenance landscape.
**Method:** Reviewed all 25 pinpointed consumer features and 9 expansions in the Master Feature & Expansion Analysis (with rulings) before searching, to surface only ideas that are (a) new relative to that list, (b) broadly welcomed rather than niche, (c) inside the threat model — zero-server, SE-bound, no metadata leakage, FS/PQ preserved, Apple frameworks only.

---

## Context: the news cycle is finally in front of us

The Trajectory doc's stated risk is that Occulta is "consistently one news cycle behind the moment when its features would be most compelling." This pass lands in the opposite position — three cycles are peaking *now*:

1. **Chat Control was reinstated July 9, 2026** (yesterday). Parliament failed to reach the 361-MEP threshold; suspicionless scanning continues to 2028, with "voluntary" scanning + risk-mitigation obligations pressuring encrypted messengers. Occulta is structurally outside the blast radius — it is not a messaging service, holds no accounts, and its payloads travel over channels the user already has.
2. **KOSA passed the House June 29, 2026** with large-scale age-verification mandates; roughly half of US states already mandate age gating. The privacy community's revolt is against ID/biometric upload, not against age proof itself.
3. **Impersonation is the fastest-growing fraud category** (~1,400% YoY in crypto-adjacent fraud; $3.05B BEC losses in the 2025 IC3 report; 1-in-4 people report encountering voice-clone scams; $2.4B reported elder losses at FTC).

Every candidate below rides at least one of these.

---

## Candidate 1 — Verified Payment Instructions (Signed Payment Rails)

**Category:** Security / Anti-fraud
**Community demand:** Very high — BEC is the #2 crime by losses in the FBI IC3 2025 report ($3.05B across 24,768 complaints, up from $2.77B); real-estate wire fraud alone was $275.1M in 2025 across 12,368 complaints [~~up from ~$173M~~ — unsourced, removed 2026-08-10]; 86% of BEC losses moved by wire/ACH and are effectively unrecoverable; industry guidance (NAR, title insurers, state DREs) now literally recommends "establish a verbal authentication code with your title company at the start of the transaction" — the same analog safe-word pattern Presence Verification already replaces cryptographically.
**Audience:** Broad — home buyers/sellers, small businesses paying vendors, families moving large sums, escrow/title/law offices. This is the largest documented per-victim loss category adjacent to the app (median six figures in real estate).

Payment details (account/routing, IBAN, crypto address) become a first-class signed artifact: a structured basket sub-envelope signed by the sender's SE key under a new domain prefix (`"occulta-payment-instructions-v1"`), pinned to the physically-verified contact. Three UI rules do the work:

1. **Instructions are immutable artifacts.** Received instructions render as a pinned, verified card — not editable text in a thread.
2. **Changes must be signed by the same key, and the UI diffs loudly.** "⚠ These instructions differ from the ones received on June 3 — account number changed." The entire BEC playbook is a last-minute "our bank details changed" email; here, an unsigned change is not merely suspicious — it is *impossible to represent* as verified.
3. **One-tap pre-wire presence check.** Before wiring, the payer runs a live Presence Verification (#15) challenge against the same key: "confirm you sent these instructions and the amount is $412,000." This binds the *live human*, the *instructions*, and the *amount* to the key exchanged at ≤25 cm.

**Why the loop closes (the #12/D critique does not apply):** Real-estate parties physically meet — buyers meet their agent and usually the title officer; small businesses meet their vendors. The UWB ceremony slots naturally into the first in-person meeting ("we exchange keys at the listing appointment; all money instructions come only through this channel"). Both parties having Occulta is the transaction's explicit protocol, agreed at the start — exactly how the industry's verbal-code recommendation already works, minus the leakable code.

**Why new vs. the existing list:** The June 2026 addendum to Expansion A mentions wire-transfer verification only as a *live presence check* (enterprise policy story). BEC does not arrive live — it arrives asynchronously in a compromised email thread. The defense the victim needs at the moment of wiring is a **trusted asynchronous artifact**, not just a challenge. No existing feature (#15, #24, or any basket type) gives payment details pinned-immutable semantics with signed-change diffing.

**Security model fit:** Zero-server (baskets); SE-signed under a new domain-separated prefix per the IDENTITY_CHALLENGE_PROTOCOL mandate — no existing signing path touched; travels only inside AES-GCM bundles (no metadata); FS/PQ untouched.

**iOS constraint:** iOS 16+, zero new primitives. Work is the structured payload type, the pinned-card UX, and the diff flow. Optional later: a signed "wire executed to account ending 1234, $X, [time]" confirmation receipt (reuses the #24 receipt pattern).

> **Suggested ruling:** The strongest candidate of this pass. Largest documented dollar losses of any addressable category; the industry's own best-practice answer is a weaker analog version of what the protocol already does; gives the Expansion A wedge a concrete artifact that works bottom-up (one cautious title office or law firm can adopt it unilaterally for its clients). Attack surface is minimal — signatures over non-secret structured data, new prefix only. Run CRYPTO_REVIEW_CHECKLIST §4 on the new domain prefix. Low-medium lift. **Priority: Near-term (pairs with Presence Verification as an "anti-impersonation" release narrative).**

---

## Candidate 2 — Anti-Scam Family Circle (packaging + two small features)

**Category:** Anti-fraud / Positioning
**Community demand:** Very high — $2.4B reported FTC losses for adults 60+; 1-in-4 exposure to voice-clone scams with losses to $15K per incident; BBB/CNN/McAfee "family safe word" advice is now a permanent consumer-press genre; grandparent-emergency scams are the canonical AI-fraud story of 2025–2026.
**Audience:** Broad and mainstream — every user with parents or grandparents. Also the app's most natural viral loop: protecting one parent requires installing Occulta on 2–5 family devices, each install physically verified by definition.

Presence Verification (#15) already is the cryptographic answer to the family safe word. What's missing is the *product wrapper* that a worried adult child can deploy on a parent's phone in ten minutes:

1. **Assisted Mode** — a simplified profile for the relative's device: huge "Check it's really them" button that runs a presence challenge against the claimed family member; plain-language results ("✓ That was really Sarah — confirmed by her phone just now" / "✗ No confirmation. Hang up and call Sarah's number.").
2. **Second Opinion** — one tap forwards a suspicious request (screenshot, voice note, message text) as a structured basket to a designated family guardian: "Mom flagged this — does it look like a scam?" The guardian's reply renders as a clear verdict card. Zero new crypto; one basket type plus UX.
3. **Money-request rule** — any message that asks for money/gift cards/codes triggers an automatic prompt on the elder's device to run the presence check first (ties into Candidate 1's instruction artifacts for the family case: "the only account details that count are signed ones").

**Why new vs. the existing list:** #15 ships the primitive; this is the deployment story for the demographic the scam wave actually targets — who will never navigate a challenge/attestation vocabulary. The Master doc has no packaging/UX-profile concept for low-capability users.

**Security model fit:** Nothing new — all flows are existing or planned primitives. Assisted Mode is a UI profile, not a permission model; no remote management, no account, nothing an abuser of the feature could repurpose (the guardian sees only what the elder explicitly forwards).

**iOS constraint:** UX work almost entirely. The one design obligation: Assisted Mode must not weaken anything (same crypto, same biometric gates — fewer choices, larger type).

> **Suggested ruling:** Highest reach-to-lift ratio in this pass. This is how Presence Verification escapes the security-literate niche and becomes the app a normal person installs for their mother — the bottom-up adoption path Section 2 says is the only realistic route to everything else. **Priority: Near-term, sequenced with/immediately after Presence Verification ships.**

---

## Candidate 3 — Sealed Evidence Journal (tamper-evident, guardian-witnessed)

**Category:** Security / Duress cluster extension
**Community demand:** Medium-high — DV advocacy orgs (NNEDV Safety Net, Operation Safe Escape) explicitly instruct survivors to *preserve evidence before removing stalkerware or cleaning devices*, and note that court-grade preservation currently requires professional digital forensics; existing survivor-evidence apps are cloud-based (a fatal flaw when the abuser controls or monitors accounts). Parallel 2026 demand: documenting ICE encounters and protest policing — current guidance ("back your footage up to Google Drive/iCloud immediately") routes evidence through exactly the cloud accounts that get subpoenaed, taken over, or watched.
**Audience:** Narrow-medium but intensely motivated — DV/stalking survivors, protest documenters, journalists; precisely the coercion-resistant audience Act 2 identified. The adversary (a person with physical or account-level access) is literally Occulta's v1.8 adversary model.

An append-only journal in the vault: each entry (photo, screenshot, audio, text note) is hashed into a chain; each chain head is SE-signed with a timestamp. Periodically — and on demand — the signed chain head travels as a small basket to one or more chosen guardian contacts, whose apps countersign a receipt ("I held chain head H at time T"). That guardian receipt is the piece local-only designs can't provide: **tamper-evidence anchored outside the device, with no server, no blockchain, no cloud account** — just people the user physically trusts, holding 32 bytes.

- Entries live in the vault → automatically inherit Travel Mode, deniable partitions, and Panic Wipe when the duress cluster ships. A survivor's journal can sit in the hidden partition; the abuser who compels an unlock sees nothing.
- Honest framing (in-product): this is *chain-of-custody support*, not automatic court admissibility — it proves the record existed by date X and hasn't been altered since, which is the thing advocates say survivors lose most often.

**Why new vs. the existing list:** Extends the Trajectory doc's projected "Sealed Session Transcripts" (#3 there) in two declared ways: (a) from message transcripts to arbitrary user-captured evidence; (b) adds the guardian-witnessed external anchor, which transcripts lack (a purely local chain is self-attested — the owner could rebuild it). Reuses the #24 receipt machinery and basket rails. Distinct from the Dead Man's Switch (#8): nothing is released; guardians hold hashes, never content.

**Security model fit:** Zero-server; SE signs chain heads and receipts under new domain prefixes; guardians receive only hashes (no content, no metadata about content — pad the receipt bundle per #21 so "evidence journal user" isn't inferable from traffic shape); FS/PQ untouched.

**iOS constraint:** iOS 16+. Hash chain + signing is trivial; work is the capture UX, chain bookkeeping, and the guardian receipt flow. Camera capture should go straight into the journal (never through the system camera roll) to avoid orphaned plaintext — same cleanup discipline as the share extension.

> **Suggested ruling:** Fits the product arc unusually well — it deepens the duress cluster's story from "protect what you hide" to "protect what you must prove," for the same audience, on the same rails. The deniable-partition dependency is the right sequencing reason to slot it after the duress cluster rather than before. Medium lift. **Priority: Phase 2 (with the duress cluster).**

---

## Candidate 4 — Attested Capture (signed voice notes / photos)

**Category:** Privacy / Anti-deepfake (secondary candidate)
**Community demand:** Medium-high ambient ("how do I know this voicemail/photo is real") — but note the industry is converging on C2PA at the platform/camera level, and baskets are already sender-authenticated.

In-app capture (mic/camera) → immediate SE signature over the media hash + timestamp under `"occulta-attested-capture-v1"` → travels in the normal basket. Recipient UI: "🎙 Captured live on Alice's device, 14:02, biometrically confirmed." The delta over ordinary basket authenticity is *capture-time* attestation — "recorded by her app just now," not "a file she attached" — which is exactly the asynchronous version of Presence Verification: unfakeable voice notes for the voice-cloning era.

**Honest boundary:** proves an unmodified Occulta app performed the capture — the same honest-app boundary as destruction receipts (#24), and it must be marketed with the same discipline (protocol proof, not media forensics). A recipient outside the contact book can verify nothing (the #12 closed-loop critique applies to *export*; in-circle it closes fully).

> **Suggested ruling:** Ship the *voice-note* case as a small affordance inside the Presence Verification narrative ("signed voice notes") rather than as a standalone feature; defer photo/video attestation and watch whether Apple exposes C2PA-style capture APIs. Low lift for the audio slice. **Priority: Near-to-mid-term, opportunistic.**

---

## Re-prioritization signals (existing items, new urgency)

1. **Expansion H (Anonymous Credentials / SD-JWT holder):** The Phase 3 gate was "EU Digital Identity Wallet rollout is the trigger." KOSA passing the House (June 29, 2026) plus ~half of US states mandating age gating means the *demand-side* trigger has arrived years before the EU issuer-side one. The community's objection is ID upload to platforms and verification vendors — "prove your age without anyone learning where you presented it" is now a mainstream complaint. Recommended: pull the W3C VC / SD-JWT credential-holder design study forward from Phase 3 to an active scoping item; the build gate can remain issuer availability.
2. **Uniform Basket Envelopes (#21):** Chat Control's reinstatement strengthens the case from "credibility feature" to timely hardening — in a scanning regime, traffic-shape and size fingerprints are what platform-side classifiers see. Consider promoting from "opportunistic" to scheduled.
3. **Duress cluster (Travel Mode, Panic Wipe, Deniable Partitions):** The 2026 US domestic climate (ICE checkpoint device searches at airports, protest documentation guidance) has expanded the audience from "border crossers" to residents who never leave the country. The Intercept and civil-liberties guidance now reads exactly like the cluster's feature list. This is the news cycle the Trajectory doc said we keep missing — it argues for acceleration, not re-scoping.

## Positioning notes (no engineering)

- **Chat Control counter-positioning (time-sensitive):** Occulta is not a messenger and has no service to compel — no accounts, no delivery infrastructure, nothing to attach a scanning obligation to. That is a *structural* answer to the week's biggest privacy story, and it is honest. Worth a public write-up while the cycle is hot.
- **Proof-of-personhood contrast:** World ID is scaling iris-scanning orbs + blockchain to prove "unique human" — and the privacy community loathes it. Occulta's contact graph already *is* proof of personhood, established at 25 cm with no biometric harvesting and no global registry: "We don't scan your iris to prove you're human. You met them." Surface "physically verified · in person · [date]" more prominently in contact UI; the rest is marketing.
- **Signal backup contrast:** Signal's most-requested feature (backups) shipped as *Signal-hosted* storage. Occulta's social recovery (#16) remains the only serverless answer — reinforces the existing "positioning, not engineering" ruling on #16.

## Considered and omitted (this pass)

- **Steganographic carrier bundles** (`.occ` payloads embedded in innocuous media, as a Chat Control reaction): would be celebrated on r/privacy, but statistical stego detection is an arms race we cannot win with Apple-framework primitives; a *detected* stego carrier is a worse forensic artifact than a clean encrypted file; and it invites App Store review risk for the whole product. The defensible subset of the benefit (size/shape unlinkability) is exactly #21. Omitted.
- **Safety check-in for meetups** (dating/marketplace): Apple's Check In ships free and built-in since iOS 17; competing with a platform feature on its home turf adds no audience. If the Dead Man's Switch (#8) ships, a short-fuse variant falls out nearly free — revisit then, not before.
- **Standalone personal C2PA / media provenance suite:** platform momentum (C2PA in cameras and OS pipelines) will out-deliver any app-level implementation for general media; only the in-circle capture-attestation slice survives scrutiny (Candidate 4).
- **Scam-detection AI / content classifiers:** would require either on-device models flagging message content (false-positive liability, scope creep) or network services (excluded). The Second Opinion flow (Candidate 2) achieves the useful subset with a human the user trusts.
- **Verified introductions (transitive trust / vouching):** repeatedly tempting for growth, and repeatedly wrong — every entry in the graph is physically verified or the graph's core claim dies. Mutual-Contact Discovery (#22) corroboration remains the ceiling. Re-affirmed, not new.

---

## Combined view — this pass ranked

| Rank | Item | Impact | Lift | Phase |
|---|---|---|---|---|
| 1 | Verified Payment Instructions | Very high ($3B+ documented losses; artifact no competitor has) | Low-med | Near-term |
| 2 | Anti-Scam Family Circle | Very high (mainstream reach + viral install loop) | Low | Near-term (with #15) |
| 3 | Sealed Evidence Journal | Med-high (intense niche, duress-cluster synergy) | Medium | Phase 2 |
| 4 | Attested Capture (voice slice) | Medium | Low | Opportunistic |
| — | Expansion H pull-forward (scoping only) | High ceiling | Scoping | Active study |

**The through-line:** the 2026 fraud wave is an *impersonation* wave — of voices, faces, email threads, and payment instructions. Occulta's primitive ("you physically met this key") is the only consumer-grade anchor that impersonation cannot cross. Candidates 1–2 aim that primitive at the two largest documented loss pools (BEC/wire fraud and elder fraud); Candidate 3 serves the coercion-resistant core; the positioning items convert this month's news cycle. None require new cryptography beyond domain-separated signatures; all are zero-server, SE-bound, and metadata-clean.

---

### Source register

- FBI IC3 2025 Annual Report — [ic3.gov](https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf); BEC analysis: [Nacha](https://www.nacha.org/news/fbis-ic3-finds-almost-85-billion-lost-business-email-compromise-last-three-years), [SpyCloud](https://spycloud.com/blog/fbi-internet-crime-report-2025/), [Red Sift](https://redsift.com/blog/fbi-ic3-2025-report-email-fraud)
- Real-estate wire fraud 2026 guidance — [Plymouth Title](https://www.plymouthtitleinsurance.com/industry-news/real-estate-wire-fraud-protect-your-closing-2026), [NAR](https://www.nar.realtor/wire-fraud), [Santa Barbara Independent](https://www.independent.com/2026/04/27/real-estate-cybercrime-and-the-one-email-that-can-cost-you-everything/)
- Voice-clone scams — [SavingAdvice (1-in-4 stat)](https://www.savingadvice.com/articles/2026/05/21/10736407_ai-voice-cloning-scams-explode-one-in-four-people-have-encountered-them-losing-up-to-15000.html), [CNN](https://www.cnn.com/2026/05/29/tech/ai-voice-cloning-scams-protect-yourself), [BBB warning](https://www.wistv.com/2026/04/03/bbb-warns-scammers-using-ai-voice-cloning-impersonate-family-members/)
- Elder fraud — [CFPB](https://www.consumerfinance.gov/consumer-tools/educator-tools/resources-for-older-adults/protecting-against-fraud/), [Elder Law Center](https://elderlawcenterbrevard.com/2026/04/17/digital-tools-protect-older-adults-from-financial-abuse/)
- Chat Control reinstatement — [The Register (Jul 9, 2026)](https://www.theregister.com/security/2026/07/09/meps-fail-to-prevent-chat-control-snoopfest-revival/5269379), [TechTimes](https://www.techtimes.com/articles/320010/20260709/eu-parliament-passes-chat-control-default-314-meps-couldnt-block-scanning-law.htm), [Breyer tracker](https://www.patrick-breyer.de/en/posts/chat-control/)
- Age verification / KOSA — [Rolling Stone](https://www.rollingstone.com/culture/culture-features/age-verification-legislation-united-states-online-safety-1235419895/), [EU age-verification policy](https://digital-strategy.ec.europa.eu/en/policies/eu-age-verification), [NatLaw Review](https://natlawreview.com/article/new-age-verification-reality-compliance-rapidly-expanding-state-regulatory)
- DV / stalkerware evidence guidance — [NNEDV Safety Net](https://www.techsafety.org/spyware-and-stalkerware-phone-surveillance), [FTC](https://consumer.ftc.gov/articles/stalkerware-what-know), [Operation Safe Escape](https://safeescape.org/stalkerware-threatens-womens-privacy/)
- ICE device searches / protest documentation — [The Intercept](https://theintercept.com/2026/03/25/ice-airports-phone-security-privacy-safety/), [Papers, Please!](https://papersplease.org/wp/2026/03/22/your-rights-when-an-airport-checkpoint-is-staffed-by-ice-agents/)
- Proof of personhood — [CoinDesk (World AgentKit)](https://www.coindesk.com/tech/2026/03/17/sam-altman-s-world-teams-up-with-coinbase-to-prove-there-is-a-real-person-behind-every-ai-transaction), [crypto.news](https://crypto.news/what-is-proof-of-personhood-verifying-real-humans-in-the-ai-age/)
- Impersonation growth — [FinancialContent crypto scam trends](https://www.financialcontent.com/article/globeprwire-2026-6-20-the-top-5-crypto-scam-trends-of-2026)
- Signal 2025–2026 features — [aboutsignal.com (2025 recap)](https://aboutsignal.com/news/this-was-2025-for-signal-strong-growth-and-many-new-features/), [2026 preview](https://aboutsignal.com/news/whats-next-for-signal-in-2026-these-handy-features-are-coming-soon/)
- C2PA landscape — [C2PA explainer](https://c2paviewer.com/articles/what-is-c2pa), [limits](https://truescreen.io/articles/c2pa-standard-history-limitations/)

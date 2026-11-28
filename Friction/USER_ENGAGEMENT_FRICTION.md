# User Engagement Friction Report

Findings organized by severity, with prioritized recommendations.
Each finding is tagged **[code]** (derived from source, file:line cited) or
**[assessment]** (strategic analysis of adoption dynamics).

Original fact-based audit: 2026-04-30.
Updated 2026-07-12: line references re-verified against current source, adoption-level
findings added, document reorganized by severity and priority.
Updated 2026-07-17: encryption-before-verification analysis added (H5, Sweep 4) —
evaluated ways to message before a physical key exchange; key-in-bundle rejected.
Updated 2026-07-18: Sweep 4 refined after a second-opinion security review —
first-message FS nuance, no-retroactive-protection caveat, and a second open
decision (send-capable vs import-only unverified tier) added; degraded-crypto
signaling and a separate "Lite" app rejected.
Updated 2026-07-22: consumer-opening memo analyzed in
CONSUMER_OPENING_AND_CEREMONY.md — casual-ceremony concepts catalogued, a
"Verified (casual)" rung proposed for the Sweep 4 ladder (commitment-based
glance SAS; short-SAS-is-weak assumption corrected), SMS/web-view fallback
rejected; two new open decisions (D3 badge rendering, D4 SAS format).
Updated 2026-08-11: every **[code]** finding re-verified against current source.
Line references corrected throughout; C2's silent-save and watchdog bullets,
C3's shard-acknowledgement row, H1, M2's missing progress indicator, M3, and
half the feature-flag item marked resolved with the commits that closed them.
Two factual corrections beyond line drift: C1's "no single-player value" claim
and its Vault note were wrong (the Vault holds personal notes/seed phrases and
needs no contacts), and H5 cited the inbound decrypt path for an outbound
encryption gate.

---

## The core engagement funnel

```
Download → Onboarding → Add contact → Exchange keys → Compose → Encrypt → Send via another app → Recipient opens .occ
```

---

## Critical — adoption blockers

These make the product fail before or at its first moment of value. Everything
downstream is irrelevant until they are resolved.

### C1. Zero value at install [assessment]

The first *messaging* moment of value requires a second person, physically
present, with an iPhone 11+ (U1 chip), the app already installed, two system
permissions granted, standing within 25 cm, inside a 30-second watchdog window.
Six multiplied conditional probabilities precede any experience of the
product's core promise. No positioning or marketing survives that funnel shape.

**Corrected 2026-08-11 — the original "no single-player value" claim was wrong,
and so was the note that followed it.** `Occulta/Features/Vault/` is not only
Shamir shard custody: `VaultEntryType` is `.seedPhrase`, `.note`, and
`.keyToken` (`Vault+Model.swift:27–31`) — personal secrets sealed under the
Secure Enclave key, requiring zero contacts. The Vault tab sits in the TabView
behind no feature flag (`OccultaApp.swift:411`); shard custody is an optional
recovery layer on top of those entries, not the whole feature. Onboarding
screen 4 now signposts it — "A private vault, too / Not everything needs a
contact." (`OnboardingView.swift:392–445`). That combination is what the
summary table's ✅ for C1 records.

What survives the correction: day-one value is a personal vault, not the
product's stated promise. The messaging funnel above is still gated on a second
person, which is why Sweep 4 (H5) matters independently of C1.

### C2. Key exchange failure modes [code]

The exchange is simultaneously the product demo, the onboarding, and the growth
loop — and it is the highest drop-off point. A failed exchange loses two users
at once, in person. Compounding gates:

- **Silent key save failure on success.** ✅ Resolved (`51e3554`, 2026-07-12).
  The empty catch block quoted here lived in `ExchangeResult.swift`, a dead v1
  view that commit deleted. The live save path is `KeyExchange.swift:269–299`,
  whose catch sets `saveState = .failed`; the view renders a "Couldn't save
  key" state with a Retry button at `KeyExchange.swift:206–223`. A save that
  throws can no longer look like success.

- **Hardware gate.** Still holds. `isExchangePossible`
  (`Exchange+Manager.swift:47–49`) checks
  `NISession.deviceCapabilities.supportsPreciseDistanceMeasurement`. Failure
  renders red text — now "Key exchange requires a UWB chip (iPhone 11 or
  later)." (`KeyExchange.swift:101–105`) — with no alternative path. iPhone X
  and earlier (and non-U1 models) are permanently blocked.

- **Watchdog.** Timer still holds; the 3-step hardware recovery does not. A
  30-second `DispatchSourceTimer` still fires `.timedOut` if no NI updates
  arrive (`Exchange+Manager.swift:243–257`). ✅ Recovery resolved (`91f4355`,
  2026-07-13): it is now an in-app banner (`KeyExchange.swift:46–51`, set at
  `:113–117`) plus the existing "Exchange Keys" button as one-tap retry
  (`:82–90`) — no Settings toggle, no device restart. See "Watchdog recovery"
  under P0.

- **Permission friction.** Still holds. Two iOS system dialogs (Nearby
  Interaction, Local Network — usage strings declared at
  `Occulta.xcodeproj/project.pbxproj:792–793`) interrupt the flow before
  exchange can proceed. The pre-exchange screen now warns about both up front
  (`KeyExchange.swift:61–69`), but the dialogs themselves are unavoidable.

- **Physical constraint.** Still holds. Both devices must be ≤ 25 cm apart,
  enforced in the NI update handler (`Exchange+Manager.swift:638`).

- **Required Diceware confirmation.** Still holds. The key is only saved after
  a manual verbal comparison (`KeyExchange.swift:231–247`) and Confirm tap
  (`:176–191`) — no timeout, no skip. (Security-required, but it sits inside
  the same fragile window.)

### C3. No retention trigger [code]

Nothing brings a user back after install:

| Missing capability | Evidence | Status |
|---|---|---|
| Message history | Compose state moved to `ComposeViewModel.messages` (`ComposeViewModel.swift:36`) and drafts now persist (H1) — but sent/received history still has no store anywhere | ⬜ Open |
| Inbox | `Contact.Message` is registered in the schema (`OccultaApp.swift:42`) with zero insert or query sites — dead scaffolding, not a store | ⬜ Open |
| Notifications | No `UNUserNotificationCenter` usage found — re-confirmed, zero matches app-wide | ⬜ Open |
| Key rotation UI | Still documented as unresolved (`OccultaApp.swift:16`); no rotate-key control in any view | ⬜ Open |
| SSS shard acknowledgement | `.acknowledge` now confirms in-flight shards (`ShardCustody+Manager.swift:242–247`); `ShardStatus` is a validated `pending → confirmed → …` machine (`Vault+Model.swift:40–51`) and `.sent` no longer exists | ✅ Resolved (`599866d`, 2026-04-30; state machine `4add524`, 2026-05-01) |

Every session is still stateless from the user's perspective for anything
received. Adoption is retention compounding; drafts are now the only thing the
app retains.

---

## High severity

### H1. Composition state loss [code]

✅ Resolved (`4f8f449` + `63ef3cb`, 2026-07-17/18). Composition is now backed by
`Message.Draft`, an AES-GCM-sealed SwiftData row written through `DraftStore`
(`DraftStore.swift`): loaded on `.task`, debounce-saved on every text or
attachment change, and flushed immediately on `.onDisappear` *before*
`composeVM.cleanup()` runs, plus on backgrounding under a background-task
assertion (`ContactDetailV2.swift:130–156`, `:198–213`; same wiring in
`ContactDetailV3.swift` and `GroupDetailV3.swift`). A phone call, app switch,
or screen timeout no longer destroys unsaved content.

Note: the original finding understated the bug — the pre-fix `cleanup()` also
deleted unsent attachment files from disk outright, not merely failed to save
them (`Docs/Features/Message Persistence/FINDINGS.md`, D-01). Drafts are the
only part of Sweep 2 that shipped; sent/received history (C3, H2) was
deliberately deferred, not resolved.

### H2. Inbound delivery can silently fail [code]

Still holds. Delivery routes through `ShareExtension → app group container →
URL scheme occulta://inbound?session=<uuid>` (`ShareViewController.swift:486`).
Malformed-URL and write failures do clean up and cancel the request
(`:475–490`), but the launch itself is a responder-chain walk that falls
through silently: if no responder handles `open(_:options:)`, the extension
still calls `completeRequest` (`:492–505`) and the `.occ` sits in the container
with no fallback and no user-visible error.

The finding's second half was already amended under Sweep 1 — a bundle from an
unknown sender does surface a message, so only the landing place is missing.

### H3. Distribution channel mismatch [assessment]

The current channel (LinkedIn founder posts, ~2x/week) peaked at 260
impressions on the best-performing post. That is not a channel — it is a
rounding error. The audience that adopts a security tool from an unknown
developer does so through public technical scrutiny (protocol spec, HN,
r/netsec, security researchers kicking the tires), not broadcast marketing.
Credibility for this product category cannot be asserted, only earned in
public.

### H4. Value proposition competes with "good enough" [assessment]

The users who feel the pain (journalists, lawyers, security professionals)
already have Signal: free, audited, works remotely. Occulta asks them to
accept large, concrete friction for a subtle jurisdictional benefit. Argument
alone does not win this trade; expert vouching and a visibly working product
do.

### H5. Encryption is hard-gated on physical verification [assessment]

Messaging requires a completed key exchange — a contact without a stored key
cannot be encrypted to at all: `encryptBundle` resolves recipient material via
`resolveKeyMaterial` (`Contact+Manager.swift:1009` → `:1370`), which throws
`contactHasNoKeys` when the contact has no unexpired key record (`:1377`).
(Corrected 2026-08-11: this previously cited `buildOwnedBasket` throwing
`noPublicKeyToEncryptWith` at `Contact+Manager.swift:1414` — wrong error, wrong
line, and wrong direction; that name belongs to the *inbound* decrypt path in
`OccultaApp.swift:567`. The finding is unaffected — only the citation was.)

Every gate in C1/C2 is therefore multiplied into the messaging funnel: nobody
can receive a first message until they have stood within 25 cm of the sender.
Signal, WhatsApp, and Threema all encrypt fully for unverified contacts and treat
verification as an *authenticity upgrade*, not a gate on encryption — the
gate is Occulta-specific friction, not an industry baseline.

One shortcut was evaluated and rejected (2026-07-17): allow sends to
unverified contacts by shipping the session key inside the bundle, behind a
warning. Rejected because:

- **It is plaintext with extra steps.** Every bundle carrier can read it,
  forever. For a product positioned as "nothing to hack, subpoena, or shut
  down," *"ships the decryption key next to the ciphertext"* becomes the
  headline of every security review — the warning dialog does not appear in
  that headline.
- **The warning cannot cover the worse half: authenticity.** With a public
  session key the bundle is also forgeable and tamperable — `senderProof` is
  an HMAC under the session key, so a carrier can rewrite content or
  impersonate the sender undetectably, inside Occulta's trust halo.
- **It poisons the upgrade path.** "Reply with your real key so we can go
  secure" is exactly the MITM insertion point; an active carrier becomes the
  permanent man-in-the-middle.
- **Warning fatigue and downgrade surface.** A click-through warning trains
  users out of reading the app's security signals (`securityLabel` tiers lose
  meaning), and attackers don't break crypto — they social-engineer victims
  into the weak mode.

The friction is real; the fix is Sweep 4 (trust ladder), not weakened crypto.

---

## Medium severity

### M1. Silent contact save failure [code]

✅ Resolved. The cited `TODO: Display a warning that a contact could not be
saved` still exists, but in dead v1 code (`Contact+Form.swift:215` — the line
moved from 209). The live form catches the throw into `showSaveError`
(`ContactFormV2.swift:96–107`) and renders "Couldn't save contact" inline at
`:76–83` with the form left open, so Save is the retry.

### M2. Encrypt-and-send friction [code]

Progress indicator ✅ resolved (`b0365af`, 2026-07-14): the Encrypt button
swaps to a `ProgressView` and disables itself while `vm.isEncrypting` is set
(`ContactDetailV2.swift:463–479`, `ComposableMessage.swift:122–129`; flag
driven from `ComposeViewModel.swift:227` and cleared on every exit path).

The app hop still holds: the user must manually route the `.occ` file to the
recipient through a separate app via `UIActivityViewController`
(`ActivityView.swift:18–19`, presented at `ContactDetailV2.swift:160–165`).
Channel-agnostic delivery means every send costs an extra app hop — but that
mechanism is the security model, and the feedback gap that wasn't is now
closed.

### M3. Skippable onboarding hides the core requirement [code]

✅ Resolved (`b8189ad`, 2026-07-12). Onboarding is now 5 screens with no Skip
button anywhere (`OnboardingView.swift:17–36`); completion is gated on reaching
the final `CommitmentScreen`. Screen 2 states the 25 cm UWB requirement
(`OnboardingView.swift:217`) and every user now passes through it. First
post-onboarding interaction is still an empty contacts list with no guidance.

---

## Low severity / contextual

- **Hidden features via flags** [code]: half resolved.
  `enableShamirShardSharing` is now `true` (`2b1c486`, 2026-07-24), so SSS is
  visible. `signature` is still `false` in `features.plist` — the signing tab
  remains invisible to users.
- **No funnel measurement** [assessment]: no telemetry is a principled,
  correct choice for this product — but it means drop-off cannot be observed
  remotely. Requires a manual substitute (see Hallway testing, P3).
- **Low-contrast text in the live exchange view** [code]: the phase step
  label ("01 · SEARCHING" etc., `KeyExchangeLiveView.swift:59` —
  `.white.opacity(0.4)` at 10pt) renders at roughly 3.7:1 against the view's
  pure black background, below the WCAG AA threshold (4.5:1) for text this
  size. Stage 5 (ML-KEM) is worse: the fingerprint-grid cell text and ring
  accent both use `Color(red: 90/255, green: 74/255, blue: 176/255)`
  (`KeyExchangeLiveView.swift:147` and `:227`), roughly 3.0:1 on black — the
  dimmest text in the flow, on the screen being read mid-exchange.

---

## Recommendations

Grouped into three sweeps where fixes share root cause or infrastructure,
plus standalone items that don't combine. Ordered by priority — P0 before
any further marketing spend.

### P0

**Sweep 1: One async-operation feedback mechanism.**
C2 (silent save + missing success confirmation), M1, M2, and part of H2 are
the same underlying gap: the app has no consistent way to tell the user an
operation succeeded, failed, or is in progress. Build one reusable
idle → loading → success → error pattern and wire it into all four sites in a
single pass instead of patching each independently:

| Site | Current gap | Status |
|---|---|---|
| Key save on exchange confirm | `KeyExchange.swift`'s `ConfirmationView` — silent `try?`, unconditional dismiss | ✅ Fixed — explicit save state, retry on failure |
| Contact form save | `ContactFormV2.swift` — silent `try?`, unconditional dismiss | ✅ Fixed — inline error, form stays open, retry via Save |
| Encrypt/send | No progress indicator during async processing | ✅ Fixed — Encrypt button shows a `ProgressView` and disables while encrypting |
| Inbound delivery | Already handled — `noPublicKeyToEncryptWith` surfaces "message was not addressed to you" (`OccultaApp.swift:546–547`, thrown from `Contact+Manager.swift:1469`) | ✅ Already existed — not a gap |

Note: the two `ExchangeResult.swift` / `Contact+Form.swift:215` citations above were dead
v1 code by the time this was fixed — the live bugs were in `KeyExchange.swift` and
`ContactFormV2.swift` respectively. Both files were confirmed via `OccultaApp.swift`'s
tab wiring before fixing.

Sweep 1 is complete. It was the highest-ROI work available: every failed
exchange loses two users in person, and every silent failure poisons word of
mouth.

**Watchdog recovery.** ✅ Fixed.
Replaced the exchange watchdog's silent teardown-and-dismiss (`KeyExchange.swift`
called `finish()` then `dismiss()` on `.timedOut` with zero explanation — worse
than the 3-step manual recovery this item originally described, which was never
actually shown in-app) with an in-app banner and one-tap retry. Since `finish()`
already resets `phase` to `.resting`, dropping the `dismiss()` call lets the view
fall back to the existing "Exchange Keys" button instead of closing — that
button is now the retry, no Settings toggle or device restart required. Note:
`.failed` is declared in `ExchangePhase` but never assigned anywhere in
`Exchange+Manager.swift` — `.timedOut` is the only reachable failure phase today.

### P1

**Sweep 2: One persistence/inbox layer.**
C3 (message history, inbox, notifications), H1 (drafts), and H2 (landing
place for inbound bundles) are all "state that needs to survive past the
current view." One persisted store + one inbox UI + one notification hook
covers drafts, message history, and inbound delivery together, rather than as
three separate features.

Drafts (H1) shipped separately once they were scoped apart from unbounded
message history, which turned out to be a much smaller problem — see
`Docs/Features/Message Persistence/FINDINGS.md`. Remaining Sweep 2 work:
message history, inbox UI, and the notification hook.

**Sweep 3: Onboarding redesign incorporating single-player value.** ✅ Done.
M3 (Skip hides the 25 cm UWB requirement) and C1 (zero value at install)
touched the same screens, and were reworked in one pass as intended: Skip is
gone, the 25 cm requirement sits on screen 2, and screen 4 surfaces the Vault
as day-one value with zero contacts. The encrypt-to-self vault this sweep
originally scoped as a new feature did not need building — `VaultEntryType`
already carried `.note`/`.seedPhrase`/`.keyToken` (see C1's correction). The
work was signposting the capability, not writing it.

**Sweep 4: Trust ladder — encryption before verification.** (H5; structural
relief for C1/C2's funnel shape)
Unverified contacts get real encryption immediately; verification tiers
upgrade *authenticity*. Threat frame: passive readability by any bundle
carrier must be impossible; an active MITM at first contact is the managed
residual, shrunk by each tier climbed. UWB stays the top tier unchanged.

The design invariant, stated once so reviews don't conflate the two axes:
**every tier preserves "only the holder of the recipient key can read this,
period" — tiers vary only in how strongly that key is bound to the intended
human.** Confidentiality against carriers is identical at every rung; what
the lower rungs weaken is authenticity of the binding, deliberately and
visibly.

| Tier | How keys arrived | Assurance |
|---|---|---|
| Verified | UWB tap (or in-person QR) | Full — current model |
| Confirmed | SAS compared over a live call | Strong vs MITM, no meeting needed |
| Introduced | Forwarded by a verified mutual contact | MITM requires a trusted friend defecting |
| Unverified | Contact card / TOFU intro bundle | Real encryption; first-contact MITM possible, caught by later tiers + gossip |

Components, in recommended build order:

1. **Contact cards** — user-exported card carrying the long-term public key
   plus a signed prekey batch (reuses `PrekeySyncBatch` and the
   `longTermFallback` derivation; Threema's red/orange/green trust UX is the
   proven model). Anyone holding a card can send an encrypted first message
   with zero round trips — the actual friction-killer. Cards must be handed
   over privately (AirDrop, existing messengers): a publicly posted card is a
   durable "I use Occulta" artifact, in tension with forensic cleanliness.
   Cross-checking a card's fingerprint over a second channel forces a MITM to
   control both.
   Known nuance: card prekeys are static — not one-time-consumed like the
   per-contact batches — so first-message forward secrecy degrades to
   signed-prekey level (Signal's same tradeoff for its last-resort prekey)
   until the first reply establishes fresh consumed batches. Cards can carry
   ML-KEM material, so hybrid PQ is preserved. Disclosable and temporary,
   not a blocker.
2. **SAS remote verification** — ZRTP-style short authentication string
   derived from the session, compared over any live call; hash commitment
   prevents grinding. Grow `IdentityChallenge` into this. Makes remote
   verification possible at all — today the only authenticity upgrade is a
   physical meeting.
3. **Gossip key-consistency audit** — contacts sharing a mutual acquaintance
   cross-check the fingerprint each holds for that person, inside existing
   E2E channels (same in-payload pattern as `custodyManifest`). Detection,
   not prevention: never blocks anything, but makes a first-contact MITM
   increasingly likely to be caught as the graph fills in.
4. **Introductions — needs an explicit decision.** A verified mutual contact
   forwards both parties' keys, signed, through already-secure channels.
   Serverless-native (the trust graph is the infrastructure) and the largest
   UX win per unit of engineering, but it is third-party key vouching — the
   no-vouching line was previously drawn for own-device keys, and whether it
   extends to introducing *other people* is a product-owner call, not an
   engineering one.

Caveats any spec must state plainly:

- **Verification detects; it does not rewind.** A first-contact MITM caught
  later — by SAS, UWB, or gossip — compromises every message sent before
  detection. Later tiers upgrade the future, not the past.
- **Warning fatigue is the primary failure mode.** Users click through
  dismissible warnings; historically these fail. The tier must be a
  persistent per-contact badge visible in the contact list, at compose, and
  at send — never a one-time dialog — and nothing about an unverified
  contact may render green or "secure."

Second open decision (alongside the introductions call in item 4): is the
Unverified tier **send-capable** (Threema model — the encrypted first
message flows immediately, the badge carries the risk) or **import-only**
(cards can be imported, but the first send requires a minimum confirmation:
SAS over a live call or a manual fingerprint compare)? Import-only
eliminates the first-contact MITM residual at the cost of the
zero-round-trip async first message — a stricter posture that is defensible
for Occulta's threat-sensitive personas. Both variants keep every bundle
carrier-blind; the choice only sets the authenticity floor.

> **Addendum (2026-10-14):** components 1 and 4 now have a worked proposal,
> [Introduction Cards](../Docs/Features/Introduction%20Cards/FINDINGS.md). It
> replaces component 1's multi-use card with an owner-issued, single-use card
> that carries its own key and a one-time prekey instead of the long-term key,
> so the first message keeps full forward secrecy and cards can't be linked to
> each other. It recasts component 4 so contacts pass the owner's card on,
> through any number of hops, asserting nothing and leaving no record of the
> route. D1 is decided there (its Q-01, 2026-10-15): the carrier route is
> allowed, since it grants no trust. D2 is decided there too (its Q-02,
> 2026-10-15): send-capable. Import-only has no purpose for a single-use card,
> because a code on a call proves nothing between people who have never met.
> Component 3 can't check card keys, so a swapped card is
> caught only at the in-person meeting.

Evaluated and shelved: PAKE / wormhole codes (interactive, and CryptoKit
exposes no PAKE primitive — building one means rolling our own crypto);
key-transparency logs and Keybase-style social proofs (require
servers/accounts — "zero servers, zero accounts" is the brand). Key-in-bundle
rejected outright — see H5.

Also rejected (2026-07-18 second-opinion review): **deliberately degraded
crypto (no FS/PQ) as an unverified-tier signal** — trust level is label
metadata, never a reason to weaken the cipher suite; that is key-in-bundle's
mistake in softer form. And **a separate "Occulta Lite" app** — splitting
the product doubles the maintenance surface and ships a weaker app under
the same name, the worst possible positioning.

### P2

**Switch distribution from broadcast to scrutiny.**
Publish a written protocol spec, post the mechanism (UWB proximity gating as
key distribution) to HN / r/netsec, and explicitly invite security researchers
to break it. One credible public critique thread outweighs a year of LinkedIn
cadence. (H3)

**Seed adoption where people already stand 25 cm apart.**
Security meetups, conferences, offices, small firms — the modern key-signing
party. "Everyone exchange keys at the meetup" turns the in-person constraint
into an event and batches the two-sided install problem into one room. (H3)

### P3

**Sequence the market honestly.**
iOS-only + U1-only + in-person-only means the addressable market today is
small and technical. Win that audience first; their public vouching is what
later convinces the general audience. Broad-audience persuasion before that
is the wrong order. (H4)

**Hallway testing.**
Watch five real pairs attempt a cold key exchange — phones out, no coaching.
This report predicts what you will see; direct observation will confirm the
priority order above without compromising the no-telemetry stance.

**Trivial: flip feature flags.**
`enableShamirShardSharing` has since been flipped to `true`; `signature` is
still `false` in `features.plist`, hiding the signing tab. One-line change
whenever that feature is ready to ship — unrelated to the sweeps above,
doesn't need to wait on them.

---

## Summary

| # | Finding | Severity | Type | Addressed by | Status |
|---|---------|----------|------|--------------|--------|
| C1 | Zero value at install | Critical | assessment | Sweep 3 | ✅ Resolved — capability already existed (vault notes), onboarding now signposts it |
| C2 | Exchange failure modes (silent save, watchdog, gates) | Critical | code | Sweep 1, Watchdog recovery | ✅ Fixed — silent save and watchdog recovery both resolved |
| C3 | No retention trigger | Critical | code | Sweep 2 | 🟡 Shard acknowledgement resolved; history, inbox, notifications, rotation UI still open |
| H1 | Composition state loss | High | code | Sweep 2 | ✅ Fixed — drafts persist via `DraftStore`, flushed on disappear and on background |
| H2 | Inbound delivery silent failure | High | code | Sweep 1, Sweep 2 | 🟡 Messaging already existed; landing place (inbox) still open |
| H3 | Distribution channel mismatch | High | assessment | Distribution to scrutiny, Seed adoption | ⬜ Open |
| H4 | Competing with "good enough" (Signal) | High | assessment | Distribution to scrutiny, Sequence market honestly | ⬜ Open |
| H5 | Encryption hard-gated on verification; no first-contact messaging | High | assessment | Sweep 4 | ⬜ Open — key-in-bundle rejected; two decisions pending (introductions; send-capable vs import-only) |
| M1 | Silent contact save failure | Medium | code | Sweep 1 | ✅ Fixed |
| M2 | Encrypt/send lacks feedback | Medium | code | Sweep 1 | ✅ Fixed — progress indicator added; the app hop remains, by design |
| M3 | Skippable onboarding hides UWB requirement | Medium | code | Sweep 3 | ✅ Fixed — Skip removed |

Key exchange remains hardware-gated, proximity-gated, and permission-gated —
inherent to the UWB approach, not fixable in code. Sweep 4 reframes what that
gate has to gate: verification, not encryption — the trust ladder lets an
encrypted first message flow before any meeting, while UWB stays the top
assurance tier. But the two failure modes
that were silent (save failing invisibly on success, timeout dismissing with
no explanation) are now loud instead: explicit save states with retry, and an
in-app banner with one-tap retry on timeout. It was also the demo, the
onboarding, and the growth loop, which is why this was P0. Sweep 1 is now
closed out, and drafts survive backgrounding. Next: a reason to return —
message history, an inbox, and a notification hook are what remain of Sweep 2;
then earn credibility in public rather than asserting it in broadcast.

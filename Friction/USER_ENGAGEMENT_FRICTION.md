# User Engagement Friction Report

Findings organized by severity, with prioritized recommendations.
Each finding is tagged **[code]** (derived from source, file:line cited) or
**[assessment]** (strategic analysis of adoption dynamics).

Original fact-based audit: 2026-04-30.
Updated 2026-07-12: line references re-verified against current source, adoption-level
findings added, document reorganized by severity and priority.
Updated 2026-07-17: encryption-before-verification analysis added (H5, Sweep 4) —
evaluated ways to message before a physical key exchange; key-in-bundle rejected.

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

The first moment of value requires a second person, physically present, with an
iPhone 11+ (U1 chip), the app already installed, two system permissions granted,
standing within 25 cm, inside a 30-second watchdog window. Six multiplied
conditional probabilities precede any experience of the product. There is no
single-player value: an installed app with zero contacts can do nothing for its
owner. No positioning or marketing survives this funnel shape.

Note: the existing `Occulta/Features/Vault/` directory is Shamir shard custody
for backup keys — it is not a personal encrypt-to-self vault and does not
provide single-player value.

### C2. Key exchange failure modes [code]

The exchange is simultaneously the product demo, the onboarding, and the growth
loop — and it is the highest drop-off point. A failed exchange loses two users
at once, in person. Compounding gates:

- **Silent key save failure on success.** The Confirm button's catch block is
  empty (`ExchangeResult.swift:132–136`):

  ```swift
  Button("Confirm") {
      do {
          try self.contactManager?.update(key: self.key, for: self.identifier)
      } catch { }
      self.exchangeManager?.confirm()
  ```

  If the update throws, the exchange appears to succeed but the contact has no
  key. The one magic moment can invisibly produce a dead contact — fatal to
  word of mouth for a product whose promise is reliability of identity.

- **Hardware gate.** `isExchangePossible` checks
  `NISession.deviceCapabilities.supportsPreciseDistanceMeasurement`. Failure
  renders red text — "Device must have UWB chip" — with no alternative path.
  iPhone X and earlier (and non-U1 models) are permanently blocked.

- **Watchdog with a 3-step hardware recovery.** A 30-second
  `DispatchSourceTimer` fires `.timedOut` if no NI updates arrive
  (`Exchange+Manager.swift:240–254`). The recovery flow requires both
  participants, simultaneously, to: toggle Settings → Privacy → Location
  Services → System Services → "Networking & Wireless" off/on, restart both
  devices, and retry.

- **Permission friction.** Two iOS system dialogs (Nearby Interaction, Local
  Network) interrupt the flow before exchange can proceed.

- **Physical constraint.** Both devices must be ≤ 25 cm apart, enforced in the
  NI update handler (`Exchange+Manager.swift:614`).

- **Required Diceware confirmation.** The key is only saved after a manual
  verbal comparison and Confirm tap — no timeout, no skip. (Security-required,
  but it sits inside the same fragile window.)

### C3. No retention trigger [code]

Nothing brings a user back after install:

| Missing capability | Evidence |
|---|---|
| Message history | `ComposableMessage` uses `@State var messages` — resets on every view appearance |
| Inbox | No persisted inbound message store in any model |
| Notifications | No `UNUserNotificationCenter` usage found |
| Key rotation UI | Documented as unresolved in `OccultaApp.swift` |
| SSS shard acknowledgement | `TODO Phase 2` in `ShardCustody+Manager.swift` — every `ShardRecord` stays `.sent` permanently |

Every session is stateless from the user's perspective. Adoption is retention
compounding; there is currently nothing to retain.

---

## High severity

### H1. Composition state loss [code]

Messages are not persisted during composition (`@State private var messages`).
A phone call, app switch, or screen timeout silently destroys all unsaved
content. There are no drafts.

### H2. Inbound delivery can silently fail [code]

Delivery routes through `ShareExtension → app group container → URL scheme
occulta://inbound?session=<uuid>` (`ShareViewController.swift:486`). If the
URL scheme fails, the file is written to the container with no fallback. The
recipient must already have the sender as a contact with an active key; if
not, `buildOwnedBasket` fails and there is no "sender not found" message in
the inbound flow.

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
cannot be encrypted to at all (`buildOwnedBasket` throws
`noPublicKeyToEncryptWith`, `Contact+Manager.swift:1414`). Every gate in
C1/C2 is therefore multiplied into the messaging funnel: nobody can receive a
first message until they have stood within 25 cm of the sender. Signal,
WhatsApp, and Threema all encrypt fully for unverified contacts and treat
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

Save errors in the contact form produce no user-facing feedback
(`Contact+Form.swift:209` — `TODO: Display a warning that a contact could not
be saved`). The contact appears unsaved with no explanation.

### M2. Encrypt-and-send friction [code]

After composing, the user taps "Encrypt," waits on async processing with no
progress indicator, then must manually route the `.occ` file to the recipient
through a separate app via `UIActivityViewController`. Channel-agnostic
delivery means every send costs an extra app hop. (The mechanism is the
security model; the missing feedback is not.)

### M3. Skippable onboarding hides the core requirement [code]

Onboarding is 4 screens with a "Skip" button visible from screen 1
(`OnboardingView.swift`). Screen 2 introduces the 25 cm UWB requirement —
skip users never see it. First post-onboarding interaction is an empty
contacts list with no guidance.

---

## Low severity / contextual

- **Hidden features via flags** [code]: `enableShamirShardSharing` and
  `signature` are `false` in `features.plist` — SSS and the signing tab are
  invisible to users.
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
| Encrypt/send | No progress indicator during async processing | ⬜ Open |
| Inbound delivery | Already handled — `noPublicKeyToEncryptWith` surfaces "message was not addressed to you" (`OccultaApp.swift:487–489`, thrown from `Contact+Manager.swift:1414`) | ✅ Already existed — not a gap |

Note: the two `ExchangeResult.swift` / `Contact+Form.swift:209` citations above were dead
v1 code by the time this was fixed — the live bugs were in `KeyExchange.swift` and
`ContactFormV2.swift` respectively. Both files were confirmed via `OccultaApp.swift`'s
tab wiring before fixing.

Remaining Sweep 1 work: encrypt/send progress feedback only.
Highest-ROI work available: every failed exchange loses two users in person,
and every silent failure poisons word of mouth.

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

**Sweep 3: Onboarding redesign incorporating single-player value.**
M3 (Skip hides the 25 cm UWB requirement) and C1 (zero value at install)
touch the same screens. Rework onboarding once: add an encrypt-to-self
personal vault so the app has day-one value with zero contacts, and use the
same redesign to stop Skip from hiding the hardware requirement it currently
hides from screen 1. Doing these separately means reworking onboarding twice.
(New feature — the existing Vault directory is shard custody, not this.)

**Sweep 4: Trust ladder — encryption before verification.** (H5; structural
relief for C1/C2's funnel shape)
Unverified contacts get real encryption immediately; verification tiers
upgrade *authenticity*. Threat frame: passive readability by any bundle
carrier must be impossible; an active MITM at first contact is the managed
residual, shrunk by each tier climbed. UWB stays the top tier unchanged.

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

Evaluated and shelved: PAKE / wormhole codes (interactive, and CryptoKit
exposes no PAKE primitive — building one means rolling our own crypto);
key-transparency logs and Keybase-style social proofs (require
servers/accounts — "zero servers, zero accounts" is the brand). Key-in-bundle
rejected outright — see H5.

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
`enableShamirShardSharing` and `signature` are `false` in `features.plist`,
hiding SSS and the signing tab. One-line change whenever those features are
ready to ship — unrelated to the sweeps above, doesn't need to wait on them.

---

## Summary

| # | Finding | Severity | Type | Addressed by | Status |
|---|---------|----------|------|--------------|--------|
| C1 | Zero value at install | Critical | assessment | Sweep 3 | ✅ Resolved — capability already existed (vault notes), onboarding now signposts it |
| C2 | Exchange failure modes (silent save, watchdog, gates) | Critical | code | Sweep 1, Watchdog recovery | ✅ Fixed — silent save and watchdog recovery both resolved |
| C3 | No retention trigger | Critical | code | Sweep 2 | ⬜ Open |
| H1 | Composition state loss | High | code | Sweep 2 | ⬜ Open |
| H2 | Inbound delivery silent failure | High | code | Sweep 1, Sweep 2 | 🟡 Messaging already existed; landing place (inbox) still open |
| H3 | Distribution channel mismatch | High | assessment | Distribution to scrutiny, Seed adoption | ⬜ Open |
| H4 | Competing with "good enough" (Signal) | High | assessment | Distribution to scrutiny, Sequence market honestly | ⬜ Open |
| H5 | Encryption hard-gated on verification; no first-contact messaging | High | assessment | Sweep 4 | ⬜ Open — key-in-bundle shortcut rejected |
| M1 | Silent contact save failure | Medium | code | Sweep 1 | ✅ Fixed |
| M2 | Encrypt/send lacks feedback | Medium | code | Sweep 1 | ⬜ Open |
| M3 | Skippable onboarding hides UWB requirement | Medium | code | Sweep 3 | ✅ Fixed — Skip removed |

Key exchange remains hardware-gated, proximity-gated, and permission-gated —
inherent to the UWB approach, not fixable in code. Sweep 4 reframes what that
gate has to gate: verification, not encryption — the trust ladder lets an
encrypted first message flow before any meeting, while UWB stays the top
assurance tier. But the two failure modes
that were silent (save failing invisibly on success, timeout dismissing with
no explanation) are now loud instead: explicit save states with retry, and an
in-app banner with one-tap retry on timeout. It was also the demo, the
onboarding, and the growth loop, which is why this was P0. Next: encrypt/send
progress feedback closes out Sweep 1; then day-one value and a reason to
return (Sweep 2); then earn credibility in public rather than asserting it in
broadcast.

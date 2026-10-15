# Consumer Opening & Ceremony Redesign — Analysis

Analysis date: 2026-07-22.
Source: an external consumer go-to-market strategy memo ("the memo"), analyzed
against [USER_ENGAGEMENT_FRICTION.md](USER_ENGAGEMENT_FRICTION.md) and previously
recorded product decisions. This document extracts the memo's claims, assesses
each, corrects one load-bearing security assumption, and catalogs key exchange
ceremony redesign concepts with their real security properties.

Cross-references use the friction report's finding IDs (C1–C3, H1–H5, M1–M3)
and sweep numbers.

---

## 1. The memo's thesis

1. **A consumer opening exists now.** Passkey fatigue ("which device has my
   passkey?"), high-profile account takeovers despite MFA (SIM swaps, SS7,
   authenticator phishing), and mainstream privacy awareness converge into a
   receptive audience for "proof that is physical."
2. **The ceremony is the guarantee and the obstacle, inseparably.** The fix is
   not weakening the ceremony but finding moments where physical proximity is
   already natural: first day at work, family gatherings, dates, concerts,
   Airbnb check-ins. In those moments two iPhones are already within UWB range
   and the ceremony costs seconds.
3. **Lead with identity, not auth.** Auth is invisible infrastructure; contacts
   are emotional and social. The consumer pitch is "the person you're talking
   to is actually them," not "secure login." Auth extends from identity later.
4. **Tiered trust.** Tier 1 casual exchange (≤10 s, no Diceware, single
   visual/audio confirmation) for new contacts and events; Tier 2 verified
   exchange (current UWB + Diceware) for trusted relationships and auth.
5. **A Cash-App-style viral moment is required.** Both people need the app;
   the wedge moment must be compelling enough that one person asks the other
   to install on the spot. The loop: someone receives something through
   Occulta they couldn't receive any other way.
6. **iMessage/SMS fallback for one-sided use.** A non-user receives a link to
   a one-time web view verifying "this message was signed by this key,
   established in person on [date]"; installs to reply.
7. **Apple/Google are not needed to start.** UWB and SE hardware are already
   deployed at scale. Platform cooperation (Contacts integration,
   `ASCredentialProviderExtension` placement, system-level tap-to-exchange)
   matters only at scale, after demonstrated traction. Dedicated hardware is
   premature for consumers.
8. **GTM arc.** Phase 1: privacy-first consumers (ProtonMail/Signal/1Password
   payers). Phase 2: professional verticals (lawyers, journalists, advisors,
   healthcare) where professional obligation legitimizes the install ask.
   Phase 3: mainstream, pitched as "Tap phones. Know it's really them.
   Forever."

---

## 2. Assessment of each claim

| # | Claim | Verdict | Notes |
|---|-------|---------|-------|
| 1 | Consumer opening exists now | Plausible, unproven | Consistent with H4: argument alone doesn't beat "good enough" — the opening is a hypothesis until expert vouching and a visibly working product exist |
| 2 | Wedge = moments where proximity is already natural | **Strong** | Same insight as P2 "seed adoption where people already stand 25 cm apart"; the memo generalizes it from events to everyday social moments |
| 3 | Identity first, auth second | **Strongest idea in the memo** | Matches what Occulta already is (a contact book); "know it's really them" is feelable in a way auth is not |
| 4 | Tier 1 casual / Tier 2 verified | Right instinct, wrong mechanism | The memo assumes short verification = weak verification and drops it entirely for Tier 1. Wrong — see §4. Also partially reinvents Sweep 4's trust ladder, which is already specced with more rigor |
| 5 | Viral install moment required | Correct diagnosis | This is C1 (zero value at install) + the two-sided cold-start problem, restated from the growth side |
| 6 | SMS/web-view fallback | **Reject as written** | See §3 — conflicts with two recorded decisions |
| 7 | Don't need Apple/Google to start | Mostly right | But "UWB in most modern Android flagships" overstates reach: Occulta is iOS/NearbyInteraction-only and no Apple↔Android UWB interop path exists today. Android is a roadmap item, not an asset |
| 8 | GTM arc privacy-first → verticals → mainstream | Aligned | Same ordering as P3 "sequence the market honestly"; Phase 2's "my firm requires verified contact exchange" is a genuinely new mechanism worth keeping |

---

## 3. Conflicts with recorded decisions

- **SMS/web-view fallback (memo #6) contradicts two standing constraints.**
  (a) A verification web view requires hosting — "zero servers, zero accounts"
  is the brand, and server-dependence was the recorded reason key-transparency
  logs and Keybase-style proofs were shelved (Sweep 4, evaluated-and-shelved).
  (b) A durable out-of-app verification artifact is a standing "I use Occulta"
  trace — the same forensic-cleanliness concern already flagged for publicly
  posted contact cards. The cold-start problem the fallback targets is already
  solved serverlessly by Sweep 4's contact cards (component 1).
- **No new vouching surface.** The memo stays clear of third-party key
  vouching — consistent with the recorded no-self-vouching line for own-device
  keys. The "introductions" question (Sweep 4, component 4) remains the open
  product-owner call it already was; nothing in the memo moves it.
- **Tier 1 as specified would violate the Sweep 4 badge invariant** ("nothing
  about a lower tier may render green/secure") only if casual exchanges were
  displayed identically to full-Diceware exchanges. §6 keeps them distinct.

---

## 4. Technical correction: short SAS under hash commitment is sound

The memo's Tier 1 drops verification because it assumes a short check is a
weak check. That assumption is false for commitment-based short authentication
strings (SAS), and the correction reshapes the whole Tier 1 design space.

**The mechanism (ZRTP-style).** Both sides cryptographically commit to their
key material *before* revealing it. A man-in-the-middle must choose its keys
before learning what SAS the honest parties will see, so it gets **exactly one
blind guess** — there is no offline grinding. Security per attempt is simply
2^-bits of the compared string, and a failed guess produces a visible mismatch
(loud detection), which is fatal for an attacker who must MITM the same pair
repeatedly.

**Consequences:**

- 1 Diceware word ≈ 12.9 bits → ~1 in 7,776 per-attempt MITM success.
- 3–4 emoji from a curated 64-glyph set ≈ 18–24 bits → ~1 in 260k to 1 in 16M.
- A generative image encoding ~20 recognizable bits is in the same range.
- ZRTP ships with a 2-word SAS; Matrix/Element ships 7 emoji. Both are
  production precedents for glance-level verification.

**The real design space is therefore "shrink the comparison to a 2-second
glance," not "Diceware vs. nothing."** Tier 1 keeps genuine MITM resistance at
near-zero friction. The memo's own Tier 1 suggestion (a single shared color)
is strictly worse: a few bits at best and colorblind-hostile.

**Implementability note.** Hash commitment is plain hashing — CryptoKit
covers it. This is unlike PAKE, which was shelved (Sweep 4) precisely because
CryptoKit exposes no PAKE primitive and building one means rolling our own
crypto. No such objection applies here.

---

## 5. Ceremony concepts catalog

Current ceremony: UWB ranging to ≤25 cm → key exchange → verbal Diceware
comparison → manual Confirm. The concepts below either replace the Diceware
comparison at Tier 1 or wrap the ceremony in a better gesture. Each is
classified by its **real** security contribution:

- **SAS** — genuine short-authentication-string comparison (MITM detection)
- **Channel binding** — ties the exchange to a shared physical event a remote
  attacker cannot reproduce
- **Distance bounding** — tightens the proximity requirement (relay margin)
- **Theater** — no security contribution; UX/emotional value only (must never
  be presented as verification)

Ranked roughly by (delight × real security) per second of friction:

| Concept | How it works | Time | Security class | Why people would enjoy it | Failure modes / cautions |
|---|---|---|---|---|---|
| **Matching bloom** | Both screens render the same generative art (aurora/mandala) derived from the session hash. Hold side by side, glance, tap. | ~3 s | SAS (~20+ recognizable bits; precedent: OpenSSH randomart, identicons) | Comparing one picture is instant; mismatches jump out; beautiful enough that screenshots market themselves | Needs a visual-hash design validated for human discriminability; low-vision users need the audio/haptic alternative |
| **Puzzle seam** | Each phone shows half of a pattern; held edge-to-edge the image continues across the seam only if hashes match. | ~3 s | SAS + physically enforces adjacency | Self-verifying — a broken seam is unmissable; the "click together" metaphor *is* the product promise | Requires both users to physically align devices; awkward with cases of very different thickness |
| **Emoji triad** | Both screens show the same 3–4 emoji from a curated 64-glyph set (Matrix's proven model). | ~2 s | SAS (~18–24 bits) | Zero reading aloud, language-independent, friendly rather than cryptographic | Curate for cross-cultural distinctness; avoid visually confusable pairs |
| **Duet chime** | Both phones play the same short SAS-derived melody — in sync it sounds like one doubled instrument; mismatch is audibly dissonant. Success = tap-to-pay-style chime. | ~3 s | SAS (audio); major accessibility win (VoiceOver users) | Sound is the emotional language of "it worked" (AirDrop whoosh, Apple Pay ding) | Useless in loud environments; must fall back to a visual SAS, not to nothing |
| **Cheers gesture** | Raise phones together like clinking glasses; correlated accelerometer spike + UWB range closing commits the exchange. Both devices sign the shared motion signature. | ~2 s | Channel binding (Bump-style) — a remote MITM cannot reproduce the shared physical jolt | Turns the ceremony into a toast — a gesture people already make at exactly the moments the memo lists (dates, dinners, celebrations) | Not an SAS — pair with one; motion correlation thresholds need tuning against false accept/reject |
| **Distance dial** | UWB ranging as the interaction: a ring tightens as phones approach and "locks" with a haptic snap at <10 cm. | ~4 s | Distance bounding — tightens the 25 cm gate to 10 cm, shrinking relay-attack margin | Makes the invisible security parameter (distance) the game; satisfying physical closure | Transport-layer only; verification still needs an SAS on top |
| **Haptic heartbeat** | Phones back-to-back; both play the identical secret-derived haptic rhythm into each palm; confirm with a lock-click haptic. | ~5 s | Weak standalone SAS (humans compare rhythm poorly — few effective bits) | Completely silent and private — no announcing a ceremony in a café; fits the discretion-sensitive persona | Use only as a confirmation layer over a visual SAS; presenting it as primary verification would be theater |
| **Moment seal** (post-exchange) | Optional: both phones co-sign a local-only timestamped note ("Met at WWDC · 22 Jul 2026") hashed into the contact record. | +3 s, opt-in | Theater for MITM purposes, but gives humans a memorable anchor for later key-change review ("I verified Bob in person in July") | The exchange produces a keepsake — the emotional artifact the memo's viral loop needs | **Must be local-only and opt-in** — a durable "Occulta exchange" artifact is a forensic-cleanliness risk if it leaves the device |
| **Diceware Lite** | Tier 1 shows **one** word pair in huge type ("VELVET FALCON"); each glances at the other's screen; no reading aloud. | ~3 s | SAS (~13 bits; sound under commitment, §4) | Minimal change from today's ceremony; cheapest concept to ship | Lowest delight of the set; a stepping stone, not the destination |

---

## 6. Recommended tier mapping

Refines the memo's Tier 1/Tier 2 into the Sweep 4 trust ladder rather than
adding a parallel scheme:

| Rung | How keys arrived | Verification | Notes |
|---|---|---|---|
| **Verified (full)** | UWB, in person | Verbal Diceware comparison (current ceremony, unchanged) | Top tier; required for auth-provider registration and sensitive relationships |
| **Verified (casual)** — *new rung* | UWB, in person | Glance-level commitment-based SAS (bloom / emoji / seam), optionally triggered by the cheers gesture, sealed by the duet chime | Physically present + UWB + one-shot SAS: stronger than Confirmed (remote SAS) because presence is proven; below full Verified only in comparison rigor |
| Confirmed | Remote | SAS over a live call | Sweep 4, unchanged |
| Introduced | Forwarded by verified mutual | Signed forwarding | Sweep 4, still gated on the open vouching decision |
| Unverified | Contact card / TOFU | None yet | Sweep 4, unchanged |

Composition of a casual exchange: **Cheers gesture** (trigger + channel
binding) → **Distance dial** lock at <10 cm (transport) → **Matching bloom**
or **Emoji triad** (the actual SAS) → **Duet chime** (success feedback) →
optional **Moment seal**. Total ≈ 8–10 s, every second of which contributes
either security or felt delight — nothing in the flow is a form.

Invariants carried over from Sweep 4:

- The tier is a **persistent per-contact badge** (contact list, compose,
  send) — never a one-time dialog.
- Casual never silently renders as full Verified (see open decision D3).
- Trust level is label metadata only — the cipher suite is identical at every
  rung.

---

## 7. Open decisions

| ID | Decision | Status |
|---|---|---|
| D1 | Introductions: does third-party key forwarding by a verified mutual cross the no-vouching line? | Pre-existing (Sweep 4 item 4); unchanged by this analysis |
| D2 | Unverified tier: send-capable (Threema model) vs import-only | Pre-existing (Sweep 4 second open decision); unchanged |
| D3 | **New:** does "Verified (casual)" get its own badge, or collapse into "Verified" with metadata? Security difference is comparison rigor only; both defeat MITM with high probability | Open — product call; the Sweep 4 badge invariant argues for distinct rendering |
| D4 | **New:** which SAS format for the casual rung — matching bloom, emoji triad, or Diceware Lite? | Open — candidate for hallway testing (P3); bloom and emoji are the front-runners on delight × security |

---

## 8. Roadmap and positioning implications

- **Hallway testing (P3) should test ceremony concepts, not just the current
  flow.** Five cold pairs attempting the casual ceremony variants answers D4
  with direct observation, consistent with the no-telemetry stance.
- **The identity-first framing sharpens all messaging.** "Tap phones. Know
  it's really them. Forever." is the consumer pitch; "secure login" and
  "cryptographic key exchange" are not. This aligns with, and should feed,
  the distribution-to-scrutiny work (P2) — the HN/r/netsec audience gets the
  protocol spec; consumers get the sentence.
- **Phase 2 verticals add a new install mechanism** worth recording:
  professional obligation ("my firm requires verified contact exchange")
  legitimizes asking a counterparty to install — a wedge the friction report's
  meetup/conference seeding (P2) doesn't cover.
- **Platform asks are sequenced, not prerequisites.** Build the
  `ASCredentialProviderExtension` and Contacts-adjacent experience toward a
  partnership conversation; do not gate consumer work on it. Dedicated
  hardware remains premature for consumers (an extra thing to carry kills
  adoption before value is felt).
- **Rejected from the memo:** the SMS/web-view fallback (§3) and treating
  Android reach as near-term (§2, claim 7).

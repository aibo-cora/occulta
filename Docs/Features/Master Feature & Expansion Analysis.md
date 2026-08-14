# Occulta — Master Feature & Expansion Analysis
**Date:** May 10, 2026
**Revised:** July 4, 2026
**Sources:**
- Feature Discovery Report, Apr 30, 2026
- Feature Discovery Report, May 9, 2026
- Expansion Opportunity Analysis, May 2026
- Critical review session, May 13, 2026
- Authentication pain-point research pass, June 12, 2026 (features 15–17; web-sourced demand evidence verified against the codebase)
- Feature ideation pass, July 4, 2026 (features 18–25; new Expansion I; checked against the public wiki's Threat Model and Security Properties pages — linked from `README.md:113-114`, not tables in the README itself — `Occulta/Features/Features.swift` (`FeatureFlags`), the identity-challenge domain-separation mandate as it exists in `IdentityChallenge+Constants.swift:10-12`, the in-code `CRYPTO_REVIEW_CHECKLIST` blocks in `ShamirSecretSharing.swift` and `Key+Manager.swift`, and `Occulta/Features/ShareExtension/SHARE_EXTENSION_PLAN 16.32.42.md`) <br>**[Provenance corrected 2026-08-09]** — this entry previously cited `CRYPTO_REVIEW_CHECKLIST.md`, `IDENTITY_CHALLENGE_PROTOCOL.md` and `CODE_GENERATION_GUIDELINES.md` as documents consulted. None existed on that date; no commit in any branch has ever touched the latter two paths. The first two named real conventions that lived only in code comments, and are relisted above by their actual locations — `CRYPTO_REVIEW_CHECKLIST.md` has since been written from those blocks (`Docs/Audit/`, 2026-08-09). `CODE_GENERATION_GUIDELINES.md` had and has no counterpart anywhere and is removed rather than relocated. The rulings for features 18–25 and Expansion I are unaffected in substance — the conventions cited were real — but the pass did not consult three documents, and said it did.
- Community demand pass, July 10, 2026 (features 26–28; re-prioritisation of #21 and Expansion H; web-sourced demand evidence — FBI IC3 2025 report, FTC elder-fraud data, Chat Control reinstatement (Jul 9), KOSA House passage (Jun 29), DV-advocacy evidence guidance; full research: `Feature Ideation — 2026-07-10 Community Demand Pass.md`)

**Scope:** Unified ranking of consumer app features and platform expansion opportunities, sorted by potential audience reach and community demand.

---

## Overview

This document synthesises three independent research passes into a single prioritised view. It is structured in two sections:

**Section 1 — Consumer App Features:** Additions to the existing Occulta iOS app. Ranked by community demand and addressable user base.

**Section 2 — Platform Expansion Opportunities:** Uses of Occulta's trust primitive beyond the personal privacy app. Ranked by market size and defensibility.

**Section 3 — Cross-cutting observations:** Overlaps, synergies, and a combined priority matrix.

---

## The Shared Foundation

Both sections derive their value from a single architectural property worth naming explicitly:

> Occulta's contact book is the only identity graph on any platform where every entry was established by physical proximity (≤ 25 cm, UWB-measured) and is bound to a hardware-protected private key that has never left the Secure Enclave. No remote compromise path. The only attack surface is physics.

Every consumer feature and every expansion opportunity is, at its core, a different use of this trust primitive.

---

# Section 1 — Consumer App Features

Features are de-duplicated across both reports. Where both reports independently propose the same concept, that is noted as a corroboration signal and weighted accordingly.

---

### 1. P2P Basket Delivery via Wi-Fi Aware
**In both reports** (Apr: Feature 2 · May: Feature 1)
**Community demand:** Very high — SimpleX GitHub #1501/#2935, HN #43363031, 9to5Mac, Privacy Guides, Kaspersky mesh blog
**Audience:** Broad — journalists, conference attendees, activists, any two people in the same building without internet

Use iOS 26's Wi-Fi Aware framework as a high-throughput, serverless transport for basket delivery between verified contacts in range (~100 m). The UWB Diceware ceremony remains the mandatory trust gate for initial key exchange; Wi-Fi Aware handles delivery at up to 250 Mbps with no access point, no cloud, and double-layer encryption (basket AES-GCM + link-layer Wi-Fi encryption). Falls back to Multipeer Connectivity (Bluetooth + peer Wi-Fi, ~2–4 Mbps) on iOS 15–25.

Briar is the Android gold standard for this model and is explicitly Android-only. iOS has no equivalent. The community knows this gap exists and is actively waiting for it to be filled. iOS 26's Wi-Fi Aware framework is the first time the platform primitives have been available to third-party apps.

**iOS constraint:** Wi-Fi Aware requires iOS 26. Background delivery of large files likely requires user confirmation; small notification-like baskets may deliver silently via Multipeer background mode.

> **Ruling (May 2026):** Removed. Baskets already travel as `.occ` files through the iOS share sheet, which the share extension handles. When two users are physically co-located, AirDrop over local Wi-Fi covers the transport without routing through any server — the privacy delta is marginal. Proximity basket delivery adds UX polish for an edge case that is already solved, not a capability gap, and does not expand the audience. If a direct in-app send experience is ever warranted, it should be built on MultipeerConnectivity (available today on iOS 16) rather than waiting for a Wi-Fi Aware API.

---

### 2. Offline Travel Mode (Cryptographic Vault Concealment)
**In both reports** (Apr: Feature 3 · May: documented gap vs. 1Password)
**Community demand:** Very high — Freedom of the Press Foundation 2026 checklist, r/privacy, r/privacyguides, journalist security forums, multiple border-crossing threads
**Audience:** Broad — anyone who crosses a border with a device; business travelers, lawyers, students, journalists, activists

Cryptographically removes designated contacts and vault items from the device ahead of a high-risk inspection or device-handover scenario. Not a UI hide — the item keys are re-encrypted under a separate travel passphrase and all other Keychain access paths are deleted. Under the primary credential, the sensitive items simply do not exist. Deactivation requires both the travel key and the original credential. Entirely offline — no network dependency at the moment of use, unlike existing solutions.

This gap is well documented in community discussion of existing tools: 1Password's Travel Mode is the current go-to recommendation, but it requires an online session to toggle — exactly when users are least likely to have connectivity or time. No app currently offers a fully offline equivalent.

**iOS constraint:** All operations are Keychain writes and deletes. `item_key = HKDF(travel_key, item_id)`; deleting the travel_key Keychain item makes all sensitive items inaccessible while the main vault remains functional. CryptoKit HKDF supports this architecture directly.

> **Ruling (May 2026):** Holds up. Broadest new audience of any feature on this list — the border-crossing use case is not niche. 1Password's online-only requirement is a documented, widely-complained-about gap. Architecture is correct and fully within iOS capabilities. **Priority 1.**

---

### 3. Cryptographic Panic Wipe
**In Apr report** (Feature 1) · **Reinforced in May** (Spyware context, Theme 2.G)
**Community demand:** High — Citizen Lab Paragon Graphite report (Jan 2025), TechCrunch spyware coverage (Dec 2025), r/privacy
**Audience:** Medium-broad — elevated post-Graphite: journalists, activists, lawyers, and anyone who has read about mercenary spyware

Sub-second, irreversible key destruction that renders all Occulta data permanently unreadable without deleting any files. A two-layer key hierarchy: all vault and basket keys are wrapped by a Keychain item (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`). Triggering a Panic Wipe calls `SecItemDelete` on that item; every encrypted blob becomes indistinguishable from random bytes instantly and without a forensic footprint from file deletion. The SE identity key survives for future use. An optional decoy vault can be configured to surface when the panic credential is entered.

The Paragon Graphite incident (January 2025, iOS 18.2.1) moved this from theoretical to documented and mainstream-covered. The audience for this feature expanded significantly post-Graphite.

**iOS constraint:** SE keys cannot be deleted on demand; the architecture must use a deletable Keychain item as the vault-wrapping layer, not the SE key directly. The SE identity key is intentionally left intact.

> **Ruling (May 2026):** Holds up. The deletable wrapping key layer is an architectural prerequisite — vault and basket keys must be re-wrapped under a single deletable Keychain item before the wipe can work. That key hierarchy change should be scoped as its own task. Once it exists, the wipe itself is trivial. Do not bundle the decoy vault into v1. **Priority 2.**

---

### 4. Hardware Security Key (YubiKey NFC) as Vault Second Factor
**In both reports** (Apr: Feature 4 · May: Feature 2)
**Community demand:** High — Strongbox 1.60.x ships it, KeePassium ships it, r/netsec, privacy community
**Audience:** Medium — enterprise professionals, lawyers, journalists with source material, security researchers, and anyone already using YubiKeys elsewhere

Optional enrollment of a hardware FIDO2/HMAC-SHA1 token as a vault second factor. `vault_key = KDF(SE_identity_key, hardware_key_response)`. Neither factor alone is sufficient. Defends against biometric coercion ("rubber hose" scenario): an adversary who forces a fingerprint still cannot access the vault without physical possession of the hardware key. Optional challenge-response caching (à la Strongbox) balances security against friction for everyday use.

Two competing apps (Strongbox, KeePassium) already ship hardware key support — it is table stakes for the KeePass-compatible security community and a known audience expectation.

**iOS constraint:** CoreNFC (iOS 13+) supports YubiKey HMAC-SHA1 challenge-response. NFC is the recommended approach for broad compatibility (YubiKey 5Ci Lightning is limited to iPhone 14 and earlier; USB-C YubiKeys work on iPhone 15+). FIDO2 via `ASAuthorizationController` handles the full assertion flow without third-party SDK dependency for that path.

> **Ruling (May 2026):** Skip for now. Occulta's SE key is already hardware-bound — the threat YubiKey adds defense against (biometric coercion) is better and more broadly addressed by Panic Wipe and Travel Mode. Strongbox and KeePassium need YubiKey because their vault key is software-derived; Occulta's is not. The audience of "Occulta users who also own YubiKeys" is a niche within a niche. Revisit if the user base demonstrably demands it.

---

### 5. On-Device Contact Compromise Detection
**In May report** (Feature 7) · **Corroborated by Apr** (Signal GitHub issues #991, #1914, iMessage CKV rationale)
**Community demand:** High — years of Signal user confusion, Privacy Guides CKV threads, r/privacy
**Audience:** All Occulta users with verified contacts — this is a baseline security guarantee, not a niche feature

Stores a cryptographic record of each contact's public key, verification method (UWB / QR / manual), and last-verified timestamp. If a key changes outside Occulta's signed key rotation protocol, the app immediately flags it: "Key changed without signed rotation — re-verify before sending." Entirely on-device. No key transparency server required.

Signal's documented failure to resolve the "key changed vs. MITM attack" UX confusion spans years and multiple GitHub issues. Occulta can solve this cleanly within its local-first architecture: because every key was established in person, any unsigned change is unambiguously anomalous.

**iOS constraint:** Detection depends on the signed key rotation protocol (already planned). False positives occur when a contact reinstalls Occulta without performing a signed rotation — UX must clearly distinguish "key changed, no rotation signature received" from "signed rotation accepted."

> **Ruling (May 2026):** Removed. This solves Signal's problem, not Occulta's. Signal needs key-change detection because keys are distributed through a server that can be silently compromised. In Occulta, keys are established via UWB at ≤25 cm — there is no server to compromise. If a contact's key changes (e.g. new phone), communication breaks immediately and obviously; they cannot decrypt anything you send. The channel failure is the detection mechanism. A silent MITM key substitution is not possible in Occulta's architecture. This feature only becomes relevant if Occulta builds a signed key rotation protocol for device migration, at which point it would be a component of that feature, not a standalone one.

---

### 6. Plausibly Deniable Vault Partitions
**In May report** (Feature 3)
**Community demand:** Medium-high — VeraCrypt hidden volume is a decade-validated pattern; journalist and activist communities explicitly request it; no iOS equivalent exists
**Audience:** Narrow-medium — journalists, activists, lawyers, anyone under coercion risk in high-risk jurisdictions

Two distinct vault surfaces, each unlocked by a different PIN or passphrase. The surface credential reveals innocuous contacts and files; the hidden credential unlocks a separate, cryptographically distinct partition. The two partitions share the same encrypted container; the hidden partition is statistically indistinguishable from ciphertext padding in the surface partition's free space. A coerced user can reveal the surface credential without exposing the hidden partition. Two separate SE-wrapped keys are used (not two biometric enrollments, which iOS does not support).

VeraCrypt is the only widely known implementation of this model and is desktop-only. No iOS privacy app currently offers it.

**iOS constraint:** Two-PIN deniability requires both credentials to be software-derived secrets wrapping distinct SE keys. The surface vault's free space must always be filled with cryptographically random data for the hidden partition to be indistinguishable — a standard VeraCrypt design pattern achievable at the file level.

> **Ruling (May 2026):** Holds up for a specific and validated audience. Two implementation details the original write-up underplays: (1) biometric unlock must never be mapped to the hidden partition — deniability only holds if the hidden vault is passphrase-only, which adds real friction for daily use; (2) keeping the surface vault's free space filled with random padding is an ongoing storage operation, not one-time setup. Both are solvable. Ships as part of the duress cluster (Travel Mode → Deniable Partitions → Panic Wipe). **Priority: Phase 2.**

---

### 7. Delay-Tolerant Proximity Outbox
**In Apr report** (Feature 5) · **Conceptually overlaps with #1**
**Community demand:** Medium — Briar's Bramble Sync Protocol is the reference implementation; activist and field journalism use cases
**Audience:** Medium — field journalists, activists in intermittent-connectivity environments, frequent in-person collaborators

Local encrypted queue for contacts who are currently unreachable. Occulta monitors for a contact's BLE presence in the background; when detected, delivers queued baskets and obtains a cryptographically signed delivery receipt from the recipient's SE key. Queue is stored encrypted and survives reboots. Small baskets can deliver automatically; large files prompt the user.

This is best understood as the asynchronous mode of Feature #1 (Wi-Fi Aware delivery): "I'll send this the next time I physically encounter you." The two features should ship as a single transport cluster.

**iOS constraint:** BLE background scan intervals are throttled by iOS when the app is not in the foreground. Reliable automatic detection is best-effort; a foreground notification ("Contact is nearby — deliver 3 pending baskets?") is the reliable UX fallback. Wi-Fi Aware (iOS 26+) improves background delivery capability significantly.

> **Ruling (May 2026):** Removed. The use case is manufactured. If you want to send a basket to someone you'll encounter physically, you can just exchange it when you see them — the UWB ceremony for new contacts and the share extension for existing ones already cover this. The BLE background throttling makes automatic delivery unreliable in practice. Briar's proximity queue solves a real problem for Briar (no internet transport available); Occulta users have internet and the share extension. This feature also depends on #1 (proximity basket delivery), which was itself removed.

---

### 8. Secure Digital Legacy (Shamir Dead Man's Switch)
**In May report** (Feature 6) · **Competitive analysis in Apr** (Bitwarden Emergency Access)
**Community demand:** Medium — crypto asset holders, journalist communities, estate planning; all current dead-man's-switch apps require cloud backends
**Audience:** Narrow-medium — crypto holders, journalists in dangerous environments, lawyers with client obligations, individuals with dependents

Configurable check-in interval with N designated legacy contacts. Shamir shares of a designated vault partition key are distributed to those contacts via encrypted baskets in advance. A missed biometric check-in triggers encrypted share release. Recipients combine K-of-N shares to reconstruct the key and access the legacy partition. All local: no cloud server, no third-party custodian. Every current dead-man's-switch iOS app requires a cloud backend — this is the only serverless architecture.

**iOS constraint:** The trigger relies on the app detecting a missed check-in. iOS background execution limits mean the mechanism uses a local notification prompt for check-in, combined with a background task for delivery. Edge cases: device seizure before shares are distributed (vault not compromised — shares weren't released yet); coerced biometric check-in (a known limitation of any biometric-gated dead man's switch without a server-side time component).

> **Ruling (May 2026):** Holds up as genuinely differentiating. Every current iOS dead-man's-switch implementation requires a cloud backend; this would be the only serverless one. The Shamir SSS infrastructure is already built. The iOS background constraint (check-in relies on the app getting execution time) is a real limitation that must be communicated clearly in UX — device seizure before share distribution means the vault is not compromised, which is actually the correct behavior. Coerced biometric check-in is a known, acknowledged limitation. **Priority: Phase 2.**

---

### 9. Offline Mesh Relay via Mutual Contacts
**In May report** (Feature 4) · **Conceptually in Apr** (Briar competitive analysis)
**Community demand:** Medium — Briar's relay model is widely praised; iOS gap is documented in Briar's own docs
**Audience:** Narrow — small activist cells, field journalist teams, research teams in remote locations

Onion-style store-and-forward routing through a mutual contact. Sender double-encrypts: outer layer to the relay contact (for transport); inner layer to the ultimate recipient (for content). The relay contact's Occulta app stores and re-delivers the inner-encrypted blob when it next detects the recipient via Bluetooth or Wi-Fi Aware, then discards its copy. The relay sees only opaque ciphertext. Requires prior UWB key exchange among all three parties and is opt-in per contact.

**iOS constraint:** Store-and-forward relay requires background detection and transfer. Core Bluetooth background mode and App Refresh support this with power and timing constraints. The UWB key exchange must have already occurred between all three parties.

> **Ruling (May 2026):** Removed. The coordination requirement is self-defeating: all three parties must have Occulta and must have performed mutual UWB exchanges in advance, which means they were all physically co-located close enough to exchange keys directly. If they were that close, the relay is unnecessary. iOS background BLE throttling makes automatic relay delivery unreliable on top of the coordination problem.

---

### 10. NFC Tap Key Exchange (Non-UWB Fallback)
**In May report** (Feature 8)
**Community demand:** Low-medium — device coverage concern raised in Privacy Guides; iPhone SE installed base is significant
**Audience:** Medium — iPhone SE users, enterprise mixed-fleet deployments, family/colleague gift use cases

NFC (5 cm range) as the key-exchange transport for devices without a UWB chip (iPhone SE 3rd gen, some iPads). Same cryptographic protocol as UWB — ephemeral ECDH + Diceware verbal verification — with NFC as the transport. Implemented as a two-step half-duplex tap sequence via CoreNFC (Device A writes → Device B reads; Device B writes → Device A reads). Extends Occulta's zero-server key exchange to the full modern iPhone installed base.

**iOS constraint:** True peer-to-peer NFC is not supported on iOS (no Android Beam equivalent). The half-duplex workaround is feasible but requires UX design to guide users through the two-step tap. `CoreNFC` entitlement required.

> **Ruling (May 2026):** Holds up. NFC at 5 cm is actually stricter than UWB at 25 cm — no security regression. Removes the hard UWB-device requirement without compromising the physical-proximity trust model. The two-step tap UX needs careful design but is workable. Lower urgency than the duress cluster, but a clean way to expand the addressable device base. **Priority: Phase 2 (lower).**

---

### 11. Threshold-Gated Group Document (M-of-N Collective Basket)
**In Apr report** (Feature 6)
**Community demand:** Low-medium — legal and investigative journalism team workflows; no iOS equivalent
**Audience:** Narrow — legal teams, investigative journalism collectives, activist cells with shared operational documents

Shamir-split document key distributed across N group members. Document can only be opened when M members physically converge via sequential UWB sessions, each contributing their share to the coordinating device. Reconstructed key held in RAM only, purged when the session ends or the app is backgrounded. Uses existing Shamir SSS implementation. Share distribution and revocation use the existing basket mechanism.

**iOS constraint:** UWB is pairwise; M-of-N requires M sequential UWB sessions (A↔B, A↔C, …). Practical for M ≤ 5 in a room. Reconstructed key material must be handled carefully: `Data` pinned to non-swappable memory, wiped immediately via `withUnsafeMutableBytes { memset }`. CryptoKit does not include Shamir SSS natively; a constant-time implementation over GF(2^8) is required.

> **Ruling (May 2026):** Removed. The audience (investigative journalism collectives, legal teams doing threshold document access on iOS) is too narrow to justify the implementation. The "everyone must physically converge" requirement means this only works for groups small enough to be in the same room — at which point they could simply hand each other a device. The use case is contrived.

---

### 12. SE-Attested vCard Export (Cryptographically Signed Contact)
**In May report** (Feature 5) · **Keybase social proof concept in Apr**
**Community demand:** Low — no explicit forum demand; useful onboarding and distribution tool
**Audience:** Broad as an onboarding mechanism — professionals who want to proactively distribute a verifiable identity

Exports a standard vCard (.vcf) with the Occulta public key embedded as a signed extension field. Signed by the SE identity key using CryptoKit P-256. Any Occulta user who receives it can verify (a) the embedded key matches the sender's SE identity and (b) the card has not been tampered with. Non-Occulta apps treat it as a regular contact card. Useful for asynchronous bootstrapping of trust before a UWB ceremony is arranged.

**iOS constraint:** vCard 4.0 supports custom extension fields (X-* / URI fields). `CNContactVCardSerialization` handles read/write. SE signing via `SecureEnclave.P256.Signing`. UX challenge: the card is a self-assertion, not a third-party endorsement — visual design must clearly communicate the difference between "signature valid" and "identity trusted."

> **Ruling (May 2026):** Removed. For the signature to mean anything to a recipient, they must already have Occulta installed and have done a prior UWB exchange with the sender. That is an extremely narrow verification audience. Outside that circle the embedded signature is unverifiable noise — no legal weight, no trust signal to anyone without Occulta. The "self-assertion vs. identity trusted" distinction the original write-up flags as a UX challenge is actually the core problem: this is a cryptographic signature with no trust anchor a third party can use.

---

### 13. Basket Manifest Filename Encryption
**In Apr competitive analysis** (Cryptomator insight)
**Community demand:** Low — metadata analysis concern; understood by technical users
**Audience:** Narrow — high-threat users who recognize metadata leakage risk

Encrypt basket manifest entries — filenames, MIME types, item counts — with a basket-specific key, not just the payloads. Prevents metadata inference from the basket container structure even without the content keys. A protocol-level hardening rather than a user-visible feature.

> **Ruling (May 2026):** Valid but invisible. No new audience, no user-facing benefit. Ship opportunistically as a protocol version bump when touching the bundle format for another reason — do not plan a release around it.

---

### 14. Vault Health Check / Security Audit
**In Apr competitive analysis** (Strongbox / KeePassium insight)
**Community demand:** Low — table stakes for vault products; users expect it from any modern vault tool
**Audience:** Broad — general password manager audience expects this

On-device scan of vault items flagging weak, reused, or stale secrets. All three major vault competitors (1Password Watchtower, Bitwarden, Strongbox) ship this. Entirely local analysis.

> **Ruling (May 2026):** Removed for current scope. Occulta's vault stores contacts and encrypted documents, not passwords. Weak/reused password detection has no surface to operate on. If Occulta ever expands into password storage this becomes relevant, but building it for a hypothetical future vault scope is speculative. Revisit only if the vault model changes.

---

### 15. Presence Verification (Anti-Deepfake Live Check)
**Added June 12, 2026 (authentication research pass)**
**Community demand:** Very high and accelerating — FBI IC3 2025 report (22,000+ AI-fraud complaints, $893M losses), Arup deepfake CFO incident ($25M wired after a video call where every participant was synthetic), Singapore deepfake Zoom fraud ($499K, Mar 2025), CNN/CBS/BBB/McAfee "family safe word" coverage (2025–2026), Scattered Spider helpdesk-impersonation attacks (MGM playbook, ongoing through 2026)
**Audience:** Broad — every Occulta user with a verified contact; families targeted by voice-clone scams; finance/executive teams targeted by deepfake calls; IT helpdesks targeted by MFA-reset social engineering

When a call, video call, or message claims to be a contact, the user issues a one-time challenge; the contact approves on their device with biometrics and their Secure Enclave signs a timestamped attestation bound to the challenge. A deepfake can clone a face and voice but cannot sign with the P-256 key that was established at ≤25 cm. The universally recommended defense today is a verbal "safe word" — static, leakable, forgettable, and socially engineerable. This is the safe word that cannot leak.

Market validation: Google shipped Fake Call Detection on June 2, 2026 — an RCS cryptographic handshake confirming a call from a saved contact originates from that contact's device. It is Android-only, Google-mediated, and RCS-bound. iOS has no equivalent, and no platform-free (serverless) implementation exists anywhere.

This is the rare feature where the closed-loop critique that removed SE-Attested vCard (#12) and Document Signing (D) does not apply: the verification circle *is* the contact book. Both parties by definition have Occulta and a prior UWB exchange. The loop fully closes.

**Codebase reality:** The cryptographic core already shipped — the Identity Challenge protocol (v1.8.x, `Features/IdentityChallenge/`) implements the full challenge → biometric-gated SE signature → verification lifecycle over encrypted `.occ` bundles, with backward-compatible fallback messages, nonce one-shot replay protection, and rate limiting. What it cannot yet claim is *presence*: the verification window is 1 hour (suitable for "this contact still controls their key," not "this person is in this conversation right now"), the transport is four share-sheet hops (unusable mid-call), and the responder's approval sheet does not state what is being attested. The feature is therefore a focused extension, not a new build: a presence mode with a ~2-minute freshness window, a distinct signing domain, intent-explicit approval UX, and a QR-over-video transport for the desktop-video-call (Arup) scenario.

**iOS constraint:** All primitives exist (SE ECDSA, encrypted bundles, QR generation/scanning from the key-exchange flows). Known residual risk: a relay attack (attacker challenges the victim while simultaneously pretexting the real contact into approving). Mitigated — not eliminated — by the tight window and by the approval sheet naming the challenger explicitly; same residual class as number-matching MFA. Single-device video calls (call and Occulta on the same phone) fall back to the messaging transport.

> **Ruling (June 2026):** Strongest addition since the duress cluster. The pain is documented at mainstream scale, the timing is exact (Google legitimized the category this month, on Android only), the architecture is uniquely suited (the physically-verified contact graph is precisely the right trust anchor), and the hard half already shipped. Carries a built-in enterprise story (helpdesk MFA-reset verification, wire-transfer callback) that gives Expansion A its missing wedge — see Section 2 addendum. Low lift, high ceiling. **Priority 1 (parallel track to the duress cluster — independent of the key-hierarchy rework that gates Panic Wipe).** Spec: `Docs/Features/Presence Verification/SPEC.md`.
>
> **Addendum (July 10, 2026) — delayed, priority revoked.** The relay/parallel-session attack documented in SPEC.md §6 was re-assessed and reclassified from an accepted residual risk to a blocking gap: it is a "mafia fraud"-class relay attack with no known guaranteed fix, and it hits hardest against exactly the adversary this feature is named for — a resourced attacker already running a live deepfake call finds relaying a challenge to the real contact easier than the deepfake itself. No content-binding or transport change closes it with a guarantee. **Downgraded from Priority 1 to Delayed** — not scheduled until either a protocol fix with a real guarantee is found, or the product claim and UX are explicitly narrowed to exclude live, resourced, dual-channel relay attacks. Downstream dependents inherit this delay until resolved: Verified Payment Instructions (#26)'s pairing with presence verification, Anti-Scam Family Circle (#27) which is built entirely on top of this primitive, and Expansion A's enterprise wedge (Section 2 addendum).
>
> **Addendum (August 9, 2026) — the #27 dependency above is overstated, and an alternative construction exists.** Two corrections from a design pass recorded in [Presence Verification/FINDINGS.md](Presence%20Verification/FINDINGS.md).
>
> **#27 is not "built entirely on top of this primitive."** Reading its own three components: **Second Opinion** (forward a suspicious request to a family guardian, *"one basket type plus UX; zero new crypto"*) depends on no presence primitive and is shippable today; **Money-request rule** routes through #26, which is independently Near-term; only **Assisted Mode** is genuinely blocked here. Two of three components are sitting shelved behind a dependency they do not have — a real cost, given #27 carried the highest reach-to-lift ratio of the July 10 pass. Second Opinion should be unshelved independently of this delay.
>
> **A different construction reaches several of the same outcomes without meeting the relay attack.** Reverse the protocol's direction: instead of the verifier challenging the prover to attest to a *circumstance* ("you are in a live call with me"), the **requester originates** a signed statement of their own *intent* ("I am asking you for $5,000"). This is not the content-binding §6 already rejected — the difference is what the signer attests to. A circumstance can be manufactured by an attacker and approved honestly by a contact who cannot observe the misuse; an intent statement has no plausible pretext, since producing it requires the real contact to knowingly lie about what they themselves want. Structural, not bar-raising. Scope limit: applies only where the requester still holds their key, so it covers family money requests, BEC (#26), and the Arup deepfake-executive case, but **not** account recovery or unknown-caller verification. Residual is behavioral, not cryptographic. **This does not unblock #15**, whose construction and delay stand exactly as written above. Construction: [Presence Verification/FINDINGS.md](Presence%20Verification/FINDINGS.md). Payments application: [Payment Cards/FINDINGS.md](Payment%20Cards/FINDINGS.md).

---

### 16. Serverless Social Recovery (Shamir Trustee Custody)
**Added June 12, 2026 (authentication research pass)**
**Community demand:** High — account-recovery lockout is the documented weak link of the passwordless transition (Gmail lockout coverage, Microsoft account-recovery threads); Google validated the social-recovery model by shipping Recovery Contacts in October 2025 (cloud-mediated)
**Audience:** All Occulta users — answers the single most existential objection to the architecture: "SE-bound keys never leave the device, so a lost phone means losing everything"

**Codebase reality: this is already built.** The Vault SSS custody system (`Features/Vault/`, flag `enableShamirShardSharing`) distributes vault-key shards to trustee contacts over encrypted bundles, tracks custody via manifests, detects owner device loss via key-fingerprint mismatch, and implements the full owner-recovery flow (shard protocol Case 9) including trustee handback and threshold reconstruction. Nineteen protocol cases are documented in `SHARD_PROTOCOL_CASES.md`.

> **Ruling (June 2026):** Not a feature to build — a feature to *finish and front*. Three gaps between what exists and what the market validation supports: (1) it is invisible — buried as a vault capability rather than positioned as the answer to "what if I lose my phone?", which is the first question every privacy-app user asks; (2) recovery scope is the vault PEK only — the SE identity key is unrecoverable by design, so recovery UX must honestly present "your data survives; your identity re-bootstraps via new UWB exchanges" as the story; (3) the demand evidence (Google Recovery Contacts, passkey-lockout coverage) belongs in marketing copy — "Google needs their cloud for this; Occulta does it with the people you've physically met." No new protocol work warranted. **Priority: positioning/UX pass, not engineering.**

---

### 17. Duress-Aware 2FA Codes (SE-Bound TOTP Vault)
**Added June 12, 2026 (authentication research pass)**
**Community demand:** High — Google Authenticator's cloud sync is not end-to-end encrypted (Google holds the keys); the Retool breach traced a $15M crypto theft to exactly that sync path; "stop using Google Authenticator" is a recurring 2025–2026 security-press genre; r/privacy recurring complaints about TOTP seed loss and migration
**Audience:** Medium-broad — every Occulta user has 2FA accounts; high-threat users currently leak their entire account map to anyone who unlocks their authenticator app

TOTP (RFC 6238) seed storage as a vault item class: seeds SE-wrapped at rest, codes computed on demand, never synced anywhere. The market is crowded (2FAS, Aegis, Raivo's collapse) — the differentiator is duress-cluster integration, which no authenticator on any platform offers: Travel Mode (#2) makes designated 2FA entries cryptographically nonexistent at a border crossing; Panic Wipe (#3) destroys them in milliseconds; deniable partitions (#6) put the sensitive accounts' 2FA in the hidden partition. A border agent who unlocks today's authenticator apps sees the user's complete account map — metadata Travel Mode cannot currently protect because it lives in a different app. Social recovery (#16) covers seed loss — attacking the exact fear that drives users to Google's insecure cloud sync.

**iOS constraint:** TOTP is trivial (HMAC-SHA1/SHA256 over CryptoKit, 30-second windows). Seed import via otpauth:// URI QR scan is the established convention. No background execution, no network, no new attack surface. The only design obligation is that seeds enter the existing vault key hierarchy so the duress features apply automatically rather than via parallel plumbing.

> **Ruling (June 2026):** Holds up as a duress-cluster amplifier rather than a standalone authenticator play. Do not market it as "another 2FA app" — ship it as a vault item type that inherits Protected Mode behavior, where it is unique on any platform. Depends on the key-hierarchy rework already scoped for Panic Wipe; sequence it after Travel Mode and Panic Wipe land so the integration story is real at launch. **Priority: Phase 2.**

---

### 18. Owner Device Set — Multi-Device Identity via Self-UWB Ceremony
**Added July 4, 2026 (feature ideation pass)**
**Category:** Authentication / Crypto
**Audience:** Broad — converts Occulta's most-cited limitation ("lose your phone, lose your contacts") into a non-event; the #1 objection on the App Store page

Hold two owned iPhones ≤25 cm apart and run the standard UWB + Diceware ceremony against yourself. Each device's SE identity key signs a domain-separated "same-owner certificate" over the other device's public key (`"occulta-device-set-v1"` prefix, nonce-freshened), distributed to contacts inside normal encrypted baskets as an optional `SealedPayload` sub-envelope per the `OccultaBundle` no-new-Version/Mode-case rule. Contacts store both keys under one identity; senders encrypt to every device in the set using the existing `useMultipleRecipientMessageFormat` capsule array. Each device keeps its own SE prekey pool, so forward secrecy stays per-device and never crosses hardware.

Distinct from `allowSynchingBetweenDevices` (disabled iCloud *data* sync) and from the signed key rotation protocol (replaces one key with another) — this establishes concurrent attested membership, which neither does.

**Security model fit:** No server (certs travel inside encrypted baskets, AES-GCM, wire format unchanged). Both keys stay SE-bound; nothing exportable. FS preserved per-device; PQ preserved (each device runs its own ML-KEM exchange on next contact).

**iOS constraint:** iPhone 11+ (U1) on both devices; reuses `ExchangeManager` as-is. `Contact` gains an optional device-set array (new optional SwiftData property, default nil) — old builds ignore the sub-envelope and keep encrypting to one key.

> **Ruling (July 2026):** A stolen *unlocked* phone enrolling an attacker device is the main attack surface — mitigated to zero by requiring biometric-gated SE signing on **both** devices within the same UWB session, so an attacker needs two biometric passes on two devices simultaneously. Cert forgery requires an SE private key, excluded by hardware. Run CRYPTO_REVIEW_CHECKLIST §3 (multi-party trace) carefully: per-device prekey pools must never be shared — the historical prekey-batch flaw. Medium lift (ceremony reuse is free; the work is contact-model evolution and multi-device prekey bookkeeping). **Priority: Near-term.**
>
> **Addendum (July 10, 2026) — superseded.** The self-vouching device-set cert design above was rejected during implementation-planning discussion (see [Multi-Device Contacts/FINDINGS.md](Multi-Device%20Contacts/FINDINGS.md), Design Sessions 3–4): it grants trust to a new key without a fresh physical UWB exchange, violating the standing no-vouching invariant, and a single coerced ceremony would silently compromise a victim's entire contact graph. The feature was renamed **Multi-Device Contacts** and narrowed to a data-model bug fix only — `Contact.Profile` gains concurrent per-device keys so a second device no longer silently overwrites the first's; the "backup phone that just works across your whole contact list" ambition is shelved, since the secure fallback (direct physical re-pairing with every contact, one at a time) doesn't scale past a handful of close contacts. Downgraded from **Priority: Near-term** to **opportunistic, low-priority** — see [Multi-Device Contacts/ROADMAP.md](Multi-Device%20Contacts/ROADMAP.md).

---

### 19. Guardian Revocation Certificates (Pre-Signed, K-of-N Released)
**Added July 4, 2026 (feature ideation pass)**
**Category:** Security / Authentication
**Audience:** All users — completes the key lifecycle (establish → rotate → **revoke**) that any serious protocol review probes first; particular pull for the journalist/activist segment where device seizure is the threat model

At setup, the SE signs a revocation statement over the owner's own public key (`"occulta-revocation-v1"` domain prefix). The cert is Shamir-split K-of-N using the existing SSS (`enableShamirShardSharing`) and shards distributed to guardian contacts via encrypted baskets. If the device is lost or stolen, guardians coordinate out-of-band; K of them release shards, any one guardian reconstructs the cert and forwards it. The reconstructed cert is wrapped as `AES-GCM(cert, key = HKDF(owner_pubkey, info: "occulta-revocation-wrap-v1"))`, so guardians can broadcast the blob to their entire contact list but only people who already hold the owner's public key can open it — everyone else sees random bytes. Recipients verify the SE signature against the stored key and mark the owner revoked/untrusted until a fresh in-person exchange.

Distinct from Contact Compromise Detection (removed — Consumer #5, Occulta has no server key-substitution path to detect), the Dead Man's Switch (#8, releases *data*, not a revocation), and signed key rotation (requires the SE that was just stolen). This is the missing quadrant: killing a key you no longer control.

**Security model fit:** No server — revocation propagates P2P through guardians. SE-bound (cert SE-signed at creation; no new private keys). No metadata leakage — encrypt-to-knowledge wrapping means broadcasting the blob reveals no relationship graph. FS/PQ untouched (pure signature verification against already-pinned keys).

**iOS constraint:** iOS 16+, zero new primitives — ECDSA, SSS, and basket distribution are all already shipped. Remaining work is UX (guardian selection, "report lost device" flow on the guardian side) and CRYPTO_REVIEW_CHECKLIST §2 (shard release must be one-way and idempotent).

> **Ruling (July 2026):** Highest reuse ratio of this batch. Malicious or coerced guardians could revoke falsely — mitigated by K-of-N threshold; worst case is a forced re-exchange (denial-of-convenience), never a confidentiality loss. Replay is moot (revocation is idempotent and terminal). Low lift. **Priority: Near-term.**
>
> **Addendum (July 22, 2026) — superseded, downgraded to positioning.** UX scoping for this feature (guardian shard-release confirmation, cross-guardian shard coordination, broadcast delivery with no server or push infrastructure) surfaced that the mechanism this spec assumed doesn't hold up: a malicious or falsely-triggered revocation's worst case, *by this doc's own ruling above*, is "a forced re-exchange, never a confidentiality loss" — but that is already the exact worst case of the feature that ships today. `Contact+Form.swift`/`ContactFormV2.swift`'s existing "Revoke Key" button (`ContactManager.reset(identity:)`) lets any contact unilaterally expire a stored key on their own device, which blocks sends (`resolveKeyMaterial`), surfaces a "PENDING EXCHANGE" badge, and requires a fresh UWB exchange to clear — with zero cryptography, zero guardians, and zero new engineering. Since the guardian/SSS/K-of-N apparatus cannot produce a better worst-case than a feature that already ships, it is not solving a gap; it is re-solving a solved problem at a much higher UX and engineering cost. The only value it could still add — reaching a contact who has *no channel to the owner besides Occulta itself* (met once via UWB, no phone number or email) — is real but narrow, and does not justify guardian shard coordination or SSS reconstruction on its own. **Downgraded from Near-term/Priority 2 (parallel) to positioning-only**, mirroring the #16 ruling: no new engineering, just make the existing "Revoke Key" button discoverable (onboarding or a security FAQ: "lost your phone? tell your contacts — they can revoke you from Contact → Revoke Key"). Revisit as an engineering item only if evidence shows the no-other-channel case is common enough to matter, and if so scope it as a minimal signed self-revocation broadcast, not the SSS/guardian design above.

---

### 20. Serverless Passkey Provider — Hardware-Bound Passkeys, Socially Recoverable
**Added July 4, 2026 (feature ideation pass)**
**Category:** Authentication
**Audience:** The mainstream password-manager market — the largest adjacent segment available to this codebase

Occulta registers as an iOS Credential Provider (`ASCredentialProviderExtension` with passkey support, iOS 17+). Each relying party gets a dedicated `SecureEnclave.P256` key (WebAuthn ES256), biometric-gated, `ThisDeviceOnly`, in a shared keychain access group so the extension can sign assertions. Unlike 1Password, Bitwarden, and iCloud Keychain — all of which sync passkey private keys through cloud infrastructure as *software* keys — Occulta passkeys stay hardware-bound, closer to a YubiKey that's already in the user's pocket. The device-loss problem that forces competitors into cloud sync has no equivalent solution here: Multi-Device Contacts (#18) was narrowed 2026-07-10 to a data-model bug fix, not a device-continuity feature, and a user's own devices have no channel to each other under the resolved no-vouching design — RP-record coverage across a user's own devices remains an open problem, tracked as ROADMAP.md R4 §1. Occulta's existing SSS custody still covers guardian-escrowed recovery of the RP-record vault (R4 §3).

**Why not covered elsewhere:** Adjacent to, but distinct from, Expansion C (Developer/API Authentication, an enterprise SDK play) — this is consumer WebAuthn shipped in the app itself, a different product and buyer.

**Security model fit:** No server — assertions compute locally; relying parties hold only public keys, outside Occulta's trust boundary. SE-bound — per-RP SE keys, domain-separated, never the identity key. No metadata leakage — RP IDs/usernames encrypted under the hybrid local DB key.

**iOS constraint:** iOS 17 floor for third-party passkey provisioning/assertion. User must enable Occulta in Settings → Passwords; `LAContext` biometrics work in-extension; no network entitlement on the extension. Self-attestation only (standard for consumer providers).

> **Ruling (July 2026):** The extension holds no plaintext secrets (SE signs; DB fields decrypt on demand under biometric), has no network entitlement, and no IPC beyond the ASAuthorization API — phishing resistance is inherited from WebAuthn origin binding. Medium-high lift: the extension, RP record model, and Settings UX are real work, though zero new cryptography. **Priority: Mid-term.**

---

### 21. Uniform Basket Envelopes — Length Padding + Traffic-Shape Hiding
**Added July 4, 2026 (feature ideation pass)**
**Category:** Privacy / Crypto (protocol hardening)
**Audience:** Not an audience feature — a credibility feature. It is the difference between surviving and failing the first independent protocol review.

**Constraint alert:** this closes a live nonconformance with the project's own metadata rule. AES-GCM is length-preserving and no padding scheme currently exists in the bundle format (Consumer #13 covers manifest filenames/MIME types/counts, not length). A passive observer of an `.occ` file — mail server, chat platform, forensic acquisition — can currently distinguish "a 3-word text" from "a 4 MB video," and fingerprint prekey-batch-carrying bundles by their characteristic size, even though file size is explicitly listed among the metadata classes this project treats as sensitive.

Before `seal()`, pad `SealedPayload` to the next size bucket (e.g., 4 KB / 64 KB / 1 MB / next power-of-two, plus small random jitter within the bucket) via an optional `padding: Data` field of random bytes. Old builds' JSON decoders ignore the unknown field — no version bump needed, per the `OccultaBundle` house rule. AAD unchanged. This also makes `PrekeySyncBatch`-carrying bundles size-invisible, closing the piggyback signature.

**Why new / overlap declaration:** Overlaps Consumer #13 (Basket Manifest Filename Encryption) — #13 encrypts manifest *strings*; this closes the *length* side-channel, which #13 explicitly does not address. Without it, #13's protection is partially theater: an observer who can't read the filename can still tell it's a video.

**Security model fit:** No server. SE untouched. Strictly reduces metadata. FS/PQ preserved — padding sits inside the ciphertext; derivation paths, `info` strings, and wire fields are unmodified.

**iOS constraint:** iOS 16+, pure CryptoKit/Data work. Watch memory on large files — stream-friendly bucketing or a capped top bucket for video. Padding bytes must come from `SecRandomCopyBytes`, never zeros (a compressibility oracle if anything downstream ever compresses — nothing does today, but zero-tolerance says random regardless).

> **Ruling (July 2026):** Like #13, ship opportunistically as a protocol version bump when the bundle format is touched for another reason — low lift, no new attack surface, and it upgrades #13 from partial to real protection. **Priority: Near-term, opportunistic (pairs with #13).**

> **Addendum (July 10, 2026):** Chat Control was reinstated July 9, 2026 — in a platform-scanning regime, size/shape fingerprints are exactly what service-side classifiers see. Promoted from opportunistic to scheduled: pair with the next protocol release rather than waiting for an incidental bundle-format touch.

---

### 22. Private Mutual-Contact Discovery + Key Corroboration
**Added July 4, 2026 (feature ideation pass)**
**Category:** Privacy / Crypto
**Audience:** Activist cells and field teams get relay-adjacent routing information; all users get a sybil-resistant trust signal no server-based product can honestly offer

Two already-verified contacts, over an authenticated session (in person or an existing pairwise channel), derive a fresh session secret and each compute `tag_i = HMAC-SHA256(sessionKey, contact_i.publicKey)` for every contact, pad the tag set to a fixed bucket size with random dummy tags (hiding counts, which are metadata), and exchange sets. Matching tags reveal mutual contacts and only mutuals. Because Occulta public keys are high-entropy and never travel in cleartext, membership probing is only possible for keys the prober already physically collected — precisely the intersection being computed. This gives PSI-equivalent leakage using pure CryptoKit HMAC (true DH-PSI needs hash-to-curve + raw scalar multiplication, which CryptoKit doesn't expose, so a hand-rolled constant-time curve implementation was ruled out as violating the Apple-frameworks-only convention). Optional layer: for each discovered mutual, exchange an SE-signed key attestation so the UI can show "2 physically-verified contacts corroborate Carol's key."

**Why new:** The missing primitive under any mesh-relay concept (which silently assumes mutual contacts are already known — today they aren't, discoverably), and a direct answer to the most-documented structural complaint about Signal-style contact discovery: it requires phone numbers and server-side infrastructure.

**Security model fit:** No server — pairwise P2P computation. SE-bound where attestations are signed. Opt-in per session, mutuals-only disclosure, padded set sizes, tags unlinkable across sessions (fresh session key each time). FS/PQ untouched.

**iOS constraint:** iOS 16+. HMAC + set intersection is trivial; the work is session UX and the corroboration data model.

> **Ruling (July 2026):** A malicious verified contact learns your mutuals *with them* — inherent to the feature's purpose and consented per session; keep it opt-in and never automatic. Low-medium lift. **Priority: Near-to-mid-term.**

---

### 23. Hybrid PQ Signatures (SE-ECDSA + ML-DSA) for Long-Lived Signed Artifacts
**Added July 4, 2026 (feature ideation pass)**
**Category:** Crypto / Security
**Audience:** Applies wherever a signed artifact must remain unforgeable for decades — revocation certs (#19), the per-device revocation broadcast introduced by Multi-Device Contacts' narrowed scope (#18), and any future document-signing or audit-log artifact

Dual-signature format for artifacts whose validity must outlive ECDSA's quantum horizon. Every such artifact carries both an SE ECDSA P-256 signature (unchanged, mandatory root) and an ML-DSA-87 (FIPS 204) signature under a distinct domain prefix; verification requires **both**. If `SecureEnclave.MLDSA` exists in the target iOS SDK, use it — ~~if SE support covers only ML-KEM (true as of the last check — verify against current CryptoKit headers before scoping), hold the ML-DSA private key software-side, wrapped under the hybrid local DB key~~ **it does exist, from iOS 26; verified 2026-08-14 against the SDK's own interface file (see the August 14 addendum below). The software-custody fallback is dead text and must not be implemented.** This does not weaken the SE-custody rule the way sole software custody would: forgery still requires the SE (ECDSA is always required), so the ML-DSA half only *adds* unforgeability — the same both-must-hold logic as the existing hybrid KEM construction and the same protection class as the already-accepted ML-KEM shared-secret storage.

**Why new:** "Harvest now, forge later" is the one PQ threat the existing ML-KEM work doesn't touch — a signed contract or notarized document must remain unforgeable for decades.

**Security model fit:** No server. SE remains the mandatory signing root. No metadata change (signatures travel where signatures already travel). PQ strengthened — the first feature to extend PQ from confidentiality to authenticity.

**iOS constraint:** ~~Gated on SDK verification of SE ML-DSA support.~~ **Gate met — SE ML-DSA ships from iOS 26 (verified 2026-08-14).** iOS 26 floor, the same availability tier as the shipped ML-KEM path, so no new gating pattern is needed. ML-DSA-87 signatures run ~4.6 KB — irrelevant for documents, but worth noting against #21's padding buckets if ever used on the wire; **ML-DSA-65 (~3.3 KB signature, ~1.95 KB public key) is equally SE-backed and is a size option this entry did not consider.** New domain prefixes only, per IDENTITY_CHALLENGE_PROTOCOL's domain-separation mandate — never modify existing signing paths. **FIPS 204 carries its own context string, which CryptoKit exposes as `signature(for:context:)`; which of the two is authoritative needs an explicit ruling rather than using both by default — see the August 14 addendum.**

> **Ruling (July 2026):** Software ML-DSA key compromise still can't forge anything (needs the SE) — worst case equals today's status quo. Run CRYPTO_REVIEW_CHECKLIST §4 on cross-protocol separation for every new prefix. Medium lift, gated on SDK support. **Priority: Mid-term.**
>
> **Addendum (August 9, 2026) — scope limit: this defends quantum, not SE extraction.** The ruling above establishes that software ML-DSA compromise alone can't forge. The converse is not stated and matters: the ML-DSA private key is held *"wrapped under the hybrid local DB key,"* which is itself SE-derived (`Key+Manager.swift:468`) — so **SE key extraction unwraps the ML-DSA half too.** Hybrid signatures put the second lock's key inside the first lock. That is fine against the threat this feature is for (Shor breaks P-256 from the public key; AES-256 survives Grover), but it means `#23` adds *zero* defence against a hardware SE compromise. Anything relying on `#23` for SE-extraction resistance is relying on the wrong control — the surviving defences there are locally-observed state and physical presence, not signatures. Raised while scoping Verified Payment Cards; see [Payment Cards/FINDINGS.md](Payment%20Cards/FINDINGS.md) threat model, "If the identity key itself is recovered." **Mechanism voided 2026-08-14 — see immediately below; the conclusion survives on different grounds.**
>
> **Addendum (August 14, 2026) — the SDK gate is met, and the August 9 mechanism is void.** `SecureEnclave.MLDSA65` and `SecureEnclave.MLDSA87` both exist, `@available(iOS 26.0, *)`, in the SDK this project already builds against. Verified by reading the interface file directly rather than documentation: `iPhoneOS26.2.sdk/System/Library/Frameworks/CryptoKit.framework/Modules/CryptoKit.swiftmodule/arm64e-apple-ios.swiftinterface`, Xcode 26.2 (17C52). Each exposes `PrivateKey` with `publicKey`, an SE-wrapped `dataRepresentation`, `init(accessControl:authenticationContext:)`, `init(dataRepresentation:authenticationContext:)`, `signature(for:)` and `signature(for:context:)`. The app already uses the sibling construct — `SecureEnclave.MLKEM1024.PrivateKey()` at `PQProvider.swift:96`, same availability tier.
>
> **What the August 9 addendum got wrong.** Its premise — the ML-DSA private key *"wrapped under the hybrid local DB key"* — describes a fallback that never needed to be taken. There is no software-held ML-DSA private key, no wrapping under the DB key, and therefore no "second lock's key inside the first lock." **Its conclusion survives on different grounds and should be restated that way:** both keys live in the same Secure Enclave, so a hardware SE compromise still takes both, and `#23` still adds zero defence against SE extraction. Everything else that premise implied is withdrawn — no new exportable secret, no new key-at-rest surface, and no interaction with local-DB key rotation on Secure Mode activation or deactivation.
>
> **Three capabilities the July entry ruled out that are now available.** (1) **Biometric-gated post-quantum signing** — `accessControl:` takes a `SecAccessControl`, so the key can be created with `.biometryCurrentSet + .devicePasscode` exactly as the vault key is (`Key+Manager.swift:655`) and driven by a pre-evaluated `LAContext` as `retrieveVaultPrivateKey(context:)` already does. Under software custody there was no biometric gate available at all. This bears directly on **Payment Cards D-09**: a single dedicated `SecureEnclave.MLDSA` payment key would deliver the biometric gate and PQ authenticity together, rather than deferring both. (2) **Native domain separation** via FIPS 204's context string, which makes separation an algorithm parameter instead of a hand-rolled prefix — and creates the ruling obligation recorded in the iOS constraint above. (3) **A parameter-set choice** — ML-DSA-65 is SE-backed too, and is the smaller wire option.
>
> **Regated.** The gate is no longer SDK support; it is **artifact availability**. Nothing on this list currently needs a signature to survive decades: `#19` is positioning-only (2026-07-22), `#18` is narrowed to a data-model fix (2026-07-10), `#26` is held pending gate zero (2026-08-14), and Expansion D was removed in May. **`#28` (Sealed Evidence Journal) and `#24` (Signed Destruction Receipts) are the only genuine long-lived artifacts, and both are unbuilt** — build `#23` when one of them is being built, not before. Priority unchanged at **Mid-term**.
>
> **Also now on the table, and previously believed impossible:** an SE-resident ML-DSA identity half established at the UWB ceremony. `#23` as scoped deliberately never touches live signing paths, so it does nothing about post-quantum *impersonation* — an adversary who derives the P-256 private key from the public key every contact holds can sign challenge responses and bundles as the owner. That gap has no fix inside this entry's scope, but it is no longer blocked on hardware. Not a recommendation; a protocol change, and it needs its own pass.
>
> **Why the stale claim survived four months:** the July entry's *"true as of the last check"* was never re-verified against an interface file, and a symbol search for `SecureEnclave.*` does not find these types — they are declared as `extension CryptoKit.SecureEnclave { public enum MLDSA87 … }`, so the nested name never appears on a line containing `SecureEnclave`. Whoever re-checks a CryptoKit availability claim should read the interface file, not grep it.

---

### 24. Signed Destruction Receipts — Expiring Baskets with Cryptographic Burn Proof
**Added July 4, 2026 (feature ideation pass)**
**Category:** Security / Privacy
**Audience:** Lawyers, HR, journalists handling source material with retention obligations — anyone who needs to *demonstrate* ephemerality, not just claim it

Sender sets a TTL inside `SealedPayload` (optional sub-envelope, same house pattern as #18). On receipt, the item is stored under a per-item wrap key; at expiry the recipient's app deletes the wrap key and SE-signs a destruction receipt over `(item fingerprint ∥ timestamp)` with prefix `"occulta-destruction-receipt-v1"`, returned as a normal basket. Sender's UI shows "destroyed, cryptographically confirmed at [time]." Mirrors the delivery-receipt pattern already specified for the Proximity Outbox concept (Consumer #7, removed) — same machinery, opposite lifecycle end.

**Why new:** Signal's disappearing messages — the obvious comparison — offer zero proof of deletion, a recurring complaint in legal/compliance discussions of ephemeral messaging.

**Security model fit:** No server. SE signs receipts. Receipt content (fingerprint, timestamp) travels only inside encrypted baskets — no metadata. FS/PQ untouched.

**iOS constraint:** iOS 16+. Honest limitation to state in-product: this proves an *unmodified Occulta app* executed the burn protocol — it cannot prevent screenshots or a jailbroken recipient, the same honest-recipient boundary as every ephemeral system and as the documented "compromised install" trust boundary. Market as protocol proof, never as DRM.

> **Ruling (July 2026):** No new attack surface — receipts are signatures over non-secret data with their own domain prefix. Low-medium lift. **Priority: Near-to-mid-term.**

---

### 25. On-Device Visual PII Redaction (Pre-Encryption Pipeline)
**Added July 4, 2026 (feature ideation pass)**
**Category:** Privacy
**Audience:** Journalists protecting sources in photos, parents, protest documentation — and a feature that demos well, which matters for growth in a category where protocol features rarely do

Optional pass before basket assembly: Vision framework detects faces (`VNDetectFaceRectanglesRequest`), human figures, and text regions (`VNRecognizeTextRequest` — catches license plates, street signs, documents in frame); the user taps regions to irreversibly pixelate/blackout via Core Image, then the redacted image enters the normal encryption flow. Fully offline — Vision runs on-device, no network entitlement anywhere near it.

**Why new / overlap declaration:** The Share Extension plan ships EXIF/GPS stripping — that removes *metadata about* the image. This removes identifying *content within* the image, a different threat (a photo of a source is identifying regardless of EXIF).

**Security model fit:** No server, no crypto changes, SE untouched, no metadata (redaction happens pre-encryption in-process; originals deleted per the share-extension cleanup discipline — redact-then-delete inside the same do/catch pattern). FS/PQ untouched.

**iOS constraint:** iOS 16+. Redaction must re-encode the image and destroy the original — never store both. Pixelation must be destructive (heavy mosaic/solid fill; light blurs are ML-reversible, so zero-tolerance means solid fill by default).

> **Ruling (July 2026):** No cryptographic attack surface — the failure mode is UX (a missed region), mitigated by a manual-confirm workflow, never auto-send. Low-medium lift. **Priority: Near-to-mid-term.**

---

### July 4, 2026 Pass — Ranking by Impact-to-Lift

| Rank | Item | Impact | Lift | Phase |
|---|---|---|---|---|
| 1 | Owner Device Set (#18) | Very high | Medium | Near-term |
| 2 | Guardian Revocation Certificates (#19) | Med-high | Low | Near-term |
| 3 | Uniform Basket Envelopes (#21) | Medium (credibility-critical) | Low | Near-term |
| 4 | Serverless Passkey Provider (#20) | Very high | Med-high | Mid-term |
| 5 | Mutual-Contact Discovery (#22) | Medium | Low-med | Near-mid |
| 6 | Signed Destruction Receipts (#24) | Medium | Low-med | Near-mid |
| 7 | Hybrid PQ Signatures (#23) | Med-high | Medium (~~SDK-gated~~ — SDK gate met 2026-08-14; gated on artifact availability) | Mid-term |
| 8 | Visual PII Redaction (#25) | Medium | Low-med | Near-mid |
| 9 | Air-Gapped SE Wallet Signer (Expansion I) | ~~High potential~~ **Removed 2026-08-14** | High | ~~Exploratory~~ — see Expansion I's August 14 addendum |

**Top 3 of this pass:**
1. **Owner Device Set (#18)** — kills the single biggest adoption objection ("what if I lose my phone") using ceremony code already shipped.
2. **Guardian Revocation Certificates (#19)** — highest reuse ratio in the batch (ECDSA + SSS + baskets, all shipped) and completes the key lifecycle reviewers will probe first.
3. **Serverless Passkey Provider (#20)** — the only idea in this pass that opens the mainstream password-manager market, with a pitch ("hardware-bound passkeys, no YubiKey, no cloud") no incumbent can copy without abandoning their sync architecture.

> **Addendum (July 10, 2026):** Item 1 above (Owner Device Set, #18) is superseded — see the addendum on section 18 above and [Multi-Device Contacts/ROADMAP.md](Multi-Device%20Contacts/ROADMAP.md). The cert-vouching mechanism this ranking assumed was rejected as a security hole; the feature was renamed **Multi-Device Contacts**, narrowed to a data-model bug fix, and downgraded from Near-term/Rank 1 to opportunistic/low-priority. Guardian Revocation Certificates (#19) and Serverless Passkey Provider (#20) are unaffected and retain their rank/priority.
>
> **Addendum (July 22, 2026):** Correction to the addendum immediately above — Guardian Revocation Certificates (#19) is *not* unaffected. See the July 22 addendum on section 19 itself: the existing "Revoke Key" contact action already delivers this feature's entire worst-case-bounded value with zero new engineering, so #19 is downgraded from Rank 2/Near-term to positioning-only. Serverless Passkey Provider (#20) retains its rank/priority.

### Ideas Considered and Omitted (July 4, 2026 pass)

- **Anonymous source drop / SecureDrop-lite** (encrypt-to-published-journalist-key): any workable design either reuses prekeys across unknown sources (the documented prekey-sharing flaw) or ships a mode without forward secrecy. FS must never be weakened — omitted rather than softened.
- **Peer app-integrity attestation during exchange** (App Attest proving the peer runs a genuine Occulta binary): would close part of the "compromised install" gap, but attestation-key creation requires a round trip to Apple's attestation service — a remote dependency and a usage signal to a third party. Zero-server/zero-telemetry — omitted. Revisit only if Apple ships fully offline attestation.
- **Key-transparency log / chain-anchored timestamping:** requires a network or public ledger dependency — omitted; #22's corroboration achieves the useful subset P2P.
- **Duress biometric variants:** iOS cannot distinguish which finger/face authenticated, and passcode-level duress is already covered by the Deniable Partitions + Panic Wipe cluster (Consumer #6, #3) — not new.
- **True DH-PSI for contact discovery:** needs hash-to-curve and raw scalar multiplication CryptoKit doesn't expose; a hand-rolled constant-time curve implementation would violate the Apple-frameworks-only convention — replaced by the HMAC construction in #22.

---

### 26. Verified Payment Instructions (Signed Payment Rails)
**Added July 10, 2026 (community demand pass)**
**Category:** Security / Anti-fraud
**Community demand:** Very high — BEC is the #2 crime type by losses in the FBI IC3 2025 report ($3.05B across 24,768 complaints, up from $2.77B); real-estate wire fraud alone was $275.1M in 2025 across 12,368 complaints; 86% of BEC losses moved by wire/ACH and are effectively unrecoverable; industry guidance (NAR, title insurers, state real-estate divisions) now recommends "establish a verbal authentication code with your title company at the start of the transaction" — the leakable analog version of what the protocol already does
**Audience:** Broad — home buyers/sellers, small businesses paying vendors, families moving large sums, escrow/title/law offices; the largest documented per-victim loss category adjacent to the app

Payment details (account/routing, IBAN, crypto address) become a first-class signed artifact: a structured basket sub-envelope signed by the sender's SE key under a new domain prefix (`"occulta-payment-instructions-v1"`), pinned to the physically-verified contact. Three UI rules do the work: (1) received instructions render as a pinned, immutable verified card — never editable text in a thread; (2) changes must be signed by the same key, and the UI diffs loudly ("⚠ account number changed from the instructions received June 3") — the entire BEC playbook is a last-minute unsigned "our bank details changed," which here cannot even be *represented* as verified; (3) a one-tap pre-wire Presence Verification (#15) challenge binds the live human, the instructions, and the amount to the key exchanged at ≤25 cm.

**Why the closed-loop critique (#12/D) does not apply:** real-estate parties physically meet — buyers meet their agent and usually the title officer; small businesses meet their vendors. The UWB ceremony slots into the first in-person meeting, and "all money instructions come only through this channel" is agreed as the transaction's explicit protocol — exactly how the industry's verbal-code recommendation already works, minus the leakable code.

**Why new / overlap declaration:** The June 2026 addendum to Expansion A covers wire-transfer verification only as a *live* presence check. BEC arrives asynchronously in a compromised email thread; the defense needed at the moment of wiring is a **trusted asynchronous artifact**, not just a challenge. No existing feature gives payment details pinned-immutable semantics with signed-change diffing.

**Security model fit:** No server (baskets); SE-signed under a new domain-separated prefix per the IDENTITY_CHALLENGE_PROTOCOL mandate — no existing signing path touched; travels only inside AES-GCM bundles (no metadata); FS/PQ untouched.

**iOS constraint:** iOS 16+, zero new primitives. Work is the structured payload type, the pinned-card UX, and the diff flow. Optional later: a signed "wire executed to account ending 1234, $X, [time]" confirmation receipt reusing the #24 pattern.

> **Ruling (July 10, 2026):** Strongest candidate of this pass. Largest documented dollar losses of any addressable category; the industry's own best practice is a weaker analog of the shipped protocol; hands the Expansion A wedge a concrete artifact adoptable bottom-up (one cautious title office can adopt unilaterally for its clients). Attack surface minimal — signatures over non-secret structured data, new prefix only; run CRYPTO_REVIEW_CHECKLIST §4. Low-medium lift. **Priority: Near-term (pairs with Presence Verification as an anti-impersonation release narrative).**
>
> **Addendum (August 9, 2026) — extended into Verified Payment Cards; decouples this feature's core value from #15.** Rule (1)'s verified card becomes a **pre-authored, reusable** artifact the owner maintains ahead of time and transmits with every request, composed with a short-lived signed *request* that binds a digest of the card it references. The recipient stores only a comparison baseline, never full details.
>
> The finding that drives it: **the card constrains the destination, which is worth more than proving the ask.** Against a *fully deceived* victim, funds can still only reach the counterparty's real account. **Sequencing consequence: substituting the signed request for rule (3)'s live #15 presence check removes that dependency — this feature can deliver its core anti-BEC value without #15**, which the "pairs with Presence Verification" framing in the ruling above no longer requires. **Scoping limit for any positioning:** protects payments to physically-met counterparties only; strangers (fake invoices, romance, investment scams) and gift-card rails are outside the closed loop.
>
> Full design, security analysis, open questions, prior art and viability read: **[Payment Cards/FINDINGS.md](Payment%20Cards/FINDINGS.md)**.

---

### 27. Anti-Scam Family Circle (Presence Verification Packaging + Two Small Features)
**Added July 10, 2026 (community demand pass)**
**Category:** Anti-fraud / Positioning
**Community demand:** Very high — $2.4B reported FTC losses for adults 60+; 1-in-4 people report encountering voice-clone scams (losses to $15K per incident); the BBB/CNN/McAfee "family safe word" advice genre is now permanent; grandparent-emergency scams are the canonical AI-fraud story of 2025–2026
**Audience:** Broad and mainstream — every user with parents or grandparents; also the app's most natural viral loop (protecting one parent installs Occulta on 2–5 family devices, each install physically verified by definition)

Presence Verification (#15) already is the cryptographic family safe word. What's missing is the product wrapper a worried adult child can deploy on a parent's phone in ten minutes:

1. **Assisted Mode** — a simplified UI profile for the relative's device: a single large "Check it's really them" button running a presence challenge against the claimed family member, with plain-language verdicts ("✓ That was really Sarah — confirmed by her phone just now" / "✗ No confirmation. Hang up and call Sarah's number.").
2. **Second Opinion** — one tap forwards a suspicious request (screenshot, voice note, message text) as a structured basket to a designated family guardian; the reply renders as a clear verdict card. One basket type plus UX; zero new crypto.
3. **Money-request rule** — messages asking for money/gift cards/codes prompt the presence check first, and tie into #26 for the family case ("the only account details that count are signed ones").

**Why new / overlap declaration:** #15 ships the primitive; this is the deployment story for the demographic the scam wave actually targets, who will never navigate challenge/attestation vocabulary. No packaging/UX-profile concept exists anywhere on this list.

**Security model fit:** Nothing new — all flows are shipped or planned primitives. Assisted Mode is a UI profile, not a permission model: same crypto, same biometric gates, fewer choices, larger type. No remote management; the guardian sees only what the elder explicitly forwards.

**iOS constraint:** Almost entirely UX work.

> **Ruling (July 10, 2026):** Highest reach-to-lift ratio of this pass. This is how Presence Verification escapes the security-literate niche and becomes the app a normal person installs for their mother — the bottom-up adoption path Section 2 identifies as the only realistic route to everything else. **Priority: Near-term, sequenced with/immediately after Presence Verification ships.**

---

### 28. Sealed Evidence Journal (Tamper-Evident, Guardian-Witnessed)
**Added July 10, 2026 (community demand pass)**
**Category:** Security / Duress-cluster extension
**Community demand:** Medium-high — DV advocacy orgs (NNEDV Safety Net, Operation Safe Escape) explicitly instruct survivors to preserve evidence *before* removing stalkerware or cleaning devices, and note court-grade preservation currently requires professional digital forensics; existing survivor-evidence apps are cloud-based — fatal when the abuser controls or monitors accounts. Parallel 2026 demand: documenting ICE encounters and protest policing, where current guidance ("back footage up to Google Drive/iCloud immediately") routes evidence through exactly the accounts that get subpoenaed, taken over, or watched
**Audience:** Narrow-medium but intensely motivated — DV/stalking survivors, protest documenters, journalists; the adversary (a person with physical or account-level access) is precisely the v1.8 adversary model

An append-only journal in the vault: each entry (photo, screenshot, audio, text note) is hashed into a chain; chain heads are SE-signed with timestamps. Periodically — and on demand — the signed chain head travels as a small basket to chosen guardian contacts, whose apps countersign a receipt ("held chain head H at time T"). The guardian receipt is the piece purely local designs cannot provide: tamper-evidence anchored outside the device with no server, no blockchain, no cloud account — just physically-trusted people holding 32 bytes. Entries live in the vault and automatically inherit Travel Mode, deniable partitions, and Panic Wipe when the duress cluster ships; a survivor's journal can sit in the hidden partition. In-product framing must be honest: chain-of-custody *support* — proof the record existed by date X and is unaltered since — not automatic court admissibility.

**Why new / overlap declaration:** Extends the Trajectory doc's projected "Sealed Session Transcripts" in two declared ways: from message transcripts to arbitrary user-captured evidence, and adding the guardian-witnessed external anchor a purely local chain lacks (a local-only chain is self-attested — the owner could rebuild it). Reuses the #24 receipt machinery and basket rails. Distinct from the Dead Man's Switch (#8): nothing is released; guardians hold hashes, never content.

**Security model fit:** No server; SE signs chain heads and receipts under new domain prefixes; guardians receive hashes only; pad receipt bundles per #21 so "evidence-journal user" is not inferable from traffic shape; FS/PQ untouched.

**iOS constraint:** iOS 16+. Hash chain + signing is trivial; the work is capture UX, chain bookkeeping, and the guardian receipt flow. Camera capture must go straight into the journal (never through the system camera roll) — same cleanup discipline as the share extension.

> **Ruling (July 10, 2026):** Deepens the duress cluster's story from "protect what you hide" to "prove what happened," for the same audience, on the same rails. The deniable-partition dependency is the right sequencing reason to slot it after the duress cluster. Medium lift. **Priority: Phase 2 (with the duress cluster).**

---

### July 10, 2026 Pass — Ranking by Impact-to-Lift

| Rank | Item | Impact | Lift | Phase |
|---|---|---|---|---|
| 1 | Verified Payment Instructions (#26) | Very high ($3B+ documented losses; artifact no competitor has) | Low-med | Near-term |
| 2 | Anti-Scam Family Circle (#27) | Very high (mainstream reach + viral install loop) | Low | Near-term (with #15) |
| 3 | Sealed Evidence Journal (#28) | Med-high (intense niche; duress-cluster synergy) | Medium | Phase 2 |

Re-prioritisations folded from this pass: #21 promoted from opportunistic to scheduled (Chat Control reinstated July 9, 2026); Expansion H scoping pulled forward (KOSA passed the House June 29, 2026); duress-cluster audience expanded to domestic US (see Section 3 addendum). Positioning items (Chat Control counter-positioning — time-sensitive; proof-of-personhood contrast vs. World ID; Signal-hosted-backup contrast) are documented in `Feature Ideation — 2026-07-10 Community Demand Pass.md`.

### Ideas Considered and Omitted (July 10, 2026 pass)

- **Steganographic carrier bundles** (`.occ` payloads embedded in innocuous media, as a Chat Control reaction): statistical stego detection is an arms race not winnable with Apple-framework primitives; a *detected* stego carrier is a worse forensic artifact than a clean encrypted file; App Store review risk for the whole product. The defensible subset of the benefit (size/shape unlinkability) is exactly #21. Omitted.
- **Safety check-in for meetups** (dating/marketplace): Apple's Check In ships free and built-in since iOS 17. If the Dead Man's Switch (#8) ships, a short-fuse variant falls out nearly free — revisit then, not before.
- **Standalone personal C2PA / media-provenance suite:** platform momentum (C2PA in cameras and OS pipelines) will out-deliver app-level implementations for general media; only the in-circle capture-attestation slice survives scrutiny — ship **signed voice notes** as a small affordance inside the Presence Verification narrative (SE signature over media hash + timestamp at in-app capture, `"occulta-attested-capture-v1"`, same honest-app boundary as #24), not as a standalone feature.
- **Scam-detection AI / content classifiers:** on-device models flagging message content bring false-positive liability and scope creep; network services are excluded. The Second Opinion flow (#27) achieves the useful subset with a human the user trusts.
- **Verified introductions (transitive trust / vouching):** re-affirmed as off-limits — every entry in the graph is physically verified or the graph's core claim dies; #22's corroboration remains the ceiling.

---

### 29. Situational Contact Actions — "Trust Check" Picker
**Added July 22, 2026 (session following the Guardian Revocation Certificates re-scoping, #19)**
**Revised July 22, 2026 (same-day, eight passes)** — rescoped from a global picker to a contact-detail-embedded one; narrowed to security/identity events only, CRUD excluded; renamed from "Something happened?" to "Significant Event" and moved below Message/Edit Contact since those are used far more often; added per-scenario eligibility so a scenario is only offered when the contact actually qualifies for it; the entry point itself is now hidden entirely when zero scenarios are eligible, rather than opening onto an empty list; renamed to "Security Actions," then to "Trust Check"; **the fourth scenario (Vault Trustee, originally "custody") removed entirely** — see below
**Category:** UX / Discoverability
**Audience:** Broad — every user with at least one contact; adds no new capability, makes existing ones findable

A guided, scenario-first prompt inside a specific contact's detail view — "Trust Check," positioned below the routine Message/Edit Contact actions rather than above them — that maps a plain-language event *about that person* to whichever existing security or identity action already addresses it, instead of expecting the user to already know that "this contact's phone was stolen" means "go to Contact → Edit → Revoke Key."

**First rescoping (global → contact-detail).** The original draft was a single global list reachable from the top of the Contacts tab, covering both contact-scoped events and device-level events ("I lost my own phone"). Splitting it revealed a stronger design: the contact-scoped scenarios are inherently about one person, and if the user is already looking at that person's contact card — which is what they'd naturally do after hearing from them — routing through a global list and picking the contact back out is a wasted screen. Embedding the prompt directly in contact detail removes that step, and two of its destinations (Revoke Key, the Private toggle) already live on that exact screen today. Device-level events have no associated contact and remain out of scope for this entry.

**Second narrowing (security/identity only, CRUD excluded, custody removed).** A codebase pass for other contact-scoped actions turned up Delete Contact (`Contact+Manager.swift:435`) as a real, shipped, contact-specific action — but on review it was explicitly excluded: this picker's purpose is routing a security-relevant event to the action that resolves it, and plain data management (editing a name, deleting a record) isn't that, even when it's contact-specific. Mixing "something happened, get help" with "manage this record" would blur exactly the distinction the picker exists to draw.

The picker originally also carried a fourth, "custody" scenario — Vault shard trustee designation — but it was cut on the same reasoning that excluded Delete Contact: it isn't a reactive security event either. An implementation-planning pass into `ShamirSecretSharing.swift` and `Vault+ShardSetup.swift` confirmed why it doesn't fit even setting the framing question aside — adding one trustee isn't an independent action. `ShamirSecretSharing.split` (`ShamirSecretSharing.swift:111-118`) regenerates a fresh random polynomial on every call, so there's no way to hand out one incremental share; `VaultShardSetup.markForDistribution()` (`Vault+ShardSetup.swift:607-656`) re-runs the full split across the *entire* trustee roster and pushes a `.replace` operation — invalidating and reissuing — to every trustee already in place, not just the new one. That's real multi-party blast radius triggered from what would have looked like a quick, contact-scoped confirmation. It belongs with the deliberate, multi-step setup flow it already has in Vault → Settings, not next to "something happened?" prompts a user taps into mid-crisis. The three remaining scenarios all fall cleanly under security/identity and none are CRUD:

| Scenario | Routed action | Reachable today? |
|---|---|---|
| [Name]'s phone was lost or stolen | Revoke Key (`ContactManager.reset(identity:)`, `Contact+Manager.swift:524`) | Yes — shipped |
| I got a suspicious call or message from [Name] | Identity Challenge | Yes, but scope the promise to "still controls the key as of now" — see iOS constraint |
| Hide [Name] if my phone is forced open | Mark Private / Secure Mode classification (`ContactManager+Classification.swift:76`) | Yes — shipped |

**Considered and left out:** **Delete Contact** — real and shipped, but out of scope by design (CRUD, not a security/identity event; see above). **Vault shard trustee designation** — real and shipped (via Vault → Settings), but out of scope by design: not a reactive event, and structurally a multi-party operation (see above), not a single-contact one. **Removing one person from a shared group** (`Contact+Manager+Groups.swift:58`) — technically contact-specific, but the only real UI path is deselecting a checkbox while editing the whole group's membership (`Group+FormV3.swift:238`), which doesn't read as an event about *this contact*. No block/mute/report action exists anywhere in the codebase to consider.

**`enableShamirShardSharing` flipped to `true` in `features.plist` (2026-07-22), unrelated to Trust Check's scope directly but decided during this investigation.** Since the flag has zero call sites anywhere in the codebase (see iOS constraint below, formerly #2), this has no functional effect on the shipped app today — it's a housekeeping change so the plist reflects intent (SSS custody is considered live, not experimental) rather than a stale `false` that could read as "still gated" to a future reader. If the flag is ever wired to something real, this is already set correctly.

**A small compensating discoverability hint, separate from Trust Check itself.** Removing Vault Trustee left the underlying problem this doc has repeatedly named — most users never visit Vault → Settings at all, so a capability that only lives there effectively doesn't exist for them — unaddressed for this specific case. Rather than reintroduce a scenario the multi-party finding above rules out, contact detail gets a small inert "Trustee" chip (dashed outline, reusing the exact visual meaning "not yet" already established by the Pending Exchange badge) shown when a contact has ML-KEM material and isn't already a trustee. It has no tap target — it's a curiosity hook, not a shortcut, and it deliberately can't trigger the re-split/reissue chain, since it does nothing at all beyond render.

**Correction (2026-07-22, same day): "isn't already a trustee" is not a single check.** The product owner flagged directly that the app has *two* separate trustee mechanisms, which an earlier pass through this doc missed — the mockup and the claim above only ever checked one of them. Both are real, both matter, and they don't behave the same way:

- **Global roster** — `GlobalShardConfig.Payload.trusteeIDs: [String]` (`GlobalShardConfig+Model.swift:66`), a single app-wide list. Checked via `shardCustodyManager.globalShardConfig()?.trusteeIDs.contains(identifier)` (`ShardCustody+Manager.swift:406-417`), sealed under a device-unlock-level key (`Key+Manager.swift:816-839`, explicitly "no `LAContext` needed"). Cheap, and available whether or not the vault itself is unlocked.
- **Per-item roster** — `ShardDistributionMetadata.shards: [ShardRecord]` (`Vault+Model.swift:94-99,79-88`), one list *per vault entry* (and a separate one for the backup key, via `bekShardMetadata()`), sealed under the vault key itself. `VaultManager.shardRecordsForTrustee(_:)` (`Vault+Manager+Shards.swift:401-420`) is the only function that answers "is this contact a trustee of mine anywhere" for this half — and it does so by fetching *every* `VaultEntry` and running an AES-GCM decrypt on each one's `shardDistributionEncrypted` blob, purely to check one contact. There is no per-contact index.

**The two checks are not just two lookups — one of them can lie.** `shardRecordsForTrustee` requires the vault to be unlocked; if it's locked, it silently returns `[]`, which is indistinguishable from "genuinely not a trustee for anything." A chip suppressed only by this check would risk confidently showing "not yet a trustee" for someone who already holds a shard, purely because the vault happened to be locked at render time — the exact class of "badge claims something false" mistake this doc has otherwise been careful to rule out (see the naming/pronoun/eligibility disciplines above).

**Not yet resolved — this needs a product call, not an engineering default.** Two live options, with the tradeoff stated plainly rather than picked silently:
1. Combine both checks; when the vault is locked (so the per-item half can't be answered), suppress the chip entirely rather than risk showing a false "not yet." Correct, but adds a full vault-entry decrypt-scan to a screen this doc has already established gets visited far more often than Vault itself — a real performance cost for a purely decorative hint, worth caching per session rather than re-running on every contact-detail render.
2. Keep the chip on the global check alone, and accept — documented, not silently — that a contact who is *only* a per-item trustee (holds a shard for one specific entry but was never added to the global roster) would be incorrectly offered the "not yet" hint. Cheaper and simpler, at a known, bounded accuracy cost for a low-stakes, inert, non-actionable element.

The mockup currently implements option 2 (global check only) as originally built, pending this decision — it has not been changed to reflect the correction above.

**Position, naming, and per-scenario eligibility.** Message and Edit Contact are opened on nearly every visit to this screen; Trust Check is opened rarely, by definition — it only applies when something has actually gone wrong. Placing it below the routine actions, and naming it as a noun phrase rather than a question, keeps it from competing with what the screen is used for most of the time while staying one scroll and one tap away. On top of that, each scenario now carries its own eligibility check, not just the feature-level reachability check described under iOS constraint below:
- **Revoke Key** and **Identity Challenge** only appear if the contact's key is currently active (`state === verified` in the mockup, mirroring the real `keyIsRevocable` gate already on the shipped Revoke Key button) — a contact whose key is already revoked has nothing left for either action to act on.
- **Hide contact** only appears if the contact isn't already marked private.

With only one category of scenario left after custody's removal, the picker no longer groups rows under a section header at all — a "Security & identity" label would just repeat what the screen's own title already says.

**Naming: "Trust Check" over "Security Actions."** A friction review of this entry raised a real risk in the naming trend up to that point ("Something happened?" → "Significant Event" → "Security Actions"): each step moved further toward auth/security vocabulary and further from the "identity first, not auth" framing the Consumer Opening memo argues is the strongest idea available to this product. A label sitting on every contact's page that reads as a security alert risks a low-grade "is something wrong with this contact?" signal even when nothing is. "Trust Check" was chosen over softer alternatives ("If something's wrong," "Need help with [Name]?") specifically because it stays legible on its own without over-explaining itself in the label — the label doesn't need to enumerate what it covers, since tapping it immediately shows the scenarios; ambiguity at rest, clarity on tap, is an acceptable trade for a row that must sit quietly on a screen most visits don't need it.

**The entry point disappears, not just the list.** If a contact fails every scenario's eligibility check — key already revoked, already marked private — Trust Check doesn't open onto an empty screen; it isn't shown at all on that contact's detail view. An empty picker would still have been a real state to design for (what does "nothing applies" even communicate to a worried user?); removing the entry point avoids the question rather than answering it, which is the right call here — there is no version of "nothing you can do" that reads as reassuring rather than alarming, so the honest move is to not raise it.

**Why new / overlap declaration:** Concrete implementation of the recommendation in #19's addendum ("make Revoke Key discoverable"), generalized to every contact-scoped security/identity action instead of a bespoke fix per feature. Also subsumes the *mechanism* (not the audience) of Anti-Scam Family Circle (#27)'s "Assisted Mode" and "Second Opinion" — still valid under the narrower scope, since both are themselves about a specific contact.

**Security model fit:** No new cryptography, no new attack surface — pure navigation over already-shipped actions. The scenario→action mapping is content, not code, but it's a living artifact that needs a pass whenever a destination's status changes elsewhere in this doc.

**iOS constraint:** None beyond standard SwiftUI navigation. Three copy/design disciplines matter more than the technical lift:
1. **Suspicious call/message** must not imply live-call authenticity — Identity Challenge proves "still controls the key," not "this is them, right now." Presence Verification's live-window mode would provide that stronger claim and is currently Delayed on an unresolved relay attack (#15's addendum).
2. **Scenario and result copy must name the contact, never refer to them by pronoun.** Each scenario is read one contact at a time in a security context, where an ambiguous "they/them/their" costs more than the minor repetition of using the name twice in a sentence — explicit beats concise here.
3. **Eligibility must be evaluated per contact at render time, not cached or assumed.** A contact's key state and private flag can both change between visits (a re-exchange, a duress-classification edit); the picker has to re-check on every open rather than reusing whatever was true last time.

> **Ruling (July 22, 2026, revised eight times):** Narrowing to contact-detail placement strengthens the case rather than shrinking it — it cuts a screen from the three originally-global scenarios. Excluding CRUD, and later excluding Vault Trustee on the same reasoning plus the multi-party-blast-radius finding, keeps the picker's purpose legible: this answers "something happened, what do I do," not "manage this contact" and not "set up a recovery scheme." Repositioning below the routine actions and adding per-contact eligibility are both refinements in the same direction — the picker earns its place by only ever showing what's true and actionable for the contact in front of the user, never a menu padded with options that don't apply or don't belong. What's left is deliberately small: three scenarios, all copy and routing over already-shipped actions, no new engineering. **Priority: Near-term.**
>
> **Shipped — v1.10.0.** Implemented as `TrustCheckV2` on `ContactDetailV2` (`2b1c486`, live-state fix `aed5895`). No longer a roadmap item.

---

## Section 1 Summary Table

| Rank | Feature | Status | Audience | Phase |
|------|---------|--------|----------|-------|
| 2 | Offline Travel Mode | **Keep** | Broad | Phase 1 |
| 3 | Cryptographic Panic Wipe | **Keep** | Medium-broad | Phase 1 |
| 15 | Presence Verification | **Delayed** — see July 10 addendum (unresolved relay/MITM gap) | Broad | Blocked, not scheduled |
| 6 | Deniable Vault Partitions | **Keep** | Narrow-medium | Phase 2 |
| 8 | Shamir Dead Man's Switch | **Keep** | Narrow-medium | Phase 2 |
| 10 | NFC Key Exchange | **Keep** | Medium | Phase 2 (lower) |
| 17 | Duress-Aware 2FA Codes | **Keep** | Medium-broad | Phase 2 (after duress cluster) |
| 16 | Serverless Social Recovery | **Built** (flagged) | Broad | Positioning/UX pass only |
| 18 | Multi-Device Contacts (was "Owner Device Set") | **Keep — narrowed to bug fix 2026-07-10** | Broad ambition shelved; bug fix affects all multi-device users | Opportunistic, low-priority |
| 19 | Guardian Revocation Certificates | **Downgraded 2026-07-22 — positioning only, see addendum** | Broad | Ongoing (positioning, no engineering) |
| 21 | Uniform Basket Envelopes | **Keep** | — (protocol) | Near-term, opportunistic |
| 20 | Serverless Passkey Provider | **Keep** | Broad | Mid-term |
| 22 | Mutual-Contact Discovery | **Keep** | Narrow-medium | Near-mid |
| 24 | Signed Destruction Receipts | **Keep** | Narrow-medium | Near-mid |
| 23 | Hybrid PQ Signatures | **Keep** | — (protocol) | Mid-term (SDK-gated) |
| 25 | Visual PII Redaction | **Keep** | Narrow-medium | Near-mid |
| 26 | Verified Payment Instructions | **Keep** | Broad | Near-term |
| 27 | Anti-Scam Family Circle | **Keep** | Broad | Near-term (with #15) |
| 28 | Sealed Evidence Journal | **Keep** | Narrow-medium | Phase 2 |
| 29 | Situational Contact Actions ("Trust Check" Picker) | **Shipped — v1.10.0** | Broad | Shipped |
| 1 | Wi-Fi Aware Basket Delivery | Removed | — | — |
| 4 | YubiKey NFC Second Factor | Deferred | — | — |
| 5 | Contact Compromise Detection | Removed | — | — |
| 7 | Proximity Outbox | Removed | — | — |
| 9 | Offline Mesh Relay | Removed | — | — |
| 11 | M-of-N Group Document | Removed | — | — |
| 12 | SE-Attested vCard | Removed | — | — |
| 13 | Filename Encryption | Opportunistic | — | — |
| 14 | Vault Health Check | Removed | — | — |

---

# Section 2 — Platform Expansion Opportunities

These are not features added to the existing consumer app. They are separate applications of Occulta's trust primitive to adjacent markets. Each uses the same UWB proximity gate + Secure Enclave key binding as its identity root. Ranked by market size and defensibility.

---

## Enterprise Reality Check

Before treating any of these as near-term targets, the structural barriers to enterprise sales need to be named explicitly.

**What enterprise procurement requires before the first customer signs:**
- **Compliance certifications**: SOC 2 Type II, ISO 27001 at minimum. Healthcare requires a HIPAA BAA. Government requires FedRAMP — a 12–18 month process costing $500K–$2M in auditing and engineering before a single contract.
- **Central administration**: IT needs a console to provision accounts, revoke access, and manage offboarding. Occulta has none — that is the security property. Building it means building a server, which means building a second product.
- **MDM integration**: Enterprises deploy apps via Mobile Device Management (Jamf, Intune). Apps must be configurable and revocable via MDM profiles.
- **SSO/IdP integration**: Enterprise authentication must integrate with existing Entra/Okta deployments via SAML or OIDC.
- **Audit logging**: Regulators and auditors require server-side records of who accessed what and when. Zero-server means zero audit trail — a compliance blocker in most regulated industries.
- **Support SLAs, legal contracts, DPAs**: No enterprise procurement closes without these.
- **A sales team**: Enterprise identity is not App Store software. It requires outbound sales, proof-of-concept deployments, security reviews, and multi-month procurement cycles.

**The architectural conflict**: FedRAMP — the government certification that would unlock the most promising market segment — requires a cloud backend. Occulta's zero-server architecture is structurally ineligible. Pursuing government enterprise would require building the server Occulta was deliberately designed not to have.

More broadly, everything that makes Occulta compelling to a privacy-conscious consumer — no admin override, no central visibility, no server-side audit trail — is a liability to the CISO whose job is demonstrating data governance to auditors.

**The closest comparable: Beyond Identity.** Founded 2020, raised $205M, hired an experienced enterprise sales team, built full SOC 2 / compliance infrastructure, uses the same underlying primitive (device SE-bound keys, challenge-response, no secret transmitted), and targets enterprise authentication. Their pitch: replace passwords and SMS OTP for logging into Salesforce, AWS, GitHub, and Okta. Five years in, they are struggling against Microsoft Entra and Okta's incumbent relationships, 12–18 month sales cycles, and conservative enterprise procurement. That is the best available data point for how hard this market is — even with $200M, a full team, and FIDO2 standards compliance.

Occulta is not trying to do what Beyond Identity does. Beyond Identity replaces enterprise app logins; Occulta's enterprise vision is a physically-verified web of trust for communications and authorization. They are genuinely different problems, and Occulta's web-of-trust property (who physically vouched for whom — traceable chain, not just "credential issued by our system") is something Beyond Identity cannot provide. But Beyond Identity's difficulty is a warning, not a roadmap.

**The realistic path to enterprise**: Not direct sales. The way privacy tools enter enterprise is bottom-up — security researchers, journalists, lawyers, and activists use a tool personally, love it, and bring it to their organisations. IT eventually approves it. This is how Signal entered enterprise: not by selling to CISOs, but by being the tool individuals insisted on using. The highest-leverage action for enterprise relevance is therefore an exceptional consumer product adopted by individuals who matter. The expansion opportunities below describe what Occulta's architecture could eventually power — they are not near-term go-to-market targets.

---

### A. Organizational Identity Graph
**Conviction:** High
**Market size:** Very large — every enterprise faces the "stolen credential" attack class
**Technical lift:** Medium (enterprise SDK)

New employees exchange keys with HR on Day 1 — this is the identity root event. That SE-bound key becomes their credential for internal communications, document access, and system authentication. No account to compromise remotely; no credential database to exfiltrate. Contractors and vendors undergo a physical onboarding gate before receiving any access. Offboarding: delete access tokens; the key remains but authorization is gone.

```
IT/HR Admin (root)
  └── Exchanges with every employee on Day 1
       └── Employees exchange with their teams
            └── Each relationship is physically verified
```

This eliminates the entire class of "stolen credential" and "phished account" attacks for internal access. The annual cost of credential-based breaches to enterprises is enormous and well-documented. The physical onboarding ceremony is the competitive moat: no remote attack can substitute a new key because physical presence was required to establish the original.

> **Ruling (May 2026):** The market framing ("every enterprise") is wrong. Here is the honest competitive picture.
>
> **What Occulta is up against:** Passkeys (FIDO2) use the same underlying primitive — device SE, P-256, challenge-response, no secret transmitted — and are being actively deployed by Microsoft Entra, Okta, Ping, and Duo right now. Large companies are migrating to them today. The one difference: passkeys allow remote self-enrollment. Occulta requires physical presence. From an enterprise's perspective, "we can onboard 10,000 remote employees with zero physical meetings" beats "everyone must physically tap phones with HR" unless the organisation has a specific threat model that makes remote credential issuance itself a risk.
>
> For organisations that do have that threat model — government agencies, defence contractors, intelligence-adjacent organisations — the entrenched solution is CAC/PIV smart cards: hardware-bound credentials with mandatory physical issuance, FIPS 201-certified, deployed at scale for 20+ years. Displacing that requires government security certification (FIPS, FedRAMP) and a multi-year procurement cycle.
>
> **What Occulta uniquely has:** Every other enterprise identity system is hub-and-spoke — credentials flow through a central IdP. Occulta is a web of trust: every edge in the graph is a physical meeting between two specific people. No existing IdP can answer "did our CTO personally verify this contractor, or did someone just add them to the system?" Occulta can. That is a genuinely unique property that passkeys and Entra do not provide.
>
> **The realistic market:** Three narrow segments, not the general enterprise market. (1) High-security government-adjacent organisations already requiring physical onboarding that want a phone-native alternative to card readers — requires FIPS certification to enter. (2) Small high-trust organisations (intelligence-adjacent, legal partnerships, investigative journalism) where chain-of-custody on credential issuance has operational value — tiny market globally. (3) A premium complement to existing FIDO2/passkey deployments for the highest-privilege roles (executives, system admins, root access), adding a physical bootstrap layer on top of infrastructure that stays in place. This last one is the most realistic near-term enterprise story — it positions Occulta as an add-on, not a replacement.
>
> The physical proximity requirement removes Occulta from competition with Okta and Microsoft Entra for the mainstream enterprise market entirely. Pursue only if willing to invest in government security certification or accept the narrow high-trust niche.

> **Addendum (June 2026):** Consumer Feature #15 (Presence Verification) supplies the concrete wedge this expansion was missing. The two hottest enterprise identity attack patterns of 2025–2026 — helpdesk MFA-reset social engineering (Scattered Spider/MGM playbook) and deepfake executive fraud (Arup, $25M) — are both "verify the human, not the credential" problems. Incumbent fixes (Nametag, HYPR Affirm) are cloud services running government-ID + selfie biometric pipelines. Occulta's version: the helpdesk demands a signed presence check against the key HR exchanged on Day 1; finance policy requires one before any wire transfer. No ID upload, no biometrics vendor, no cloud. This is bottom-up adoptable (a family anti-scam feature that scales into an enterprise control), consistent with the "premium complement, not replacement" positioning above, and requires no certification to pilot in a small high-trust org.
>
> **Addendum (July 10, 2026):** This wedge is on hold. #15 was delayed (see its ruling addendum) after a relay/MITM attack was reclassified from an accepted residual risk to a blocking gap with no known guaranteed fix. Since the wedge here — helpdesk MFA-reset and wire-transfer verification — is precisely the "resourced, real-time attacker" scenario that attack targets, this expansion inherits the delay rather than being independently viable.
>
> **Addendum (August 9, 2026) — protocol generalization explored, separable from the Presence Verification delay above.** A design pass asked whether Expansion A's undesigned "enterprise SDK" could instead be a generalized protocol — any org's relying party verifies Occulta identity without a bespoke integration, the way MCP decouples client from server and WebAuthn decouples relying party from authenticator — rather than one-off per-org integration work. Base mechanism (org-root-signed membership attestation, challenge-response modeled on the already-shipped `IDENTITY_CHALLENGE_PROTOCOL`) needs only Identity Challenge, not live Presence Verification, so it is *not* blocked by the addendum above. Found a real blocking gap of its own: no design yet for delegated vouching at org scale that doesn't reopen the self-vouching hole `Multi-Device Contacts/FINDINGS.md` already closed for a single device. See [Organizational Identity Graph/FINDINGS.md](Organizational%20Identity%20Graph/FINDINGS.md).
>
> **Addendum (August 9, 2026, second pass) — reviewed, then re-architected.** Three follow-on sessions the same day (FINDINGS.md Design Sessions 2–4) revised the addendum above on both of its claims.
>
> **The separability claim was correct but backwards.** The base protocol genuinely doesn't depend on #15 — but what made this expansion's wedge compelling was the *presence* claim ("this human is here, now"), not the *membership* claim ("this key belongs to an employee"). Membership-only is what Entra plus passkeys already ship at scale. The half that survives the #15 delay is the half carrying no differentiation. The sharper argument, and the one to lead with: **a relay attack requires a channel to relay across, and a co-located ceremony has none** — employee and admin in the same room at ≤25 cm, no remote leg for the mafia-fraud-class attack that downgraded #15 to occupy. In-person lifecycle ceremonies are therefore genuinely unblocked; remote presence checks remain blocked.
>
> **The standing-credential model was replaced.** Review found the org-root-signed membership attestation with TTL re-signing to be the common origin of five blocking findings: root-key continuity (a single admin's non-exportable SE key, with no rotation, escrow, or K-of-N), re-signing delivery (no automatic channel exists post-pairing — every bundle is a manual share sheet, confirmed against code in `Multi-Device Contacts/FINDINGS.md` Session 10), device-loss lockout with no possible remote recovery, cross-verifier linkability, and a discoverable affiliation artifact at rest that contradicts the duress cluster for this expansion's own target segments. Re-cast: **Occulta as the enrollment and recovery authority, not the credential.** The daily credential stays whatever the org already runs (Entra/Okta passkeys, YubiKeys, or #20); Occulta gates only enrollment, MFA reset/recovery, device addition, and step-up for irreversible actions — rare, friction-tolerant, high-value events matching what Occulta is actually good at. Artifacts are one-shot and event-bound, so nothing persists to revoke or refresh. Root becomes a pinned admin roster with thresholds scaled to blast radius — K-of-N for roster changes and top-tier step-up, a single roster signature for ordinary enrollment and recovery, so routine events never require assembling multiple admins. Delegated vouching — the blocking gap named above — is not solved but *removed*: the graph stays depth-1, scaled by widening the roster and narrowing enrollment to high-privilege accounts rather than by vouching downward. Scoping to high-privilege accounts is load-bearing twice over: it is what keeps the graph flat *and* what keeps the in-person friction survivable (a handful of ceremonies a year at ~50 accounts; indefensible at full headcount). One operational gap stays open and must be answered before any pilot — recovery when no roster holder is physically reachable, e.g. a device lost while travelling; the default recommendation is that privileged access remains suspended until in-person recovery, stated as policy up front rather than discovered mid-incident.
>
> **Also settled.** An OIDC IdP layer is rejected outright: an authorization server observing every login event is central metadata visibility, a mandate violation, and the compliance audit gap that makes it perpetually tempting is better answered by the relying party retaining signed artifacts in its own existing log. A W3C VC / SD-JWT issuer layer is deferred on linkability grounds plus Expansion H's own 2–3 year ecosystem gate. **Honest cost:** the "cryptographic proof of who physically vouched for whom" story is given up — it is not verifiable by any relying party, because an SE signature proves key possession, not that a proximity ceremony occurred, and closing that gap would require Apple App Attest in the verification path. What is kept is "a remote attacker cannot fabricate this event," which is deliverable and is what the documented attacks (helpdesk MFA reset, deepfake executive fraud) actually exploit.

---

### B. Physical Access Control
**Conviction:** High
**Market size:** Large — corporate offices, data centers, regulated facilities, high-security residential
**Technical lift:** Medium (companion hardware required)

A door controller or secure facility holds its own Occulta identity. An administrator grants access by encrypting a signed access token to the employee's public key. Entry requires a challenge-response: the door challenges, the device signs with its SE key, the door verifies against the stored public key. Revocation is instant: delete or re-encrypt the access token. The audit trail is ECDSA-signed and unforgeable.

RFID/NFC keycards — the current standard — are trivially cloned, frequently lost, and managed through centralized credential databases that are high-value attack targets. The Occulta model has no badge to clone (SE key is hardware-bound), no credential database to breach (access tokens are encrypted to individual keys), and no remote takeover path (physical presence was required to establish the key).

> **Ruling (May 2026):** Not a standalone opportunity. The document's competitive framing is outdated — it positions Occulta against cloneable RFID cards, but modern HID SEOS and iCLASS SE cards already use AES challenge-response and are not trivially cloned. More importantly, **HID Mobile Access already ships exactly what this expansion describes**: iPhone as credential, delivered over Bluetooth LE, NFC tap-to-enter, deployed at major enterprises today. Allegion, Assa Abloy, and Schlage all support it. Apple Wallet Home Key does the same for residential. The incumbent owns this market.
>
> Occulta's differentiators against HID Mobile Access — no cloud backend, physical UWB bootstrap — both work against Occulta here. Enterprise physical security teams want the cloud backend for centralised management and bulk revocation. And UWB bootstrap adds nothing for door access specifically: you have to be within NFC/BLE range to open the door anyway, so the proximity constraint is already enforced by physics.
>
> Additionally, you cannot make a phone the sole key to a building. Batteries die, phones are forgotten. Physical access control cannot fail open — RFID fallback stays in the system regardless, which means Occulta is always an add-on, never a replacement.
>
> Remove from the independent expansion list. Viable only as a downstream feature inside organisations already on Expansion A.

---

### C. Developer and API Authentication
**Conviction:** High
**Market size:** Large — financial APIs, healthcare systems, government services, critical infrastructure
**Technical lift:** Medium (SDK + server-side library)

API keys are stolen constantly — stored in `.env` files, committed to Git, leaked in logs, phished from developer accounts. The Occulta model: developer physically registers their SE identity with the API provider at onboarding. Every API call uses a challenge-response — server sends a nonce, client signs with the SE key, server verifies. No secret is ever transmitted. A stolen device cannot be used without biometrics; a phished developer account grants nothing because there is no account.

| Method | Weakness | Occulta equivalent |
|--------|----------|--------------------|
| API key / secret | Stored in plaintext, easily stolen | No secret exists to steal |
| OAuth token | Account compromise = token compromise | No remote account |
| FIDO2 / passkey | Self-enrollment; no physical-presence bootstrap | Physical bootstrap required |
| mTLS client cert | CA trust model; cert issuable by compromised CA | No CA; SE-bound |

> **Ruling (May 2026):** Real pain point, but Occulta only applies to one of three layers of the problem and the market framing needs to match.
>
> **Layer 1 — Service-to-service** (CI/CD, microservices, cron jobs): AWS IAM with OIDC, GitHub Actions OIDC tokens, and Workload Identity Federation already eliminate long-lived secrets here with zero hardware. An iPhone cannot sit in a pipeline. Occulta is irrelevant to this layer.
>
> **Layer 2 — Human developer authenticating to tooling** (GitHub, AWS console): Passkeys and FIDO2 hardware keys (YubiKey) already solve this. Deploying at security-conscious organisations today.
>
> **Layer 3 — Human developer making authenticated calls to a production API where the specific human's physical identity is legally required**: This is the only layer Occulta applies to. The current standard is mTLS with PKI client certificates, already deployed in healthcare (SMART on FHIR), financial services (PSD2 eIDAS certs), and government, and already meeting regulatory requirements.
>
> Occulta's genuine differentiator: the credential was physically bootstrapped, so "this API call was made by a human whose physical identity was verified in person" is provable in a way mTLS cannot match. That matters in a narrow set of regulated industries where the physical identity of the human actor has legal significance — physicians signing orders, regulated traders, government contractors.
>
> That is essentially the same buyer as Expansion A. Package the two together and position as a single regulated-industry identity platform, not as independent products.

---

### D. Document Signing and Notarization
**Conviction:** High
**Market size:** Large — legal, medical, journalistic, financial use cases
**Technical lift:** Very low — ECDSA signing from the SE is already implemented

Any document (contract, NDA, consent form, evidence release) can be signed by the SE key. The signature attests: "the human being whose public key you hold — the one you physically verified in person — signed this document." Counterparties verify the signature against the public key in their Occulta contact book. Multi-party agreements bundle all signatures independently.

DocuSign identity is an email address — trivially compromised, account-takeable. Occulta identity is SE-bound: you cannot sign if someone has your email; they need your unlocked device and your biometrics. The "I physically met this person" bootstrap means every signer's key was verified before any document was ever signed.

> **Ruling (May 2026):** Removed. The verifier must already have Occulta installed and have done a prior UWB exchange with the signer. No legal weight outside that circle — courts and counterparties do not recognise Occulta signatures. The "very low technical lift" claim is accurate for the signing half, but the verification problem is fundamental: this is a closed-loop trust system and the loop barely closes. The "self-assertion vs. identity trusted" UX caveat is not a design detail to solve around — it is the core limitation.

---

### E. M-of-N Authorization Controls
**Conviction:** High
**Market size:** Medium — financial controls, infrastructure operations, board governance, legal authorizations
**Technical lift:** Low — builds directly on existing Shamir SSS implementation

Any privileged action generates a payload that must be co-signed by M-of-N designated identities before execution. Co-signers are drawn from the authorizer's Occulta contact book — physically verified individuals only. The threshold is cryptographically enforced, not just policy. You cannot fake a co-signer. You cannot forge a threshold.

- **Financial controls:** Wire transfer over $X requires 2-of-3 CFO-verified identities to co-sign
- **Infrastructure operations:** Production deployment requires 2-of-N senior engineer approvals
- **Board governance:** Board resolution requires quorum proven by SE-signed votes from physically-verified board members
- **Legal authorizations:** Settlement approval, acquisition terms — threshold signatures

The M-of-N requirement is not procedural — it is mathematically enforced by Shamir's Secret Sharing. And crucially, a co-signer who was not physically present during key exchange with the original authorizer cannot be added to the quorum.

> **Ruling (May 2026):** Removed as a Phase 1 in-app feature. The listed use cases (wire transfers, production deployments, board resolutions) all require integration with external systems — Occulta would produce a threshold-signed blob that nothing reads or enforces. "Authorization" without a system acting on it is not authorization. The verifier adoption problem is the same as Document Signing: every co-signer needs Occulta and a prior UWB exchange. Getting a CFO or board member to install a personal privacy iOS app for this purpose is not realistic. Belongs in Phase 2 once an enterprise SDK exists and real institutional customers are onboarded.

---

### F. Inheritance and Dead Man's Switch
**Conviction:** High
**Market size:** Medium — crypto asset holders, estate planning, individuals with dependents
**Technical lift:** Low — builds on existing Vault and Shamir SSS

Owner designates trustees in their Occulta contact book (physically verified individuals). Occulta issues a periodic identity challenge; owner must respond with their SE-signed challenge response. If the challenge goes unanswered for N days, the system marks the owner inactive and delivers Shamir shares to trustees. K-of-N trustees converge to reconstruct and access a designated legacy partition.

**Note:** This opportunity overlaps with Consumer Feature #8 (Shamir Dead Man's Switch). The consumer feature is the personal privacy use case (journalist check-in); this expansion is the institutional/estate-planning framing. They share implementation.

> **Ruling (May 2026):** Not a separate expansion — same implementation as Consumer Feature #8, one codebase, two positioning stories. The "institutional/estate planning" framing is weaker than it appears: most people approaching estate planning want a lawyer or institution as a backstop, not a purely peer-to-peer cryptographic system. The crypto-holder audience is the strongest fit — they already think in terms of keys and self-custody, and the "no cloud custodian" property is exactly what they want. Position as consumer feature #8 with a crypto-holder marketing angle, not as a separate enterprise expansion.

---

### G. Physical Asset Provenance and Chain of Custody
**Conviction:** Medium
**Market size:** Medium — legal evidence, pharmaceuticals, classified hardware, luxury goods
**Technical lift:** High (hardware integration required)

A physical asset is assigned an Occulta identity (embedded chip, QR companion, or dedicated hardware). Each transfer of custody requires physical proximity + key exchange between outgoing and incoming custodians. The transfer is signed by both SE keys, creating an unforgeable chain. Any gap (unsigned transfer) is immediately detectable.

Target use cases: legal evidence chain of custody, pharmaceutical cold chain, classified hardware tracking, luxury goods authentication, medical device sterilization verification.

> **Ruling (May 2026):** Not a standalone opportunity. Every target use case has a deeply entrenched incumbent that doesn't require both parties to have Occulta installed.
>
> Luxury goods: Aura Blockchain Consortium (LVMH, Prada, Cartier) already does cryptographic provenance — buyers verify via a web browser or generic app, not a niche privacy iOS app. Legal evidence: chain-of-custody is a legal and procedural requirement; signatures from an iOS app require extensive regulatory recognition before any court accepts them; dedicated platforms (Axon Evidence, Tyler Technologies) own this market. Pharmaceuticals: FDA DSCSA compliance requires validated systems; SAP Advanced Track and Trace and TraceLink are the platforms; a consumer iOS app is not in that supply chain. Supply chain broadly: GS1 standards, ERP systems, VeChain, and IBM Food Trust are entrenched.
>
> The Aura comparison is worth dwelling on: it already provides trustless cryptographic provenance with no single authority, and it works with a browser. Occulta requires both parties to have the app.
>
> Remove from the independent expansion list. Revisit only as a downstream feature of A, where the organisation is already Occulta-native.

---

### H. Anonymous Credentials and Selective Disclosure
**Conviction:** Exploratory
**Market size:** Large (long-term) — age verification, professional license verification, security clearances, press credentials
**Technical lift:** Very high — requires ZK proof primitives not currently in the Occulta codebase

A trusted authority issues a signed credential bound to the user's Occulta public key asserting a claim: "this key belongs to a licensed physician," "this key belongs to a person over 18," "this key has clearance level 3." The credential is presented to a verifier using zero-knowledge techniques — they learn the claim, not the claimant's identity. The SE-bound key makes the credential unforgeable in a way that software credentials cannot match.

This is the most technically ambitious expansion and the longest time horizon. ZK primitive implementation is non-trivial; the value proposition is strongest once the organizational identity graph (Opportunity A) has established Occulta as a trusted identity layer for institutions.

> **Ruling (May 2026):** Phase 3, but the technical approach in the original write-up is wrong and the competitive landscape has moved significantly.
>
> **What's already solved:** The EU Digital Identity Wallet (eIDAS 2.0) is mandated for all member states. Apple Wallet already ships state IDs in several US states with NFC presentation and selective disclosure via mdoc/ISO 18013-5. Google Wallet is doing the same. SD-JWT (Selective Disclosure JWTs) and mdoc achieve the practical "prove one attribute without revealing others" outcome for most real use cases without true ZK proofs. Apple and the EU are solving the issuer adoption problem — the thing that seemed like a decade away is now 2–3 years away.
>
> **What's not solved:** Every existing system routes credential presentation through a platform intermediary — Apple knows when you presented your ID, to whom, and where. Occulta's SE-bound credential with no Apple/Google in the middle is a genuine privacy differentiator. "Prove your age to a venue without Apple knowing you were there" is a real value proposition for Occulta's audience.
>
> **The right path:** Do not build ZK primitives from scratch. Implement W3C Verifiable Credentials and SD-JWT as a privacy-preserving credential holder that accepts credentials from standards-based issuers (EU Digital Identity Wallet, US mDL programs) as they come online. The SE binding is the unique security property; the no-intermediary architecture is the unique privacy property. Both are achievable without ZK. Monitor the EU Digital Identity Wallet rollout — that is the trigger that makes this worth building.

> **Addendum (July 10, 2026):** The demand-side trigger arrived ahead of the issuer-side one — KOSA passed the House June 29, 2026 with large-scale age-verification mandates, and roughly half of US states now mandate some form of age gating. The community's revolt is against ID/biometric upload, not age proof itself. Pull the W3C VC / SD-JWT credential-holder scoping study forward to active; the build gate remains issuer availability (EU wallet / US mDL rollout).

---

### I. Air-Gapped SE Signer for P-256 Smart Wallets + Physically-Verified Social Recovery
**Added July 4, 2026 (feature ideation pass)**
**Conviction:** Exploratory
**Market size:** Large — crypto asset holders, security-literate, accustomed to paying, evangelical
**Technical lift:** High

Occulta as a fully offline hardware-wallet-grade signer for chains that verify secp256r1: RIP-7212 precompile L2s (Base, Optimism, Polygon) via account-abstraction wallets, and Sui/Aptos natively. A **dedicated** SE key per wallet (distinct tag, never the identity key — signing attacker-supplied digests with the identity key would be a cross-protocol catastrophe, per CRYPTO_REVIEW_CHECKLIST §4). Transaction arrives as QR/file, is decoded and human-readably displayed (EIP-712 typed data where available), biometric-gated SE signs the digest, low-s normalized (public post-processing, no private key needed), returned as QR/file. Occulta carries zero network code for this — broadcasting is the wallet app's job, outside Occulta's trust boundary. Recovery: the smart wallet's guardian set maps to physically-verified Occulta contacts who co-sign recovery operations with their own SE keys — guardians actually met in person, with hardware keys, rather than addresses configured and hoped-correct.

**Why new / overlap declaration:** Adjacent to Expansion E (M-of-N Authorization, removed — co-signs *Occulta* payloads); this signs *external chain* payloads with dedicated keys and an air-gap workflow — a different product surface.

**Security model fit:** No server — strictly air-gapped signing. SE-bound, dedicated domain-separated keys. No metadata — nothing persisted beyond encrypted wallet-key references; no chain data stored. Chain signatures are classical by the *chain's* spec — fully separate keys and paths, so this neither touches nor weakens Occulta's own protocol.

**iOS constraint:** iOS 16+ (SE digest signing, AVFoundation QR). Per-chain payload decoding is where the real lift lives; blind-signing must be refused (display-or-decline policy); s-normalization required for chains enforcing canonical signatures.

> **Ruling (July 2026):** A malicious transaction presented for signing is mitigated by mandatory decode-and-display consent and per-wallet key isolation — worst case bounds to one wallet's assets, never Occulta identity/contacts. WalletConnect-style online pairing is explicitly out — QR/file only. High lift. **Priority: Exploratory.**
>
> **Addendum (August 14, 2026) — removed. The enabling fact was stale when written, and its adoption inverts the premise.**
>
> **The entry is stale on its own trigger.** It frames the opportunity as *"RIP-7212 precompile L2s (Base, Optimism, Polygon)."* P-256 verification reached Ethereum **L1 mainnet** as EIP-7951 in the Fusaka upgrade, activated **3 December 2025** — seven months before this entry was drafted. Precompile at `0x100`, 3450 gas, interface-compatible with the L2 RIP-7212 implementations and fixing security issues found in them. Avalanche has it via ACP-204. The opportunity was never L2-scoped.
>
> **The premise is inverted.** EIP-7951's own rationale states its purpose: to verify *"signatures generated by modern secure hardware including Apple Secure Enclave, Android Keystore, and FIDO2/WebAuthn devices."* The precompile exists to make passkeys work as wallet signers — which is exactly what this entry proposes Occulta become. Wide P-256 support is therefore not a tailwind; it is the mechanism by which this use case was commoditized, and the incumbents got there first at scale: Coinbase Smart Wallet shipped passkey signing in June 2024 and passed one million accounts by August 2025 (270,000 in a single day), with Safe, Argent and Eco shipping passkey signers alongside. An iPhone is already a P-256 smart-account signer with no additional app installed. **This is the same shape as three rulings already made in this document** — Expansion B removed because HID Mobile Access shipped it, G removed because Aura shipped it, D removed on verifier adoption.
>
> **What survives, with its cost stated.** (1) **Device-bound versus synced** — passkeys backed by iCloud Keychain are cloud-synced software keys, while an SE key is `ThisDeviceOnly` and non-exportable. Real, but *verbatim the argument `#20` already makes*, and `#20` is the cheaper and more general build. (2) **Physically-verified guardians** — genuinely unique; no wallet can offer guardians met at ≤ 25 cm. But it inherits the closed-loop critique that removed D, E and `#12`, and this entry does not address that co-signing is an on-chain operation: each guardian needs Occulta, a prior UWB exchange, *and* a funded chain account. (3) **Decode-and-display** — the one thing the passkey path cannot do, since a WebAuthn signer receives an opaque challenge and therefore blind-signs userOp hashes by construction.
>
> **`#20` subsumes most of this entry at a fraction of the lift.** An `ASCredentialProviderExtension` can already be the passkey behind an ERC-4337 smart account: the relying party is the wallet's web app, the artifact is a standard WebAuthn assertion, and on-chain verification of those assertions is production practice in passkey wallets today (Coinbase's `WebAuthn.sol`, Daimo's `p256-verifier` — named from prior knowledge, not verified against source in this pass). That path needs no QR plumbing and no per-chain payload decoder, which is where this entry itself locates "the real lift." What it loses is item (3): the display.
>
> **A caveat on the air gap, for whoever revisits this.** An iPhone running an app that declines to use the network is a *policy* air gap, not a physical one. It competes against Keystone and Ledger, which carry no radio — a weaker position than "hardware-wallet-grade" implies. It also means adding an attacker-supplied-digest signing surface to the same device that holds the contact graph, the vault, and duress state; per-wallet key isolation bounds the asset loss but does not remove that surface.
>
> **Disposition.** Removed from the expansion list as written. The device-bound signer argument belongs in `#20`. Physically-verified wallet guardians should be filed as their own item if wanted, with the closed-loop and funded-account costs stated up front rather than discovered later. If anything exploratory is retained, retain the display — *"the signer that will not blind-sign"* is the only defensible product claim left, and it is small.

---

## Section 2 Summary Table

| | Opportunity | Status | Notes |
|--|-------------|--------|-------|
| A | Organizational Identity Graph | **Keep — Phase 2** | Narrow to gov-adjacent orgs and high-trust cells; package with C as a single regulated-industry platform |
| C | Developer / API Authentication | **Keep — Phase 2** | Same buyer as A; regulated-industry human API auth only; package together |
| H | Anonymous Credentials | **Keep — Phase 3 (scoping active)** | Build W3C VC / SD-JWT credential holder, not ZK from scratch; KOSA-era age-verification mandates pulled scoping forward (Jul 2026); build still gated on issuer availability |
| B | Physical Access Control | Downstream of A only | HID Mobile Access already owns this market; not standalone |
| F | Inheritance / Dead Man's Switch | Same as #8 | Not a separate expansion; crypto-holder positioning |
| G | Asset Provenance | Downstream of A only | Every market has entrenched incumbents; not standalone |
| D | Document Signing / Notarization | Removed | — |
| E | M-of-N Authorization | Removed | — |
| I | Air-Gapped SE Smart-Wallet Signer | **Removed 2026-08-14** | P-256 verification reached L1 with EIP-7951 (Fusaka, 3 Dec 2025), and the precompile exists to make passkeys work as wallet signers — so its adoption commoditizes this entry rather than enabling it. Survivors: the device-bound argument folds into #20, which subsumes most of the build; physically-verified guardians want their own item. See the August 14 addendum |

---

# Section 3 — Cross-Cutting Observations

## Overlaps and Synergies

**Consumer Feature #8 ↔ Expansion F (Dead Man's Switch / Inheritance)**
The personal privacy use case (journalist in a dangerous environment) and the estate/inheritance use case share all cryptographic infrastructure. Implement once; position differently for each audience.

**Consumer Feature #1, #7, #9 (Transport cluster) — all removed**
Wi-Fi Aware Delivery, Proximity Outbox, and Mesh Relay were grouped as a transport cluster. All three were removed: the share extension covers proximity delivery adequately, and the async/relay use cases require iOS background behaviour that is too constrained to be reliable.

**Consumer Feature #15 ↔ Expansion A (Presence Verification as the enterprise wedge)**
The same challenge–response primitive serves the family anti-scam scenario and the enterprise helpdesk/wire-transfer verification scenario. One implementation, two stories — and the consumer story is the bottom-up adoption path Section 2 identifies as the only realistic route into enterprise.

**Consumer Feature #16 ↔ Consumer Feature #8 (shared Shamir custody rails)**
The trustee shard-custody system that already ships (social recovery) is the same distribution/manifest/reconstruction machinery the Dead Man's Switch needs; #8 adds a trigger (missed check-in) to rails that exist.

**Consumer Feature #17 ↔ Duress Cluster**
2FA seeds as vault items inherit Travel Mode, Panic Wipe, and deniable-partition behavior automatically — the differentiator over every standalone authenticator app is the cluster, not the TOTP math.

## The Duress Cluster

Travel Mode (#2), Panic Wipe (#3), and Deniable Vault Partitions (#6) form a natural "duress protection" product narrative. All three address the same threat actor (a person with physical access to the device under coercion) at different points in the encounter:

- **Before the encounter:** Travel Mode cryptographically removes sensitive items
- **During the encounter:** Deniable Partitions provide a convincing surface vault under coercion
- **As a last resort:** Panic Wipe destroys all access in milliseconds

No iOS app currently offers all three. Shipping them as a named feature set ("Protected Mode") is a strong positioning opportunity for the journalist and activist market.

**Audience update (July 10, 2026):** The 2026 US domestic climate — ICE device searches at airport checkpoints, protest-documentation guidance — has expanded the duress audience from border-crossers to residents who never leave the country; civil-liberties guidance now reads like this cluster's feature list. This is the news cycle the Trajectory doc warned we keep missing: it argues for acceleration, not re-scoping. The Sealed Evidence Journal (#28) extends the cluster from "protect what you hide" to "prove what happened" for the same audience.

---

## Combined Priority Matrix

### Phase 1 — Consumer App (iOS 16+, immediate)

| Priority | Item | Rationale |
|----------|------|-----------|
| 1 | Offline Travel Mode | Broadest new audience; documents a real gap vs. 1Password; fully offline; no external dependencies |
| 2 | Cryptographic Panic Wipe | Requires key hierarchy rework as prerequisite; wipe itself is then trivial; post-Graphite urgency |
| 1 (parallel) | Verified Payment Instructions (#26) | Largest documented loss pool adjacent to the app (BEC $3.05B, 2025 IC3); trusted asynchronous artifact no competitor has; anti-impersonation pairing with Presence Verification (#15) on hold — see Delayed section below |
| 2 (parallel) | Anti-Scam Family Circle (#27) | Mainstream reach + family install loop; **partially unblocked 2026-08-09** — only Assisted Mode depends on Presence Verification (#15). Second Opinion needs no presence primitive and is shippable now; the Money-request rule routes through #26. See Delayed section below |
| 1 (parallel) | Situational Contact Actions ("Trust Check" Picker, #29) | Very low lift, no new attack surface; generalized fix for a discoverability gap this doc has hit twice (#19, #27's Assisted Mode); not blocked on Presence Verification if the suspicious-call row is scoped honestly (see #29's iOS constraint) |

### Delayed — Blocked Pending Protocol Fix

| Item | Reason |
|------|--------|
| Presence Verification (#15) | Downgraded from Priority 1 on 2026-07-10: the relay/parallel-session attack (SPEC.md §6 addendum) has no known guaranteed fix and hits hardest against the exact adversary this feature targets. Not scheduled until a protocol fix with a real guarantee is found, or the product claim is explicitly narrowed to exclude live, resourced, dual-channel relay attacks. The Verified Payment Instructions (#26) release pairing is blocked on this. Anti-Scam Family Circle (#27) is only **partially** blocked — Assisted Mode alone depends on #15; its Second Opinion component is shippable today (see #15's August 9 addendum). Expansion A's enterprise wedge was **partially unblocked 2026-08-09**: co-located (in-person) lifecycle ceremonies have no channel for a relay attack to occupy and do not depend on #15 at all; only remote presence checks remain blocked. See Expansion A's second August 9 addendum. |

### Phase 2 — Duress Cluster Completion + Coverage

| Priority | Item | Rationale |
|----------|------|-----------|
| 3 | Deniable Vault Partitions | Completes the duress cluster; no iOS equivalent |
| 4 | Shamir Dead Man's Switch | Only serverless iOS implementation; SSS custody rails already shipped (see #16) |
| 5 | NFC Key Exchange (fallback) | Removes hard UWB-device requirement; no security tradeoff |
| 6 | Duress-Aware 2FA Codes | Unique only once the duress cluster exists; sequence after Travel Mode + Panic Wipe |
| 7 | Uniform Basket Envelopes (#21) | Promoted July 10, 2026 (Chat Control reinstatement): schedule with the next protocol release; upgrades #13 (filename encryption) from partial to real metadata protection — ship together |
| 8 | Mutual-Contact Discovery (#22) | Sybil-resistant trust signal no server-based product can offer; low-medium lift |
| 9 | Signed Destruction Receipts (#24) | Answers the "prove it was deleted" gap in every ephemeral-messaging competitor; low-medium lift |
| 10 | Visual PII Redaction (#25) | Demos well, distinct threat from existing EXIF/GPS stripping; low-medium lift |
| 11 | Sealed Evidence Journal (#28) | Extends the duress cluster from "protect what you hide" to "prove what happened"; guardian-witnessed tamper evidence on shipped rails; sequence after deniable partitions |
| 12 (opportunistic) | Multi-Device Contacts (#18, narrowed 2026-07-10) | Downgraded from its original Near-term/Rank-1 ranking above the table: the "backup phone that just works" ambition was rejected as a security hole (self-vouching device certs) and shelved; what remains is a data-model bug fix (a second device no longer silently overwrites the first's key for a contact). Ships opportunistically, not scheduled — see ROADMAP.md |

### Phase 2/3 — Gated on Platform or SDK

| Item | Rationale |
|------|-----------|
| Serverless Passkey Provider (#20) | Opens the mainstream password-manager market; medium-high lift (Credential Provider extension + RP record model + Settings UX); iOS 17 floor |
| Hybrid PQ Signatures (#23) | Extends PQ from confidentiality to authenticity for the per-device revocation broadcast (#18, narrowed scope) and any future signed artifact; ~~gated on confirming SE ML-DSA support in the target SDK~~ **SDK gate met 2026-08-14 — `SecureEnclave.MLDSA65`/`MLDSA87` ship from iOS 26, so this row no longer belongs under a platform gate. Regated on artifact availability: only #28 and #24 need decades-long unforgeability, and both are unbuilt.** (No longer paired with #19 — downgraded 2026-07-22, no revocation cert remains to sign) |

### Ongoing — Positioning (no engineering)

| Item | Rationale |
|------|-----------|
| Serverless Social Recovery (#16) | Already built behind `enableShamirShardSharing`; surface it as the answer to "what if I lose my phone?" — the validation (Google Recovery Contacts, passkey-lockout coverage) is marketing material |
| Guardian Revocation Certificates (#19) | Downgraded 2026-07-22: the existing per-contact "Revoke Key" action already bounds the worst case to a forced re-exchange with zero new engineering; make it discoverable (onboarding/security FAQ: "lost your phone? tell your contacts to revoke you"), don't build the guardian/SSS layer |

### Future — Enterprise (prerequisite: consumer product first)

These are not buildable as near-term targets. Direct enterprise sales requires compliance certifications, admin infrastructure, and a sales team — none of which exist yet. The realistic path is bottom-up: build an exceptional consumer product, get adopted by individuals who matter, let enterprise follow from that. These items describe what Occulta's architecture could eventually power.

| Item | Notes |
|------|-------|
| Organizational Identity Graph + Developer API Auth (A + C) | Same buyer, same sales motion. Unique property **(revised 2026-08-09)**: physically-verified enrollment and recovery that a remote attacker cannot fabricate — *not* "who vouched for whom," which no relying party can verify, since an SE signature proves key possession and not that a proximity ceremony occurred. Re-cast as an enrollment/recovery authority layered on whatever credential the org already runs, scoped to high-privilege accounts rather than headcount. Market is gov-adjacent orgs, high-trust cells, regulated industries. FedRAMP certification required for government segment and conflicts with zero-server architecture. |
| Anonymous Credentials (H) | Don't build ZK. Implement W3C VC / SD-JWT as a privacy-preserving credential holder with SE binding and no platform intermediary. EU Digital Identity Wallet rollout (2–3 years) is the concrete trigger. |
| Physical Access Control (B) | Downstream of A only. HID Mobile Access already owns this market as a standalone product. |
| Asset Provenance (G) | Downstream of A only. Every market segment has entrenched incumbents that work with a browser. |
| Air-Gapped SE Smart-Wallet Signer (I) | ~~Exploratory, high lift. Strictly air-gapped, dedicated per-wallet SE keys with no overlap with Occulta identity/contacts; real work is per-chain payload decoding and a mandatory display-or-decline consent flow.~~ **Removed 2026-08-14** — commoditized by the P-256 precompile it depended on; `#20` subsumes most of the build without the per-chain decoder. See Expansion I's August 14 addendum. |

---

*Consolidated from five independent research passes. All features are zero-server and Secure Enclave-compatible. Feature descriptions reflect the more detailed specification where sources diverge. Consumer feature rulings, expansion opportunity rulings, competitive landscape analysis, and enterprise structural barrier assessment added May 13, 2026. Features 18–25 and Expansion I (multi-device identity, key revocation, passkey provider, traffic-shape hardening, mutual-contact discovery, hybrid PQ signatures, destruction receipts, visual PII redaction, and an air-gapped smart-wallet signer) added July 4, 2026. Features 26–28 (verified payment instructions, anti-scam family circle, sealed evidence journal), the #21 promotion, and the Expansion H scoping pull-forward added July 10, 2026 from the community demand pass.*

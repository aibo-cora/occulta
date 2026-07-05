# Occulta — Master Feature & Expansion Analysis
**Date:** May 10, 2026
**Revised:** July 4, 2026
**Sources:**
- Feature Discovery Report, Apr 30, 2026
- Feature Discovery Report, May 9, 2026
- Expansion Opportunity Analysis, May 2026
- Critical review session, May 13, 2026
- Authentication pain-point research pass, June 12, 2026 (features 15–17; web-sourced demand evidence verified against the codebase)
- Feature ideation pass, July 4, 2026 (features 18–25; new Expansion I; checked against the README Security Properties/Threat Model tables, Features.swift/FeatureFlags, CRYPTO_REVIEW_CHECKLIST.md, IDENTITY_CHALLENGE_PROTOCOL.md, CODE_GENERATION_GUIDELINES.md, and the Share Extension plan)

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

Cryptographically removes designated contacts and vault items from the device before a border crossing. Not a UI hide — the item keys are re-encrypted under a separate travel passphrase and all other Keychain access paths are deleted. Under the primary credential, the sensitive items simply do not exist. Deactivation requires both the travel key and the original credential. Entirely offline: activate on airplane mode before landing, deactivate after clearing customs.

The community's expressed ideal — "toggle Travel Mode on the plane, before landing, with no internet, and have my sensitive vault be cryptographically non-existent by the time a border agent picks up my phone" — is quoted verbatim across multiple forum threads. 1Password Travel Mode is the current recommendation but requires a web session at precisely the moment users need it most. No app currently offers a fully offline equivalent.

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

---

### 20. Serverless Passkey Provider — Hardware-Bound Passkeys, Socially Recoverable
**Added July 4, 2026 (feature ideation pass)**
**Category:** Authentication
**Audience:** The mainstream password-manager market — the largest adjacent segment available to this codebase

Occulta registers as an iOS Credential Provider (`ASCredentialProviderExtension` with passkey support, iOS 17+). Each relying party gets a dedicated `SecureEnclave.P256` key (WebAuthn ES256), biometric-gated, `ThisDeviceOnly`, in a shared keychain access group so the extension can sign assertions. Unlike 1Password, Bitwarden, and iCloud Keychain — all of which sync passkey private keys through cloud infrastructure as *software* keys — Occulta passkeys stay hardware-bound, closer to a YubiKey that's already in the user's pocket. The device-loss problem that forces competitors into cloud sync is instead solved by Owner Device Set (#18) for multi-device continuity, with Occulta's existing SSS custody covering the vault of RP records.

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
**Audience:** Applies wherever a signed artifact must remain unforgeable for decades — revocation certs (#19), device-set certs (#18), and any future document-signing or audit-log artifact

Dual-signature format for artifacts whose validity must outlive ECDSA's quantum horizon. Every such artifact carries both an SE ECDSA P-256 signature (unchanged, mandatory root) and an ML-DSA-87 (FIPS 204) signature under a distinct domain prefix; verification requires **both**. If `SecureEnclave.MLDSA` exists in the target iOS SDK, use it; if SE support covers only ML-KEM (true as of the last check — verify against current CryptoKit headers before scoping), hold the ML-DSA private key software-side, wrapped under the hybrid local DB key. This does not weaken the SE-custody rule the way sole software custody would: forgery still requires the SE (ECDSA is always required), so the ML-DSA half only *adds* unforgeability — the same both-must-hold logic as the existing hybrid KEM construction and the same protection class as the already-accepted ML-KEM shared-secret storage.

**Why new:** "Harvest now, forge later" is the one PQ threat the existing ML-KEM work doesn't touch — a signed contract or notarized document must remain unforgeable for decades.

**Security model fit:** No server. SE remains the mandatory signing root. No metadata change (signatures travel where signatures already travel). PQ strengthened — the first feature to extend PQ from confidentiality to authenticity.

**iOS constraint:** Gated on SDK verification of SE ML-DSA support. ML-DSA-87 signatures run ~4.6 KB — irrelevant for documents, but worth noting against #21's padding buckets if ever used on the wire. New domain prefixes only, per IDENTITY_CHALLENGE_PROTOCOL's domain-separation mandate — never modify existing signing paths.

> **Ruling (July 2026):** Software ML-DSA key compromise still can't forge anything (needs the SE) — worst case equals today's status quo. Run CRYPTO_REVIEW_CHECKLIST §4 on cross-protocol separation for every new prefix. Medium lift, gated on SDK support. **Priority: Mid-term.**

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

### July 2026 Pass — Ranking by Impact-to-Lift

| Rank | Item | Impact | Lift | Phase |
|---|---|---|---|---|
| 1 | Owner Device Set (#18) | Very high | Medium | Near-term |
| 2 | Guardian Revocation Certificates (#19) | Med-high | Low | Near-term |
| 3 | Uniform Basket Envelopes (#21) | Medium (credibility-critical) | Low | Near-term |
| 4 | Serverless Passkey Provider (#20) | Very high | Med-high | Mid-term |
| 5 | Mutual-Contact Discovery (#22) | Medium | Low-med | Near-mid |
| 6 | Signed Destruction Receipts (#24) | Medium | Low-med | Near-mid |
| 7 | Hybrid PQ Signatures (#23) | Med-high | Medium (SDK-gated) | Mid-term |
| 8 | Visual PII Redaction (#25) | Medium | Low-med | Near-mid |
| 9 | Air-Gapped SE Wallet Signer (Expansion I) | High potential | High | Exploratory |

**Top 3 of this pass:**
1. **Owner Device Set (#18)** — kills the single biggest adoption objection ("what if I lose my phone") using ceremony code already shipped.
2. **Guardian Revocation Certificates (#19)** — highest reuse ratio in the batch (ECDSA + SSS + baskets, all shipped) and completes the key lifecycle reviewers will probe first.
3. **Serverless Passkey Provider (#20)** — the only idea in this pass that opens the mainstream password-manager market, with a pitch ("hardware-bound passkeys, no YubiKey, no cloud") no incumbent can copy without abandoning their sync architecture.

### Ideas Considered and Omitted (July 2026 pass)

- **Anonymous source drop / SecureDrop-lite** (encrypt-to-published-journalist-key): any workable design either reuses prekeys across unknown sources (the documented prekey-sharing flaw) or ships a mode without forward secrecy. FS must never be weakened — omitted rather than softened.
- **Peer app-integrity attestation during exchange** (App Attest proving the peer runs a genuine Occulta binary): would close part of the "compromised install" gap, but attestation-key creation requires a round trip to Apple's attestation service — a remote dependency and a usage signal to a third party. Zero-server/zero-telemetry — omitted. Revisit only if Apple ships fully offline attestation.
- **Key-transparency log / chain-anchored timestamping:** requires a network or public ledger dependency — omitted; #22's corroboration achieves the useful subset P2P.
- **Duress biometric variants:** iOS cannot distinguish which finger/face authenticated, and passcode-level duress is already covered by the Deniable Partitions + Panic Wipe cluster (Consumer #6, #3) — not new.
- **True DH-PSI for contact discovery:** needs hash-to-curve and raw scalar multiplication CryptoKit doesn't expose; a hand-rolled constant-time curve implementation would violate the Apple-frameworks-only convention — replaced by the HMAC construction in #22.

---

## Section 1 Summary Table

| Rank | Feature | Status | Audience | Phase |
|------|---------|--------|----------|-------|
| 2 | Offline Travel Mode | **Keep** | Broad | Phase 1 |
| 3 | Cryptographic Panic Wipe | **Keep** | Medium-broad | Phase 1 |
| 15 | Presence Verification | **Keep** | Broad | Phase 1 (parallel track) |
| 6 | Deniable Vault Partitions | **Keep** | Narrow-medium | Phase 2 |
| 8 | Shamir Dead Man's Switch | **Keep** | Narrow-medium | Phase 2 |
| 10 | NFC Key Exchange | **Keep** | Medium | Phase 2 (lower) |
| 17 | Duress-Aware 2FA Codes | **Keep** | Medium-broad | Phase 2 (after duress cluster) |
| 16 | Serverless Social Recovery | **Built** (flagged) | Broad | Positioning/UX pass only |
| 18 | Owner Device Set | **Keep** | Broad | Near-term |
| 19 | Guardian Revocation Certificates | **Keep** | Broad | Near-term |
| 21 | Uniform Basket Envelopes | **Keep** | — (protocol) | Near-term, opportunistic |
| 20 | Serverless Passkey Provider | **Keep** | Broad | Mid-term |
| 22 | Mutual-Contact Discovery | **Keep** | Narrow-medium | Near-mid |
| 24 | Signed Destruction Receipts | **Keep** | Narrow-medium | Near-mid |
| 23 | Hybrid PQ Signatures | **Keep** | — (protocol) | Mid-term (SDK-gated) |
| 25 | Visual PII Redaction | **Keep** | Narrow-medium | Near-mid |
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

---

## Section 2 Summary Table

| | Opportunity | Status | Notes |
|--|-------------|--------|-------|
| A | Organizational Identity Graph | **Keep — Phase 2** | Narrow to gov-adjacent orgs and high-trust cells; package with C as a single regulated-industry platform |
| C | Developer / API Authentication | **Keep — Phase 2** | Same buyer as A; regulated-industry human API auth only; package together |
| H | Anonymous Credentials | **Keep — Phase 3** | Build W3C VC / SD-JWT credential holder, not ZK from scratch; EU Digital Identity Wallet rollout is the trigger |
| B | Physical Access Control | Downstream of A only | HID Mobile Access already owns this market; not standalone |
| F | Inheritance / Dead Man's Switch | Same as #8 | Not a separate expansion; crypto-holder positioning |
| G | Asset Provenance | Downstream of A only | Every market has entrenched incumbents; not standalone |
| D | Document Signing / Notarization | Removed | — |
| E | M-of-N Authorization | Removed | — |
| I | Air-Gapped SE Smart-Wallet Signer | **Keep — Exploratory** | High-lift, high-potential; crypto asset holders; strictly air-gapped, dedicated per-wallet SE keys, no overlap with Occulta identity |

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

---

## Combined Priority Matrix

### Phase 1 — Consumer App (iOS 16+, immediate)

| Priority | Item | Rationale |
|----------|------|-----------|
| 1 | Offline Travel Mode | Broadest new audience; documents a real gap vs. 1Password; fully offline; no external dependencies |
| 2 | Cryptographic Panic Wipe | Requires key hierarchy rework as prerequisite; wipe itself is then trivial; post-Graphite urgency |
| 1 (parallel) | Presence Verification | Identity Challenge protocol already shipped; remaining work is presence mode + transport + positioning; independent of the key-hierarchy rework, so it runs as a parallel track |
| 1 (parallel) | Owner Device Set (#18) | Kills the "lose your phone, lose your contacts" objection using ceremony code already shipped; independent of the key-hierarchy rework |
| 2 (parallel) | Guardian Revocation Certificates (#19) | Highest reuse ratio of any feature on this list (ECDSA + SSS + baskets, all shipped); completes the key lifecycle reviewers probe first |

### Phase 2 — Duress Cluster Completion + Coverage

| Priority | Item | Rationale |
|----------|------|-----------|
| 3 | Deniable Vault Partitions | Completes the duress cluster; no iOS equivalent |
| 4 | Shamir Dead Man's Switch | Only serverless iOS implementation; SSS custody rails already shipped (see #16) |
| 5 | NFC Key Exchange (fallback) | Removes hard UWB-device requirement; no security tradeoff |
| 6 | Duress-Aware 2FA Codes | Unique only once the duress cluster exists; sequence after Travel Mode + Panic Wipe |
| 7 | Uniform Basket Envelopes (#21) | Low lift, opportunistic; upgrades #13 (filename encryption) from partial to real metadata protection — ship together on the next bundle-format touch |
| 8 | Mutual-Contact Discovery (#22) | Sybil-resistant trust signal no server-based product can offer; low-medium lift |
| 9 | Signed Destruction Receipts (#24) | Answers the "prove it was deleted" gap in every ephemeral-messaging competitor; low-medium lift |
| 10 | Visual PII Redaction (#25) | Demos well, distinct threat from existing EXIF/GPS stripping; low-medium lift |

### Phase 2/3 — Gated on Platform or SDK

| Item | Rationale |
|------|-----------|
| Serverless Passkey Provider (#20) | Opens the mainstream password-manager market; medium-high lift (Credential Provider extension + RP record model + Settings UX); iOS 17 floor |
| Hybrid PQ Signatures (#23) | Extends PQ from confidentiality to authenticity for revocation certs (#19), device-set certs (#18), and any future signed artifact; gated on confirming SE ML-DSA support in the target SDK |

### Ongoing — Positioning (no engineering)

| Item | Rationale |
|------|-----------|
| Serverless Social Recovery (#16) | Already built behind `enableShamirShardSharing`; surface it as the answer to "what if I lose my phone?" — the validation (Google Recovery Contacts, passkey-lockout coverage) is marketing material |

### Future — Enterprise (prerequisite: consumer product first)

These are not buildable as near-term targets. Direct enterprise sales requires compliance certifications, admin infrastructure, and a sales team — none of which exist yet. The realistic path is bottom-up: build an exceptional consumer product, get adopted by individuals who matter, let enterprise follow from that. These items describe what Occulta's architecture could eventually power.

| Item | Notes |
|------|-------|
| Organizational Identity Graph + Developer API Auth (A + C) | Same buyer, same sales motion. Unique property: web-of-trust (who physically vouched for whom) — no existing IdP can answer this. Market is gov-adjacent orgs, high-trust cells, regulated industries. FedRAMP certification required for government segment and conflicts with zero-server architecture. |
| Anonymous Credentials (H) | Don't build ZK. Implement W3C VC / SD-JWT as a privacy-preserving credential holder with SE binding and no platform intermediary. EU Digital Identity Wallet rollout (2–3 years) is the concrete trigger. |
| Physical Access Control (B) | Downstream of A only. HID Mobile Access already owns this market as a standalone product. |
| Asset Provenance (G) | Downstream of A only. Every market segment has entrenched incumbents that work with a browser. |
| Air-Gapped SE Smart-Wallet Signer (I) | Exploratory, high lift. Strictly air-gapped, dedicated per-wallet SE keys with no overlap with Occulta identity/contacts; real work is per-chain payload decoding and a mandatory display-or-decline consent flow. |

---

*Consolidated from four independent research passes. All features are zero-server and Secure Enclave-compatible. Feature descriptions reflect the more detailed specification where sources diverge. Consumer feature rulings, expansion opportunity rulings, competitive landscape analysis, and enterprise structural barrier assessment added May 13, 2026. Features 18–25 and Expansion I (multi-device identity, key revocation, passkey provider, traffic-shape hardening, mutual-contact discovery, hybrid PQ signatures, destruction receipts, visual PII redaction, and an air-gapped smart-wallet signer) added July 4, 2026.*

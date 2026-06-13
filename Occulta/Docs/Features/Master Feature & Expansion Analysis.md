# Occulta — Master Feature & Expansion Analysis
**Date:** May 10, 2026
**Revised:** May 13, 2026
**Sources:**
- Feature Discovery Report, Apr 30, 2026
- Feature Discovery Report, May 9, 2026
- Expansion Opportunity Analysis, May 2026
- Critical review session, May 13, 2026

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

## Section 1 Summary Table

| Rank | Feature | Status | Audience | Phase |
|------|---------|--------|----------|-------|
| 2 | Offline Travel Mode | **Keep** | Broad | Phase 1 |
| 3 | Cryptographic Panic Wipe | **Keep** | Medium-broad | Phase 1 |
| 6 | Deniable Vault Partitions | **Keep** | Narrow-medium | Phase 2 |
| 8 | Shamir Dead Man's Switch | **Keep** | Narrow-medium | Phase 2 |
| 10 | NFC Key Exchange | **Keep** | Medium | Phase 2 (lower) |
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

---

# Section 3 — Cross-Cutting Observations

## Overlaps and Synergies

**Consumer Feature #8 ↔ Expansion F (Dead Man's Switch / Inheritance)**
The personal privacy use case (journalist in a dangerous environment) and the estate/inheritance use case share all cryptographic infrastructure. Implement once; position differently for each audience.

**Consumer Feature #1, #7, #9 (Transport cluster) — all removed**
Wi-Fi Aware Delivery, Proximity Outbox, and Mesh Relay were grouped as a transport cluster. All three were removed: the share extension covers proximity delivery adequately, and the async/relay use cases require iOS background behaviour that is too constrained to be reliable.

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

### Phase 2 — Duress Cluster Completion + Coverage

| Priority | Item | Rationale |
|----------|------|-----------|
| 3 | Deniable Vault Partitions | Completes the duress cluster; no iOS equivalent |
| 4 | Shamir Dead Man's Switch | Only serverless iOS implementation; SSS already built |
| 5 | NFC Key Exchange (fallback) | Removes hard UWB-device requirement; no security tradeoff |

### Future — Enterprise (prerequisite: consumer product first)

These are not buildable as near-term targets. Direct enterprise sales requires compliance certifications, admin infrastructure, and a sales team — none of which exist yet. The realistic path is bottom-up: build an exceptional consumer product, get adopted by individuals who matter, let enterprise follow from that. These items describe what Occulta's architecture could eventually power.

| Item | Notes |
|------|-------|
| Organizational Identity Graph + Developer API Auth (A + C) | Same buyer, same sales motion. Unique property: web-of-trust (who physically vouched for whom) — no existing IdP can answer this. Market is gov-adjacent orgs, high-trust cells, regulated industries. FedRAMP certification required for government segment and conflicts with zero-server architecture. |
| Anonymous Credentials (H) | Don't build ZK. Implement W3C VC / SD-JWT as a privacy-preserving credential holder with SE binding and no platform intermediary. EU Digital Identity Wallet rollout (2–3 years) is the concrete trigger. |
| Physical Access Control (B) | Downstream of A only. HID Mobile Access already owns this market as a standalone product. |
| Asset Provenance (G) | Downstream of A only. Every market segment has entrenched incumbents that work with a browser. |

---

*Consolidated from three independent research passes. All features are zero-server and Secure Enclave-compatible. Feature descriptions reflect the more detailed specification where sources diverge. Consumer feature rulings, expansion opportunity rulings, competitive landscape analysis, and enterprise structural barrier assessment added May 13, 2026.*

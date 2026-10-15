# Occulta — Feature Evolution & Trajectory

**Date:** June 29, 2026
**Scope:** Full product arc from genesis to present, with projected features beyond the existing roadmap.

---

## The Arc in Three Acts

### Act 1: The Trust Primitive (v1.1–v1.5)

The app launched with a single, radical bet: *physical proximity as the only key distribution mechanism*. UWB Diceware exchange, forward-secret messaging, identity challenge. No server, no account, no cloud. The first two years were about proving that a contact book with cryptographically-verified identity could exist and work on iOS. Foundational but narrow — it could only do one-to-one messaging with people you'd physically met.

### Act 2: Depth Over Breadth (v1.6–v1.8)

Rather than growing the user base, the team went deeper on threat resistance.

- **v1.6–v1.7:** Vault + Shamir SSS — answered "what if I lose my phone?" with a serverless social recovery model that no other iOS app offers.
- **v1.8:** The most ambitious release — Secure Mode with 72 documented security bugs resolved, hybrid post-quantum crypto, and forensic trace elimination. This is where Occulta crossed from "privacy app" to "coercion-resistant system." The adversary model shifted from remote attacker to *person with physical access under duress*.

Act 2 revealed the product's real audience: not the casual privacy-conscious user, but the journalist, activist, lawyer, and anyone who faces physical threat — a small but intensely motivated market.

### Act 3: Scale the Protocol (v1.9–present)

Group messaging is the inflection point. It's the first feature that doesn't serve the individual user's threat model — it serves a *group's* threat model. The wire format is sophisticated: per-recipient key wrapping, trial-decryption slot-finding for privacy-preserving recipient discovery, and AAD binding that prevents cross-group replay. Presence Verification is arriving simultaneously — the first feature with clear mainstream pull (the deepfake/scam wave is real and accelerating).

---

## Version Timeline

| Period | Version(s) | Major Features | Focus |
|--------|-----------|----------------|-------|
| 2023 Q2–Q3 | v1.1–v1.3 | UWB key exchange, forward secrecy, identity challenge, message threading | Foundation |
| 2023 Q3–Q4 | v1.4–v1.5 | Challenge refactor, exchange session timeout, reliability | Stability |
| 2023 Q4–2024 Q1 | v1.6–v1.7 | Vault, Shamir SSS, trustee custody, shard reconciliation | Recovery/Trust |
| 2024 Q1–Q2 | v1.8.0–v1.8.3 | Secure Mode (72 bugs), hybrid ML-KEM crypto, post-quantum | Coercion resistance |
| 2024 Q3–2026 Q2 | v1.9.0 (ongoing) | Group messaging (7-step), Presence Verification, CI/CD | Multi-recipient, presence |

---

## Architectural Trajectory

### Phase 0 (v1.1–v1.5): Single-Recipient Messaging
- **Focus:** One-to-one encrypted communication with UWB key exchange
- **Primitive:** ECDH + AES-GCM per message; ephemeral keys destroyed after use

### Phase 1 (v1.6–v1.7): Trustee Recovery & Vault
- **Focus:** User data persistence through device loss
- **Innovation:** Serverless social recovery via Shamir's Secret Sharing
- **Audience unlocked:** People with data worth recovering (crypto holders, journalists, lawyers)

### Phase 2 (v1.8): Coercion Resistance
- **Focus:** Protect against physical coercion and surveillance
- **Innovations:**
  - Duress mode — multiple PIN layers with plausible deniability
  - Hybrid cryptography — ML-KEM-1024 post-quantum resistance on iOS 18+
  - Forensic trace elimination — no behavioral tell distinguishes real PIN from duress
- **Audience unlocked:** Journalists, activists, border-crossing travelers, high-threat professionals
- **Implementation scale:** 72 security issues documented and resolved

### Phase 3 (v1.9): Group Operations & Presence Verification
- **Focus:** Multi-recipient messaging + live identity verification
- **Innovations:**
  - Group messaging — single bundle to multiple recipients with per-recipient key wrapping
  - Presence Verification — SE-signed challenge-response to detect deepfakes and impersonation
- **Audience unlocked:** Families (anti-scam), executives (deepfake defense), enterprises (wire-transfer verification)

---

## Planned Roadmap (from Master Feature & Expansion Analysis)

### Phase 1 (immediate)
| Feature | Rationale |
|---------|-----------|
| Offline Travel Mode | Broadest new audience; documents a real gap vs. 1Password; fully offline |
| Cryptographic Panic Wipe | Requires key hierarchy rework as prerequisite; post-Graphite urgency |
| Presence Verification | Identity Challenge already shipped; parallel track independent of key-hierarchy rework |

### Phase 2
| Feature | Rationale |
|---------|-----------|
| Deniable Vault Partitions | Completes the duress cluster; no iOS equivalent |
| Shamir Dead Man's Switch | Only serverless iOS implementation; SSS custody rails already exist |
| NFC Key Exchange | Removes hard UWB-device requirement; no security regression |
| Duress-Aware 2FA Codes | Unique only once duress cluster exists |

### Positioning (no engineering required)
| Item | Note |
|------|------|
| Serverless Social Recovery | Already built behind `enableShamirShardSharing`; needs surfacing as the answer to "what if I lose my phone?" |

---

## Projected Features (Beyond the Current Roadmap)

These are architectural gaps and logical extensions identified from the trajectory analysis. They are not currently planned but follow directly from the product arc.

---

### 1. Verified Group Membership Proofs

**Problem:** Group messaging encrypts content correctly but provides no cryptographic guarantee about roster integrity. A compromised sender could add a phantom recipient to a group bundle without any member knowing.

**Solution:** A signed group manifest — each member's SE key signs the roster at group creation and at each roster change. Any bundle whose sender-claimed membership list doesn't match the last signed manifest is rejected. The manifest itself travels as an authenticated attachment to the group bundle.

**Why it matters:** As groups grow, the implicit trust in the sender to honestly report the recipient list becomes the weakest link. This seals it.

**Prerequisite:** None. Builds on existing group wire format.

---

### 2. Contact Migration Protocol (Signed Key Rotation)

**Problem:** The SE identity key is indestructible by design, but iPhones die. Today, a new phone requires re-doing every UWB exchange from scratch. Long-term relationships are severed at the hardware level.

**Solution:** Before a device wipe, the old SE key signs the new SE key (from the new device) with a timestamped rotation certificate. Contacts who receive the signed rotation can update their key record without re-verifying in person. Any unsigned key change still triggers a re-verify requirement — the protocol can distinguish "signed rotation" from "unexplained key change."

**Why it matters:** This is the prerequisite for several downstream features — including contact-compromise detection, which is currently excluded from the roadmap precisely because it would require this protocol to be meaningful.

**Note:** The Master Feature doc removed "Contact Compromise Detection" (#5) because "channel failure is the detection mechanism" in Occulta's model. That reasoning holds today. But signed key rotation is a user-experience necessity for any user who has spent months building their contact graph.

---

### 3. Sealed Session Transcripts

**Problem:** Decrypted messages exist in-app as mutable plaintext. A message can be silently edited or deleted with no evidence of tampering. In legal and journalistic use cases where message authenticity is later disputed, this is a gap.

**Solution:** An append-only hash chain over the message transcript — each incoming or outgoing message authenticates the full preceding history. Tampering with any past message breaks the chain, which is visually surfaced to the user. The chain root is SE-signed at session initiation.

**Why it matters:** Journalists and lawyers already use Occulta. The ability to produce a verifiably unaltered transcript is a natural extension of the existing trust model. No server required — verification is purely local.

**Prerequisite:** None. This is a local data model change.

---

### 4. Group Secure Mode (Layer-Aware Group Membership)

**Problem:** Secure Mode operates per-contact today. But a group that includes at least one hidden contact is itself a metadata leak at the real layer — the group's existence reveals that certain hidden contacts exist.

**Solution:** Groups are layer-scoped objects. A group exists only at the depth where all its members are visible. Entering a duress layer causes groups containing hidden members to disappear entirely — not just hide some recipients. The group's existence at deeper layers is indistinguishable from groups that were never created.

**Why it matters:** The intersection of Group Messaging and Secure Mode creates a logical gap that undermines the coercion resistance guarantee. A coercer who sees a group with 3 visible members and knows the user has 5 contacts can infer the existence of 2 hidden ones.

**Prerequisite:** Group messaging (v1.9.0). Depends on the layer store abstraction from Secure Mode.

---

### 5. Proximity-Anchored Shared Vault (2-of-2 Escrow)

**Problem:** The Vault is per-user. There's no natural way for two parties to jointly hold a vault — shared passwords, a couple's sensitive documents, a legal partnership's key material — where either party's SE key alone is insufficient.

**Solution:** A shared vault partition encrypted to a 2-of-2 Shamir split across two contacts' SE keys. Opening the vault requires both parties to be physically present and both to authenticate. Destruction of either party's key share renders the vault inaccessible — no unilateral exfiltration.

**Why it matters:** This is a clean consumer use case (couples, business partners) and the smallest building block for the enterprise M-of-N authorization model that was excluded from the roadmap as "Phase 2 enterprise only." Getting it right at the consumer level first is the right sequencing.

**Prerequisite:** Existing Shamir SSS infrastructure. Low implementation lift.

---

### 6. Audit-Free Read Receipts

**Problem:** After group messaging ships, the natural user question is "did everyone read this?" A server-based read receipt creates metadata. There's currently no privacy-preserving answer.

**Solution:** On message open, the recipient's SE key signs a timestamped delivery attestation — a small bundle containing the message ID, a timestamp, and the SE signature. This travels back to the sender as a reply basket. The sender verifies the signature locally. The receipt is point-to-point (goes only to the sender) and stored nowhere else.

**Why it matters:** This is the first "social" UX feature that doesn't compromise the protocol. It's also the mechanism that enables the Dead Man's Switch trigger — the check-in proof is architecturally identical to a read receipt.

**Prerequisite:** None. This is a new bundle type that builds on the existing basket mechanism.

---

### 7. Multi-Device Contacts

**Problem:** A contact is modeled as exactly one active key at a time (`contactPublicKeys` is a rotation history, not a device roster). If someone owns two devices and both are paired via UWB, there's no way to send one message that either device can open — today the second pairing would just rotate/overwrite the first device's key.

**Solution:** Reuse the group-messaging envelope (`GroupEnvelope`/`Recipient`, per-recipient wrapped session key, trial-decryption slot-finding) to wrap the same message once per device key belonging to one contact — the wire format already treats a "recipient" as a key, not a contact, so no bundle-format change is required. The real work is in the data model: `Contact.Profile` needs to support several concurrently-active keys (one per paired device) instead of "one active, rest expired," plus a way to revoke a single device's key without invalidating the others.

**Why it matters:** Users increasingly pair from more than one device (phone + backup phone, personal + work). Without this, every additional device fragments the relationship into a separate contact identity.

**Prerequisite:** Group messaging (v1.9.0) for the envelope format. Needed its own design pass on key-rotation semantics (concurrent active keys) and per-device revocation before implementation — raised 2026-07-01, resolved 2026-07-10. Design findings: [Multi-Device Contacts/FINDINGS.md](Multi-Device%20Contacts/FINDINGS.md).

**Strategic roadmap:** [Multi-Device Contacts/ROADMAP.md](Multi-Device%20Contacts/ROADMAP.md) — Device-Bound, Recoverable Through People. A three-year feature arc extending to guardian-based revocation and optional passkey provider, with five releases (R0–R5), constraint analysis, trade-off reasoning, and the honest case against passkeys. **Revised 2026-07-10:** R1's original "backup phone that just works" ambition (then called Owner Device Set) was rejected as a security hole — a self-vouching device cert would let one coerced ceremony silently extend trust to an attacker's device across a victim's entire contact graph — and narrowed to a data-model bug fix only: concurrent per-device keys so a second device stops silently overwriting the first's, with no promoted UX to encourage broad re-pairing. R1 moved from a committed 2026 Q4 slot to opportunistic/low-priority. R2 (Guardian Revocation) is unaffected and stands on its own merits. R3–R4 (Passkey Provider) remain deferred until retention data justifies the additional surface area.

---

### 8. Passive Re-Verification on Re-Encounter

**Problem:** The identity ceremony happens once, at first contact, and is never repeated. Every competitor's manual verification step (Signal safety numbers, Threema/Briar QR scans) suffers the same failure — checked once, if ever, then forgotten. Usability studies put opt-in completion at 14–25%.

**Solution:** Whenever two already-paired contacts come back within UWB range, silently re-attest that their pinned keys still match. Surface an alert only on mismatch. "No alert" must never be allowed to read as "actively verified" in the UI — the absence of a warning is not itself a positive signal.

**Why it matters:** Converts a rare, low-completion opt-in event into a frequent, near-zero-friction, high-coverage check, for free — Occulta already opens a UWB session on every re-encounter.

**Prerequisite:** None. Reuses the existing UWB ranging + identity challenge primitives on every re-encounter, not just first contact.

**Trade-off:** Only covers people physically re-encountered; remote-only contacts still need an explicit manual re-verify path.

---

### 9. Correlated Vault Trustee Warning

**Problem:** Shamir-based Vault recovery doesn't check whether a user's chosen trustees are mutually connected. If they are, coercing or socially engineering one likely compromises the rest of the threshold set.

**Solution:** A local-only heuristic over the existing contact graph flags correlated trustee sets before a threshold is even set, computed entirely on-device with nothing transmitted. Support reshare after any trustee's device changes.

**Why it matters:** No consumer Shamir tool — Ledger, Vault12, Cypherock included — ships this today. It strengthens the existing Vault/Shamir cluster (v1.6–v1.7) rather than adding new attack surface.

**Prerequisite:** Existing Shamir SSS infrastructure + local contact graph. Needs a proactive-secret-sharing protocol for reshare; the heuristic itself must not leak relationship data anywhere.

---

### 10. Stealth Vault Recovery Ritual

**Problem:** Reconstructing a Vault from trustees is inherently observable to those trustees — contacting several people to rebuild a secret can itself broadcast "something has gone wrong" at exactly the moment that's most dangerous to reveal.

**Solution:** Make the reconstruction flow behaviorally indistinguishable from an ordinary proximity tap or check-in, not a labeled "emergency recovery."

**Why it matters:** Extends the duress cluster's core principle — statistical indistinguishability from the real thing — to the one part of the Vault/Shamir design that still looks like a distress flare from the trustee's side.

**Prerequisite:** Existing Shamir Vault + trustee custody flow (v1.6–v1.7). Complements the planned Shamir Dead Man's Switch (Phase 2 roadmap) — same reconstruction path, same need for a non-alarming ritual.

**Trade-off:** Harder to reason about and test than a clearly-labeled flow; needs real threat-modeling with people who'd use it under duress, not just internal design review.

---

### Positioning & Audit Ideas (from Opportunity Map, August 2026)

Sourced from a competitive research pass reading twelve encryption competitors' whitepapers, audits, and public failures against Occulta's architecture. None require new engineering beyond an audit engagement — but per that research's own conclusion, every claim below should ship with proof (an audit, a citation, a working demo), not rest on the architecture being sound in principle.

| Item | Note |
|------|------|
| Name "integrity-fail-closed" as a property | Signal's 2026 integrity paper found hijacked sessions inject messages while safety numbers still verify — false confidence. Occulta's inverse (a hijacked identity can't produce a valid bundle at all) deserves a name — but only after an independent audit confirms the property holds under the same attack class. |
| Disclose what the transport still sees | A `.occ` bundle sent over email or iMessage is still logged by that channel's own server. State this plainly per channel at send time rather than letting the channel-agnostic pitch imply more than it delivers. Costs one line of UI copy. |
| Reconsider the "32 layers" headline number | An adversary who already knows Secure Mode exists may not be deterred by a layer count, and the real mitigation for physical coercion is procedural (safe words, check-in protocols), not the cryptography alone — say so. Commission an audit that specifically tries to distinguish real state from decoy layers by file size, timing, or padding before repeating the number publicly. |
| Publish an audited "nothing to enumerate" claim | Occulta has no contact-discovery API by construction — the exact surface that let researchers enumerate 3.5B WhatsApp accounts without breaking any encryption. Worth an independently audited, falsifiable claim rather than a policy promise. |
| Formalize the no-roster group model academically | Matrix/MLS, Signal groups, and Session's swarms all require a server to hold group membership or sender-key state; a 2025 paper already compares those four. Occulta's local-only, no-server-roster group model is a distinct, unexamined category worth the same formal treatment. |
| Say plainly the company's survival isn't a dependency | Keybase died from an acquihire, not a crypto break, and took the service down with it. Every competitor reviewed depends on an ongoing business or homeserver operator to keep verifying identity or delivering messages. Costs nothing to start saying — it's already true. |

---

### Noted and rejected: cross-device cert vouching

The same research pass proposed "second-device enrollment over UWB" — a user's two devices cross-signing each other via a tap ceremony so contacts accept the new device transitively, without re-meeting it. This is the "Owner Device Set" design already proposed and rejected for [Multi-Device Contacts R1](Multi-Device%20Contacts/ROADMAP.md): a single coerced cert ceremony between a user's own two devices would silently extend trust to an attacker's device across that user's entire contact graph, with no physical tell for any contact to notice (ROADMAP.md, "Why not a device-to-device ceremony"; [FINDINGS.md](Multi-Device%20Contacts/FINDINGS.md), Design Sessions 3–4). Not re-added here — the standing invariant holds: no mechanism may grant trust to a new key except a fresh physical UWB exchange with each contact directly; only revocation may travel by signature alone.

---

## The Bigger Pattern

Occulta is executing a depth-first strategy: build one thing with absolute correctness, then extend it precisely. Every feature traces back to the same primitive — physically-verified identity bound to a Secure Enclave key. The roadmap hasn't chased growth; it's chased the hardest problems of the original use case.

The risk in that strategy is timing: Presence Verification would have been undeniable before the Arup deepfake incident. The duress cluster is directly validated by Paragon Graphite coverage. The app is consistently one news cycle behind the moment when its features would be most compelling. Accelerating the duress cluster to market is the highest-leverage action available.

**The v2.0 opportunity:** v1.9 completes the protocol layer (group messaging + presence verification). v2.0 could launch as a cohesive product centered on the duress cluster under a single brand — Travel Mode, Panic Wipe, Deniable Partitions, and 2FA all under one "Protected Mode" umbrella. That's the first version describable to a journalist in one sentence: *"It's the phone that protects you even when someone forces you to hand it over."*

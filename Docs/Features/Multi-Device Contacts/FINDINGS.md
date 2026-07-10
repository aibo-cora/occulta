# Multi-Device Contacts — Design Findings

**Status:** Exploratory — no SPEC.md yet, not scoped for a release
**Context:** Design discussion, 2026-07-02. Captures conclusions reached before any implementation, so the reasoning isn't lost before this gets formally scoped.

**Problem statement:** A contact who owns more than one paired device (phone + backup phone, personal + work) should be reachable by a single send, openable on any of their devices that completed key exchange. Today `Contact.Profile` models exactly one active key at a time — a second device pairing would rotate/overwrite the first device's key rather than adding to it.

---

## Confirmed / Verified

### D-01 · The group-messaging envelope already fits this with no wire-format change

`OccultaBundle.GroupEnvelope` / `Recipient` / `RecipientPayload` (`OccultaBundle.swift:465–505`) wraps a random session key separately per recipient *key*, with trial-decryption slot-finding and no cleartext hint of which slot belongs to whom (`Crypto+Manager+GroupDecrypt.swift`). The abstraction was already "one slot per key to wrap for," never "one slot per contact" — confirmed by `GroupRecipient` (`Crypto+Manager+GroupEncrypt.swift:15–25`) taking `publicKey` / `quantumMaterial` / `contactPrekey` directly, with no contact identifier threaded through the crypto layer at all.

**Conclusion:** feeding one `GroupRecipient` per device-key belonging to the same contact works today, unchanged, at the bundle format level. All required changes are upstream of the crypto layer.

---

### D-02 · Per-device prekey pools are a hard requirement, not an inefficiency

Prekey private halves are Secure Enclave-bound (`Prekey.swift:24–31`, tag `"prekey.<contactID>.<id>"`) — non-exportable, non-syncable across devices by construction. There is no cryptographic way for one device to generate a prekey whose private half also exists on a second device. This mirrors Signal's resolution to the identical problem: multi-device isn't one identity with a shared pool, it's N independent per-device sessions fanned out at send time. Nothing to optimize away here — the "efficiency" work is in transport/administration, not the crypto:

- SE tag extends to `"prekey.<contactID>.<deviceID>.<id>"`. Verified this stays compatible with the existing contact-wide cleanup `seTagPrefix(contactID:)` (`Prekey.swift:67–69`), which prefix-matches and doesn't care what follows `contactID.`. A new `seTagPrefix(contactID:deviceID:)` becomes possible for revoking a single device's pool without touching the others.
- Pool depletion accelerates with device count: a multi-device send consumes one prekey per device per message (same mechanics as a group send today), so replenishment thresholds need to be evaluated per device, not per contact.

---

### D-03 · `deviceID` can be made as immutable as `contactID`, if minted the same way

Verified `Contact.Profile.identifier` (`Contact+Model.swift:12`) is `UUID().uuidString`, assigned once at contact creation, and never reassigned anywhere in the codebase (grepped all `.identifier =` call sites — no mutation path exists). It is not derived from the system Contacts framework or any other value that could shift.

`deviceID` doesn't exist yet, so this is a design choice, not a discovered constraint: mint a random UUID once, at the moment a specific device's key is first exchanged, and store it as a field on the `Key` record (`Contact+Model.swift:246–281`) — never derive it from anything observable (device name, OS version, etc.). Done this way, it's exactly as stable as `contactID` and safe to use in an SE tag prefix.

**Edge case (not yet resolved):** if a contact's device is wiped/reinstalled, its SE identity key regenerates and re-pairing produces a new key with a new `deviceID` — the old slot's prekey pool becomes orphaned. This is the same shape of problem single-device key rotation already has, just now scoped per-device. Cleanup-on-expiry, not a tag-stability problem. Overlaps with the "Contact Migration Protocol" projected feature (`Feature Evolution & Trajectory.md`, item 2) — signed key rotation would let a legitimate re-pair carry continuity forward instead of silently orphaning the pool.

---

### D-04 · Per-recipient prekey replenishment already exists and needs no new mechanism

`RecipientPayload.prekeyBatch` (`OccultaBundle.swift:501–504`) already carries the sender's fresh prekeys for one specific recipient slot, explicitly documented as mirroring the single-recipient replenishment logic. `GroupRecipient.pendingBatch` (`Crypto+Manager+GroupEncrypt.swift:24`) is built by `ContactManager` per recipient and sealed into that recipient's own encrypted slot (`Crypto+Manager+GroupEncrypt.swift:153`).

**Conclusion:** for multi-device, `ContactManager` builds one `GroupRecipient` per (contact, device) pair instead of one per contact, each carrying that device's own `pendingBatch` computed against that device's own threshold. The batch travels inside that device's own encrypted slot — device A never sees device B's replenishment prekeys, which is a useful isolation property if one device is later compromised. No new struct, no new wire field. The only new code is upstream: `ContactManager` fanning out one recipient per device instead of one per contact.

---

## Open Questions (Unresolved)

### Q-01 · Revocation of a single device

`expiredOn` (`Contact+Model.swift:257`) is currently the only invalidation mechanism, and it's rotation semantics: one key expires, a new one becomes active. Multi-device needs "kill device B's key, leave device A's key active" — a concurrently-active-keys model, not a rotation model. Not designed yet.

### Q-02 · Pairing UX for "add another device to an existing contact" — RESOLVED, see Design Session 3

~~Unclear whether re-running UWB pairing with someone who already has a `Contact.Profile` should be detected as "this is contact X, add a device" vs. treated as a brand new contact. No dedupe-by-identity flow exists today to hook into.~~

Resolved: no auto-detection. The user explicitly triggers "add a device" from Bob's existing `Contact.Profile` and performs a fresh physical UWB exchange, which attaches the new key to that profile as an additional device slot instead of creating a new contact. See D-07.

### Q-03 · Group cap interaction

The 32-member group cap (`b702ce4`) counts recipient slots. If each device of a multi-device contact consumes its own slot, a contact with 3 devices in a group send costs 3 of the 32 slots. Not yet decided whether that's acceptable or whether multi-device contacts should be capped separately.

---

## Prerequisite for implementation

`Contact.Profile`'s key model must move from "one active key, rotation history" to "several concurrently-active keys, one per device" before any of D-01–D-04 can be implemented. Q-01–Q-03 should be resolved (or explicitly deferred with a documented reason) before writing a SPEC.md.

---

## Design Session 2 — Schema Brainstorm (2026-07-03)

Scope: how `Contact.Profile` should actually represent multiple active keys. No code written — findings below are grounded in the current implementation, read directly.

### D-05 · `expiredOn` is manual-only today, not automatic rotation

`update(key:for:)` (`Contact+Manager.swift:483–520`) only **appends** a new `Key` — it never expires the previous one. `expiredOn` is set exclusively by `reset(identity:)` (`Contact+Manager.swift:522–537`), an explicit user-triggered action. The "one active key" behavior everywhere else in the codebase is an accident of `.last(where: { expiredOn == nil })` resolving to the most recently appended row, not an enforced invariant.

**Implication:** the rotation-vs-new-device fork we were treating as a hard architectural decision is softer than it looked — there's no existing automatic-rotation mechanism to preserve or work around. We're formalizing a loose pattern, not replacing a strict one.

### D-06 · Blast radius confirmed: 34 call sites, two distinct access patterns

Grepped every `contactPublicKeys` reference. All 34 call sites assume a single key and split into two categories that need different treatment under multi-device:

- **Fan-out sites** — `Contact+Manager.swift` (encryption/decryption paths), `IdentityChallenge+Coordinator.swift` — need *all* active devices (`.filter`, not `.last`).
- **Display sites** — `Contact+Detail.swift`, `Contacts+DesignTokens.swift` (fingerprint, "last exchanged" UI) — need *one* key to show, because no UI currently exists for a device list. This is a product decision hiding inside what looks like a pure data-model change (see Q-05).

### Q-04 · Schema shape: field addition vs. new `Device` entity (undecided)

**Option A (minimal):** add `deviceID: String` to the existing `Key` struct, keep the flat `[Key]` array on `Profile`. "All active devices" = `.filter { $0.expiredOn == nil }` grouped by `deviceID`. New optional column, lightweight SwiftData migration, same pattern already used for `encryptionScheme` / `maxBundleVersion`. Existing rows get `deviceID == nil`, treated as one implicit legacy device — no backfill needed.

**Option B (richer):** a new `Device` model owning its own key-rotation history. Gives a natural home for device metadata (label, added date, revoked flag) beyond key material, but is a new `@Model`, a new relationship, and a heavier migration.

Leaning toward Option A on simplicity grounds unless per-device metadata (beyond the key itself) is wanted now. Not decided.

### Q-05 · Does the UI need real multi-device display in this pass?

Display call sites (fingerprint view, "last exchanged" label) currently show one key. Under multi-device, either: (a) UI stays single-key and picks "most recently added device" as a display default, or (b) UI grows an actual device list/picker. Affects whether `deviceID` alone is sufficient or a `deviceLabel`/nickname field is also needed. Not decided.

### Q-06 · `reset(identity:)` becomes a latent bug under multi-device if untouched (refines Q-01)

As written, `reset(identity:)` does `contactPublicKeys?.last?.expiredOn = ...` — expires only the most-recently-added key. Once multiple devices are active concurrently, this would silently leave every other device's key live while appearing to have "reset" the contact. Needs to split into two explicit operations: revoke one device's key vs. revoke/forget the entire contact (all devices). This mostly resolves Q-01's revocation question — `expiredOn` was already a manual per-key kill switch, it just needs to be correctly scoped once there's more than one row to choose from.

---

## Design Session 3 — Device Discovery & Revocation Propagation (2026-07-05)

Two mechanisms were proposed and rejected in discussion. Keeping the reasoning here so it isn't re-litigated later.

### Rejected: self-vouching device certs

**Proposal:** Bob's own devices pair with each other and jointly produce a signed roster cert listing all of Bob's device public keys. The cert rides piggyback on outbound bundles (like `prekeyBatch`, D-04). Alice's app ingests it and starts encrypting to every device it lists, without physically pairing with each one herself.

**Why rejected:** this requires Alice to trust a new device on the strength of another device's signature vouching for it — trust extended without Alice ever having been physically present for that device's key exchange. That's a direct exception to Occulta's core invariant since Act 1: physical proximity is the *only* key distribution mechanism. The user's concern, stated directly: people will be afraid to trust any key they weren't physically present to exchange, even from an already-trusted contact. Standing principle going forward (saved to memory as `no-self-vouching-device-trust`): **any mechanism that grants trust to a new key must be a fresh physical UWB exchange.** A device signing its own revocation (or an already-trusted device revoking another of its own devices) is fine and doesn't violate this — revocation only narrows trust, it never grants it to something unverified.

Secondary reasons this would have been costly even setting the principle aside: SE identity keys aren't exportable across a contact's own devices, so there's no single "Bob" signing key to anchor a roster cert to in the first place — the cert would have had to be signed by whichever specific device Alice already trusts, vouching for a new one, which is exactly the trust-extension the user rejected.

### Rejected: mesh/gossip revocation propagation

**Proposal:** when Bob revokes a device, he tells one contact (Alice); Alice then relays the revocation to her own contacts, so it propagates transitively through the social graph faster than Bob messaging everyone directly.

**Why rejected:**
- For Alice to relay *only* to contacts who also know Bob, her app needs to determine "does Carol also have Bob as a contact" — there's no server or shared namespace to check this against, so it requires either a contact-list correlation mechanism (a privacy leak in itself) or blind broadcast to every contact regardless of whether they know Bob (which leaks unrelated third-party metadata into every conversation Alice has).
- It spreads risk across the graph: a duress search of Alice's device would surface revocation history for people Alice never directly exchanged keys with, exposing structure of Bob's device management through a contact who was only ever a courier.
- The actual speed benefit over direct broadcast is marginal — it only matters if Bob has no working device left to broadcast from at all, at which point a verbal "my phone was stolen" to his contacts achieves the same thing without any of the above risk.

**Resolution:** revocation propagates by direct, immediate broadcast — the moment a device is revoked, a signed self-revocation (from the revoked device itself, or from another of Bob's already-trusted devices) is sent directly to every one of Bob's contacts, with no relay hop. This is a self-contained, independently verifiable artifact for each recipient (each contact checks it against a device key they already trust for Bob) and requires no gossip infrastructure.

### D-07 · Resolved device-add flow

Adding a device is a user-initiated action, not an automatic detection:
1. From Bob's existing `Contact.Profile`, the user explicitly starts "add a device."
2. A fresh UWB physical exchange runs, identical to first-contact pairing.
3. The resulting key attaches to Bob's existing `Contact.Profile` as a new device slot (new `deviceID`, per D-03), instead of creating a new contact.

No cert, no vouching, no auto-detection needed — this fully resolves Q-02. Revocation of any one device slot is a direct, immediately-broadcast, signed self-revocation per the resolution above, refining Q-01/Q-06 further: `reset(identity:)` needs a per-device revoke path that also triggers this broadcast, separate from "forget contact entirely."

---

## Design Session 4 — Async ML-KEM Introduction for a Device-Set Member (2026-07-10) — RESOLVED, see below

**Resolved 2026-07-10 — cert-vouching rejected; Design Session 3 / D-07 stands as the design.** This session's design work (captured in [ROADMAP.md](ROADMAP.md), R1) built a cert-based mechanism where a contact accepts a new device belonging to someone they've already met, on the strength of a signature from a device they've already pinned — *without* physically exchanging keys with the new device directly. That was structurally identical to "Rejected: self-vouching device certs" above, which Design Session 3 already rejected and recorded as a standing principle in memory (`no-self-vouching-device-trust`): *"any mechanism that grants trust to a new key must be a fresh physical UWB exchange."*

The deciding argument, beyond the standing principle itself: **attacker cost under coercion.** A coerced device-set ceremony (Face ID compelled once, the exact scenario the app's whole duress cluster exists to resist) would silently propagate an attacker's device to a victim's *entire* contact graph in one event, with no physical tell for any contact. Direct re-pairing (D-07) requires an attacker to physically stage a ceremony with every contact individually — an O(1)-vs-O(N) attacker-cost gap that matters specifically because Occulta's threat model is "person with physical access under duress," not a remote attacker. R1's cert mechanism reopened exactly the class of attack the last two version cycles (Vault/SSS, then the v1.8 duress cluster) were built to close.

**Outcome:** R1 in ROADMAP.md has been rewritten to drop the cert entirely and hold D-07's model as designed — renamed "Multi-Device Contacts" (no shared cross-device "set" object exists in the resolved design). R2's guardian-revocation cert was also corrected, since it had assumed a shared `identityRootPubKey` across devices that the resolved model doesn't have; it now pre-signs and escrows one cert per device.

The finding below (D-08) was reached in the course of designing R1's now-abandoned cert mechanism. It's kept — not deleted — because the reasoning itself (KEMs are inherently asynchronous; Occulta's live-mutual-ceremony usage was a design choice, not a requirement) is sound and may be useful if a future, *explicitly opt-in* feature ever needs async remote key introduction under a deliberately different, weaker trust model. **It does not apply to R1 as resolved.** Every device-contact pairing under the current design is a full live exchange, so there is no async-introduction problem left to solve.

### D-08 · ML-KEM material can be introduced asynchronously, without weakening the shipped protocol

**Starting assumption (wrong, corrected in discussion):** ML-KEM material only ever comes from a live *mutual* encapsulation performed during physical UWB proximity — per bundle.md, "device-bound, never transmitted after the exchange." Initial framing treated this as a hard constraint: a new device (B) introduced via R1's cert would have no way to get PQ protection with any of the owner's existing contacts short of physically re-meeting each one.

**Correction:** the live-mutual-ceremony usage is a design choice in how Occulta *currently* uses ML-KEM, not a requirement of what a KEM *is*. A KEM public key is inherently asynchronous — publish it once, and anyone holding it can encapsulate against it later with no interaction from the owner, symmetric to how classical prekeys already work in this codebase. Signal ships exactly this pattern in production (PQXDH: a signed, longer-lived KEM public key, encapsulated against asynchronously).

**Resulting design:**
- Device B's persistent ML-KEM public key (the public half of a keypair it already generates and retains locally — no new primitive) is bound into the same signed introduction payload as its identity key, delivered to the contact once.
- Establishment is then asynchronous: whichever side sends first performs one-sided encapsulation against the recipient's public key, embeds the resulting ciphertext inline in that bundle (new field, same treatment as today's ephemeral public key), and the recipient decapsulates and caches the shared secret exactly like today's live-ceremony-derived one — symmetric, usable bidirectionally from then on.
- Two deltas stated explicitly rather than hidden: (a) no forward-secrecy regression, since the shipped ML-KEM component was never forward-secret to begin with; (b) asymmetric contribution — only the initiating side's randomness goes into the secret, versus both sides contributing in the live ceremony. Doesn't weaken ML-KEM's IND-CCA2 confidentiality guarantee, but is a real behavioral difference from what ships today.
- A parallel bootstrap problem for classical one-time prekeys (B has no prekey pool with any contact it never physically met) is solved the same way: B signs a compact digest over a locally-generated prekey batch, which travels alongside the ML-KEM key in the same introduction payload — anchoring a bag of unsigned one-time prekeys the way a Signal-style signed prekey does.

Full mechanism, wire fields, and test plan: [ROADMAP.md](ROADMAP.md) R1 §2, §7, §9.

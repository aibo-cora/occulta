# Multi-Device Contacts — Design Findings

**Status:** Exploratory — no SPEC.md yet, not scoped for a release
**Context:** Design discussion, 2026-07-02. Captures conclusions reached before any implementation, so the reasoning isn't lost before this gets formally scoped.

**Problem statement (original, kept for the reasoning trail):** A contact who owns more than one paired device (phone + backup phone, personal + work) should be reachable by a single send, openable on any of their devices that completed key exchange. Today `Contact.Profile` models exactly one active key at a time — a second device pairing would rotate/overwrite the first device's key rather than adding to it.

**Scope narrowed 2026-07-10 — see Design Session 5.** The "reachable on any device, seamlessly" ambition is shelved. What's still being fixed: the overwrite defect (last sentence above) — a real bug regardless of how far the broader feature goes.

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

### Q-01 · Revocation of a single device — design resolved (Q-06, D-07), not implemented

`expiredOn` (`Contact+Model.swift:257`) is currently the only invalidation mechanism, and it's rotation semantics: one key expires, a new one becomes active. Multi-device needs "kill device B's key, leave device A's key active" — a concurrently-active-keys model, not a rotation model. **Design settled:** `expiredOn` becomes a correctly-scoped per-device kill switch (Q-06) distributed via the direct revocation broadcast (D-07, Design Session 3). **Not built:** neither the corrected `reset(identity:)` split nor the broadcast itself exist in code yet — see Design Session 6's "load-bearing dependency" note.

### Q-02 · Pairing UX for "add another device to an existing contact" — RESOLVED, see Design Session 3

~~Unclear whether re-running UWB pairing with someone who already has a `Contact.Profile` should be detected as "this is contact X, add a device" vs. treated as a brand new contact. No dedupe-by-identity flow exists today to hook into.~~

Resolved: no auto-detection. The user explicitly triggers "add a device" from Bob's existing `Contact.Profile` and performs a fresh physical UWB exchange, which attaches the new key to that profile as an additional device slot instead of creating a new contact. See D-07.

### Q-03 · Group cap interaction

The 32-member group cap (`b702ce4`) counts recipient slots. If each device of a multi-device contact consumes its own slot, a contact with 3 devices in a group send costs 3 of the 32 slots. Not yet decided whether that's acceptable or whether multi-device contacts should be capped separately.

### Q-07 · Vault custody reconciliation has no device provenance — safety-critical, blocking. Fix proposed, not implemented. See Design Session 6

`ShardCustodyManager.processInboundManifest`/`processExpectedShards` key everything by `Contact.Profile.identifier` (the same value regardless of which of the contact's devices sent the bundle) and have no concept of "which device established this custody relationship." A second device with no local custody history sending an empty manifest can cause real shards to be flagged possibly-absent or handed back, purely because it doesn't know about a relationship the contact's other device built. Design deferred — logged only. **Fix design not yet done; do not ship any multi-device change that reaches these code paths until it is.**

---

## Prerequisite for implementation

`Contact.Profile`'s key model must move from "one active key, rotation history" to "several concurrently-active keys, one per device" before any of D-01–D-04 can be implemented. Q-01–Q-03 should be resolved (or explicitly deferred with a documented reason) before writing a SPEC.md. **Q-07 additionally blocks shipping any multi-device change that touches Vault/shard custody — this is a correctness-and-safety gap, not a cosmetic one.**

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

### Q-04 · Schema shape: field addition vs. new `Device` entity — RESOLVED 2026-07-10, Option A

**Decision: Option A.** Add `deviceID: String?` to the existing `Contact.Profile.Key` `@Model` (`Contact+Model.swift:245`) — not a new `Device` entity. Confirmed by reading the actual model, not just the earlier abstract description: `Key` is already a proper SwiftData model with its own row and a cascade relationship to `Profile`, and it already carries `quantumKeyMaterialEncrypted` directly on the key itself — so ML-KEM material is already scoped at exactly the right granularity for multi-device with zero extra work. "All active devices" = `.filter { $0.expiredOn == nil }` grouped by `deviceID`. New optional column, lightweight SwiftData migration — same precedent already used for `signedAttributes` ("new optional column, no plan required," `Contact+Model.swift:56`). Existing rows get `deviceID == nil`, treated as one implicit legacy device, no backfill.

Option B's stated justification (a natural home for device labels/metadata) is moot given Q-05's resolution — no device-list UI is being built, so there's no metadata to give a home to yet. ML-DSA was also considered for this model at one point (device-set cert signing) and is explicitly dropped — nothing in the resolved design (Design Session 4) signs anything, so there's no material to store.

### Q-05 · Does the UI need real multi-device display in this pass? — RESOLVED 2026-07-10, no

**Decision: no.** Design Session 5 narrowed R1 to a quiet data-model fix with no UX investment to promote or streamline multi-device adoption — a device-list/picker UI is exactly the kind of investment that decision rules out. Display call sites (fingerprint view, "last exchanged" label) keep showing one key, defaulting to whichever is currently selected by the existing `.last`-style logic at those sites (per D-06, these are display-only call sites, not fan-out ones — picking "wrong" here is cosmetic, not a correctness issue). No `deviceLabel`/nickname field needed since there's no UI to show it in.

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

---

## Design Session 5 — Scope Narrowed: Bug Fix, Not Flagship Feature (2026-07-10)

**Question raised:** with the cert-vouching mechanism gone (Design Session 4) and the secure fallback being "physically re-pair every device with every contact," is the broader feature still worth building — or did fixing the security hole quietly gut the value proposition too?

**Answer: mostly gutted, yes.** Two distinct things had been bundled under "Multi-Device Contacts":

1. **A real defect.** Today, pairing a second device with an existing contact silently overwrites the first device's key for that contact (see problem statement above) — the first device stops receiving from that contact with no warning. This is a genuine bug, independent of everything else, and D-01–D-06's concurrent-key data model fixes it correctly.
2. **A "backup phone that just works" ambition.** This was R1's actual driving pitch, and it's the part that doesn't survive the secure redesign. Making a second device useful to a contact now requires physically re-pairing with *that contact*, one at a time (D-07). For someone with a real contact list, that cost exceeds the convenience of a second device. This isn't a shortcoming of R1's specific design — it's structural: any cheaper version of "multi-device for many contacts" requires the vouching shortcut Design Sessions 3–4 already rejected, and Occulta's no-server, no-vouching thesis has no cheaper substitute to offer. Every other messenger can do backup-device sync cheaply because it has a server and an account model to lean on; Occulta explicitly doesn't.

**Resolution:** ship (1), shelve (2). R1 in ROADMAP.md is narrowed to the data-model fix — quiet infrastructure, not a promoted feature. No UX (checklists, reminders, dashboards) will be built to encourage broad re-pairing. R1 moves from a committed 2026 Q4 slot to opportunistic/low-priority. R2 (Guardian Revocation) is confirmed to stand on its own merits — it solves total device loss, which is orthogonal to whether `Contact.Profile` supports concurrent keys — so this doesn't affect R2's priority. R3–R5 were already deferred in the Trade-off Analysis for independent reasons and remain so, now with one less justification (R1 no longer serves as their "recovery substrate" foundation in any meaningful sense).

If usage data ever shows real demand from users with small, close contact circles willing to re-meet in person for a second device, the narrowed R1 becomes cheap to extend with UX — the underlying mechanism doesn't need to change, just the amount of product investment wrapped around it.

---

## Design Session 6 — Vault Custody Reconciliation Has No Device Provenance (2026-07-10)

**Logged only — fix design deferred to a separate pass.**

**Question raised:** even the narrowed R1 (concurrent device keys) adds a second device that can send bundles to a contact. Does the existing Vault/shard-custody system handle that safely, or can a second device's bundle corrupt custody state established by the first?

**Finding: it doesn't handle it safely — this is a real, previously-uncatalogued gap, and it's more serious than the `contactPublicKeys` fan-out issues D-01–D-06 already cover.**

`ShardCustodyManager.processInboundManifest` (`ShardCustody+Manager.swift:227`) and `processExpectedShards` (`ShardCustody+Manager.swift:280`) are both keyed by the contact's overall identity (`senderIdentifier` / `ownerIdentifier`, resolving to `Contact.Profile.identifier`), which is identical regardless of which of the contact's devices actually sent the bundle. Neither function has any concept of device provenance.

**Concretely, two failure paths:**

1. **`processInboundManifest`, lines 258–268:** loops over every `PotentiallyLostShard` row for `senderIdentifier` and sets `isAbsent = !manifestSet.contains(...)` for each — i.e., it treats *this one manifest* as authoritative for the whole custody relationship with that contact. A second device with no local custody history (it never participated in any shard exchange — a contact's own devices don't sync with each other, no more than ours do) sends an empty manifest by construction, not because anything was lost. Run through this loop, every real shard held for that contact gets flagged possibly-absent.
2. **`processExpectedShards`, line 280 onward:** derives `currentFP` from `senderPublicKey` (the sending device's own key) and deletes `CustodyShard` rows whose stored `ownerKeyFingerprint` doesn't match. Per `buildShardOperations`'s doc comment (`ShardCustody+Manager.swift:300`), a fingerprint mismatch is the *existing, deliberate* signal for identity key rotation, triggering a trustee-side handback. A second concurrently-valid device is not a rotation — but this code has no way to distinguish the two. If device B ever exercises this path, the rotation-detection logic could misfire and hand back shards still correctly held for device A.

**Why this is a different tier of problem than D-01–D-06:** those findings are about who can *read* a message (fan-out, display defaults) — recoverable, cosmetic-adjacent. This one can cause **active, incorrect deletion or false-loss-flagging of real custody state** in a system (Vault/SSS recovery) that exists precisely so users don't lose access to their own data. The team already hardened one adjacent version of this exact problem class — the `shardMetadataAttempted` flag (`Contact+Manager.swift:1695`) exists specifically to stop an ambiguous empty manifest from being misread, with an explicit comment that collapsing the distinction "would drop that signal." Multi-device reopens a harder version of the same class of bug: not just empty-vs-not-attempted, but *whose* manifest gets to speak for a relationship at all.

**Status:** logged as Q-07, marked blocking. A fix direction is proposed below — **not implemented, not fully verified, expected to keep changing as this gets iterated on.** Do not ship R1 (even in its narrowed, data-model-only form) if it enables a second device to reach `processInboundManifest`/`processExpectedShards` before this is resolved.

### Proposed fix direction v2 (2026-07-10 — supersedes v1 above, will keep iterating)

**Core simplification: don't make Vault/custody multi-device-aware at all. Keep it scoped to one device per identity, in both directions, and let `processInboundManifest`/`processExpectedShards`/`mismatchHandbackOps` keep the single-device assumption they already have.** This replaces the recorded-recipient-fingerprint-set proposal above — that design solved cross-device reconciliation; this one avoids needing reconciliation in the first place.

**Which of a contact's devices we trust for shard traffic — outward-facing, fully computed, no new signal.** Define it as the oldest key with `expiredOn == nil` for that contact (`Key.acquiredAt`, already a field — [Contact+Model.swift:245](Occulta/Data%20Models/Contact+Model.swift:245)). Both sides derive the same answer independently, with zero new wire messages. When a contact revokes a device, the existing revocation broadcast (R1 §6) removes it from the active set and every recipient recomputes the new answer automatically — "promotion" isn't an event, it's a side effect of data that already changes for other reasons.

**Bundle routing:** `shardOperations`/`custodyManifest`/`expectedShards` populate *only* the recipient slot for whichever of a contact's devices resolves to the above — every other part of the fanned-out bundle still reaches all their active devices per R1 §4 unchanged. This is the one real code change: the per-recipient payload assembly (`Contact+Manager.swift`, around the recipient-construction pass that already calls `buildShardOperations`) needs to know, per recipient, whether it's building for the trusted device or not.

**Defense in depth on receipt, not just well-behaved senders:** don't rely solely on contacts' clients correctly withholding shard content from their own non-trusted devices. `processInboundManifest`/`processExpectedShards` should also verify the sender's fingerprint matches the resolved trusted-device answer and discard shard-relevant content otherwise — the same "don't trust the sender's claim, verify independently" posture already used for fallback-mode filtering a few lines away (`Contact+Manager.swift`, the `isFallback` filtering comment: *"regardless of what the sender claims, drop them here — rather than relying on the sender to have gated correctly"*).

**Our own vault needs no local "master" tracking at all — this was the wrong frame.** A device's local behavior is already fully determined by whether it holds local `PendingShardDistribute`/`CustodyShard` rows, which only ever exist where they were created. No flag to compute, nothing to consult. The only real requirement: **a newly-paired second device doesn't get Vault-initiating capability by default**, so it can't start an independent, unsynchronized distribution history that fragments the same underlying vault. That's a local gate ("is Vault already active on this device"), not a cross-device concept.

**Loss and promotion — exactly one unavoidable manual step, everything else automatic:**
- A contact's device being lost: fully automatic on our side, via the existing revocation broadcast + the deterministic recomputation above.
- *Our own* device being lost: **cannot be automatic**, and this isn't a gap to close — Occulta's own devices have no channel to each other by design (the same standing invariant that killed the cert-vouching design earlier this session). There is no data path by which a surviving device could independently verify the other is gone. The user must say so, on the surviving device, once. Every downstream step — revocation broadcast, contacts recomputing the new trusted device, Vault activating on the surviving device — follows automatically from that one trigger.
- **Open, not yet decided:** whether the resync step (the newly-designated device asking known trustees what they currently hold, to rebuild local tracking state) runs automatically once the manual trigger fires, or wants its own confirmation — it's the one part of this flow that reaches out and potentially alters trustee-facing state, not just a passive broadcast. Also still depends on unverified capabilities of `Vault+Manager+Reconstruction.swift`.

**Also still needed:** wherever `buildShardOperations(for:currentContactPublicKey:)`'s caller currently resolves "the contact's public key," it must resolve to the trusted-device key specifically — not whatever D-06's general `.last`-pattern cleanup happens to pick for other (cosmetic) call sites. Getting this one wrong reintroduces the false-rotation risk this whole design exists to close.

**Why this is preferred over v1:** no new schema fields, no set-based comparisons, and `processInboundManifest`/`processExpectedShards`/`mismatchHandbackOps` need no internal changes at all — they only ever see one device's traffic per relationship, exactly as today. It also concentrates Vault-sensitive material on fewer devices, which is a security property, not just a simplification.

**Not yet verified:** `mismatchHandbackOps`'s actual implementation (only its doc comment read so far). Whether the recipient-payload assembly can cleanly special-case one recipient's fields without restructuring the fan-out loop. `Vault+Manager+Reconstruction.swift`'s actual resync capabilities. No tamper table, trace tests, or R0-style checklist pass done yet — expect this to keep changing.

**Load-bearing dependency that doesn't exist yet:** this whole design leans on "the revocation broadcast" (R1 §6: a surviving device SE-signs `occulta-device-revocation-v1 ∥ lostDevicePubKey ∥ timestamp` and sends it directly to every contact) treating it as a stable given. Checked 2026-07-10: **it isn't implemented anywhere** — `occulta-device-revocation-v1` appears nowhere in the codebase outside this doc and ROADMAP.md. It's a resolved *design* (FINDINGS.md Design Session 3, 2026-07-05) with a wire shape written down (ROADMAP.md R1 §6), but no struct, no bundle field, no handler. The only shipped, related code is `reset(identity:)` (`Contact+Manager.swift:524`), which is local-only (`contact.contactPublicKeys?.last?.expiredOn = ...`, no send) and already has Q-06's documented bug (`.last` instead of all active keys) baked in. Everything in this write-up described as "automatic once the manual trigger fires" depends on building this broadcast first.
